import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { publishFile } from '../agent-media.mjs';

const origin = process.argv[2];
const bootstrapSecret = process.env.BC_TEST_PAIR_SECRET;
const mountDevice = process.env.BC_TEST_MEDIA_MOUNT === '1';
const workerURL = new URL('../media-worker.mjs', import.meta.url).href;
function createWorker() {
  const code = `import {parentPort} from 'node:worker_threads';
    globalThis.postMessage = (data, transfers) => parentPort.postMessage(data, transfers);
    parentPort.on('message', data => globalThis.onmessage?.({data}));
    await import(${JSON.stringify(workerURL)});
    parentPort.postMessage({type:'loaded'});`;
  const worker = new Worker(new URL('data:text/javascript,' + encodeURIComponent(code)), { type: 'module' });
  const loaded = new Promise((resolve) => worker.once('message', resolve));
  return {
    postMessage: (data, transfers) => { loaded.then(() => worker.postMessage(data, transfers)); },
    addEventListener: (type, listener) => {
      if (type === 'message') worker.on('message', (data) => { if (data.type !== 'loaded') listener({ data }); });
      else if (type === 'error') worker.on('error', (error) => listener({ error }));
    },
    terminate: () => { worker.terminate(); },
  };
}
async function api(method, path, body, token) {
  const response = await fetch(new URL(path, origin), {
    method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  return response;
}
const pair = await api('POST', '/v1/pair', { secret: bootstrapSecret, name: 'browser-file-test' });
assert.equal(pair.status, 201);
const credentials = await pair.json();
const bytes = Uint8Array.from({ length: 70000 }, (_, i) => i % 251);
const file = new File([bytes], 'fixture.iso');
const first = await publishFile({ agentOrigin: origin, token: credentials.token, file, createWorker });
try {
  const read = await api('POST', '/v1/media/sources/' + first.sourceId + '/read', { offset: '65530', length: 100 }, credentials.token);
  assert.equal(read.status, 200);
  assert.equal(read.headers.get('Content-Type'), 'application/octet-stream');
  assert.deepEqual(new Uint8Array(await read.arrayBuffer()), bytes.slice(65530, 65630));
  const large = await api('POST', '/v1/media/sources/' + first.sourceId + '/read', { offset: '0', length: 65536 }, credentials.token);
  assert.equal(large.status, 200);
  assert.deepEqual(new Uint8Array(await large.arrayBuffer()), bytes.slice(0, 65536));
  const boundary = await api('POST', '/v1/media/sources/' + first.sourceId + '/read', { offset: '70000', length: 1 }, credentials.token);
  assert.equal(boundary.status, 416);
  const listing = await api('GET', '/v1/media/sources', null, credentials.token);
  const sources = await listing.json();
  assert.equal(sources.length, 1);
  assert.equal(sources[0].connected, true);
  assert.equal(sources[0].size, '70000');
  if (mountDevice) {
    const opened = await (await api('POST', '/v1/connections', { mode: 'auto' }, credentials.token)).json();
    assert.equal(opened.status, 'ok'); assert.equal(opened.browser_media_available, true);
    const route = '/v1/connections/' + opened.connection_id;
    const invitation = await (await api('POST', '/v1/pairing', null, credentials.token)).json();
    const other = await (await api('POST', '/v1/pair', { secret: invitation.secret, name: 'other-consumer' })).json();
    const otherConnection = await (await api('POST', '/v1/connections', { mode: 'auto' }, other.token)).json();
    const payload = { media_uri: '/redfish/v1/Managers/mgr1/VirtualMedia/cd', source_id: first.sourceId, write_protected: true };
    const refused = await (await api('POST', '/v1/connections/' + otherConnection.connection_id + '/media', payload, other.token)).json();
    assert.equal(refused.status, 'unsupported');
    const mounted = await (await api('POST', route + '/media', payload, credentials.token)).json();
    assert.equal(mounted.status, 'ok'); assert.equal(mounted.media_source_id, first.sourceId);
    assert.equal(mounted.remote_media_retained, false);
    const range = await fetch(mounted.url, { headers: { Range: 'bytes=65530-65629' }, signal: AbortSignal.timeout(8000) });
    assert.equal(range.status, 206);
    assert.deepEqual(new Uint8Array(await range.arrayBuffer()), bytes.slice(65530, 65630));
    for (const value of ['bytes=69990-', 'bytes=-10']) {
      const tail = await fetch(mounted.url, { headers: { Range: value }, signal: AbortSignal.timeout(8000) });
      assert.equal(tail.status, 206); assert.deepEqual(new Uint8Array(await tail.arrayBuffer()), bytes.slice(-10));
    }
    const invalid = await fetch(mounted.url, { headers: { Range: 'bytes=18446744073709551616-18446744073709551617' }, signal: AbortSignal.timeout(8000) });
    assert.equal(invalid.status, 416); assert.equal(invalid.headers.get('Content-Range'), 'bytes */70000');
    assert.equal((await (await api('DELETE', route, null, credentials.token)).json()).status, 'ok');
    assert.equal((await fetch(mounted.url, { signal: AbortSignal.timeout(8000) })).status, 404);
    assert.equal((await (await api('DELETE', '/v1/connections/' + otherConnection.connection_id, null, other.token)).json()).status, 'ok');
  }
} finally {
  await first.close();
}
const second = await publishFile({ agentOrigin: origin, token: credentials.token, file, createWorker });
assert.notEqual(second.sourceId, first.sourceId);
assert.notEqual(second.channel, first.channel);
const revoked = await api('DELETE', '/v1/clients/' + credentials.client_id, null, credentials.token);
assert.equal(revoked.status, 200);
let timer;
try {
  const state = await Promise.race([second.closed, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('revocation did not close the source')), 3000); })]);
  assert.equal(state.reason, 'connection_closed');
} finally {
  clearTimeout(timer);
  await second.close();
}
assert.equal((await api('GET', '/v1/media/sources', null, credentials.token)).status, 401);
console.log(JSON.stringify({ real_blob_read: true, worker: true, bytes_compared: 65636, range_rejected: true, new_generation: true, revoked_channel_closed: true, device_mounted_from_blob: mountDevice }));
