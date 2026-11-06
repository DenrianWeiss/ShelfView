import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import { BrowserMediaSource, encodeFrame, decodeFrame, OP, MediaProtocolError } from '../media-protocol.mjs';

function request(id, offset, length, channel = 7) {
  const body = new Uint8Array(4);
  new DataView(body.buffer).setUint32(0, length);
  return encodeFrame({ opcode: OP.READ, channel, requestId: id, offset }, body);
}

test('C encoder and browser decoder agree on 64-bit IDs and wire byte order', {
  skip: !process.env.BC_MEDIA_VECTOR,
}, () => {
  const hex = execFileSync(process.env.BC_MEDIA_VECTOR, { encoding: 'utf8' }).trim();
  const bytes = Uint8Array.from(Buffer.from(hex, 'hex'));
  const frame = decodeFrame(bytes.buffer);
  assert.equal(frame.requestId, 9007199254740993n);
  assert.equal(frame.offset, 1n);
  assert.equal(frame.opcode, OP.READ);
  assert.deepEqual([...frame.payload], [0, 0, 0, 6]);
  assert.deepEqual(new Uint8Array(request(frame.requestId, frame.offset, 6)), bytes);
});

test('actual Blob random reads return exact DATA payloads', async () => {
  const bytes = Uint8Array.from({ length: 70000 }, (_, i) => i % 251);
  const source = new BrowserMediaSource(new Blob([bytes]), { channel: 7 });
  const frames = await Promise.all([source.handleFrame(request(1n, 65530n, 100)), source.handleFrame(request(2n, 0n, 512))]);
  for (const [i, offset, length] of [[0, 65530, 100], [1, 0, 512]]) {
    const frame = decodeFrame(frames[i]);
    assert.equal(frame.opcode, OP.DATA);
    assert.deepEqual(frame.payload, bytes.slice(offset, offset + length));
  }
  const invalid = decodeFrame(await source.handleFrame(request(3n, 9007199254740993n, 1)));
  assert.equal(invalid.opcode, OP.ERROR);
  assert.equal(JSON.parse(new TextDecoder().decode(invalid.payload)).error, 'invalid_range');
});

test('cancellation suppresses late reads but keeps the window occupied until the read settles', async () => {
  let resolve;
  const file = { size: 64, slice: () => ({ arrayBuffer: () => new Promise((r) => { resolve = r; }) }) };
  const source = new BrowserMediaSource(file, { channel: 7, window: 1 });
  const pending = source.handleFrame(request(1n, 0n, 4));
  await source.handleFrame(encodeFrame({ opcode: OP.CANCEL, channel: 7, requestId: 1n }));
  const denied = decodeFrame(await source.handleFrame(request(2n, 0n, 4)));
  assert.equal(JSON.parse(new TextDecoder().decode(denied.payload)).error, 'window_exceeded');
  resolve(new ArrayBuffer(4));
  assert.equal(await pending, null);
  source.close();
  await assert.rejects(source.handleFrame(request(3n, 0n, 4)), MediaProtocolError);
});

test('malformed messages, wrong channels and reused IDs are rejected', async () => {
  const source = new BrowserMediaSource(new Blob(['example']), { channel: 7 });
  await assert.rejects(source.handleFrame(request(1n, 0n, 1, 8)), /channel/);
  const frame = request(1n, 0n, 1);
  new Uint8Array(frame)[39] = 1;
  await assert.rejects(source.handleFrame(frame), /Reserved/);
  await source.handleFrame(request(1n, 0n, 1));
  await assert.rejects(source.handleFrame(request(1n, 0n, 1)), /Reused/);
  assert.throws(() => decodeFrame(new ArrayBuffer(39)), /Truncated/);
});

test('browser read failures become ERROR frames', async () => {
  const source = new BrowserMediaSource({ size: 8, slice: () => ({ arrayBuffer: async () => { throw new Error('permission revoked'); } }) }, { channel: 7 });
  const frame = decodeFrame(await source.handleFrame(request(1n, 0n, 8)));
  assert.equal(frame.opcode, OP.ERROR);
  assert.equal(JSON.parse(new TextDecoder().decode(frame.payload)).error, 'source_read_failed');
});

test('Worker clones a real Blob, reads off-thread and transfers the DATA buffer', async () => {
  const url = new URL('../media-worker.mjs', import.meta.url).href;
  const bootstrap = `import { parentPort } from 'node:worker_threads';
    globalThis.postMessage = (data, transfers) => parentPort.postMessage(data, transfers);
    parentPort.on('message', data => globalThis.onmessage?.({data}));
    await import(${JSON.stringify(url)});
    parentPort.postMessage({type:'loaded'});`;
  const worker = new Worker(new URL('data:text/javascript,' + encodeURIComponent(bootstrap)), { type: 'module' });
  try {
    await once(worker, 'message');
    let next = once(worker, 'message');
    worker.postMessage({ type: 'open', sourceId: 'test-generation', file: new Blob(['disk-image-bytes']), channel: 7 });
    const [ready] = await next;
    assert.equal(ready.type, 'ready');
    assert.equal(ready.size, '16');
    next = once(worker, 'message');
    const frame = request(1n, 5n, 5);
    worker.postMessage({ type: 'frame', sourceId: 'test-generation', frame }, [frame]);
    assert.equal(frame.byteLength, 0);
    const [response] = await next;
    assert.equal(new TextDecoder().decode(decodeFrame(response.frame).payload), 'image');
    next = once(worker, 'message');
    worker.postMessage({ type: 'close', sourceId: 'test-generation' });
    assert.equal((await next)[0].type, 'closed');
  } finally {
    await worker.terminate();
  }
});
