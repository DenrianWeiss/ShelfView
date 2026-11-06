import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentClient, AgentError } from '../agent-client.mjs';
const id = 'a'.repeat(32), token = 'b'.repeat(64);
const options = { agentOrigin: 'http://127.0.0.1:8445', token };

test('connection queries and power use the paired connection without retries', async () => {
  const requests = [];
  const client = new AgentClient({ ...options, fetchImpl: async (url, init) => {
    requests.push([url, init]);
    return { ok: true, json: async () => ({ status: 'ok', connection_id: id }) };
  } });
  await client.connect();
  await client.query(id, 'tasks');
  await client.query(id, 'system', '/redfish/v1/Systems/arbitrary');
  await client.power(id, '/redfish/v1/Systems/arbitrary', 'On');
  await client.close(id);
  assert.deepEqual(requests.map(([url]) => url.pathname), ['/v1/connections', `/v1/connections/${id}/query`,
    `/v1/connections/${id}/query`, `/v1/connections/${id}/power`, `/v1/connections/${id}`]);
  assert.deepEqual(requests.map(([, init]) => init.method), ['POST', 'POST', 'POST', 'POST', 'DELETE']);
  assert.deepEqual(JSON.parse(requests[1][1].body), { operation: 'tasks' });
  for (const [url, init] of requests) {
    assert.equal(url.search, ''); assert.equal(url.origin, options.agentOrigin);
    assert.equal(init.headers.Authorization, `Bearer ${token}`);
    assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit'); assert.equal(init.cache, 'no-store');
  }
});

test('device failures retain task/outcome information and do not replay', async () => {
  let calls = 0;
  const result = { status: 'outcome_unknown', flags: 1, http_status: 0 };
  const client = new AgentClient({ ...options, fetchImpl: async () => {
    calls++; return { ok: true, json: async () => result };
  } });
  await assert.rejects(client.power(id, '/redfish/v1/Systems/1', 'On'), (error) =>
    error instanceof AgentError && error.message === 'outcome_unknown' && error.result === result);
  assert.equal(calls, 1);
  const offline = new AgentClient({ ...options, fetchImpl: async () => { throw new Error('offline'); } });
  await assert.rejects(offline.power(id, '/redfish/v1/Systems/1', 'On'), /outcome_unknown/);
  await assert.rejects(offline.query(id, 'systems'), /connection_failed/);
});

test('reject malformed connection identities before sending credentials', async () => {
  let calls = 0;
  const client = new AgentClient({ ...options, fetchImpl: async () => { calls++; } });
  for (const value of ['../clients', 'https://other.invalid', '', null]) assert.throws(() => client.close(value));
  assert.equal(calls, 0);
  assert.throws(() => new AgentClient({ ...options, token: 'invalid' }));
  assert.throws(() => new AgentClient({ ...options, agentOrigin: 'http://user:pass@host' }));
});

test('browser media mount passes only the source identity to the agent', async () => {
  const requests = [];
  const client = new AgentClient({ ...options, fetchImpl: async (url, init) => {
    requests.push(JSON.parse(init.body)); return { ok: true, json: async () => ({ status: 'ok' }) };
  } });
  await client.mountFileMedia(id, '/redfish/v1/Managers/1/VirtualMedia/CD', 'a'.repeat(32));
  assert.deepEqual(requests, [{ media_uri: '/redfish/v1/Managers/1/VirtualMedia/CD', source_id: 'a'.repeat(32), write_protected: true }]);
  assert.throws(() => client.mountFileMedia(id, '/slot', '../other'));
  assert.equal(requests.length, 1);
});

test('manual eject explicitly identifies an unassociated media slot', async () => {
  let request;
  const client = new AgentClient({ ...options, fetchImpl: async (url, init) => {
    request = init; return { ok: true, json: async () => ({ status: 'ok' }) };
  } });
  await client.ejectMedia(id, '/redfish/v1/Managers/1/VirtualMedia/CD');
  assert.equal(request.method, 'DELETE');
  assert.deepEqual(JSON.parse(request.body), { media_uri: '/redfish/v1/Managers/1/VirtualMedia/CD' });
});

test('HTTP authorization errors and malformed JSON remain explicit', async () => {
  const rejected = new AgentClient({ ...options, fetchImpl: async () => ({ ok: false, status: 401, json: async () => ({ error: 'unauthorized' }) }) });
  await assert.rejects(rejected.query(id, 'systems'), /unauthorized/);
  const malformed = new AgentClient({ ...options, fetchImpl: async () => ({ ok: true, json: async () => { throw new Error(); } }) });
  await assert.rejects(malformed.query(id, 'systems'), /invalid_response/);
});

test('damaged mutation acknowledgements remain uncertain without retries', async () => {
  for (const body of [null, [], {}, { status: 0 }, 'broken-json']) {
    let requests = 0;
    const client = new AgentClient({ ...options, fetchImpl: async () => {
      requests++;
      return { ok: true, json: async () => {
        if (body === 'broken-json') throw new SyntaxError();
        return body;
      } };
    } });
    await assert.rejects(client.mountMedia(id, '/redfish/v1/Managers/1/VirtualMedia/CD', 'https://images.test/os.iso'),
      error => error.message === 'outcome_unknown');
    await assert.rejects(client.ejectMedia(id), error => error.message === 'outcome_unknown');
    assert.equal(requests, 2);
  }
});

test('browser fetch is invoked without an AgentClient receiver', async () => {
  const client = new AgentClient({ ...options, fetchImpl: async function () {
    assert.equal(this, undefined);
    return { ok: true, json: async () => ({ status: 'ok', members: [] }) };
  } });
  await client.query(id, 'systems');
});


test('one deadline covers headers and body; timed-out writes remain uncertain', async () => {
  // Keep the loop alive while AbortSignal.timeout uses an unreferenced timer.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    for (const stallBody of [false, true]) {
      let calls = 0;
      const client = new AgentClient({ ...options, timeoutMs: 5, fetchImpl: async (_, { signal }) => {
        calls++;
        const wait = () => new Promise((_, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        });
        if (!stallBody) return await wait();
        return { ok: true, json: wait };
      } });
      await assert.rejects(client.query(id, 'systems'), error => error.message === 'timeout');
      await assert.rejects(client.power(id, '/redfish/v1/Systems/1', 'On'),
        error => error.message === 'outcome_unknown');
      assert.equal(calls, 2);
    }
  } finally { clearInterval(keepAlive); }
});


test('associated connections bind the expected device and close mismatched responses', async () => {
  const requests = [];
  let device = 'rack-1';
  const client = new AgentClient({ ...options, fetchImpl: async (_, init) => {
    requests.push(init);
    return { ok: true, json: async () => ({ status: 'ok', connection_id: id, device_id: device }) };
  } });
  await client.connect('rack-1');
  assert.equal(JSON.parse(requests[0].body).device_id, 'rack-1');
  device = 'rack-2';
  await assert.rejects(client.connect('rack-1'), error =>
    error.message === 'device_association_mismatch' && error.result.cleanupConfirmed);
  assert.equal(requests.at(-1).method, 'DELETE');
  await assert.rejects(client.connect(''), /invalid_device_id/);
});
