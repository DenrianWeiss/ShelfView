import assert from 'node:assert/strict';
import test from 'node:test';
import { pairAgent } from '../agent-pair.mjs';

const SECRET = 'a'.repeat(64);
const TOKEN = 'b'.repeat(64);

test('pairing request and result validation', async () => {
  let request;
  const fetchImpl = async (url, options) => {
    request = { url: String(url), options };
    return { ok: true, json: async () => ({ client_id: 'c'.repeat(32), token: TOKEN }) };
  };
  const result = await pairAgent({ agentOrigin: 'http://127.0.0.1:8445/', secret: SECRET, fetchImpl });
  assert.equal(request.url, 'http://127.0.0.1:8445/v1/pair');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(request.options.body), { secret: SECRET, name: 'desktop' });
  assert.deepEqual(result, { clientId: 'c'.repeat(32), token: TOKEN });
  await assert.rejects(() => pairAgent({ agentOrigin: 'http://127.0.0.1:8445/', secret: 'short', fetchImpl }));
  await assert.rejects(() => pairAgent({
    agentOrigin: 'http://127.0.0.1:8445/', secret: SECRET,
    fetchImpl: async () => ({ ok: false, json: async () => ({}) }),
  }), /pairing_rejected/);
  await assert.rejects(() => pairAgent({
    agentOrigin: 'http://127.0.0.1:8445/', secret: SECRET,
    fetchImpl: async () => ({ ok: true, json: async () => ({ client_id: 'c'.repeat(32), token: 'bad' }) }),
  }), /invalid_pairing_result/);
});
