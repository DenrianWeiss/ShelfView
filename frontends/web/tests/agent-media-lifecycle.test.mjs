import assert from 'node:assert/strict';
import test from 'node:test';
import { publishFile } from '../agent-media.mjs';

test('channel construction failures revoke tickets and report uncertain cleanup', async () => {
  const originalFetch = globalThis.fetch, originalSocket = globalThis.WebSocket;
  const sourceId = 'a'.repeat(32), token = 'b'.repeat(64);
  const ticket = { source_id: sourceId, ticket: token, size: '1', channel: 1,
    max_block: 4096, window: 1, websocket_path: '/v1/media/ws' };
  try {
    for (const workerFailure of [true, false]) {
      const requests = [];
      let terminated = false;
      globalThis.fetch = async (url, options) => {
        requests.push([url.pathname, options.method]);
        if (options.method === 'POST') return { ok: true, json: async () => ({ ...ticket }) };
        if (!workerFailure) throw new Error('offline');
        return { ok: true, status: 200 };
      };
      globalThis.WebSocket = class { constructor() { throw new Error('socket unavailable'); } };
      await assert.rejects(publishFile({ agentOrigin: 'http://127.0.0.1:8445', token,
        file: new Blob(['x']), createWorker: () => {
          if (workerFailure) throw new Error('worker unavailable');
          return { terminate() { terminated = true; } };
        },
      }), error => error.message === 'media_channel_unavailable' && error.cleanupConfirmed === workerFailure);
      assert.equal(terminated, !workerFailure);
      assert.deepEqual(requests, [['/v1/media/tickets', 'POST'], [`/v1/media/sources/${sourceId}`, 'DELETE']]);
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (originalSocket === undefined) delete globalThis.WebSocket;
    else globalThis.WebSocket = originalSocket;
  }
});
