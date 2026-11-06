import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserWorker } from './browser-worker.mjs';
import { createConsoleDecoder } from '../kvm-decoder.mjs';

test('worker decodes fragmented video into owned snapshots and publishes readiness', { timeout: 5000 }, async () => {
  let resolveFrame, rejectFrame;
  const firstFrame = new Promise((resolve, reject) => { resolveFrame = resolve; rejectFrame = reject; });
  const output = [];
  const decoder = createConsoleDecoder({ WorkerCtor: BrowserWorker, onFrame: resolveFrame,
    onError: reason => rejectFrame(new Error(reason)), onOutput: bytes => output.push(bytes) });
  try {
    const feed = bytes => decoder.feed(Uint8Array.from(bytes).buffer);
    feed(new TextEncoder().encode('RFB 003.008\n')); feed([1, 1]); feed([0, 0, 0, 0]);
    const init = new Uint8Array(24); init[1] = 1; init[3] = 1; init[4] = 32; init[5] = 24; init[23] = 1;
    feed(init); feed([107]);
    const update = new Uint8Array(16); update[3] = 1; update[9] = 1; update[11] = 1;
    feed(update); feed([0, 0]); feed([255, 0]);
    const frame = await firstFrame;
    assert.deepEqual([...frame.pixels], [255, 0, 0, 255]);
    assert.equal(frame.width, 1); assert.equal(frame.height, 1);
    assert.ok(output.length >= 3);
    assert.equal(decoder.ready, true);
  } finally { decoder.close(); }
});
