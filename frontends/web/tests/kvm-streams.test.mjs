import assert from 'node:assert/strict';
import test from 'node:test';
import { KvmInputStream } from '../kvm-streams.mjs';
import { KvmView } from '../kvm-input.mjs';

test('input remains ordered while drawing waits and tile deltas are composed', async () => {
  const scheduled = [], drawn = [], sent = [];
  const previous = globalThis.requestAnimationFrame;
  globalThis.requestAnimationFrame = callback => scheduled.push(callback);
  try {
    const input = new KvmInputStream(event => sent.push(event));
    const canvas = { getContext: () => ({ createImageData: (width, height) => ({ width, height, data: new Uint8ClampedArray(width * height * 4) }),
      putImageData: image => drawn.push([...image.data]) }) };
    const viewer = new KvmView({ canvas, session: { input } }); viewer.active = true;
    const tile = { canvasWidth: 2, canvasHeight: 1, width: 1, height: 1, stride: 4, y: 0, pixelFormat: 'rgba8' };
    viewer.drawTile({ ...tile, x: 0, pixels: new Uint8Array([1, 2, 3, 255]) });
    viewer.drawTile({ ...tile, x: 1, pixels: new Uint8Array([4, 5, 6, 255]) });
    await input.send({ type: 'key', keysym: 97, down: true });
    await input.send({ type: 'key', keysym: 97, down: false });
    assert.deepEqual(sent.map(event => event.down), [true, false]);
    assert.equal(drawn.length, 0); assert.equal(scheduled.length, 1);
    scheduled[0](); assert.deepEqual(drawn[0], [1, 2, 3, 255, 4, 5, 6, 255]);
    await input.close();
    await assert.rejects(input.send({ type: 'key', keysym: 98, down: true }), /input_closed/);
  } finally { globalThis.requestAnimationFrame = previous; }
});

test('input failures stop queued events instead of losing a release silently', async () => {
  const sent = [], errors = [];
  const stream = new KvmInputStream(event => { sent.push(event); throw new Error('transport_failed'); }, error => errors.push(error));
  const results = await Promise.allSettled([
    stream.send({ type: 'key', down: true, keysym: 97 }),
    stream.send({ type: 'key', down: false, keysym: 97 }),
  ]);
  assert.deepEqual(results.map(result => result.status), ['rejected', 'rejected']);
  assert.equal(sent.length, 1); assert.deepEqual(errors, ['transport_failed']);
  await stream.close();
});
