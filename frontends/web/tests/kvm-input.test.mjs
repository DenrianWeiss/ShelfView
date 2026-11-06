import assert from 'node:assert/strict';
import test from 'node:test';
import { keysymFor, pointerMask, KvmView } from '../kvm-input.mjs';

test('platform keysym and button mapping', () => {
  assert.equal(keysymFor({ code: 'KeyA', key: 'a' }), 0x61);
  assert.equal(keysymFor({ code: 'Enter', key: 'Enter' }), 0xff0d);
  assert.equal(keysymFor({ code: 'F5', key: 'F5' }), 0xffc2);
  assert.equal(keysymFor({ code: 'Digit1', key: '1' }), 0x31);
  assert.equal(keysymFor({ key: 'a' }), 0x61);
  assert.equal(keysymFor({ key: '中' }), 0);
  assert.equal(keysymFor({ code: 'KeyA', key: 'a', isComposing: true }), 0);
  assert.equal(keysymFor({ key: 'Unidentified' }), 0);
  assert.equal(pointerMask(1), 1);
  assert.equal(pointerMask(3), 3);
  assert.equal(pointerMask(0), 0);
});
test('canvas view sends input and draws frames', () => {
  const sent = []; const drawn = [];
  const canvas = {
    width: 0, height: 0, tabIndex: 0,
    getContext: () => ({
      putImageData: (image) => drawn.push(image),
      createImageData: (width, height) => ({ width, height, data: new Uint8ClampedArray(width * height * 4) }),
    }),
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 20, height: 10 }),
    addEventListener() {}, removeEventListener() {},
  };
  const view = new KvmView({ canvas, session: { input: { send: (event) => sent.push(event) } } });
  view.start();
  view.drawFrame({ width: 2, height: 2, pixels: new Uint8ClampedArray(16).fill(255) });
  assert.equal(canvas.width, 2); assert.equal(canvas.height, 2);
  assert.equal(drawn.length, 1);
  view.handleKey({ code: 'KeyA', key: 'A', preventDefault() {} }, true);
  view.handleMouse({ clientX: 10, clientY: 5, buttons: 1 });
  assert.deepEqual(sent[0], { type: 'key', down: true, keysym: 0x61 });
  assert.deepEqual(sent[1], { type: 'pointer', buttons: 1, x: 1, y: 1 });
  view.wheel({ clientX: 10, clientY: 5, buttons: 1, deltaY: -1, preventDefault() {} });
  assert.deepEqual(sent[2], { type: 'scroll', buttons: 1, x: 1, y: 1, wheel: 1 });
  view.input.supportsScroll = false;
  view.wheel({ deltaY: 1, preventDefault() { assert.fail('unsupported wheel was captured'); } });
  assert.equal(sent.length, 3);
  view.blur();
  assert.deepEqual(sent.slice(3), [
    { type: 'key', down: false, keysym: 0x61 },
    { type: 'pointer', buttons: 0, x: 1, y: 1 },
  ]);
  view.stop();
  assert.equal(sent.length, 5);
});

test('slow paste validates the entire text and normalizes line endings', async () => {
  const { pastePlan } = await import('../kvm-input.mjs');
  assert.deepEqual(pastePlan('A\r\n\t!\rb'), [65, 0xff0d, 0xff09, 33, 0xff0d, 98]);
  assert.equal(pastePlan('abc中'), null);
  assert.equal(pastePlan('abc\0'), null);
});

test('slow paste releases keys and stops on cancellation or disconnect', async () => {
  const sent = [];
  const view = new KvmView({ canvas: { getContext: () => ({}) }, session: { input: { send: event => sent.push(event) } } });
  view.active = true;
  view.pressedKeys = new Set([0xffe1]);
  await view.slowPaste('ab', 10, () => view.cancelPaste());
  assert.deepEqual(sent, [{ type: 'key', down: false, keysym: 0xffe1 }, { type: 'chord', keys: [97] }]);
  assert.equal(view.pasting, false);
  sent.length = 0;
  await view.slowPaste('ab', 10, () => { view.active = false; });
  assert.equal(sent.length, 1);
  view.active = true;
  sent.length = 0;
  await assert.rejects(view.slowPaste('abc中'), /paste_unsupported/);
  assert.equal(sent.length, 0);
});
