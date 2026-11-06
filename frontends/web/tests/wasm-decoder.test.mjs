import assert from 'node:assert/strict';
import test from 'node:test';
import { createConsoleDecoder } from '../generated/console-decoder.mjs';

const bytes = (...values) => Uint8Array.from(values.flat());
async function clientFixture(t) {
  const frames = [], sizes = [], names = [], errors = [], output = [];
  const decoder = await createConsoleDecoder({ onFrame: f => frames.push(f), onSize: s => sizes.push(s),
    onName: n => names.push(n), onOutput: b => output.push(...b) });
  t.after(() => decoder.close());
  const rfb = {
    feed(bytes) { try { decoder.feed(bytes); } catch (error) { errors.push(error.status ?? error.message); } },
    takeOutput() { const result = Uint8Array.from(output); output.length = 0; return result; },
    get width() { return decoder.width; }, get height() { return decoder.height; },
    get ready() { return decoder.ready; },
  };
  return { rfb, frames, sizes, names, errors };
}
function handshake(rfb, name = 'kvm') {
  rfb.feed(new TextEncoder().encode('RFB 003.008\n'));
  assert.deepEqual([...rfb.takeOutput()], [...new TextEncoder().encode('RFB 003.008\n')]);
  rfb.feed(bytes([1, 1])); assert.deepEqual([...rfb.takeOutput()], [1]);
  rfb.feed(bytes([0, 0, 0, 0])); assert.deepEqual([...rfb.takeOutput()], [1]);
  const init = new Uint8Array(24);
  init[1] = 2; init[3] = 2; init[4] = 32; init[5] = 24; init[7] = 1;
  init[9] = 255; init[11] = 255; init[13] = 255; init[14] = 16; init[15] = 8;
  init[20] = 0; init[21] = 0; init[22] = 0; init[23] = name.length;
  rfb.feed(init); rfb.feed(new TextEncoder().encode(name));
  const output = rfb.takeOutput();
  assert.equal(output[0], 2); assert.equal(output.length, 20 + 10);
  return output;
}
test('handshake, raw frame and resize', async t => {
  const { rfb, frames, sizes, names, errors } = await clientFixture(t);
  handshake(rfb);
  assert.equal(rfb.width, 2); assert.equal(rfb.height, 2);
  assert.deepEqual(sizes, [{ width: 2, height: 2 }]); assert.deepEqual(names, ['kvm']);
  const update = new Uint8Array(16); update[3] = 1; update[9] = 2; update[11] = 2;
  const pixels = bytes([0, 0, 255, 0], [0, 255, 0, 0], [255, 0, 0, 0], [255, 255, 255, 0]);
  rfb.feed(update); rfb.feed(pixels);
  assert.equal(frames.length, 1);
  assert.deepEqual([...frames[0].pixels], [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255]);
  const resize = new Uint8Array(16); resize[3] = 1; resize[9] = 3; resize[11] = 1;
  new DataView(resize.buffer).setInt32(12, -223);
  rfb.feed(resize);
  assert.equal(rfb.width, 3); assert.equal(rfb.height, 1);
  assert.equal(rfb.takeOutput()[0], 3);
  assert.deepEqual(errors, []);
});
test('copyrect copies existing pixels', async t => {
  const { rfb, frames, errors } = await clientFixture(t);
  handshake(rfb);
  const update = new Uint8Array(16); update[3] = 1; update[9] = 2; update[11] = 2;
  const pixels = bytes([0, 0, 255, 0], [0, 255, 0, 0], [255, 0, 0, 0], [255, 255, 255, 0]);
  rfb.feed(update); rfb.feed(pixels);
  const rect = new Uint8Array(20); rect[3] = 1;
  const rectView = new DataView(rect.buffer);
  rectView.setUint16(8, 1); rectView.setUint16(10, 1);
  rectView.setInt32(12, 1);
  rectView.setUint16(16, 1); rectView.setUint16(18, 1);
  rfb.feed(rect);
  assert.equal(frames.length, 2);
  assert.deepEqual([...frames[1].pixels.slice(0, 8)], [255, 255, 255, 255, 0, 255, 0, 255]);
  assert.deepEqual(errors, []);
});

test('hextile background and subrect', async t => {
  const { rfb, frames, errors } = await clientFixture(t);
  handshake(rfb);
  const frame = new Uint8Array(16 + 1 + 4 + 4 + 1 + 4 + 2);
  frame[3] = 1;
  frame[9] = 2; frame[11] = 2;
  new DataView(frame.buffer).setInt32(12, 5);
  frame[16] = 30;
  new DataView(frame.buffer).setUint32(17, 0x000000FF, true);
  frame[25] = 1;
  new DataView(frame.buffer).setUint32(26, 0x00FF0000, true);
  frame[30] = 0; frame[31] = 0x11;
  rfb.feed(frame);
  assert.equal(frames.length, 1);
  assert.deepEqual([...frames[0].pixels.slice(0, 8)], [255, 0, 0, 255, 255, 0, 0, 255]);
  assert.deepEqual(errors, []);
});

test('fragmented updates and unsupported security', async t => {
  const first = await clientFixture(t); handshake(first.rfb);
  const update = new Uint8Array(16); update[3] = 1; update[9] = 2; update[11] = 2;
  first.rfb.feed(update.subarray(0, 8)); first.rfb.feed(update.subarray(8));
  first.rfb.feed(bytes([0, 0, 255, 0], [0, 255, 0, 0]));
  first.rfb.feed(bytes([255, 0, 0, 0], [255, 255, 255, 0]));
  assert.equal(first.frames.length, 1);
  const second = await clientFixture(t);
  second.rfb.feed(new TextEncoder().encode('RFB 003.008\n')); second.rfb.takeOutput();
  second.rfb.feed(bytes([1, 2]));
  assert.deepEqual(second.errors, [4]);
});

test('legacy RFB None security uses version-specific handshakes', async t => {
  for (const minor of [3, 5, 7]) {
    const { rfb: client } = await clientFixture(t);
    const version = `RFB 003.${String(minor).padStart(3, '0')}\n`;
    for (const byte of new TextEncoder().encode(version)) client.feed(Uint8Array.of(byte));
    assert.equal(new TextDecoder().decode(client.takeOutput()), minor === 7 ? 'RFB 003.007\n' : 'RFB 003.003\n');
    client.feed(Uint8Array.from(minor === 7 ? [1, 1] : [0, 0, 0, 1]));
    assert.deepEqual([...client.takeOutput()], minor === 7 ? [1, 1] : [1]);
    assert.equal(client.ready, false);
  }
});
