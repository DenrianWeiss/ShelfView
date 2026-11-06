import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserWorker } from './browser-worker.mjs';
import { connectKvm } from '../agent-kvm.mjs';

class FakeSocket {
  static instances = [];
  constructor(url) {
    this.url = url; this.readyState = 0; this.sent = []; this.listeners = new Map();
    FakeSocket.instances.push(this);
    queueMicrotask(() => { this.readyState = 1; this.emit('open', {}); });
  }
  addEventListener(name, handler) {
    if (!this.listeners.has(name)) this.listeners.set(name, []);
    this.listeners.get(name).push(handler);
  }
  emit(name, event) { for (const handler of this.listeners.get(name) || []) handler(event); }
  send(data) { this.sent.push(data); }
  message(data) { this.emit('message', { data }); }
  close() { this.readyState = 3; this.emit('close', {}); }
}

const TICKET = 'a'.repeat(64);
const fetchTicket = async () => ({ ok: true, json: async () => ({ ticket: TICKET, websocket_path: '/v1/kvm/ws', input_version: 1 }) });

test('ticket authentication and RFB wiring', { timeout: 10000 }, async t => {
  FakeSocket.instances = [];
  const frames = []; const errors = [];
  let resolveFrame, rejectFrame;
  const received = new Promise((resolve, reject) => { resolveFrame = resolve; rejectFrame = reject; });
  const session = await connectKvm({
    agentOrigin: 'http://127.0.0.1:8445', token: 'b'.repeat(64), WebSocketCtor: FakeSocket, WorkerCtor: BrowserWorker,
    fetchImpl: fetchTicket, onFrame: frame => { frames.push(frame); resolveFrame(); }, onError: error => { errors.push(error); rejectFrame(new Error(error)); },
  });
  t.after(() => session.close());
  const socket = FakeSocket.instances[0];
  assert.equal(String(socket.url), 'ws://127.0.0.1:8445/v1/kvm/ws');
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(JSON.parse(socket.sent[0]), { ticket: TICKET });
  socket.message(JSON.stringify({ type: 'ready', input_capabilities: 1 }));
  assert.equal(session.input.supportsScroll, true);
  const encoder = new TextEncoder();
  socket.message(encoder.encode('RFB 003.008\n').buffer);
  socket.message(new Uint8Array([1, 1]).buffer);
  socket.message(new Uint8Array([0, 0, 0, 0]).buffer);
  const init = new Uint8Array(24); init[1] = 2; init[3] = 2; init[4] = 32; init[5] = 24; init[23] = 1;
  socket.message(init.buffer); socket.message(new Uint8Array([0x6b]).buffer);
  const update = new Uint8Array(16); update[3] = 1; update[9] = 2; update[11] = 2;
  socket.message(update.buffer);
  socket.message(Uint8Array.from([0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0]).buffer);
  await received;
  assert.equal(frames.length, 1);
  assert.deepEqual([...frames[0].pixels], [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255]);
  assert.ok(socket.sent.some((part) => part instanceof Uint8Array && part.length === 50 && part[40] === 3));
  assert.deepEqual(errors, []);
  await session.input.send({ type: 'chord', keys: [0xffe3, 0xffff] });
  await session.input.send({ type: 'scroll', x: 1, y: 1, buttons: 2, wheel: -1 });
  assert.deepEqual(socket.sent.slice(-2).map(JSON.parse), [
    { type: 'input', event: { type: 'chord', keys: [0xffe3, 0xffff] } },
    { type: 'input', event: { type: 'scroll', x: 1, y: 1, buttons: 2, wheel: -1, width: 2, height: 2 } },
  ]);
  await session.close();
  assert.equal(session.input.supportsScroll, false);
});
