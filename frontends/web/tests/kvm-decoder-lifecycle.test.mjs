import assert from 'node:assert/strict';
import test from 'node:test';
import { createConsoleDecoder } from '../kvm-decoder.mjs';
import { connectKvm } from '../agent-kvm.mjs';

class WorkerStub {
  static current;
  listeners = new Map();
  messages = [];
  terminated = 0;
  constructor() { WorkerStub.current = this; }
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  postMessage(message) { this.messages.push(message); }
  terminate() { this.terminated++; }
  emit(data) { this.listeners.get('message')({ data }); }
}

test('a failed decoder startup closes the connecting KVM socket', async () => {
  let socket;
  class Socket {
    readyState = 0;
    closed = 0;
    constructor() { socket = this; }
    close() { this.closed++; this.readyState = 3; }
  }
  class UnavailableWorker { constructor() { throw new Error('worker blocked'); } }
  await assert.rejects(connectKvm({ agentOrigin: 'http://127.0.0.1:8445', token: 'b'.repeat(64),
    WebSocketCtor: Socket, WorkerCtor: UnavailableWorker,
    fetchImpl: async () => ({ ok: true, json: async () => ({ ticket: 'a'.repeat(64),
      websocket_path: '/v1/kvm/ws', input_version: 1 }) }),
  }), /kvm_worker_unavailable/);
  assert.equal(socket.closed, 1);
});

test('decoder overflow is terminal and reports once even when worker events arrive late', () => {
  const errors = [], frames = [];
  const decoder = createConsoleDecoder({ WorkerCtor: WorkerStub,
    onError: error => errors.push(error), onFrame: frame => frames.push(frame) });
  const worker = WorkerStub.current;
  for (let i = 0; i < 257; i++) decoder.feed(new ArrayBuffer(1));
  decoder.feed(new ArrayBuffer(1));
  worker.emit({ type: 'consumed', bytes: 1, ready: true });
  worker.emit({ type: 'frame', frame: {} });
  worker.listeners.get('error')({});
  decoder.close();
  assert.equal(worker.messages.length, 256);
  assert.equal(worker.terminated, 1);
  assert.deepEqual(errors, ['kvm_decoder_overloaded']);
  assert.deepEqual(frames, []);
  assert.equal(decoder.ready, false);
});

test('worker and transfer failures release the decode lane', () => {
  for (const transferFailure of [false, true]) {
    const errors = [];
    const decoder = createConsoleDecoder({ WorkerCtor: WorkerStub, onError: error => errors.push(error) });
    const worker = WorkerStub.current;
    if (transferFailure) {
      worker.postMessage = () => { throw new Error('transfer failed'); };
      decoder.feed(new ArrayBuffer(1));
    } else worker.emit({ type: 'error', reason: 'kvm_decoder_error' });
    decoder.close();
    assert.equal(worker.terminated, 1);
    assert.deepEqual(errors, ['kvm_decoder_error']);
  }
});
