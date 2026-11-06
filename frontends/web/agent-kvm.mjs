import { createConsoleDecoder } from './kvm-decoder.mjs';
import { KvmInputStream } from './kvm-streams.mjs';
export async function connectKvm({ agentOrigin, token, onFrame, onSize, onName, onError, WebSocketCtor = WebSocket,
  fetchImpl = fetch, timeoutMs = 10000, WorkerCtor = globalThis.Worker }) {
  const origin = new URL(agentOrigin);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password || origin.search ||
      origin.hash || origin.pathname !== '/') throw new Error('invalid_agent_origin');
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) throw new Error('invalid_token');
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) throw new Error('invalid_timeout');
  if (!WorkerCtor) throw new Error('kvm_worker_unavailable');
  const started = performance.now();
  const response = await fetchImpl(new URL('/v1/kvm/tickets', origin), {
    method: 'POST', headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(timeoutMs), redirect: 'error',
  });
  if (!response.ok) throw new Error('kvm_ticket_rejected');
  const ticket = await response.json();
  if (typeof ticket.ticket !== 'string' || !/^[0-9a-f]{64}$/.test(ticket.ticket) || ticket.websocket_path !== '/v1/kvm/ws')
    throw new Error('invalid_kvm_ticket');
  if (ticket.input_version !== 1) throw new Error('kvm_input_unsupported');
  if (ticket.management_device_id !== undefined &&
      (typeof ticket.management_device_id !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(ticket.management_device_id)))
    throw new Error('invalid_kvm_ticket');
  const remaining = timeoutMs - (performance.now() - started);
  if (remaining <= 0) throw new Error('kvm_connection_timeout');
  const wsURL = new URL(ticket.websocket_path, origin);
  wsURL.protocol = origin.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocketCtor(wsURL);
  socket.binaryType = 'arraybuffer';
  let decoder;
  let ready = false, finished = false, width = 0, height = 0, inputCapabilities = 0;
  let handshakeTimer;
  let finishClosed;
  const closed = new Promise((resolve) => { finishClosed = resolve; });
  const fail = (reason) => {
    if (finished) return;
    finished = true; clearTimeout(handshakeTimer); decoder?.close();
    if (socket.readyState < 2) socket.close();
    finishClosed({ reason });
    if (onError) onError(reason);
  };
  try {
    decoder = createConsoleDecoder({ WorkerCtor, onFrame, onSize: size => {
      width = size.width; height = size.height; onSize?.(size);
    }, onName, onError: fail,
      onReady: () => clearTimeout(handshakeTimer),
      onOutput: bytes => { if (!finished && socket.readyState === 1) socket.send(bytes); } });
  } catch (error) {
    finished = true;
    if (socket.readyState < 2) socket.close();
    throw new Error('kvm_worker_unavailable', { cause: error });
  }
  handshakeTimer = setTimeout(() => fail('kvm_connection_timeout'), remaining);
  socket.addEventListener('open', () => {
    if (finished) return;
    socket.send(JSON.stringify({ ticket: ticket.ticket }));
    ticket.ticket = '';
  });
  socket.addEventListener('message', ({ data }) => {
    if (finished) return;
    if (!ready) {
      let message = null;
      try { message = typeof data === 'string' ? JSON.parse(data) : null; } catch { message = null; }
      if (!message || message.type !== 'ready') { fail('kvm_authentication_failed'); return; }
      const capabilities = message.input_capabilities ?? 0;
      if (!Number.isInteger(capabilities) || capabilities < 0 || capabilities > 0xffffffff) {
        fail('kvm_message_protocol_error'); return;
      }
      inputCapabilities = capabilities;
      ready = true; return;
    }
    if (!(data instanceof ArrayBuffer)) { fail('kvm_message_protocol_error'); return; }
    decoder.feed(data);
  });
  socket.addEventListener('close', () => { clearTimeout(handshakeTimer); decoder.close(); if (!finished) { finished = true; finishClosed({ reason: 'closed' }); } });
  socket.addEventListener('error', () => fail('kvm_connection_error'));
  const input = new KvmInputStream(async event => {
    if (finished || !ready || socket.readyState !== 1 || !decoder.ready) throw new Error('input_not_ready');
    if (socket.bufferedAmount > 1024 * 1024) throw new Error('input_overloaded');
    const uint = value => Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
    let payload;
    switch (event.type) {
    case 'key':
      if (!uint(event.keysym) || typeof event.down !== 'boolean') throw new Error('invalid_key');
      payload = { type: 'key', keysym: event.keysym, down: event.down }; break;
    case 'pointer': case 'scroll':
      if (!width || !height || !uint(event.x) || !uint(event.y) || !uint(event.buttons) || event.buttons > 7)
        throw new Error('invalid_pointer');
      payload = { type: event.type, buttons: event.buttons, x: Math.min(event.x, width - 1),
        y: Math.min(event.y, height - 1), width, height };
      if (event.type === 'scroll') {
        if (!(inputCapabilities & 1)) throw new Error('input_unsupported');
        if (!Number.isInteger(event.wheel) || event.wheel < -127 || event.wheel > 127) throw new Error('invalid_pointer');
        payload.wheel = event.wheel;
      }
      break;
    case 'chord':
      if (!Array.isArray(event.keys) || !event.keys.length || event.keys.length > 8 || !event.keys.every(uint))
        throw new Error('invalid_chord');
      payload = { type: 'chord', keys: event.keys }; break;
    default: throw new Error('invalid_input_event');
    }
    socket.send(JSON.stringify({ type: 'input', event: payload }));
  }, fail);
  Object.defineProperty(input, 'ready', { get: () => !finished && ready && decoder.ready });
  Object.defineProperty(input, 'supportsScroll', { get: () => !finished && (inputCapabilities & 1) !== 0 });
  return {
    closed, input, managementDeviceId: ticket.management_device_id ?? null,
    close: async () => {
      await input.close();
      clearTimeout(handshakeTimer);
      decoder.close();
      if (!finished) { finished = true; socket.close(); finishClosed({ reason: 'closed' }); }
    },
  };
}
