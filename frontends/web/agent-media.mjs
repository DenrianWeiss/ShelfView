export async function publishFile({ agentOrigin, token, file, createWorker, timeoutMs = 10000, fetchImpl = fetch, WebSocketCtor = globalThis.WebSocket }) {
  const origin = new URL(agentOrigin);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/')
    throw new Error('invalid_agent_origin');
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token) || !file || !Number.isSafeInteger(file.size) || file.size < 0 || typeof file.slice !== 'function')
    throw new Error('invalid_media_source');
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) throw new Error('invalid_timeout');
  const response = await fetchImpl(new URL('/v1/media/tickets', origin), {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: typeof file.name === 'string' ? file.name : 'disk-image', size: String(file.size) }),
    signal: AbortSignal.timeout(timeoutMs), redirect: 'error',
  });
  if (!response.ok) throw new Error('media_ticket_rejected');
  const ticket = await response.json();
  if (typeof ticket.source_id !== 'string' || !/^[0-9a-f]{32}$/.test(ticket.source_id) ||
      typeof ticket.ticket !== 'string' || !/^[0-9a-f]{64}$/.test(ticket.ticket) || ticket.size !== String(file.size) ||
      !Number.isInteger(ticket.channel) || ticket.channel <= 0 || ticket.channel > 0xffffffff ||
      !Number.isInteger(ticket.max_block) || ticket.max_block < 1 || ticket.max_block > 1048576 ||
      !Number.isInteger(ticket.window) || ticket.window < 1 || ticket.window > 8 || ticket.websocket_path !== '/v1/media/ws')
    throw new Error('invalid_media_ticket');
  const wsURL = new URL(ticket.websocket_path, origin);
  wsURL.protocol = origin.protocol === 'https:' ? 'wss:' : 'ws:';
  const revoke = async () => {
    try {
      const result = await fetchImpl(new URL('/v1/media/sources/' + ticket.source_id, origin), {
        method: 'DELETE', headers: { Authorization: `Bearer ${token}` }, redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      return result.ok || result.status === 404;
    } catch { return false; }
  };
  let worker, socket;
  try {
    worker = createWorker ? createWorker() : new Worker(new URL('./media-worker.mjs', import.meta.url), { type: 'module' });
    socket = new WebSocketCtor(wsURL);
  } catch (error) {
    worker?.terminate();
    const cleanupConfirmed = await revoke();
    throw Object.assign(new Error('media_channel_unavailable'), { cause: error, cleanupConfirmed });
  }
  socket.binaryType = 'arraybuffer';
  let finishClosed;
  const closed = new Promise((resolve) => { finishClosed = resolve; });
  return new Promise((resolve, reject) => {
    let done = false, published = false, serverReady = false;
    const timer = setTimeout(() => cleanup('authentication_timeout'), timeoutMs);
    const cleanup = (reason) => {
      if (done) return;
      done = true; clearTimeout(timer);
      worker.terminate();
      if (socket.readyState < 2) socket.close();
      revoke().then(cleanupConfirmed => {
        finishClosed({ sourceId: ticket.source_id, reason, cleanupConfirmed });
        if (!published) reject(Object.assign(new Error(reason), { cleanupConfirmed }));
      });
    };
    worker.addEventListener('error', () => cleanup('worker_error'));
    worker.addEventListener('message', ({ data }) => {
      if (done) return;
      if (data?.sourceId !== ticket.source_id || data.type === 'error') { cleanup('worker_protocol_error'); return; }
      if (data.type === 'ready' && serverReady && !published && data.size === ticket.size) {
        clearTimeout(timer); published = true;
        resolve({ sourceId: ticket.source_id, channel: ticket.channel, closed, close: () => { cleanup('closed'); return closed; } });
      } else if (data.type === 'frame' && serverReady && data.frame instanceof ArrayBuffer &&
                 data.frame.byteLength <= ticket.max_block + 40 && socket.readyState === 1 &&
                 socket.bufferedAmount + data.frame.byteLength <= (ticket.max_block + 40) * ticket.window) {
        socket.send(data.frame);
      } else cleanup('media_backpressure_or_protocol_error');
    });
    socket.addEventListener('open', () => {
      if (done) return;
      socket.send(JSON.stringify({ ticket: ticket.ticket }));
      ticket.ticket = '';
    });
    socket.addEventListener('message', ({ data }) => {
      if (done) return;
      if (!serverReady) {
        let ready;
        try { ready = typeof data === 'string' ? JSON.parse(data) : null; } catch { ready = null; }
        if (!ready || ready.type !== 'ready' || ready.source_id !== ticket.source_id || ready.channel !== ticket.channel ||
            ready.size !== ticket.size || ready.max_block !== ticket.max_block || ready.window !== ticket.window) {
          cleanup('invalid_media_authentication'); return;
        }
        serverReady = true;
        worker.postMessage({ type: 'open', sourceId: ticket.source_id, file, channel: ticket.channel, maxBlock: ticket.max_block, window: ticket.window });
      } else if (data instanceof ArrayBuffer && data.byteLength <= ticket.max_block + 40) {
        worker.postMessage({ type: 'frame', sourceId: ticket.source_id, frame: data }, [data]);
      } else cleanup('invalid_media_message');
    });
    socket.addEventListener('close', () => cleanup('connection_closed'));
    socket.addEventListener('error', () => cleanup('connection_error'));
  });
}
