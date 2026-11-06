export function createConsoleDecoder({ onFrame, onSize, onName, onError, onOutput, onReady, WorkerCtor = globalThis.Worker }) {
  if (!WorkerCtor) throw new Error('kvm_worker_unavailable');
  const worker = new WorkerCtor(new URL('./kvm-decoder-worker.mjs', import.meta.url), { type: 'module' });
  let ready = false, closed = false, queued = 0, count = 0;
  const close = () => {
    if (closed) return;
    closed = true; ready = false; queued = count = 0;
    worker.terminate();
  };
  const fail = reason => {
    if (closed) return;
    close();
    onError?.(reason);
  };
  worker.addEventListener('message', ({ data }) => {
    if (closed) return;
    switch (data.type) {
    case 'output': onOutput?.(data.bytes); break;
    case 'frame':
      try { onFrame?.(data.frame); }
      finally { if (!closed) worker.postMessage({ type: 'frame-consumed' }); }
      break;
    case 'size': onSize?.(data.size); break;
    case 'name': onName?.(data.name); break;
    case 'consumed': {
      const wasReady = ready;
      queued -= data.bytes; count--; ready = data.ready;
      if (!wasReady && ready) onReady?.();
      break;
    }
    case 'error': fail(data.reason); break;
    }
  });
  worker.addEventListener('error', () => fail('kvm_decoder_error'));
  return {
    get ready() { return ready && !closed; },
    feed(data) {
      if (closed) return;
      if (!(data instanceof ArrayBuffer) || count >= 256 || queued + data.byteLength > 32 * 1024 * 1024) { fail('kvm_decoder_overloaded'); return; }
      queued += data.byteLength; count++;
      try { worker.postMessage({ type: 'feed', bytes: data }, [data]); }
      catch { fail('kvm_decoder_error'); }
    },
    close,
  };
}
