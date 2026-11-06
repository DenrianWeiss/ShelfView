let awaitingFrame = false, latestFrame = null, decodedFrame = null, failed = false;
function publishFrame(frame) {
  if (awaitingFrame) { latestFrame = frame; return; }
  awaitingFrame = true;
  postMessage({ type: 'frame', frame }, [frame.pixels.buffer]);
}
const loaded = import('./generated/console-decoder.mjs').then(({ createConsoleDecoder }) =>
  createConsoleDecoder({
    onFrame: frame => { decodedFrame = frame; },
    onSize: size => postMessage({ type: 'size', size }),
    onName: name => postMessage({ type: 'name', name }),
    onOutput: bytes => postMessage({ type: 'output', bytes }, [bytes.buffer]),
  }));
let decoder;
function fail() {
  if (failed) return;
  failed = true; decoder?.close();
  latestFrame = decodedFrame = null;
  postMessage({ type: 'error', reason: 'kvm_decoder_error' });
}
let pending = loaded.then(value => { decoder = value; }).catch(fail);
self.addEventListener('message', ({ data }) => {
  if (failed) return;
  if (data.type === 'frame-consumed') {
    awaitingFrame = false;
    if (latestFrame) { const frame = latestFrame; latestFrame = null; publishFrame(frame); }
    return;
  }
  if (data.type !== 'feed' || !(data.bytes instanceof ArrayBuffer)) return;
  pending = pending.then(() => {
    if (failed) return;
    decoder.feed(new Uint8Array(data.bytes));
    postMessage({ type: 'consumed', bytes: data.bytes.byteLength, ready: decoder.ready });
    if (decodedFrame) { const frame = decodedFrame; decodedFrame = null; publishFrame(frame); }
  }).catch(fail);
});
