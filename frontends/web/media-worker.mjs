import { BrowserMediaSource } from './media-protocol.mjs';

let source = null;
let sourceId = null;

globalThis.onmessage = async ({ data }) => {
  try {
    if (data?.type === 'open') {
      if (typeof data.sourceId !== 'string' || !data.sourceId) throw new Error('invalid_source');
      source?.close();
      source = new BrowserMediaSource(data.file, data);
      sourceId = data.sourceId;
      globalThis.postMessage({ type: 'ready', sourceId, size: String(data.file.size) });
      return;
    }
    if (!source || data?.sourceId !== sourceId) throw new Error('invalid_source');
    if (data.type === 'close') {
      source.close(); source = null;
      globalThis.postMessage({ type: 'closed', sourceId });
      sourceId = null;
      return;
    }
    if (data.type !== 'frame') throw new Error('invalid_message');
    const activeId = sourceId;
    const response = await source.handleFrame(data.frame);
    if (response !== null) globalThis.postMessage({ type: 'frame', sourceId: activeId, frame: response }, [response]);
  } catch {
    source?.close(); source = null;
    globalThis.postMessage({ type: 'error', sourceId, error: 'media_protocol_error' });
    sourceId = null;
  }
};
