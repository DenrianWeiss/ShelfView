export const HEADER_SIZE = 40;
export const OP = Object.freeze({ READ: 1, DATA: 2, ERROR: 3, CANCEL: 4, CLOSE: 5 });
const U64_MAX = (1n << 64n) - 1n;

export class MediaProtocolError extends Error {}

function check(condition, message) {
  if (!condition) throw new MediaProtocolError(message);
}

export function encodeFrame({ opcode, channel, requestId, offset = 0n }, payload = new Uint8Array()) {
  check(Number.isInteger(opcode) && opcode >= 1 && opcode <= 5, 'Invalid opcode');
  check(Number.isInteger(channel) && channel > 0 && channel <= 0xffffffff, 'Invalid channel');
  check(typeof requestId === 'bigint' && requestId > 0n && requestId <= U64_MAX, 'Invalid request ID');
  check(typeof offset === 'bigint' && offset >= 0n && offset <= U64_MAX, 'Invalid offset');
  check(payload instanceof Uint8Array && payload.byteLength <= 1048576, 'Invalid payload');
  const buffer = new ArrayBuffer(HEADER_SIZE + payload.byteLength);
  const bytes = new Uint8Array(buffer), view = new DataView(buffer);
  bytes.set([66, 67, 84, 76]);
  view.setUint16(4, 1);
  view.setUint16(6, opcode);
  view.setUint32(8, channel);
  view.setBigUint64(16, requestId);
  view.setBigUint64(24, offset);
  view.setUint32(32, payload.byteLength);
  bytes.set(payload, HEADER_SIZE);
  return buffer;
}

export function decodeFrame(buffer, maxPayload = 1048576) {
  check(buffer instanceof ArrayBuffer && buffer.byteLength >= HEADER_SIZE, 'Truncated frame');
  const view = new DataView(buffer), bytes = new Uint8Array(buffer);
  check(bytes[0] === 66 && bytes[1] === 67 && bytes[2] === 84 && bytes[3] === 76, 'Invalid magic');
  check(view.getUint16(4) === 1, 'Unsupported version');
  const opcode = view.getUint16(6), channel = view.getUint32(8);
  const requestId = view.getBigUint64(16), offset = view.getBigUint64(24), length = view.getUint32(32);
  check(opcode >= 1 && opcode <= 5 && channel !== 0 && requestId !== 0n, 'Invalid header');
  check(view.getUint32(12) === 0 && view.getUint32(36) === 0, 'Reserved bits set');
  check(length <= maxPayload && buffer.byteLength === HEADER_SIZE + length, 'Invalid payload length');
  return { opcode, channel, requestId, offset, payload: bytes.subarray(HEADER_SIZE) };
}

export class BrowserMediaSource {
  #file; #channel; #maxBlock; #window; #pending = new Map(); #closed = false; #last = 0n;

  constructor(file, { channel, maxBlock = 1048576, window = 8 }) {
    check(file && typeof file.slice === 'function' && Number.isSafeInteger(file.size) && file.size >= 0, 'Invalid browser file');
    check(Number.isInteger(channel) && channel > 0 && channel <= 0xffffffff, 'Invalid channel');
    check(Number.isInteger(maxBlock) && maxBlock > 0 && maxBlock <= 1048576, 'Invalid block limit');
    check(Number.isInteger(window) && window > 0 && window <= 8, 'Invalid window');
    this.#file = file; this.#channel = channel; this.#maxBlock = maxBlock; this.#window = window;
  }

  close() {
    this.#closed = true;
    for (const task of this.#pending.values()) task.cancelled = true;
  }

  async handleFrame(buffer) {
    check(!this.#closed, 'Source closed');
    const frame = decodeFrame(buffer, 4);
    check(frame.channel === this.#channel, 'Wrong source channel');
    if (frame.opcode === OP.CANCEL || frame.opcode === OP.CLOSE) {
      check(frame.payload.length === 0, 'Invalid control payload');
      if (frame.opcode === OP.CLOSE) this.close();
      else {
        const task = this.#pending.get(frame.requestId);
        if (task) task.cancelled = true;
      }
      return null;
    }
    check(frame.opcode === OP.READ && frame.payload.length === 4, 'Expected READ');
    check(frame.requestId > this.#last, 'Reused or reordered request ID');
    this.#last = frame.requestId;
    const length = new DataView(frame.payload.buffer, frame.payload.byteOffset, 4).getUint32(0);
    const error = (code) => encodeFrame({ ...frame, opcode: OP.ERROR }, new TextEncoder().encode(JSON.stringify({ error: code })));
    const size = BigInt(this.#file.size);
    if (!length || length > this.#maxBlock || frame.offset > size || BigInt(length) > size - frame.offset)
      return error('invalid_range');
    if (this.#pending.size >= this.#window) return error('window_exceeded');
    const task = { cancelled: false };
    this.#pending.set(frame.requestId, task);
    try {
      const start = Number(frame.offset);
      const data = await this.#file.slice(start, start + length).arrayBuffer();
      if (this.#closed || task.cancelled) return null;
      if (!(data instanceof ArrayBuffer) || data.byteLength !== length) return error('short_read');
      return encodeFrame({ ...frame, opcode: OP.DATA }, new Uint8Array(data));
    } catch {
      return this.#closed || task.cancelled ? null : error('source_read_failed');
    } finally {
      this.#pending.delete(frame.requestId);
    }
  }
}
