import createModule from './bcontrol-decoder.mjs';

export async function createConsoleDecoder(callbacks = {}, options = {}) {
  const module = await createModule(options);
  return new ConsoleDecoder(module, callbacks);
}

class ConsoleDecoder {
  constructor(module, callbacks) {
    this.module = module;
    this.callbacks = callbacks;
    this.width = 0; this.height = 0; this.named = false;
    this.handle = module._bc_web_decoder_create();
    if (!this.handle) throw new Error('kvm_decoder_memory');
    this.output = module._malloc(8192);
    this.written = module._malloc(4);
    if (!this.output || !this.written) { this.close(); throw new Error('kvm_decoder_memory'); }
  }
  get ready() { return !!this.handle && !!this.module._bc_web_decoder_ready(this.handle); }
  check(status) {
    if (status === 0) return;
    const error = new Error('kvm_decoder_error'); error.status = status; throw error;
  }
  feed(bytes) {
    if (!this.handle) throw new Error('kvm_decoder_closed');
    if (!(bytes instanceof Uint8Array) || bytes.length > 32 * 1024 * 1024) throw new Error('kvm_decoder_overloaded');
    if (!bytes.length) return;
    const m = this.module, input = m._malloc(bytes.length);
    if (!input) throw new Error('kvm_decoder_memory');
    try {
      m.HEAPU8.set(bytes, input);
      this.check(m._bc_web_decoder_feed(this.handle, input, bytes.length));
    } finally { m._free(input); }
    for (;;) {
      this.check(m._bc_web_decoder_output(this.handle, this.output, 8192, this.written));
      const count = m.HEAPU32[this.written >>> 2];
      if (!count) break;
      this.callbacks.onOutput?.(m.HEAPU8.slice(this.output, this.output + count));
    }
    const width = m._bc_web_decoder_width(this.handle), height = m._bc_web_decoder_height(this.handle);
    if (width && height && (width !== this.width || height !== this.height)) {
      this.width = width; this.height = height;
      this.callbacks.onSize?.({ width, height });
    }
    if (this.ready && !this.named) {
      this.named = true;
      const pointer = m._bc_web_decoder_name(this.handle), length = m._bc_web_decoder_name_length(this.handle);
      this.callbacks.onName?.(new TextDecoder().decode(m.HEAPU8.subarray(pointer, pointer + length)));
    }
    const status = m._bc_web_decoder_tile(this.handle);
    if (status === 3) return;
    this.check(status);
    try {
      const stride = m._bc_web_decoder_stride(this.handle), pointer = m._bc_web_decoder_pixels(this.handle);
      const pixels = m.HEAPU8.slice(pointer, pointer + stride * height);
      this.callbacks.onFrame?.({ width, height, stride, pixels });
    } finally { m._bc_web_decoder_ack(this.handle); }
  }
  close() {
    const m = this.module;
    if (this.handle) m._bc_web_decoder_destroy(this.handle);
    if (this.output) m._free(this.output);
    if (this.written) m._free(this.written);
    this.handle = this.output = this.written = 0;
  }
}
