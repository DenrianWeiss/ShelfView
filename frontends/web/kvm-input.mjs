// Physical (US) keyboard mapping. KVM input is intentionally raw: IME
// composition and layout-dependent characters are not forwarded.
const SPECIAL = new Map([
  ['Backspace', 0xff08], ['Tab', 0xff09], ['Enter', 0xff0d], ['NumpadEnter', 0xff0d], ['Escape', 0xff1b],
  ['ShiftLeft', 0xffe1], ['ShiftRight', 0xffe2], ['ControlLeft', 0xffe3], ['ControlRight', 0xffe4],
  ['AltLeft', 0xffe9], ['AltRight', 0xffea], ['MetaLeft', 0xffe7], ['MetaRight', 0xffe8],
  ['OSLeft', 0xffeb], ['OSRight', 0xffec], ['CapsLock', 0xffe5], ['ContextMenu', 0xff67],
  ['Delete', 0xffff], ['Home', 0xff50], ['End', 0xff57], ['PageUp', 0xff55], ['PageDown', 0xff56],
  ['ArrowLeft', 0xff51], ['ArrowUp', 0xff52], ['ArrowRight', 0xff53], ['ArrowDown', 0xff54],
  ['Insert', 0xff63], ['Pause', 0xff13], ['ScrollLock', 0xff14], ['NumLock', 0xff7f],
  ['F1', 0xffbe], ['F2', 0xffbf], ['F3', 0xffc0], ['F4', 0xffc1], ['F5', 0xffc2], ['F6', 0xffc3],
  ['F7', 0xffc4], ['F8', 0xffc5], ['F9', 0xffc6], ['F10', 0xffc7], ['F11', 0xffc8], ['F12', 0xffc9],
]);
const PRINTABLE = new Map([
  ['Space', 0x20], ['Minus', 0x2d], ['Equal', 0x3d], ['BracketLeft', 0x5b], ['BracketRight', 0x5d],
  ['Backslash', 0x5c], ['IntlBackslash', 0x5c], ['Semicolon', 0x3b], ['Quote', 0x27], ['Backquote', 0x60],
  ['Comma', 0x2c], ['Period', 0x2e], ['Slash', 0x2f],
  ['NumpadAdd', 0xffab], ['NumpadSubtract', 0xffad], ['NumpadMultiply', 0xffaa], ['NumpadDivide', 0xffaf],
  ['NumpadDecimal', 0xffae], ['Numpad0', 0xffb0], ['Numpad1', 0xffb1], ['Numpad2', 0xffb2], ['Numpad3', 0xffb3],
  ['Numpad4', 0xffb4], ['Numpad5', 0xffb5], ['Numpad6', 0xffb6], ['Numpad7', 0xffb7], ['Numpad8', 0xffb8],
  ['Numpad9', 0xffb9],
]);
for (let code = 0; code < 26; ++code) PRINTABLE.set(`Key${String.fromCharCode(65 + code)}`, 0x61 + code);
for (let digit = 0; digit < 10; ++digit) PRINTABLE.set(`Digit${digit}`, 0x30 + digit);

export function keysymFor(event) {
  if (!event || event.isComposing === true || event.key === 'Process' || event.key === 'Unidentified') return 0;
  const code = typeof event.code === 'string' ? event.code : '';
  if (SPECIAL.has(code)) return SPECIAL.get(code);
  if (PRINTABLE.has(code)) return PRINTABLE.get(code);
  // Fallback for synthetic events without a physical code: ASCII only.
  if (!code && typeof event.key === 'string' && event.key.length === 1) {
    const point = event.key.codePointAt(0);
    if (point >= 0x20 && point <= 0x7e) return point;
  }
  return 0;
}
export function pointerMask(buttons) {
  let mask = 0;
  if (buttons & 1) mask |= 1;
  if (buttons & 2) mask |= 2;
  if (buttons & 4) mask |= 4;
  return mask;
}
function mappedPoint(canvas, event) {
  const rect = canvas.getBoundingClientRect();
  const width = canvas.width || rect.width, height = canvas.height || rect.height;
  if (!rect.width || !rect.height) return { x: 0, y: 0 };
  const x = Math.floor((event.clientX - rect.left) * width / rect.width);
  const y = Math.floor((event.clientY - rect.top) * height / rect.height);
  return { x: Math.max(0, Math.min(width - 1, x)), y: Math.max(0, Math.min(height - 1, y)) };
}
export function pastePlan(text) {
  const chars = [...text.replace(/\r\n?/g, '\n')].map(c => c.codePointAt(0));
  if (chars.some(c => c !== 9 && c !== 10 && (c < 32 || c > 126))) return null;
  return chars.map(c => c === 10 ? 0xff0d : c === 9 ? 0xff09 : c);
}
export class KvmView {
  constructor({ canvas, session, onError, mediaRenderer = null }) {
    if (!canvas || typeof canvas.getContext !== 'function') throw new Error('invalid_canvas');
    if (!session || typeof session.input?.send !== 'function') throw new Error('invalid_session');
    this.canvas = canvas; this.input = session.input; this.mediaRenderer = mediaRenderer; this.onError = onError || (() => {});
    this.context = canvas.getContext('2d');
    this.image = null; this.buttons = 0; this.active = false;
    this.keydown = (event) => this.handleKey(event, true);
    this.keyup = (event) => this.handleKey(event, false);
    this.mousemove = (event) => this.handleMouse(event);
    this.mousedown = (event) => { this.buttons = event.buttons; this.handleMouse(event); };
    this.mouseup = (event) => { this.buttons = event.buttons; this.handleMouse(event); };
    this.contextmenu = (event) => event.preventDefault();
    this.wheel = (event) => {
      if (!this.active || this.input.ready === false || this.input.supportsScroll === false || !event.deltaY) return;
      event.preventDefault();
      const point = mappedPoint(this.canvas, event);
      this.sendInput({ type: 'scroll', buttons: pointerMask(event.buttons ?? this.buttons),
        x: point.x, y: point.y, wheel: event.deltaY < 0 ? 1 : -1 });
    };
    this.blur = () => this.releaseInput();
  }
  cancelPaste() { this.pasteGeneration = (this.pasteGeneration || 0) + 1; }
  async sendChord(keys) {
    if (!this.active || this.input.ready === false) return;
    this.cancelPaste();
    const added = keys.filter(key => !this.pressedKeys?.has(key));
    if (added.length) await this.input.send({ type: 'chord', keys: added });
  }
  async slowPaste(text, interval = 50, onProgress = () => {}) {
    if (this.pasting || !this.active) return;
    if (this.input.ready === false) throw new Error('input_not_ready');
    const keys = pastePlan(text);
    if (!keys) throw new Error('paste_unsupported');
    if (!keys.length) throw new Error('clipboard_empty');
    this.cancelPaste();
    const generation = this.pasteGeneration;
    this.pasting = true;
    try {
      for (const key of this.pressedKeys || []) await this.input.send({ type: 'key', down: false, keysym: key });
      this.pressedKeys?.clear();
      for (let i = 0; i < keys.length; i++) {
        if (!this.active || this.pasteGeneration !== generation) return false;
        await this.input.send({ type: 'chord', keys: [keys[i]] });
        onProgress(i + 1, keys.length);
        if (i + 1 < keys.length) await new Promise(resolve => setTimeout(resolve, Math.max(10, Math.min(1000, Number(interval) || 50))));
      }
      return true;
    } finally { this.pasting = false; }
  }
  handleKey(event, down) {
    if (!this.active || this.input.ready === false) return;
    if (down) this.cancelPaste();
    const keysym = keysymFor(event);
    if (!keysym) return;
    event.preventDefault();
    this.pressedKeys ??= new Set();
    if (down) this.pressedKeys.add(keysym); else this.pressedKeys.delete(keysym);
    this.sendInput({ type: 'key', down, keysym });
  }
  handleMouse(event) {
    if (!this.active || this.input.ready === false) return;
    if (typeof event.buttons === 'number') this.buttons = event.buttons;
    const point = mappedPoint(this.canvas, event);
    this.lastPoint = point;
    this.sendInput({ type: 'pointer', buttons: pointerMask(this.buttons), x: point.x, y: point.y });
  }
  sendInput(event) {
    try { Promise.resolve(this.input.send(event)).catch(error => this.onError(error.message)); }
    catch (error) { this.onError(error.message); }
  }
  drawFrame(frame) {
    if (!frame) return;
    this.drawTile({ ...frame, canvasWidth: frame.width, canvasHeight: frame.height,
      x: 0, y: 0, stride: frame.stride ?? frame.width * 4, pixelFormat: 'rgba8' });
  }
  drawTile(tile) {
    const { canvasWidth, canvasHeight, x, y, width, height, stride, pixelFormat } = tile;
    if (pixelFormat !== 'rgba8') throw new Error('unsupported_pixel_format');
    if (![canvasWidth, canvasHeight, x, y, width, height, stride].every(Number.isSafeInteger) ||
        canvasWidth < 1 || canvasHeight < 1 || canvasWidth > 8192 || canvasHeight > 8192 ||
        width < 1 || height < 1 || x < 0 || y < 0 || x + width > canvasWidth || y + height > canvasHeight ||
        stride < width * 4) throw new Error('invalid_tile');
    const pixels = tile.pixels;
    if (!(pixels instanceof Uint8Array || pixels instanceof Uint8ClampedArray) ||
        pixels.length < (height - 1) * stride + width * 4) throw new Error('invalid_tile');
    if (!this.image || this.image.width !== canvasWidth || this.image.height !== canvasHeight) {
      this.canvas.width = canvasWidth; this.canvas.height = canvasHeight;
      this.image = this.context.createImageData(canvasWidth, canvasHeight);
    }
    for (let row = 0; row < height; row++) {
      this.image.data.set(pixels.subarray(row * stride, row * stride + width * 4),
        ((y + row) * canvasWidth + x) * 4);
    }
    if (this.drawPending) return;
    this.drawPending = true;
    const schedule = globalThis.requestAnimationFrame ?? (callback => callback());
    schedule(() => {
      this.drawPending = false;
      if (this.active) this.context.putImageData(this.image, 0, 0);
    });
  }
  async drawMedia(packet) {
    if (!this.mediaRenderer) throw new Error('media_stream_unsupported');
    await this.mediaRenderer.present(packet);
  }
  start() {
    if (this.active) return;
    this.active = true;
    this.canvas.tabIndex = 0;
    this.canvas.addEventListener('keydown', this.keydown);
    this.canvas.addEventListener('keyup', this.keyup);
    this.canvas.addEventListener('mousemove', this.mousemove);
    this.canvas.addEventListener('mousedown', this.mousedown);
    this.canvas.addEventListener('mouseup', this.mouseup);
    this.canvas.addEventListener('contextmenu', this.contextmenu);
    this.canvas.addEventListener('wheel', this.wheel, { passive: false });
    this.canvas.addEventListener('blur', this.blur);
  }
  releaseInput() {
    this.cancelPaste();
    for (const keysym of this.pressedKeys || []) this.sendInput({ type: 'key', down: false, keysym });
    this.pressedKeys?.clear();
    if (this.buttons) this.sendInput({ type: 'pointer', buttons: 0, x: this.lastPoint?.x ?? 0, y: this.lastPoint?.y ?? 0 });
    this.buttons = 0;
  }
  stop() {
    this.cancelPaste();
    if (!this.active) return;
    this.active = false;
    this.releaseInput();
    this.mediaRenderer?.close();
    this.canvas.removeEventListener('keydown', this.keydown);
    this.canvas.removeEventListener('keyup', this.keyup);
    this.canvas.removeEventListener('mousemove', this.mousemove);
    this.canvas.removeEventListener('mousedown', this.mousedown);
    this.canvas.removeEventListener('mouseup', this.mouseup);
    this.canvas.removeEventListener('contextmenu', this.contextmenu);
    this.canvas.removeEventListener('wheel', this.wheel);
    this.canvas.removeEventListener('blur', this.blur);
  }
}
