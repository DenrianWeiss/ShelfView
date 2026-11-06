export class KvmInputStream {
  constructor(send, onError = () => {}) {
    this.sendEvent = send; this.onError = onError;
    this.tail = Promise.resolve(); this.pending = 0; this.closed = false; this.failure = null;
  }
  send(event) {
    if (this.closed) return Promise.reject(this.failure ?? new Error('input_closed'));
    if (this.pending >= 1024) {
      this.failure = new Error('input_overloaded'); this.closed = true;
      this.onError(this.failure.message);
      return Promise.reject(this.failure);
    }
    const copy = { ...event, ...(event.keys ? { keys: [...event.keys] } : {}) };
    this.pending++;
    const sent = this.tail.then(async () => {
      if (this.failure) throw this.failure;
      await this.sendEvent(copy);
    });
    this.tail = sent.catch(error => {
      if (!this.failure) {
        this.failure = error; this.closed = true; this.onError(error.message);
      }
    }).finally(() => { this.pending--; });
    return sent;
  }
  close() { this.closed = true; return this.tail; }
}
