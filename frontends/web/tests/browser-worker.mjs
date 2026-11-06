import { Worker } from 'node:worker_threads';

export class BrowserWorker {
  constructor(url) {
    this.worker = new Worker(`
      const { parentPort } = require('node:worker_threads');
      globalThis.postMessage = (data, transfer) => parentPort.postMessage(data, transfer);
      globalThis.self = { addEventListener: (_, handler) => parentPort.on('message', data => handler({ data })) };
      import(${JSON.stringify(url.href)});
    `, { eval: true });
  }
  addEventListener(name, handler) {
    this.worker.on(name, data => handler(name === 'message' ? { data } : data));
  }
  postMessage(data, transfer) { this.worker.postMessage(data, transfer); }
  terminate() { this.worker.terminate(); }
}
