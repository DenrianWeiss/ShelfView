import assert from 'node:assert/strict';
import test from 'node:test';
import { agentOrigin, reconnectDelay, initKvmPage } from '../kvm-page.mjs';

test('agent origin validation', () => {
  assert.equal(agentOrigin('http://127.0.0.1:8445/'), 'http://127.0.0.1:8445');
  assert.equal(agentOrigin('https://agent.example'), 'https://agent.example');
  for (const value of ['ftp://host', 'http://user:pass@host/', 'http://host/path', 'http://host/?x=1', 'http://host/#x'])
    assert.throws(() => agentOrigin(value));
});

test('reconnect backoff grows and caps', () => {
  assert.equal(reconnectDelay(1), 500);
  assert.equal(reconnectDelay(2), 1000);
  assert.equal(reconnectDelay(3), 2000);
  assert.equal(reconnectDelay(10), 5000);
});

function page(options) {
  const elements = new Map();
  const document = { querySelector(selector) {
    if (!elements.has(selector)) elements.set(selector, {
      value: '', disabled: false, textContent: '', listeners: {},
      addEventListener(type, handler) { this.listeners[type] = handler; },
      fire(type) { return this.listeners[type]?.({ preventDefault() {} }); },
      focus() {},
      showModal() { this.open = true; },
      close() { this.open = false; this.listeners.close?.(); },
    });
    return elements.get(selector);
  } };
  initKvmPage(document, options);
  return selector => document.querySelector(`#kvm-${selector}`);
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

test('disconnect cancels pending pairing without starting a viewer session', async () => {
  const pairing = deferred();
  let connections = 0;
  const element = page({ pair: () => pairing.promise, connect: () => { connections++; } });
  element('agent').value = 'https://first.example';
  const submitted = element('connect').fire('submit');
  element('disconnect').fire('click');
  pairing.resolve({ token: 'first-token' });
  await submitted;
  assert.equal(connections, 0);
  assert.equal(element('agent').disabled, false);
  assert.equal(element('connect-button').disabled, false);
});

test('switching agents re-pairs and closes stale connections without updating the viewer', async () => {
  const pairs = [], connections = [];
  const element = page({
    pair: async ({ agentOrigin }) => { pairs.push(agentOrigin); return { token: agentOrigin }; },
    connect: options => {
      const pending = deferred();
      connections.push({ ...pending, options });
      return pending.promise;
    },
  });
  element('agent').value = 'https://first.example';
  await element('connect').fire('submit');
  element('disconnect').fire('click');
  element('agent').value = 'https://second.example';
  await element('connect').fire('submit');
  assert.deepEqual(pairs, ['https://first.example', 'https://second.example']);
  assert.equal(connections[1].options.token, 'https://second.example');
  const status = element('status').textContent;
  connections[0].options.onError('kvm_authentication_failed');
  connections[0].options.onFrame({});
  assert.equal(element('status').textContent, status);
  let closed = 0;
  connections[0].resolve({ close() { closed++; } });
  await Promise.resolve();
  assert.equal(closed, 1);
  element('disconnect').fire('click');
  connections[1].resolve({ close() { closed++; } });
  await Promise.resolve();
  assert.equal(closed, 2);
});


test('viewer management requires association and cleans up on disconnect', async () => {
  for (const deviceId of [null, 'rack-1']) {
    const closed = deferred();
    let mounts = 0, cleanups = 0, connects = 0;
    const element = page({
      pair: async () => ({ token: 'paired' }),
      connect: async () => ({ managementDeviceId: deviceId, closed: closed.promise, close() {} }),
      createView: () => ({ start() {}, stop() {}, cancelPaste() {}, releaseInput() {} }),
      createManagementClient: options => {
        assert.equal(options.agentOrigin, 'https://agent.example');
        assert.equal(options.token, 'paired');
        return options;
      },
      mountManagement: (_, options) => {
        mounts++; assert.equal(options.deviceId, 'rack-1');
        return { connect: async () => { connects++; }, dispose: async () => { cleanups++; } };
      },
    });
    element('agent').value = 'https://agent.example';
    await element('connect').fire('submit');
    await Promise.resolve();
    assert.equal(element('management').disabled, deviceId === null);
    await element('management').fire('click');
    assert.equal(mounts, deviceId ? 1 : 0);
    assert.equal(connects, mounts);
    element('disconnect').fire('click');
    await Promise.resolve(); await Promise.resolve();
    assert.equal(cleanups, mounts);
    assert.equal(element('management').disabled, true);
    closed.resolve({ reason: 'closed' });
  }
});
