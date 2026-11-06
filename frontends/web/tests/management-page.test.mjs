import assert from 'node:assert/strict';
import test from 'node:test';
import { initManagementPage } from '../management-page.mjs';
import { setLanguage } from '../i18n.mjs';

setLanguage('zh-CN');

class Element {
  constructor(tag = '') { this.tag = tag; this.value = ''; this.textContent = ''; this.disabled = false; this.children = []; this.listeners = {}; this.dataset = {}; }
  append(node) { if (this.tag === 'select' && !this.children.length) this.value = node.value; this.children.push(node); }
  replaceChildren() { this.children = []; this.value = ''; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  async fire(type = 'click') { this.listeners[type]({ preventDefault() {} }); await new Promise((resolve) => setImmediate(resolve)); }
}
function setup({ flags = 19, supported = ['On'], failPower = false, confirm = () => true, boundClient = null, deviceId = null, media = { inserted: false, image: "", flags: 28 }, failMediaEject = () => false, retainedMediaUri = null, localSource = null, localEvents = [] } = {}) {
  const ids = ['media-file', 'media-local-form', 'mount-local-media', 'refresh-media', 'media-state', 'media-form', 'media-image-url', 'mount-media', 'eject-media', 'notice', 'workspace', 'connect', 'disconnect', 'forget', 'agent-origin', 'pair-secret', 'system-name', 'power-state',
    'boot-state', 'boot-form', 'apply-boot', 'connection-state', 'connect-form', 'power-form', 'apply-power', 'sensors', 'tasks', 'sensors-state', 'tasks-state', 'refresh-systems', 'refresh-sensors', 'refresh-tasks'];
  const nodes = Object.fromEntries(ids.map((id) => [id, new Element()]));
  nodes['boot-target'] = new Element('select'); nodes['boot-mode'] = new Element('select');
  nodes['media-devices'] = new Element('select');
  nodes.systems = new Element('select'); nodes['power-actions'] = new Element('select');
  nodes['agent-origin'].value = 'http://127.0.0.1:8445'; nodes['pair-secret'].value = 'secret';
  let pairs = 0, writes = 0, closes = 0;
  let managedMedia = retainedMediaUri;
  const client = {
    connect: async () => ({ connection_id: 'id', managed_media_uri: managedMedia, browser_media_available: Boolean(localSource) }), close: async () => { closes++; if (localSource) localEvents.push('connection'); },
    query: async (id, op) => {
      switch (op) {
        case 'probe': return { flags };
        case 'managers': return { members: ['/redfish/v1/Managers/1'] };
        case 'virtual-media': return { members: ['/redfish/v1/Managers/1/VirtualMedia/cd'] };
        case 'virtual-media-info': return { media, managed_media_uri: managedMedia };
        case 'systems': return { members: ['/redfish/v1/Systems/host'] };
        case 'system': return { name: '<img src=x>', power_state: 'Off' };
        case 'boot': return { boot: { target: 0, flags: 20, supported_targets: 9, supported_modes: 4 } };
        case 'reset-capabilities': return { reset: { supported_actions: supported } };
        case 'chassis': return { members: ['/redfish/v1/Chassis/1'] };
        case 'sensors': return { members: ['/redfish/v1/Chassis/1/Sensors/1'] };
        case 'sensor': return { sensor: { id: 'ambient', reading: null, units: 'Cel', health: 'OK' } };
        case 'tasks': return { members: ['/redfish/v1/TaskService/Tasks/1'] };
        case 'task': return { task: { state: 'Running', status: 'OK', percent_complete: 0 } };
      }
    },
    mountMedia: async (_, uri, image) => { writes++; media.inserted = true; media.image = image; managedMedia = uri; return { managed_media_uri: managedMedia }; },
    publishMediaFile: async () => { localEvents.push('publish'); return localSource; },
    mountFileMedia: async (_, uri, sourceId) => {
      localEvents.push('mount'); assert.equal(sourceId, localSource.sourceId); writes++;
      managedMedia = uri; media.inserted = true; media.image = 'http://agent/media/generated';
      return { managed_media_uri: uri, media_source_id: sourceId };
    },
    ejectMedia: async () => {
      writes++;
      if (failMediaEject()) throw new Error('outcome_unknown');
      media.inserted = false; media.image = ''; managedMedia = null; return { managed_media_uri: null };
    },
    boot: async () => { writes++; return { flags: 4 }; },
    power: async () => { writes++; if (failPower) throw new Error('outcome_unknown'); return { flags: 3 }; },
  };
  const controller = initManagementPage({ getElementById: (id) => nodes[id], createElement: (tag) => new Element(tag) }, {
    pair: async () => { pairs++; return { token: 'token' }; }, createClient: () => client, confirm, boundClient, deviceId,
  });
  return { nodes, controller, counts: () => ({ pairs, writes, closes }) };
}

test('connect discovers capabilities; reads real values as text; disconnect clears device data', async () => {
  const { nodes: n, counts } = setup();
  await n['connect-form'].fire('submit');
  assert.equal(n['pair-secret'].value, ''); assert.equal(n['agent-origin'].disabled, true);
  assert.equal(n['system-name'].textContent, '<img src=x>'); assert.equal(n['power-state'].textContent, '关机');
  assert.equal(n['apply-power'].disabled, false);
  await n['refresh-sensors'].fire();
  assert.equal(n.sensors.children[0].children[1].textContent, '—');
  await n['refresh-tasks'].fire();
  assert.equal(n.tasks.children[0].children[3].textContent, '0%');
  await n['power-form'].fire('submit');
  assert.equal(n.notice.textContent, '命令已接受，任务待处理'); assert.equal(counts().writes, 1);
  await n.disconnect.fire();
  assert.equal(n.workspace.disabled, true); assert.equal(n.sensors.children.length, 0); assert.equal(counts().closes, 1);
  await n['connect-form'].fire('submit'); assert.equal(counts().pairs, 1);
  await n.disconnect.fire(); await n.forget.fire(); assert.equal(n['agent-origin'].disabled, false);
});

test('missing capabilities gate controls and unknown outcomes do not claim success', async () => {
  const { nodes: n, counts } = setup({ flags: 1, supported: [] });
  await n['connect-form'].fire('submit');
  assert.equal(n['refresh-tasks'].disabled, true); assert.equal(n['refresh-sensors'].disabled, true);
  assert.equal(n['apply-power'].disabled, true);
  await n['power-form'].fire('submit'); assert.equal(counts().writes, 0);
  const failed = setup({ failPower: true });
  await failed.nodes['connect-form'].fire('submit'); await failed.nodes['power-form'].fire('submit');
  assert.match(failed.nodes.notice.textContent, /结果未知/); assert.equal(failed.counts().writes, 1);
  const cancelled = setup({ confirm: () => false });
  await cancelled.nodes['connect-form'].fire('submit'); await cancelled.nodes['power-form'].fire('submit');
  assert.equal(cancelled.counts().writes, 0);
});

test('boot selection is gated by advertised targets and requires confirmation', async () => {
  const { nodes: n, counts } = setup();
  await n['connect-form'].fire('submit');
  assert.deepEqual(n['boot-target'].children.map(x => x.value), ['none', 'cd']);
  assert.deepEqual(n['boot-mode'].children.map(x => x.value), ['preserve', 'uefi']);
  n['boot-target'].value = 'cd';
  await n['boot-form'].fire('submit');
  assert.equal(counts().writes, 1);
  assert.equal(n.notice.textContent, '启动设置已读回确认');
  const cancelled = setup({ confirm: () => false });
  await cancelled.nodes['connect-form'].fire('submit');
  await cancelled.nodes['boot-form'].fire('submit');
  assert.equal(cancelled.counts().writes, 0);
});


test('power confirmation cannot carry over to a changed target or disconnected session', async () => {
  for (const change of ['target', 'disconnect']) {
    let approve;
    const { nodes: n, counts } = setup({ confirm: () => new Promise(resolve => { approve = resolve; }) });
    await n['connect-form'].fire('submit');
    await n['power-form'].fire('submit');
    if (change === 'target') n.systems.value = '/redfish/v1/Systems/other';
    else await n.disconnect.fire();
    approve(true);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(counts().writes, 0);
  }
});


test('closing an associated panel during login waits and logs out without starting reads', async () => {
  let finishLogin, queries = 0, closes = 0;
  const boundClient = {
    connect: deviceId => {
      assert.equal(deviceId, 'rack-1');
      return new Promise(resolve => { finishLogin = resolve; });
    },
    query: async () => { queries++; },
    close: async id => { assert.equal(id, 'pending-id'); closes++; },
  };
  const { controller } = setup({ boundClient, deviceId: 'rack-1' });
  const started = controller.connect();
  const closing = controller.dispose();
  assert.equal(closes, 0);
  finishLogin({ connection_id: 'pending-id' });
  await Promise.all([started, closing]);
  assert.equal(queries, 0);
  assert.equal(closes, 1);
});


test('retained remote media is restored from the agent without a new mount', async () => {
  const uri = '/redfish/v1/Managers/1/VirtualMedia/cd';
  const { nodes, counts } = setup({ flags: 23, retainedMediaUri: uri, media: { inserted: true, image: 'https://images.example/disk.iso', flags: 28 } });
  await nodes['connect-form'].fire('submit');
  assert.equal(nodes['media-devices'].value, uri);
  assert.equal(nodes['mount-media'].disabled, true);
  assert.equal(nodes['eject-media'].disabled, false);
  assert.equal(counts().writes, 0);
});

test('browser file source stays open until management cleanup finishes', async () => {
  const events = [];
  const source = { sourceId: 'a'.repeat(32), closed: new Promise(() => {}), close: async () => {
    events.push('source'); return { cleanupConfirmed: true };
  } };
  const { nodes, controller } = setup({ flags: 23, localSource: source, localEvents: events });
  await nodes['connect-form'].fire('submit'); await nodes['refresh-media'].fire();
  nodes['media-file'].files = [new Blob(['fixture'])]; await nodes['media-file'].fire('change');
  assert.equal(nodes['mount-local-media'].disabled, false);
  await nodes['media-local-form'].fire('submit');
  assert.deepEqual(events, ['publish', 'mount']);
  assert.equal(nodes['eject-media'].disabled, false);
  await controller.dispose();
  assert.deepEqual(events, ['publish', 'mount', 'connection', 'source']);
});

test('closing during file publication does not start a late device mount', async () => {
  const events = []; let ready;
  const publication = new Promise(resolve => { ready = resolve; });
  const { nodes, controller } = setup({ flags: 23, localSource: publication, localEvents: events });
  await nodes['connect-form'].fire('submit'); await nodes['refresh-media'].fire();
  nodes['media-file'].files = [new Blob(['fixture'])]; await nodes['media-file'].fire('change');
  await nodes['media-local-form'].fire('submit');
  const closing = controller.dispose();
  ready({ sourceId: 'a'.repeat(32), closed: new Promise(() => {}), close: async () => {
    events.push('source'); return { cleanupConfirmed: true };
  } });
  await closing;
  assert.deepEqual(events, ['publish', 'source', 'connection']);
});

test('remote media is capability gated and failed removal retains ownership', async () => {
  let fail = true;
  const { nodes: n, counts } = setup({ flags: 23, failMediaEject: () => fail });
  await n['connect-form'].fire('submit');
  await n['refresh-media'].fire();
  assert.equal(n['mount-media'].disabled, false);
  assert.equal(n['eject-media'].disabled, true);
  n['media-image-url'].value = 'https://images.example/install.iso';
  await n['media-form'].fire('submit');
  assert.equal(n['mount-media'].disabled, true);
  assert.equal(n['media-devices'].disabled, true);
  assert.equal(n['eject-media'].disabled, false);
  await n['eject-media'].fire();
  assert.equal(n['mount-media'].disabled, true);
  assert.equal(n['eject-media'].disabled, false);
  assert.match(n['media-state'].textContent, /尚未确认/);
  fail = false;
  await n['eject-media'].fire();
  assert.equal(n['mount-media'].disabled, false);
  assert.equal(n['eject-media'].disabled, true);
  assert.equal(counts().writes, 3);
  for (const media of [{ inserted: true, image: '', flags: 28 }, { inserted: false, image: 'https://images.example/existing.iso', flags: 28 }]) {
    const other = setup({ flags: 23, media });
    await other.nodes['connect-form'].fire('submit');
    await other.nodes['refresh-media'].fire();
    assert.equal(other.nodes['mount-media'].disabled, true);
    assert.equal(other.nodes['eject-media'].disabled, false);
    assert.equal(other.counts().writes, 0);
  }
  const legacy = setup({ flags: 23, media: { inserted: null, image: '', flags: 12 } });
  await legacy.nodes['connect-form'].fire('submit');
  await legacy.nodes['refresh-media'].fire();
  assert.equal(legacy.nodes['mount-media'].disabled, false);
});
