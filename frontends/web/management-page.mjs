import { pairAgent } from './agent-pair.mjs';
import { agentOrigin } from './agent-origin.mjs';
import { AgentClient } from './agent-client.mjs';
import { managementMarkup } from './management-markup.mjs';
import {
  apply, bindLanguageSelect, onLanguageChange, powerStateLabel, sensorHealthLabel, sensorStateLabel,
  taskStateLabel, taskStatusLabel, t, unitLabel, number, percent,
} from './i18n.mjs';

const actions = {
  On: 'power.action.on', ForceOff: 'power.action.forceOff', GracefulShutdown: 'power.action.gracefulShutdown',
  GracefulRestart: 'power.action.gracefulRestart', ForceRestart: 'power.action.forceRestart', Nmi: 'power.action.nmi',
  ForceOn: 'power.action.forceOn', PushPowerButton: 'power.action.pushPowerButton', PowerCycle: 'power.action.powerCycle',
};
const errors = {
  device_association_mismatch: 'error.invalidResponse', invalid_device_id: 'error.invalidResponse',
  unsupported: 'error.unsupported', unauthorized: 'error.unauthorized', authentication_required: 'error.authenticationRequired',
  client_revoked: 'error.clientRevoked', authentication_failed: 'error.authenticationFailed',
  outcome_unknown: 'error.outcomeUnknown', connection_failed: 'error.connectionFailed', timeout: 'error.timeout',
  pairing_rejected: 'error.pairingRejected', invalid_pairing_secret: 'error.invalidPairingSecret',
  invalid_agent_origin: 'error.invalidAgentOrigin', invalid_response: 'error.invalidResponse', limit_exceeded: 'error.limitExceeded',
};
const bootTargets = ['boot.target.none', 'boot.target.pxe', 'boot.target.disk', 'boot.target.cd', 'boot.target.setup', 'boot.target.usb', 'boot.target.uefiShell'];
const bootKeys = ['none', 'pxe', 'disk', 'cd', 'setup', 'usb', 'uefi-shell'];

const targetLabel = (index) => t(bootTargets[index] ?? 'boot.unknownDevice');
const actionLabel = (action) => t(actions[action] ?? 'common.unknown');

export function initManagementPage(document, { pair = pairAgent, createClient = (options) => new AgentClient(options),
  confirm = null, boundClient = null, deviceId = null } = {}) {
  const el = (id) => document.getElementById(id);
  const confirmPower = confirm || ((text) => new Promise((resolve) => {
    const dialog = el('power-confirm');
    el('confirm-message').textContent = text; dialog.returnValue = 'cancel';
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true });
    dialog.showModal();
  }));
  let client = boundClient, connection = null, busy = false, capabilities = 0, disposed = false;
  let pending = Promise.resolve(), cleanupUnconfirmed = false;
  let mediaInfo = null, ownedMedia = null, mediaOwnershipPending = false;
  let localMedia = null, browserMediaAvailable = false;
  const syncMediaOwnership = result => {
    if (typeof result?.browser_media_available === 'boolean') browserMediaAvailable = result.browser_media_available;
    if (result && Object.hasOwn(result, 'managed_media_uri')) {
      ownedMedia = typeof result.managed_media_uri === 'string' ? result.managed_media_uri : null;
      mediaOwnershipPending = false;
    }
  };
  const message = (text, error = false) => { el('notice').textContent = text; el('notice').dataset.error = String(error); };
  const showError = (error) => message(t(errors[error.message] ?? 'error.operationFailed'), true);
  const releaseLocalSource = async () => {
    const source = localMedia; localMedia = null;
    if (!source) return;
    const result = await source.close();
    if (!result.cleanupConfirmed) { cleanupUnconfirmed = true; throw new Error('management_cleanup_unconfirmed'); }
  };
  const controls = () => {
    el('workspace').disabled = disposed || busy || !connection;
    el('connect').disabled = busy || Boolean(connection);
    el('disconnect').disabled = busy || !connection;
    el('forget').disabled = busy || Boolean(connection) || !client;
    el('agent-origin').disabled = busy || Boolean(client);
    el('pair-secret').disabled = busy || Boolean(client);
    el('media-devices').disabled = busy || mediaOwnershipPending || Boolean(ownedMedia) || !el('media-devices').value;
    el('mount-media').disabled = busy || cleanupUnconfirmed || mediaOwnershipPending || Boolean(ownedMedia) || Boolean(localMedia) || !mediaInfo || mediaInfo.inserted === true || Boolean(mediaInfo.image) || !(mediaInfo.flags & 4);
    el('media-file').disabled = busy || !browserMediaAvailable || Boolean(ownedMedia) || mediaOwnershipPending || Boolean(localMedia);
    el('mount-local-media').disabled = busy || cleanupUnconfirmed || mediaOwnershipPending || Boolean(ownedMedia) || Boolean(localMedia) || !browserMediaAvailable ||
      !mediaInfo || mediaInfo.inserted === true || Boolean(mediaInfo.image) || !(mediaInfo.flags & 4) || el('media-file').files?.length !== 1;
    el('eject-media').disabled = busy || mediaOwnershipPending || !mediaInfo || !el('media-devices').value ||
      (ownedMedia && ownedMedia !== el('media-devices').value) || (!ownedMedia && mediaInfo.inserted === false && !mediaInfo.image) || !(mediaInfo.flags & 8);
  };
  const run = (work) => {
    if (busy || disposed) return pending;
    busy = true; controls();
    pending = (async () => {
      try { await work(); } catch (error) { showError(error); }
      finally { busy = false; controls(); }
    })();
    return pending;
  };
  const clear = (id) => el(id).replaceChildren();
  const option = (select, value, label) => {
    const node = document.createElement('option'); node.value = value; node.textContent = label; select.append(node);
  };
  const missing = () => t('common.notAvailable');
  const row = (id, values) => {
    const tr = document.createElement('tr');
    for (const value of values) {
      const td = document.createElement('td');
      td.textContent = value == null || value === '' ? missing() : value;
      tr.append(td);
    }
    el(id).append(tr);
  };
  const query = async (operation, uri) => {
    const result = await client.query(connection, operation, uri); syncMediaOwnership(result); return result;
  };
  const clearSystem = () => {
    el('system-name').textContent = missing(); el('power-state').textContent = missing();
    clear('power-actions'); option(el('power-actions'), '', t('power.noActions'));
    el('power-actions').disabled = true; el('apply-power').disabled = true;
    clear('boot-target'); clear('boot-mode'); el('boot-state').textContent = t('boot.settingsNotRead');
    el('boot-target').disabled = true; el('boot-mode').disabled = true; el('apply-boot').disabled = true;
  };
  const boot = async (uri) => {
    clear('boot-target'); clear('boot-mode');
    el('boot-target').disabled = true; el('boot-mode').disabled = true; el('apply-boot').disabled = true;
    try {
      const { boot: info } = await query('boot', uri);
      el('boot-state').textContent = info.flags & 1
        ? t('boot.override', { mode: t(info.flags & 2 ? 'boot.continuous' : 'boot.nextBoot'), target: targetLabel(info.target) })
        : t('boot.currentOrder');
      option(el('boot-target'), 'none', targetLabel(0));
      if ((info.flags & 4) && (info.flags & 48)) {
        for (let i = 1; i < bootKeys.length; ++i) if (info.supported_targets & (1 << i)) option(el('boot-target'), bootKeys[i], targetLabel(i));
      }
      option(el('boot-mode'), 'preserve', t('boot.preserve'));
      if (info.supported_modes & 2) option(el('boot-mode'), 'legacy', t('boot.legacy'));
      if (info.supported_modes & 4) option(el('boot-mode'), 'uefi', t('boot.uefi'));
      el('boot-target').disabled = false; el('boot-mode').disabled = false; el('apply-boot').disabled = false;
    } catch (error) {
      el('boot-state').textContent = error.message === 'unsupported' ? t('boot.notProvided') : t('boot.readFailed');
      if (error.message !== 'unsupported') throw error;
    }
  };
  const system = async () => {
    clearSystem();
    const uri = el('systems').value;
    if (!uri) return;
    const result = await query('system', uri);
    el('system-name').textContent = result.name || result.id || uri;
    el('power-state').textContent = powerStateLabel(result.power_state) || result.raw_power_state || t('common.unknown');
    try {
      const result = await query('reset-capabilities', uri);
      const supported = result.reset?.supported_actions?.filter((action) => Object.hasOwn(actions, action)) || [];
      if (supported.length) {
        clear('power-actions');
        for (const action of supported) option(el('power-actions'), action, actionLabel(action));
        el('power-actions').disabled = false; el('apply-power').disabled = false;
      }
    } catch (error) { if (error.message !== 'unsupported') throw error; }
    await boot(uri);
  };
  const systems = async () => {
    clearSystem(); clear('systems');
    const result = await query('systems');
    for (const uri of result.members) option(el('systems'), uri, uri.split('/').pop() || uri);
    if (!result.members.length) option(el('systems'), '', t('web.noSystems'));
    await system();
  };
  const collection = async (kind) => {
    clear(kind); el(`${kind}-state`).textContent = t('web.reading');
    let count = 0;
    try {
      const collections = kind === 'sensors' ? (await query('chassis')).members : [null];
      const seen = new Set();
      for (const parent of collections) {
        let members;
        try { members = (await query(kind, parent ?? undefined)).members; }
        catch (error) { if (kind === 'sensors' && error.message === 'unsupported') continue; throw error; }
        for (const uri of members) {
          if (seen.has(uri)) continue;
          seen.add(uri);
          const result = await query(kind === 'sensors' ? 'sensor' : 'task', uri);
          if (kind === 'sensors') {
            const sensor = result.sensor;
            row(kind, [sensor.name || sensor.id || uri, sensor.reading == null ? missing() : number(sensor.reading),
              unitLabel(sensor.units) || missing(), sensorHealthLabel(sensor.health) || missing(), sensorStateLabel(sensor.state) || missing()]);
          } else {
            const task = result.task;
            row(kind, [uri.split('/').pop() || uri, taskStateLabel(task.state) || task.state || missing(),
              taskStatusLabel(task.status) || task.status || missing(),
              task.percent_complete == null ? missing() : percent(task.percent_complete)]);
          }
          count++;
        }
      }
      el(`${kind}-state`).textContent = count
        ? t(kind === 'sensors' ? 'sensor.items' : 'task.items', { count })
        : t('web.noData');
    } catch (error) {
      el(`${kind}-state`).textContent = t(kind === 'sensors' ? 'sensor.itemsRead' : 'task.itemsRead', {
        count, error: t(errors[error.message] ?? 'web.readFailed'),
      });
      throw error;
    }
  };
  const readMedia = async () => {
    mediaInfo = null;
    const uri = el('media-devices').value;
    if (!uri) { el('media-state').textContent = t('media.noDevices'); return; }
    el('media-state').textContent = t('web.reading');
    try {
      mediaInfo = (await query('virtual-media-info', uri)).media;
      if (ownedMedia && ownedMedia !== uri) { await discoverMedia(); return; }
      if (!ownedMedia && !mediaOwnershipPending) await releaseLocalSource();
      el('media-state').textContent = mediaInfo?.inserted === true ? t('media.mounted')
        : mediaInfo?.inserted === false ? t('media.notMounted') : t('common.unknown');
      if (mediaInfo?.inserted === true && !mediaInfo.image) el('media-state').textContent += ' · ' + t('media.sourceUnverified');
    } catch (error) { el('media-state').textContent = t('media.readFailed'); throw error; }
  };
  const discoverMedia = async () => {
    if (ownedMedia) {
      clear('media-devices'); option(el('media-devices'), ownedMedia, ownedMedia.split('/').pop() || ownedMedia);
      el('media-devices').value = ownedMedia; await readMedia(); return;
    }
    clear('media-devices'); mediaInfo = null;
    const managers = (await query('managers')).members;
    if (ownedMedia) { await discoverMedia(); return; }
    const seen = new Set();
    for (const manager of managers) {
      let members;
      try { members = (await query('virtual-media', manager)).members; }
      catch (error) { if (error.message === 'unsupported') continue; throw error; }
      for (const uri of members) if (!seen.has(uri)) {
        seen.add(uri); option(el('media-devices'), uri, uri.split('/').pop() || uri);
      }
    }
    await readMedia();
  };
  el('refresh-media').addEventListener('click', () => run(discoverMedia));
  el('media-devices').addEventListener('change', () => run(readMedia));
  el('media-file').addEventListener('change', controls);
  el('media-local-form').addEventListener('submit', event => {
    event.preventDefault();
    const file = el('media-file').files?.[0], uri = el('media-devices').value, id = connection;
    if (busy || disposed || !connection || el('mount-local-media').disabled || !file || !uri) return;
    run(async () => {
      const source = await client.publishMediaFile(file);
      localMedia = source;
      if (disposed || connection !== id) { await releaseLocalSource(); return; }
      source.closed.then(() => {
        if (localMedia === source && !disposed) { el('media-state').textContent = t('media.operationUnconfirmed'); controls(); }
      });
      mediaOwnershipPending = true;
      try { syncMediaOwnership(await client.mountFileMedia(id, uri, source.sourceId)); }
      catch (error) {
        syncMediaOwnership(error.result);
        if (!ownedMedia && !mediaOwnershipPending) await releaseLocalSource();
        el('media-state').textContent = t(error.message === 'outcome_unknown' ? 'media.operationUnconfirmed' : 'media.mountFailed');
        throw error;
      }
      await readMedia();
      if (mediaInfo?.inserted !== true) el('media-state').textContent = t('media.operationUnconfirmed');
    });
  });
  el('media-form').addEventListener('submit', event => {
    event.preventDefault();
    const uri = el('media-devices').value, image = el('media-image-url').value.trim();
    if (busy || disposed || !connection || el('mount-media').disabled || !uri || !image) return;
    run(async () => {
      mediaOwnershipPending = true;
      try { syncMediaOwnership(await client.mountMedia(connection, uri, image)); }
      catch (error) {
        syncMediaOwnership(error.result);
        el('media-state').textContent = t(error.message === 'outcome_unknown' ? 'media.operationUnconfirmed' : 'media.mountFailed');
        throw error;
      }
      await readMedia();
      if (mediaInfo?.inserted !== true || (mediaInfo.image && mediaInfo.image !== image))
        el('media-state').textContent = t('media.operationUnconfirmed');
    });
  });
  el('eject-media').addEventListener('click', () => {
    if (busy || disposed || !connection || el('eject-media').disabled) return;
    run(async () => {
      try { syncMediaOwnership(await client.ejectMedia(connection, el('media-devices').value)); if (!ownedMedia && !mediaOwnershipPending) await releaseLocalSource(); }
      catch (error) { el('media-state').textContent = t('media.removalUnconfirmed'); throw error; }
      await readMedia();
    });
  });
  const connect = () => {
    if (connection || disposed) return pending;
    return run(async () => {
      const origin = agentOrigin(el('agent-origin').value);
      message(t('web.connecting'));
      if (!client) {
        const secret = el('pair-secret').value.trim();
        el('pair-secret').value = '';
        const paired = await pair({ agentOrigin: origin, secret, name: 'web' });
        client = createClient({ agentOrigin: origin, token: paired.token });
        el('pair-secret').required = false;
      }
      let result;
      try { result = await client.connect(deviceId); }
      catch (error) {
        cleanupUnconfirmed = error.message === 'outcome_unknown' || error.result?.cleanupConfirmed === false;
        throw error;
      }
      connection = result.connection_id;
      syncMediaOwnership(result);
      if (disposed) return;
      el('connection-state').textContent = t('web.connected');
      capabilities = 0;
      el('refresh-systems').disabled = true; el('refresh-sensors').disabled = true; el('refresh-tasks').disabled = true;
      el('refresh-media').disabled = true;
      capabilities = (await query('probe')).flags;
      el('refresh-systems').disabled = !(capabilities & 1);
      el('refresh-sensors').disabled = !(capabilities & 2);
      el('refresh-tasks').disabled = !(capabilities & 16);
      el('refresh-media').disabled = !(capabilities & 4);
      el('sensors-state').textContent = capabilities & 2 ? t('sensor.clickRefresh') : t('sensor.noChassis');
      el('tasks-state').textContent = capabilities & 16 ? t('task.clickRefresh') : t('task.noService');
      message(t('web.connected'));
      if (capabilities & 1) await systems();
      else message(t('web.noSystemRelation'));
      if ((capabilities & 4) && ownedMedia) await discoverMedia();
    });
  };
  el('connect-form').addEventListener('submit', (event) => { event.preventDefault(); connect(); });
  el('disconnect').addEventListener('click', () => run(async () => {
    const id = connection;
    try { await client.close(id); message(t('web.disconnected')); }
    finally {
      try { await releaseLocalSource(); }
      finally {
      connection = null; capabilities = 0; mediaInfo = null; ownedMedia = null; mediaOwnershipPending = false;
      clear("media-devices"); el("media-state").textContent = t("sensor.notRead");
      el('connection-state').textContent = t('kvm.notConnected');
      clearSystem(); clear('systems'); clear('sensors'); clear('tasks');
      el('sensors-state').textContent = t('sensor.notRead'); el('tasks-state').textContent = t('task.notRead');
      }
    }
  }));
  el('forget').addEventListener('click', () => {
    if (busy || connection) return;
    client = null; el('pair-secret').required = true; el('pair-secret').value = '';
    controls(); message(t('web.forgetHint'));
  });
  el('refresh-systems').addEventListener('click', () => run(systems));
  el('systems').addEventListener('change', () => run(system));
  for (const kind of ['sensors', 'tasks']) el(`refresh-${kind}`).addEventListener('click', () => run(() => collection(kind)));
  el('boot-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const uri = el('systems').value, id = connection, target = el('boot-target').value, mode = el('boot-mode').value;
    if (busy || !id || el('apply-boot').disabled || !bootKeys.includes(target)) return;
    if (!(await confirmPower(t('boot.confirm', { target: targetLabel(bootKeys.indexOf(target)) })))) return;
    if (busy || connection !== id || el('systems').value !== uri) return;
    run(async () => {
      const result = await client.boot(id, uri, target, mode);
      const status = result.flags & 4 ? t('boot.appliedReadBack') : t('boot.appliedTask');
      try { await boot(uri); message(status); }
      catch { message(t('web.afterCommandReadFailed', { status }), true); }
    });
  });
  el('power-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const action = el('power-actions').value, uri = el('systems').value, id = connection;
    if (busy || !connection || el('apply-power').disabled || !Object.hasOwn(actions, action)) return;
    if (!(await confirmPower(t('power.confirm', { action: actionLabel(action) })))) return;
    if (busy || connection !== id || el('systems').value !== uri || el('power-actions').value !== action) return;
    run(async () => {
      const result = await client.power(id, uri, action);
      const accepted = result.flags & 2 ? t('power.acceptedTask') : t('power.accepted');
      message(accepted);
      try { await system(); } catch { message(t('web.afterCommandReadFailed', { status: accepted }), true); }
    });
  });
  bindLanguageSelect(el('language'));
  apply(document);
  el('connection-state').textContent = t('kvm.notConnected');
  el('sensors-state').textContent = t('sensor.notRead');
  el('tasks-state').textContent = t('task.notRead');
  el('boot-state').textContent = t('boot.settingsNotRead');
  el('media-state').textContent = t('sensor.notRead');
  const systemsSelect = el('systems');
  if (systemsSelect?.children?.length) systemsSelect.children[0].textContent = t('web.noSystems');
  message(t('web.enterPairing'));
  const stopLanguageUpdates = onLanguageChange(() => {
    apply(document);
    el('connection-state').textContent = connection ? t('web.connected') : t('kvm.notConnected');
  });
  controls();
  return {
    connect,
    async dispose() {
      disposed = true; controls();
      stopLanguageUpdates();
      await pending;
      const id = connection; connection = null;
      try { if (id) await client.close(id); }
      finally { await releaseLocalSource(); }
      if (cleanupUnconfirmed) throw new Error("management_cleanup_unconfirmed");
    },
  };
}

export function mountManagementPanel(container, options = {}) {
  container.innerHTML = managementMarkup;
  const owner = container.ownerDocument;
  const scoped = {
    getElementById: id => container.querySelector(`#${id}`),
    createElement: tag => owner.createElement(tag),
    querySelectorAll: selector => container.querySelectorAll(selector),
  };
  if (options.boundClient) {
    container.querySelector('#connect-form').hidden = true;
    container.querySelector('#agent-origin').value = options.boundClient.origin;
  }
  return initManagementPage(scoped, options);
}
if (typeof document !== 'undefined' && document.getElementById('management-panel')) {
  mountManagementPanel(document.getElementById('management-panel'));
  bindLanguageSelect(document.getElementById('language'));
}
