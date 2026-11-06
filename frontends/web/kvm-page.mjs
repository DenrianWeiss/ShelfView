import { connectKvm } from './agent-kvm.mjs';
import { pairAgent } from './agent-pair.mjs';
import { agentOrigin } from './agent-origin.mjs';
import { KvmView } from './kvm-input.mjs';
import { AgentClient } from './agent-client.mjs';
import { mountManagementPanel } from './management-page.mjs';
import { apply, bindLanguageSelect, onLanguageChange, t } from './i18n.mjs';
export { agentOrigin };
export function reconnectDelay(attempt) { return Math.min(500 * 2 ** Math.max(0, attempt - 1), 5000); }
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Service errors are localized at the page boundary.
const errorKeys = {
  management_cleanup_unconfirmed: 'error.sessionMayExist',
  input_overloaded: 'kvm.inputOverloaded',
  input_not_ready: 'kvm.notConnected',
  input_closed: 'kvm.disconnected',
  kvm_connection_timeout: 'error.deviceTimeout',
  kvm_decoder_error: 'kvm.error.protocol',
  kvm_decoder_overloaded: 'kvm.error.protocol',
  kvm_worker_unavailable: 'kvm.error.browserUnavailable',
  kvm_input_unsupported: 'kvm.error.agentUpdate',
  invalid_tile: 'kvm.error.protocol',
  unsupported_pixel_format: 'kvm.error.unsupported',
  media_stream_unsupported: 'kvm.error.unsupported',
  paste_unsupported: 'kvm.pasteUnsupported',
  clipboard_empty: 'sol.clipboardEmpty',
  invalid_agent_origin: 'error.invalidAgentOrigin',
  invalid_token: 'error.authenticationFailed',
  invalid_timeout: 'kvm.connectFailed',
  kvm_ticket_rejected: 'error.authenticationFailed',
  invalid_kvm_ticket: 'error.invalidResponse',
  kvm_authentication_failed: 'error.authenticationFailed',
  kvm_message_protocol_error: 'error.status.protocol_error',
  kvm_connection_error: 'error.connectionFailed',
  invalid_keysym: 'kvm.error.internal',
  invalid_pointer: 'kvm.error.internal',
  invalid_canvas: 'kvm.error.internal',
  invalid_session: 'kvm.error.internal',
  pairing_failed: 'kvm.pairingFailed',
  pairing_rejected: 'error.pairingRejected',
  invalid_pairing_secret: 'error.invalidPairingSecret',
  invalid_client_name: 'kvm.pairingFailed',
  invalid_pairing_result: 'error.invalidResponse',
  connect_failed: 'kvm.connectFailed',
};

export function initKvmPage(document, { pair = pairAgent, connect = connectKvm,
  mountManagement = mountManagementPanel, createManagementClient = options => new AgentClient(options),
  createView = options => new KvmView(options) } = {}) {
  const form = document.querySelector('#kvm-connect');
  const originInput = document.querySelector('#kvm-agent');
  const secretInput = document.querySelector('#kvm-secret');
  const connectButton = document.querySelector('#kvm-connect-button');
  const disconnectButton = document.querySelector('#kvm-disconnect');
  const status = document.querySelector('#kvm-status');
  const canvas = document.querySelector('#kvm-screen');
  const pasteButton = document.querySelector('#kvm-paste');
  const cancelPasteButton = document.querySelector('#kvm-cancel-paste');
  const pasteInterval = document.querySelector('#kvm-paste-interval');
  const sendKeyButton = document.querySelector('#kvm-send-key');
  const keyChoice = document.querySelector('#kvm-key');
  const managementButton = document.querySelector('#kvm-management');
  const managementDialog = document.querySelector('#kvm-management-dialog');
  let management = null, managementClosing = Promise.resolve(), managementCleanupFailed = false;
  let session = null, view = null, token = null, pairedOrigin = null;
  let generation = 0, connecting = false;
  let manual = false, attempts = 0;
  let lastStatus = { key: 'kvm.disconnected', params: {} };
  const retries = 3;
  const showKey = (key, params = {}) => { lastStatus = { key, params }; status.textContent = t(key, params); };
  const showError = (message, fallback = 'kvm.connectFailed') => {
    const key = errorKeys[message];
    showKey(key ?? fallback);
  };
  const closeManagement = () => {
    const panel = management; management = null;
    if (managementDialog?.open) managementDialog.close();
    if (panel) managementClosing = managementClosing.then(() => panel.dispose()).catch(() => {
      managementCleanupFailed = true;
      if (managementButton) managementButton.disabled = true;
      showError('management_cleanup_unconfirmed');
    });
    return managementClosing;
  };
  managementDialog?.addEventListener('close', () => { if (!managementDialog.open) closeManagement(); });
  document.querySelector('#kvm-management-close')?.addEventListener('click', () => managementDialog.close());
  managementButton?.addEventListener('click', async () => {
    const opened = session, current = generation;
    if (!opened?.managementDeviceId || managementCleanupFailed || management) return;
    await managementClosing;
    if (session !== opened || generation !== current || managementCleanupFailed || management) return;
    view?.cancelPaste(); view?.releaseInput();
    management = mountManagement(document.querySelector('#kvm-management-body'), {
      boundClient: createManagementClient({ agentOrigin: pairedOrigin, token }), deviceId: opened.managementDeviceId,
    });
    managementDialog.showModal();
    await management.connect();
  });
  const cleanup = (reason) => {
    generation++; connecting = false; originInput.disabled = false;
    if (managementButton) managementButton.disabled = true;
    closeManagement();
    if (pasteButton) pasteButton.disabled = true;
    if (cancelPasteButton) cancelPasteButton.disabled = true;
    if (sendKeyButton) sendKeyButton.disabled = true;
    if (view) { view.stop(); view = null; }
    if (session) { session.close(); session = null; }
    connectButton.disabled = false; disconnectButton.disabled = true; attempts = 0;
    if (!reason || reason === 'disconnected' || reason === 'closed') showKey('kvm.disconnected');
    else showError(reason);
  };
  const runSession = async (origin, current) => {
    while (!manual && current === generation) {
      let activeView = null;
      try {
        const opened = await connect({
          agentOrigin: origin, token,
          onFrame: (frame) => {
            if (current === generation && activeView && activeView === view) activeView.drawFrame(frame);
          },
          onError: (reason) => { if (current === generation) showError(reason); },
        });
        if (current !== generation) { opened.close(); return; }
        session = opened;
        if (managementButton) managementButton.disabled = !opened.managementDeviceId || managementCleanupFailed;
        view = createView({ canvas, session, onError: (reason) => {
          if (current === generation && activeView === view) showError(reason);
        } });
        activeView = view;
        view.start(); canvas.focus();
        if (pasteButton) pasteButton.disabled = false;
        if (sendKeyButton) sendKeyButton.disabled = false;
        attempts = 0; disconnectButton.disabled = false; showKey('kvm.connected');
        const { reason } = await opened.closed;
        if (current !== generation) return;
        if (view) view.cancelPaste();
        if (pasteButton) pasteButton.disabled = true;
        if (managementButton) managementButton.disabled = true;
        closeManagement();
        session = null;
        if (manual) break;
        if (++attempts > retries) { cleanup(reason); return; }
        if (view) { view.stop(); view = null; }
        showKey('kvm.reconnecting'); await sleep(reconnectDelay(attempts));
      } catch (error) {
        if (current !== generation) return;
        if (view) view.cancelPaste();
        if (pasteButton) pasteButton.disabled = true;
        if (managementButton) managementButton.disabled = true;
        closeManagement();
        session = null;
        if (manual) break;
        if (++attempts > retries) { cleanup(error.message || 'connect_failed'); return; }
        showKey('kvm.reconnecting'); await sleep(reconnectDelay(attempts));
      }
    }
    if (current === generation) cleanup('disconnected');
  };
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (session || connecting) return;
    let origin;
    try { origin = agentOrigin(originInput.value); } catch (error) { showError(error.message); return; }
    const current = ++generation;
    connecting = true; originInput.disabled = true; disconnectButton.disabled = false;
    if (pairedOrigin !== origin) { token = null; pairedOrigin = null; }
    connectButton.disabled = true; showKey('kvm.connecting');
    manual = false; attempts = 0;
    try {
      if (!token) {
        const secret = secretInput.value.trim();
        secretInput.value = '';
        const paired = await pair({ agentOrigin: origin, secret });
        if (current !== generation) return;
        token = paired.token; pairedOrigin = origin;
      }
    } catch (error) {
      if (current !== generation) return;
      cleanup(); showError(error.message, 'kvm.pairingFailed'); return;
    }
    if (current !== generation) return;
    runSession(origin, current).catch((error) => {
      if (current === generation) { cleanup(); showError(error.message, 'kvm.connectFailed'); }
    });
  });
  disconnectButton.addEventListener('click', () => {
    manual = true;
    cleanup('disconnected');
  });
  const chords = { ctrlAltDelete: [0xffe3, 0xffe9, 0xffff], altF4: [0xffe9, 0xffc1], escape: [0xff1b] };
  sendKeyButton?.addEventListener('click', async () => {
    const keys = chords[keyChoice?.value];
    if (!view || !keys) return;
    try { await view.sendChord(keys); canvas.focus(); }
    catch (error) { showError(error.message); }
  });
  document.querySelector('#kvm-fullscreen')?.addEventListener('click', async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.querySelector('#kvm-viewer')?.requestFullscreen();
    } catch (error) { showError(error.message); }
  });
  pasteButton?.addEventListener('click', async () => {
    const target = view;
    if (!target || target.pasting) return;
    target.cancelPaste();
    const generation = target.pasteGeneration;
    pasteButton.disabled = true;
    cancelPasteButton.disabled = false;
    pasteInterval.disabled = true;
    try {
      const text = await navigator.clipboard.readText();
      if (view !== target || !session || target.pasteGeneration !== generation) return;
      const completed = await target.slowPaste(text, pasteInterval.value, (sent, total) => showKey('kvm.pasteProgress', { sent, total }));
      if (view === target) showKey(completed ? 'kvm.connected' : 'sol.pasteCancelled');
    } catch (error) {
      if (errorKeys[error.message]) showError(error.message);
      else showKey('kvm.pasteFailed');
    }
    finally {
      pasteButton.disabled = !session;
      cancelPasteButton.disabled = true;
      pasteInterval.disabled = false;
    }
  });
  cancelPasteButton?.addEventListener('click', () => view?.cancelPaste());
  document.addEventListener?.('visibilitychange', () => { if (document.hidden) view?.cancelPaste(); });
  globalThis.addEventListener?.('pagehide', () => { manual = true; cleanup('disconnected'); });
  bindLanguageSelect(document.querySelector('#language'));
  apply(document);
  onLanguageChange(() => {
    apply(document);
    status.textContent = t(lastStatus.key, lastStatus.params);
  });
}
if (typeof document !== 'undefined') initKvmPage(document);
