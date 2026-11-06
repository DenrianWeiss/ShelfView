import { catalog } from './i18n-catalog.mjs';

const storageKey = 'bcontrol.language';
const supported = catalog.languages.map(({ tag }) => tag);
const listeners = new Set();

function systemLanguage() {
  try {
    const tag = (globalThis.navigator?.language || '').toLowerCase();
    return tag.startsWith('zh') ? 'zh-CN' : 'en';
  } catch { return catalog.default; }
}

function storedLanguage() {
  try { return globalThis.localStorage?.getItem(storageKey) || null; } catch { return null; }
}

function initialLanguage() {
  const stored = storedLanguage();
  if (stored && supported.includes(stored)) return stored;
  const system = systemLanguage();
  return supported.includes(system) ? system : catalog.default;
}

let current = initialLanguage();

export function languages() { return catalog.languages.map(({ tag, name }) => ({ tag, name })); }
export function getLanguage() { return current; }
export function has(key) { return Object.hasOwn(catalog.messages, key); }

export function setLanguage(tag) {
  if (!supported.includes(tag)) throw new Error(`unsupported_language:${tag}`);
  if (tag === current) return;
  current = tag;
  try { globalThis.localStorage?.setItem(storageKey, tag); } catch { /* storage unavailable */ }
  try { if (globalThis.document?.documentElement) globalThis.document.documentElement.lang = tag; } catch { /* no document */ }
  apply();
  for (const listener of listeners) listener(tag);
}

export function onLanguageChange(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function t(key, params = {}) {
  const message = catalog.messages[key];
  if (!message) return key;
  const template = message[current] ?? message[catalog.default];
  if (typeof template !== 'string') return key;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, name) =>
    Object.hasOwn(params, name) ? String(params[name]) : `{${name}}`);
}

const unitKeys = {
  'Cel': 'sensor.unit.celsius',
  '[degF]': 'sensor.unit.fahrenheit',
  'K': 'sensor.unit.kelvin',
  'V': 'sensor.unit.volt',
  'A': 'sensor.unit.ampere',
  'W': 'sensor.unit.watt',
  'J': 'sensor.unit.joule',
  '{rev}/min': 'sensor.unit.rpm',
  'Hz': 'sensor.unit.hertz',
  '%': 'sensor.unit.percent',
};
const healthKeys = { OK: 'sensor.health.ok', Warning: 'sensor.health.warning', Critical: 'sensor.health.critical' };
const stateKeys = { Enabled: 'sensor.state.enabled', Disabled: 'sensor.state.disabled', Absent: 'sensor.state.absent', UnavailableOffline: 'sensor.state.unavailableOffline' };
const taskStateKeys = {
  Completed: 'task.state.completed', Exception: 'task.state.exception', Killed: 'task.state.killed',
  Cancelled: 'task.state.cancelled', Running: 'task.state.running', Pending: 'task.state.pending',
  Starting: 'task.state.starting', Suspended: 'task.state.suspended', Interrupted: 'task.state.interrupted',
};
const taskStatusKeys = { OK: 'task.status.ok', Critical: 'task.status.critical', Warning: 'task.status.warning' };
const powerStateKeys = { On: 'power.state.on', Off: 'power.state.off', PoweringOn: 'power.state.poweringOn', PoweringOff: 'power.state.poweringOff', Unknown: 'power.state.unknown' };

function label(map, value) {
  if (value == null || value === '') return '';
  const key = map[String(value)];
  return key ? t(key) : String(value);
}

export const unitLabel = (value) => label(unitKeys, value);
export const sensorHealthLabel = (value) => label(healthKeys, value);
export const sensorStateLabel = (value) => label(stateKeys, value);
export const taskStateLabel = (value) => label(taskStateKeys, value);
export const taskStatusLabel = (value) => label(taskStatusKeys, value);
export const powerStateLabel = (value) => label(powerStateKeys, value);

export function number(value) {
  if (value == null || value === '' || !Number.isFinite(Number(value))) return '';
  return new Intl.NumberFormat(current, { maximumFractionDigits: 3 }).format(Number(value));
}

export function percent(value) { return `${number(value)}%`; }

export function apply(root = globalThis.document) {
  if (!root || typeof root.querySelectorAll !== 'function') return;
  for (const node of root.querySelectorAll('[data-i18n]')) node.textContent = t(node.getAttribute('data-i18n'));
  for (const node of root.querySelectorAll('[data-i18n-placeholder]')) node.setAttribute('placeholder', t(node.getAttribute('data-i18n-placeholder')));
  for (const node of root.querySelectorAll('[data-i18n-title]')) node.setAttribute('title', t(node.getAttribute('data-i18n-title')));
  for (const node of root.querySelectorAll('[data-i18n-aria-label]')) node.setAttribute('aria-label', t(node.getAttribute('data-i18n-aria-label')));
}

export function bindLanguageSelect(select) {
  if (!select || typeof select.append !== 'function') return;
  const doc = select.ownerDocument || globalThis.document;
  if (!doc || typeof doc.createElement !== 'function') return;
  select.replaceChildren();
  for (const { tag, name } of languages()) {
    const option = doc.createElement('option');
    option.value = tag;
    option.textContent = name;
    select.append(option);
  }
  select.value = current;
  select.addEventListener('change', () => setLanguage(select.value));
}

if (typeof document !== 'undefined') {
  document.documentElement.lang = current;
  apply(document);
}
