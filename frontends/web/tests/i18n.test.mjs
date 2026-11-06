import assert from 'node:assert/strict';
import test from 'node:test';
import {
  apply, getLanguage, number, percent, powerStateLabel, sensorHealthLabel, sensorStateLabel,
  setLanguage, t, taskStateLabel, unitLabel,
} from '../i18n.mjs';

test('catalog drives both languages and token mappings', () => {
  try {
    setLanguage('en');
    assert.equal(getLanguage(), 'en');
    assert.equal(t('common.cancel'), 'Cancel');
    assert.equal(t('add.readingSystem', { uri: '/redfish/v1/Systems/1' }), 'Reading system /redfish/v1/Systems/1');
    assert.equal(unitLabel('Cel'), '°C');
    assert.equal(unitLabel('{rev}/min'), 'rpm');
    assert.equal(sensorHealthLabel('OK'), 'OK');
    assert.equal(sensorStateLabel('UnavailableOffline'), 'Unavailable offline');
    assert.equal(powerStateLabel('PoweringOn'), 'Powering on');
    assert.equal(taskStateLabel('Completed'), 'Completed');
    assert.equal(number(22.5), '22.5');
    assert.equal(percent(0), '0%');

    setLanguage('zh-CN');
    assert.equal(t('common.cancel'), '取消');
    assert.equal(sensorStateLabel('UnavailableOffline'), '离线不可用');
    assert.equal(powerStateLabel('PoweringOn'), '正在开机');
  } finally {
    setLanguage('zh-CN');
  }
});

test('apply only writes translated text, never markup', () => {
  const nodes = [{ textContent: '', getAttribute: () => 'common.cancel' }];
  const root = { querySelectorAll: (selector) => selector === '[data-i18n]' ? nodes : [] };
  apply(root);
  assert.equal(nodes[0].textContent, '取消');
});

test('unknown tokens stay visible rather than disappearing', () => {
  assert.equal(t('missing.key'), 'missing.key');
  assert.equal(unitLabel('custom-unit'), 'custom-unit');
  assert.equal(sensorHealthLabel('VendorHealth'), 'VendorHealth');
});
