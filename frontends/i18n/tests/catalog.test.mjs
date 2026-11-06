import test from 'node:test';
import assert from 'node:assert/strict';
import { loadCatalog, checkArtifacts } from '../sync.mjs';

const catalog = loadCatalog();
const tags = catalog.languages.map((language) => language.tag);
const placeholder = /\{([a-zA-Z0-9_]+)\}/g;
const placeholders = (text) => [...text.matchAll(placeholder)].map((match) => match[1]).sort();

test('catalog has a stable schema and complete translations', () => {
  assert.equal(catalog.version, 1);
  assert.ok(tags.includes(catalog.default));
  assert.ok(tags.length >= 2);
  for (const [key, message] of Object.entries(catalog.messages)) {
    assert.match(key, /^[a-z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$/, `invalid key ${key}`);
    for (const tag of tags) {
      assert.equal(typeof message[tag], 'string', `${key} is missing ${tag}`);
      assert.ok(message[tag].length > 0, `${key} has an empty ${tag}`);
    }
    const expected = placeholders(message[catalog.default]);
    for (const tag of tags) {
      assert.deepEqual(placeholders(message[tag]), expected, `${key} placeholders differ in ${tag}`);
    }
  }
});

test('generated platform artifacts are current', () => {
  const stale = checkArtifacts(catalog);
  assert.deepEqual(stale, [], `run node frontends/i18n/sync.mjs: ${stale.join(', ')}`);
});
