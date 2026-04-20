/**
 * Unit tests for `40mcp settings --show` provenance logic.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildProvenance,
  formatProvenance,
  ENV_OVERLAY,
} from '../../src/config/settings-show.js';
import { DEFAULT_SETTINGS } from '../../src/config/settings.js';

function mergedWith(overlay) {
  // Build a merged-with-defaults tree like loadSettings returns.
  const merged = structuredClone(DEFAULT_SETTINGS);
  for (const { path, value } of overlay) {
    const parts = path.split('.');
    let cursor = merged;
    for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
    cursor[parts[parts.length - 1]] = value;
  }
  return merged;
}

describe('buildProvenance — source attribution', () => {
  it('reports every default when no settings loaded', () => {
    const rows = buildProvenance({ settings: DEFAULT_SETTINGS, source: null, env: {} });
    assert.ok(rows.length > 0);
    for (const row of rows) {
      // Env-only keys (daemonSecret, passphrase) are not in DEFAULT_SETTINGS;
      // they get `env:NAME (unset)`. All tree-present keys should read `default`.
      if (row.source.startsWith('env:')) continue;
      assert.equal(row.source, 'default', `${row.path} should be default, got ${row.source}`);
    }
  });

  it('attributes overridden leaves to settings.json', () => {
    const settings = mergedWith([
      { path: 'bridge.transport.port', value: 9999 },
      { path: 'instance.name', value: 'Prod' },
    ]);
    const rows = buildProvenance({ settings, source: '/tmp/settings.json', env: {} });
    const port = rows.find((r) => r.path === 'bridge.transport.port');
    assert.equal(port.value, 9999);
    assert.equal(port.source, 'settings.json:/tmp/settings.json');
    const name = rows.find((r) => r.path === 'instance.name');
    assert.equal(name.value, 'Prod');
    assert.equal(name.source, 'settings.json:/tmp/settings.json');
  });

  it('env overlay wins over settings.json when set', () => {
    const settings = mergedWith([{ path: 'frontdoor.limits.sse.maxConnections', value: 200 }]);
    const rows = buildProvenance({
      settings,
      source: '/tmp/settings.json',
      env: { MAX_SSE_CONNECTIONS: '500' },
    });
    const row = rows.find((r) => r.path === 'frontdoor.limits.sse.maxConnections');
    assert.equal(row.value, 500);
    assert.equal(row.source, 'env:MAX_SSE_CONNECTIONS');
  });

  it('redacts secret env-only keys', () => {
    const rows = buildProvenance({
      settings: DEFAULT_SETTINGS,
      source: null,
      env: { VAULT_DAEMON_SECRET: 'super-secret' },
    });
    const row = rows.find((r) => r.path === 'bridge.vault.daemonSecret');
    assert.equal(row.value, '<set>');
    assert.equal(row.secret, true);
    assert.equal(row.source, 'env:VAULT_DAEMON_SECRET');
  });

  it('reports env-only keys as unset when absent', () => {
    const rows = buildProvenance({ settings: DEFAULT_SETTINGS, source: null, env: {} });
    const row = rows.find((r) => r.path === 'bridge.vault.daemonSecret');
    assert.equal(row.value, '<unset>');
    assert.equal(row.source, 'env:VAULT_DAEMON_SECRET (unset)');
  });
});

describe('formatProvenance', () => {
  it('groups output by top-level cluster', () => {
    const rows = buildProvenance({ settings: DEFAULT_SETTINGS, source: null, env: {} });
    const out = formatProvenance(rows);
    assert.match(out, /\[bridge\]/);
    assert.match(out, /\[frontdoor\]/);
    assert.match(out, /\[instance\]/);
    assert.match(out, /Precedence: CLI > env > settings.json > default/);
  });

  it('returns empty string when no rows', () => {
    assert.equal(formatProvenance([]), '');
  });

  it('renders settings.json source with the file path', () => {
    const settings = mergedWith([{ path: 'bridge.transport.port', value: 7777 }]);
    const rows = buildProvenance({ settings, source: '/my/path.json', env: {} });
    const out = formatProvenance(rows);
    assert.match(out, /bridge\.transport\.port\s+=\s+7777\s+← settings\.json:\/my\/path\.json/);
  });
});

describe('ENV_OVERLAY table', () => {
  it('every overlay entry has a unique env name', () => {
    const names = ENV_OVERLAY.map((o) => o.env);
    assert.equal(new Set(names).size, names.length);
  });

  it('every overlay entry has a parse function', () => {
    for (const o of ENV_OVERLAY) {
      assert.equal(typeof o.parse, 'function', `${o.env} is missing parse()`);
    }
  });
});
