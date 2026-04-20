/**
 * `40mcp settings --show` — walk the merged settings tree and attribute each
 * leaf to its source layer (env / settings.json / default).
 *
 * Precedence at runtime is `CLI > env > settings.json > default`. CLI is
 * command-specific and not knowable here (no `serve`/`link` invocation
 * context), so this module reports the top three layers and notes that CLI
 * flags override anything when a command is actually run.
 *
 * @module config/settings-show
 */

import { DEFAULT_SETTINGS } from './settings.js';

/**
 * Env vars that currently short-circuit a settings key at a consumption
 * site. Keep this list explicit — silently adding an env overlay elsewhere
 * in the codebase without updating this table would make `settings --show`
 * lie about effective values.
 *
 * `secret: true` suppresses the value in output (prints `<set>` / `<unset>`)
 * so operators can pipe the output without leaking credentials.
 */
export const ENV_OVERLAY = [
  { key: 'frontdoor.limits.sse.maxConnections', env: 'MAX_SSE_CONNECTIONS', parse: (v) => parseInt(v, 10) },
  { key: 'bridge.vault.daemonSecret', env: 'VAULT_DAEMON_SECRET', secret: true, parse: (v) => v },
  { key: 'bridge.vault.passphrase', env: 'VAULT_PASSPHRASE', secret: true, parse: (v) => v },
];

/**
 * Build a flat, sorted list of provenance rows for every leaf in
 * DEFAULT_SETTINGS (plus any env-only keys listed in ENV_OVERLAY).
 *
 * @param {object} opts
 * @param {object} opts.settings - merged settings tree (as returned by loadSettings)
 * @param {string|null} opts.source - path to the settings file, or null for defaults
 * @param {NodeJS.ProcessEnv} [opts.env=process.env]
 * @returns {Array<{ path: string, value: any, source: string, secret: boolean }>}
 */
export function buildProvenance({ settings, source, env = process.env }) {
  const rows = [];
  const envOverlayByKey = new Map(ENV_OVERLAY.map((o) => [o.key, o]));

  const defaultLeaves = flattenLeaves(DEFAULT_SETTINGS);
  const settingsLeaves = flattenLeaves(settings || {});

  for (const { path: keyPath, value: defaultValue } of defaultLeaves) {
    const overlay = envOverlayByKey.get(keyPath);
    const envValue = overlay && env[overlay.env] != null && env[overlay.env] !== ''
      ? overlay.parse(env[overlay.env])
      : undefined;

    // Settings-file value lookup — pull from merged tree; compare to the
    // default tree to decide if the operator actually set it (vs. just
    // getting the default merged in).
    const settingsValue = settingsLeaves.find((l) => l.path === keyPath)?.value;
    const isFromSettingsFile = source != null && !deepEqual(settingsValue, defaultValue);

    let row;
    if (envValue !== undefined) {
      row = { path: keyPath, value: envValue, source: `env:${overlay.env}`, secret: Boolean(overlay.secret) };
    } else if (isFromSettingsFile) {
      row = { path: keyPath, value: settingsValue, source: `settings.json:${source}`, secret: false };
    } else {
      row = { path: keyPath, value: defaultValue, source: 'default', secret: false };
    }
    rows.push(row);
  }

  // Also surface env-only keys (secrets) that aren't in DEFAULT_SETTINGS so
  // operators can confirm which credentials are resolved from the environment.
  for (const overlay of ENV_OVERLAY) {
    if (defaultLeaves.some((l) => l.path === overlay.key)) continue;
    const present = env[overlay.env] != null && env[overlay.env] !== '';
    rows.push({
      path: overlay.key,
      value: overlay.secret ? (present ? '<set>' : '<unset>') : (present ? overlay.parse(env[overlay.env]) : null),
      source: present ? `env:${overlay.env}` : `env:${overlay.env} (unset)`,
      secret: Boolean(overlay.secret),
    });
  }

  rows.sort((a, b) => a.path.localeCompare(b.path));
  return rows;
}

/**
 * Format provenance rows for stderr display. Groups by top-level cluster,
 * pads `key = value` columns for easy scanning.
 */
export function formatProvenance(rows) {
  if (rows.length === 0) return '';
  const maxPath = Math.max(...rows.map((r) => r.path.length));
  const maxValue = Math.max(...rows.map((r) => formatValue(r).length));
  const lines = [];
  let lastCluster = null;
  for (const row of rows) {
    const cluster = row.path.split('.')[0];
    if (cluster !== lastCluster) {
      if (lastCluster !== null) lines.push('');
      lines.push(`[${cluster}]`);
      lastCluster = cluster;
    }
    const path = row.path.padEnd(maxPath);
    const val = formatValue(row).padEnd(maxValue);
    lines.push(`  ${path} = ${val}  ← ${row.source}`);
  }
  lines.push('');
  lines.push('Precedence: CLI > env > settings.json > default');
  lines.push('(CLI flag overrides everything when a command is actually run.)');
  return lines.join('\n') + '\n';
}

function formatValue(row) {
  if (row.secret) return String(row.value);
  if (row.value === null) return 'null';
  if (Array.isArray(row.value)) return JSON.stringify(row.value);
  if (typeof row.value === 'string') return JSON.stringify(row.value);
  return String(row.value);
}

function flattenLeaves(obj, prefix = '') {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      out.push(...flattenLeaves(v, path));
    } else {
      out.push({ path, value: v });
    }
  }
  return out;
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return a === b;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const ak = Object.keys(a);
    const bk = Object.keys(b);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}
