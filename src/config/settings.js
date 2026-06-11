/**
 * 40mcp runtime settings — single file for operator-tunable behavior.
 *
 * Shape: three top-level clusters.
 *   instance.*  — identity (name, tags)
 *   bridge.*    — `40mcp serve` knobs (transport, limits, network, vault)
 *   frontdoor.* — `40mcp link` knobs (transport, auth, limits, surface,
 *                 policy/tenant paths, telemetry)
 *
 * Precedence at every consumption site is uniform:
 *   CLI flag > env var > settings.json > default.
 *
 * Merging is deliberately done at the CLI boundary (`pick(...)`) rather than
 * inside the loader — env reads stay in one place, defaults are explicit at
 * each call site, and test fixtures don't need to simulate `process.env` to
 * exercise the loader.
 *
 * @module config/settings
 */

import { readFile, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { BridgeError, BridgeErrorCode } from '../errors.js';

/** Hard ceiling for settings file size. Mirrors MAX_CONFIG_FILE_BYTES. */
const MAX_SETTINGS_FILE_BYTES = 16 * 1024 * 1024;

const SETTINGS_FILENAME = '40mcp.settings.json';

// `instance.name` is a friendly display label surfaced in banners / logs.
// The canonical audit identity is the `.mcp.json` entry key, so this field
// just needs to render safely in a stderr line: no control characters, no
// line separators (log-forgery primitive), length-bounded. Operators should
// be free to use normal display text like "GitHub Production".
const INSTANCE_NAME_MAX = 100;
const INSTANCE_NAME_FORBIDDEN = /[\x00-\x1f\x7f-\x9f\u2028\u2029]/;
const VALID_TRANSPORT_TYPES = new Set(['stdio', 'sse']);

/**
 * Full default tree. Every knob has a default here so consumers never have
 * to reach for `??` fallbacks — they `pick(cli, env, settings, DEFAULT_X)`.
 * Frozen so consumers can't mutate shared state.
 */
export const DEFAULT_SETTINGS = deepFreeze({
  instance: {
    name: null,
    tags: [],
  },
  bridge: {
    transport: { type: 'stdio', host: null, port: null },
    limits: {
      dispatch: { maxConcurrent: 50, requestTimeoutMs: null },
      request: { maxBytes: null },
      response: { maxBytes: null },
    },
    network: { allowPrivate: true, strictSsrf: false },
    vault: { path: null, daemon: false },
  },
  frontdoor: {
    transport: { type: 'stdio', host: null, port: null },
    auth: { requireBearerEnv: null, bearerFile: null },
    network: { allowedOrigins: [] },
    limits: {
      sse: {
        maxConnections: null,
        maxSessionsPerIp: null,
        maxSessionsPerPrincipal: null,
        idleTimeoutMs: null,
      },
    },
    surface: { allowTools: [], denyTools: [], healthDetail: false },
    policy: { path: null },
    tenantMap: { path: null },
    telemetry: { audit: true, events: true },
  },
});

/**
 * Load settings from disk with discovery precedence:
 *   1. `opts.explicitPath` (from `--settings <path>`) — must exist or throw.
 *   2. Sibling of the bridge/link config file — load if present.
 *   3. `40mcp.settings.json` in CWD — load if present.
 *   4. None found — return `DEFAULT_SETTINGS`, `source: null`.
 *
 * @param {object} [opts]
 * @param {string|null} [opts.explicitPath] - Path from `--settings` flag.
 * @param {string|null} [opts.configPath] - Bridge/link config file path (sibling probe).
 * @param {string} [opts.cwd] - Current working directory (default: process.cwd()).
 * @returns {Promise<{ settings: object, source: string|null, warnings: string[] }>}
 */
export async function loadSettings(opts = {}) {
  const { explicitPath = null, configPath = null, cwd = process.cwd() } = opts;

  if (explicitPath) {
    const abs = resolve(cwd, String(explicitPath));
    return readAndValidate(abs, '--settings');
  }

  if (configPath) {
    const siblingPath = join(dirname(resolve(cwd, configPath)), SETTINGS_FILENAME);
    if (await fileExists(siblingPath)) {
      return readAndValidate(siblingPath, '(auto-discovered)');
    }
  }

  const cwdPath = join(cwd, SETTINGS_FILENAME);
  if (await fileExists(cwdPath)) {
    return readAndValidate(cwdPath, '(auto-discovered)');
  }

  return { settings: DEFAULT_SETTINGS, source: null, warnings: [] };
}

async function readAndValidate(absPath, label) {
  let st;
  try {
    st = await stat(absPath);
  } catch (err) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `${label} ${absPath}: ${err.message}`,
    );
  }
  if (st.size > MAX_SETTINGS_FILE_BYTES) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `${label} ${absPath}: file too large (${st.size} > ${MAX_SETTINGS_FILE_BYTES} bytes).`,
    );
  }
  let raw;
  try {
    raw = await readFile(absPath, 'utf-8');
  } catch (err) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `${label} ${absPath}: ${err.message}`,
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `${label} ${absPath} is not valid JSON: ${err.message}`,
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `${label} ${absPath} must contain a JSON object.`,
    );
  }

  const validation = validateSettings(parsed);
  if (!validation.valid) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `Invalid ${SETTINGS_FILENAME} (${absPath}):\n  - ${validation.errors.join('\n  - ')}`,
      { errors: validation.errors, warnings: validation.warnings },
    );
  }

  const merged = mergeWithDefaults(parsed);
  return { settings: deepFreeze(merged), source: absPath, warnings: validation.warnings };
}

async function fileExists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate a parsed settings object.
 *
 * @param {any} settings
 * @param {object} [opts]
 * @param {string} [opts.cwd] - Working directory used for path-containment checks (default: process.cwd()).
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateSettings(settings, opts = {}) {
  const { cwd = process.cwd() } = opts;
  const errors = [];
  const warnings = [];

  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
    return { valid: false, errors: ['settings must be a JSON object'], warnings };
  }

  const allowedTop = new Set(['instance', 'bridge', 'frontdoor']);
  for (const key of Object.keys(settings)) {
    if (!allowedTop.has(key)) {
      errors.push(`settings: unknown top-level key "${key}" (allowed: instance, bridge, frontdoor)`);
    }
  }

  if (settings.instance !== undefined) validateInstance(settings.instance, errors);
  if (settings.bridge !== undefined) validateBridge(settings.bridge, errors);
  if (settings.frontdoor !== undefined) validateFrontdoor(settings.frontdoor, errors, warnings, cwd);

  return { valid: errors.length === 0, errors, warnings };
}

function validateInstance(instance, errors) {
  if (!isPlainObject(instance)) {
    errors.push('settings.instance must be an object');
    return;
  }
  const allowed = new Set(['name', 'tags']);
  for (const key of Object.keys(instance)) {
    if (!allowed.has(key)) errors.push(`settings.instance: unknown key "${key}"`);
  }
  if (instance.name !== undefined && instance.name !== null) {
    if (typeof instance.name !== 'string' || instance.name.length === 0 || instance.name.length > INSTANCE_NAME_MAX) {
      errors.push(`settings.instance.name must be a non-empty string ≤ ${INSTANCE_NAME_MAX} characters`);
    } else if (INSTANCE_NAME_FORBIDDEN.test(instance.name)) {
      errors.push('settings.instance.name must not contain control characters or line separators');
    }
  }
  if (instance.tags !== undefined) {
    if (!Array.isArray(instance.tags) || !instance.tags.every((t) => typeof t === 'string')) {
      errors.push('settings.instance.tags must be an array of strings');
    }
  }
}

function validateBridge(bridge, errors) {
  if (!isPlainObject(bridge)) {
    errors.push('settings.bridge must be an object');
    return;
  }
  const allowed = new Set(['transport', 'limits', 'network', 'vault']);
  for (const key of Object.keys(bridge)) {
    if (!allowed.has(key)) errors.push(`settings.bridge: unknown key "${key}"`);
  }
  if (bridge.transport !== undefined) {
    validateTransport(bridge.transport, 'settings.bridge.transport', errors);
  }
  if (bridge.limits !== undefined) validateBridgeLimits(bridge.limits, errors);
  if (bridge.network !== undefined) validateBridgeNetwork(bridge.network, errors);
  if (bridge.vault !== undefined) validateBridgeVault(bridge.vault, errors);
}

function validateBridgeLimits(limits, errors) {
  if (!isPlainObject(limits)) {
    errors.push('settings.bridge.limits must be an object');
    return;
  }
  const allowed = new Set(['dispatch', 'request', 'response']);
  for (const key of Object.keys(limits)) {
    if (!allowed.has(key)) errors.push(`settings.bridge.limits: unknown key "${key}"`);
  }
  if (limits.dispatch !== undefined) {
    if (!isPlainObject(limits.dispatch)) {
      errors.push('settings.bridge.limits.dispatch must be an object');
    } else {
      for (const key of Object.keys(limits.dispatch)) {
        if (key !== 'maxConcurrent' && key !== 'requestTimeoutMs') {
          errors.push(`settings.bridge.limits.dispatch: unknown key "${key}"`);
        }
      }
      if (limits.dispatch.maxConcurrent !== undefined) {
        const v = limits.dispatch.maxConcurrent;
        if (!Number.isInteger(v) || v < 1 || v > 10_000) {
          errors.push('settings.bridge.limits.dispatch.maxConcurrent must be an integer in [1, 10000]');
        }
      }
      if (limits.dispatch.requestTimeoutMs !== undefined) {
        const v = limits.dispatch.requestTimeoutMs;
        if (!Number.isInteger(v) || v < 1) {
          errors.push('settings.bridge.limits.dispatch.requestTimeoutMs must be a positive integer');
        }
      }
    }
  }
  for (const side of ['request', 'response']) {
    if (limits[side] !== undefined) {
      if (!isPlainObject(limits[side])) {
        errors.push(`settings.bridge.limits.${side} must be an object`);
      } else {
        for (const key of Object.keys(limits[side])) {
          if (key !== 'maxBytes') errors.push(`settings.bridge.limits.${side}: unknown key "${key}"`);
        }
        if (limits[side].maxBytes !== undefined) {
          const parsed = tryParseByteSize(limits[side].maxBytes);
          if (parsed == null || parsed < 1) {
            errors.push(`settings.bridge.limits.${side}.maxBytes must be a positive number or size string (e.g. "1MB")`);
          }
        }
      }
    }
  }
}

function validateBridgeNetwork(network, errors) {
  if (!isPlainObject(network)) {
    errors.push('settings.bridge.network must be an object');
    return;
  }
  for (const key of Object.keys(network)) {
    if (key !== 'allowPrivate' && key !== 'strictSsrf') {
      errors.push(`settings.bridge.network: unknown key "${key}"`);
    }
  }
  if (network.allowPrivate !== undefined && typeof network.allowPrivate !== 'boolean') {
    errors.push('settings.bridge.network.allowPrivate must be boolean');
  }
  if (network.strictSsrf !== undefined && typeof network.strictSsrf !== 'boolean') {
    errors.push('settings.bridge.network.strictSsrf must be boolean');
  }
}

function validateBridgeVault(vault, errors) {
  if (!isPlainObject(vault)) {
    errors.push('settings.bridge.vault must be an object');
    return;
  }
  for (const key of Object.keys(vault)) {
    if (key !== 'path' && key !== 'daemon') errors.push(`settings.bridge.vault: unknown key "${key}"`);
  }
  if (vault.path !== undefined && vault.path !== null && typeof vault.path !== 'string') {
    errors.push('settings.bridge.vault.path must be a string');
  }
  if (vault.daemon !== undefined && typeof vault.daemon !== 'boolean') {
    errors.push('settings.bridge.vault.daemon must be boolean');
  }
}

function validateFrontdoor(frontdoor, errors, warnings, cwd) {
  if (!isPlainObject(frontdoor)) {
    errors.push('settings.frontdoor must be an object');
    return;
  }
  const allowed = new Set(['transport', 'auth', 'network', 'limits', 'surface', 'policy', 'tenantMap', 'telemetry']);
  for (const key of Object.keys(frontdoor)) {
    if (key === 'steering') {
      // Removed feature: fail with a migration message instead of a generic
      // unknown-key error so the operator knows enforcement is gone.
      errors.push('settings.frontdoor.steering is no longer supported — the steering module was removed. Remove this block, or pin 40mcp to 0.1.x.');
      continue;
    }
    if (!allowed.has(key)) errors.push(`settings.frontdoor: unknown key "${key}"`);
  }
  const transportType =
    isPlainObject(frontdoor.transport) && typeof frontdoor.transport.type === 'string'
      ? frontdoor.transport.type
      : 'stdio';

  if (frontdoor.transport !== undefined) {
    validateTransport(frontdoor.transport, 'settings.frontdoor.transport', errors);
  }
  if (frontdoor.auth !== undefined) {
    validateFrontdoorAuth(frontdoor.auth, errors);
    if (transportType === 'stdio' && hasAnyAuth(frontdoor.auth)) {
      errors.push('settings.frontdoor.auth.* requires settings.frontdoor.transport.type = "sse"');
    }
  }
  if (frontdoor.network !== undefined) {
    validateFrontdoorNetwork(frontdoor.network, errors);
    if (transportType === 'stdio' && Array.isArray(frontdoor.network.allowedOrigins) && frontdoor.network.allowedOrigins.length > 0) {
      warnings.push('settings.frontdoor.network.allowedOrigins is ignored when transport.type = "stdio"');
    }
  }
  if (frontdoor.limits !== undefined) {
    validateFrontdoorLimits(frontdoor.limits, errors);
    if (transportType === 'stdio' && isPlainObject(frontdoor.limits.sse) && Object.keys(frontdoor.limits.sse).length > 0) {
      warnings.push('settings.frontdoor.limits.sse.* is ignored when transport.type = "stdio"');
    }
  }
  if (frontdoor.surface !== undefined) validateFrontdoorSurface(frontdoor.surface, errors);
  for (const key of ['policy', 'tenantMap']) {
    if (frontdoor[key] !== undefined) validatePathWrapper(frontdoor[key], `settings.frontdoor.${key}`, errors, cwd);
  }
  if (frontdoor.telemetry !== undefined) {
    if (!isPlainObject(frontdoor.telemetry)) {
      errors.push('settings.frontdoor.telemetry must be an object');
    } else {
      for (const key of Object.keys(frontdoor.telemetry)) {
        if (key !== 'audit' && key !== 'events') errors.push(`settings.frontdoor.telemetry: unknown key "${key}"`);
      }
      if (frontdoor.telemetry.audit !== undefined && typeof frontdoor.telemetry.audit !== 'boolean') {
        errors.push('settings.frontdoor.telemetry.audit must be boolean');
      }
      if (frontdoor.telemetry.events !== undefined && typeof frontdoor.telemetry.events !== 'boolean') {
        errors.push('settings.frontdoor.telemetry.events must be boolean');
      }
    }
  }
}

function validateFrontdoorAuth(auth, errors) {
  if (!isPlainObject(auth)) {
    errors.push('settings.frontdoor.auth must be an object');
    return;
  }
  for (const key of Object.keys(auth)) {
    if (key !== 'requireBearerEnv' && key !== 'bearerFile') {
      errors.push(`settings.frontdoor.auth: unknown key "${key}"`);
    }
  }
  if (auth.requireBearerEnv !== undefined && auth.requireBearerEnv !== null && typeof auth.requireBearerEnv !== 'string') {
    errors.push('settings.frontdoor.auth.requireBearerEnv must be a string');
  }
  if (auth.bearerFile !== undefined && auth.bearerFile !== null && typeof auth.bearerFile !== 'string') {
    errors.push('settings.frontdoor.auth.bearerFile must be a string');
  }
}

function validateFrontdoorNetwork(network, errors) {
  if (!isPlainObject(network)) {
    errors.push('settings.frontdoor.network must be an object');
    return;
  }
  for (const key of Object.keys(network)) {
    if (key !== 'allowedOrigins') errors.push(`settings.frontdoor.network: unknown key "${key}"`);
  }
  if (network.allowedOrigins !== undefined) {
    if (!Array.isArray(network.allowedOrigins) || !network.allowedOrigins.every((o) => typeof o === 'string')) {
      errors.push('settings.frontdoor.network.allowedOrigins must be an array of strings');
    }
  }
}

function validateFrontdoorLimits(limits, errors) {
  if (!isPlainObject(limits)) {
    errors.push('settings.frontdoor.limits must be an object');
    return;
  }
  for (const key of Object.keys(limits)) {
    if (key !== 'sse') errors.push(`settings.frontdoor.limits: unknown key "${key}"`);
  }
  if (limits.sse === undefined) return;
  if (!isPlainObject(limits.sse)) {
    errors.push('settings.frontdoor.limits.sse must be an object');
    return;
  }
  const sseAllowed = new Set(['maxConnections', 'maxSessionsPerIp', 'maxSessionsPerPrincipal', 'idleTimeoutMs']);
  for (const key of Object.keys(limits.sse)) {
    if (!sseAllowed.has(key)) errors.push(`settings.frontdoor.limits.sse: unknown key "${key}"`);
  }
  for (const key of ['maxConnections', 'maxSessionsPerIp', 'maxSessionsPerPrincipal']) {
    if (limits.sse[key] !== undefined) {
      const v = limits.sse[key];
      if (!Number.isInteger(v) || v < 1) {
        errors.push(`settings.frontdoor.limits.sse.${key} must be a positive integer`);
      }
    }
  }
  if (limits.sse.idleTimeoutMs !== undefined) {
    const v = limits.sse.idleTimeoutMs;
    if (!Number.isInteger(v) || v < 1000) {
      errors.push('settings.frontdoor.limits.sse.idleTimeoutMs must be an integer ≥ 1000');
    }
  }
}

function validateFrontdoorSurface(surface, errors) {
  if (!isPlainObject(surface)) {
    errors.push('settings.frontdoor.surface must be an object');
    return;
  }
  const allowed = new Set(['allowTools', 'denyTools', 'healthDetail']);
  for (const key of Object.keys(surface)) {
    if (!allowed.has(key)) errors.push(`settings.frontdoor.surface: unknown key "${key}"`);
  }
  for (const key of ['allowTools', 'denyTools']) {
    if (surface[key] !== undefined) {
      if (!Array.isArray(surface[key]) || !surface[key].every((s) => typeof s === 'string')) {
        errors.push(`settings.frontdoor.surface.${key} must be an array of strings`);
      }
    }
  }
  if (surface.healthDetail !== undefined && typeof surface.healthDetail !== 'boolean') {
    errors.push('settings.frontdoor.surface.healthDetail must be boolean');
  }
}

function validateTransport(transport, label, errors) {
  if (!isPlainObject(transport)) {
    errors.push(`${label} must be an object`);
    return;
  }
  const allowed = new Set(['type', 'host', 'port']);
  for (const key of Object.keys(transport)) {
    if (!allowed.has(key)) errors.push(`${label}: unknown key "${key}"`);
  }
  if (transport.type !== undefined && !VALID_TRANSPORT_TYPES.has(transport.type)) {
    errors.push(`${label}.type must be one of: ${[...VALID_TRANSPORT_TYPES].join(', ')}`);
  }
  if (transport.host !== undefined && transport.host !== null && typeof transport.host !== 'string') {
    errors.push(`${label}.host must be a string`);
  }
  if (transport.port !== undefined && transport.port !== null) {
    const p = transport.port;
    if (!Number.isInteger(p) || p < 0 || p > 65535) {
      errors.push(`${label}.port must be an integer in [0, 65535]`);
    }
  }
}

function validatePathWrapper(value, label, errors, cwd) {
  if (!isPlainObject(value)) {
    errors.push(`${label} must be an object`);
    return;
  }
  for (const key of Object.keys(value)) {
    if (key !== 'path') errors.push(`${label}: unknown key "${key}"`);
  }
  if (value.path !== undefined && value.path !== null) {
    if (typeof value.path !== 'string') {
      errors.push(`${label}.path must be a string`);
    } else if (!isPathContained(value.path, cwd)) {
      errors.push(
        `${label}.path must be a relative path contained within the working directory (got "${value.path}")`,
      );
    }
  }
}

/**
 * Return true only when `p` resolves to a path strictly inside `cwd`.
 * Rejects absolute paths and any path that escapes via `..` traversal.
 *
 * @param {string} p   - The path value from settings.
 * @param {string} cwd - Working directory to treat as the containment root.
 * @returns {boolean}
 */
function isPathContained(p, cwd) {
  // Reject absolute paths outright — they can target arbitrary locations.
  if (isAbsolute(p)) return false;
  const abs = resolve(cwd, p);
  const rel = relative(cwd, abs);
  // A safe relative path never starts with '..' and is never empty (which
  // would mean it equals cwd itself — a directory, not a file).
  return rel.length > 0 && !rel.startsWith('..');
}

function hasAnyAuth(auth) {
  if (!isPlainObject(auth)) return false;
  return (
    (auth.requireBearerEnv !== undefined && auth.requireBearerEnv !== null) ||
    (auth.bearerFile !== undefined && auth.bearerFile !== null)
  );
}

/**
 * Parse a byte size value.
 *   "1MB" / "512KB" / "2GB" / "1024" / 1024 → bytes (number).
 * Returns `null` when the input can't be parsed — callers (validator, consumer
 * site) decide how to treat the nullish result.
 *
 * @param {string|number} value
 * @returns {number|null}
 */
export function parseByteSize(value) {
  if (typeof value === 'number') {
    return Number.isFinite(value) && value >= 0 ? value : null;
  }
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed === '') return null;
  // Support integer literals with optional suffix. Reject negative / decimal.
  const m = /^(\d+)\s*([KMGT]?B)?$/i.exec(trimmed);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  const suffix = (m[2] || 'B').toUpperCase();
  const mult = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 }[suffix];
  if (mult === undefined) return null;
  return n * mult;
}

function tryParseByteSize(value) {
  return parseByteSize(value);
}

/**
 * Pick the first defined value from a precedence chain.
 * `null` and `undefined` are treated as "not set"; `false`, `0`, `""`, `[]`
 * are treated as set (operator explicitly chose them).
 *
 * Usage: `pick(cliValue, envValue, settingsValue, DEFAULT)`.
 *
 * @param  {...any} values
 * @returns {any}
 */
export function pick(...values) {
  for (const v of values) {
    if (v !== undefined && v !== null) return v;
  }
  return undefined;
}

function mergeWithDefaults(partial) {
  return {
    instance: { ...DEFAULT_SETTINGS.instance, ...(partial.instance || {}) },
    bridge: mergeBridge(partial.bridge || {}),
    frontdoor: mergeFrontdoor(partial.frontdoor || {}),
  };
}

function mergeBridge(b) {
  return {
    transport: { ...DEFAULT_SETTINGS.bridge.transport, ...(b.transport || {}) },
    limits: {
      dispatch: { ...DEFAULT_SETTINGS.bridge.limits.dispatch, ...((b.limits || {}).dispatch || {}) },
      request: { ...DEFAULT_SETTINGS.bridge.limits.request, ...((b.limits || {}).request || {}) },
      response: { ...DEFAULT_SETTINGS.bridge.limits.response, ...((b.limits || {}).response || {}) },
    },
    network: { ...DEFAULT_SETTINGS.bridge.network, ...(b.network || {}) },
    vault: { ...DEFAULT_SETTINGS.bridge.vault, ...(b.vault || {}) },
  };
}

function mergeFrontdoor(f) {
  return {
    transport: { ...DEFAULT_SETTINGS.frontdoor.transport, ...(f.transport || {}) },
    auth: { ...DEFAULT_SETTINGS.frontdoor.auth, ...(f.auth || {}) },
    network: { ...DEFAULT_SETTINGS.frontdoor.network, ...(f.network || {}) },
    limits: {
      sse: { ...DEFAULT_SETTINGS.frontdoor.limits.sse, ...((f.limits || {}).sse || {}) },
    },
    surface: { ...DEFAULT_SETTINGS.frontdoor.surface, ...(f.surface || {}) },
    policy: { ...DEFAULT_SETTINGS.frontdoor.policy, ...(f.policy || {}) },
    tenantMap: { ...DEFAULT_SETTINGS.frontdoor.tenantMap, ...(f.tenantMap || {}) },
    telemetry: { ...DEFAULT_SETTINGS.frontdoor.telemetry, ...(f.telemetry || {}) },
  };
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function deepFreeze(o) {
  if (o === null || typeof o !== 'object' || Object.isFrozen(o)) return o;
  for (const key of Object.keys(o)) {
    deepFreeze(o[key]);
  }
  return Object.freeze(o);
}
