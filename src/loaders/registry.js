/**
 * Loader plugin registry — extensible API format detection and loading.
 *
 * Built-in loaders: OpenAPI, GraphQL, HAR.
 * Custom loaders can be registered for gRPC, WebSocket, SOAP, etc.
 *
 * @module loaders/registry
 */

import { loadOpenApiSpec } from '../openapi.js';
import { loadGraphqlSchema } from './graphql.js';
import { loadHarFile } from './har.js';

/** @type {Array<import('../index.d.ts').LoaderPlugin>} */
const plugins = [];

// ─── Built-in loaders ───────────────────────────────────────────────────────

const builtinOpenApi = {
  name: 'openapi',
  detect(input) {
    if (typeof input === 'object' && input !== null) {
      return !!(input.openapi || input.swagger || input.paths);
    }
    if (typeof input === 'string') {
      return /\.(json|ya?ml)$/i.test(input) && !/\.har$/i.test(input);
    }
    return false;
  },
  load: loadOpenApiSpec,
};

const builtinGraphql = {
  name: 'graphql',
  detect(input) {
    if (typeof input === 'object' && input !== null) {
      return !!input.__schema || !!input.data?.__schema;
    }
    if (typeof input === 'string') {
      return /^https?:\/\//.test(input) && /graphql/i.test(input);
    }
    return false;
  },
  load: loadGraphqlSchema,
};

const builtinHar = {
  name: 'har',
  detect(input) {
    if (typeof input === 'object' && input !== null) {
      return !!(input.log && input.log.entries);
    }
    if (typeof input === 'string') {
      return /\.har$/i.test(input);
    }
    return false;
  },
  load: loadHarFile,
};

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Register a custom loader plugin.
 * Custom plugins are checked before built-in loaders (LIFO order).
 *
 * @param {object} plugin
 * @param {string} plugin.name - Unique loader name
 * @param {Function} plugin.detect - (input: string|object) => boolean
 * @param {Function} plugin.load - (input: string|object, options?) => Promise<{ baseUrl, tools }>
 */
export function registerLoader(plugin) {
  if (!plugin.name || !plugin.detect || !plugin.load) {
    throw new Error('Loader plugin must have name, detect, and load properties');
  }

  // Remove existing plugin with same name (allows re-registration)
  const idx = plugins.findIndex((p) => p.name === plugin.name);
  if (idx !== -1) plugins.splice(idx, 1);

  // Prepend so custom loaders take priority
  plugins.unshift(plugin);
}

/**
 * Auto-detect and load tools from any supported format.
 *
 * Checks registered plugins first (custom loaders), then built-in loaders.
 * Throws if no loader can handle the input.
 *
 * @param {string|object} input - File path, URL, or parsed object
 * @param {object} [options] - Passed to the matching loader
 * @returns {Promise<{ baseUrl: string, tools: Array }>}
 */
export async function loadFromAny(input, options) {
  if (input == null) {
    throw new Error(
      `loadFromAny() requires a file path, URL, or parsed object — received ${input === null ? 'null' : 'undefined'}. ` +
      `Register a custom loader with registerLoader({ name, detect, load }).`,
    );
  }

  // Check custom plugins first
  for (const plugin of plugins) {
    if (plugin.detect(input)) {
      return plugin.load(input, options);
    }
  }

  // Check built-in loaders
  if (builtinOpenApi.detect(input)) return builtinOpenApi.load(input, options);
  if (builtinGraphql.detect(input)) return builtinGraphql.load(input, options);
  if (builtinHar.detect(input)) return builtinHar.load(input, options);

  const inputDesc =
    typeof input === 'string' ? input : (JSON.stringify(input) ?? String(input)).slice(0, 100);
  throw new Error(
    `No loader found for input: ${inputDesc}. ` +
    `Register a custom loader with registerLoader({ name, detect, load }).`,
  );
}

/**
 * List all registered loader plugins (custom + built-in).
 * @returns {Array<{ name: string, builtin: boolean }>}
 */
export function listLoaders() {
  const custom = plugins.map((p) => ({ name: p.name, builtin: false }));
  const builtin = [
    { name: 'openapi', builtin: true },
    { name: 'graphql', builtin: true },
    { name: 'har', builtin: true },
  ];
  return [...custom, ...builtin];
}
