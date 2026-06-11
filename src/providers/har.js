/**
 * HAR Provider — Provider-interface adapter over `loadHarFile`.
 *
 * Pure adapter, mirroring `providers/openapi.js`: no new parsing, no new
 * validation, no reshaping of tool objects. The legacy `loadHarFile(...)`
 * export remains the stable surface — this wrapper does not replace it.
 *
 * @module providers/har
 */

import { loadHarFile } from '../loaders/har.js';

/**
 * Build a HAR Provider.
 *
 * File reading / traffic analysis is deferred until `components()` is
 * invoked, so construction is synchronous and non-throwing for I/O.
 *
 * @param {string|object} harOrPath - HAR file path or parsed HAR object,
 *   passed straight to `loadHarFile`.
 * @param {object} [opts]
 * @param {string} [opts.name='har'] - Provider name for audit logging and
 *   collision detection (SPEC §2 prefix regex).
 * @param {string[]} [opts.include]        - Forwarded to `loadHarFile`.
 * @param {string[]} [opts.exclude]        - Forwarded to `loadHarFile`.
 * @param {string[]} [opts.methods]        - Forwarded to `loadHarFile`.
 * @param {number}   [opts.minObservations] - Forwarded to `loadHarFile`.
 * @param {boolean}  [opts.allowPrivate]   - Forwarded to `loadHarFile`.
 * @returns {{ name: string, components: () => Promise<{ tools: object[] }> }}
 */
export function har(harOrPath, opts = {}) {
  const { name = 'har', ...loaderOpts } = opts;

  return {
    name,
    async components() {
      const { tools } = await loadHarFile(harOrPath, loaderOpts);
      return { tools };
    },
  };
}
