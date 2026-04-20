/**
 * OpenAPI Provider — reference implementation of the Provider interface.
 *
 * A thin wrapper around the existing `loadOpenApiSpec` loader. The point of
 * this module is to demonstrate that a Provider can be authored as a pure
 * adapter: no new parsing, no new validation, no reshaping of tool objects.
 *
 * The legacy `loadOpenApiSpec(...)` export in `src/openapi.js` and
 * `src/index.js` remains the stable surface — this wrapper does not replace
 * it. Call sites are free to continue using the loader directly.
 *
 * @module providers/openapi
 */

import { loadOpenApiSpec } from '../openapi.js';

/**
 * Build an OpenAPI Provider.
 *
 * The returned object is duck-typed-Provider — callers get the tool array
 * verbatim from `loadOpenApiSpec`, including every field (`name`, `method`,
 * `path`, `inputSchema`, `bodyMap`, etc.) in its existing shape. No close()
 * is exposed because the underlying loader holds no open handles.
 *
 * Note: spec loading is deferred until `components()` is invoked, so
 * `openapi(specOrUrl)` itself is synchronous and non-throwing for I/O. This
 * matches how linked-MCP providers will behave once they move behind this
 * interface (construction cheap, connection lazy).
 *
 * @param {string|object} specOrUrl - Path / URL / parsed spec object, passed
 *   straight to `loadOpenApiSpec`.
 * @param {object} [opts]
 * @param {string} [opts.name='openapi'] - Provider name for audit logging
 *   and collision detection. Must satisfy the SPEC §2 prefix regex
 *   (enforced by `createProvider`).
 * @param {string[]} [opts.include]      - Forwarded to `loadOpenApiSpec`.
 * @param {string[]} [opts.exclude]      - Forwarded to `loadOpenApiSpec`.
 * @param {string[]} [opts.tags]         - Forwarded to `loadOpenApiSpec`.
 * @param {string[]} [opts.methods]      - Forwarded to `loadOpenApiSpec`.
 * @param {Function} [opts.nameTransform] - Forwarded to `loadOpenApiSpec`.
 * @param {boolean}  [opts.allowPrivate] - Forwarded to `loadOpenApiSpec`.
 * @param {boolean}  [opts.strict]       - Forwarded to `loadOpenApiSpec`.
 * @returns {{ name: string, components: () => Promise<{ tools: object[] }> }}
 */
export function openapi(specOrUrl, opts = {}) {
  const { name = 'openapi', ...loaderOpts } = opts;

  return {
    name,
    async components() {
      // Preserve the loader output verbatim — do not reshape tool objects.
      // `loadOpenApiSpec` returns `{ baseUrl, tools }`; the Provider contract
      // only requires `tools` (with optional `resources` / `prompts`), so we
      // forward just the tools array. `baseUrl` remains available via the
      // legacy loader for callers that need it.
      const { tools } = await loadOpenApiSpec(specOrUrl, loaderOpts);
      return { tools };
    },
  };
}
