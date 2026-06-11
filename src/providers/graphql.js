/**
 * GraphQL Provider — Provider-interface adapter over `loadGraphqlSchema`.
 *
 * Pure adapter, mirroring `providers/openapi.js`: no new parsing, no new
 * validation, no reshaping of tool objects. The legacy
 * `loadGraphqlSchema(...)` export remains the stable surface — this wrapper
 * does not replace it.
 *
 * @module providers/graphql
 */

import { loadGraphqlSchema } from '../loaders/graphql.js';

/**
 * Build a GraphQL Provider.
 *
 * Loading (introspection fetch for endpoint URLs, or conversion of an
 * already-parsed schema object) is deferred until `components()` is
 * invoked, so construction is synchronous and non-throwing for I/O.
 *
 * @param {string|object} endpointOrSchema - Endpoint URL or parsed
 *   introspection schema, passed straight to `loadGraphqlSchema`.
 * @param {object} [opts]
 * @param {string} [opts.name='graphql'] - Provider name for audit logging
 *   and collision detection (SPEC §2 prefix regex).
 * @param {object} [opts.headers]       - Forwarded to `loadGraphqlSchema`.
 * @param {string} [opts.endpoint]      - Forwarded to `loadGraphqlSchema`.
 * @param {boolean} [opts.allowPrivate] - Forwarded to `loadGraphqlSchema`.
 * @returns {{ name: string, components: () => Promise<{ tools: object[] }> }}
 */
export function graphql(endpointOrSchema, opts = {}) {
  const { name = 'graphql', ...loaderOpts } = opts;

  return {
    name,
    async components() {
      const { tools } = await loadGraphqlSchema(endpointOrSchema, loaderOpts);
      return { tools };
    },
  };
}
