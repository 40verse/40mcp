/**
 * Provider interface shell.
 *
 * A Provider is anything that emits `{ tools, resources?, prompts? }`. The
 * interface is pure duck typing — there is no class hierarchy. Any object
 * with the shape below satisfies the contract:
 *
 *   {
 *     name:       string,                                  // stable identity
 *     components: () => Promise<{ tools: Tool[], resources?, prompts? }>,
 *     close?:     () => Promise<void>,                     // optional cleanup
 *   }
 *
 * `name` is required so audit logs and diagnostics can attribute a tool to
 * its origin ("this tool came from provider `openapi:stripe`"). `close()`
 * is optional and exists for providers holding network handles (linked MCP
 * stdio/SSE, future HAR watchers) so not every caller has to know which
 * provider kinds need cleanup.
 *
 * ### What this module ships
 *
 * - `createProvider({ name, components, close? })` — validating factory that
 *   returns a frozen Provider-conformant object.
 * - `openapi(specOrUrl, opts)` / `graphql(endpointOrSchema, opts)` /
 *   `har(harOrPath, opts)` — adapters wrapping the corresponding loaders.
 * - `componentsFromProviders(providers)` — gather `{ tools }` from N
 *   providers with SPEC §2 collision rules.
 *
 * ### Bridge integration
 *
 * `componentsFromProviders(providers)` gathers `{ tools }` from a provider
 * list with fail-loud collision rules, and `createBridgeFromProviders`
 * (src/compose/from-providers.js) builds a bridge from providers and ties
 * provider `close()` into the bridge lifecycle. Legacy loaders
 * (`loadOpenApiSpec`, `loadGraphqlSchema`, `loadHarFile`, `connectStdio`,
 * `connectSse`, `createReverseBridge`) keep their current return shape and
 * remain the stable surface — the Provider path is additive.
 *
 * ### What this module does NOT ship
 *
 * - Transform / Hooks interfaces. Those live in separate modules.
 *
 * @module providers
 */

import { BridgeError, BridgeErrorCode } from '../errors.js';

/**
 * Tool-name / prefix character charset and length, pinned in SPEC.md §2
 * ("Tool-name invariant"): `^[a-zA-Z0-9_-]{1,64}$`. Provider names participate
 * in the same namespace as tool prefixes — a provider's `name` is how audit
 * logs and collision detection refer to it — so we reuse the same regex to
 * keep the identifier universe coherent.
 */
const PROVIDER_NAME_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * Construct a Provider-conformant object.
 *
 * Validates:
 *   - `name` is a non-empty string matching the prefix regex from SPEC §2.
 *   - `components` is a function (async or sync returning a promise).
 *   - `close`, if provided, is a function.
 *
 * Returns a frozen object so callers cannot accidentally mutate `name` or
 * swap `components` after registration. The frozen shape also means the
 * bridge (when W2.x+ wires providers in) can rely on stable identity for
 * collision detection and lifecycle bookkeeping.
 *
 * @param {object} spec
 * @param {string} spec.name - Stable provider identity (matches `^[a-zA-Z0-9_-]{1,64}$`).
 * @param {() => Promise<{ tools: object[], resources?: object[], prompts?: object[] }>} spec.components
 * @param {() => Promise<void>} [spec.close] - Optional cleanup (awaited at bridge/frontdoor close).
 * @returns {Readonly<{ name: string, components: Function, close?: Function }>}
 */
export function createProvider(spec) {
  if (spec == null || typeof spec !== 'object') {
    throw new TypeError(
      'createProvider({ name, components, close? }) requires an object spec.',
    );
  }

  const { name, components, close } = spec;

  if (typeof name !== 'string' || name.length === 0) {
    throw new TypeError(
      'createProvider: `name` must be a non-empty string.',
    );
  }
  if (!PROVIDER_NAME_REGEX.test(name)) {
    throw new TypeError(
      `createProvider: \`name\` "${name}" does not match the tool-prefix regex ` +
      `${PROVIDER_NAME_REGEX} pinned in SPEC.md §2 (Tool-name invariant). ` +
      'Provider names share the tool-prefix namespace; allowed charset is ' +
      '[a-zA-Z0-9_-], 1-64 chars.',
    );
  }
  if (typeof components !== 'function') {
    throw new TypeError(
      'createProvider: `components` must be a function returning ' +
      '{ tools, resources?, prompts? } (or a promise thereof).',
    );
  }
  if (close !== undefined && typeof close !== 'function') {
    throw new TypeError(
      'createProvider: `close`, if provided, must be a function.',
    );
  }

  // Only attach `close` when the caller supplied one. Keeping the property
  // absent (rather than `undefined`) lets callers duck-type-check with
  // `'close' in provider` if they need to decide whether to invoke it.
  const provider = close !== undefined
    ? { name, components, close }
    : { name, components };

  return Object.freeze(provider);
}

/**
 * Gather components from N Providers into a single `{ tools }` set.
 *
 * This is the Provider-side half of bridge integration: callers resolve a
 * provider list into one tool array, then hand it to `createRestBridge`
 * (or use the `createBridgeFromProviders` convenience in
 * `src/compose/from-providers.js`, which does both steps and wires
 * provider `close()` into the bridge lifecycle).
 *
 * Collision behaviour follows SPEC §2 ("Tool-name invariant"): a duplicate
 * tool name across providers fails loudly with a `CONFIG_INVALID`
 * BridgeError naming the conflicting tool and both providers — the same
 * contract `connectMany` and `createMixer` enforce. There is no silent
 * drop.
 *
 * @param {Array<{ name: string, components: Function, close?: Function }>} providers
 * @returns {Promise<{ tools: object[] }>}
 */
export async function componentsFromProviders(providers) {
  if (!Array.isArray(providers) || providers.length === 0) {
    throw new TypeError(
      'componentsFromProviders(providers) requires a non-empty array of Provider-conformant objects.',
    );
  }
  const tools = [];
  const originByToolName = new Map();
  for (const provider of providers) {
    if (!provider || typeof provider.name !== 'string' || typeof provider.components !== 'function') {
      throw new TypeError(
        'componentsFromProviders: every entry must be Provider-conformant ' +
        '({ name: string, components: () => Promise<{ tools }> }).',
      );
    }
    const components = await provider.components();
    const providerTools = components && Array.isArray(components.tools) ? components.tools : null;
    if (!providerTools) {
      throw new BridgeError(
        BridgeErrorCode.CONFIG_INVALID,
        `Provider "${provider.name}" components() did not return { tools: Tool[] }.`,
      );
    }
    for (const tool of providerTools) {
      const existing = originByToolName.get(tool.name);
      if (existing !== undefined) {
        throw new BridgeError(
          BridgeErrorCode.CONFIG_INVALID,
          `Duplicate tool name "${tool.name}" from provider "${provider.name}" ` +
          `(already provided by "${existing}"). Use distinct tool names or a ` +
          'nameTransform on one provider to disambiguate.',
        );
      }
      originByToolName.set(tool.name, provider.name);
      tools.push(tool);
    }
  }
  return { tools };
}

export { openapi } from './openapi.js';
export { graphql } from './graphql.js';
export { har } from './har.js';
