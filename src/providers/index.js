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
 * - `openapi(specOrUrl, opts)` — the one reference implementation, wrapping
 *   `loadOpenApiSpec`.
 *
 * ### What this module does NOT ship
 *
 * - Bridge integration. Providers exist but `createRestBridge` does not yet
 *   consume them through this interface. Legacy loaders (`loadOpenApiSpec`,
 *   `loadGraphqlSchema`, `loadHarFile`, `connectStdio`, `connectSse`,
 *   `createReverseBridge`) keep their current return shape and remain the
 *   stable surface; migration is additive and lands in a future PR.
 * - Transform / Hooks interfaces. Those live in separate modules.
 *
 * @module providers
 */

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

export { openapi } from './openapi.js';
