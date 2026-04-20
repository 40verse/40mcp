/**
 * Multi-tenant tool scoping — per-call auth context.
 *
 * Wraps a bridge dispatch function to inject per-tenant credentials
 * and tool access control. Each call can carry a tenant context that
 * overrides the base auth and restricts which tools are available.
 *
 * @module tenant/scope
 */

import { BridgeError, BridgeErrorCode } from '../errors.js';

/**
 * Safe HTTP header name pattern. Tenant-controlled `auth.header` fields flow
 * straight into the request headers; without this check a tenant context
 * containing `header: "X-Evil\r\nInjected"` would cause header injection
 * depending on the underlying fetch runtime. Kept strict and matches the
 * pattern used by `src/core/client.js`.
 */
const SAFE_HEADER_PATTERN = /^[a-zA-Z0-9\-]+$/;

/**
 * Deep-freeze an object and all its nested values so that mutable references
 * inside (e.g. allowlist/blocklist arrays) cannot be modified by downstream
 * hooks or chain-step executors after the tenant envelope is built. Handles
 * cycles via a WeakSet sentinel. Iterate ALL own properties including
 * non-enumerable ones — Object.values() only covers enumerable own properties,
 * leaving mutable references inside a "frozen" envelope.
 * @param {*} obj
 * @returns {*} The same object, frozen recursively
 */
const deepFreeze = (obj, _seen = new WeakSet()) => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (_seen.has(obj)) return obj;
  _seen.add(obj);
  Object.freeze(obj);
  // Use getOwnPropertyNames to include non-enumerable props (not just Object.values)
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object') {
      deepFreeze(val, _seen);
    }
  }
  return obj;
};

/**
 * Create a tenant-scoped dispatch wrapper.
 *
 * @param {object} config
 * @param {Function} config.dispatch - Base bridge dispatch function
 * @param {Function} config.resolveContext - async (request) => TenantContext
 *   Called on each tool dispatch to resolve the tenant context.
 *   Receives the MCP request metadata (or webhook metadata).
 *   Must return a TenantContext object.
 * @param {object} [config.defaults] - Default tenant context. By default this is
 *   ONLY used when `defaults.allowFallback === true`. Without that flag, an
 *   unresolved tenant context (resolveContext returning null/undefined) is treated
 *   as a hard authentication failure to prevent accidental ACL bypass when an
 *   operator configures a default tenant but expects allowlists to be enforced.
 * @returns {Function} Tenant-scoped dispatch function
 *
 * TenantContext schema:
 * {
 *   tenantId: 'tenant-123',               // Unique tenant identifier
 *   auth: { type: 'bearer', value: '...' }, // Override auth for this tenant
 *   allowlist: ['tool_a', 'tool_b'],       // Only these tools are accessible (optional)
 *   blocklist: ['admin_tool'],              // These tools are blocked (optional)
 *   metadata: { ... },                      // Arbitrary metadata passed to hooks
 * }
 */
export function createTenantScope(config) {
  const { dispatch, resolveContext, defaults = {} } = config;

  if (!dispatch) {
    throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, 'Tenant scope requires a dispatch function');
  }
  if (!resolveContext) {
    throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, 'Tenant scope requires a resolveContext function');
  }

  /**
   * Tenant-scoped dispatch.
   *
   * @param {string} toolName - Tool to call
   * @param {object} args - Tool arguments
   * @param {object} [requestMeta] - Request metadata (passed to resolveContext)
   * @returns {Promise<any>} Tool result
   */
  async function scopedDispatch(toolName, args, requestMeta) {
    // Resolve tenant context. SECURE-BY-DEFAULT: if resolveContext returns a falsy
    // value, refuse to fall back to `defaults` unless the operator explicitly opted
    // in with `defaults.allowFallback: true`. The previous behaviour silently
    // inherited `defaults` even when it carried no allowlist, allowing any caller
    // whose context failed to resolve to receive unrestricted tool access.
    const resolved = await resolveContext(requestMeta);
    let ctx;
    if (resolved) {
      ctx = resolved;
    } else if (defaults.allowFallback === true) {
      ctx = defaults;
    } else {
      throw new BridgeError(
        BridgeErrorCode.AUTH_MISSING,
        'No tenant context resolved and defaults.allowFallback is not enabled',
        { toolName },
      );
    }

    // Use != null (not !) so tenantId: 0 is a valid falsy-but-present
    // tenant rather than silently falling through to defaults.tenantId.
    if (ctx.tenantId == null && defaults.tenantId == null) {
      throw new BridgeError(
        BridgeErrorCode.AUTH_MISSING,
        'No tenant context resolved — tenantId is required',
      );
    }

    const tenantId = ctx.tenantId != null ? ctx.tenantId : defaults.tenantId;

    // Tool access control: allowlist.
    // REQUIRE Array. If a tenant context carries `allowlist: "list_users"`
    // (a string), `String.prototype.includes` would do SUBSTRING matching —
    // not exact-element matching — so any tool name that is a substring of
    // the allowlist string would match. Fail closed if the allowlist is present
    // but not an array.
    //
    // An empty array allowlist (`[]`) is treated as DENY-ALL, not allow-all.
    // Previously the `length > 0` short-circuit meant an operator who set
    // `allowlist: []` (e.g. for tenant suspension) would silently get
    // unrestricted access. Operators who want no restriction must OMIT the
    // `allowlist` field entirely.
    if (ctx.allowlist != null) {
      if (!Array.isArray(ctx.allowlist)) {
        throw new BridgeError(
          BridgeErrorCode.CONFIG_INVALID,
          `Tenant "${tenantId}" allowlist must be an array, got ${typeof ctx.allowlist}`,
          { tenantId },
        );
      }
      if (!ctx.allowlist.includes(toolName)) {
        // Previously the error context embedded the FULL allowlist — a probing
        // tenant could learn the entire set of tools another tenant was permitted
        // to call by submitting any disallowed tool name and reading the error
        // body. Never return the allowlist to the caller; operators can still
        // correlate via logs.
        throw new BridgeError(
          BridgeErrorCode.AUTH_MISSING,
          `Tool "${toolName}" is not in tenant "${tenantId}" allowlist`,
          { tenantId, toolName },
        );
      }
    }

    // Tool access control: blocklist — same type guard. An empty blocklist
    // is a no-op (blocks nothing) which is the intuitive reading.
    if (ctx.blocklist != null) {
      if (!Array.isArray(ctx.blocklist)) {
        throw new BridgeError(
          BridgeErrorCode.CONFIG_INVALID,
          `Tenant "${tenantId}" blocklist must be an array, got ${typeof ctx.blocklist}`,
          { tenantId },
        );
      }
      if (ctx.blocklist.includes(toolName)) {
        throw new BridgeError(
          BridgeErrorCode.AUTH_MISSING,
          `Tool "${toolName}" is blocked for tenant "${tenantId}"`,
          { tenantId, toolName },
        );
      }
    }

    // Inject tenant auth as a non-enumerable property so it doesn't appear in
    // JSON.stringify output, audit logs, or accidental arg passthrough.
    // Strip any attacker-supplied `_tenant` key first: a caller controlling the
    // raw args object could otherwise smuggle a tenant override that downstream
    // hooks reading from req.args/_tenant might honour before our defineProperty
    // overwrite takes effect.
    //
    // Include `allowlist` and `blocklist` on the tenant envelope so
    // chain-internal sub-step dispatches (which bypass `scopedDispatch` entirely
    // by calling `internalDispatch` directly) can re-enforce the per-tenant ACL.
    // Previously a tenant restricted to `['outer_chain_tool']` could invoke
    // EVERY inner tool that the chain declared, because the allowlist check only
    // ran at the outer wrapper. The bridge now re-checks allowlist/blocklist via
    // `args._tenant` on every dispatch, not just the entry point.
    const enrichedArgs = { ...args };
    delete enrichedArgs._tenant;
    // Freeze the _tenant envelope so no downstream hook or chain-step executor
    // can overwrite it by doing `args._tenant = {...}`. Previously
    // writable:true + configurable:true allowed any code that held the
    // enrichedArgs reference to silently escalate its tenant context.
    Object.defineProperty(enrichedArgs, '_tenant', {
      value: deepFreeze({
        tenantId,
        auth: ctx.auth || defaults.auth || null,
        metadata: { ...(defaults.metadata || {}), ...(ctx.metadata || {}) },
        allowlist: ctx.allowlist != null ? [...ctx.allowlist] : null,
        blocklist: ctx.blocklist != null ? [...ctx.blocklist] : null,
      }),
      enumerable: false,
      writable: false,
      configurable: false,
    });

    return dispatch(toolName, enrichedArgs);
  }

  return scopedDispatch;
}

/**
 * Create a per-tenant API client factory.
 *
 * Returns a beforeRequest hook that injects tenant-specific auth headers.
 * Use this with bridge config's hooks.beforeRequest.
 *
 * @returns {Function} beforeRequest hook
 */
export function tenantAuthHook() {
  return async (req) => {
    // The earlier implementation fell back to `req.body?._tenant` /
    // `req.args?._tenant` "for backwards compat". Those fields are
    // attacker-controllable — any caller submitting JSON containing
    // `{"_tenant":{"auth":{...}}}` could inject tenant auth headers on
    // outbound requests (BYOK header injection). The scoped dispatcher already
    // attaches a non-enumerable `_tenant` to the args and the bridge's path.js
    // copies the value to `req.tenant`, so server-side population is always
    // available when scoping is in use. Drop the body/args fallback entirely.
    const tenantCtx = req.tenant;
    if (!tenantCtx?.auth) return null;

    const { auth } = tenantCtx;
    const headers = {};

    switch (auth.type) {
      case 'bearer': {
        const token = auth.value || (auth.envVar ? process.env[auth.envVar] : '') || '';
        if (token) headers['Authorization'] = `Bearer ${token}`;
        break;
      }
      case 'header': {
        const value = auth.value || (auth.envVar ? process.env[auth.envVar] : '') || '';
        if (value && auth.header) {
          if (!SAFE_HEADER_PATTERN.test(auth.header)) {
            process.stderr.write(
              `[40mcp] SECURITY: tenant auth.header "${auth.header}" contains invalid characters; refusing to inject\n`,
            );
            break;
          }
          headers[auth.header] = value;
        }
        break;
      }
      case 'basic': {
        const creds = auth.value || (auth.envVar ? process.env[auth.envVar] : '') || '';
        if (creds) headers['Authorization'] = `Basic ${Buffer.from(creds).toString('base64')}`;
        break;
      }
    }

    // The backwards-compat `body._tenant` / `args._tenant` strip path is
    // gone with the fallback read. The scoped dispatcher already strips
    // `_tenant` from `enrichedArgs` as a non-enumerable property, so nothing
    // leaks downstream. Just return headers.
    return { headers };
  };
}
