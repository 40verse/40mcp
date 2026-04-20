import { ApiError, AuthError, BridgeError, BridgeErrorCode, apiErrorFromStatus } from '../errors.js';
import { assertSafeUrl } from './env.js';
import { safeLog } from './events.js';

/** A03-1: Validate header name to prevent header injection. */
const SAFE_HEADER_PATTERN = /^[a-zA-Z0-9\-]+$/;

/**
 * Defense-in-depth validation of header VALUES returned by beforeRequest /
 * tenant auth hooks. Although undici rejects CRLF + other control characters
 * at serialisation, validating at the boundary gives a clear error and prevents
 * the control-char from ever reaching the socket. Permits horizontal tab
 * (0x09), printable ASCII (>= 0x20), and any byte >= 0x80 so UTF-8 /
 * extended-ASCII values still pass.
 */
function isUnsafeHeaderValue(v) {
  if (typeof v !== 'string') return false;
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    // Reject \r (0x0D), \n (0x0A), NUL (0x00), DEL (0x7F), and everything
    // below 0x20 except horizontal tab (0x09).
    if (c === 0x7f) return true;
    if (c < 0x20 && c !== 0x09) return true;
  }
  return false;
}

/**
 * Format an AbortSignal.reason (or an AbortError) as a short human string.
 * External cancellation often carries no reason — default to a stable phrase.
 */
function reasonMessage(reason) {
  if (reason == null) return 'external cancellation';
  if (typeof reason === 'string') return reason;
  if (reason instanceof Error) return reason.message || reason.name || 'external cancellation';
  try {
    return String(reason);
  } catch {
    return 'external cancellation';
  }
}

/** Safely read an environment variable — rejects keys that aren't valid env var names to prevent prototype pollution or controlled variable injection. */
function safeEnvVar(name) {
  if (typeof name !== 'string' || !/^[A-Z_][A-Z0-9_]*$/i.test(name)) return undefined;
  return process.env[name];
}

// ─── Circuit Breaker ─────────────────────────────────────────────────────────

const CB_CLOSED = 'CLOSED';
const CB_OPEN = 'OPEN';
const CB_HALF_OPEN = 'HALF_OPEN';

/**
 * Simple per-client circuit breaker.
 * Opens after `threshold` consecutive failures; attempts recovery after `recoveryMs`.
 */
class CircuitBreaker {
  constructor({ threshold = 5, recoveryMs = 60_000 } = {}) {
    this.threshold = threshold;
    this.recoveryMs = recoveryMs;
    this._state = CB_CLOSED;
    this._failures = 0;
    this._openedAt = null;
  }

  /** Returns true if the next call is allowed through. */
  allowRequest() {
    if (this._state === CB_CLOSED) return true;
    if (this._state === CB_OPEN) {
      if (Date.now() - this._openedAt >= this.recoveryMs) {
        this._state = CB_HALF_OPEN;
        return true; // allow one probe
      }
      return false;
    }
    // HALF_OPEN — one probe allowed
    return true;
  }

  /** Call on successful response. */
  onSuccess() {
    this._failures = 0;
    this._state = CB_CLOSED;
    this._openedAt = null;
  }

  /** Call on failed response. */
  onFailure() {
    this._failures += 1;
    if (this._state === CB_HALF_OPEN || this._failures >= this.threshold) {
      this._state = CB_OPEN;
      this._openedAt = Date.now();
    }
  }

  get state() {
    return this._state;
  }
}

/**
 * OAuth2 token cache for automatic refresh.
 * @private
 */
class OAuth2TokenManager {
  constructor(config) {
    this.tokenUrl = config.tokenUrl;
    // SSRF guard: the OAuth2 token endpoint is an outbound fetch target chosen
    // by the config. A spec with `tokenUrl: "http://169.254.169.254/..."`
    // would previously POST the client credentials (and any refresh token) to
    // the cloud metadata endpoint on every refresh — simultaneously an SSRF
    // AND a credential-exfil oracle. Validate with the same guard used by the
    // OpenAPI / GraphQL / CLI URL-accepting paths.
    assertSafeUrl(this.tokenUrl, {
      allowPrivate: config.allowPrivate === true,
      label: 'oauth2 tokenUrl',
    });
    this.clientId = safeEnvVar(config.clientIdEnv) || config.clientId || '';
    this.clientSecret = safeEnvVar(config.clientSecretEnv) || config.clientSecret || '';
    if (config.clientSecret && !config.clientSecretEnv) {
      process.stderr.write('[40mcp] WARNING: oauth2 clientSecret is set directly in config — credentials may be committed to source control. Use clientSecretEnv instead.\n');
    }
    this.scope = config.scope || '';
    this.grantType = config.grantType || 'client_credentials';
    // Backoff after refresh failure: don't hammer the token endpoint
    this.retryDelayMs = config.retryDelayMs || 5_000;
    this._accessToken = null;
    this._expiresAt = 0;
    this._refreshPromise = null;
    this._lastFailureTime = 0;
  }

  async getToken() {
    // Return cached token if still valid (with 60s buffer)
    if (this._accessToken && Date.now() < this._expiresAt - 60_000) {
      return this._accessToken;
    }

    // Backoff: if the last refresh attempt failed recently, don't retry yet
    if (this._lastFailureTime && Date.now() - this._lastFailureTime < this.retryDelayMs) {
      throw new AuthError(
        BridgeErrorCode.AUTH_EXPIRED,
        `OAuth2 token refresh is in backoff — last attempt failed ${Date.now() - this._lastFailureTime}ms ago. Retry after ${this.retryDelayMs}ms.`,
        { tokenUrl: this.tokenUrl },
      );
    }

    // Coalesce concurrent refresh requests
    if (this._refreshPromise) {
      return this._refreshPromise;
    }

    this._refreshPromise = this._refresh();
    try {
      const token = await this._refreshPromise;
      this._lastFailureTime = 0; // reset on success
      return token;
    } catch (err) {
      this._lastFailureTime = Date.now();
      throw err;
    } finally {
      this._refreshPromise = null;
    }
  }

  async _refresh() {
    const body = new URLSearchParams({
      grant_type: this.grantType,
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });
    if (this.scope) body.set('scope', this.scope);

    // Cap OAuth2 token refresh at 10 s by default. Without a timeout, a slow
    // or malicious token endpoint could stall the first dispatch on every
    // refresh cycle indefinitely.
    const refreshTimeoutMs = 10_000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), refreshTimeoutMs);
    let response;
    try {
      // Use `redirect: 'manual'` to prevent a compromised OAuth2 authorization
      // server from redirecting to IMDS and exfiltrating credentials. Without
      // this, a server returning `302 Location: http://169.254.169.254/...`
      // would cause undici to REPLAY the POST body (including client_id +
      // client_secret) on 307/308 redirects. `manual` returns an opaque
      // redirect response which we treat as a failure.
      response = await fetch(this.tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        signal: controller.signal,
        redirect: 'manual',
      });
      if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
        throw new AuthError(
          BridgeErrorCode.AUTH_EXPIRED,
          `OAuth2 token endpoint returned a redirect — refusing to follow. Check tokenUrl.`,
          { tokenUrl: this.tokenUrl },
        );
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new AuthError(
          BridgeErrorCode.AUTH_EXPIRED,
          `OAuth2 token refresh timed out after ${refreshTimeoutMs}ms`,
          { tokenUrl: this.tokenUrl, timeoutMs: refreshTimeoutMs },
        );
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      throw new AuthError(
        BridgeErrorCode.AUTH_EXPIRED,
        `OAuth2 token refresh failed: ${response.status}`,
        { tokenUrl: this.tokenUrl, status: response.status },
      );
    }

    const data = await response.json();
    this._accessToken = data.access_token;
    this._expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    return this._accessToken;
  }
}

/**
 * Warn once at client construction time when `auth.value` contains an
 * unresolved `${VAR}` template. Users who confuse `auth.envVar` with
 * `auth.value` otherwise send the literal string as the credential and see
 * silent 401s. The warning is emitted at `createApiClient` setup — not per
 * request — so sustained workloads don't flood stderr.
 */
function warnOnUnresolvedAuthValue(authConfig) {
  if (!authConfig || typeof authConfig.value !== 'string') return;
  if (/\$\{?[A-Z_]/.test(authConfig.value)) {
    process.stderr.write(
      `[40mcp] WARNING: auth.value contains an unresolved template (e.g. "\${VAR}"). ` +
      `This is NOT expanded — use auth.envVar instead to reference an env var. ` +
      `The literal string will be sent as the credential and likely fail authentication.\n`,
    );
  }
}

function buildHeaders(authConfig) {
  const headers = { 'Content-Type': 'application/json' };

  if (!authConfig) return headers;

  switch (authConfig.type) {
    case 'header': {
      const value = safeEnvVar(authConfig.envVar) || authConfig.value || '';
      if (value) headers[authConfig.header] = value;
      break;
    }
    case 'bearer': {
      const token = safeEnvVar(authConfig.envVar) || authConfig.value || '';
      if (token) headers['Authorization'] = `Bearer ${token}`;
      break;
    }
    case 'basic': {
      const creds = safeEnvVar(authConfig.envVar) || authConfig.value || '';
      if (creds) headers['Authorization'] = `Basic ${Buffer.from(creds).toString('base64')}`;
      break;
    }
    case 'oauth2': {
      // Token will be injected dynamically per-request
      break;
    }
    case 'sealed':
    case 'sealed-bearer':
      // Auth injected via beforeRequest hook from vault — no static header
      break;
  }

  return headers;
}

/**
 * Create an API client factory.
 *
 * @param {string} baseUrl - Resolved base URL
 * @param {object} [authConfig] - Auth configuration
 * @param {object} [hooks] - Lifecycle hooks
 * @returns {Function} async function(method, path, body)
 */
export function createApiClient(baseUrl, authConfig, hooks) {
  const resolvedBaseUrl = baseUrl.replace(/\/$/, '');

  // A10-1: Validate baseUrl scheme to prevent SSRF
  if (resolvedBaseUrl && !/^https?:\/\//i.test(resolvedBaseUrl)) {
    throw new Error(`Invalid baseUrl scheme: "${resolvedBaseUrl}". Only http:// and https:// are allowed.`);
  }

  // SSRF defence-in-depth: the redirect walk and OAuth2 token endpoint both
  // run target URLs through `assertSafeUrl`, but the initial
  // `${resolvedBaseUrl}${path}` passed to fetch() used to be scheme-checked
  // only. Callers who use `createApiClient` directly (e.g. via
  // `compose/mixer.js`) or who construct a bridge without the top-level
  // `strictSsrf` check got no protection against an adversarial
  // `baseUrl: "http://169.254.169.254"`.
  //
  // Default `allowPrivate: true` matches `createRestBridge`'s default
  // (loopback + RFC-1918 stay reachable for local dev and test harnesses).
  // `assertSafeUrl` always refuses cloud-metadata hosts regardless of the
  // flag, so this gate closes the credential-exfil path without breaking
  // legitimate localhost development. Pass `hooks.allowPrivate: false` for
  // strict production mode.
  if (resolvedBaseUrl) {
    assertSafeUrl(resolvedBaseUrl, {
      allowPrivate: hooks?.allowPrivate !== false,
      label: 'baseUrl',
    });
  }

  // Fire the auth.value template warning ONCE at
  // construction time, not per request.
  warnOnUnresolvedAuthValue(authConfig);

  // Warn when credentials sent over HTTP
  if (authConfig && resolvedBaseUrl.startsWith('http://') && !resolvedBaseUrl.startsWith('http://localhost') && !resolvedBaseUrl.startsWith('http://127.0.0.1')) {
    process.stderr.write(
      `[40mcp] WARNING: Credentials will be sent over plaintext HTTP to ${resolvedBaseUrl}. Use HTTPS in production.\n`,
    );
  }

  // Validate custom header name for auth
  if (authConfig?.type === 'header' && authConfig.header && !SAFE_HEADER_PATTERN.test(authConfig.header)) {
    throw new Error(`Invalid auth header name: "${authConfig.header}". Only alphanumeric and hyphens allowed.`);
  }

  // Warn when static credential is used without envVar
  if (authConfig?.value && !authConfig?.envVar) {
    process.stderr.write(
      `[40mcp] WARNING: auth.value is set without auth.envVar — credentials may be committed to source control. Use envVar instead.\n`,
    );
  }

  // OAuth2 token manager (lazy init only for oauth2 auth type)
  const oauth2Manager = authConfig?.type === 'oauth2'
    ? new OAuth2TokenManager(authConfig)
    : null;

  // Configurable request timeout (default 30s)
  const timeoutMs = hooks?.timeoutMs || 30_000;
  // Bound the upstream response body. A malicious or buggy upstream that
  // returns 10 GB via `response.text()` can OOM the bridge. Default 10 MB
  // matches the upstream-MCP connector.
  const maxResponseBytes = hooks?.maxResponseBytes || 10 * 1024 * 1024;

  // Circuit breaker — open after N consecutive failures (disabled by default)
  const cb = hooks?.circuitBreaker
    ? new CircuitBreaker(hooks.circuitBreaker)
    : null;

  return async function api(method, path, body, tenant, opts) {
    const url = `${resolvedBaseUrl}${path}`;
    const headers = buildHeaders(authConfig);
    // External cancellation signal threaded from bridge.dispatch(..., {signal}).
    // When absent, behaviour is unchanged — only the internal timeout signal
    // is wired. When present, it's composed with the timeout signal via
    // AbortSignal.any so either source aborts the fetch.
    const externalSignal = opts && opts.signal instanceof AbortSignal ? opts.signal : null;
    // Short-circuit: caller passed an already-aborted signal. Surface a
    // structured BridgeError(ABORTED) without touching the upstream or
    // running the auth hook at all.
    if (externalSignal && externalSignal.aborted) {
      const reason = externalSignal.reason;
      throw new BridgeError(
        BridgeErrorCode.ABORTED,
        `dispatch aborted: ${reasonMessage(reason)}`,
        { method, path, cause: reason },
      );
    }

    // Inject OAuth2 token dynamically
    if (oauth2Manager) {
      const token = await oauth2Manager.getToken();
      headers['Authorization'] = `Bearer ${token}`;
    }

    if (hooks?.beforeRequest) {
      const modified = await hooks.beforeRequest({ method, url, headers, body, tenant });
      if (modified) {
        // Validate hook-returned header names to prevent CRLF injection via
        // the key side of the object. Static config headers are already checked
        // at construction via SAFE_HEADER_PATTERN — this is the dynamic path
        // that previously trusted the hook output blindly.
        if (modified.headers) {
          for (const k of Object.keys(modified.headers)) {
            if (!SAFE_HEADER_PATTERN.test(k)) {
              throw new Error(
                `beforeRequest returned invalid header name "${k}". Only [a-zA-Z0-9-] permitted.`,
              );
            }
            // Also validate header VALUES to prevent CRLF injection. Without this
            // a malicious beforeRequest / tenant auth hook could return
            // `{ 'X-Foo': 'val\r\nX-Injected: evil' }` and, even though undici
            // rejects this at serialisation, we want a clear error at the
            // boundary — defense-in-depth against any future transport swap.
            const v = modified.headers[k];
            if (isUnsafeHeaderValue(v)) {
              throw new Error(
                `beforeRequest returned invalid header value for "${k}" — control characters are not permitted.`,
              );
            }
          }
          Object.assign(headers, modified.headers);
        }
        if (modified.body !== undefined) body = modified.body;
      }
    }

    // Circuit breaker check before sending request
    if (cb && !cb.allowRequest()) {
      throw new ApiError(
        BridgeErrorCode.API_NETWORK,
        `Circuit breaker open: too many consecutive failures on ${resolvedBaseUrl}. Will retry after ${cb.recoveryMs / 1000}s.`,
        { method, path, circuitState: cb.state },
      );
    }

    // Abort signal for request timeout. When the caller threaded an
    // external cancellation signal through bridge.dispatch(..., {signal}),
    // compose the two via AbortSignal.any so either source aborts the
    // fetch. `AbortSignal.any` is stable in Node 20+; on older runtimes
    // (no `any` method) fall back to the external signal alone — we don't
    // fight the runtime version.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let effectiveSignal = controller.signal;
    if (externalSignal) {
      if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
        try {
          effectiveSignal = AbortSignal.any([externalSignal, controller.signal]);
        } catch {
          // `any` available but threw on this input — fall back to the
          // external signal so cancellation still propagates.
          effectiveSignal = externalSignal;
        }
      } else {
        // Runtime without AbortSignal.any — prefer the external signal so
        // cancellation still works. The internal timeout controller remains
        // for its side effects (response-size guard calls controller.abort())
        // but can no longer interrupt the fetch itself on this runtime.
        effectiveSignal = externalSignal;
      }
    }

    const init = { method, headers, signal: effectiveSignal };
    if (body && method !== 'GET') {
      // Cap the outbound request body. validateToolArgs checks types but not
      // content length, so an MCP client can supply a 100 MB string field that
      // passes type=string and then blows heap during JSON.stringify. Default
      // 10 MB matches the response cap; overridable per-client via
      // hooks.maxRequestBytes.
      const maxRequestBytes = hooks?.maxRequestBytes || 10 * 1024 * 1024;
      const serialized = JSON.stringify(body);
      const byteLen = Buffer.byteLength(serialized, 'utf8');
      if (byteLen > maxRequestBytes) {
        clearTimeout(timeout);
        throw new ApiError(
          BridgeErrorCode.API_NETWORK,
          `Outbound request body exceeds maximum allowed size (${byteLen} > ${maxRequestBytes} bytes) on ${method} ${path}`,
          { method, path, byteLen, maxRequestBytes },
        );
      }
      init.body = serialized;
    }

    // Refuse to auto-follow redirects. Default Node fetch follows up to 20
    // hops — a permitted upstream that returns `302 Location:
    // http://169.254.169.254/...` would send subsequent tool calls to IMDS
    // with the bridge's outbound auth headers. Set `redirect: 'manual'` and
    // walk the chain ourselves, asserting each Location header against
    // `assertSafeUrl`. Operators can opt into private-network redirects via
    // `hooks.allowPrivateRedirect: true` for dev/test.
    if (init.redirect === undefined) {
      init.redirect = 'manual';
    }

    let response;
    try {
      response = await fetch(url, init);
      // Manual redirect loop — bounded at 5 hops.
      let hops = 0;
      while (
        response &&
        (response.type === 'opaqueredirect' ||
          (response.status >= 300 && response.status < 400 && response.status !== 304))
      ) {
        if (hops >= 5) {
          throw new ApiError(
            BridgeErrorCode.API_NETWORK,
            `Redirect chain exceeded 5 hops on ${method} ${path}`,
            { method, path },
          );
        }
        const loc = response.headers?.get?.('location');
        if (!loc) {
          // Opaque redirect or 3xx with no Location — treat as terminal.
          break;
        }
        // Resolve relative Locations against the current URL.
        // Reject protocol-relative URLs (//host/path) — they inherit the base scheme
        // and can be used to redirect to attacker-controlled hosts
        if (typeof loc === 'string' && loc.startsWith('//')) {
          throw new ApiError(
            BridgeErrorCode.API_NETWORK,
            `[client] Redirect to protocol-relative URL rejected: "${loc.slice(0, 50)}"`,
            { method, path },
          );
        }
        let nextUrl;
        try {
          nextUrl = new URL(loc, url).toString();
        } catch {
          throw new ApiError(
            BridgeErrorCode.API_NETWORK,
            `Invalid redirect Location on ${method} ${path}`,
            { method, path },
          );
        }
        // Reject non-http/https final URLs
        if (!nextUrl.startsWith('http://') && !nextUrl.startsWith('https://')) {
          throw new ApiError(
            BridgeErrorCode.API_NETWORK,
            `[client] Redirect to non-http/https URL rejected: "${nextUrl.slice(0, 50)}"`,
            { method, path },
          );
        }
        try {
          assertSafeUrl(nextUrl, {
            allowPrivate: hooks?.allowPrivateRedirect === true,
            label: 'redirect target',
          });
        } catch (redirectErr) {
          throw new ApiError(
            BridgeErrorCode.API_NETWORK,
            `Refused redirect to private/loopback target on ${method} ${path}: ${redirectErr.message}`,
            { method, path },
          );
        }
        hops += 1;
        // For 307/308, the body is replayed; for 301/302/303, RFC allows
        // method change to GET (and drop body). Match fetch()/undici
        // defaults conservatively: preserve method and body only on
        // 307/308, downgrade to GET + no-body on 301/302/303. This
        // keeps OAuth2 POST bodies from silently migrating but still
        // supports the common GET → GET redirect.
        const redirectInit = { ...init, redirect: 'manual' };
        if (response.status === 301 || response.status === 302 || response.status === 303) {
          redirectInit.method = 'GET';
          delete redirectInit.body;
        }
        response = await fetch(nextUrl, redirectInit);
      }
    } catch (err) {
      cb?.onFailure();
      // External cancellation takes priority: when the caller's signal is
      // aborted, surface BridgeError(ABORTED) regardless of how Node surfaced
      // the failure. Node's fetch throws the abort reason verbatim when a
      // non-undefined reason was passed (so err.name may be "Error" rather
      // than "AbortError"); relying on err.name alone mis-classifies the
      // cancellation as API_NETWORK. Checking externalSignal.aborted is the
      // authoritative path.
      if (externalSignal && externalSignal.aborted) {
        const reason = externalSignal.reason;
        throw new BridgeError(
          BridgeErrorCode.ABORTED,
          `dispatch aborted: ${reasonMessage(reason)}`,
          { method, path, cause: reason },
        );
      }
      if (err.name === 'AbortError') {
        // Internal timeout controller fired (or an `AbortError` bubbled from
        // some other source without the external signal tripping). Surface
        // as API_TIMEOUT.
        throw new ApiError(BridgeErrorCode.API_TIMEOUT, `Request timeout (${timeoutMs}ms) on ${method} ${path}`, { method, path, timeoutMs });
      }
      // Re-throw BridgeError subclasses as-is
      if (err.bridgeCode) throw err;
      throw new ApiError(BridgeErrorCode.API_NETWORK, `Network error calling ${method} ${path}: ${err.message}`, { method, path });
    } finally {
      clearTimeout(timeout);
    }

    // Response-size guard: check Content-Length up front when the server
    // advertises it. The streaming read below provides the authoritative
    // bound — this is just an early rejection.
    const declaredLen = Number(response.headers?.get?.('content-length') || '0');
    if (Number.isFinite(declaredLen) && declaredLen > maxResponseBytes) {
      controller.abort();
      cb?.onFailure();
      throw new ApiError(
        BridgeErrorCode.API_NETWORK,
        `Response exceeds maximum allowed size (${declaredLen} > ${maxResponseBytes} bytes) on ${method} ${path}`,
        { method, path, declaredLen, maxResponseBytes },
      );
    }

    // Stream the body with a byte cap so a server that omits Content-Length
    // still cannot OOM the bridge. Aborts the fetch as soon as the cap is
    // exceeded so we don't keep the connection open.
    async function readBodyBounded(res) {
      const reader = res.body?.getReader?.();
      if (!reader) {
        // Undici/Node fetch should always expose a body stream; fall back
        // to the unbounded read only if the runtime lacks streams.
        return await res.text();
      }
      let total = 0;
      const chunks = [];
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxResponseBytes) {
          try { await reader.cancel(); } catch { /* ignore */ }
          controller.abort();
          throw new ApiError(
            BridgeErrorCode.API_NETWORK,
            `Response exceeds maximum allowed size (> ${maxResponseBytes} bytes) on ${method} ${path}`,
            { method, path, maxResponseBytes },
          );
        }
        chunks.push(value);
      }
      return Buffer.concat(chunks).toString('utf-8');
    }

    if (!response.ok) {
      cb?.onFailure();
      let detail = '';
      try { detail = await readBodyBounded(response); } catch (e) { detail = `[body read error: ${e.code || e.message}]`; }
      // Scrub newlines/control chars from upstream response body before
      // writing to stderr to prevent log forgery. Without this, a malicious
      // or compromised upstream API could return a 4xx body containing
      // `\n[40mcp:audit] {"fake":"entry"}\n` and forge audit entries into
      // any log aggregator grepping for the `[40mcp:audit]` prefix. The
      // sanitized detail passed to apiErrorFromStatus is also scrubbed
      // because downstream sinks write `err.message` verbatim.
      if (detail) {
        process.stderr.write(`[40mcp] API error ${response.status} on ${method} ${path}: ${safeLog(detail, 500)}\n`);
      }
      throw apiErrorFromStatus(response.status, method, path, safeLog(detail, 200));
    }

    cb?.onSuccess();

    if (response.status === 204) return { success: true };

    const text = await readBodyBounded(response);
    if (!text) return { success: true };
    const contentType = response.headers?.get?.('content-type') || '';
    try {
      return JSON.parse(text);
    } catch {
      // A response claiming JSON that fails to parse is a possible MITM indicator.
      if (contentType.includes('application/json')) {
        process.stderr.write(
          `[40mcp] WARNING: ${method} ${path} returned Content-Type: application/json but body is not valid JSON — possible MITM or malformed response.\n`,
        );
      }
      return { success: true, body: text };
    }
  };
}
