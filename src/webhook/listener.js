/**
 * Webhook ingestion — receive HTTP webhooks and trigger tool chains.
 *
 * Creates an HTTP server that listens for incoming webhooks, matches them
 * against route definitions, and dispatches corresponding tool calls.
 *
 * @module webhook/listener
 */

import { createServer } from 'node:http';
import { timingSafeEqual, createHmac, randomBytes } from 'node:crypto';
import { BridgeError, BridgeErrorCode } from '../errors.js';
import { sanitizeTransportEgress, validateToolArgs, RESERVED_ENVELOPE_KEYS } from '../bridge.js';
import { getByPath } from '../core/object.js';
import { parseBody } from '../core/body.js';
import { emitEvent, safeLog } from '../core/events.js';

/**
 * Strict-integer timestamp parser.
 *
 * Reject scientific-notation, decimals, and non-numeric forms that `Number()`
 * silently coerces. The previous heuristic — `Number(tsValue) * (tsValue.length === 10 ? 1000 : 1)` —
 * accepted `"1e10"` (length 4 → treated as ms → 10_000_000_000 ms = far future, replay window bypassed).
 * It also let an attacker flip a captured 10-digit timestamp into the 11+-digit branch by
 * prepending a digit, suppressing the `* 1000` and shifting the value into the ms domain.
 *
 * The replacement requires plain digits and disambiguates seconds vs ms by magnitude
 * (anything ≥ 10^12 is treated as ms, otherwise seconds — same convention as Stripe/GitHub).
 *
 * @param {string} value Header value
 * @returns {number|null} ms since epoch, or null if value is not a strict integer
 */
export function parseWebhookTimestamp(value) {
  if (typeof value !== 'string') return null;
  if (!/^[0-9]+$/.test(value)) return null;
  // Cap at 13 digits (year ~5138 in ms). Anything longer is rejected as an
  // overflow attempt; anything ≥10^12 is interpreted as ms, smaller as seconds.
  if (value.length > 13) return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return n >= 1e12 ? n : n * 1000;
}

// Per-process HMAC key for constant-time secret comparison. Used in
// validateSecret() header-type comparison to eliminate length oracles that
// previous length checks introduced. See SECURITY.md for design rationale.
const _WEBHOOK_HMAC_KEY = randomBytes(32);

/** Safe path pattern — no traversal, only alphanumeric + hyphens + slashes */
const SAFE_PATH_PATTERN = /^\/[a-zA-Z0-9\-_/]*$/;

/** Default replay window: 5 minutes in seconds */
const DEFAULT_REPLAY_WINDOW_SECONDS = 300;

/**
 * Validate a webhook secret against the request.
 * @private
 */
function validateSecret(req, body, rawBody, route) {
  if (!route.secret) return { ok: true };

  const secret = process.env[route.secret.envVar] || route.secret.value || '';
  if (!route.secret.envVar && route.secret.value) {
    process.stderr.write(`[40mcp] WARNING: webhook secret for route "${route.path || route.name}" is set directly in config — use envVar instead.\n`);
  }
  if (!secret) return { ok: false, reason: 'no_secret_configured' };

  switch (route.secret.type) {
    case 'header': {
      // Use HMAC-SHA256 to eliminate length oracles. The previous length check
      // (`expected.length === received.length`) leaks the expected secret's
      // length via timing. HMAC both values with a stable per-process key so
      // both digests are always 32 bytes. `timingSafeEqual` on equal-length
      // 32-byte digests is fully constant-time with no length branch.
      const header = (route.secret.header || 'x-webhook-secret').toLowerCase();
      const expectedDigest = createHmac('sha256', _WEBHOOK_HMAC_KEY).update(secret).digest();
      const receivedDigest = createHmac('sha256', _WEBHOOK_HMAC_KEY).update(req.headers[header] || '').digest();
      return timingSafeEqual(expectedDigest, receivedDigest)
        ? { ok: true }
        : { ok: false, reason: 'header_mismatch' };
    }
    case 'hmac': {
      // HMAC-SHA256 signature verification (GitHub, Stripe style)
      const header = (route.secret.header || 'x-hub-signature-256').toLowerCase();
      const signature = req.headers[header];
      if (!signature) return { ok: false, reason: 'missing_signature' };

      // Use HMAC normalization to eliminate length oracles (same as 'header' case).
      const computed = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');
      const expectedDigest = createHmac('sha256', _WEBHOOK_HMAC_KEY).update(computed).digest();
      const receivedDigest = createHmac('sha256', _WEBHOOK_HMAC_KEY).update(signature).digest();
      if (!timingSafeEqual(expectedDigest, receivedDigest)) {
        return { ok: false, reason: 'hmac_mismatch' };
      }

      // Replay protection: default ON for HMAC routes, opt-out with replayWindow: false
      const replayEnabled = route.secret.replayWindow !== false;
      if (replayEnabled) {
        // `typeof NaN === 'number'` is true, so the previous guard accepted
        // `replayWindow: NaN` as valid. Then `delta > NaN*1000` is always false,
        // silently disabling the past-bound replay check and leaving only the 5 s
        // future-skew clamp. A captured signed webhook would be replayable forever.
        // Require finite + positive.
        const rawWindow = route.secret.replayWindow;
        const windowSeconds =
          typeof rawWindow === 'number' && Number.isFinite(rawWindow) && rawWindow > 0
            ? rawWindow
            : DEFAULT_REPLAY_WINDOW_SECONDS;
        const tsHeader = (route.secret.timestampHeader || 'x-webhook-timestamp').toLowerCase();
        const tsValue = req.headers[tsHeader];
        if (!tsValue) return { ok: false, reason: 'missing_timestamp' };
        const tsMs = parseWebhookTimestamp(tsValue);
        if (tsMs === null) return { ok: false, reason: 'invalid_timestamp' };
        // `Math.abs(now - ts) > window*1000` treats past and future equally.
        // A captured valid webhook can be replayed with a timestamp `window-1`
        // into the future, accepted NOW, AND still replayable later — effectively
        // doubling the replay window. Enforce asymmetric bounds: allow a small
        // forward skew for client clock drift (5 s) but reject anything beyond
        // that as a clear replay/forge.
        // H4: CLOCK_SKEW_TOLERANCE_MS is now configurable via route.clockSkewMs
        // with a 30-second absolute maximum cap.
        const MAX_CLOCK_SKEW_MS = 30_000; // 30 seconds absolute max
        const clockSkewMs = Math.min(
          typeof route.clockSkewMs === 'number' && route.clockSkewMs > 0
            ? route.clockSkewMs
            : 5_000,
          MAX_CLOCK_SKEW_MS,
        );
        const now = Date.now();
        const delta = now - tsMs; // positive = past, negative = future
        if (delta > windowSeconds * 1000 || delta < -clockSkewMs) {
          return { ok: false, reason: 'replay_window' };
        }
      }

      return { ok: true };
    }
    case 'query': {
      // Use a hardcoded safe base — req.headers.host is attacker-controlled
      // and can contain CRLF or authority-confusion strings. The webhook listener
      // only needs the pathname/query, not host. Use HMAC normalization.
      const url = new URL(req.url, 'http://internal');
      const param = route.secret.param || 'token';
      const expectedDigest = createHmac('sha256', _WEBHOOK_HMAC_KEY).update(secret).digest();
      const receivedDigest = createHmac('sha256', _WEBHOOK_HMAC_KEY).update(url.searchParams.get(param) || '').digest();
      return timingSafeEqual(expectedDigest, receivedDigest)
        ? { ok: true }
        : { ok: false, reason: 'query_mismatch' };
    }
    default:
      process.stderr.write('[40mcp] warning: unknown webhook secret type: ' + safeLog(route.secret.type, 50) + '\n');
      return { ok: false, reason: 'unknown_type' };
  }
}

/**
 * Testing shim for validateSecret — exposes the internal comparison function so
 * invariant tests can verify correctness of the HMAC-normalised comparison path
 * without spinning up a full HTTP server.
 * @internal
 */
export function _validateSecretForTesting(req, body, rawBody, route) {
  return validateSecret(req, body, rawBody, route);
}

/**
 * Extract tool arguments from webhook payload using a field mapping.
 *
 * When `argMap` is missing, previously the ENTIRE parsed body flowed through
 * as args — a webhook signed by a trusted sender (GitHub, Stripe) whose
 * PAYLOAD is attacker-controlled (issue body, customer metadata) could smuggle
 * `_tenant` / `_chain` / `_depth` keys straight into dispatch. The
 * `validateToolArgs` reserved-key scan now catches these at the dispatch
 * boundary, but belt-and-braces strip here too so the webhook surface fails
 * closed even if a future refactor ever bypasses the validator. Top-level
 * enumerable-only strip matches the historical semantics; nested reserved
 * keys remain caught by the recursive scanner in bridge.js.
 * @private
 */
function extractArgs(body, argMap, req) {
  if (!argMap) {
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      const cleaned = {};
      for (const key of Object.keys(body)) {
        if (key.startsWith('_') || key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        cleaned[key] = body[key];
      }
      return cleaned;
    }
    return body;
  }

  // Use a null-prototype object to eliminate the __proto__ setter side-channel.
  // Also reject any argMap key that is a reserved internal envelope key — an
  // operator-configured `_tenant` output key would allow header/body values to
  // inject into the tenant context.
  const _reservedArgKeySet = new Set(RESERVED_ENVELOPE_KEYS);
  const args = Object.create(null);
  for (const [toolArg, source] of Object.entries(argMap)) {
    if (_reservedArgKeySet.has(toolArg) || toolArg.startsWith('_')) {
      process.stderr.write(`[webhook] argMap key "${safeLog(toolArg, 60)}" is reserved — skipped\n`);
      continue;
    }
    if (typeof source === 'string') {
      if (source.startsWith('$body.')) {
        args[toolArg] = getByPath(body, source.substring(6));
      } else if (source.startsWith('$header.')) {
        const headerName = source.substring(8).toLowerCase();
        args[toolArg] = req.headers[headerName];
      } else if (source.startsWith('$query.')) {
        // Use safe hardcoded base (same fix as validateSecret query path).
        const url = new URL(req.url, 'http://internal');
        args[toolArg] = url.searchParams.get(source.substring(7));
      } else {
        // Static value
        args[toolArg] = source;
      }
    } else {
      args[toolArg] = source;
    }
  }
  return args;
}


/**
 * Match a request against a route definition.
 * @private
 */
function matchRoute(req, route) {
  // Method match (default: POST)
  const method = (route.method || 'POST').toUpperCase();
  if (req.method !== method) return false;

  // Path match — use safe base, not req.headers.host (attacker-controlled).
  const url = new URL(req.url, 'http://internal');
  return url.pathname === route.path;
}

/**
 * Create a webhook listener that triggers tool dispatches.
 *
 * @param {object} config
 * @param {string} [config.name='webhook-listener'] - Server name
 * @param {number} [config.port=9090] - Port to listen on
 * @param {string} [config.host='127.0.0.1'] - Host to bind
 * @param {Function} config.dispatch - Bridge dispatch function (async (toolName, args) => result)
 * @param {Array<WebhookRoute>} config.routes - Route definitions
 * @returns {{ start(): Promise<{ httpServer, url }>, routes: Array }}
 *
 * Route schema:
 * {
 *   path: '/hooks/github',                    // URL path to match
 *   method: 'POST',                           // HTTP method (default: POST)
 *   tool: 'process_github_event',             // Tool to dispatch
 *   argMap: {                                  // Map webhook payload to tool args
 *     event_type: '$header.x-github-event',
 *     repo: '$body.repository.full_name',
 *     action: '$body.action',
 *   },
 *   filter: { '$body.action': ['opened', 'closed'] },  // Optional: only trigger for matching values
 *   secret: {                                  // Optional: webhook secret validation
 *     type: 'hmac',                            // 'header', 'hmac', or 'query'
 *     envVar: 'GITHUB_WEBHOOK_SECRET',
 *     header: 'x-hub-signature-256',
 *   },
 *   response: 'async',                        // 'async' (202 immediately) or 'sync' (wait for result)
 * }
 */
/** Per-route async error rate limiter — prevents log flooding from repeated failures */
function buildErrorRateLimiter(windowMs = 60_000, maxPerWindow = 10) {
  const state = new Map(); // routePath -> { count, windowStart }
  return function shouldLog(routePath, writeSuppressedWarning) {
    const now = Date.now();
    const s = state.get(routePath) || { count: 0, windowStart: now };
    if (now - s.windowStart > windowMs) {
      state.set(routePath, { count: 1, windowStart: now });
      return true;
    }
    s.count += 1;
    state.set(routePath, s);
    if (s.count === maxPerWindow + 1 && writeSuppressedWarning) {
      writeSuppressedWarning();
    }
    return s.count <= maxPerWindow;
  };
}

export function createWebhookListener(config) {
  const {
    name = 'webhook-listener',
    port = 9090,
    host = '127.0.0.1',
    dispatch,
    routes = [],
    exposeRoutes = false,
  } = config;

  if (!dispatch) {
    throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, 'Webhook listener requires a dispatch function');
  }

  // Per-route async error rate limiter — suppresses log flooding
  const shouldLogError = buildErrorRateLimiter(
    config.errorLogWindowMs || 60_000,
    config.maxErrorsPerWindow || 10,
  );

  // Per-route in-flight dispatch cap. Phase-1 rate-limited error LOGGING;
  // nothing rate-limited the dispatch itself. A compromised webhook sender can
  // fire valid HMAC'd requests at 10k/s and accumulate unbounded pending
  // dispatch() Promises. Reject with 429 when the per-route concurrent cap is
  // reached.
  //
  // Also cap GLOBAL in-flight across all routes. Without this, a listener with
  // N routes can buffer N * maxInFlightPerRoute pending bodies in memory (each
  // up to MAX_BODY_SIZE = 1 MB). The global cap bounds total memory independent
  // of route count.
  const maxInFlightPerRoute = config.maxInFlightPerRoute || 50;
  const maxInFlightGlobal = config.maxInFlightGlobal || 200;
  const inFlight = new Map(); // routePath -> count
  let totalInFlight = 0;

  if (routes.length === 0) {
    throw new BridgeError(BridgeErrorCode.CONFIG_INVALID, 'Webhook listener requires at least one route');
  }

  // Validate routes
  for (const route of routes) {
    if (!route.path || !SAFE_PATH_PATTERN.test(route.path)) {
      throw new BridgeError(BridgeErrorCode.CONFIG_INVALID, `Invalid webhook route path: "${route.path}"`);
    }
    if (!route.tool) {
      throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, `Webhook route ${route.path} requires a tool name`);
    }
  }

  const httpServer = createServer(async (req, res) => {
    // CORS — no wildcard; webhook endpoints are server-to-server, not browser-accessible
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Parse URL once; compare pathname rather than req.url so query strings
    // on health probes / LB checks don't fall through to 404, and so OPTIONS
    // scoping can consult pathname.
    let parsedUrl;
    try {
      // H17 — use hardcoded safe base; req.headers.host is attacker-controlled
      // and can carry CRLF sequences or authority-confusion strings.
      parsedUrl = new URL(req.url, 'http://internal');
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request URL' }));
      return;
    }
    const pathname = parsedUrl.pathname;

    if (req.method === 'OPTIONS') {
      // Previously served 204 for ANY path, which is a deployment fingerprint
      // (distinguishes 40mcp webhook listener from a generic server). Limit
      // OPTIONS 204 to configured webhook routes; everything else falls through
      // to 404 just like a real webhook deployment would behave.
      if (routes.some((r) => r.path === pathname)) {
        res.writeHead(204);
        res.end();
      } else {
        res.writeHead(404);
        res.end();
      }
      return;
    }

    // Health check
    if (req.method === 'GET' && pathname === '/health') {
      res.setHeader('Content-Type', 'application/json');
      res.writeHead(200);
      // Structural fields (name, routes.length) help an attacker map the
      // deployment. Mirror the SSE transport's `exposeSessionCount` gate:
      // expose only when the operator opts in via `exposeHealthDetails: true`.
      const healthBody = { status: 'ok' };
      if (config.exposeHealthDetails === true) {
        healthBody.name = name;
        healthBody.routes = routes.length;
      }
      res.end(JSON.stringify(healthBody));
      return;
    }

    // Route listing — disabled by default (information disclosure).
    // Enable with exposeRoutes: true (only for trusted internal networks).
    if (req.method === 'GET' && pathname === '/routes') {
      if (!exposeRoutes) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Not found' }));
        return;
      }
      res.setHeader('Content-Type', 'application/json');
      res.writeHead(200);
      res.end(JSON.stringify({
        routes: routes.map((r) => ({
          path: r.path,
          method: r.method || 'POST',
          tool: r.tool,
          hasSecret: !!r.secret,
          response: r.response || 'async',
        })),
      }));
      return;
    }

    // Find matching route
    const route = routes.find((r) => matchRoute(req, r));
    if (!route) {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'No matching webhook route' }));
      return;
    }

    // Parse body
    let body, rawBody;
    try {
      ({ parsed: body, rawBody } = await parseBody(req));
    } catch (err) {
      // Never echo the raw JSON.parse error — it includes byte offsets and
      // partial token content from the body that can reveal parser behaviour to
      // an attacker. Log the detail to stderr for operators but return a neutral
      // message to the caller. Scrub req.url and err.message — both can contain
      // attacker-controlled bytes (malformed path, raw JSON.parse error text
      // echoing input).
      process.stderr.write(`[${name}] body parse error on ${safeLog(req.url, 200)}: ${safeLog(err.message, 200)}\n`);
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid request body' }));
      return;
    }

    // Validate secret
    const valid = await validateSecret(req, body, rawBody, route);
    if (!valid.ok) {
      // Emit structured event so SOC/SIEM can detect HMAC brute-force, replay
      // attacks, missing-timestamp probes, etc. Rate-limited per-route to avoid
      // flooding the event stream from sustained noise.
      if (shouldLogError(`hmac:${route.path}`, () => {
        process.stderr.write(`[${name}] Webhook secret-failure rate limit reached on ${route.path} — further failures suppressed\n`);
      })) {
        const eventType = valid.reason === 'replay_window' ? 'webhook.replay_fail' : 'webhook.hmac_fail';
        emitEvent(eventType, {
          route: route.path,
          tool: route.tool,
          reason: valid.reason,
          clientIp: req.socket?.remoteAddress || null,
          secretType: route.secret?.type || null,
        });
      }
      res.writeHead(401);
      res.end(JSON.stringify({ error: 'Invalid webhook secret' }));
      return;
    }

    // Apply filter (if defined)
    if (route.filter) {
      const match = Object.entries(route.filter).every(([path, allowed]) => {
        const value = path.startsWith('$body.')
          ? getByPath(body, path.substring(6))
          : path.startsWith('$header.')
            ? req.headers[path.substring(8).toLowerCase()]
            : undefined;
        return Array.isArray(allowed) ? allowed.includes(value) : value === allowed;
      });
      if (!match) {
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'filtered', message: 'Event did not match filter criteria' }));
        return;
      }
    }

    // Extract args from payload
    const args = extractArgs(body, route.argMap, req);

    // Per-route AND global in-flight dispatch caps.
    const current = inFlight.get(route.path) || 0;
    if (current >= maxInFlightPerRoute) {
      emitEvent('webhook.in_flight_cap', {
        scope: 'per_route',
        route: route.path,
        tool: route.tool,
        current,
        cap: maxInFlightPerRoute,
        clientIp: req.socket?.remoteAddress || null,
      });
      res.setHeader('Retry-After', '1');
      res.writeHead(429);
      res.end(JSON.stringify({ error: 'Too many in-flight webhooks for this route' }));
      return;
    }
    if (totalInFlight >= maxInFlightGlobal) {
      emitEvent('webhook.in_flight_cap', {
        scope: 'global',
        route: route.path,
        tool: route.tool,
        current: totalInFlight,
        cap: maxInFlightGlobal,
        clientIp: req.socket?.remoteAddress || null,
      });
      res.setHeader('Retry-After', '1');
      res.writeHead(429);
      res.end(JSON.stringify({ error: 'Webhook listener is at global in-flight capacity' }));
      return;
    }
    inFlight.set(route.path, current + 1);
    totalInFlight += 1;
    const releaseSlot = () => {
      const n = (inFlight.get(route.path) || 1) - 1;
      if (n <= 0) inFlight.delete(route.path);
      else inFlight.set(route.path, n);
      totalInFlight = Math.max(0, totalInFlight - 1);
    };

    // `validateToolArgs` reserved-key scan must run on the async dispatch
    // path. The `extractArgs` belt-and-braces only strips top-level `_`-prefixed
    // keys; `validateToolArgs` recurses into nested objects/arrays. An
    // argMap-derived call with `{ body: { _tenant: "x" } }` would slip past
    // extractArgs but be caught here. Validate BEFORE sending the 202 so we
    // can still reject with a meaningful HTTP error.
    const argsValidationError = validateToolArgs(args, route.inputSchema || null);
    if (argsValidationError) {
      emitEvent('webhook.reserved_key_rejected', {
        route: route.path,
        tool: route.tool,
        error: argsValidationError,
        clientIp: req.socket?.remoteAddress || null,
      });
      releaseSlot();
      res.writeHead(400);
      res.end(JSON.stringify({ error: `Tool "${route.tool}": ${argsValidationError}` }));
      return;
    }

    // Async mode (default): respond immediately, dispatch in background
    if (route.response !== 'sync') {
      res.setHeader('Content-Type', 'application/json');
      res.writeHead(202);
      res.end(JSON.stringify({ status: 'accepted', tool: route.tool }));

      // Fire and forget — rate-limited error logging to prevent log flooding
      dispatch(route.tool, args)
        .catch((err) => {
          if (shouldLogError(route.path, () => {
            process.stderr.write(`[${name}] Error rate limit reached on ${route.path} — further errors suppressed\n`);
          })) {
            process.stderr.write(`[${name}] Webhook dispatch error on ${route.path} → ${route.tool}: ${safeLog(err.message, 300)}\n`);
          }
        })
        .finally(releaseSlot);
      return;
    }

    // Sync mode: wait for dispatch result
    try {
      const rawResult = await dispatch(route.tool, args);
      // Mirror the bridge.js CallTool egress pipeline — strip reserved envelope
      // keys and sanitize prompt-injection strings before the webhook caller
      // receives the payload.
      const result = sanitizeTransportEgress(rawResult);
      res.setHeader('Content-Type', 'application/json');
      res.writeHead(200);
      res.end(JSON.stringify({ status: 'ok', result }));
      releaseSlot();
      return;
    } catch (err) {
      releaseSlot();
      if (shouldLogError(route.path, () => {
        process.stderr.write(`[${name}] Error rate limit reached on ${route.path} — further errors suppressed\n`);
      })) {
        process.stderr.write(`[${name}] Webhook dispatch error on ${route.path} → ${route.tool}: ${safeLog(err.message, 300)}\n`);
      }
      res.writeHead(500);
      res.end(JSON.stringify({ error: 'Tool dispatch failed', message: 'An internal error occurred' }));
    }
  });

  // Slowloris hardening. Without server-level read timeouts, an attacker can
  // open N sockets, dribble headers, and hold workers indefinitely — bypassing
  // the in-flight caps entirely because the cap counters are only incremented
  // AFTER `parseBody` resolves. Force conservative timeouts at the HTTP server
  // layer so the operating system cannot be coerced into holding stalled
  // pre-body connections past 30 s.
  httpServer.headersTimeout = 15_000;
  httpServer.requestTimeout = 30_000;
  httpServer.keepAliveTimeout = 10_000;

  return {
    routes,

    async start() {
      return new Promise((resolve, reject) => {
        httpServer.listen(port, host, () => {
          const actualPort = httpServer.address().port;
          const url = `http://${host}:${actualPort}`;
          process.stderr.write(`[${name}] Webhook listener started — ${routes.length} routes at ${url}\n`);
          resolve({ httpServer, url });
        });
        httpServer.on('error', reject);
      });
    },
  };
}
