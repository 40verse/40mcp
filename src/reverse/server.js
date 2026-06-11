import { createServer } from 'node:http';
import { URL } from 'node:url';
import { timingSafeEqual, createHmac, randomBytes } from 'node:crypto';
import { parseBody } from '../core/body.js';
import { validateToolArgs, emitAuditLog } from '../bridge.js';
import { stripInternalEnvelopes } from '../core/envelope.js';
import { safeLog } from '../core/events.js';
import { BridgeError, BridgeErrorCode } from '../errors.js';

/**
 * Generate an OpenAPI 3.0 spec from MCP tool definitions.
 *
 * @param {object} config
 * @param {string} config.name - API name
 * @param {string} [config.version] - API version (default: '1.0.0')
 * @param {Array<object>} config.tools - MCP tool definitions
 * @param {string} [config.basePath] - Base path prefix (default: '/api')
 * @returns {object} OpenAPI 3.0 spec object
 */
export function generateOpenApiSpec(config) {
  const {
    name = 'API',
    version = '1.0.0',
    tools = [],
    basePath = '/api',
  } = config;

  const paths = {};

  for (const tool of tools) {
    const pathKey = `${basePath}/tools/${tool.name}`;
    paths[pathKey] = {
      post: {
        operationId: tool.name,
        summary: tool.description || `Call ${tool.name}`,
        requestBody: {
          content: {
            'application/json': {
              schema: tool.inputSchema || {
                type: 'object',
                properties: {},
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Tool result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    result: {
                      description: 'The result from the tool',
                    },
                  },
                },
              },
            },
          },
          400: {
            description: 'Invalid arguments',
          },
          404: {
            description: 'Tool not found',
          },
          500: {
            description: 'Tool execution error',
          },
        },
      },
    };
  }

  return {
    openapi: '3.0.0',
    info: {
      title: name,
      version,
    },
    paths,
  };
}

/**
 * Create a REST API server from MCP tool definitions.
 *
 * @param {object} config
 * @param {string} config.name - API name
 * @param {string} [config.version] - API version
 * @param {Array<object>} config.tools - MCP tool definitions (name, description, inputSchema)
 * @param {Function} config.dispatch - async function(toolName, args) → result
 * @param {number} [config.port] - Port (default: 8080)
 * @param {string} [config.basePath] - Base path prefix (default: '/api')
 * @param {object} [config.auth] - Optional auth validation
 * @param {string} [config.auth.header] - Required header name
 * @param {string} [config.auth.envVar] - Env var holding expected value
 * @returns {{ start(): Promise<{ httpServer, url }>, generateOpenApiSpec(): object }}
 */
export function createReverseBridge(config) {
  const {
    name = 'api',
    version = '1.0.0',
    tools = [],
    dispatch,
    port = 8080,
    basePath = '/api',
    auth,
  } = config;

  if (!dispatch || typeof dispatch !== 'function') {
    throw new Error('config.dispatch must be an async function(toolName, args) → result');
  }

  // Build tool map for O(1) lookup
  const toolMap = new Map();
  for (const tool of tools) {
    toolMap.set(tool.name, tool);
  }

  // Hoist the `/api/tools/:toolName` regex out of the request handler.
  // The previous `new RegExp(…)` inside `handleRequest` recompiled once per
  // inbound request — pure waste at high RPS. Precompile once at factory
  // construction time.
  const toolPathRe = new RegExp(`^${basePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\/tools\\/([a-zA-Z0-9_-]+)$`);

  // CORS: configurable origin (A05-1)
  const allowedOrigin = config.allowedOrigin || 'http://localhost';
  if (allowedOrigin === '*') {
    throw new Error(
      '[reverse] Wildcard CORS origin "*" is not allowed — specify an explicit origin (e.g., "https://myapp.com")',
    );
  }
  // Only emit CORS headers when the request Origin matches the configured
  // allowedOrigin. The previous code called setCorsHeaders(res) unconditionally,
  // emitting Access-Control-Allow-Origin on every response regardless of the
  // request origin. This allowed any page at the default 'http://localhost'
  // origin (e.g., a malicious local app or dev tool) to make authenticated
  // cross-origin requests to the bridge. With origin reflection, only requests
  // whose Origin header exactly equals allowedOrigin receive the permissive
  // header; all others get no CORS header, so the browser's same-origin policy
  // blocks them.
  function setCorsHeaders(req, res) {
    const requestOrigin = req.headers['origin'];
    if (requestOrigin && requestOrigin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
  }

  // Validate auth config at startup
  if (auth && (!auth.header || typeof auth.header !== 'string')) {
    throw new Error('auth.header must be a non-empty string when auth is configured');
  }

  // A01-2: Hard-fail on public binds without auth. The review recommended
  // converting the warning to a hard error when the operator asks to bind
  // beyond loopback without auth — otherwise the reverse bridge becomes an
  // open HTTP→MCP relay for anyone who can reach the listen socket.
  // Loopback-only binds still fall through to the warn path because a
  // single-user dev box is a reasonable loopback deployment.
  const bindHost = config.host || '127.0.0.1';
  const isLoopback = bindHost === '127.0.0.1' || bindHost === 'localhost' || bindHost === '::1';

  // 0.0.0.0 without auth is a hard error (not a warning)
  if (bindHost === '0.0.0.0' && !auth) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      'Binding to 0.0.0.0 without authentication is not allowed. Set auth or bind to 127.0.0.1.',
    );
  }

  if (!auth && !isLoopback) {
    throw new Error(
      `[${name}] reverse bridge refuses to start on non-loopback host "${bindHost}" without auth. ` +
      `Set config.auth = { envVar: "...", header: "..." } or bind to 127.0.0.1.`,
    );
  }
  if (!auth) {
    process.stderr.write(`[${name}] WARNING: No auth configured — all endpoints are unauthenticated\n`);
  }

  // A01-3: Warn when auth env var is missing at startup
  if (auth && auth.envVar && !process.env[auth.envVar]) {
    process.stderr.write(`[${name}] WARNING: auth.envVar "${auth.envVar}" is not set — all requests will be rejected\n`);
  }

  // A07-2: Constant-time auth comparison using HMAC-SHA256 digest comparison.
  // The previous variable-length pad approach leaked a byte-length oracle —
  // `Buffer.alloc(maxLen)` allocation branches are distinguishable under
  // timing analysis even when the final `timingSafeEqual` runs. Fix:
  // HMAC-SHA256 both sides with a stable per-process key so both digests are
  // ALWAYS 32 bytes regardless of secret or header lengths. `timingSafeEqual`
  // on equal-length 32-byte buffers is fully constant-time with no length
  // branch. Use a cryptographically random per-process key. The previous key
  // was derived from `Date.now()` (millisecond timestamp) — a guessable value
  // that could be brute-forced from observable server-start time signals
  // (/proc/<pid>/stat, HTTP Date headers), making the HMAC key trivially
  // recoverable and defeating the timing-normalization guarantee.
  // Design rationale: see SECURITY.md § "Authentication Model (Reverse Bridge)".
  const _AUTH_HMAC_KEY = randomBytes(32);
  function checkAuth(req) {
    if (!auth) return true;
    const expectedValue = process.env[auth.envVar];
    if (!expectedValue) return false;
    const headerValue = req.headers[auth.header.toLowerCase()] || '';
    // Hash both to fixed 32-byte digests — eliminates the length oracle entirely.
    const expectedDigest = createHmac('sha256', _AUTH_HMAC_KEY).update(expectedValue).digest();
    const receivedDigest = createHmac('sha256', _AUTH_HMAC_KEY).update(headerValue).digest();
    return timingSafeEqual(expectedDigest, receivedDigest);
  }

  // Set defensive response headers on EVERY path —
  // `X-Content-Type-Options: nosniff` prevents browsers / intermediaries
  // from MIME-sniffing an error body into something executable, and
  // `X-Frame-Options: DENY` is cheap belt-and-braces against clickjacking
  // in case a UI is ever served from this surface. Applied uniformly to
  // success, error, 204, 404, and 415 paths.
  function setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
  }

  // HTTP response helpers
  function sendJson(res, statusCode, data) {
    res.statusCode = statusCode;
    setSecurityHeaders(res);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data));
  }

  // Graceful-shutdown state. Mirrors `createRestBridge`'s
  // close() contract: once `close()` is invoked, new POST /tools/:name
  // dispatches are refused with a 503, in-flight dispatches are awaited
  // up to the caller-supplied timeout, and the HTTP server is torn down
  // cleanly (including keep-alive sockets via closeAllConnections when
  // available). Idempotent: a second call returns the same promise.
  const shutdownState = {
    closing: false,
    inFlight: new Set(),
  };

  // Main request handler
  async function handleRequest(req, res) {
    setCorsHeaders(req, res);

    // Parse URL once; use pathname for routing.
    let url;
    try {
      // Use hardcoded base so an attacker-controlled Host header cannot manipulate
      // URL resolution (host-header injection). Only pathname is used for routing
      // — the host part is irrelevant.
      url = new URL(req.url, 'http://internal');
    } catch {
      sendJson(res, 400, { error: 'Invalid request URL' });
      return;
    }
    const pathname = url.pathname;

    // Handle OPTIONS (CORS preflight) — return 204 not 200 to match RFC-7231,
    // and only for paths under the configured basePath so probes to unrelated
    // URLs don't get a 200 fingerprint.
    if (req.method === 'OPTIONS') {
      setSecurityHeaders(res);
      if (pathname === basePath || pathname.startsWith(`${basePath}/`)) {
        res.statusCode = 204;
      } else {
        res.statusCode = 404;
      }
      res.end();
      return;
    }

    // Route: GET /api/health
    if (pathname === `${basePath}/health` && req.method === 'GET') {
      sendJson(res, 200, { status: 'ok' });
      return;
    }

    // Route: GET /api/tools (auth-gated — exposes tool schemas)
    if (pathname === `${basePath}/tools` && req.method === 'GET') {
      if (!checkAuth(req)) {
        sendJson(res, 401, { error: 'Unauthorized' });
        return;
      }
      const toolList = tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      }));
      sendJson(res, 200, { tools: toolList });
      return;
    }

    // Route: GET /api/openapi.json (auth-gated — exposes full API surface)
    if (pathname === `${basePath}/openapi.json` && req.method === 'GET') {
      if (!checkAuth(req)) {
        sendJson(res, 401, { error: 'Unauthorized' });
        return;
      }
      const spec = generateOpenApiSpec({ name, version, tools, basePath });
      sendJson(res, 200, spec);
      return;
    }

    // Route: POST /api/tools/:toolName
    const toolMatch = pathname.match(toolPathRe);
    if (toolMatch && req.method === 'POST') {
      const toolName = toolMatch[1];

      // Refuse new dispatches once close() has been invoked. 503 is the
      // standard "service unavailable; draining" status; include the
      // structured error code so machine callers can branch on it.
      if (shutdownState.closing) {
        sendJson(res, 503, {
          error: 'Reverse bridge is shutting down',
          code: BridgeErrorCode.SHUTTING_DOWN,
        });
        return;
      }

      // Check auth
      if (!checkAuth(req)) {
        sendJson(res, 401, { error: 'Unauthorized' });
        return;
      }

      const tool = toolMap.get(toolName);
      if (!tool) {
        sendJson(res, 404, { error: `Tool not found: ${toolName}` });
        return;
      }

      // Track the dispatch in the in-flight set for graceful shutdown.
      // The tracking promise is the handle; it resolves when the handler
      // settles regardless of outcome (success, error, timeout).
      let releaseTracking;
      const tracking = new Promise((resolve) => { releaseTracking = resolve; });
      shutdownState.inFlight.add(tracking);
      try {
        const { parsed: body } = await parseBody(req);

        // Support both { args: {...} } and flat {...}
        const args = body.args || body;

        // The reverse bridge relied on the callee's dispatch to run
        // validateToolArgs. That is only true when dispatch comes from
        // buildDispatcher/buildMixerDispatcher; a custom dispatch wrapper
        // (connectMany, test mock) would bypass reserved-key rejection entirely.
        // Enforce the gate at the HTTP ingestion point.
        const validationError = validateToolArgs(args, tool.inputSchema);
        if (validationError) {
          sendJson(res, 400, { error: `Tool "${toolName}": ${validationError}` });
          return;
        }

        // Call dispatch
        let result = await dispatch(toolName, args);

        // Strip reserved envelope keys (`_steering`, `_chain`, etc.) from the
        // REST response body: REST clients are not MCP agents and have no use
        // for internal dispatch metadata. This also prevents chain error
        // messages (potentially containing upstream API error bodies) from
        // leaking to external callers.
        result = stripInternalEnvelopes(result);

        sendJson(res, 200, { result });
      } catch (err) {
        // parseBody throws 'Unsupported Content-Type' when strictContentType
        // is true (default) and the client sends a non-application/json body.
        // Return 415 so clients know the media type is wrong, not that their
        // JSON is malformed.
        if (err.message === 'Unsupported Content-Type') {
          sendJson(res, 415, { error: 'Unsupported Media Type: expected application/json' });
        } else if (err.message === 'Invalid JSON body' || err.message === 'Invalid JSON in request body') {
          sendJson(res, 400, { error: 'Invalid JSON in request body' });
        } else {
          // Scrub err.message — ApiError wraps upstream response bodies and
          // would otherwise carry newline injection through to stderr verbatim.
          process.stderr.write(`[40mcp:reverse] Tool execution error: ${safeLog(err.message, 300)}\n`);
          sendJson(res, 500, { error: 'Tool execution error' });
        }
      } finally {
        shutdownState.inFlight.delete(tracking);
        try { releaseTracking(); } catch { /* never throws */ }
      }
      return;
    }

    // 404 for unmatched routes
    sendJson(res, 404, { error: 'Not found' });
  }

  const httpServer = createServer(handleRequest);

  // Enforce server-level read timeouts so a Slowloris attacker cannot hold
  // connections indefinitely in the pre-body / pre-headers phase, bypassing
  // the in-dispatch caps. Node defaults (headersTimeout=60s, requestTimeout=300s)
  // are far too lax for a REST bridge that expects machine-to-machine POSTs.
  //
  // Node.js v22 does not reliably enforce headersTimeout via the server property
  // — the native mechanism does not fire for partial-header connections in v22.
  // Implement manually: on each new TCP connection start a timer; clear it when
  // a complete request (headers fully parsed) arrives on that socket; destroy the
  // socket if the timer fires first. Functionally equivalent to headersTimeout
  // but works on all Node.js versions.
  //
  // DEBT(slowloris): This per-socket timer guards only the *first* request on
  // each TCP connection. Subsequent requests on a keep-alive connection are NOT
  // guarded by this timer — only by `requestTimeout` (30 s, set below), which
  // kicks in after headers are fully received, not during the headers phase.
  // A Slowloris attacker targeting a keep-alive connection would need to
  // successfully deliver at least one complete request to clear the timer, then
  // stall headers on a subsequent request. `requestTimeout` provides a backstop
  // but is less tight than headersTimeout. Mitigation: `keepAliveTimeout` is
  // set to 10 s to limit how long the server waits for the next request on a
  // keep-alive connection; this narrows the Slowloris window after the first
  // request. Future: replace with the Node.js native `headersTimeout` once the
  // v22 bug is confirmed fixed upstream.
  const headersTimeoutMs = config.headersTimeout ?? 15_000;
  httpServer.requestTimeout = 30_000;
  httpServer.keepAliveTimeout = 10_000;

  httpServer.on('connection', (socket) => {
    const timer = setTimeout(() => socket.destroy(), headersTimeoutMs);
    // Clear timer once a complete request arrives on this socket (headers parsed).
    const onRequest = (req) => {
      if (req.socket === socket) {
        clearTimeout(timer);
        httpServer.removeListener('request', onRequest);
      }
    };
    httpServer.on('request', onRequest);
    // Clean up if socket closes before any request arrives (e.g. timer fires first).
    socket.once('close', () => {
      clearTimeout(timer);
      httpServer.removeListener('request', onRequest);
    });
  });

  // Graceful shutdown primitive. Matches the bridge's
  // close() contract: refuse new dispatches, await in-flight up to
  // `timeoutMs`, close the HTTP server (including keep-alive sockets via
  // closeAllConnections when available), emit bridge.shutdown_timeout on
  // deadline. Idempotent. Cascades into the upstream dispatch if the
  // caller passed a dispatch that itself exposes close() — this lets a
  // reverse bridge that owns its underlying bridge tear everything down
  // with a single call.
  let closePromise = null;
  const close = ({ timeoutMs = 10_000 } = {}) => {
    if (closePromise) return closePromise;
    shutdownState.closing = true;

    closePromise = (async () => {
      const snapshot = Array.from(shutdownState.inFlight);
      let timedOut = false;
      if (snapshot.length > 0) {
        await new Promise((resolve) => {
          let settled = false;
          const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            timedOut = true;
            resolve();
          }, timeoutMs);
          if (typeof timer.unref === 'function') timer.unref();
          Promise.allSettled(snapshot).then(() => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve();
          });
        });
      }

      if (timedOut) {
        emitAuditLog({
          ts: Date.now(),
          event: 'bridge.shutdown_timeout',
          inFlightCount: shutdownState.inFlight.size,
          timeoutMs,
          surface: 'reverse',
        });
      }

      // Close the HTTP server. closeAllConnections is Node 18.2+; skip
      // when unavailable so we don't regress on older runtimes. Without it
      // keep-alive sockets block server.close() until their idle timer fires.
      try {
        if (typeof httpServer.closeAllConnections === 'function') {
          try { httpServer.closeAllConnections(); } catch { /* ignore */ }
        }
        await new Promise((resolve) => {
          if (!httpServer.listening) return resolve();
          httpServer.close(() => resolve());
        });
      } catch { /* best-effort */ }

      // Cascade to the underlying dispatch if it owns a close() method.
      // The reverse bridge receives dispatch as a function; callers that
      // pass `bridge.dispatch` may also stash a close on the function
      // (when built by createRestBridge this is the dispatch fn itself).
      // We only cascade when the caller explicitly asked for it via
      // config.ownsDispatch: true to avoid surprising double-close behavior.
      if (config.ownsDispatch && typeof dispatch.close === 'function') {
        try { await dispatch.close({ timeoutMs }); } catch { /* ignore */ }
      }
    })();
    return closePromise;
  };

  return {
    /**
     * Start the server and return the listening server + URL.
     * @returns {Promise<{ httpServer, url }>}
     */
    async start() {
      return new Promise((resolve, reject) => {
        const host = config.host || '127.0.0.1';
        httpServer.listen(port, host, () => {
          const addr = httpServer.address();
          const url = `http://${host}:${addr.port}`;
          resolve({ httpServer, url, close });
        });
        httpServer.on('error', reject);
      });
    },

    /**
     * Generate the OpenAPI spec without starting the server.
     * @returns {object} OpenAPI 3.0 spec
     */
    generateOpenApiSpec() {
      return generateOpenApiSpec({ name, version, tools, basePath });
    },

    /**
     * Graceful shutdown primitive. Refuses new dispatches,
     * awaits in-flight requests up to `timeoutMs` (default 10 s), closes
     * the HTTP server, emits `bridge.shutdown_timeout` if the deadline
     * elapsed. Idempotent. Never calls `process.exit`.
     *
     * @param {{ timeoutMs?: number }} [opts]
     * @returns {Promise<void>}
     */
    close,
  };
}
