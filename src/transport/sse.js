import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { emitEvent, buildInstanceField } from '../core/events.js';
import { frontdoorContext } from './context.js';

/**
 * Create and start an SSE transport.
 * @param {object|null} server - MCP Server instance. Pass `null` together
 * with `options.serverFactory` to create a fresh server per inbound SSE
 * connection — required for a multi-client frontdoor because the MCP
 * SDK's `Server` only owns one transport at a time (second `.connect()`
 * throws "Already connected to a transport"). When a factory is not
 * supplied, the single server is shared across all sessions (acceptable
 * for single-client consumers).
 * @param {object} options
 * @param {number} options.port - Port to listen on (default: 8080)
 * @param {string} options.path - SSE endpoint path (default: '/sse')
 * @param {string} options.messagePath - Message endpoint path (default: '/message')
 * @param {string|Record<string,string>} [options.requireBearer] - When set,
 * `GET /sse` and `POST /message` require `Authorization: Bearer <token>`.
 * Single-token mode: pass the literal token string. Multi-token mode:
 * pass an object mapping principal name → token; every entry is checked
 * in constant time and the matching principal is surfaced on the
 * `sse.auth_ok` / `sse.session_open` events. Principal names must match
 * `/^[a-zA-Z0-9_-]{1,64}$/` — enforced by the caller (see cli.js).
 * `/health` and CORS preflights remain open.
 * @param {Function} [options.healthProvider] - Optional callback invoked on
 * `GET /health`. Returns an object that replaces the default
 * `{status:"ok"}` payload — used by the published frontdoor to surface
 * per-upstream liveness when `--health-detail` is set. Must not throw;
 * errors fall back to the default payload.
 * @param {number} [options.maxSessionsPerPrincipal=5] - Cap on concurrent
 * sessions attributed to a single principal in multi-token mode.
 * Composes with `maxSessionsPerIp`. No-op for unauthenticated requests
 * and for single-token mode (no principal to attribute against).
 * @param {Function} [options.serverFactory] - `() => Server`. When set,
 * called for every inbound GET /sse to build a fresh Server and
 * register its handlers. Supersedes the `server` argument. Required
 * for multi-client frontdoors.
 * @returns {Promise<{ httpServer, url }>}
 */
export async function createSseTransport(server, options = {}) {
 const {
 port = 8080,
 path = '/sse',
 messagePath = '/message',
 // exposeSessionCount: set true only for internal/trusted networks
 exposeSessionCount = false,
 // idleTimeoutMs: close SSE connections idle for this long — Slow Loris mitigation
 idleTimeoutMs = 5 * 60 * 1000,
 // requireBearer: application-layer auth token for the SSE frontdoor.
 // CORS / allowedOrigins only restricts browser origins; when the
 // transport is published to non-browser MCP clients (GPT, claude.ai,
 // etc.) a bearer token is the real auth boundary.
 requireBearer,
 healthProvider,
 serverFactory,
 } = options;

 // Per-process HMAC key — identical strategy to reverse/server.js. Hashing
 // both the expected token and the received header value to fixed-size
 // digests removes the length oracle from `timingSafeEqual`.
 const _AUTH_HMAC_KEY = randomBytes(32);

 // Normalize requireBearer into a list of `{ principal, digest }` entries
 // so single-token and multi-token modes share the same comparison path.
 // Empty / null → no auth required. Single string → one entry with
 // principal === null (no principal attribution in events). Object →
 // one entry per key.
 //
 // Library-layer note: an empty object (`{}`) deliberately collapses to
 // "no auth required" so `createSseTransport` stays a clean primitive —
 // higher layers decide what an empty input means. The CLI frontdoor
 // path (`link --sse --bearer-file`) rejects an empty file at startup
 // so an operator can't accidentally publish an open frontdoor through
 // a missing entry. Keep these two layers in their respective lanes.
 const _expectedEntries = (() => {
 if (!requireBearer) return [];
 if (typeof requireBearer === 'string') {
 return [{
 principal: null,
 digest: createHmac('sha256', _AUTH_HMAC_KEY).update(requireBearer).digest(),
 }];
 }
 if (typeof requireBearer === 'object') {
 return Object.entries(requireBearer).map(([principal, token]) => ({
 principal,
 digest: createHmac('sha256', _AUTH_HMAC_KEY).update(String(token)).digest(),
 }));
 }
 return [];
 })();

 /**
 * Validate `Authorization: Bearer <token>` in constant time.
 * Returns `{ ok: true, principal }` when auth is not configured or
 * the token matches (principal is `null` in single-token mode).
 * Returns `{ ok: false }` when the token is missing or wrong.
 *
 * Iterates every registered entry regardless of whether an earlier
 * entry already matched — the early-out form would leak "matched
 * earlier in the map" via timing when the map is ordered.
 */
 function checkBearer(req) {
 if (_expectedEntries.length === 0) return { ok: true, principal: null };
 const header = req.headers['authorization'];
 if (typeof header !== 'string') return { ok: false };
 // Accept only the exact `Bearer ` prefix (case-insensitive scheme,
 // exactly one space). Tolerate trailing whitespace in the token since
 // some HTTP clients trim differently.
 const match = /^Bearer\s+(\S.*)$/i.exec(header);
 if (!match) return { ok: false };
 const receivedDigest = createHmac('sha256', _AUTH_HMAC_KEY).update(match[1].trim()).digest();

 let matched = false;
 let matchedPrincipal = null;
 for (const entry of _expectedEntries) {
 const eq = timingSafeEqual(entry.digest, receivedDigest);
 if (eq && !matched) {
 matched = true;
 matchedPrincipal = entry.principal;
 }
 }
 return matched ? { ok: true, principal: matchedPrincipal } : { ok: false };
 }

 // Maximum concurrent SSE connections — configurable via MAX_SSE_CONNECTIONS env var.
 // Prevents unbounded growth of the sessions Map under connection-flood conditions.
 const MAX_SSE_CONNECTIONS = options.maxConnections
 || (process.env.MAX_SSE_CONNECTIONS ? parseInt(process.env.MAX_SSE_CONNECTIONS, 10) : 100);

 // Map of sessionId -> SSEServerTransport (bounded)
 const MAX_SESSIONS = options.maxSessions || MAX_SSE_CONNECTIONS;
 const SESSION_ID_PATTERN = /^[a-zA-Z0-9_-]{1,128}$/;
 const sessions = new Map();

 // Per-IP rate limiting on session creation
 const MAX_SESSIONS_PER_IP = options.maxSessionsPerIp || 10;
 const ipSessionCounts = new Map(); // ip -> count of active sessions

 // Per-principal rate limiting on session creation. With multi-token auth
 //, `principal` identifies the credential a request
 // authenticated under — a more useful key than IP because (a) one
 // consumer roams across networks, and (b) many consumers share one egress
 // IP behind corporate NAT. The cap composes with the per-IP cap (defense
 // in depth — whichever trips first wins). Single-token mode and the
 // unauthenticated path use `principal === null`; the per-principal cap
 // skips those (no identity to attribute against), leaving the per-IP cap
 // as the only bound.
 const MAX_SESSIONS_PER_PRINCIPAL = options.maxSessionsPerPrincipal || 5;
 const principalSessionCounts = new Map();

 // Sessionless GET /sse connections were neither counted against
 // `sessions.size` nor `ipSessionCounts`, so an attacker could open
 // unlimited `GET /sse` (no sessionId) per IP, each holding a transport
 // + idle timer + socket. Track sessionless load separately but cap it at
 // the same per-IP ceiling as sessioned connections; reject the request
 // before allocating a transport when over the cap.
 let sessionlessTotal = 0;
 const ipSessionlessCounts = new Map();

 const httpServer = createServer(async (req, res) => {
 // Add CORS headers — reflect the request origin if it is in the allowedOrigins list.
 // When allowedOrigins is not configured, allow any localhost/127.0.0.1 origin
 // (including those with ports, e.g. http://localhost:3000) via an EXACT
 // hostname check. The previous `startsWith('http://localhost')` matched
 // `http://localhost.attacker.com`, enabling a DNS-rebinding attack.
 const requestOrigin = req.headers['origin'];
 let originAllowed = false;
 if (requestOrigin) {
 if (options.allowedOrigins && options.allowedOrigins.length > 0) {
 originAllowed = options.allowedOrigins.includes(requestOrigin);
 } else {
 let parsedOrigin = null;
 try { parsedOrigin = new URL(requestOrigin); } catch { /* invalid origin */ }
 if (
 parsedOrigin &&
 parsedOrigin.protocol === 'http:' &&
 (parsedOrigin.hostname === 'localhost' || parsedOrigin.hostname === '127.0.0.1')
) {
 originAllowed = true;
 }
 }
 }
 if (originAllowed) {
 res.setHeader('Access-Control-Allow-Origin', requestOrigin);
 }
 res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
 // Allow Authorization when bearer auth is enabled so browser clients can
 // attach the token through CORS preflight. `Content-Type` stays on for
 // the POST /message JSON body.
 res.setHeader(
 'Access-Control-Allow-Headers',
 requireBearer ? 'Content-Type, Authorization' : 'Content-Type',
);

 // Handle CORS preflight
 // Parse the URL ONCE at handler entry so downstream comparisons use
 // `url.pathname` (exact match) rather than `req.url` (raw string,
 // query-string-sensitive) or `startsWith()` (overmatches `/sseboom`,
 // `/health?x=1`, etc.).
 let parsedUrl;
 try {
 // Use hardcoded base so an attacker-controlled Host header cannot
 // manipulate URL resolution (host-header injection). Only pathname is
 // used for routing — the host part is irrelevant.
 parsedUrl = new URL(req.url, 'http://internal');
 } catch {
 res.writeHead(400);
 res.end('Invalid request URL');
 return;
 }
 const pathname = parsedUrl.pathname;

 if (req.method === 'OPTIONS') {
 res.writeHead(204);
 res.end();
 return;
 }

 // Health endpoint — omit session count to prevent information disclosure
 if (req.method === 'GET' && pathname === '/health') {
 res.setHeader('Content-Type', 'application/json');
 res.writeHead(200);
 let health = { status: 'ok' };
 if (typeof healthProvider === 'function') {
 try {
 const detail = healthProvider();
 if (detail && typeof detail === 'object') health = { status: 'ok',...detail };
 } catch {
 // Never let a broken provider turn /health into a 500 — the
 // orchestrator liveness probe must keep working. Fall through
 // to the default payload.
 }
 }
 // Surface operator-set instance metadata so /health is self-describing
 // for orchestration and audit tooling. No-op when settings.instance.*
 // is unset so library consumers see unchanged shape.
 const inst = buildInstanceField();
 if (inst) health.instance = inst;
 // Session count is gated behind exposeSessionCount to prevent enumeration
 if (exposeSessionCount) health.sessions = sessions.size;
 res.end(JSON.stringify(health));
 return;
 }

 // SSE connection endpoint — use exact pathname match, not `startsWith`.
 // Previously `/sseboom` matched `/sse` and allocated a transport on every
 // probe — DoS amplification.
 if (req.method === 'GET' && pathname === path) {
 let sessionId = parsedUrl.searchParams.get('sessionId');
 const clientIp = req.socket.remoteAddress || 'unknown';

 // Bearer auth is enforced BEFORE session / rate-limit accounting
 // so unauthenticated callers can never influence the pool.
 const authResult = checkBearer(req);
 if (!authResult.ok) {
 emitEvent('sse.auth_failed', { path: pathname, clientIp });
 res.setHeader('WWW-Authenticate', 'Bearer');
 res.writeHead(401);
 res.end('Unauthorized');
 return;
 }
 // Principal is surfaced on auth + session events when multi-token
 // mode is in use. Single-token mode keeps `principal: null` so
 // the field is uniformly present and log parsers can rely on it.
 const principal = authResult.principal;
 if (requireBearer) emitEvent('sse.auth_ok', { path: pathname, clientIp, principal });

 // Validate session ID format
 if (sessionId && !SESSION_ID_PATTERN.test(sessionId)) {
 res.writeHead(400);
 res.end('Invalid sessionId format');
 return;
 }

 // Session-hijack guard (CVE: red-hat finding): the previous gate allowed
 // a new GET to claim an existing sessionId slot — `sessions.set(sessionId, transport)`
 // below would overwrite the legitimate transport, redirecting all
 // server→client messages to the attacker. Reject any inbound sessionId
 // that collides with a live session, regardless of cap state. Clients
 // that need to reconnect must request a new session.
 if (sessionId && sessions.has(sessionId)) {
 emitEvent('sse.session_collision', { sessionId, clientIp });
 res.writeHead(409);
 res.end('Session already exists');
 return;
 }

 // Gate the global cap on the combined live load: `sessions.size +
 // sessionlessTotal`, so sessionless GETs cannot escape quota.
 if (sessions.size + sessionlessTotal >= MAX_SESSIONS) {
 emitEvent('sse.rate_limit_hit', { reason: 'global_cap', clientIp });
 res.writeHead(503);
 res.end('Max sessions reached');
 return;
 }

 // Per-IP rate limiting: prevent one client from monopolising the session
 // pool. Combine sessioned and sessionless per-IP counts so an attacker
 // can't escape by mixing forms.
 const ipSessioned = ipSessionCounts.get(clientIp) || 0;
 const ipSessionless = ipSessionlessCounts.get(clientIp) || 0;
 if (ipSessioned + ipSessionless >= MAX_SESSIONS_PER_IP) {
 emitEvent('sse.rate_limit_hit', { reason: 'per_ip_cap', clientIp });
 res.writeHead(429);
 res.end('Too many sessions from this IP');
 return;
 }

 // Per-principal rate limiting. Only applies when the
 // request authenticated to a known principal — single-token mode and
 // the no-auth path leave principal === null and skip this gate. The
 // per-IP cap above still bounds those.
 if (principal !== null) {
 const principalCount = principalSessionCounts.get(principal) || 0;
 if (principalCount >= MAX_SESSIONS_PER_PRINCIPAL) {
 emitEvent('sse.rate_limit_hit', { reason: 'per_principal_cap', clientIp, principal });
 res.writeHead(429);
 res.end('Too many sessions for this principal');
 return;
 }
 }

 const transport = new SSEServerTransport(messagePath, res);

 // If the inbound GET didn't supply a sessionId, adopt the
 // transport's server-generated UUID. `SSEServerTransport.start()`
 // writes an `endpoint` SSE event with `?sessionId=<that UUID>` — so
 // the subsequent POST /message from the client will land on this
 // UUID, not on anything the URL would have carried. MCP SDK clients
 // don't supply a sessionId on GET, so without this fallback their
 // POSTs would 404. URL-supplied sessionIds remain supported for
 // callers that want to choose their own (session-hijack guard
 // above still applies to them).
 if (!sessionId) sessionId = transport.sessionId;

 // Track a single `onFinalClose` cleanup that runs on both the happy
 // path (via transport.onclose) and the error path (catch). The previous
 // code incremented counters BEFORE `server.connect(transport)` but never
 // rolled them back on errors — repeated start failures permanently
 // exhausted the caps.
 let closed = false;
 let idleTimer = null;
 const onFinalClose = () => {
 if (closed) return;
 closed = true;
 if (idleTimer) clearTimeout(idleTimer);
 if (sessionId) {
 sessions.delete(sessionId);
 const remaining = (ipSessionCounts.get(clientIp) || 1) - 1;
 if (remaining <= 0) ipSessionCounts.delete(clientIp);
 else ipSessionCounts.set(clientIp, remaining);
 if (principal !== null) {
 const remP = (principalSessionCounts.get(principal) || 1) - 1;
 if (remP <= 0) principalSessionCounts.delete(principal);
 else principalSessionCounts.set(principal, remP);
 }
 emitEvent('sse.session_close', { sessionId, clientIp, principal });
 } else {
 sessionlessTotal = Math.max(0, sessionlessTotal - 1);
 const r = (ipSessionlessCounts.get(clientIp) || 1) - 1;
 if (r <= 0) ipSessionlessCounts.delete(clientIp);
 else ipSessionlessCounts.set(clientIp, r);
 }
 };

 if (sessionId) {
 sessions.set(sessionId, transport);
 ipSessionCounts.set(clientIp, (ipSessionCounts.get(clientIp) || 0) + 1);
 if (principal !== null) {
 principalSessionCounts.set(principal, (principalSessionCounts.get(principal) || 0) + 1);
 }
 // Stash the session's authenticated principal on the transport so
 // POST /message can surface it to the CallTool handler via
 // frontdoorContext.run — the MCP SDK doesn't otherwise pass the
 // underlying HTTP request through to the tool-call layer.
 transport._frontdoorPrincipal = principal;
 emitEvent('sse.session_open', { sessionId, clientIp, principal });

 // Idle timeout: close this connection if no message arrives within the window
 function resetIdleTimer() {
 if (!idleTimeoutMs) return;
 if (idleTimer) clearTimeout(idleTimer);
 idleTimer = setTimeout(() => {
 process.stderr.write(`[40mcp] SSE session "${sessionId}" idle timeout — closing connection\n`);
 res.end();
 }, idleTimeoutMs);
 }
 resetIdleTimer();
 // Reset idle timer whenever a message is received on this session
 const origHandlePost = transport.handlePostMessage?.bind(transport);
 if (origHandlePost) {
 transport.handlePostMessage = (postReq, postRes) => {
 resetIdleTimer();
 return origHandlePost(postReq, postRes);
 };
 }

 transport.onclose = onFinalClose;
 } else {
 // Sessionless connection — count it against the caps.
 sessionlessTotal += 1;
 ipSessionlessCounts.set(clientIp, ipSessionless + 1);
 // Idle timeout for sessionless connections (health probes, etc.)
 if (idleTimeoutMs > 0) {
 idleTimer = setTimeout(() => {
 if (!res.writableEnded) res.end();
 }, idleTimeoutMs);
 if (typeof idleTimer.unref === 'function') idleTimer.unref();
 }
 req.socket.once('close', onFinalClose);
 transport.onclose = onFinalClose;
 }

 try {
 // Multi-client frontdoor: build a fresh Server per SSE session so
 // each session owns its own transport. The MCP SDK's Server
 // rejects a second `.connect()` with "Already connected to a
 // transport" — a shared Server therefore caps the frontdoor at
 // one concurrent client, which would negate the entire multi-
 // token / per-principal design. Callers opt in by passing a
 // `serverFactory`; legacy `server` still works for single-client
 // consumers (the existing integration tests that open a stream
 // and immediately abort without making a tool call).
 const sessionServer = typeof serverFactory === 'function' ? serverFactory() : server;
 await sessionServer.connect(transport);
 // The real MCP SDK's `server.connect()` auto-calls
 // `transport.start()`. Test harnesses that provide a mock
 // server with `connect: async () => {}` don't, so we need a
 // fallback `.start()` call. If it's already started, the SDK
 // throws "SSEServerTransport already started!" — safe to
 // swallow because the first path already sent headers.
 if (!res.headersSent) {
 try {
 await transport.start();
 } catch {
 // already started via connect — ignore
 }
 }
 } catch (err) {
 process.stderr.write(`[40mcp] SSE start error: ${err.message}\n`);
 // Only roll back the counter when the transport never successfully
 // reached the wire. When headers are already sent, the connection IS
 // live and the counter must remain incremented; tearing it down here
 // would leak the slot.
 if (!res.headersSent) {
 onFinalClose();
 res.writeHead(500);
 res.end('Internal server error');
 }
 }
 return;
 }

 // Message POST endpoint — exact pathname match.
 if (req.method === 'POST' && pathname === messagePath) {
 const sessionId = parsedUrl.searchParams.get('sessionId');

 const postAuth = checkBearer(req);
 if (!postAuth.ok) {
 const clientIp = req.socket.remoteAddress || 'unknown';
 emitEvent('sse.auth_failed', { path: pathname, clientIp });
 res.setHeader('WWW-Authenticate', 'Bearer');
 res.writeHead(401);
 res.end('Unauthorized');
 return;
 }
 if (requireBearer) {
 emitEvent('sse.auth_ok', {
 path: pathname,
 clientIp: req.socket.remoteAddress || 'unknown',
 principal: postAuth.principal,
 });
 }

 const transport = sessions.get(sessionId);
 if (!transport) {
 res.writeHead(404);
 res.end('Session not found');
 return;
 }

 // Enforce a per-request socket timeout ONLY on message POSTs
 // (not the long-lived GET /sse stream). A slow
 // POST that drips body bytes to stay under the idle timer would
 // otherwise hold a socket indefinitely. 30s default matches the
 // outbound fetch timeout and is generous for any legitimate MCP
 // message handling.
 const messageRequestTimeoutMs = options.messageRequestTimeoutMs || 30_000;
 req.setTimeout(messageRequestTimeoutMs, () => {
 emitEvent('sse.message_request_timeout', { sessionId });
 if (!res.headersSent) {
 res.writeHead(408);
 res.end('Request timeout');
 }
 req.destroy();
 });

 // Bound the inbound message body. The SDK's handlePostMessage
 // reads the body with no size gate; an authenticated
 // MCP client can otherwise POST an arbitrarily large CallTool
 // payload and OOM the bridge. We check Content-Length up front and
 // also enforce a streaming byte cap via abort on the request socket.
 const MAX_MESSAGE_BYTES = options.maxMessageBytes || 1 * 1024 * 1024; // 1 MB
 const declared = Number(req.headers['content-length'] || '0');
 if (Number.isFinite(declared) && declared > MAX_MESSAGE_BYTES) {
 emitEvent('sse.message_too_large', { sessionId, declared, cap: MAX_MESSAGE_BYTES });
 res.writeHead(413);
 res.end('Payload too large');
 return;
 }
 // Streaming guard: if Content-Length was missing or lied, abort once
 // received bytes exceed the cap. We piggy-back on the existing
 // `data` events before passing req to handlePostMessage — but since
 // the SDK consumes the stream itself, we instead wrap the socket
 // close on byte-count breach.
 let received = 0;
 const onData = (chunk) => {
 received += chunk.length;
 if (received > MAX_MESSAGE_BYTES) {
 emitEvent('sse.message_too_large', { sessionId, received, cap: MAX_MESSAGE_BYTES });
 req.destroy(new Error('payload too large'));
 }
 };
 req.on('data', onData);

 // Propagate the session's authenticated principal (and sessionId)
 // into the CallTool handler via AsyncLocalStorage. The MCP SDK's
 // handler does not receive the HTTP request, so this is how the
 // frontdoor surfaces identity to downstream layers (audit events,
 // tenant scope resolution, policy gates).
 const sessionPrincipal = transport._frontdoorPrincipal ?? null;
 try {
 await frontdoorContext.run(
 { principal: sessionPrincipal, sessionId },
 () => transport.handlePostMessage(req, res),
);
 } catch (err) {
 process.stderr.write(`[40mcp] SSE message handler error: ${err.message}\n`);
 if (!res.headersSent) {
 res.writeHead(500);
 res.end('Internal server error');
 }
 } finally {
 req.off('data', onData);
 }
 return;
 }

 // Not found
 res.writeHead(404);
 res.end('Not found');
 });

 // Patch close() to destroy all open connections before stopping the server.
 // Without this, long-lived SSE connections keep the process alive until the
 // idle timeout fires (default 5 min), causing test hangs and spurious failures
 // on Node 18 where connection cleanup is less aggressive than later versions.
 const _close = httpServer.close.bind(httpServer);
 httpServer.close = (cb) => {
 httpServer.closeAllConnections();
 return _close(cb);
 };

 // Slowloris hardening on the SSE control plane.
 // `headersTimeout` and `requestTimeout` apply to the non-streaming
 // control path (POST /message, GET /health, OPTIONS). The long-lived
 // GET /sse stream is intentionally exempt from `requestTimeout` by
 // Node when it has already started sending the response, so this
 // does not clip live SSE sessions.
 httpServer.headersTimeout = 15_000;
 httpServer.requestTimeout = 30_000;
 httpServer.keepAliveTimeout = 10_000;

 return new Promise((resolve, reject) => {
 const host = options.host || '127.0.0.1';

 httpServer.listen(port, host, () => {
 const assignedPort = httpServer.address().port;
 const url = `http://${host}:${assignedPort}`;
 resolve({ httpServer, url });
 });

 httpServer.on('error', reject);
 });
}
