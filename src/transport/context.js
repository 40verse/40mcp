/**
 * Frontdoor request context — AsyncLocalStorage for propagating
 * per-request identity and session info into the CallTool handler.
 *
 * The MCP SDK's `Server.setRequestHandler(CallToolRequestSchema, ...)`
 * handler does not see the underlying HTTP request. To give the
 * frontdoor access to the authenticated `principal` (set by bearer
 * auth) and the `sessionId` at tool-call time — for audit events,
 * tenant resolution, and downstream policy decisions — we wrap
 * `handlePostMessage` in an ALS `.run()` at the SSE transport layer.
 *
 * `currentPrincipal()` / `currentSessionId()` return the stored value
 * when called inside a request, or `null` when called outside one
 * (library consumers, tests, startup).
 *
 * @module transport/context
 */

import { AsyncLocalStorage } from 'node:async_hooks';

export const frontdoorContext = new AsyncLocalStorage();

/**
 * @returns {string|null} matched principal from bearer auth, or null
 * in single-token / unauthenticated modes (and when no request is in
 * flight).
 */
export function currentPrincipal() {
  const store = frontdoorContext.getStore();
  return store?.principal ?? null;
}

/**
 * @returns {string|null} SSE session id owning the current request.
 */
export function currentSessionId() {
  const store = frontdoorContext.getStore();
  return store?.sessionId ?? null;
}
