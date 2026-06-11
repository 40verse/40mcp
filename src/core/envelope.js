/**
 * Trust-boundary envelope primitives — the single source of truth for
 * reserved envelope keys and the strip/sanitize walkers that enforce them.
 *
 * Every dispatch surface (bridge, mixer, connectMany, webhook listener,
 * reverse bridge) imports these primitives from here. `src/bridge.js`
 * re-exports the public names for backward compatibility, but new code
 * should import from this module directly. SPEC §2 "Reserved envelope
 * keys" points at this file as the registry: adding a reserved key here
 * is sufficient — every strip path picks it up.
 *
 * @module core/envelope
 */

import { sanitizeDescription } from './sanitize.js';

/**
 * Keys that must never appear in tool-call args, regardless of the tool's
 * inputSchema. validateToolArgs must enforce these restrictions because
 * MCP clients (or webhook bodies) could otherwise smuggle internal
 * dispatch-control keys like `_tenant`, `_chain`, `_depth`, or `_steering`
 * into the args object and influence downstream dispatch behaviour. Reject
 * every `_`-prefixed key uniformly plus the known prototype-pollution keys.
 */
export const RESERVED_ARG_KEYS = new Set([
  '__proto__', 'constructor', 'prototype',
  // `_steering` carried the (removed) steering module's envelope. It stays
  // reserved so no operator or upstream can shadow it, and so a future
  // external steering package can reclaim it without a breaking envelope
  // change.
  '_tenant', '_chain', '_depth', '_steering', '_source', '_upstream',
  '_policy', '_transforms', '_error', '_error_code',
  // applyResponseTransform (transforms/response.js) injects
  // _truncated, _summary, and _original_count as internal processing metadata.
  // Without these in the reserved set an attacker-controlled upstream can
  // inject { _truncated: true } into a result, falsely signalling truncation
  // to the LLM and manipulating downstream reasoning. Adding them here ensures
  // stripInternalEnvelopes removes them from any upstream-supplied payload at
  // the connect.js trust boundary before transforms run.
  '_truncated', '_summary', '_original_count',
  // Forward-reserved envelope keys. None of these are emitted or
  // consumed by 40mcp today. They are reserved so future additive features can
  // attach bridge-authored metadata without introducing a breaking change to
  // the envelope contract and without creating an upstream-injection vector
  // during the rollout window. Reserving early lets `stripInternalEnvelopes`
  // and `sanitizeTransportEgress` scrub any operator- or upstream-emitted
  // collisions on every egress path before the feature ships.
  //   _trace        — future OTEL / W3C traceparent context
  //   _cost         — future per-tool cost attribution (tokens, $, latency)
  //   _warnings     — future non-fatal dispatch warnings surfaced to clients
  //   _version      — future per-tool API version advertised by the bridge
  //   _correlation  — future cross-instance request correlation identifier
  '_trace', '_cost', '_warnings', '_version', '_correlation',
]);

/**
 * Exposed for the upstream → bridge trust boundary (connect.js). Stripped
 * from any tool result returned by a connected MCP server so an attacker
 * controlling the upstream cannot inject operator-reserved envelope keys
 * back into the bridge dispatch layer. Must mirror `RESERVED_ARG_KEYS`
 * exactly, including prototype-poisoning keys (`__proto__`, `constructor`,
 * `prototype`) which `JSON.parse('{"__proto__":{...}}')` materializes as
 * own properties. Downstream consumers of upstream results must not inherit
 * a prototype-pollution surface from the network layer.
 */
export const RESERVED_ENVELOPE_KEYS = Array.from(RESERVED_ARG_KEYS);

/**
 * Keys the bridge's own `applyResponseTransform` legitimately writes into
 * a dispatch result as response metadata (truncation markers, etc.).
 * These keys MUST be stripped from upstream-supplied payloads (both
 * connected MCP servers and REST responses) to prevent an attacker from
 * forging the metadata. But once the bridge's transforms have run, the
 * keys are trusted bridge-internal metadata and must survive transport
 * egress so downstream LLM clients can see that truncation occurred.
 *
 * The upstream-boundary strip path (`stripInternalEnvelopes`, used by
 * `connect.js` and by the bridge's REST response scrubber) strips the full
 * `RESERVED_ENVELOPE_KEYS` set including these. The transport-egress
 * strip path (`sanitizeTransportEgress`) strips `EGRESS_STRIP_KEYS`, a
 * narrower set that omits these response-metadata keys so the bridge's
 * own transform output reaches the LLM client intact.
 */
const BRIDGE_RESPONSE_META_KEYS = new Set(['_truncated', '_summary', '_original_count']);

/**
 * Strip set for the transport-egress boundary. Excludes bridge-authored
 * response metadata (`_truncated`, `_summary`, `_original_count`) because
 * `applyResponseTransform` legitimately emits them and downstream clients
 * need to see them. Upstream-injected copies are scrubbed earlier via the
 * full-set `stripInternalEnvelopes` pass on the upstream side.
 */
export const EGRESS_STRIP_KEYS = RESERVED_ENVELOPE_KEYS.filter(
  (k) => !BRIDGE_RESPONSE_META_KEYS.has(k),
);

export const MAX_STRIP_DEPTH = 10;

/**
 * Strip 40mcp internal envelope keys from a dispatch result before it
 * crosses any trust boundary (MCP stdio/SSE or REST egress).
 *
 * `createRestBridge` must strip reserved envelope keys from upstream
 * REST responses before the MCP CallTool handler ships them to clients.
 * An attacker-controlled or compromised upstream returning
 * `{ _steering: { authority: "ROOT" }, _tenant: {...} }` would otherwise
 * ship those authority envelopes to the LLM client verbatim.
 *
 * Walks arrays and nested objects up to MAX_STRIP_DEPTH levels deep.
 *
 * @param {unknown} data
 * @param {number} [depth=0]
 * @param {object} [opts]
 * @param {(key: string) => void} [opts.onStrip] - Called once per stripped
 *   key occurrence. Used by trust boundaries that log strips (connect.js
 *   emits a SECURITY stderr line naming the upstream and tool).
 * @returns {unknown}
 */
export function stripInternalEnvelopes(data, depth = 0, opts = undefined) {
  if (depth >= MAX_STRIP_DEPTH) return data;
  if (!data || typeof data !== 'object') return data;
  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i += 1) {
      data[i] = stripInternalEnvelopes(data[i], depth + 1, opts);
    }
    return data;
  }
  for (const key of RESERVED_ENVELOPE_KEYS) {
    if (key in data) {
      if (opts && typeof opts.onStrip === 'function') opts.onStrip(key);
      delete data[key];
    }
  }
  for (const k of Object.keys(data)) {
    if (data[k] && typeof data[k] === 'object') {
      data[k] = stripInternalEnvelopes(data[k], depth + 1, opts);
    }
  }
  return data;
}

/**
 * Sanitize prompt-injection strings in upstream tool result objects
 * before they reach the LLM context window.
 *
 * Walk the result object recursively (capped at MAX_STRIP_DEPTH)
 * and apply `sanitizeDescription` to every string leaf. Non-string
 * values (numbers, booleans, null) are passed through unchanged.
 * Arrays are walked element-by-element. The sanitizer replaces strings
 * that match any PROMPT_INJECTION_PATTERNS with a neutral placeholder,
 * labelled "upstream result" so the operator can trace the source.
 *
 * @param {unknown} value
 * @param {number} [depth=0]
 * @returns {unknown}
 */
export function sanitizeResultObject(value, depth = 0) {
  if (depth >= MAX_STRIP_DEPTH) return value;
  if (typeof value === 'string') {
    return sanitizeDescription(value, { label: 'upstream result' });
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeResultObject(item, depth + 1));
  }
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = sanitizeResultObject(v, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Like `stripInternalEnvelopes` but uses the narrower `EGRESS_STRIP_KEYS`
 * set. Walks arrays and nested objects up to MAX_STRIP_DEPTH levels deep.
 * Preserves bridge-authored response metadata (`_truncated`, `_summary`,
 * `_original_count`) so downstream callers can observe truncation.
 *
 * @param {unknown} data
 * @param {number} [depth=0]
 * @returns {unknown}
 */
export function stripEgressEnvelopes(data, depth = 0) {
  if (depth >= MAX_STRIP_DEPTH) return data;
  if (!data || typeof data !== 'object') return data;
  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i += 1) {
      data[i] = stripEgressEnvelopes(data[i], depth + 1);
    }
    return data;
  }
  for (const key of EGRESS_STRIP_KEYS) {
    if (key in data) delete data[key];
  }
  for (const k of Object.keys(data)) {
    if (data[k] && typeof data[k] === 'object') {
      data[k] = stripEgressEnvelopes(data[k], depth + 1);
    }
  }
  return data;
}

/**
 * Shared transport-egress pipeline: strip reserved envelope keys then
 * sanitize string values for prompt injection. Apply this at every
 * transport boundary that returns dispatch results to external callers
 * (MCP CallTool, webhook sync response, REST egress, etc.).
 *
 * Uses `stripEgressEnvelopes` (narrower than `stripInternalEnvelopes`) so
 * bridge-authored response metadata such as `_truncated` / `_summary` /
 * `_original_count` survives transport. Upstream-forged copies of those
 * keys are scrubbed at the upstream trust boundary (`connect.js` and the
 * REST dispatch path) using the full-set `stripInternalEnvelopes`.
 *
 * @param {unknown} result Raw dispatch result
 * @returns {unknown} Sanitized result safe for external callers
 */
export function sanitizeTransportEgress(result) {
  const stripped = stripEgressEnvelopes(result);
  return sanitizeResultObject(stripped);
}
