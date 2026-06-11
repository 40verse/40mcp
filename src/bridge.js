import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { dispatchToolCall } from './core/path.js';
import { createStdioTransport } from './transport/stdio.js';
import { createSseTransport } from './transport/sse.js';
import { createApiClient } from './core/client.js';
import { applyResponseTransform } from './transforms/response.js';
import { executeChain } from './compose/chain.js';
import { assertValidConfig } from './validate.js';
import { AuditEventCode, BridgeError, BridgeErrorCode } from './errors.js';
import { resolveEnvVars, assertSafeUrl } from './core/env.js';
import { safeLog, getTelemetryConfig, buildInstanceField, instanceBannerSuffix } from './core/events.js';
import { sanitizeDescription, sanitizeMcpToolDescription } from './core/sanitize.js';
import './core/types.js';

// ─── Runtime input schema validation ────────────────────────────────────────

/**
 * Map JSON Schema type names to runtime type-check functions.
 *
 * `typeof NaN === 'number'` and `typeof Infinity === 'number'` are both true.
 * The `number` checker must reject NaN/Infinity/-Infinity/-0 as invalid
 * `number` values because downstream comparators like `if (limit > MAX_LIMIT)`
 * silently misbehave — `NaN > X` is always false, allowing a hostile MCP client
 * to send `{"limit": NaN}` and disable downstream caps. Require finiteness at
 * the type boundary. `integer` was already safe (`Number.isInteger` rejects
 * NaN/Infinity) but we add the explicit finite check for consistency and
 * defense-in-depth.
 */
const TYPE_CHECKERS = {
  string: (v) => typeof v === 'string',
  number: (v) => typeof v === 'number' && Number.isFinite(v),
  integer: (v) => typeof v === 'number' && Number.isFinite(v) && Number.isInteger(v),
  boolean: (v) => typeof v === 'boolean',
  array: (v) => Array.isArray(v),
  object: (v) => v !== null && typeof v === 'object' && !Array.isArray(v),
};

/**
 * Validate args against an inputSchema.
 * Checks required fields and type of each provided property.
 * Returns null on success, error message string on failure.
 *
 * @param {object} args
 * @param {object} schema - JSON Schema (type: 'object' with properties + required)
 * @returns {string|null}
 */
/**
 * Keys that must never appear in tool-call args, regardless of the tool's
 * inputSchema. validateToolArgs must enforce these restrictions because
 * MCP clients (or webhook bodies) could otherwise smuggle internal
 * dispatch-control keys like `_tenant`, `_chain`, `_depth`, or `_steering`
 * into the args object and influence downstream dispatch behaviour. Reject
 * every `_`-prefixed key uniformly plus the known prototype-pollution keys.
 */
const RESERVED_ARG_KEYS = new Set([
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
 * Exposed for connect.js (upstream → bridge trust boundary). Stripped from
 * any tool result returned by a connected MCP server so an attacker
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
 * `connect.js` and by the REST response scrubber below) strips the full
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
 * @returns {unknown}
 */
export const MAX_STRIP_DEPTH = 10;
export function stripInternalEnvelopes(data, depth = 0) {
  if (depth >= MAX_STRIP_DEPTH) return data;
  if (!data || typeof data !== 'object') return data;
  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i += 1) {
      data[i] = stripInternalEnvelopes(data[i], depth + 1);
    }
    return data;
  }
  for (const key of RESERVED_ENVELOPE_KEYS) {
    if (key in data) delete data[key];
  }
  for (const k of Object.keys(data)) {
    if (data[k] && typeof data[k] === 'object') {
      data[k] = stripInternalEnvelopes(data[k], depth + 1);
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

/**
 * Recursively scan an args tree for reserved envelope keys.
 *
 * The reserved-key check must run BEFORE any schema-driven short-circuit,
 * so tools without a declared `inputSchema` still receive full reserved-key
 * filtering. Without this, an MCP client (or webhook body under a route with
 * no argMap) could smuggle `_tenant`, `_chain`, `_depth`, `_steering` into
 * a schemaless tool's args — `dispatchToolCall` at path.js would then read
 * `args._tenant` and drive the outbound identity as an attacker-chosen tenant.
 *
 * The scan must also recurse into nested objects (not just top-level args).
 * An OpenAPI-declared `type: "object"` body parameter accepts any nested
 * contents, so `{body: {_tenant: "victim"}}` could pass validation and
 * create a cross-tenant data exfil channel if the upstream is another
 * 40mcp instance.
 *
 * The recursive walker caps depth (matches `MAX_STRIP_DEPTH = 10`)
 * and arrays are walked element by element. Returns `null` on
 * success, an error string on the first reserved key it finds.
 */
const MAX_RESERVED_SCAN_DEPTH = 10;
function scanReservedKeys(value, depth = 0, path = '') {
  if (depth >= MAX_RESERVED_SCAN_DEPTH) return null;
  if (value == null || typeof value !== 'object') return null;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const err = scanReservedKeys(value[i], depth + 1, `${path}[${i}]`);
      if (err) return err;
    }
    return null;
  }
  for (const key of Object.keys(value)) {
    if (RESERVED_ARG_KEYS.has(key)) {
      const fullPath = path ? `${path}.${key}` : key;
      return `Argument "${fullPath}" is reserved and cannot be supplied by callers`;
    }
    const err = scanReservedKeys(value[key], depth + 1, path ? `${path}.${key}` : key);
    if (err) return err;
  }
  return null;
}

export function validateToolArgs(args, schema) {
  // Reserved-key rejection runs UNCONDITIONALLY, before any schema-driven
  // short-circuit. Tools without a declared inputSchema still receive full
  // reserved-key protection. The walker recurses into nested objects/arrays
  // so smuggled reserved keys inside `type:"object"` body params are caught.
  if (args && typeof args === 'object') {
    const reservedErr = scanReservedKeys(args);
    if (reservedErr) return reservedErr;
  }

  if (!schema || typeof schema !== 'object') return null;

  const properties = schema.properties || {};
  const required = Array.isArray(schema.required) ? schema.required : [];
  // Enforce additionalProperties: false when the schema opts in. Default
  // behaviour stays backwards-compatible for existing tools (schemas that
  // don't set additionalProperties still accept extras), but internal
  // reserved keys are ALWAYS rejected regardless.
  //
  // JSON Schema also allows `additionalProperties: <subschema>` (extras must
  // match a sub-schema). 40mcp does NOT implement sub-schema validation.
  // A tool author that expects sub-schema enforcement gets silent passthrough —
  // the validator skips the constraint entirely. Warn loudly the first time
  // we see this shape so the operator knows enforcement is not happening.
  const strictAdditional = schema.additionalProperties === false;
  if (
    schema.additionalProperties &&
    typeof schema.additionalProperties === 'object' &&
    !validateToolArgs._warnedSubschema
  ) {
    process.stderr.write(
      `[40mcp] WARNING: additionalProperties as an object schema is NOT enforced — ` +
      `extras pass through unvalidated. Use additionalProperties:false to reject extras strictly.\n`,
    );
    validateToolArgs._warnedSubschema = true;
  }

  // Check required fields using hasOwnProperty (not inherited properties).
  // `args[key] === undefined` is unsafe when an attacker-controlled schema
  // (e.g. a loaded OpenAPI/GraphQL spec) places an inherited property name
  // in `required` — `args.toString` would resolve to `Object.prototype.toString`
  // (a Function, never undefined), silently bypassing the required-field
  // contract. Use hasOwnProperty so the check only consults own properties.
  const hasOwn = Object.prototype.hasOwnProperty;
  const missing = required.filter((key) =>
    !hasOwn.call(args, key) || args[key] === undefined || args[key] === null,
  );
  if (missing.length > 0) {
    return `Missing required argument${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}`;
  }

  // Check types of provided properties
  for (const [key, value] of Object.entries(args)) {
    if (RESERVED_ARG_KEYS.has(key)) {
      return `Argument "${key}" is reserved and cannot be supplied by callers`;
    }
    if (value === undefined || value === null) continue;
    const propSchema = properties[key];
    if (!propSchema || !propSchema.type) {
      if (strictAdditional) {
        return `Unknown argument "${key}" (additionalProperties: false)`;
      }
      continue;
    }
    const checker = TYPE_CHECKERS[propSchema.type];
    if (checker && !checker(value)) {
      return `Argument "${key}" must be of type ${propSchema.type}, got ${Array.isArray(value) ? 'array' : typeof value}`;
    }
    // Enforce JSON Schema `enum` constraints. The validator must check
    // the `enum` field, not just `type`. Without this, `memory_type:
    // {type: "string", enum: MEMORY_TYPES}` would accept ANY string at
    // runtime, including attacker-chosen values that flow through to
    // downstream handlers. Schema-declared enums must be enforced uniformly
    // across every dispatch surface.
    if (Array.isArray(propSchema.enum) && !propSchema.enum.includes(value)) {
      return `Argument "${key}" must be one of: ${propSchema.enum.join(', ')}`;
    }

    // Enforce additional JSON Schema constraints that were previously silently
    // ignored. Both the validator and `simplifySchema` (openapi.js) now preserve
    // and enforce these fields so OpenAPI-loaded tools get the same validation
    // coverage as inline-defined tools.

    // String constraints
    if (typeof value === 'string') {
      if (propSchema.pattern !== undefined) {
        // Guard against ReDoS (Regular Expression Denial of Service). An
        // attacker-controlled OpenAPI/GraphQL spec can inject a catastrophically
        // backtracking pattern (e.g. `^(a+)+$`) that freezes the Node.js event
        // loop on a single tool call. Reject patterns showing common ReDoS
        // indicators (nested quantifiers, quantified alternation) or exceeding
        // a safe length before compiling.
        let re;
        try {
          const pat = propSchema.pattern;
          if (
            typeof pat === 'string' &&
            // Cap regex length at 100 chars to reduce attack surface —
            // catastrophically backtracking patterns are still representable
            // under 100 chars. Block all known dangerous structures:
            pat.length <= 100 &&
            !/\([^)]*[+*?][^)]*\)[+*?]/.test(pat) && // nested quantifiers: (a+)+
            !/\([^)]*\|[^)]*\)[+*?]/.test(pat) &&    // quantified alternation: (a|b)*
            !/\[[^\]]*\][+*?]\[[^\]]*\][+*?]/.test(pat) && // adjacent quantified char classes: [a-z]*[a-z]*
            !/\(\?:[^)]*[+*?][^)]*\)[+*?]/.test(pat) && // non-capturing with inner+outer quantifier: (?:a+)+
            // Block {n,m} repetition-range syntax with outer quantifiers too
            // (e.g. (a{1,5}){1,5}, (?:X{n,m})*), which also causes catastrophic
            // backtracking but was previously allowed.
            !/\([^)]*\{[0-9]+,[0-9]*\}[^)]*\)[+*?{]/.test(pat)
          ) {
            re = new RegExp(pat);
          }
        } catch { /* invalid regex — skip */ }
        if (re && !re.test(value)) {
          return `Argument "${key}" does not match required pattern`;
        }
      }
      if (propSchema.minLength !== undefined && value.length < propSchema.minLength) {
        return `Argument "${key}" is too short (minimum ${propSchema.minLength} characters)`;
      }
      if (propSchema.maxLength !== undefined && value.length > propSchema.maxLength) {
        return `Argument "${key}" is too long (maximum ${propSchema.maxLength} characters)`;
      }
    }

    // Numeric constraints
    if (typeof value === 'number') {
      if (propSchema.minimum !== undefined && value < propSchema.minimum) {
        return `Argument "${key}" must be >= ${propSchema.minimum}`;
      }
      if (propSchema.maximum !== undefined && value > propSchema.maximum) {
        return `Argument "${key}" must be <= ${propSchema.maximum}`;
      }
      if (propSchema.exclusiveMinimum !== undefined && value <= propSchema.exclusiveMinimum) {
        return `Argument "${key}" must be > ${propSchema.exclusiveMinimum}`;
      }
      if (propSchema.exclusiveMaximum !== undefined && value >= propSchema.exclusiveMaximum) {
        return `Argument "${key}" must be < ${propSchema.exclusiveMaximum}`;
      }
      if (propSchema.multipleOf !== undefined && propSchema.multipleOf !== 0) {
        // Floating-point safe: use remainder with tolerance
        const remainder = Math.abs(value % propSchema.multipleOf);
        const tolerance = 1e-10 * Math.abs(propSchema.multipleOf);
        if (remainder > tolerance && Math.abs(remainder - Math.abs(propSchema.multipleOf)) > tolerance) {
          return `Argument "${key}" must be a multiple of ${propSchema.multipleOf}`;
        }
      }
    }

    // Array constraints
    if (Array.isArray(value)) {
      if (propSchema.minItems !== undefined && value.length < propSchema.minItems) {
        return `Argument "${key}" must have at least ${propSchema.minItems} items`;
      }
      if (propSchema.maxItems !== undefined && value.length > propSchema.maxItems) {
        return `Argument "${key}" must have at most ${propSchema.maxItems} items`;
      }
      if (propSchema.uniqueItems === true) {
        const seen = new Set();
        for (const item of value) {
          const repr = JSON.stringify(item);
          if (seen.has(repr)) {
            return `Argument "${key}" must contain unique items`;
          }
          seen.add(repr);
        }
      }
    }
  }

  return null;
}

// ─── Audit trail ────────────────────────────────────────────────────────────

/**
 * Emit a structured audit log entry to stderr.
 * Each line is a self-contained JSON object for easy log-aggregation ingestion.
 * Fields: ts (epoch ms), tool, status ('success'|'error'), durationMs, errorCode.
 * Args are intentionally omitted — they may contain credentials or PII.
 *
 * Wrapped in try/catch so a stderr EPIPE (e.g., daemon mode with `>&-`) or
 * write error does NOT propagate up through the dispatch path. Telemetry must
 * never crash the host.
 *
 * Exported so compose/mixer.js can emit identical-format audit lines.
 */
export function emitAuditLog(entry) {
  if (!getTelemetryConfig().audit) return;
  try {
    // Inject instance metadata when set so the audit trail carries a
    // friendly name and tags alongside the canonical identifiers.
    // Caller-supplied keys win over the injected field (caller may have
    // already set `instance` for a sub-context).
    const inst = buildInstanceField();
    const enriched = inst && (entry === null || entry === undefined || !Object.prototype.hasOwnProperty.call(entry, 'instance'))
      ? { instance: inst, ...entry }
      : entry;
    process.stderr.write(`[40mcp:audit] ${JSON.stringify(enriched)}\n`);
  } catch (err) {
    // Telemetry must never crash the host — swallow serialization errors
    // and stderr write failures (EPIPE, closed fd, etc.). Emit a minimal
    // placeholder line so incident investigators can see that an audit
    // event was attempted. If even that write fails (closed stderr), swallow
    // — there is nowhere to report.
    try {
      const reason = err?.code || err?.name || 'unknown';
      // Use JSON.stringify to escape special characters so log-forgery attacks
      // (custom Error whose .code contains injected audit-log fields) cannot
      // succeed. The prefix is preserved so log-forwarders that filter on
      // "[40mcp:audit]" still match.
      process.stderr.write('[40mcp:audit] ' + JSON.stringify({ error: 'emit_failed', reason }) + '\n');
    } catch {
      // nothing to do — stderr itself is broken
    }
  }
}

/**
 * Format an AbortSignal.reason as a short human string for the structured
 * BridgeError message. Signals cancelled without an explicit reason default
 * to a stable phrase so log consumers can grep on it.
 */
function abortReasonText(reason) {
  if (reason == null) return 'external cancellation';
  if (typeof reason === 'string') return reason;
  if (reason instanceof Error) return reason.message || reason.name || 'external cancellation';
  try {
    return String(reason);
  } catch {
    return 'external cancellation';
  }
}

// ─── Tool dispatcher ────────────────────────────────────────────────────────

function buildDispatcher(toolDefs, apiClient, dispatcherOptions = {}) {
  const toolMap = new Map();
  for (const tool of toolDefs) {
    // Reject empty or non-string tool names even if validateConfig was
    // bypassed. Without this, `toolMap.set("", tool)` succeeds and an MCP
    // client sending `CallTool{name:""}` would match.
    if (typeof tool.name !== 'string' || tool.name.length === 0) {
      throw new Error(`Tool name must be a non-empty string (got ${JSON.stringify(tool.name)})`);
    }
    toolMap.set(tool.name, tool);
  }
  // MCP tool-call boundary hooks. These run around the dispatch
  // body, NOT around the outbound HTTP fetch — that's what `beforeRequest`/
  // `afterRequest` already do at the HTTP boundary. Typical use: OTEL span
  // start/close, RFC 8693 delegation token mint, policy DSL enforcement,
  // cost attribution, correlation recording. Default to no-op async fns so
  // the hook always resolves to something awaitable.
  const userBeforeDispatch = dispatcherOptions.beforeDispatch || (async () => {});
  const userAfterDispatch = dispatcherOptions.afterDispatch || (async () => {});

  // Graceful shutdown: the enclosing factory (createRestBridge) owns the
  // shutdown state and hands us a `shutdownState` object. We track each
  // in-flight dispatch via a Promise in `shutdownState.inFlight` so
  // `close()` can await draining. Chain the user-supplied hooks with our
  // internal tracking; if the user threw in beforeDispatch we still clear
  // our tracker via the outer finally in `dispatch`.
  const shutdownState = dispatcherOptions.shutdownState || {
    closing: false,
    inFlight: new Set(),
  };
  const beforeDispatch = async (name, args, ctx) => {
    return userBeforeDispatch(name, args, ctx);
  };
  const afterDispatch = async (name, result, ctx) => {
    return userAfterDispatch(name, result, ctx);
  };

  // Global concurrent dispatch cap: prevent an authenticated client from
  // firing unbounded parallel tool calls and saturating the event loop.
  // The cap covers ALL transports feeding this dispatcher — SSE, webhook,
  // reverse bridge, compound-chain callers — so there's a single process-wide
  // ceiling. Chain-internal calls (depth > 0) are exempted because chain
  // fan-out is already bounded inside executeChain.
  // Require finite values and clamp to a hard ceiling so a config typo
  // like `Infinity` or `NaN` can't silently disable the dispatch cap.
  const requestedMax = dispatcherOptions.maxConcurrentDispatches;
  const clampedMax =
    typeof requestedMax === 'number' && Number.isFinite(requestedMax) && requestedMax > 0
      ? requestedMax
      : 50;
  const maxConcurrentDispatches = Math.max(1, Math.min(clampedMax, 10_000));
  let inFlightDispatches = 0;

  // `bridge.dispatch` is exported and a host harness (TUI, tests) can call
  // it with a 3rd arg. Use a module-private Symbol as an unforgeable trust
  // marker: "this options object came from the internal chain executor".
  // External callers have no handle to this Symbol so they cannot stamp it;
  // internal chain recursion through `internalDispatch` stamps it on every
  // forward. This prevents external callers from poisoning `_chainStack`
  // or setting `_depth > 0` to bypass the concurrency cap.
  const INTERNAL_OPTS = Symbol('40mcp:internal');

  // `internalDispatch` is passed to `executeChain` and trusts its
  // options (honors `_depth`, `_chainStack`, etc.). External callers
  // reach it only through the exported `dispatch` below, which strips
  // `_`-prefixed keys before forwarding.
  const internalDispatch = async function internalDispatch(name, args, chainOptions) {
    const opts = chainOptions || {};
    const isInternal = opts[INTERNAL_OPTS] === true;
    if (!isInternal) {
      if (inFlightDispatches >= maxConcurrentDispatches) {
        throw new McpError(
          ErrorCode.InternalError,
          `Dispatch capacity exceeded: ${inFlightDispatches}/${maxConcurrentDispatches} concurrent calls in flight. Retry shortly.`,
        );
      }
      inFlightDispatches += 1;
    }
    try {
      return await dispatchInner(name, args, opts);
    } finally {
      if (!isInternal) inFlightDispatches -= 1;
    }
  };

  // Exported dispatch: sanitizes options (strips `_`-prefixed keys the
  // external caller isn't allowed to set) and forwards to the internal
  // path.
  const dispatch = async function dispatch(name, args, chainOptions) {
    // Graceful shutdown refusal: once `close()` has been invoked the
    // bridge MUST NOT accept new dispatches. Emit a dedicated audit
    // event (distinct from ordinary errors) so operators can see how
    // many calls arrived after shutdown began. Throw a structured
    // BridgeError carrying `SHUTTING_DOWN` so callers can switch on it.
    if (shutdownState.closing) {
      emitAuditLog({
        ts: Date.now(),
        event: 'bridge.shutdown_refused',
        tool: name,
        status: 'error',
        errorCode: BridgeErrorCode.SHUTTING_DOWN,
      });
      throw new BridgeError(
        BridgeErrorCode.SHUTTING_DOWN,
        `Bridge is shutting down — refusing dispatch of "${name}".`,
      );
    }

    let safeOptions;
    if (chainOptions && typeof chainOptions === 'object') {
      safeOptions = {};
      for (const key of Object.keys(chainOptions)) {
        if (key.startsWith('_')) continue;
        safeOptions[key] = chainOptions[key];
      }
    }
    // Tool cancellation via AbortSignal. External callers may
    // supply `options.signal` to cancel the dispatch mid-flight. The signal
    // travels verbatim through safeOptions into the outbound fetch where it
    // composes with the internal timeout signal. Short-circuit here when the
    // signal is already aborted — fire afterDispatch for observability so
    // OTEL spans still close, then throw a structured BridgeError(ABORTED)
    // without running beforeDispatch, prehook, or any upstream I/O.
    const externalSignal =
      safeOptions && safeOptions.signal instanceof AbortSignal ? safeOptions.signal : null;

    // MCP tool-call boundary: build the dispatch-hook context once so
    // beforeDispatch and afterDispatch see the same envelope (tenant,
    // toolName, args). The tenant field is a best-effort lookup of the
    // caller-supplied `_tenant` envelope — undefined when the call arrives
    // from a transport that hasn't resolved one.
    const tenant = (args && typeof args === 'object' && args._tenant) || undefined;
    const dispatchContext = { toolName: name, args, tenant };

    // Fail fast on a pre-aborted signal before allocating tracking state —
    // a cancelled dispatch should not occupy a slot in the in-flight set
    // that `close()` would wait on. afterDispatch still fires for OTEL
    // span closure even though no HTTP work ran.
    if (externalSignal && externalSignal.aborted) {
      const reason = externalSignal.reason;
      const abortErr = new BridgeError(
        BridgeErrorCode.ABORTED,
        `dispatch aborted: ${abortReasonText(reason)}`,
        { toolName: name, cause: reason },
      );
      try {
        await afterDispatch(name, undefined, { ...dispatchContext, error: abortErr });
      } catch (hookErr) {
        try {
          process.stderr.write(
            `[40mcp] afterDispatch hook threw for "${safeLog(name, 128)}": ${safeLog(hookErr?.message || String(hookErr), 512)}\n`,
          );
        } catch { /* stderr broken — nothing to do */ }
      }
      throw abortErr;
    }

    // Register this dispatch in the in-flight set BEFORE any awaitable work
    // runs so `close()` always sees it. We use a deferred promise that
    // resolves when the outer dispatch settles (success or error). The
    // promise is the tracking handle — not the dispatch result — so
    // `close()` can `Promise.allSettled` the set without swallowing errors.
    let releaseTracking;
    const tracking = new Promise((resolve) => { releaseTracking = resolve; });
    shutdownState.inFlight.add(tracking);

    let result;
    let errOrUndef;
    try {
      result = await internalDispatch(name, args, safeOptions);
      // Sanitize the result before returning so callers
      // that invoke dispatch() directly (not via the MCP callTool handler)
      // receive sanitized output. sanitizeTransportEgress strips reserved
      // envelope keys (_steering, _tenant, etc.) AND redacts prompt-injection
      // strings in one pass. The callTool handler applies it a second time —
      // idempotent, harmless.
      result = sanitizeTransportEgress(result);
    } catch (err) {
      errOrUndef = err;
      throw err;
    } finally {
      // afterDispatch fires AFTER response-transform + egress-sanitize,
      // even on error, so OTEL spans always close. An afterDispatch throw
      // must NOT break dispatch — log to stderr and continue. If the
      // inner dispatch already threw, the finally block's rethrow above
      // (via the outer try/catch pattern) still surfaces the real error.
      try {
        await afterDispatch(name, result, { ...dispatchContext, error: errOrUndef });
      } catch (hookErr) {
        try {
          process.stderr.write(
            `[40mcp] afterDispatch hook threw for "${safeLog(name, 128)}": ${safeLog(hookErr?.message || String(hookErr), 512)}\n`,
          );
        } catch { /* stderr broken — nothing to do */ }
      }
      // Remove tracking AFTER afterDispatch so close() does not resolve
      // before the user's observability hook has drained.
      shutdownState.inFlight.delete(tracking);
      try { releaseTracking(); } catch { /* never throws */ }
    }
    return result;
  };

  // Helper used by `dispatchInner` to recurse into `executeChain`
  // carrying the trusted-internal marker AND the outer tool name so
  // `executeChain` can seed its `chainStack` with the current frame
  // at the TOP. Without this, the
  // invocation-cycle detector missed the first call's worth of
  // prehook + dispatchToolCall prep before blocking recursion.
  const callChain = async function callChain(toolName, chainSteps, args, options) {
    const trusted = {
      ...(options || {}),
      [INTERNAL_OPTS]: true,
      _currentChainName: toolName,
    };
    return executeChain(chainSteps, args, internalDispatch, trusted);
  };

  async function dispatchInner(name, args, chainOptions) {
    args = args || {};
    const callTs = Date.now();

    // Re-enforce tenant allowlist
    // and blocklist at every dispatch entry, NOT just at the outer
    // `scopedDispatch` wrapper. Previously chain inner steps invoked
    // via `internalDispatch` bypassed `scopedDispatch` entirely, so a
    // tenant restricted to `['outer_chain_tool']` could invoke EVERY
    // sub-tool the chain declared with bridge-root identity. The
    // tenant envelope now carries
    // allowlist/blocklist on `args._tenant`; check them here so the
    // invariant holds at every dispatch surface uniformly.
    const tenantCtx = args && typeof args === 'object' ? args._tenant : null;
    if (tenantCtx && typeof tenantCtx === 'object') {
      if (Array.isArray(tenantCtx.allowlist) && !tenantCtx.allowlist.includes(name)) {
        const error = new McpError(
          ErrorCode.InvalidRequest,
          `Tool "${name}" is not in tenant "${tenantCtx.tenantId || '?'}" allowlist`,
        );
        emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: AuditEventCode.TENANT_ACL_DENY, tenantId: tenantCtx.tenantId, durationMs: Date.now() - callTs });
        throw error;
      }
      if (Array.isArray(tenantCtx.blocklist) && tenantCtx.blocklist.includes(name)) {
        const error = new McpError(
          ErrorCode.InvalidRequest,
          `Tool "${name}" is blocked for tenant "${tenantCtx.tenantId || '?'}"`,
        );
        emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: AuditEventCode.TENANT_ACL_DENY, tenantId: tenantCtx.tenantId, durationMs: Date.now() - callTs });
        throw error;
      }
    }

    const tool = toolMap.get(name);
    if (!tool) {
      const error = new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
      emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: error.code, durationMs: Date.now() - callTs });
      throw error;
    }

    // Re-enforce tool.policy at every dispatchInner entry so compose-chain
    // sub-steps cannot reach `deny` or `require_approval` tools by routing
    // through a benign-looking outer chain tool that bypasses policyDispatch.
    //
    // - 'deny': always blocked here, whether the call is a chain sub-dispatch
    //   or a direct top-level call without a policy gate. "Deny" means never.
    // - 'require_approval': blocked ONLY for chain sub-dispatches (identified
    //   by the internal-opts Symbol). Top-level calls reach dispatchInner
    //   either through createPolicyGate (which already approved) or through
    //   a caller that chose to skip the gate — the bridge doesn't second-
    //   guess that choice. Chain sub-dispatches can't re-trigger interactive
    //   approval from inside dispatchInner, so blocking them is the only safe
    //   option for the chain case.
    // - 'log_only' / 'allow' / undefined: pass through.
    const toolPolicy = tool.policy;
    const isChainSubDispatch = chainOptions && chainOptions[INTERNAL_OPTS] === true;
    if (toolPolicy === 'deny') {
      const error = new McpError(
        ErrorCode.InvalidRequest,
        `Tool "${name}" is blocked by policy`,
      );
      emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: AuditEventCode.POLICY_DENIED, durationMs: Date.now() - callTs });
      throw error;
    }
    if (toolPolicy === 'require_approval' && isChainSubDispatch) {
      const error = new McpError(
        ErrorCode.InvalidRequest,
        `Tool "${name}" requires approval and cannot be called from a compose chain without re-entering the policy gate`,
      );
      emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: AuditEventCode.POLICY_APPROVAL_REQUIRED_IN_CHAIN, durationMs: Date.now() - callTs });
      throw error;
    }

    // Runtime input schema validation
    const validationError = validateToolArgs(args, tool.inputSchema);
    if (validationError) {
      const error = new McpError(ErrorCode.InvalidParams, `Tool "${name}": ${validationError}`);
      emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: error.code, durationMs: Date.now() - callTs });
      throw error;
    }

    // Tool deprecation warning.
    // `tool.deprecated` / `tool.successor` are caller-controlled strings
    // (loaded from config, or stitched from an upstream MCP server). A
    // value containing `\n` forges an extra stderr line that mimics the
    // `[40mcp:audit]` / `[40mcp] SECURITY:` prefix conventions. Scrub
    // control characters via safeLog before interpolation.
    if (tool.deprecated) {
      const msg = typeof tool.deprecated === 'string'
        ? tool.deprecated
        : `Tool "${safeLog(name, 128)}" is deprecated.`;
      const successor = tool.successor ? ` Use "${safeLog(tool.successor, 128)}" instead.` : '';
      process.stderr.write(`[40mcp] DEPRECATED: ${safeLog(msg, 512)}${successor}\n`);
    }

    // Tool version check — warn if version mismatch. Same log-forgery concern
    // applies to `tool.version` / `tool.removedIn`: both come from config.
    if (tool.version && tool.removedIn) {
      process.stderr.write(`[40mcp] WARNING: Tool "${safeLog(name, 128)}" (v${safeLog(tool.version, 32)}) will be removed in v${safeLog(tool.removedIn, 32)}\n`);
    }

    // Compound tool chain — delegate to chain executor with depth tracking.
    // Call via `callChain` so the internal trust marker is stamped onto
    // options. `dispatch` here is the TRUST-SAFE path; we use `internalDispatch`
    // inside `callChain` so depth/chainStack are honored for legitimate
    // recursion but external `_*` injection is still rejected at the
    // exported `dispatch` entry.
    if (tool.chain) {
      const options = {
        ...(chainOptions || {}),
        response: tool.chainResponse || undefined,
      };
      try {
        const result = await callChain(name, tool.chain, args, options);
        emitAuditLog({ ts: callTs, tool: name, status: 'success', durationMs: Date.now() - callTs });
        return result;
      } catch (err) {
        emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: err?.code || 'UNKNOWN', durationMs: Date.now() - callTs });
        throw err;
      }
    }

    // MCP tool-call boundary: beforeDispatch fires AFTER tenant resolve,
    // BEFORE the HTTP dispatch body. Do not conflate with beforeRequest — that's the HTTP
    // boundary and runs INSIDE dispatchToolCall/createApiClient. A throw
    // here aborts the dispatch; the caller sees the error and afterDispatch
    // still fires (via the outer finally) with context.error set.
    const beforeDispatchContext = {
      toolName: name,
      args,
      tenant: args && typeof args === 'object' ? args._tenant : undefined,
    };
    await beforeDispatch(name, args, beforeDispatchContext);

    // Shared dispatch: path interpolation + query/body mapping. Thread the
    // external cancellation signal (if any) into the outbound fetch via
    // `dispatchToolCall`'s opts argument. When absent, apiClient wiring is
    // unchanged — the internal timeout controller runs alone.
    const dispatchToolCallOpts =
      chainOptions && chainOptions.signal instanceof AbortSignal
        ? { signal: chainOptions.signal }
        : undefined;
    let result;
    try {
      result = await dispatchToolCall(tool, args, apiClient, dispatchToolCallOpts);
    } catch (err) {
      emitAuditLog({ ts: callTs, tool: name, status: 'error', errorCode: err?.code || 'UNKNOWN', durationMs: Date.now() - callTs });
      throw err;
    }

    // Upstream REST responses are attacker-controllable. Strip the FULL
    // reserved-envelope set (including bridge response-metadata keys like
    // `_truncated`) before transforms run. Without this, a malicious upstream
    // could pre-set `{ _truncated: true }` in its payload and deceive the LLM
    // about whether the response was truncated.
    result = stripInternalEnvelopes(result);

    // Apply response transforms if defined. After this, any response-metadata
    // keys (`_truncated`, `_summary`, `_original_count`) are trusted bridge
    // output and must survive transport egress (see EGRESS_STRIP_KEYS).
    if (tool.response) {
      result = applyResponseTransform(result, tool.response);
    }

    emitAuditLog({ ts: callTs, tool: name, status: 'success', durationMs: Date.now() - callTs });

    return result;
  }

  return dispatch;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Create an MCP server that bridges to a REST API.
 *
 * @param {object} config
 * @param {string} config.name        - Server name (shown to MCP clients)
 * @param {string} config.version     - Server version
 * @param {string} config.baseUrl     - REST API base URL (env vars interpolated: ${VAR})
 * @param {object} [config.auth]      - Auth config
 * @param {string} config.auth.type   - 'header' | 'bearer' | 'basic'
 * @param {string} [config.auth.header]  - Header name (for type='header')
 * @param {string} [config.auth.envVar]  - Env var holding the credential
 * @param {string} [config.auth.value]   - Static credential value (prefer envVar)
 * @param {object} [config.hooks]     - Lifecycle hooks
 * @param {Function} [config.hooks.beforeRequest] - Modify request before sending
 * @param {Array}  config.tools       - Tool definitions
 *
 * Each tool:
 * @param {string} tool.name          - MCP tool name (snake_case recommended)
 * @param {string} tool.description   - Human-readable description for the agent
 * @param {string} tool.method        - HTTP method: GET, POST, PUT, PATCH, DELETE
 * @param {string} tool.path          - URL path with :param placeholders
 * @param {object} [tool.queryMap]    - Rename map: { toolArg: 'apiQueryParam' }
 * @param {object} [tool.bodyMap]     - Rename map: { toolArg: 'apiBodyField' }
 * @param {object} tool.inputSchema   - JSON Schema for the tool's input
 */
export function createRestBridge(config) {
  assertValidConfig(config);

  const {
    name = 'rest-bridge',
    version = '1.0.0',
    baseUrl,
    auth,
    hooks,
    tools: toolDefs = [],
    // Optional dispatch wrapper. If present, called with the bridge's raw
    // `dispatch(name, args, opts)` and expected to return a function with
    // the same signature. The wrapped function is used both for the
    // internal MCP-server CallTool handler AND as the `dispatch` property
    // on the returned bridge object, so library consumers and the server
    // layer see the same policy / instrumentation surface.
    //
    // Primary use: inject `createPolicyGate({ dispatch, tools, approvalHandler })`
    // so a `serve`-style bridge can enforce `tool.policy` annotations
    // without the caller having to rewire the MCP Server manually.
    wrapDispatch,
  } = config;

  // Sealed vault auth — wire createAuthHook or createBearerHook as beforeRequest
  let vaultAuthHook = null;
  if (auth?.type === 'sealed' || auth?.type === 'sealed-bearer') {
    if (!config.vault) {
      throw new Error(
        `auth.type "${auth.type}" requires config.vault — pass a createVault() or initVault() instance.\n` +
        `Example: createRestBridge({ ..., vault: createVault({ path, passphrase }), auth: { type: 'sealed', name: 'my-secret', header: 'X-API-Key' } })`,
      );
    }
    if (auth.type === 'sealed') {
      if (!auth.name) throw new Error('auth.name is required for sealed auth');
      if (!auth.header) throw new Error('auth.header is required for sealed auth');
      vaultAuthHook = config.vault.createAuthHook({ [auth.name]: auth.header });
    } else {
      if (!auth.name) throw new Error('auth.name is required for sealed-bearer auth');
      vaultAuthHook = config.vault.createBearerHook(auth.name);
    }
  }

  const effectiveHooks = vaultAuthHook
    ? {
        ...hooks,
        beforeRequest: async (req) => {
          const vaultMod = await vaultAuthHook(req);
          const userMod = hooks?.beforeRequest ? await hooks.beforeRequest(req) : null;
          if (!vaultMod && !userMod) return null;
          return {
            headers: { ...(vaultMod?.headers || {}), ...(userMod?.headers || {}) },
            body: userMod?.body ?? vaultMod?.body,
          };
        },
      }
    : hooks;

  // Resolve env vars in baseUrl: "${VAR}" or "$VAR"
  const resolvedBaseUrl = resolveEnvVars(baseUrl || '', name);

  if (!baseUrl && !resolvedBaseUrl) {
    throw new Error(
      `createRestBridge() requires a baseUrl — none was provided. ` +
      `Set baseUrl to a URL or an env var reference like "\${API_BASE_URL}".`,
    );
  } else if (!resolvedBaseUrl) {
    const allChain = Array.isArray(toolDefs) && toolDefs.length > 0 && toolDefs.every((t) => t.chain);
    if (!allChain) {
      throw new Error(
        `[${name}] config.baseUrl resolved to empty. ` +
        `Ensure the environment variable referenced by baseUrl is set.`,
      );
    }
  }

  // Validate the RESOLVED baseUrl against the
  // cloud-metadata denylist UNCONDITIONALLY. Previously `createRestBridge`
  // only ran the scheme check inside `createApiClient`, so a config
  // passing `baseUrl: "http://169.254.169.254"` (AWS IMDS) or
  // `baseUrl: "${INTERNAL_HOST}"` resolving to the same target
  // dispatched every tool call against the metadata service — trivial
  // credential exfil. `assertSafeUrl` is called on spec fetches by CLI
  // loaders but never on the dispatch path itself — close that gap.
  //
  // Default is `allowPrivate: true` so loopback / RFC-1918 targets
  // continue to work for local dev and test harnesses; metadata hosts
  // (`169.254.169.254` et al.) are always rejected regardless. Set
  // `config.strictSsrf: true` to additionally refuse loopback and
  // private IP ranges for production deployments.
  if (resolvedBaseUrl) {
    try {
      // When `config.allowPrivate` is set explicitly it wins; otherwise derive
      // from `strictSsrf` so the legacy shorthand (strictSsrf=true => reject
      // private) keeps working. Splitting lets an operator turn on
      // `strictSsrf` without implicitly flipping `allowPrivate`.
      const allowPrivate =
        config.allowPrivate !== undefined
          ? config.allowPrivate === true
          : config.strictSsrf !== true;
      assertSafeUrl(resolvedBaseUrl, {
        allowPrivate,
        label: `[${name}] baseUrl`,
      });
    } catch (err) {
      throw new Error(
        `${err.message} (baseUrl rejected at createRestBridge entry; set config.strictSsrf: false or remove the metadata endpoint).`,
      );
    }
  }

  const apiClient = createApiClient(resolvedBaseUrl, auth, effectiveHooks);

  // MCP tool-call boundary hooks. These are distinct from
  // beforeRequest/afterRequest which run at the HTTP boundary inside
  // createApiClient. Default to no-op async fns when unset so the dispatch
  // path always awaits something resolvable.
  const beforeDispatch = config.hooks?.beforeDispatch || (async () => {});
  const afterDispatch = config.hooks?.afterDispatch || (async () => {});

  // Graceful-shutdown coordination. Owned by the bridge
  // factory so `close()` and `dispatch` share a single view. The dispatcher
  // wraps every dispatch in a tracking promise held in `inFlight`.
  const shutdownState = {
    closing: false,
    inFlight: new Set(),
  };
  // Transport handles registered by `start()` so `close()` can tear them
  // down regardless of which transport is active. Multiple entries are
  // possible if the embedder starts + restarts the same bridge (uncommon
  // but legal).
  const transportResources = [];

  const dispatch = buildDispatcher(toolDefs, apiClient, {
    // Forward settings-sourced dispatch limits. When unset the dispatcher
    // falls back to its built-in defaults (maxConcurrent = 50).
    maxConcurrentDispatches: config.maxConcurrentDispatches,
    beforeDispatch,
    afterDispatch,
    shutdownState,
  });

  // Apply the optional wrapDispatch hook. Used by `40mcp serve --policy`
  // to wire a `createPolicyGate` around the bridge's dispatch so embedded
  // `tool.policy` annotations are enforced end-to-end through the MCP
  // server's CallTool handler. A caller that returns a function with the
  // same `(name, args, options)` signature gets that function used wherever
  // `dispatch` is — both in the MCP CallTool handler below AND as the
  // bridge's public `dispatch` export.
  const wrappedDispatch = typeof wrapDispatch === 'function'
    ? wrapDispatch(dispatch)
    : dispatch;

  // Build MCP tool list (strip bridge-specific fields, surface deprecation)
  const mcpTools = toolDefs.map((t) => {
    let description = t.description || '';
    if (t.deprecated) {
      const notice = typeof t.deprecated === 'string' ? t.deprecated : 'This tool is deprecated.';
      const successor = t.successor ? ` Use "${t.successor}" instead.` : '';
      description = `[DEPRECATED: ${notice}${successor}] ${description}`;
    }
    if (t.version) {
      description = `[v${t.version}] ${description}`;
    }
    // Deprecated/version notices are operator-supplied strings that are
    // prepended AFTER the loader's initial sanitization pass. An attacker who
    // controls the OpenAPI/HAR spec's `deprecated` or `x-version` field could
    // embed a prompt-injection payload without going through `sanitizeDescription`.
    // Sanitize the fully-composed description using the shared wrapper so bridge
    // and mixer stay in sync if the policy evolves.
    description = sanitizeMcpToolDescription(description, { label: 'bridge/mcpTools' });
    return {
      name: t.name,
      description,
      inputSchema: t.inputSchema || { type: 'object', properties: {}, required: [] },
    };
  });

  const server = new Server(
    { name, version },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: mcpTools }));

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name: toolName, arguments: args } = request.params;

    // The MCP SDK (as of @modelcontextprotocol/sdk 1.x) passes a request-
    // scoped AbortSignal on `extra.signal`. A `notifications/cancelled`
    // from the client aborts it. Forward it to dispatch() so the outbound
    // HTTP fetch composes with it. If the SDK ever stops exposing `signal`,
    // the guard silently falls back to no cancellation wiring.
    const dispatchOptions =
      extra && extra.signal instanceof AbortSignal ? { signal: extra.signal } : undefined;

    let result;
    try {
      result = await wrappedDispatch(toolName, args || {}, dispatchOptions);
    } catch (err) {
      if (err instanceof McpError) throw err;
      // Only expose error details in development — default to generic message to prevent info leakage
      const detail = process.env.NODE_ENV === 'development' ? (err.message || String(err)) : 'Internal error';
      throw new McpError(ErrorCode.InternalError, detail);
    }

    // Strip 40mcp internal envelope keys from the upstream REST response
    // before shipping it to the MCP client. An adversary-controlled or
    // compromised upstream that injects `_steering`, `_tenant`, `_chain`, etc.
    // into its JSON response body would otherwise ship those authority
    // envelopes verbatim to the LLM. Uses the narrower egress set so
    // bridge-authored response metadata (`_truncated`, `_summary`,
    // `_original_count`) survives to the LLM.
    const stripped = stripEgressEnvelopes(result);
    // Sanitize prompt-injection strings embedded in the upstream response
    // before they reach the LLM. An adversary-controlled upstream can return
    // {"message": "Ignore all previous instructions..."} — this walker
    // replaces every matching string leaf with a neutral placeholder.
    const sanitized = sanitizeResultObject(stripped);
    return {
      content: [{ type: 'text', text: JSON.stringify(sanitized, null, 2) }],
    };
  });

  // Shared, idempotent graceful-shutdown primitive.
  //
  // Contract:
  //   1. Refuse new dispatches with a BridgeError(SHUTTING_DOWN) and emit a
  //      `bridge.shutdown_refused` audit event.
  //   2. Await the in-flight set for up to `timeoutMs` (default 10 s).
  //   3. Close registered transports (MCP stdio/SSE, HTTP server with
  //      closeAllConnections when available).
  //   4. Emit a `bridge.shutdown_timeout` audit event with the count of
  //      dispatches still running if the timeout elapsed.
  //
  // Idempotent: second call returns the same promise as the first.
  // Never calls `process.exit` — the embedder decides when the process ends.
  let closePromise = null;
  const closeBridge = ({ timeoutMs = 10_000 } = {}) => {
    if (closePromise) return closePromise;
    shutdownState.closing = true;

    closePromise = (async () => {
      // Snapshot in-flight tracking promises. Adding happens only via
      // the dispatch path, which is now closed off by `closing = true`,
      // so the set can only shrink. Iterate the snapshot so later
      // deletions during draining don't surprise the iterator.
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
          // Unref the timer so it doesn't itself keep the event loop alive
          // (the bridge might be the last thing keeping the process up).
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
        });
      }

      // Close transports. Each registered resource knows how to tear itself
      // down; swallow errors so one broken transport can't block the others.
      for (const resource of transportResources) {
        try { await resource(); } catch { /* best-effort */ }
      }
      transportResources.length = 0;
    })();
    return closePromise;
  };

  return {
    /**
     * Start the MCP server.
     * Uses stdio by default, or SSE if config.transport.type === 'sse'.
     * @returns {Promise<{ server, dispatch }>}
     */
    async start() {
      const transportConfig = config.transport || {};
      if (transportConfig.type === 'sse') {
        const { httpServer, url } = await createSseTransport(server, {
          port: transportConfig.port ?? 8080,
          host: transportConfig.host,
          allowedOrigins: transportConfig.allowedOrigins,
          maxSessions: transportConfig.maxSessions,
          maxSessionsPerIp: transportConfig.maxSessionsPerIp,
          requireBearer: transportConfig.requireBearer,
        });
        process.stderr.write(`[${name}] MCP server started (SSE) — ${mcpTools.length} tools at ${url}${instanceBannerSuffix()}\n`);
        // Provide `close()` on the start() return so callers can
        // deterministically tear down the transport. The returned close
        // wrapper delegates to the bridge-level `close()` so callers get
        // draining + idempotence for free.
        const transportClose = async () => {
          try { await server.close?.(); } catch { /* ignore */ }
          try {
            // closeAllConnections is Node 18.2+; skip when unavailable so
            // we don't regress on older runtimes. Without it, keep-alive
            // connections block `server.close()` until their idle timer
            // fires.
            if (typeof httpServer.closeAllConnections === 'function') {
              try { httpServer.closeAllConnections(); } catch { /* ignore */ }
            }
            await new Promise((resolve) => {
              if (!httpServer || typeof httpServer.close !== 'function') return resolve();
              httpServer.close(() => resolve());
            });
          } catch { /* ignore */ }
        };
        transportResources.push(transportClose);
        return { server, dispatch: wrappedDispatch, httpServer, url, close: closeBridge };
      }
      const transport = createStdioTransport();
      await server.connect(transport);
      // Gate the startup banner's resolved baseUrl behind `logBaseUrl: true`
      // in the config. When stdio is wired through an MCP client that surfaces
      // server logs in its UI, the operator's internal/tenant API hostname
      // would otherwise leak to whoever reads that panel.
      if (config.logBaseUrl === true) {
        process.stderr.write(`[${name}] MCP server started — ${mcpTools.length} tools, base: ${resolvedBaseUrl}${instanceBannerSuffix()}\n`);
      } else {
        process.stderr.write(`[${name}] MCP server started — ${mcpTools.length} tools${instanceBannerSuffix()}\n`);
      }
      // Close the SDK server so its transport.close() runs and the data
      // listener on process.stdin detaches. Without this, a restart in a
      // host harness leaves a zombie listener consuming bytes from stdin.
      const transportClose = async () => {
        try { await server.close?.(); } catch { /* ignore */ }
      };
      transportResources.push(transportClose);
      return { server, dispatch: wrappedDispatch, close: closeBridge };
    },

    /**
     * Graceful shutdown primitive. Refuses new dispatches,
     * awaits in-flight dispatches up to `timeoutMs` (default 10 s), closes
     * registered transports, emits a `bridge.shutdown_timeout` audit event
     * if the deadline elapsed, and resolves. Never calls `process.exit`.
     * Idempotent: a second call returns the same promise as the first.
     *
     * @param {{ timeoutMs?: number }} [opts]
     * @returns {Promise<void>}
     */
    close: closeBridge,

    /** Access the underlying MCP Server instance (for custom transports). */
    server,

    /** Access the dispatch function directly (for testing). If a
     *  `wrapDispatch` hook was supplied, callers get the wrapped function
     *  so `bridge.dispatch` and the MCP CallTool handler route through the
     *  same policy / instrumentation surface. */
    dispatch: wrappedDispatch,

    /** Access the API client directly (for testing). */
    apiClient,
  };
}
