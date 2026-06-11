/**
 * Canonical leaf-dispatch pipeline — the single implementation of the
 * SPEC §2 "Pipeline order" steps that every REST-backed dispatch surface
 * shares:
 *
 *   outbound HTTP fetch (dispatchToolCall, incl. beforeRequest/afterRequest)
 *     → strip upstream envelope keys (full reserved set)
 *     → tool.response shaping (applyResponseTransform)
 *     → Transform.applyToResult
 *
 * Both `createRestBridge` (src/bridge.js) and `createMixer`
 * (src/compose/mixer.js) route their non-chain tool calls through
 * `runLeafDispatch`. Before this module existed each surface re-implemented
 * the sequence independently and they drifted: the mixer skipped the
 * upstream-side `stripInternalEnvelopes` pass, so an upstream REST API
 * could forge bridge response metadata (`{ "_truncated": true }`) that the
 * narrower transport-egress strip deliberately preserves. Sharing one
 * implementation makes that class of drift structurally impossible.
 *
 * Steps that are NOT part of the leaf and remain surface-specific: tenant
 * ACL re-checks, policy re-checks, arg validation, chain delegation,
 * concurrency caps, shutdown tracking, audit logging, egress-sanitize, and
 * the beforeDispatch/afterDispatch hook pair. See SPEC §2 for where each
 * runs.
 *
 * @module core/pipeline
 */

import { dispatchToolCall } from './path.js';
import { stripInternalEnvelopes } from './envelope.js';
import { applyResponseTransform } from '../transforms/response.js';

/**
 * Execute the canonical REST leaf dispatch for one tool call.
 *
 * Ordering invariants (BREAKING to change pre-1.0, per SPEC §2):
 *
 * 1. `stripInternalEnvelopes` runs on the raw upstream response BEFORE
 *    `tool.response` shaping, so upstream-forged reserved keys (including
 *    bridge response-metadata like `_truncated`) never reach a transform.
 * 2. `tool.response` shaping runs next; any response-metadata keys it
 *    emits are trusted bridge output from this point on.
 * 3. `Transform.applyToResult` runs LAST, downstream of shaping and
 *    upstream of the caller's egress-sanitize, so a Transform sees the
 *    shaped result and egress-sanitize still scrubs anything a Transform
 *    reintroduces.
 *
 * @param {object} params
 * @param {string} params.name - Fully-qualified tool name (for Transform context).
 * @param {object} params.tool - Tool definition (`method`, `path`, `response?`, …).
 * @param {object} params.args - Validated tool args.
 * @param {object} params.apiClient - Client from `createApiClient`.
 * @param {AbortSignal} [params.signal] - Optional cancellation signal threaded
 *   into the outbound fetch.
 * @param {object} [params.transform] - Optional Transform-conformant object
 *   (typically a `composeTransforms` composite). Only `applyToResult` runs
 *   here; `applyToDispatch` is the caller's responsibility because it must
 *   run before arg re-validation and the beforeDispatch hook.
 * @param {object} [params.context] - Context forwarded to `applyToResult`
 *   (`{ toolName, tenant?, … }`).
 * @returns {Promise<unknown>} The shaped result, ready for egress-sanitize.
 */
export async function runLeafDispatch({ name, tool, args, apiClient, signal, transform, context }) {
  const dispatchOpts = signal instanceof AbortSignal ? { signal } : undefined;
  let result = await dispatchToolCall(tool, args, apiClient, dispatchOpts);

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

  // Transform seam: applyToResult runs after shaping and before the
  // caller's egress-sanitize (SPEC §2 "Pipeline order").
  if (transform && typeof transform.applyToResult === 'function') {
    result = transform.applyToResult(name, result, context || { toolName: name });
  }

  return result;
}
