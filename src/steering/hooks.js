/**
 * Agent Steering — prehook/posthook primitives.
 *
 * The MCP server is stateless. "Agent steering" = injecting structured
 * inference instructions into the *call* (prehook) or back into the
 * *return* (posthook). The agent reads these instructions and acts —
 * the server never holds state between calls.
 *
 * Two primitives:
 *
 *   runPrehook(tool, args)
 *     - Before dispatch, returns an object { args, instructions, classification }.
 *     - `instructions` is text the agent should read BEFORE interpreting the
 *       tool result — used to steer classification, scoping, or routing.
 *     - `classification` is the write-time classification object when the
 *       tool opts into steering.write.
 *     - `args` may be returned unchanged or with steering-derived defaults
 *       filled in; the function never strips required fields.
 *
 *   runPosthook(tool, result, ctx)
 *     - After dispatch, returns an object { result, instructions }.
 *     - `instructions` is text appended to the MCP return payload telling
 *       the agent what to do next (e.g. "classify this as memory_type X",
 *       "call mem_release on handle Y", "pin if correction").
 *     - The bridge surfaces these instructions as an `_steering` field on
 *       the returned content so the agent sees them without parsing prose.
 *
 * Config shape (per-tool):
 *
 *   tool.steering = {
 *     write?: boolean,                    // enforce memory_type/confidence/importance
 *     prehook?: string | PrehookSpec,     // instructions injected before dispatch
 *     posthook?: string | PosthookSpec,   // instructions injected after dispatch
 *   }
 *
 * Prehook/posthook values can be:
 *   - a plain string  → emitted verbatim as instructions
 *   - a PrehookSpec   → { instructions: string, require?: string[] }
 *   - a PosthookSpec  → { instructions: string, require_next?: string[] }
 *
 * The design is stateless on purpose: the server transforms one call at a
 * time. State lives in the agent's context, not in the server.
 *
 * @module steering/hooks
 */

import { classifyWrite } from './apply.js';
import { resolveAuthority, checkAuthority } from './authority.js';
import { sanitizeDescription, hasPromptInjection } from '../core/sanitize.js';

/**
 * Sanitize a hook instruction string against prompt injection.
 * Redacts the string and emits a stderr warning if an injection pattern is found.
 * @private
 */
function sanitizeInstruction(instruction) {
  if (typeof instruction !== 'string') return instruction;
  if (hasPromptInjection(instruction)) {
    process.stderr.write(`[steering/hooks] SECURITY: hook instruction contains prompt injection pattern — redacted\n`);
    instruction = '[hook instruction redacted: injection pattern detected]';
  }
  return sanitizeDescription(instruction, { label: 'hook instruction' });
}

/**
 * Resolve a prehook/posthook value to its canonical shape.
 * Strings become { instructions }. Objects pass through.
 * @private
 */
function normalizeHookSpec(spec) {
  if (spec == null) return null;
  if (typeof spec === 'string') return { instructions: spec };
  if (typeof spec === 'object') return { ...spec };
  return null;
}

/**
 * Run the prehook for a tool call.
 *
 * Returns `{ args, classification, instructions }`:
 *   - args is returned unchanged (hook is a pure inspection pass today,
 *     but this shape lets future hooks inject defaults without breaking callers).
 *   - classification is set only when tool.steering.write === true and args
 *     pass classifyWrite().
 *   - instructions is the prehook text to surface to the agent, or null.
 *
 * Throws if tool.steering.write === true and classification fails.
 *
 * @param {object} tool
 * @param {object} args
 * @returns {{ args: object, classification: object|null, instructions: string|null }}
 */
export function runPrehook(tool, args) {
  const steering = tool?.steering;
  if (!steering) return { args, classification: null, instructions: null, authority: null };

  let classification = null;
  if (steering.write === true) {
    classification = classifyWrite(args);
  }

  // Authority gate: declarative on tool.steering.authority. Runs AFTER
  // classification so we have normalized memory_type/confidence/importance
  // to check against. Throws on denial — the bridge turns this into an
  // InvalidParams error so the MCP client sees a clear reason string.
  //
  // Previously the gate only fired when `classification` was non-null, i.e. only
  // when `steering.write === true`. A tool config declaring `authority: "OBSERVER"`
  // WITHOUT `write: true` (typo, or a read-like tool that wants ACL) silently
  // bypassed every authority check. The operator saw "authority: OBSERVER" in
  // their config and assumed enforcement; the runtime accepted everything. Fix:
  // an authority-declared tool MUST also declare `write: true`. Refuse the call
  // if the operator forgot, rather than silently allowing.
  let authority = null;
  if (steering.authority != null) {
    authority = resolveAuthority(steering.authority);
    if (!classification) {
      throw new Error(
        `tool "${tool.name || '(unnamed)'}" declares steering.authority but not steering.write:true — ` +
        `authority gating requires write classification. Add steering.write:true or remove authority.`,
      );
    }
    const gate = checkAuthority(authority, {
      memory_type: classification.memory_type,
      confidence: classification.confidence,
      importance: classification.importance,
      coordination_scope: args.coordination_scope,
    });
    if (!gate.allowed) {
      // gate.reason contains authority IDs, allowed scopes, and confidence
      // ceilings — internal bridge configuration that should not be forwarded to
      // unauthenticated MCP clients via the InvalidParams error that bridge.js
      // constructs from err.message. Log the detail to stderr for operator
      // visibility; emit an opaque denial to the caller.
      process.stderr.write(`[40mcp] authority denied: ${gate.reason}\n`);
      throw new Error('authority denied');
    }
  }

  const spec = normalizeHookSpec(steering.prehook);
  const instructions = spec?.instructions != null ? sanitizeInstruction(spec.instructions) : null;

  return { args, classification, instructions, authority };
}

/**
 * Run the posthook for a tool call.
 *
 * Returns `{ result, instructions }`:
 *   - result is the (possibly wrapped) tool result. Today it's passed through
 *     unchanged; the bridge attaches the instructions envelope separately so
 *     that downstream response transforms still see the original payload.
 *   - instructions is the posthook text to surface to the agent, or null.
 *
 * The `ctx` argument carries the classification from the prehook so posthook
 * text can reference it (e.g. for an "escalate if memory_type=correction" rule).
 *
 * @param {object} tool
 * @param {any} result
 * @param {{ classification: object|null }} [ctx]
 * @returns {{ result: any, instructions: string|null }}
 */
export function runPosthook(tool, result, ctx = {}) {
  const steering = tool?.steering;
  if (!steering) return { result, instructions: null };

  const spec = normalizeHookSpec(steering.posthook);
  if (!spec) return { result, instructions: null };

  let instructions = spec.instructions != null ? sanitizeInstruction(spec.instructions) : null;

  // If posthook is marked as conditional on classification, only emit when
  // the prehook actually produced one.
  if (spec.only_if_classified && !ctx.classification) {
    instructions = null;
  }

  return { result, instructions };
}

/**
 * Wrap a dispatch result with steering instructions for the MCP client.
 * Attaches a `_steering` envelope containing prehook/posthook instructions
 * and classification metadata. The original result payload is preserved
 * under `value`.
 *
 * Callers (the bridge) use this to build the final MCP content block.
 *
 * @param {any} result - original tool result
 * @param {{ prehook?: string|null, posthook?: string|null, classification?: object|null }} envelope
 * @returns {object}
 */
export function attachSteeringEnvelope(result, envelope) {
  const {
    prehook = null,
    posthook = null,
    classification = null,
    authority = null,
  } = envelope || {};
  if (!prehook && !posthook && !classification && !authority) return result;
  return {
    value: result,
    _steering: {
      ...(prehook ? { prehook_instructions: prehook } : {}),
      ...(posthook ? { posthook_instructions: posthook } : {}),
      ...(classification ? { classification } : {}),
      ...(authority ? { authority: { id: authority.id } } : {}),
    },
  };
}
