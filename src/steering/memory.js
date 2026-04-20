/**
 * AgenticMemory — a class-based facade for agentic memory operations
 * over 40mcp's stateless steering contract.
 *
 * 40mcp does not store memory itself. `AgenticMemory` is a thin, stateless
 * wrapper that shapes calls through `classifyWrite` + `checkAuthority`
 * before delegating to a user-provided dispatch function (typically the
 * 40mcp bridge's `dispatch`, or a downstream MCP tool). The class exists
 * so that application code has one obvious surface to talk to when it
 * wants agentic-memory semantics — it never hides network I/O or holds
 * session state.
 *
 * Responsibilities:
 *
 *   - Enforce `classifyWrite` at the write boundary (forced inference).
 *   - Enforce `checkAuthority` against the calling agent's capabilities.
 *   - Route write / release / read through named tools on a dispatcher.
 *   - Emit structured outcome objects — never throw opaque errors.
 *
 * Non-responsibilities:
 *
 *   - No persistence. No caching. No session tracking.
 *   - No agent identity database. The caller passes `agent_id` explicitly.
 *   - No retries. The dispatcher decides.
 *
 * Typical use in application code:
 *
 *   import { createRestBridge } from '40mcp';
 *   import { AgenticMemory, AUTHORITIES } from '40mcp/steering';
 *
 *   const bridge = createRestBridge(config);
 *   const memory = new AgenticMemory({
 *     dispatch: bridge.dispatch,
 *     authority: AUTHORITIES.RESEARCHER,
 *     writeTool: 'memory_write',
 *     releaseTool: 'mem_release',
 *     readTool: 'memory_read',
 *   });
 *
 *   await memory.write({
 *     agent_id: 'agent-a',
 *     content: 'Auth flow diverges on expired tokens',
 *     memory_type: 'observation',
 *     confidence: 0.85,
 *     importance: 0.7,
 *     coordination_scope: 'auth',
 *   });
 *
 *   await memory.release({ handle_id: 'h-123', outcome: 'persisted' });
 *
 * @module steering/memory
 */

import { classifyWrite } from './apply.js';
import { resolveAuthority, checkAuthority } from './authority.js';

/**
 * Valid release outcomes — mirrors the downstream MCP contract.
 * @type {ReadonlyArray<string>}
 */
export const RELEASE_OUTCOMES = Object.freeze(['persisted', 'discarded', 'escalated']);

/**
 * AgenticMemory — wraps a dispatcher with steering + authority enforcement.
 */
export class AgenticMemory {
  /**
   * @param {object} opts
   * @param {Function} opts.dispatch - async (toolName, args) => result
   * @param {string|object} [opts.authority] - authority preset name, spec, or Authority
   * @param {string} [opts.writeTool='memory_write'] - tool name for writes
   * @param {string} [opts.releaseTool='mem_release'] - tool name for releases
   * @param {string} [opts.readTool='memory_read'] - tool name for reads
   */
  constructor(opts = {}) {
    if (typeof opts.dispatch !== 'function') {
      throw new Error('AgenticMemory: opts.dispatch must be a function (toolName, args) => result');
    }
    this.dispatch = opts.dispatch;
    // When no authority is bound, default to READONLY (deny all writes) rather
    // than null (unrestricted). A null authority previously meant the
    // checkAuthority gate was silently skipped — any caller could write
    // high-confidence corrections without restriction. Callers who truly want
    // unrestricted writes must pass `authority: 'ROOT'` explicitly.
    this.authority = opts.authority != null
      ? resolveAuthority(opts.authority)
      : resolveAuthority('READONLY');
    this.writeTool = opts.writeTool || 'memory_write';
    this.releaseTool = opts.releaseTool || 'mem_release';
    this.readTool = opts.readTool || 'memory_read';
  }

  /**
   * Write a classified memory. Forces classification at the call
   * boundary and gates against the bound authority. Returns the
   * downstream tool's result on success or throws an Error with a
   * descriptive message on authority / classification failure.
   *
   * Required fields in `args`:
   *   - content              (string)
   *   - memory_type          (enum MEMORY_TYPES)
   *   - confidence           (0..1)
   *   - importance           (0..1)
   *
   * Optional:
   *   - agent_id             (string) — who is writing
   *   - coordination_scope   (string) — authority scope check
   *   - ...any extra args forwarded to the dispatched tool
   *
   * @param {object} args
   * @returns {Promise<any>}
   */
  async write(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('AgenticMemory.write: args must be an object');
    }

    // Step 1: forced-inference classification.
    const classification = classifyWrite(args);

    // Step 2: authority gate (if one was bound to this instance).
    if (this.authority) {
      const gate = checkAuthority(this.authority, {
        memory_type: classification.memory_type,
        confidence: classification.confidence,
        importance: classification.importance,
        coordination_scope: args.coordination_scope,
      });
      if (!gate.allowed) {
        throw new Error(`AgenticMemory.write: ${gate.reason}`);
      }
    }

    // Step 3: dispatch to the downstream write tool. The dispatcher may
    // do its own prehook/posthook — that's a feature, not a conflict.
    // We forward the full args including the classification-normalized
    // memory_type/confidence/importance so the tool sees a canonical payload.
    return this.dispatch(this.writeTool, {
      ...args,
      memory_type: classification.memory_type,
      confidence: classification.confidence,
      importance: classification.importance,
    });
  }

  /**
   * Release a handle in the multi-agent coordination surface.
   * Transitions the handle from active → released with an outcome.
   *
   * @param {{ handle_id: string, outcome: 'persisted'|'discarded'|'escalated', note?: string }} args
   * @returns {Promise<any>}
   */
  async release(args) {
    if (!args || typeof args.handle_id !== 'string') {
      throw new Error('AgenticMemory.release: handle_id is required');
    }
    if (!RELEASE_OUTCOMES.includes(args.outcome)) {
      throw new Error(
        `AgenticMemory.release: outcome must be one of ${RELEASE_OUTCOMES.join(', ')} — got "${args.outcome}"`,
      );
    }
    return this.dispatch(this.releaseTool, args);
  }

  /**
   * Read a handle / memory entry. Delegates without any classification —
   * reads are not steered.
   *
   * @param {object} args
   * @returns {Promise<any>}
   */
  async read(args) {
    return this.dispatch(this.readTool, args || {});
  }
}

/**
 * Factory helper for users who prefer a plain function over `new`.
 * @param {ConstructorParameters<typeof AgenticMemory>[0]} opts
 * @returns {AgenticMemory}
 */
export function createAgenticMemory(opts) {
  return new AgenticMemory(opts);
}
