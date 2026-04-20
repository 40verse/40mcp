/**
 * Agent Authority — authority presets and authority gating for steered writes.
 *
 * An Authority is a capability bundle that describes what an agent is
 * allowed to do with memory. It answers three questions at the write
 * boundary:
 *
 *   1. Which memory_types may this agent commit?
 *      (e.g. a research-agent can write hypothesis/inference but NOT
 *      correction/decision — those require an operator with decision
 *      authority.)
 *
 *   2. What are its confidence / importance ceilings?
 *      (Prevents low-trust agents from flagging everything as importance=1.)
 *
 *   3. Which coordination scopes may it own?
 *      (Keeps an auth-wing agent from stamping memories into the billing
 *      wing without explicit handoff.)
 *
 * Authority is enforced at the prehook. If the tool declares
 * `steering.authority`, the bridge consults the gate before dispatch and
 * rejects unauthorized calls with `InvalidParams`. This makes authority
 * gating a stateless, declarative concern — no session tracking, no
 * membership database inside 40mcp. The agent identity comes in the call
 * args (`agentId`); the policy comes from the tool config.
 *
 * Built-in presets:
 *
 *   AUTHORITIES.READONLY    — No writes at all.
 *   AUTHORITIES.OBSERVER    — Observations, facts, references. Low ceilings.
 *   AUTHORITIES.RESEARCHER  — Observer + inferences + hypotheses + assumptions.
 *   AUTHORITIES.DECIDER     — Researcher + decisions + corrections. Full ceilings.
 *   AUTHORITIES.ROOT        — Unrestricted. Use for orchestrator agents.
 *
 * Usage in config:
 *
 *   "steering": {
 *     "write": true,
 *     "authority": "RESEARCHER"          // preset name
 *   }
 *
 *   "steering": {
 *     "write": true,
 *     "authority": {                     // inline custom authority
 *       "id": "auth-wing-writer",
 *       "allowed_memory_types": ["observation", "inference"],
 *       "max_confidence": 0.9,
 *       "max_importance": 0.8,
 *       "allowed_scopes": ["auth", "session"]
 *     }
 *   }
 *
 * @module steering/authority
 */

import { MEMORY_TYPES } from './schema.js';

/**
 * An Authority describes a capability bundle. Plain data — no methods.
 * The `Authority` factory below builds well-shaped instances and freezes
 * them so the built-in presets cannot be mutated at runtime.
 *
 * @typedef {object} Authority
 * @property {string} id
 * @property {ReadonlyArray<string>} allowed_memory_types
 * @property {number} max_confidence
 * @property {number} max_importance
 * @property {ReadonlyArray<string>|null} allowed_scopes - null = all scopes allowed
 */

/**
 * Build a frozen Authority from a plain spec. Validates the shape so
 * typos in config fail loudly instead of silently allowing everything.
 *
 * @param {object} spec
 * @returns {Authority}
 */
export function Authority(spec) {
  if (!spec || typeof spec !== 'object') {
    throw new Error('Authority(spec): spec must be an object');
  }
  const id = typeof spec.id === 'string' ? spec.id : 'unnamed';

  const allowed = Array.isArray(spec.allowed_memory_types) ? spec.allowed_memory_types : [];
  for (const t of allowed) {
    if (!MEMORY_TYPES.includes(t)) {
      throw new Error(`Authority "${id}": allowed_memory_types contains unknown memory_type "${t}"`);
    }
  }

  // `typeof NaN === 'number'` is true, and `NaN < 0` / `NaN > 1` are both
  // false — so the previous range check accepted `max_confidence: NaN` as a
  // valid bound, then `confidence > NaN` is always false, making the ceiling
  // effectively infinity. Throw loudly on explicit non-finite numbers so a
  // config typo (e.g. `parseFloat('foo')` upstream) is caught at boot, not
  // silently demoted to a default.
  if (spec.max_confidence !== undefined) {
    if (typeof spec.max_confidence !== 'number' || !Number.isFinite(spec.max_confidence)) {
      throw new Error(`Authority "${id}": max_confidence must be a finite number in [0,1]`);
    }
  }
  if (spec.max_importance !== undefined) {
    if (typeof spec.max_importance !== 'number' || !Number.isFinite(spec.max_importance)) {
      throw new Error(`Authority "${id}": max_importance must be a finite number in [0,1]`);
    }
  }
  const max_confidence = spec.max_confidence !== undefined ? spec.max_confidence : 1;
  const max_importance = spec.max_importance !== undefined ? spec.max_importance : 1;
  if (max_confidence < 0 || max_confidence > 1) {
    throw new Error(`Authority "${id}": max_confidence must be in [0,1]`);
  }
  if (max_importance < 0 || max_importance > 1) {
    throw new Error(`Authority "${id}": max_importance must be in [0,1]`);
  }

  // H5: validate each scope value against a strict allowlist pattern.
  // The original regex permitted `.` anywhere, so `..` was a valid scope name.
  // Tighten: require alphanumeric start and end, with dots, colons, hyphens,
  // and underscores only in the interior. Single-char scopes (alphanumeric only)
  // are also allowed.
  const VALID_SCOPE = /^[a-zA-Z0-9]([a-zA-Z0-9_:.-]{0,62}[a-zA-Z0-9])?$/;
  const allowed_scopes =
    spec.allowed_scopes == null
      ? null
      : Array.isArray(spec.allowed_scopes)
        ? (() => {
            for (const scope of spec.allowed_scopes) {
              if (typeof scope !== 'string' || !VALID_SCOPE.test(scope)) {
                throw new Error(`[authority] Invalid scope value "${String(scope).slice(0, 32)}" in authority "${id}"`);
              }
            }
            return Object.freeze([...spec.allowed_scopes]);
          })()
        : (() => { throw new Error(`Authority "${id}": allowed_scopes must be an array or null`); })();

  return Object.freeze({
    id,
    allowed_memory_types: Object.freeze([...allowed]),
    max_confidence,
    max_importance,
    allowed_scopes,
  });
}

/**
 * Built-in authority presets. Use by name in config (e.g. "authority": "RESEARCHER")
 * or construct a custom Authority inline.
 *
 * Ceilings reflect a sane default trust gradient: observers can't flag
 * anything as critical, researchers can flag high-importance hypotheses
 * but not corrections, deciders have full run. ROOT is unconstrained.
 */
export const AUTHORITIES = Object.freeze({
  READONLY: Authority({
    id: 'READONLY',
    allowed_memory_types: [],
    max_confidence: 0,
    max_importance: 0,
    allowed_scopes: [],
  }),

  OBSERVER: Authority({
    id: 'OBSERVER',
    allowed_memory_types: ['observation', 'fact', 'reference'],
    max_confidence: 0.8,
    max_importance: 0.5,
    allowed_scopes: null,
  }),

  RESEARCHER: Authority({
    id: 'RESEARCHER',
    allowed_memory_types: [
      'observation', 'fact', 'reference',
      'inference', 'hypothesis', 'assumption',
    ],
    max_confidence: 0.9,
    max_importance: 0.8,
    allowed_scopes: null,
  }),

  DECIDER: Authority({
    id: 'DECIDER',
    allowed_memory_types: [
      'observation', 'fact', 'reference',
      'inference', 'hypothesis', 'assumption',
      'decision', 'correction',
    ],
    max_confidence: 1,
    max_importance: 1,
    allowed_scopes: null,
  }),

  ROOT: Authority({
    id: 'ROOT',
    allowed_memory_types: [...MEMORY_TYPES],
    max_confidence: 1,
    max_importance: 1,
    allowed_scopes: null,
  }),
});

/**
 * Resolve an authority reference: a preset name, an Authority object, or
 * a plain spec. Returns a canonical Authority or throws.
 *
 * @param {string|object} ref
 * @returns {Authority}
 */
export function resolveAuthority(ref) {
  if (ref == null) {
    throw new Error('resolveAuthority: ref is required');
  }
  if (typeof ref === 'string') {
    // Previously `AUTHORITIES[ref]` walked the prototype chain.
    // `AUTHORITIES["toString"]` returned `Function.prototype.toString` — truthy,
    // bypassing the `if (!preset)` guard, then crashed downstream when
    // `authority.allowed_memory_types.includes(...)` ran on a Function. Worse,
    // with any prior prototype pollution, the lookup could return an
    // attacker-controlled value. Use `Object.hasOwn` so only own enumerable
    // preset keys resolve.
    if (!Object.prototype.hasOwnProperty.call(AUTHORITIES, ref)) {
      throw new Error(`Unknown authority preset "${ref}". Known: ${Object.keys(AUTHORITIES).join(', ')}`);
    }
    const preset = AUTHORITIES[ref];
    return preset;
  }
  if (typeof ref === 'object') {
    // Previously a frozen object with the right shape passed through WITHOUT
    // re-validation. An attacker who could supply a pre-frozen
    // `{id, allowed_memory_types: ['*'], max_confidence: 999, max_importance: 999}`
    // bypassed every bound check in `Authority()`. Always re-construct via
    // `Authority(ref)` — the cost is one freeze per dispatch, which is negligible,
    // and validation is guaranteed.
    return Authority(ref);
  }
  throw new Error(`resolveAuthority: ref must be a string, object, or Authority — got ${typeof ref}`);
}

/**
 * Check a steered write against an authority. Pure function — does not
 * throw. Returns `{ allowed, reason }` so callers can decide whether to
 * reject with a nice error or downgrade silently.
 *
 * The check runs AFTER classifyWrite() has normalized the args, so we can
 * assume memory_type/confidence/importance are present and valid.
 *
 * @param {Authority} authority
 * @param {{ memory_type: string, confidence: number, importance: number, coordination_scope?: string }} classified
 * @returns {{ allowed: boolean, reason: string|null }}
 */
export function checkAuthority(authority, classified) {
  if (!authority) return { allowed: false, reason: 'no authority resolved' };

  const { memory_type, confidence, importance, coordination_scope } = classified;

  if (!authority.allowed_memory_types.includes(memory_type)) {
    return {
      allowed: false,
      reason: `authority "${authority.id}" may not write memory_type="${memory_type}" (allowed: ${authority.allowed_memory_types.join(', ') || '<none>'})`,
    };
  }

  if (confidence > authority.max_confidence) {
    return {
      allowed: false,
      reason: `authority "${authority.id}" confidence ceiling is ${authority.max_confidence}, got ${confidence}`,
    };
  }

  if (importance > authority.max_importance) {
    return {
      allowed: false,
      reason: `authority "${authority.id}" importance ceiling is ${authority.max_importance}, got ${importance}`,
    };
  }

  // Previously the scope check short-circuited when `coordination_scope == null`
  // — i.e., a caller omitting `coordination_scope` entirely SKIPPED the scope
  // gate, inheriting the max of all scopes regardless of `authority.allowed_scopes`.
  // A scope-restricted authority (e.g. AUTHORITIES.DECIDER scoped to ['auth'])
  // became trivially bypassable by leaving the field unset. Fail closed: if the
  // authority declares `allowed_scopes !== null`, a missing or non-string
  // `coordination_scope` is a denial.
  if (authority.allowed_scopes !== null) {
    if (typeof coordination_scope !== 'string' || coordination_scope.length === 0) {
      return {
        allowed: false,
        reason: `authority "${authority.id}" requires coordination_scope`,
      };
    }
    if (!authority.allowed_scopes.includes(coordination_scope)) {
      return {
        allowed: false,
        reason: `authority "${authority.id}" may not write into scope "${coordination_scope}"`,
      };
    }
  }

  return { allowed: true, reason: null };
}
