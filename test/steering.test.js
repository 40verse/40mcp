/**
 * Tests for Agent Steering — forced-inference write classification.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MEMORY_TYPES,
  CONFIDENCE_RANGE,
  IMPORTANCE_RANGE,
  DECAY_POLICIES,
  STEERING_WRITE_REQUIRED_FIELDS,
  applySteering,
  classifyWrite,
  deriveDecayPolicy,
  runPrehook,
  runPosthook,
  attachSteeringEnvelope,
  Authority,
  AUTHORITIES,
  resolveAuthority,
  checkAuthority,
  AgenticMemory,
  createAgenticMemory,
  RELEASE_OUTCOMES,
} from '../src/steering/index.js';

describe('steering/schema', () => {
  it('exports MEMORY_TYPES array with expected values', () => {
    assert(Array.isArray(MEMORY_TYPES));
    assert.equal(MEMORY_TYPES.length, 8);
    assert(MEMORY_TYPES.includes('correction'));
    assert(MEMORY_TYPES.includes('decision'));
    assert(MEMORY_TYPES.includes('observation'));
    assert(MEMORY_TYPES.includes('inference'));
    assert(MEMORY_TYPES.includes('fact'));
    assert(MEMORY_TYPES.includes('hypothesis'));
    assert(MEMORY_TYPES.includes('assumption'));
    assert(MEMORY_TYPES.includes('reference'));
  });

  it('exports CONFIDENCE_RANGE and IMPORTANCE_RANGE', () => {
    assert.equal(CONFIDENCE_RANGE.min, 0);
    assert.equal(CONFIDENCE_RANGE.max, 1);
    assert.equal(IMPORTANCE_RANGE.min, 0);
    assert.equal(IMPORTANCE_RANGE.max, 1);
  });

  it('exports DECAY_POLICIES with all memory types', () => {
    for (const type of MEMORY_TYPES) {
      assert(DECAY_POLICIES[type], `no policy for ${type}`);
      assert(['permanent', 'archive', 'decay'].includes(DECAY_POLICIES[type].class));
      assert(typeof DECAY_POLICIES[type].minConfidenceToRetain === 'number');
    }
  });

  it('marks corrections and decisions as permanent', () => {
    assert.equal(DECAY_POLICIES.correction.class, 'permanent');
    assert.equal(DECAY_POLICIES.correction.halfLifeDays, null);
    assert.equal(DECAY_POLICIES.decision.class, 'permanent');
    assert.equal(DECAY_POLICIES.decision.halfLifeDays, null);
  });

  it('marks observations, facts, references as archive', () => {
    assert.equal(DECAY_POLICIES.observation.class, 'archive');
    assert.equal(DECAY_POLICIES.observation.halfLifeDays, 365);
    assert.equal(DECAY_POLICIES.fact.class, 'archive');
    assert.equal(DECAY_POLICIES.fact.halfLifeDays, 365);
    assert.equal(DECAY_POLICIES.reference.class, 'archive');
    assert.equal(DECAY_POLICIES.reference.halfLifeDays, 365);
  });

  it('marks inferences, hypotheses, assumptions as decay', () => {
    assert.equal(DECAY_POLICIES.inference.class, 'decay');
    assert.equal(DECAY_POLICIES.inference.halfLifeDays, 30);
    assert.equal(DECAY_POLICIES.hypothesis.class, 'decay');
    assert.equal(DECAY_POLICIES.hypothesis.halfLifeDays, 14);
    assert.equal(DECAY_POLICIES.assumption.class, 'decay');
    assert.equal(DECAY_POLICIES.assumption.halfLifeDays, 60);
  });

  it('exports STEERING_WRITE_REQUIRED_FIELDS with 3 fields', () => {
    assert(STEERING_WRITE_REQUIRED_FIELDS.memory_type);
    assert(STEERING_WRITE_REQUIRED_FIELDS.confidence);
    assert(STEERING_WRITE_REQUIRED_FIELDS.importance);
    assert.equal(STEERING_WRITE_REQUIRED_FIELDS.memory_type.type, 'string');
    assert(Array.isArray(STEERING_WRITE_REQUIRED_FIELDS.memory_type.enum));
  });
});

describe('steering/apply', () => {
  describe('applySteering', () => {
    it('returns tool unchanged if steering is not present', () => {
      const tool = {
        name: 'my_tool',
        description: 'Does something',
        method: 'POST',
        path: '/api/action',
        inputSchema: {
          type: 'object',
          properties: { foo: { type: 'string' } },
          required: ['foo'],
        },
      };
      const result = applySteering(tool);
      assert.equal(result.name, 'my_tool');
      assert.deepEqual(result.inputSchema.required, ['foo']);
    });

    it('returns tool unchanged if steering.write is false', () => {
      const tool = {
        name: 'my_tool',
        description: 'Does something',
        steering: { write: false },
        inputSchema: {
          type: 'object',
          properties: { foo: { type: 'string' } },
          required: ['foo'],
        },
      };
      const result = applySteering(tool);
      assert.deepEqual(result.inputSchema.required, ['foo']);
    });

    it('injects steering fields when steering.write === true', () => {
      const tool = {
        name: 'write_memory',
        description: 'Write to memory',
        steering: { write: true },
        inputSchema: {
          type: 'object',
          properties: { content: { type: 'string' } },
          required: ['content'],
        },
      };
      const result = applySteering(tool);
      assert(result.inputSchema.properties.memory_type);
      assert(result.inputSchema.properties.confidence);
      assert(result.inputSchema.properties.importance);
      assert(result.inputSchema.properties.content);
      assert(result.inputSchema.required.includes('memory_type'));
      assert(result.inputSchema.required.includes('confidence'));
      assert(result.inputSchema.required.includes('importance'));
      assert(result.inputSchema.required.includes('content'));
    });

    it('does not mutate the original tool', () => {
      const tool = {
        name: 'write_memory',
        steering: { write: true },
        inputSchema: {
          type: 'object',
          properties: { content: { type: 'string' } },
          required: ['content'],
        },
      };
      const original = JSON.stringify(tool);
      applySteering(tool);
      assert.equal(JSON.stringify(tool), original);
    });

    it('creates empty schema if inputSchema is missing', () => {
      const tool = {
        name: 'write_memory',
        steering: { write: true },
      };
      const result = applySteering(tool);
      assert(result.inputSchema);
      assert(result.inputSchema.properties.memory_type);
      assert(result.inputSchema.required.includes('memory_type'));
    });

    it('steering fields override existing props (steering schema is authoritative)', () => {
      // merge order is `{ ...existing, ...STEERING_WRITE_REQUIRED_FIELDS }`
      // so steering takes precedence. Consequence: in property order, existing
      // keys come first and steering keys come last.
      const tool = {
        name: 'write_memory',
        steering: { write: true },
        inputSchema: {
          type: 'object',
          properties: { my_field: { type: 'string' } },
          required: ['my_field'],
        },
      };
      const result = applySteering(tool);
      const propKeys = Object.keys(result.inputSchema.properties);
      assert(propKeys.indexOf('my_field') < propKeys.indexOf('memory_type'));
      // Steering fields are all present
      assert(result.inputSchema.properties.memory_type);
      assert(result.inputSchema.properties.confidence);
      assert(result.inputSchema.properties.importance);
    });
  });

  describe('deriveDecayPolicy', () => {
    it('returns the correct policy for correction', () => {
      const policy = deriveDecayPolicy('correction');
      assert.equal(policy.class, 'permanent');
      assert.equal(policy.halfLifeDays, null);
    });

    it('returns the correct policy for each memory type', () => {
      for (const type of MEMORY_TYPES) {
        const policy = deriveDecayPolicy(type);
        assert(policy);
        assert(policy.class);
        assert(typeof policy.minConfidenceToRetain === 'number');
      }
    });

    it('throws on unknown memory_type', () => {
      assert.throws(
        () => deriveDecayPolicy('unknown_type'),
        (err) => err.message.includes('Unknown memory_type'),
      );
    });
  });

  describe('classifyWrite', () => {
    it('returns classification object with decay_policy', () => {
      const args = {
        memory_type: 'observation',
        confidence: 0.9,
        importance: 0.8,
        content: 'some data',
      };
      const result = classifyWrite(args);
      assert.equal(result.memory_type, 'observation');
      assert.equal(result.confidence, 0.9);
      assert.equal(result.importance, 0.8);
      assert(result.decay_policy);
      assert.equal(result.decay_policy.class, 'archive');
    });

    it('returns permanent policy for corrections', () => {
      const result = classifyWrite({
        memory_type: 'correction',
        confidence: 1.0,
        importance: 1.0,
      });
      assert.equal(result.decay_policy.class, 'permanent');
    });

    it('returns decay policy for hypotheses', () => {
      const result = classifyWrite({
        memory_type: 'hypothesis',
        confidence: 0.5,
        importance: 0.6,
      });
      assert.equal(result.decay_policy.class, 'decay');
      assert.equal(result.decay_policy.halfLifeDays, 14);
    });

    it('throws if memory_type is missing', () => {
      assert.throws(
        () => classifyWrite({ confidence: 0.9, importance: 0.8 }),
        (err) => err.message.includes('memory_type is required'),
      );
    });

    it('throws if memory_type is unknown', () => {
      assert.throws(
        () => classifyWrite({
          memory_type: 'bad_type',
          confidence: 0.9,
          importance: 0.8,
        }),
        (err) => err.message.includes('Unknown memory_type'),
      );
    });
  });
});

describe('steering/hooks', () => {
  describe('runPrehook', () => {
    it('returns no classification / no instructions when tool has no steering', () => {
      const tool = { name: 'plain' };
      const result = runPrehook(tool, { foo: 1 });
      assert.equal(result.classification, null);
      assert.equal(result.instructions, null);
      assert.deepEqual(result.args, { foo: 1 });
    });

    it('surfaces prehook string instructions verbatim', () => {
      const tool = { name: 'ticket', steering: { prehook: 'Include repro in body.' } };
      const result = runPrehook(tool, { subject: 'x' });
      assert.equal(result.instructions, 'Include repro in body.');
      assert.equal(result.classification, null);
    });

    it('surfaces prehook object instructions', () => {
      const tool = { name: 'ticket', steering: { prehook: { instructions: 'Be careful.' } } };
      const result = runPrehook(tool, {});
      assert.equal(result.instructions, 'Be careful.');
    });

    it('runs classifyWrite when steering.write is true and produces classification', () => {
      const tool = { name: 'memw', steering: { write: true } };
      const result = runPrehook(tool, { memory_type: 'correction', confidence: 1, importance: 1 });
      assert(result.classification);
      assert.equal(result.classification.memory_type, 'correction');
      assert.equal(result.classification.decay_policy.class, 'permanent');
    });

    it('throws when steering.write is true and classification is missing fields', () => {
      const tool = { name: 'memw', steering: { write: true } };
      assert.throws(
        () => runPrehook(tool, { content: 'x' }),
        (err) => err.message.includes('memory_type'),
      );
    });
  });

  describe('runPosthook', () => {
    it('returns null instructions when tool has no steering', () => {
      const tool = { name: 'plain' };
      const result = runPosthook(tool, { ok: true });
      assert.equal(result.instructions, null);
      assert.deepEqual(result.result, { ok: true });
    });

    it('surfaces posthook string instructions', () => {
      const tool = { name: 't', steering: { posthook: 'Call mem_release next.' } };
      const result = runPosthook(tool, { id: 1 });
      assert.equal(result.instructions, 'Call mem_release next.');
    });

    it('gates posthook on classification when only_if_classified is set', () => {
      const tool = {
        name: 't',
        steering: { posthook: { instructions: 'Pin.', only_if_classified: true } },
      };
      // No classification passed → instructions should be suppressed
      const withoutClass = runPosthook(tool, { id: 1 }, { classification: null });
      assert.equal(withoutClass.instructions, null);
      // Classification present → instructions surfaced
      const withClass = runPosthook(tool, { id: 1 }, {
        classification: { memory_type: 'correction', decay_policy: { class: 'permanent' } },
      });
      assert.equal(withClass.instructions, 'Pin.');
    });
  });

  describe('attachSteeringEnvelope', () => {
    it('returns result unchanged when envelope is empty', () => {
      const result = attachSteeringEnvelope({ ok: true }, {});
      assert.deepEqual(result, { ok: true });
    });

    it('wraps result in { value, _steering } when any field is present', () => {
      const wrapped = attachSteeringEnvelope(
        { ok: true },
        { prehook: 'before', posthook: 'after', classification: { memory_type: 'correction' } },
      );
      assert.deepEqual(wrapped.value, { ok: true });
      assert.equal(wrapped._steering.prehook_instructions, 'before');
      assert.equal(wrapped._steering.posthook_instructions, 'after');
      assert.equal(wrapped._steering.classification.memory_type, 'correction');
    });

    it('omits fields that are null/undefined in the envelope', () => {
      const wrapped = attachSteeringEnvelope({ ok: true }, { prehook: 'only this' });
      assert.equal(wrapped._steering.prehook_instructions, 'only this');
      assert.equal(wrapped._steering.posthook_instructions, undefined);
      assert.equal(wrapped._steering.classification, undefined);
    });

    it('surfaces authority id in the envelope', () => {
      const wrapped = attachSteeringEnvelope({ ok: true }, { authority: AUTHORITIES.RESEARCHER });
      assert.equal(wrapped._steering.authority.id, 'RESEARCHER');
    });
  });
});

describe('steering/authority', () => {
  describe('Authority factory', () => {
    it('builds a frozen Authority from a spec', () => {
      const a = Authority({
        id: 'test',
        allowed_memory_types: ['observation', 'fact'],
        max_confidence: 0.5,
        max_importance: 0.5,
      });
      assert.equal(a.id, 'test');
      assert(Object.isFrozen(a));
      assert.throws(() => { a.id = 'mutated'; });
    });

    it('rejects unknown memory_type in allowed_memory_types', () => {
      assert.throws(
        () => Authority({ id: 'bad', allowed_memory_types: ['not_a_type'] }),
        (err) => err.message.includes('unknown memory_type'),
      );
    });

    it('rejects out-of-range confidence ceiling', () => {
      assert.throws(
        () => Authority({ id: 'bad', max_confidence: 1.5 }),
        (err) => err.message.includes('max_confidence'),
      );
    });

    it('rejects non-array allowed_scopes', () => {
      assert.throws(
        () => Authority({ id: 'bad', allowed_scopes: 'auth' }),
        (err) => err.message.includes('allowed_scopes must be an array'),
      );
    });
  });

  describe('AUTHORITIES presets', () => {
    it('READONLY allows nothing', () => {
      assert.equal(AUTHORITIES.READONLY.allowed_memory_types.length, 0);
      assert.equal(AUTHORITIES.READONLY.max_confidence, 0);
    });

    it('OBSERVER permits observation/fact/reference only', () => {
      const allowed = AUTHORITIES.OBSERVER.allowed_memory_types;
      assert(allowed.includes('observation'));
      assert(allowed.includes('fact'));
      assert(allowed.includes('reference'));
      assert(!allowed.includes('correction'));
      assert(!allowed.includes('decision'));
    });

    it('RESEARCHER permits inferences and hypotheses but not corrections', () => {
      const allowed = AUTHORITIES.RESEARCHER.allowed_memory_types;
      assert(allowed.includes('inference'));
      assert(allowed.includes('hypothesis'));
      assert(allowed.includes('assumption'));
      assert(!allowed.includes('correction'));
      assert(!allowed.includes('decision'));
    });

    it('DECIDER permits corrections and decisions', () => {
      const allowed = AUTHORITIES.DECIDER.allowed_memory_types;
      assert(allowed.includes('correction'));
      assert(allowed.includes('decision'));
    });

    it('ROOT permits every memory_type', () => {
      for (const t of MEMORY_TYPES) {
        assert(AUTHORITIES.ROOT.allowed_memory_types.includes(t), `ROOT missing ${t}`);
      }
      assert.equal(AUTHORITIES.ROOT.max_confidence, 1);
    });

    it('presets are frozen', () => {
      assert(Object.isFrozen(AUTHORITIES));
      assert(Object.isFrozen(AUTHORITIES.RESEARCHER));
    });
  });

  describe('resolveAuthority', () => {
    it('resolves a preset name', () => {
      const a = resolveAuthority('RESEARCHER');
      assert.equal(a.id, 'RESEARCHER');
    });

    it('throws on unknown preset name', () => {
      assert.throws(
        () => resolveAuthority('NOBODY'),
        (err) => err.message.includes('Unknown authority preset'),
      );
    });

    it('re-validates an already-frozen Authority object (authority validation fix)', () => {
      // authority validation: the previous pass-through branch was unsafe
      // accepted any frozen object with the right SHAPE without
      // re-running Authority() validation, allowing a config loader to
      // smuggle out-of-range max_confidence/max_importance via a
      // pre-frozen object. The fix re-constructs via Authority() so
      // the result is structurally equivalent but not reference-equal.
      const a = resolveAuthority(AUTHORITIES.DECIDER);
      assert.deepEqual(a.allowed_memory_types, AUTHORITIES.DECIDER.allowed_memory_types);
      assert.equal(a.id, AUTHORITIES.DECIDER.id);
      assert.ok(Object.isFrozen(a));
    });

    it('builds an Authority from a plain spec', () => {
      const a = resolveAuthority({
        id: 'custom',
        allowed_memory_types: ['observation'],
      });
      assert.equal(a.id, 'custom');
      assert(Object.isFrozen(a));
    });
  });

  describe('checkAuthority', () => {
    it('allows a write within the authority', () => {
      const r = checkAuthority(AUTHORITIES.OBSERVER, {
        memory_type: 'observation',
        confidence: 0.7,
        importance: 0.4,
      });
      assert.equal(r.allowed, true);
      assert.equal(r.reason, null);
    });

    it('denies a write with a disallowed memory_type', () => {
      const r = checkAuthority(AUTHORITIES.OBSERVER, {
        memory_type: 'correction',
        confidence: 0.5,
        importance: 0.5,
      });
      assert.equal(r.allowed, false);
      assert(r.reason.includes('correction'));
    });

    it('denies a write above the confidence ceiling', () => {
      const r = checkAuthority(AUTHORITIES.OBSERVER, {
        memory_type: 'observation',
        confidence: 0.95,
        importance: 0.4,
      });
      assert.equal(r.allowed, false);
      assert(r.reason.includes('confidence ceiling'));
    });

    it('denies a write above the importance ceiling', () => {
      const r = checkAuthority(AUTHORITIES.OBSERVER, {
        memory_type: 'observation',
        confidence: 0.5,
        importance: 0.99,
      });
      assert.equal(r.allowed, false);
      assert(r.reason.includes('importance ceiling'));
    });

    it('denies a write into a disallowed scope', () => {
      const authWing = Authority({
        id: 'auth-wing',
        allowed_memory_types: ['observation'],
        allowed_scopes: ['auth'],
      });
      const r = checkAuthority(authWing, {
        memory_type: 'observation',
        confidence: 0.5,
        importance: 0.5,
        coordination_scope: 'billing',
      });
      assert.equal(r.allowed, false);
      assert(r.reason.includes('scope'));
    });

    it('allows any scope when allowed_scopes is null', () => {
      const r = checkAuthority(AUTHORITIES.RESEARCHER, {
        memory_type: 'inference',
        confidence: 0.8,
        importance: 0.5,
        coordination_scope: 'anywhere',
      });
      assert.equal(r.allowed, true);
    });
  });

  describe('runPrehook authority integration', () => {
    it('throws when a steered write violates authority', () => {
      const tool = {
        name: 'memw',
        steering: { write: true, authority: 'OBSERVER' },
      };
      assert.throws(
        () => runPrehook(tool, { memory_type: 'correction', confidence: 1, importance: 1 }),
        (err) => err.message.includes('authority denied'),
      );
    });

    it('passes when a steered write respects authority', () => {
      const tool = {
        name: 'memw',
        steering: { write: true, authority: 'RESEARCHER' },
      };
      const r = runPrehook(tool, { memory_type: 'hypothesis', confidence: 0.7, importance: 0.5 });
      assert(r.classification);
      assert.equal(r.authority.id, 'RESEARCHER');
    });

    it('refuses tools declaring authority without steering.write:true (authority enforcement)', () => {
      // authority enforcement: prevent unsafe write access without explicit steering
      // SKIPPED the authority check when classification was null
      // (i.e. when steering.write !== true). A tool config declaring
      // `authority: "OBSERVER"` but no `write: true` silently accepted
      // every call. The operator saw "authority: OBSERVER" in their
      // config and assumed enforcement; the runtime accepted
      // everything. The fix throws at prehook time so the operator
      // gets a loud signal that their config is incomplete.
      const tool = {
        name: 'plain',
        steering: { authority: 'OBSERVER' }, // no write:true
      };
      assert.throws(
        () => runPrehook(tool, {}),
        (err) => err.message.includes('requires write classification') ||
                 err.message.includes('write:true'),
      );
    });
  });
});

describe('steering/memory', () => {
  describe('AgenticMemory.write', () => {
    it('dispatches a classified write to the write tool', async () => {
      const calls = [];
      const dispatch = async (toolName, args) => {
        calls.push({ toolName, args });
        return { ok: true };
      };
      const mem = new AgenticMemory({ dispatch, authority: 'RESEARCHER' });
      const r = await mem.write({
        agent_id: 'a1',
        content: 'x',
        memory_type: 'observation',
        confidence: 0.8,
        importance: 0.4,
      });
      assert.deepEqual(r, { ok: true });
      assert.equal(calls.length, 1);
      assert.equal(calls[0].toolName, 'memory_write');
      assert.equal(calls[0].args.memory_type, 'observation');
    });

    it('rejects a write that violates the bound authority', async () => {
      const dispatch = async () => ({ ok: true });
      const mem = new AgenticMemory({ dispatch, authority: 'OBSERVER' });
      await assert.rejects(
        () => mem.write({
          content: 'x',
          memory_type: 'correction',
          confidence: 1,
          importance: 1,
        }),
        (err) => err.message.includes('AgenticMemory.write') && err.message.includes('correction'),
      );
    });

    it('rejects a write with missing classification fields', async () => {
      const dispatch = async () => ({ ok: true });
      const mem = new AgenticMemory({ dispatch });
      await assert.rejects(
        () => mem.write({ content: 'x', confidence: 0.5, importance: 0.5 }),
        (err) => err.message.includes('memory_type'),
      );
    });

    it('defaults to READONLY when no authority is bound (secure-by-default)', async () => {
      // an unbound authority defaults to READONLY (deny all writes),
      // not null (unrestricted). Callers who truly want unrestricted writes must
      // pass `authority: 'ROOT'` explicitly.
      const dispatch = async () => ({ ok: true });
      const mem = new AgenticMemory({ dispatch });
      await assert.rejects(
        () => mem.write({
          content: 'x',
          memory_type: 'correction',
          confidence: 1,
          importance: 1,
        }),
        (err) => err.message.includes('AgenticMemory.write') && err.message.includes('READONLY'),
      );
    });

    it('permits write only when authority is explicitly elevated to ROOT', async () => {
      const calls = [];
      const dispatch = async (toolName, args) => { calls.push(args); return { ok: true }; };
      const mem = new AgenticMemory({ dispatch, authority: 'ROOT' });
      await mem.write({
        content: 'x',
        memory_type: 'correction',
        confidence: 1,
        importance: 1,
      });
      assert.equal(calls.length, 1);
    });
  });

  describe('AgenticMemory.release', () => {
    it('dispatches release with handle_id and outcome', async () => {
      const calls = [];
      const dispatch = async (toolName, args) => { calls.push({ toolName, args }); return { ok: true }; };
      const mem = new AgenticMemory({ dispatch });
      await mem.release({ handle_id: 'h-1', outcome: 'persisted' });
      assert.equal(calls[0].toolName, 'mem_release');
      assert.equal(calls[0].args.handle_id, 'h-1');
      assert.equal(calls[0].args.outcome, 'persisted');
    });

    it('rejects an invalid outcome', async () => {
      const mem = new AgenticMemory({ dispatch: async () => ({}) });
      await assert.rejects(
        () => mem.release({ handle_id: 'h-1', outcome: 'done' }),
        (err) => err.message.includes('outcome must be one of'),
      );
    });

    it('requires handle_id', async () => {
      const mem = new AgenticMemory({ dispatch: async () => ({}) });
      await assert.rejects(
        () => mem.release({ outcome: 'persisted' }),
        (err) => err.message.includes('handle_id is required'),
      );
    });
  });

  describe('createAgenticMemory', () => {
    it('returns an AgenticMemory instance', () => {
      const mem = createAgenticMemory({ dispatch: async () => ({}) });
      assert(mem instanceof AgenticMemory);
    });

    it('throws when dispatch is missing', () => {
      assert.throws(
        () => new AgenticMemory({}),
        (err) => err.message.includes('dispatch'),
      );
    });
  });

  it('RELEASE_OUTCOMES is the frozen canonical set', () => {
    assert(Object.isFrozen(RELEASE_OUTCOMES));
    assert.deepEqual([...RELEASE_OUTCOMES], ['persisted', 'discarded', 'escalated']);
  });
});
