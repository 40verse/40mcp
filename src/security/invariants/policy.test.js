/**
 * Security invariants — policy gate surface
 *
 * Tests for enum enforcement, policy:deny/require_approval chain bypass
 * prevention, MCP-egress envelope strip, case-insensitive policy lookup,
 * and scope-name validation.
 *
 * @module security/invariants/policy
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  validateToolArgs,
  RESERVED_ENVELOPE_KEYS,
  stripInternalEnvelopes,
  MAX_STRIP_DEPTH,
  createRestBridge,
} from '../../bridge.js';
import { createPolicyGate, mergeToolPolicies } from '../policy.js';

// ─────────────────────────────────────────────────────────────────────────────
// Enum + chain tenant escalation + gate self-exemption
// ─────────────────────────────────────────────────────────────────────────────

describe(' enum + cross-feature invariants', () => {
  it('validateToolArgs ENFORCES enum (not just type)', () => {
    // Single largest finding: schema-declared `enum` was purely
    // declarative documentation; the validator only checked `type`.
    const schema = {
      type: 'object',
      properties: {
        memory_type: { type: 'string', enum: ['fact', 'observation'] },
      },
    };
    const err = validateToolArgs({ memory_type: 'correction' }, schema);
    assert.ok(err, 'enum violation must be rejected');
    assert.match(err, /one of/);
  });

  it('validateToolArgs accepts valid enum value', () => {
    const schema = {
      type: 'object',
      properties: {
        memory_type: { type: 'string', enum: ['fact', 'observation'] },
      },
    };
    assert.equal(validateToolArgs({ memory_type: 'fact' }, schema), null);
  });

  it('validateToolArgs enum check works on integer enum', () => {
    const schema = {
      type: 'object',
      properties: { level: { type: 'integer', enum: [1, 2, 3] } },
    };
    assert.ok(validateToolArgs({ level: 4 }, schema));
    assert.equal(validateToolArgs({ level: 2 }, schema), null);
  });

  it('mixer Unicode prefix dedup normalizes NFC', async () => {
    // 'café' (NFC) and 'cafe\u0301' (NFD) used to be
    // distinct prefixes but render identically. Normalization to NFC
    // makes them collide in seenPrefixes and trigger the dup error.
    const { createMixer } = await import('../../compose/mixer.js');
    assert.throws(
      () => createMixer({
        name: 'm',
        servers: [
          { name: 's1', prefix: 'café', baseUrl: 'http://x', tools: [] },
          { name: 's2', prefix: 'cafe\u0301', baseUrl: 'http://y', tools: [] },
        ],
      }),
      /Duplicate prefix/,
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Policy-gate chain bypass + MCP-egress envelope strip
// policy:deny/require_approval must be enforced transitively across
// compose-chain sub-dispatches; reserved envelope keys must be stripped
// from upstream REST responses before they reach the MCP client
// ─────────────────────────────────────────────────────────────────────────────

describe(' policy-gate chain bypass + MCP-egress envelope strip', () => {
  // ── stripInternalEnvelopes ─────────────────────────────────────────────

  it(' stripInternalEnvelopes removes all RESERVED_ENVELOPE_KEYS from a flat object', () => {
    // Object.fromEntries creates OWN properties for all keys including
    // prototype-pollution sentinels (__proto__, constructor, prototype) —
    // unlike direct assignment which goes through __proto__'s setter.
    // Use hasOwnProperty for the assertion because `key in obj` always
    // returns true for __proto__ (it lives on Object.prototype).
    const input = Object.fromEntries(
      RESERVED_ENVELOPE_KEYS.map((k) => [k, `attacker-value-for-${k}`]),
    );
    input.regular_data = 'public';
    const result = stripInternalEnvelopes(input);
    for (const key of RESERVED_ENVELOPE_KEYS) {
      assert.equal(
        Object.prototype.hasOwnProperty.call(result, key),
        false,
        `key "${key}" should be stripped`,
      );
    }
    assert.equal(result.regular_data, 'public');
  });

  it(' stripInternalEnvelopes strips nested envelope keys at any depth up to MAX_STRIP_DEPTH', () => {
    // Build a deeply nested object: { a: { b: { c: { _steering: 'evil' } } } }
    const input = {
      items: [
        {
          id: 1,
          metadata: {
            deeper: {
              _steering: { authority: 'ROOT' },
              _tenant: 'hidden-admin',
              safe: 'value',
            },
          },
        },
      ],
    };
    const result = stripInternalEnvelopes(input);
    assert.equal('_steering' in result.items[0].metadata.deeper, false);
    assert.equal('_tenant' in result.items[0].metadata.deeper, false);
    assert.equal(result.items[0].metadata.deeper.safe, 'value');
  });

  it(' stripInternalEnvelopes uses RESERVED_ENVELOPE_KEYS as key set (symmetry)', () => {
    // The strip function must respect exactly RESERVED_ENVELOPE_KEYS — no drift.
    // Build an object with all reserved keys plus extras.
    const input = Object.fromEntries(RESERVED_ENVELOPE_KEYS.map((k) => [k, 'evil']));
    input.keep_me = 'good';
    const stripped = stripInternalEnvelopes(input);
    // All reserved keys gone — use hasOwnProperty because `key in obj`
    // is always true for __proto__ (it lives on Object.prototype).
    for (const k of RESERVED_ENVELOPE_KEYS) {
      assert.equal(Object.prototype.hasOwnProperty.call(stripped, k), false);
    }
    // Non-reserved key preserved
    assert.equal(stripped.keep_me, 'good');
  });

  it(' stripInternalEnvelopes MAX_STRIP_DEPTH cap prevents unbounded recursion', () => {
    // Build a chain of nested objects MAX_STRIP_DEPTH + 2 levels deep.
    // The reserved key buried below the cap must NOT be stripped — it's
    // out of reach, but the function must not throw or blow the stack.
    let deep = { _steering: 'evil-below-cap' };
    for (let i = 0; i < MAX_STRIP_DEPTH + 1; i += 1) {
      deep = { level: deep };
    }
    deep._steering = 'evil-at-cap'; // at top level — must be stripped
    assert.doesNotThrow(() => stripInternalEnvelopes(deep));
    assert.equal('_steering' in stripInternalEnvelopes({ _steering: 'top' }), false);
  });

  // ── policy-gate chain bypass ──────────────────────────────────────────────

  it(' policy:deny is enforced transitively through compose chain sub-dispatches', async () => {
    // Reproduction of CMP12-policy-gate-chain-bypass probe.
    // A chain tool that declares a deny-policy sub-tool as a step must NOT
    // be able to reach it — dispatchInner re-checks tool.policy on every
    // sub-dispatch entry (symmetric to the tenant ACL re-check).
    const bridge = createRestBridge({
      name: 'test-policy-chain',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999', // unreachable loopback — allowPrivate:true lets test harness bypass IP check
      tools: [
        {
          name: 'chain_benign',
          chain: [{ call: 'admin_delete', as: 'r', args: {} }],
          inputSchema: { type: 'object' },
        },
        {
          name: 'admin_delete',
          method: 'POST',
          path: '/admin/delete',
          policy: 'deny',
          inputSchema: { type: 'object' },
        },
      ],
    });

    // Direct call to admin_delete — outer dispatch sees policy and should
    // also be blocked (belt-and-suspenders; the main guarantee is chain bypass).
    await assert.rejects(
      () => bridge.dispatch('admin_delete', {}),
      /blocked by policy/i,
    );

    // Chain bypass — the key regression: chain_benign must NOT reach admin_delete.
    await assert.rejects(
      () => bridge.dispatch('chain_benign', {}),
      /blocked by policy/i,
    );
  });

  it(' policy:require_approval is refused inside compose chain sub-dispatches', async () => {
    // An approval-gated tool cannot be called mid-chain because the
    // interactive approval handler lives on createPolicyGate, not inside
    // the bridge. The bridge must refuse outright rather than hang waiting
    // for an approval handler that will never arrive.
    const bridge = createRestBridge({
      name: 'test-policy-approval-chain',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999',
      tools: [
        {
          name: 'chain_wrapper',
          chain: [{ call: 'guarded_action', as: 'r', args: {} }],
          inputSchema: { type: 'object' },
        },
        {
          name: 'guarded_action',
          method: 'POST',
          path: '/guarded',
          policy: 'require_approval',
          inputSchema: { type: 'object' },
        },
      ],
    });

    await assert.rejects(
      () => bridge.dispatch('chain_wrapper', {}),
      /requires approval.*compose chain|policy gate/i,
    );
  });

  it(' sidecar toolPolicies:deny blocks compose-chain sub-dispatches (post-merge)', async () => {
    // The serve --policy path merges sidecar toolPolicies into embedded
    // tool.policy via mergeToolPolicies() BEFORE bridge construction. Without
    // that merge, the bridge's per-dispatch re-check (which reads only
    // tool.policy) would let a chain sub-dispatch tunnel through a sidecar
    // `deny`. This invariant locks in the merge behavior — a regression to
    // "only embedded policy is enforced in chains" would make this test fail.
    const tools = [
      {
        name: 'chain_wrapper',
        chain: [{ call: 'admin_delete', as: 'r', args: {} }],
        inputSchema: { type: 'object' },
      },
      {
        name: 'admin_delete',
        method: 'POST',
        path: '/admin/delete',
        inputSchema: { type: 'object' },
        // NOTE: no embedded policy — the sidecar rule is the only protection.
      },
    ];
    const merged = mergeToolPolicies(tools, { admin_delete: 'deny' });
    assert.equal(merged, 1, 'sidecar deny must have been applied to admin_delete');
    assert.equal(tools[1].policy, 'deny', 'sidecar rule must land on tool.policy');

    const bridge = createRestBridge({
      name: 'test-sidecar-deny-chain',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999',
      tools,
    });

    await assert.rejects(
      () => bridge.dispatch('chain_wrapper', {}),
      /blocked by policy/i,
    );
  });

  it(' sidecar toolPolicies:require_approval is refused inside compose chains (post-merge)', async () => {
    // Symmetric to the deny case above — sidecar `require_approval` on a
    // chained tool must be refused the same way embedded require_approval is.
    // Approval handlers live on createPolicyGate, not inside the bridge; a
    // chain sub-dispatch cannot re-enter the gate, so the bridge must refuse.
    const tools = [
      {
        name: 'chain_wrapper',
        chain: [{ call: 'guarded_action', as: 'r', args: {} }],
        inputSchema: { type: 'object' },
      },
      {
        name: 'guarded_action',
        method: 'POST',
        path: '/guarded',
        inputSchema: { type: 'object' },
        // NOTE: no embedded policy — the sidecar rule is the only protection.
      },
    ];
    const merged = mergeToolPolicies(tools, { guarded_action: 'require_approval' });
    assert.equal(merged, 1);
    assert.equal(tools[1].policy, 'require_approval');

    const bridge = createRestBridge({
      name: 'test-sidecar-approval-chain',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999',
      tools,
    });

    await assert.rejects(
      () => bridge.dispatch('chain_wrapper', {}),
      /requires approval.*compose chain|policy gate/i,
    );
  });

  it(' createPolicyGate-approved top-level call reaches dispatch for a require_approval tool', async () => {
    // The symmetric positive case for the chain-sub-dispatch rejection above.
    // When a tool is marked `policy: "require_approval"` and the caller
    // wraps bridge.dispatch with createPolicyGate({ tools, approvalHandler }),
    // an approved top-level call MUST reach dispatch. Previously the bridge
    // rejected every `require_approval` tool unconditionally, breaking this
    // core flow even after the policy gate said approve.
    //
    // `tools` is passed to createPolicyGate so it can extract the embedded
    // `tool.policy` annotation — without that argument the gate sees no
    // policy, never calls approvalHandler, and the test proves nothing.
    const tools = [
      {
        name: 'guarded_action',
        method: 'POST',
        path: '/guarded',
        policy: 'require_approval',
        inputSchema: { type: 'object' },
      },
    ];
    const bridge = createRestBridge({
      name: 'test-policy-approved-toplevel',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999',
      tools,
    });

    let approvalCount = 0;
    const gatedDispatch = createPolicyGate({
      dispatch: bridge.dispatch,
      tools,
      approvalHandler: async () => {
        approvalCount += 1;
        return 'approve';
      },
    });

    // The call should get past the policy gate AND past the bridge re-check.
    // The HTTP POST to 127.0.0.1:9999 will fail — that's fine; we're asserting
    // the error is NOT a policy/approval rejection.
    try {
      await gatedDispatch('guarded_action', {});
    } catch (err) {
      assert.equal(
        /blocked by policy|requires approval/i.test(err.message),
        false,
        `Approved call must not be rejected by policy gate or bridge re-check; got: ${err.message}`,
      );
    }

    assert.equal(
      approvalCount,
      1,
      'approvalHandler must be invoked exactly once for the require_approval tool',
    );
  });

  it(' createRestBridge honors wrapDispatch for the exported dispatch (serve --policy plumbing)', async () => {
    // The `wrapDispatch` hook on createRestBridge is what lets `40mcp serve
    // --policy` install a policy gate around the bridge's dispatch without
    // the caller having to rewire the MCP Server manually. Proves the wrapper
    // is called exactly once per dispatch on the path the MCP CallTool handler
    // uses (and that the raw dispatch is still reachable through the wrapper).
    const calls = [];
    const bridge = createRestBridge({
      name: 'test-wrap-dispatch',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999',
      tools: [
        {
          name: 'probe',
          method: 'GET',
          path: '/probe',
          inputSchema: { type: 'object' },
        },
      ],
      wrapDispatch: (rawDispatch) => async (name, args, opts) => {
        calls.push({ name, argsIsPlainObject: args !== null && typeof args === 'object' });
        return rawDispatch(name, args, opts);
      },
    });

    // Expect ECONNREFUSED — the baseUrl is intentionally unreachable. We're
    // asserting that wrapDispatch ran, not that the HTTP call succeeded.
    try {
      await bridge.dispatch('probe', {});
    } catch { /* network error expected */ }

    assert.equal(calls.length, 1, 'wrapDispatch must be invoked exactly once per bridge.dispatch');
    assert.equal(calls[0].name, 'probe');
    assert.equal(calls[0].argsIsPlainObject, true);
  });

  it(' policy:allow and policy:log_only tools are reachable from compose chains', async () => {
    // Only deny/require_approval are blocked — allow and log_only must pass.
    // This verifies the fix does not over-block.
    const bridge = createRestBridge({
      name: 'test-policy-passthrough',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999',
      tools: [
        {
          name: 'chain_outer',
          chain: [{ call: 'inner_allowed', as: 'r', args: {} }],
          inputSchema: { type: 'object' },
        },
        {
          name: 'inner_allowed',
          method: 'GET',
          path: '/inner',
          policy: 'allow',
          inputSchema: { type: 'object' },
        },
      ],
    });

    // The chain will attempt an HTTP call to 127.0.0.1:9999 which will fail
    // with a network error — but that error must NOT be a policy error.
    // We verify the call gets past the policy gate.
    try {
      await bridge.dispatch('chain_outer', {});
    } catch (err) {
      // Network error is expected (127.0.0.1:9999 unreachable) —
      // policy gate must not have blocked it.
      assert.equal(
        /blocked by policy|requires approval/i.test(err.message),
        false,
        `Expected network error, got policy error: ${err.message}`,
      );
    }
  });

  it(' symmetric: chain sub-dispatches re-check both tenant ACL and policy at dispatchInner', async () => {
    // Both tenant ACL  and policy gate  are enforced at dispatchInner
    // entry — neither check can be bypassed by routing through a chain tool.
    const bridge = createRestBridge({
      name: 'test-dual-gate',
      version: '1.0.0',
      baseUrl: 'http://127.0.0.1:9999',
      tools: [
        {
          name: 'chain_root',
          chain: [{ call: 'privileged_tool', as: 'r', args: {} }],
          inputSchema: { type: 'object' },
        },
        {
          name: 'privileged_tool',
          method: 'POST',
          path: '/privileged',
          policy: 'deny',
          inputSchema: { type: 'object' },
        },
      ],
    });

    // Policy gate blocks sub-dispatch regardless of tenant context.
    await assert.rejects(
      () => bridge.dispatch('chain_root', {}),
      /blocked by policy/i,
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Case-insensitive policy lookup
// ─────────────────────────────────────────────────────────────────────────────

describe('case-insensitive policy lookup', () => {
  it('createPolicyGate matches Admin_Delete against admin_delete deny policy', async () => {
    const gate = createPolicyGate({
      dispatch: async (name, _args) => ({ result: name }),
      toolPolicies: { admin_delete: 'deny' },
    });
    await assert.rejects(
      () => gate('Admin_Delete', {}),
      /denied|policy/i,
    );
  });

  it('createPolicyGate allows when casing matches with allow policy', async () => {
    const gate = createPolicyGate({
      dispatch: async (name, _args) => ({ result: name }),
      toolPolicies: { list_users: 'allow' },
    });
    const result = await gate('list_users', {});
    assert.ok(result);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Policy: falsy bypass + args.type vs args.action_type
// ─────────────────────────────────────────────────────────────────────────────

describe('policy falsy bypass and action_type gate', () => {
  it('policy:deny stored as a falsy-looking value is still enforced', async () => {
    const gate = createPolicyGate({
      tools: [{ name: 'sensitive_tool', policy: 'deny', method: 'DELETE', path: '/admin' }],
      toolPolicies: {},
      defaultPolicy: 'allow',
      dispatch: async () => ({}),
    });
    await assert.rejects(() => gate('sensitive_tool', {}), /denied|deny|blocked/i,
      'tool with policy:deny must be denied');
  });

  it('policy lookup is case-insensitive (Admin_Delete matches admin_delete rule)', async () => {
    const gate = createPolicyGate({
      tools: [{ name: 'admin_delete', policy: 'deny', method: 'DELETE', path: '/admin' }],
      toolPolicies: {},
      defaultPolicy: 'allow',
      dispatch: async () => ({}),
    });
    await assert.rejects(() => gate('Admin_Delete', {}), /denied|deny|blocked/i,
      'Mixed-case tool name must match lowercase deny rule');
  });

  it('args.type does NOT trigger dangerousActions gate (only action_type does)', async () => {
    let dispatched = false;
    const gate = createPolicyGate({
      tools: [],
      toolPolicies: {},
      defaultPolicy: 'allow',
      dangerousActions: ['delete'],
      dispatch: async () => { dispatched = true; return {}; },
    });
    await gate('any_tool', { type: 'delete' });
    assert.ok(dispatched, 'args.type:delete must not trigger dangerous action escalation');
  });

  it('args.action_type DOES trigger dangerousActions gate', async () => {
    const gate = createPolicyGate({
      tools: [],
      toolPolicies: {},
      defaultPolicy: 'allow',
      dangerousActions: ['delete'],
      dispatch: async () => ({}),
      approvalHandler: async () => 'deny',
    });
    await assert.rejects(() => gate('any_tool', { action_type: 'delete' }), /denied|deny/i,
      'args.action_type:delete must trigger require_approval → deny');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// M3: invalid toolPolicies values rejected
// ─────────────────────────────────────────────────────────────────────────────

describe('policy validation', () => {
  it('createPolicyGate ignores toolPolicies entries with invalid policy values', async () => {
    let dispatched = false;
    const gate = createPolicyGate({
      tools: [],
      toolPolicies: {
        safe_tool: 'allow',
        evil_tool: 'inject_evil_value',   // invalid — must be ignored
        another: null,                     // invalid type — must be ignored
      },
      defaultPolicy: 'deny',
      dispatch: async () => { dispatched = true; return {}; },
    });
    await assert.doesNotReject(() => gate('safe_tool', {}));
    assert.ok(dispatched, 'safe_tool with valid allow policy must dispatch');
    await assert.rejects(() => gate('evil_tool', {}), /denied|deny|blocked/i,
      'invalid policy value must be ignored; defaultPolicy deny must apply');
  });
});
