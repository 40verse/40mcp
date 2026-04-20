/**
 * Policy × Tenant composition — covers the SPEC §5 policy-gate × tenant criterion:
 *
 *   "A single end-to-end integration test proving tenant-scoped approval
 *    decisions remain correct through composition (e.g. Tenant A auto-approve,
 *    Tenant B require_approval on the same tool)."
 *
 * Stack under test (outer → inner):
 *   createTenantScope → router-by-tenantId → createPolicyGate(A|B) → fakeBridge
 *
 * This test uses a router-by-tenant pattern to prove ONE realistic composition
 * shape for per-tenant policy: each tenant owns its own `createPolicyGate`
 * instance with its own `toolPolicies` and `approvalHandler`, and a thin router
 * forwards to the correct gate based on the tenant envelope that
 * `createTenantScope` stamps onto `args._tenant`. It is a sufficient proof of
 * the criterion, not a normative architecture — other compositions (e.g. a
 * single gate with a tenant-aware `policyResolver`) are equally valid.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createPolicyGate } from '../src/security/policy.js';
import { createTenantScope } from '../src/tenant/scope.js';
import { BridgeErrorCode } from '../src/errors.js';

function silentLogger() {
  return () => {};
}

function buildStack({
  onTenantAApproval,
  onTenantBApproval,
  tenantAPolicy = 'allow',
  tenantBPolicy = 'require_approval',
} = {}) {
  const bridgeCalls = [];
  const fakeBridge = async (toolName, args) => {
    bridgeCalls.push({
      tool: toolName,
      tenantId: args._tenant?.tenantId ?? null,
      args: Object.fromEntries(Object.entries(args).filter(([k]) => k !== '_tenant')),
    });
    return { ok: true, tool: toolName };
  };

  const tenantAGate = createPolicyGate({
    dispatch: fakeBridge,
    toolPolicies: { delete_record: tenantAPolicy },
    approvalHandler: onTenantAApproval,
    logger: silentLogger(),
  });

  const tenantBGate = createPolicyGate({
    dispatch: fakeBridge,
    toolPolicies: { delete_record: tenantBPolicy },
    approvalHandler: onTenantBApproval,
    logger: silentLogger(),
  });

  const routerCalls = [];
  const router = async (toolName, args, chainOptions) => {
    const tenantId = args._tenant?.tenantId;
    routerCalls.push({ tool: toolName, tenantId });
    if (tenantId === 'tenant-a') return tenantAGate(toolName, args, chainOptions);
    if (tenantId === 'tenant-b') return tenantBGate(toolName, args, chainOptions);
    throw new Error(`Unknown tenant: ${tenantId}`);
  };

  const scoped = createTenantScope({
    dispatch: router,
    resolveContext: async (meta) => meta,
  });

  return { scoped, bridgeCalls, routerCalls };
}

describe('policy × tenant composition — SPEC §5 policy-gate × tenant criterion', () => {
  it('Tenant A auto-approves, Tenant B requires (and receives) approval on the SAME tool', async () => {
    const approvalLog = [];
    const { scoped, bridgeCalls } = buildStack({
      onTenantBApproval: async (ctx) => {
        approvalLog.push({ tool: ctx.tool, tenantId: ctx.args._tenant?.tenantId });
        return 'approve';
      },
    });

    const resultA = await scoped(
      'delete_record',
      { id: 1 },
      { tenantId: 'tenant-a', allowlist: ['delete_record'] },
    );
    const resultB = await scoped(
      'delete_record',
      { id: 2 },
      { tenantId: 'tenant-b', allowlist: ['delete_record'] },
    );

    assert.deepEqual(resultA, { ok: true, tool: 'delete_record' });
    assert.deepEqual(resultB, { ok: true, tool: 'delete_record' });
    assert.equal(approvalLog.length, 1, 'approvalHandler must fire exactly once — only for Tenant B');
    assert.equal(approvalLog[0].tenantId, 'tenant-b');
    assert.equal(bridgeCalls.length, 2, 'both calls must reach the bridge after approval');
    assert.deepEqual(
      bridgeCalls.map((c) => c.tenantId),
      ['tenant-a', 'tenant-b'],
    );
  });

  it('Tenant B denial short-circuits with POLICY_DENIED and the bridge is never called', async () => {
    const { scoped, bridgeCalls } = buildStack({
      onTenantBApproval: async () => 'deny',
    });

    await assert.rejects(
      scoped(
        'delete_record',
        { id: 99 },
        { tenantId: 'tenant-b', allowlist: ['delete_record'] },
      ),
      (err) => {
        assert.equal(err.bridgeCode, BridgeErrorCode.POLICY_DENIED);
        return true;
      },
    );
    assert.equal(bridgeCalls.length, 0, 'denied approval must not reach the downstream bridge');
  });

  it('Tenant allowlist fires BEFORE the policy gate — disallowed tool never triggers approval', async () => {
    let policyObserved = false;
    const onTenantBApproval = async () => {
      policyObserved = true;
      return 'approve';
    };

    const { scoped, bridgeCalls, routerCalls } = buildStack({ onTenantBApproval });

    await assert.rejects(
      scoped(
        'admin_tool',
        {},
        { tenantId: 'tenant-b', allowlist: ['delete_record'] },
      ),
      /not in tenant "tenant-b" allowlist/,
    );
    assert.equal(
      policyObserved,
      false,
      'policy approval handler must not observe calls that tenant allowlist already rejected',
    );
    assert.equal(routerCalls.length, 0, 'router (and therefore gate) must not be invoked');
    assert.equal(bridgeCalls.length, 0);
  });

  it('concurrent cross-tenant approvals do not leak tenantId or auth across calls', async () => {
    // Compose per-tenant gates whose approval handlers stash the full context,
    // then drive both tenants concurrently and confirm each handler only ever
    // sees its own tenant's metadata.
    const seenA = [];
    const seenB = [];
    const { scoped, bridgeCalls } = buildStack({
      tenantAPolicy: 'require_approval',
      tenantBPolicy: 'require_approval',
      onTenantAApproval: async (ctx) => {
        // Introduce a microtask so schedules actually interleave.
        await new Promise((r) => setImmediate(r));
        seenA.push(ctx.args._tenant?.tenantId);
        return 'approve';
      },
      onTenantBApproval: async (ctx) => {
        await new Promise((r) => setImmediate(r));
        seenB.push(ctx.args._tenant?.tenantId);
        return 'approve';
      },
    });

    const calls = [];
    for (let i = 0; i < 8; i += 1) {
      calls.push(
        scoped(
          'delete_record',
          { id: i },
          { tenantId: 'tenant-a', allowlist: ['delete_record'] },
        ),
      );
      calls.push(
        scoped(
          'delete_record',
          { id: i },
          { tenantId: 'tenant-b', allowlist: ['delete_record'] },
        ),
      );
    }
    await Promise.all(calls);

    assert.equal(seenA.length, 8);
    assert.equal(seenB.length, 8);
    assert.ok(seenA.every((t) => t === 'tenant-a'), 'Tenant A handler saw foreign tenantId');
    assert.ok(seenB.every((t) => t === 'tenant-b'), 'Tenant B handler saw foreign tenantId');
    assert.equal(bridgeCalls.length, 16);
  });
});
