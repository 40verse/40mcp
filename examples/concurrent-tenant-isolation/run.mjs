#!/usr/bin/env node
/**
 * concurrent-tenant-isolation — proves 40mcp can serve two tenants
 * with DIFFERENT approval requirements on the SAME tool surface,
 * under concurrent load, with zero auth bleed.
 *
 * Topology:
 *
 *   Tenant A (auto-approve)         Tenant B (require_approval)
 *          │                                  │
 *          └──────┬───────────────────────────┘
 *                 │
 *                 ▼
 *           createPolicyGate
 *                 │
 *                 ▼
 *           createTenantScope
 *                 │
 *                 ▼
 *           bridge dispatch  ──▶  upstream
 *
 * Both tenants invoke the same `read_data` and `mutate_data` tools.
 * - Tenant A's policy: both tools 'allow'.
 * - Tenant B's policy: read 'allow', mutate 'require_approval'.
 *
 * The approval handler is interactive in production; here it's a
 * deterministic stub that records every approval request so the test
 * can verify which tenant triggered which approval.
 *
 * The demo fires N concurrent calls per tenant (mixed read/mutate),
 * collects per-tenant audit trails, and asserts:
 *   1. Tenant A's mutate calls succeed without approval (policy=allow).
 *   2. Tenant B's mutate calls trigger the approval handler.
 *   3. Every approval handler invocation is attributed to tenant B.
 *   4. No tenant ever observes the other's auth context (zero bleed).
 *   5. Concurrent load (50 calls × 2 tenants) preserves all of the above.
 */

import { performance } from 'node:perf_hooks';
import { writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createTenantScope } from '../../src/tenant/scope.js';
import { createPolicyGate } from '../../src/security/policy.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(__dirname, 'results');

const N = 50; // concurrent calls per tenant per tool

// ─── Topology ──────────────────────────────────────────────────────────

// Backend dispatch records who called it and what was asked.
const audit = []; // { tenantId, tool, ok }
const baseDispatch = async (name, args) => {
  // The non-enumerable _tenant envelope is set by createTenantScope.
  // If the isolation is broken, this would observe the wrong tenantId.
  const tenantId = args?._tenant?.tenantId || 'NONE';
  audit.push({ tenantId, tool: name, ok: true });
  // Simulate a tiny async hop to maximize interleaving.
  await new Promise((r) => setImmediate(r));
  return { result: `${name} executed for ${tenantId}` };
};

// Approval handler — records every request, auto-approves for tenant B.
// In production this would prompt a human; here it's deterministic so
// the test can verify call attribution.
const approvalRequests = []; // { tool, tenantHint, decision }
const approvalHandler = async (ctx) => {
  // ctx has { tool, args, method, path, ... }. _tenant is non-enumerable
  // on args — read it via direct property access (the tenant-scope
  // pattern from chain.js).
  const tenantId = ctx.args?._tenant?.tenantId || 'NONE';
  approvalRequests.push({ tool: ctx.tool, tenantId, decision: 'approve' });
  return 'approve';
};

// One policy gate, two tenants, different per-tool policies. The gate
// resolves policy by tool NAME, not by tenant — but since each tenant
// scopes its OWN gate, we get per-tenant policy by composition.
function buildScopedDispatch(tenantId, toolPolicies) {
  const gated = createPolicyGate({
    dispatch: baseDispatch,
    toolPolicies,
    approvalHandler,
  });
  return createTenantScope({
    dispatch: gated,
    resolveContext: async () => ({
      tenantId,
      auth: { type: 'bearer', value: `${tenantId}-token` },
    }),
  });
}

// Tenant A: both tools allowed, zero approvals expected.
const dispatchA = buildScopedDispatch('tenant-A', {
  read_data: 'allow',
  mutate_data: 'allow',
});

// Tenant B: read allowed, mutate requires approval.
const dispatchB = buildScopedDispatch('tenant-B', {
  read_data: 'allow',
  mutate_data: 'require_approval',
});

// ─── Workload ──────────────────────────────────────────────────────────

async function runWorkload() {
  const t0 = performance.now();

  // Build the call list: N reads + N mutates for each tenant = 4N total.
  // Interleave so the event loop sees A,B,A,B,... maximizing the chance
  // of context bleed if any leak primitive exists.
  const calls = [];
  for (let i = 0; i < N; i += 1) {
    calls.push(['A', 'read_data', dispatchA, i]);
    calls.push(['B', 'read_data', dispatchB, i]);
    calls.push(['A', 'mutate_data', dispatchA, i]);
    calls.push(['B', 'mutate_data', dispatchB, i]);
  }

  const settled = await Promise.all(
    calls.map(async ([who, tool, dispatch, i]) => {
      try {
        const result = await dispatch(tool, { iter: i }, {});
        return { who, tool, ok: true, result };
      } catch (err) {
        return { who, tool, ok: false, err: err.message };
      }
    }),
  );

  const wallMs = Math.round(performance.now() - t0);
  return { wallMs, settled };
}

// ─── Verification ──────────────────────────────────────────────────────

function verify({ wallMs, settled }) {
  const checks = [];

  // 1. Every dispatch reached the backend with the CORRECT tenantId.
  //    audit[].tenantId must match the originating call's "who".
  //    We can't directly tag — but we can count and verify expectations.
  const auditByTenant = audit.reduce((acc, a) => {
    acc[a.tenantId] = (acc[a.tenantId] || 0) + 1;
    return acc;
  }, {});
  // Expected: each tenant fires 2N calls (N read + N mutate).
  const expected = 2 * N;
  checks.push({
    id: 'C1-tenant-A-call-count',
    pass: auditByTenant['tenant-A'] === expected,
    detail: `tenant-A backend hits: ${auditByTenant['tenant-A']} (expected ${expected})`,
  });
  checks.push({
    id: 'C2-tenant-B-call-count',
    pass: auditByTenant['tenant-B'] === expected,
    detail: `tenant-B backend hits: ${auditByTenant['tenant-B']} (expected ${expected})`,
  });
  // No spurious tenant identities should appear in the audit.
  const wrongTenants = Object.keys(auditByTenant).filter(
    (k) => k !== 'tenant-A' && k !== 'tenant-B',
  );
  checks.push({
    id: 'C3-no-bleed-tenant-id',
    pass: wrongTenants.length === 0,
    detail: wrongTenants.length === 0
      ? 'no spurious tenant IDs observed at backend'
      : `BLEED: observed unexpected tenants ${JSON.stringify(wrongTenants)}`,
  });

  // 2. Tenant A's mutate calls did NOT trigger approval handler.
  const aApprovals = approvalRequests.filter((r) => r.tenantId === 'tenant-A').length;
  checks.push({
    id: 'C4-tenant-A-no-approvals',
    pass: aApprovals === 0,
    detail: `tenant-A approval handler invocations: ${aApprovals} (expected 0)`,
  });

  // 3. Tenant B's mutate calls triggered the approval handler exactly N times.
  const bApprovals = approvalRequests.filter((r) => r.tenantId === 'tenant-B' && r.tool === 'mutate_data').length;
  checks.push({
    id: 'C5-tenant-B-mutate-approval-count',
    pass: bApprovals === N,
    detail: `tenant-B mutate approval requests: ${bApprovals} (expected ${N})`,
  });

  // 4. Tenant B's read calls did NOT trigger approval (read is 'allow').
  const bReadApprovals = approvalRequests.filter((r) => r.tenantId === 'tenant-B' && r.tool === 'read_data').length;
  checks.push({
    id: 'C6-tenant-B-read-no-approval',
    pass: bReadApprovals === 0,
    detail: `tenant-B read approval requests: ${bReadApprovals} (expected 0)`,
  });

  // 5. No call result contains the OTHER tenant's identifier.
  //    Result text is `<tool> executed for <tenantId>` — A's results
  //    must say "for tenant-A", B's must say "for tenant-B".
  let crossLeak = 0;
  for (const s of settled) {
    if (!s.ok) continue;
    const expectedTag = `for tenant-${s.who}`;
    if (!s.result.result.includes(expectedTag)) crossLeak += 1;
  }
  checks.push({
    id: 'C7-no-cross-tenant-result-leak',
    pass: crossLeak === 0,
    detail: crossLeak === 0
      ? `${settled.length} settled calls, every result tagged with originating tenant`
      : `LEAK: ${crossLeak} results contain wrong tenant tag`,
  });

  // 6. All calls completed (no errors).
  const failed = settled.filter((s) => !s.ok);
  checks.push({
    id: 'C8-no-dispatch-errors',
    pass: failed.length === 0,
    detail: failed.length === 0
      ? `${settled.length}/${settled.length} calls succeeded`
      : `${failed.length} calls failed: ${failed.slice(0, 3).map((f) => f.err).join('; ')}`,
  });

  return checks;
}

// ─── Main ──────────────────────────────────────────────────────────────

async function main() {
  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  40mcp concurrent tenant isolation — different approval reqs');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  N = ${N} calls per tenant per tool (${4 * N} total interleaved)`);
  console.log('  tenant-A: read=allow, mutate=allow');
  console.log('  tenant-B: read=allow, mutate=require_approval');
  console.log('');

  const workload = await runWorkload();
  const checks = verify(workload);

  for (const c of checks) {
    const icon = c.pass ? '✓' : '✗';
    console.log(`  ${icon} ${c.id.padEnd(36)} ${c.detail}`);
  }
  const pass = checks.filter((c) => c.pass).length;
  const fail = checks.length - pass;
  console.log('');
  console.log(`  ── ${pass} PASS · ${fail} FAIL · wall=${workload.wallMs}ms`);
  console.log('══════════════════════════════════════════════════════════════');

  await mkdir(OUT_DIR, { recursive: true });
  const summary = {
    run_at: new Date().toISOString(),
    config: { N, total_calls: 4 * N },
    wall_ms: workload.wallMs,
    backend_audit_counts: audit.reduce((acc, a) => {
      acc[a.tenantId] = (acc[a.tenantId] || 0) + 1;
      return acc;
    }, {}),
    approval_handler_invocations: approvalRequests.length,
    approval_breakdown: approvalRequests.reduce((acc, r) => {
      const k = `${r.tenantId}/${r.tool}`;
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    }, {}),
    checks,
    totals: { pass, fail },
  };
  await writeFile(resolve(OUT_DIR, 'concurrent-tenant-latest.json'), JSON.stringify(summary, null, 2));

  if (fail > 0) process.exit(1);
}

main().catch((err) => {
  console.error('concurrent-tenant-isolation crashed:', err);
  process.exit(1);
});
