# Concurrent tenant isolation — different approval requirements

Two tenants share the same tool surface. They have **different**
per-tool policies — one auto-approves, the other requires human
approval for the destructive tool. Under concurrent load, with the
event loop interleaved A,B,A,B,…, the demo proves:

- Each tenant's call reaches the backend tagged with *its own*
  `tenantId` only — never the other's.
- Approval handler is invoked *exactly* the right number of times
  for the *correct* tenant. Tenant A's mutate calls bypass the
  handler entirely. Tenant B's mutate calls all hit it.
- No call result contains the other tenant's identifier.
- No dispatch errors under 200 concurrent calls (50 × 2 tenants × 2 tools).

## Run

```bash
node examples/concurrent-tenant-isolation/run.mjs
```

## Last run

```
══════════════════════════════════════════════════════════════
  40mcp concurrent tenant isolation — different approval reqs
══════════════════════════════════════════════════════════════
  N = 50 calls per tenant per tool (200 total interleaved)
  tenant-A: read=allow, mutate=allow
  tenant-B: read=allow, mutate=require_approval

  ✓ C1-tenant-A-call-count               tenant-A backend hits: 100 (expected 100)
  ✓ C2-tenant-B-call-count               tenant-B backend hits: 100 (expected 100)
  ✓ C3-no-bleed-tenant-id                no spurious tenant IDs observed at backend
  ✓ C4-tenant-A-no-approvals             tenant-A approval handler invocations: 0 (expected 0)
  ✓ C5-tenant-B-mutate-approval-count    tenant-B mutate approval requests: 50 (expected 50)
  ✓ C6-tenant-B-read-no-approval         tenant-B read approval requests: 0 (expected 0)
  ✓ C7-no-cross-tenant-result-leak       200 settled calls, every result tagged with originating tenant
  ✓ C8-no-dispatch-errors                200/200 calls succeeded

  ── 8 PASS · 0 FAIL · wall=13ms
══════════════════════════════════════════════════════════════
```

JSON report: `results/concurrent-tenant-latest.json`.

## What this proves

- **Per-tenant policy by composition.** 40mcp doesn't need a
  per-tenant policy registry — `createTenantScope` wraps `createPolicyGate`,
  and each tenant gets its own gate with its own rules. The
  composition is the policy.
- **Non-enumerable `_tenant` envelope is leak-proof under concurrency.**
  Each call's `args._tenant` is set non-enumerably by the scope wrapper
  and never reads back into another concurrent call's args.
- **Approval handler attribution is correct.** When tenant B's mutate
  call hits the gate, the handler sees `ctx.args._tenant.tenantId === 'tenant-B'`
  — never `tenant-A`, never `NONE`.

## Topology

```
Tenant A (auto-approve)        Tenant B (require_approval)
       │                                  │
       └─────────┬────────────────────────┘
                 │
        createTenantScope (per tenant)
                 │
        createPolicyGate (per tenant, different rules)
                 │
                 ▼
              backend dispatch ──▶ upstream
```

The approval handler in this demo is a deterministic stub that
auto-approves and records every request. In production it's the
human-in-the-loop hook (Slack approval, PagerDuty challenge, terminal
prompt, etc.) — the demo proves the wiring works under load before
the real handler is plugged in.
