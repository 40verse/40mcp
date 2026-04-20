# Three-tier trust topology — killer demo

A runnable proof that 40mcp's application-layer gating holds a trust
boundary when network-layer controls alone would not.

## What this demo proves

Three 40mcp instances, three separate trust zones, three different
credentials — and a probe suite that shows each layer holds
independently:

```
Instance 3           Instance 1              Instance 2           upstream
(external client)    (gateway)               (backend + vault)    (real API)

    │ CLIENT_TOKEN        │
    ├────────────────────▶│  PROXY_TOKEN         │
    │                     ├─────────────────────▶│  DEEP_SECRET
    │                     │                      ├──────────────────▶
    │   ─── direct ───    │                      │
    ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶◉ 401
    │                                              (app-layer refusal,
    │                                               not network-layer)
```

- **Instance 2** holds `DEEP_SECRET` — the real upstream credential —
  in a closure that never leaves its process. Inbound auth gate
  requires `PROXY_TOKEN`. Policy gate refuses destructive tools even
  if auth passes.
- **Instance 1** holds `PROXY_TOKEN` only. No vault. No deep
  credentials. Proxies tool calls to Instance 2 using its token.
- **Instance 3** holds `CLIENT_TOKEN` only. Reaches Instance 1 legally.
  Refused at Instance 2 directly, even on a flat network.

## The scenario

What happens when network controls fail? An operator misconfigures a
firewall, a pod leaks onto the mesh, an IP allowlist has a stale CIDR
— suddenly Instance 3 can reach Instance 2 directly. Does the trust
boundary hold?

**Yes. Application-layer gating is orthogonal to network gating.** This
demo runs 8 probes covering every edge of the topology, including
scenarios where the attacker has network access *and* a stolen
`PROXY_TOKEN`. The policy gate is the second layer — even with auth
bypassed, deny-policy tools remain unreachable.

## How to run it

```bash
node examples/three-tier-trust/run.mjs
```

No arguments. No external dependencies. Binds to loopback on random
ports. Completes in under a second.

```
══════════════════════════════════════════════════════════════
  40mcp three-tier trust topology — application-layer gating
══════════════════════════════════════════════════════════════
  upstream on :XXXXX  (requires Bearer DEEP_SECRET)
  Instance 2 on :XXXXX  (auth PROXY_TOKEN, policy gate)
  Instance 1 on :XXXXX  (auth CLIENT_TOKEN, proxies to Instance 2)

  ✓ L1  direct no-token       → 401                  PASS
  ✓ L2  direct with CLIENT_TOKEN → 401               PASS
  ✓ L3  direct stolen PROXY_TOKEN read tool → passes auth PASS
  ✓ L4  direct stolen PROXY_TOKEN destructive → policy denied PASS
  ✓ L5  via gateway with CLIENT_TOKEN  → 200         PASS
  ✓ L6  via gateway destructive        → backend policy denies PASS
  ✓ L7  DEEP_SECRET not in gateway response          PASS
  ✓ L8  compromise scope report                      PASS

  ── 8 PASS · 0 FAIL · 0 ERROR
══════════════════════════════════════════════════════════════
```

The output is also written to `scripts/stress-test/results/three-tier-latest.{json,md}`.

## Probes in detail

| ID | Attack shape | Layer tested | Expected |
|----|--------------|--------------|----------|
| **L1** | Instance 3 → Instance 2 direct, no token | reverse-bridge `auth.envVar` | 401 |
| **L2** | Instance 3 → Instance 2 direct, `CLIENT_TOKEN` (wrong token) | constant-time token compare | 401 |
| **L3** | Instance 3 → Instance 2 direct, **stolen `PROXY_TOKEN`**, read tool | auth passes (as expected — token leak) | 200 |
| **L4** | Instance 3 → Instance 2 direct, **stolen `PROXY_TOKEN`**, destructive tool | `createPolicyGate` deny rule | 500 (policy denied) |
| **L5** | Instance 3 → Instance 1 → Instance 2, read tool | happy path | 200 |
| **L6** | Instance 3 → Instance 1 → Instance 2, destructive tool | backend policy denies, gateway returns 500 | 500 |
| **L7** | `DEEP_SECRET` appearing in Instance 1's proxied response | credential closure isolation | isolated (not in body) |
| **L8** | Instance 1 full-compromise blast radius | capability enumeration | documented (attacker ≠ `DEEP_SECRET`) |

## The key insight — L3 + L4

The critical pair. **L3 shows that stolen credentials bypass the auth
layer** (that's the definition of a stolen credential — nothing 40mcp
can do about that at auth time). **L4 shows the policy gate is the
second layer** — even with valid `PROXY_TOKEN`, the `delete_all` tool
is refused because it's marked `policy: 'deny'` in the backend
configuration.

This is **action gating that outlives network gating.**
Network controls (mTLS, IP allowlists, overlay meshes) and application
controls (auth + policy) are independent. If either one holds, the
destructive action does not execute. They compose.

Applied to a real deployment:

- **Network layer** handles instance-to-instance reachability via
  whatever your platform gives you (Cloudflare Access, Tailscale ACLs,
  k8s NetworkPolicy, bastion hosts).
- **Application layer** handles per-action gating that's
  network-independent — `policy: 'deny'` on destructive actions,
  `policy: 'require_approval'` on high-risk actions, `policy: 'log_only'`
  on monitored actions.

If network controls fail, the policy gate still refuses the dangerous
action. If policy config is weak, the network still keeps the attacker
from reaching the vault instance in the first place.

## What this replicates that no other MCP framework offers

- **Closure-scoped credential isolation** — `DEEP_SECRET` lives in a
  closure inside Instance 2's process. It is never returned, logged,
  or serialized. Instance 1 has no API to request it.
- **Per-tool policy gate** — `createPolicyGate` refuses specific tools
  by name, regardless of which credential authenticated the call.
  Deny rules are absolute; require-approval rules can be wired to
  human-in-the-loop handlers.
- **Bidirectional reverse bridge** — Instance 1 consuming Instance 2
  over HTTP uses the same reverse-bridge primitive that Instance 2
  uses to accept calls. Both sides of every hop are symmetric 40mcp.
- **Zero network assumption** — the demo binds everything to loopback
  and makes zero assumptions about firewalls. The security guarantees
  come from the 40mcp layer, not the kernel.

Those four properties together are the 40mcp thesis. No other open
MCP framework ships all four in one runtime.

## Run this before every release

This example is also the regression signal for the three-tier pattern.
Any future change that weakens reverse-bridge auth, the policy gate,
or the credential closure will flip a probe to FAIL and block release.

```bash
# Pre-release check
node examples/three-tier-trust/run.mjs
# must report: 8 PASS · 0 FAIL · 0 ERROR
```

## See also

- [`CONCEPT.md`](../../CONCEPT.md) — the "Trust Topology" section of the
  fourth-dimension concept doc frames this pattern geometrically.
- [`src/reverse/server.js`](../../src/reverse/server.js) — reverse
  bridge with `auth.envVar` + constant-time token compare.
- [`src/security/policy.js`](../../src/security/policy.js) — policy
  gate with `deny` / `require_approval` / `log_only` rules.
- [`scripts/stress-test/three-tier-sim.mjs`](../../scripts/stress-test/three-tier-sim.mjs)
  — the original location of this simulator, still runs, same code.
