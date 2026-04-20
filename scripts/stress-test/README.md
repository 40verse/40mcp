# 40mcp stress test + simulation harness

Zero-dependency load tester, red-team attack-surface probe, and
realistic-usage simulator for 40mcp. All three share the same
harness helpers (`harness.mjs`) and run against loopback servers.

## Quick start

```bash
# Stress test (load + latency)
node scripts/stress-test/run.mjs            # full run (~20s)
node scripts/stress-test/run.mjs --smoke    # faster smoke (~7s)
node scripts/stress-test/run.mjs --only=1,4 # subset by scenario id

# Simulation (attack-surface probes + realistic workload)
node scripts/stress-test/simulate.mjs          # full (~15s, 54 probes)
node scripts/stress-test/simulate.mjs --fast   # 5s usage window
node scripts/stress-test/simulate.mjs --probes # probes only
node scripts/stress-test/simulate.mjs --usage  # usage only

# Federation (two chained 40mcp instances: client → A → B → upstream)
node scripts/stress-test/chain-sim.mjs         # full (~12s)
node scripts/stress-test/chain-sim.mjs --fast  # 5s throughput window
```

Each runner overwrites its own pair of result files:
- `results/latest.{json,md}` — stress runner
- `results/simulate-latest.{json,md}` — simulate runner
- `results/chain-latest.{json,md}` — federation runner

## Layout

| File | Purpose |
|------|---------|
| `run.mjs`              | Stress runner — 8 load scenarios |
| `scenarios.mjs`        | Stress scenarios (reverse, webhook, validator, openapi) |
| `simulate.mjs`         | Simulation runner — probes + usage sim |
| `attack-surface.mjs`   | 54 red-team probes across 14 boundaries (reverse, webhook, mcp-bridge, openapi, har, ssrf, slowloris, egress, composition, auth, tenant, policy-gate, prompt-injection, schema-validation, federation) |
| `chain-sim.mjs`        | Two chained 40mcp instances — federation throughput + per-hop latency + strip/injection/auth propagation probes |
| `usage-sim.mjs`        | 6-bucket realistic workload generator |
| `harness.mjs`          | Percentiles, concurrent driver, `node:http` helpers |
| `REPORT.md`            | Narrative analysis of the stress run |
| `ATTACK-SURFACE.md`    | Narrative analysis of the simulation run + findings |
| `results/`             | Machine-readable results |

## What it tests

1. Reverse bridge happy path (HTTP → dispatch → JSON)
2. Reverse bridge input validation under attack-shaped payloads
3. Reverse bridge large-response serialization
4. Webhook listener sync HMAC verification
5. Webhook listener forged-signature rejection (attack load)
6. `validateToolArgs` CPU throughput
7. `loadOpenApiSpec` with a 3 000-operation synthetic spec
8. Reverse bridge auth rejection (missing / wrong-length / wrong token)

See [`REPORT.md`](./REPORT.md) for the current numbers and analysis.

## Design notes

- The harness is zero-dependency on purpose — it has to run in any
  container that can run 40mcp.
- Scenarios run sequentially so RSS deltas per scenario are meaningful.
- Every server binds to `127.0.0.1` on a random port in `30000–39999`.
  If you hit a collision, rerun — the range is wide enough that this is
  rare.
- Dispatch functions are always local mocks. We're measuring 40mcp, not
  the upstream APIs.
- Attack-shaped payloads in scenario 2 are expected to produce 400s
  and are counted in `errors` by design. Look at `statusCounts` to see
  the real breakdown.
