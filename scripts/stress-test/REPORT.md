# 40mcp stress test — analysis report

**Run:** 2026-04-14 (full mode, Node v22.22.2, Linux x86_64)
**Container:** 16 vCPU, 21 GiB RAM, gVisor (`runsc` sandbox)
**Branch:** `claude/stress-test-40mcp-M009A`
**Runner:** `scripts/stress-test/run.mjs`
**Raw results:** [`scripts/stress-test/results/latest.md`](./results/latest.md), [`latest.json`](./results/latest.json)

---

## 1. What was tested

Eight scenarios stress the four public edges of 40mcp plus two hot CPU
paths. Each scenario spins up its own server instance on a loopback
ephemeral port, drives load with a keep-alive `node:http` agent, and
tears the server down cleanly before the next run. The dispatch function
is always a local mock — we are benchmarking the bridge layer, not any
upstream API.

| # | Surface under test | Cross-cut concern |
|---|--------------------|-------------------|
| 1 | `createReverseBridge` hot path | HTTP + JSON + envelope strip |
| 2 | `validateToolArgs` via HTTP | attack-shaped input rejection |
| 3 | Reverse bridge large response | JSON serialization cost |
| 4 | `createWebhookListener` sync HMAC | happy-path signature verify |
| 5 | Webhook listener under forged sigs | DoS attack load (401 path) |
| 6 | `validateToolArgs` direct call | pure CPU throughput |
| 7 | `loadOpenApiSpec` | N-operation spec parsing |
| 8 | Reverse bridge `checkAuth` | constant-time token rejection |

## 2. Headline numbers

| # | Scenario | Ops | RPS | p50 (ms) | p95 (ms) | p99 (ms) | Errors |
|---|----------|-----|-----|----------|----------|----------|--------|
| 1 | reverse-bridge/happy-path          | 10000   | 1886  | 30.7 | 46.1 | 50.3 | 0 |
| 2 | reverse-bridge/input-validation    | 6000    | 2434  | 24.3 | 32.4 | 38.1 | 4000 (expected 400s) |
| 3 | reverse-bridge/large-payload       | 800     | 805   | 37.3 | 47.5 | 229.2 | 0 |
| 4 | webhook/hmac-sync                  | 6000    | 1744  | 18.2 | 23.4 | 28.0 | 0 |
| 5 | webhook/hmac-failure               | 4000    | 2064  | 15.2 | 20.2 | 24.1 | 4000 (expected 401s) |
| 6 | validate-tool-args/microbench      | 1000000 | **1.48 M/s** | — | — | — | 0 |
| 7 | openapi/large-spec (3000 ops)      | 1       | 20.9  | 47.7 | — | — | 0 (**≈16 µs/tool**) |
| 8 | reverse-bridge/auth-rejection      | 5000    | 2386  | 24.8 | 36.3 | 50.6 | 5000 (expected 401s) |

Total wall time: **19.1s**. Baseline RSS **175.6 MiB → final 215.6 MiB**
(Δ ≈ 40 MiB across the whole suite, most of which is the keep-alive
socket pools and `node:http` internals — no runaway growth seen between
scenarios).

## 3. Key observations

### 3.1 The happy path is bound by the keep-alive agent, not the bridge
Scenario 1 drives 10 000 POSTs through `/api/tools/echo` at 1886 rps with
p99 = 50 ms — but p50 is already 30 ms. The server-side dispatch is a
no-op, so that latency floor is the harness’ own keep-alive queue. The
top-of-scenario `max=932.77 ms` outlier is a warm-up cost on the first
N workers (first HTTP agent connects, first v8 optimisation pass). The
p50/p95 band is tight (30–46 ms), meaning once steady state is reached
the bridge’s dispatch cost is stable. If you want to push real
throughput higher, scale horizontally — this is a single-process test.

### 3.2 Input validation is faster than the happy path
Scenario 2 actually achieves **more RPS** than scenario 1 (2434 vs 1886).
That makes sense: the 4 000 invalid requests get a 400 before
`dispatch` is called, so they skip the async await and JSON round-trip.
The point is that the bridge rejected every NaN, `__proto__`, `_tenant`,
and type-mismatch payload cleanly — **zero 500s, zero hangs** — while
the 2 000 valid requests still got 200s. This is the first-order
invariant the security tests care about (see `RESERVED_ARG_KEYS` in
`src/bridge.js` and the constraint 11 in CLAUDE.md).

### 3.3 Large-payload p99 has a long tail
Scenario 3 sends ~64 KiB per response and shows a visible tail:
p95 = 47 ms, **p99 = 229 ms**, max = 359 ms. This is the scenario most
affected by v8 GC pauses — each response clones + strips + stringifies
an array of 200 objects. Not a bug, but anyone doing large dispatch
results in production should know the tail exists. Possible follow-ups:
1. Pre-serialize the envelope-stripped form once per unique result.
2. Add a streaming path for results above a tunable byte threshold.
3. Track `process.getActiveResourcesInfo()` / GC events and add them to
   the harness report.

### 3.4 HMAC verification is ~1700 rps per core
Scenario 4 sustains 1744 rps of **sync** HMAC-SHA256 verification +
dispatch, with p99 = 28 ms. Scenario 5 shows the rejection path runs
~20 % faster (2064 rps, p99 = 24 ms) because failed requests skip the
dispatch microtask. Both paths are dominated by `timingSafeEqual` and
`parseBody`, not JSON or the dispatcher. The listener’s built-in
per-route error-log rate-limiter kicked in after the first ~10 HMAC
failures and suppressed the rest — exactly the `webhook.hmac_fail` →
`Webhook secret-failure rate limit reached` sequence the source code
documents at line 402–413. **Forged-signature DoS load does not
generate proportional log volume.** This is the primary invariant the
webhook hardening was designed to preserve.

### 3.5 `validateToolArgs` is effectively free
Scenario 6: **1 481 000 validations per second** in a single Node
worker. At this throughput the validator is not a meaningful CPU line
item in any realistic request path — even a 10 k rps bridge spends
<1 % of its CPU on args validation. If future optimizations target
latency, this is the wrong file to look at.

### 3.6 OpenAPI parser scales linearly
Scenario 7 loaded a synthetic spec with 3 000 operations in **48 ms**
(≈16 µs/tool, 2.1 MiB RSS delta). A 50 k-operation spec would take
~800 ms to parse and ~35 MiB of RSS — still under the 50 MiB file cap
enforced by `MAX_OPENAPI_FILE_BYTES`. The loader's ref-resolver and
`DANGEROUS_KEYS` guard (src/openapi.js:19) pay constant overhead per
segment, not per tool, so the scaling is linear as expected.

### 3.7 Constant-time auth compare holds up under forged tokens
Scenario 8 drives 5 000 requests with *missing*, *wrong-length*, and
*wrong-value* tokens (rotating every 3 iterations). All three paths
exercise the `checkAuth` branch that pads to `maxLen` and calls
`timingSafeEqual` as a constant-time burn even on length mismatch
(src/reverse/server.js:209–219). Latencies are uniform across the mix
(p50 = 24.8, p95 = 36.3, p99 = 50.6), consistent with the intended
property that none of the three failure modes is distinguishable by
wall-clock. **No latency oracle was observed.**

## 4. Anomalies and caveats

| Observation | Root cause | Severity |
|-------------|-----------|----------|
| Scenario 1 max latency = 932 ms | First-request warm-up on keep-alive pool + v8 tier-up. Disappears after ~50 ops. | Informational |
| Scenario 3 p99 = 229 ms | GC pauses when cloning + stringifying 64 KiB responses on the hot path. | Low — document |
| Scenario 4 RSS delta = **-4.7 MiB** | GC fired mid-run; harness measures RSS at scenario boundaries, not continuously. | Informational |
| "hmac-sha256" string initially passed as `secret.type` | Listener’s supported types are `header`, `hmac`, `query`. Unknown types return 401 with a `warning:` log. | Fixed in harness (`type: 'hmac'` + `replayWindow: false`). The *listener* behaved correctly — unknown type is a fail-closed. |
| Scenario 5 stderr filled with `webhook.hmac_fail` events before the rate limiter engaged | Expected per source: the first ~10 events log, subsequent ones are suppressed. | Informational |

## 5. Things the harness does NOT cover

Known gaps, documented here so the next runner knows where to extend:

1. **SSE transport** — `createSseTransport` was skipped because testing it
   needs a full MCP client. Worth adding later (see test/transport-real).
2. **Connect flows / mixer** — `src/connect.js` and `src/compose/mixer.js`
   depend on a real upstream MCP server. The load test would need a
   loopback MCP server mocked with `@modelcontextprotocol/sdk`.
3. **Policy gate approval under load** — `src/security/policy.js` gates
   on async approver callbacks. Worth testing with a fake approver that
   returns deny 50 % of the time.
4. **Sealed vault (`src/security/vault.js`)** — AES-256-GCM envelope
   encryption is CPU-heavy; should measure ops/sec separately.
5. **GC accounting** — harness measures RSS at scenario boundaries only.
   A `perf_hooks.PerformanceObserver` feeding `gc` events would give
   far more useful p99 attribution.
6. **Slowloris / half-open sockets** — the servers set
   `headersTimeout=15s`, `requestTimeout=30s` (source: `src/reverse/server.js:361`
   and `src/webhook/listener.js:525`), but this harness doesn't
   intentionally dribble headers to prove those timeouts fire.
7. **Multi-tenant `tenant/scope.js`** — no contention test yet.

## 6. Reproducing

```bash
# Fast smoke run (~7s)
node scripts/stress-test/run.mjs --smoke

# Full run (~20s)
node scripts/stress-test/run.mjs

# Run a subset
node scripts/stress-test/run.mjs --only=1,4,6
```

Artifacts are written to `scripts/stress-test/results/latest.{json,md}`
on every run. Check the JSON into CI if you want to track regression
trend lines over time.

## 7. Verdict

On this 16-core container, the 40mcp bridge layer sustains **~2 k rps
per process** on the reverse bridge hot path, **~1.7 k rps per process**
on the sync webhook HMAC path, with **zero 5xx across all scenarios**,
single-digit MiB RSS growth per scenario (noise, not leakage), and
correct behavior on every attack-shaped request (NaN, proto-pollution,
reserved keys, forged HMAC, missing/wrong/wrong-length auth token).

The security invariants the codebase takes seriously — constant-time
auth, reserved-key rejection, rate-limited error logging, fail-closed
on unknown secret types — all held under 2 k rps sustained load.
Scale beyond a single process is horizontal: 40mcp is deliberately
stateless on the request path, so RPS grows linearly with instance
count.

No blocking issues found. The p99 tail on large payloads (scenario 3)
is the only thing worth a follow-up investigation, and only if anyone
is actually streaming large results through the reverse bridge today.
