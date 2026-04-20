# 40mcp trust-proof suite

Four executable demos. Each proves a distinct half of the 40mcp
thesis. Each produces a verifiable runtime report. Together they
form one coherent trust-proof system suitable for inclusion in
beta release evidence.

## Run all four

```bash
npm run trust-demos
```

Or directly:

```bash
node examples/run-trust-demos.mjs
```

Aggregate report: `examples/results/trust-demos-latest.json`

## Latest run

```
══════════════════════════════════════════════════════════════
  40mcp trust-proof suite
  4 demos · run sequentially · aggregate report
══════════════════════════════════════════════════════════════

▶ Three-tier trust topology
    application-layer gating survives network compromise
  ✓ 8 PASS · 0 FAIL

▶ Concurrent tenant isolation
    per-tenant policy by composition; zero bleed under load
  ✓ 8 PASS · 0 FAIL

▶ Hostile upstream sanitize-in-place
    per-field surgical sanitization; utility preserved
  ✓ 12 PASS · 0 FAIL

▶ Legacy HAR round-trip
    full tesseract loop: legacy → HAR → tools → policy → reverse → client
  ✓ 11 PASS · 0 FAIL

══════════════════════════════════════════════════════════════
  4/4 demos passed · 39 checks PASS · 0 checks FAIL · wall=2419ms
══════════════════════════════════════════════════════════════
```

## What each demo proves

| # | Demo | Trust claim | Path |
|---|------|-------------|------|
| 1 | **Three-tier trust topology** | A compromised edge instance cannot execute destructive actions because deeper policy boundaries still hold, even after token theft. | [`three-tier-trust/`](./three-tier-trust/) |
| 2 | **Concurrent tenant isolation** | Two tenants on the same tool surface with different per-tool policies maintain audit identity and approval-handler attribution under interleaved concurrent load. Zero context bleed. | [`concurrent-tenant-isolation/`](./concurrent-tenant-isolation/) |
| 3 | **Hostile upstream sanitize-in-place** | A spec containing both legitimate and hostile tool shapes loads with the malicious fields rewritten in place and the legitimate tools fully usable through a real reverse bridge. | [`hostile-upstream-quarantine/`](./hostile-upstream-quarantine/) |
| 4 | **Legacy HAR round-trip** | The full tesseract loop: an undocumented HTTP system is captured to HAR, converted to tools, governed by policy, re-exposed as REST, called by a fresh client, and the result matches the original upstream byte-for-byte. The legacy upstream's destructive-action counter remains zero after a policy-denied call. | [`legacy-har-roundtrip/`](./legacy-har-roundtrip/) |

## Reading order

If a reviewer is reading the suite cold, this is the order that
moves from simple to most-thesis-load-bearing:

1. **Three-tier trust** — the architecture proof. Establishes that
   application-layer gating is a real second layer, not a thin coat
   on top of network controls. The L3 + L4 critical pair (stolen
   token bypasses auth → policy gate still refuses destructive tool)
   is the structural insight that makes the rest of the suite mean
   what it claims.

2. **Concurrent tenant isolation** — the multi-tenant proof. Cashes
   out the subtle claim that policy behavior can differ per tenant
   *through composition* without a per-tenant policy registry, under
   200 interleaved concurrent calls, with zero context bleed.

3. **Hostile upstream sanitize-in-place** — the safety-without-loss
   proof. Demonstrates the per-field surgical sanitization pattern
   that lets 40mcp accept partially-hostile inputs without losing
   the legitimate parts.

4. **Legacy HAR round-trip** — the full-loop flagship. Runs every
   layer of the framework end-to-end and verifies the loop closes.
   This is the demo to lead with in any external presentation.

## What each demo does NOT prove

Trust evidence works by being precise about its scope. Each demo's
README opens with the exact claim it makes; here are the corresponding
**non-claims** so reviewers don't read more into the suite than
it actually demonstrates.

- **Three-tier trust** does *not* prove network isolation. It assumes
  the operator has a separate network layer; the demo proves the
  application layer is a useful second defense, not a replacement.
- **Concurrent tenant isolation** does *not* prove production-scale
  tenancy. 200 interleaved calls is enough to surface context bleed
  in process memory; it is not a soak test for thousands of tenants
  or millions of requests per minute.
- **Hostile upstream sanitize-in-place** does *not* prove every
  possible hostile spec is handled. It proves the five attack shapes
  it lists are neutralized by the sanitizer, and that
  legitimate sibling fields survive the rewrite. New attack shapes
  belong in the trust matrix (`npm run trust-matrix`), not here.
- **Legacy HAR round-trip** does *not* prove every possible legacy
  HTTP system can be captured. It proves the full circuit closes
  without breaking for the entry classes the loader handles, and
  that the destructive-action denial reaches the upstream's own
  counter.

## Reproducibility

Each demo:

- Binds to loopback (`127.0.0.1`) on a random port. No external
  network calls.
- Spins up its own mock upstream, bridge, and policy gate.
- Runs in under 1 second of wall time (full suite: ~2.4s).
- Uses zero external dependencies beyond what 40mcp ships.
- Writes a JSON report to `<demo>/results/*-latest.json`.
- Returns non-zero exit code on any check failure.

`npm run trust-demos` produces an aggregate report at
`examples/results/trust-demos-latest.json` — one file with the
full per-demo JSON and a top-level totals block. CI artifact ready.

## Related trust evidence

- **`npm run trust-matrix`** — the adversarial composition test
  matrix (`src/security/trust-matrix/`). Eleven named scenarios
  covering SSRF, schema abuse, HAR injection, tenant escalation,
  vault degraded auth, and more.
- **`npm run test:invariants`** — the per-trust-surface invariant
  test split (`src/security/invariants/`). Regression coverage
  across the sanitize, SSRF, tenant, vault, webhook, and policy
  boundaries.
- **[`CONCEPT.md`](../CONCEPT.md)** — the geometric framing of the
  trust topology (Dimension 4 + the Trust Topology section).
- **[`SECURITY.md`](../SECURITY.md)** — the threat model, supported
  versions, and disclosure process.

## When to update this suite

Add a demo here when:

- A new trust claim emerges that no existing demo proves.
- A newly-fixed security finding has a runtime shape that a static
  invariant test cannot fully express.
- A reviewer asks "but how does that hold under <X>?" and the answer
  is "let me show you".

Don't add a demo here when:

- A unit test or invariant test would do. The demos are for thesis-load-bearing
  proofs; unit tests are for structural correctness.
- The runtime is over 5 seconds. The suite needs to stay tight enough
  to be runnable by every contributor before every release.
- The demo can't fail. Every probe in every demo must have a path
  where it would FAIL if the underlying defense regressed.
