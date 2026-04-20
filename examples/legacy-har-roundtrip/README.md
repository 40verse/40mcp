# Legacy HAR round-trip — full self-referential loop

The strongest 40mcp thesis proof in one demo. It runs every layer of
the framework end-to-end and verifies the output of one becomes the
input of the next, all the way around the circuit.

```
legacy upstream ──▶ HAR capture ──▶ loadHarFile ──▶ inferred tools
                                                          │
                                                          ▼
                                                createPolicyGate
                                                          │
                                                          ▼
                                                 createReverseBridge
                                                          │
                                  fresh client ◀──────────┘
                                       │
                                       ▼
                                  legacy upstream  (round-trip closed)
```

## What this proves

1. **Capture: legacy → HAR.** A real undocumented HTTP service can be
   recorded into a HAR file (in this demo we synthesize the equivalent;
   the loader's contract is identical to a real recording).
2. **Convert: HAR → tools.** `loadHarFile` infers tool definitions
   from observed traffic, including method, path template, and
   inferred parameters.
3. **Sanitize at conversion time.** A hostile HAR entry containing
   `Authorization`, `Cookie`, `password`, and `api_key` is included
   in the source. Every credential header is stripped from tool defs;
   every sensitive param name is filtered from inputSchema.
4. **Govern: policy gate.** The inferred tools are wrapped in
   `createPolicyGate` with per-tool rules: read tools `allow`,
   destructive `DELETE` tools `deny`.
5. **Re-expose: tools → REST.** The governed tool list is mounted on
   a `createReverseBridge`, turning the federation back into HTTP for
   downstream consumers.
6. **Round-trip: client → bridge → upstream → bridge → client.** A
   fresh HTTP client hits the bridge. Legitimate requests succeed AND
   produce responses that match the original upstream byte-for-byte.
   Destructive requests are refused at the policy gate **before** the
   dispatch reaches the upstream — verified by checking the upstream's
   own delete counter remains zero.

## Run

```bash
node examples/legacy-har-roundtrip/run.mjs
```

## Last run

```
══════════════════════════════════════════════════════════════
  40mcp legacy HAR round-trip — full self-referential loop
══════════════════════════════════════════════════════════════

  STEP 1: start legacy upstream
  ✓ S1-upstream-running                    legacy upstream on :XXXXX

  STEP 2: synthesize HAR capture (6 entries: 5 clean + 1 hostile)
  ✓ S2-har-synthesized                     6 entries (1 hostile with creds + sensitive params)

  STEP 3: loadHarFile → infer tool definitions
  ✓ S3-tools-inferred                      4 tools inferred from HAR
  ✓ S4-credentials-stripped                no credential leak in any tool def
  ✓ S5-sensitive-params-filtered           no sensitive param names in any inputSchema.properties

  STEP 4: govern with createPolicyGate (read=allow, DELETE=deny)
  ✓ S4-policy-mapped                       1 DELETE tool(s) marked deny, others allow

  STEP 5: re-expose as REST via createReverseBridge
  ✓ S5-bridge-started                      reverse bridge on :XXXXX with 4 tools

  STEP 6: round-trip via fresh client (utility + policy verification)
  ✓ S6-utility-list-works                  list_items: status=200 items=2
  ✓ S6-policy-delete-blocked               delete_items: status=500 blocked by policy gate
  ✓ S6-upstream-delete-not-reached         legacy upstream delete count = 0
  ✓ S7-roundtrip-integrity                 direct=2 items, via-bridge=2 items — identical

  ── 11 PASS · 0 FAIL (of 11)
══════════════════════════════════════════════════════════════
```

JSON report: `results/roundtrip-latest.json`.

## The hardest assertion — S6-upstream-delete-not-reached

A passing policy gate is necessary but not sufficient — the test that
matters is that **the destructive operation never reached the
backend**. The legacy upstream maintains its own delete counter. After
the demo's policy-denied DELETE call, the counter must still be zero.
If the policy gate were a logging-only stub, the call would pass
through and the counter would tick. It doesn't. **The deny rule is
load-bearing, not advisory.**

## Why this is the strongest thesis proof

The demo runs five distinct framework capabilities end-to-end in one
process:

| Capability | Verified by |
|---|---|
| Load HAR → tool definitions | `loadHarFile` returns a populated `tools` array |
| Strip credentials at load time | hostile entry's `Authorization` / `Cookie` / `api_key` absent from any tool def |
| Filter sensitive parameter names | `password` / `api_key` not present in any `inputSchema.properties` |
| Per-tool policy gate | DELETE tool refused with `[policy] [DENY]`; legacy upstream's delete counter remains 0 |
| Re-expose governed tools as REST | `createReverseBridge` accepts the inferred tool list, dispatches successfully |

We are not aware of an open MCP framework that ships all five of these
steps in one runtime, but this is not a competitive claim — it is a
description of what 40mcp's tesseract architecture is for. The
[CONCEPT.md](../../CONCEPT.md) "Trust Topology" and "Dimension 4"
sections frame the same shape geometrically: the system observes its
own output (HAR) and generates its own input (tools). This demo proves
the loop closes without breaking.

## Topology

```
                 ┌──────────────────┐
                 │  legacy upstream │  (mock — represents an
                 │   /api/items     │   undocumented HTTP system)
                 └────────┬─────────┘
                          │ traffic
                          ▼
                 ┌──────────────────┐
                 │  HAR capture     │  (synthesized from observed
                 │  6 entries        │   requests/responses + 1 hostile)
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  loadHarFile     │  ─── strips credentials
                 │                  │  ─── filters sensitive params
                 └────────┬─────────┘
                          │ tool defs
                          ▼
                 ┌──────────────────┐
                 │  createPolicyGate│  ─── DELETE tools → deny
                 │                  │  ─── GET/POST → allow
                 └────────┬─────────┘
                          │ governed dispatch
                          ▼
                 ┌──────────────────┐
                 │createReverseBridge│  ─── re-exposes as REST
                 │  /api/tools/...  │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  fresh client    │  ─── legitimate calls work
                 │                  │  ─── destructive calls blocked
                 └──────────────────┘  ─── round-trip integrity verified
```
