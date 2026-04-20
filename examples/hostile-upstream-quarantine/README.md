# Hostile upstream sanitize-in-place — neutralize without breaking utility

Loads an OpenAPI spec containing **2 legitimate tools and 5 hostile
tool shapes** in the same file. Proves 40mcp:

1. **Neutralizes every attack at load time** — proto-pollution `$ref`,
   `__proto__` parameter, homoglyph prompt-injection in the tool
   summary, 1 MiB description bomb, self-referential schema recursion.
2. **Preserves utility for the legitimate tools** — `list_users` and
   `get_user` survive load and dispatch successfully through a real
   `createReverseBridge` against a mock upstream.
3. **Sanitized tools remain dispatchable.** This is a precise claim,
   not strong isolation: the malicious *metadata* (description text,
   parameter names, $ref segments) is rewritten in place to its safe
   equivalent. The tool's identity, route, and dispatch path are
   preserved. There is no separate "quarantine zone" — the sanitized
   tool sits in the same tool list as the legitimate ones, callable
   through the same bridge, with its hostile fields neutralized.

The hardest half of the thesis: it is easy to refuse a hostile spec
entirely. It is much harder to load a *partially*-hostile spec,
neutralize the bad fields surgically, and keep the legitimate parts
working. This demo proves the second half.

## Run

```bash
node examples/hostile-upstream-quarantine/run.mjs
```

## Last run

```
══════════════════════════════════════════════════════════════
  40mcp hostile upstream sanitize-in-place — neutralize + preserve
══════════════════════════════════════════════════════════════
  Loading a spec with 2 legitimate + 5 hostile tool shapes...

  LOAD-TIME NEUTRALIZATION
    ✓ L0-load-completes                    loaded 7 tool(s) in 3ms (no crash, no hang)
    ✓ L1-legitimate-listUsers-survived     list_users present in tools list
    ✓ L2-legitimate-getUser-survived       get_user present in tools list
    ✓ L3-homoglyph-injection-detected      manipulate tool description redacted
    ✓ L4-giant-description-capped          giant description length: 12 (cap ≤ 8192)
    ✓ L5-proto-param-rejected              protoparam.inputSchema.properties does not contain __proto__
    ✓ L6-proto-param-sibling-preserved     real_query survived alongside the rejected __proto__
    ✓ L7-proto-ref-no-pollution            proto_bomb tool has no polluted property
    ✓ L8-recursion-loop-bounded            loop tool processed without infinite recursion

  UTILITY PRESERVATION (legitimate calls through reverse bridge)
    ✓ U1-list-users-works                  status=200 body={"result":[{"id":"u1"},{"id":"u2"}]}
    ✓ U2-get-user-works                    status=200 body={"result":{"id":"alice","name":"alice"}}
    ✓ U3-sanitized-tool-still-dispatchable sanitized "giant" dispatched

  ── 12 PASS · 0 FAIL (of 12)
══════════════════════════════════════════════════════════════
```

JSON report: `results/quarantine-latest.json`.

## What this proves

| Defense | Mechanism | Where |
|---|---|---|
| Proto-pollution `$ref` (`#/constructor/prototype/...`) | `DANGEROUS_KEYS` block in `resolveRefPath` | `src/openapi.js` |
| `__proto__` parameter name | `DANGEROUS_KEYS` filter at parametersToSchema | `src/openapi.js` |
| **Homoglyph prompt-injection** in summary/description | `sanitizeDescription` after NFKC normalization | `src/core/sanitize.js` |
| **Description size bomb** (1 MiB) | `MAX_DESCRIPTION_BYTES` cap in `sanitizeDescription` | `src/core/sanitize.js` |
| **Self-referential schema** recursion | `MAX_REF_DEPTH` cap in `resolveRefPath` | `src/openapi.js` |
| Utility for legitimate tools | reverse bridge serves them; dispatch routes work | `src/reverse/server.js` |

`sanitizeDescription` is armed against the homoglyph and size-bomb
classes. **The trust evidence is that the demo passes today against
the five attack shapes it lists.**

## The pattern: per-field surgical sanitization

The pattern this demo proves is **per-field surgical sanitization**:
malicious *fields* on a tool definition are rewritten or dropped while
the rest of the tool definition (identity, route, dispatch path)
remains intact. A spec with one bad field on one tool does not lose
the rest of that tool, and does not lose any other tool in the same
file.

The two trivial designs — *refuse the whole spec on any failure* and
*accept everything blindly* — are not what this demo runs. The first
loses utility; the second loses safety. The middle ground is the
load-time per-field rewrite that `sanitizeDescription` implements.

## Topology

```
hostile.openapi.json ──▶ loadOpenApiSpec ──▶ 7 sanitized tools
                              │                    │
                              ├─ proto-ref            ▼
                              │  refused        createReverseBridge
                              ├─ __proto__           │
                              │  filtered           ▼
                              ├─ homoglyph        legitimate calls
                              │  redacted         ── list_users    ✓
                              ├─ 1 MiB desc      ── get_user       ✓
                              │  capped          ── giant          ✓ (sanitized in place, still dispatchable)
                              └─ self-ref
                                 bounded
```
