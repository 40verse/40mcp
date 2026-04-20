# Security Evolution

How 40mcp's security posture was developed, and the lessons that shaped it.

This document preserves the design intelligence earned during pre-release hardening. The code carries the fixes; this document carries the *reasoning*.

---

## Why 40mcp needed adversarial review

40mcp is an API-to-MCP bridge — it sits between an LLM client and upstream HTTP APIs. That position makes it a high-value interception point: it holds credentials, forwards user intent, and shapes what an LLM can do. A naive bridge would be a credential exfiltration vector, an SSRF launcher, and a prompt injection amplifier all at once.

The hardening process involved multiple rounds of adversarial scanning against the codebase. Findings were triaged through a release-gate framework (see [release-gate.md](release-gate.md)) that distinguished blockers from follow-ups using trust-boundary analysis.

---

## Core lessons

### 1. Transitive enforcement beats edge-only enforcement

Early implementations applied tenant ACL checks and policy gates at the outer bridge boundary. This was insufficient — compound chains (`executeChain`) dispatch sub-calls internally, and composition paths (`createMixer`, webhook-to-tool dispatch) create new entry points that bypass the outer wrapper.

**The fix:** Tenant context and policy enforcement propagate through the entire dispatch chain. Every internal dispatch point re-validates, not just the outermost handler. The invariant test suite (`src/security/invariants/tenant.test.js`) exercises cross-chain tenant isolation with 200 concurrent calls across 2 tenants.

**Lesson:** If a security check lives at the edge, composition will eventually route around it. Enforce transitively or accept the gap.

### 2. Transport-edge hardening must be centralized

40mcp has multiple result-exit paths: MCP `tools/call` (bridge), MCP `tools/call` (mixer), reverse bridge REST egress, webhook sync response, and `dispatch()` export. Each path needs two things: `stripInternalEnvelopes` (remove internal metadata) and `sanitizeResultObject` (redact prompt-injection patterns from string leaves).

Early versions applied these per-exit-path. They drifted. The mixer's `CallToolRequestSchema` handler applied envelope stripping but not result sanitization — meaning an upstream MCP server returning `"Ignore all previous instructions..."` would forward the string verbatim to the LLM.

**The fix:** A shared `sanitizeTransportEgress()` function combines both passes. Every result-exit path calls it. SECURITY.md carries an explicit audit table mapping every exit path to its sanitization status. The invariant suite (`src/security/invariants/sanitize.test.js`) covers all documented exit paths.

**Lesson:** When sanitization is copy-pasted per boundary, it will drift. Centralize it in a shared function and audit the mapping explicitly.

### 3. Prompt injection defense is layered, not singular

Prompt injection in the MCP context comes from multiple vectors:

| Vector | Defense |
|--------|---------|
| Malicious tool descriptions in community configs | `sanitizeMcpToolDescription` strips adversarial instruction patterns |
| Upstream MCP server schemas (via `connectStdio`/`connectSse`) | Schema sanitization strips `$ref`, prototype-poisoning keys, oversized descriptions |
| Upstream API response data | `sanitizeResultObject` redacts injection patterns from all string leaves |
| Unicode homoglyph bypass | Normalization before pattern matching (Greek lookalikes, Cyrillic substitutions) |
| Oversized payloads | Description size caps, response size guards (10 MB upstream limit) |
| NUL-byte smuggling | NUL stripping in sanitization pipeline |

No single layer is sufficient. Description sanitization alone doesn't help when the injection comes in a response body. Response sanitization alone doesn't help when the injection is in a tool description. The invariant suite tests each layer independently and in composition.

**Lesson:** Prompt injection defense requires consistent application across every surface where text flows toward an LLM. Audit the egress map, not just the individual functions.

### 4. SSRF defense requires decoding, not just string matching

The SSRF surface evolved through multiple rounds:

| Phase | Finding | Fix |
|-------|---------|-----|
| Early | Loopback (`127.0.0.1`, `::1`) not blocked | `assertSafeUrl` with IP range checks |
| Hardening | IPv6 ULA and multicast not blocked | Unconditional IPv6 range blocks |
| Hardening | CGNAT and reserved ranges not blocked | Extended IPv4 range catalog |
| Hardening | `localhost` hostname not blocked | Loopback hostname denylist |
| Hardening | `::127.0.0.1` bypasses IPv4 checks | IPv4-from-IPv6 decoder with re-validation |
| Hardening | Alternative IPv4 representations bypass | Alternative representation decoder |
| Post-beta | DNS rebinding via auto-reconnect | IP pre-resolution and pinning |

**Lesson:** SSRF defense is an arms race against encoding tricks. The only safe approach is to decode all representations to a canonical IP and validate against a comprehensive range catalog, then pin the resolved address for the connection lifetime.

### 5. Vault boundaries must fail closed

The vault daemon architecture separates the passphrase holder (daemon process) from the bridge processes that use credentials. Bridge processes authenticate via Unix socket IPC and receive scoped short-lived JWTs.

An early implementation of `vault-client.js` returned `null` when the daemon was unreachable (`ENOENT`/`ECONNREFUSED`), allowing requests to proceed without authentication. This silent degradation meant a daemon crash would cause all bridge requests to go out unauthenticated.

**The fix:** Auth hooks (`createAuthHook`, `createBearerHook`) now throw on daemon failure. Requests fail loudly rather than proceeding without credentials. The invariant suite (`src/security/invariants/vault.test.js`) tests the fail-closed behavior explicitly.

**Lesson:** Security boundaries must fail closed. Silent degradation from "authenticated" to "unauthenticated" is worse than a crash.

### 6. Trust claims must be narrower than proof

Early documentation used absolute claims about security that were broader than what could be proven. The review process surfaced the gap between aspiration and evidence.

**The fix:** Documentation was scrubbed to use scoped language: "security controls, policy gates, or composition" instead of absolute claims. A "What We Do Not Claim" section was added to SECURITY.md. Known limitations (DNS rebinding, MCP client auth, operator trust) are stated explicitly rather than hidden.

**Lesson:** Users make deployment decisions based on your documentation. Overclaiming erodes trust more than honest scoping does.

---

## Representative failure classes

| Class | Example | Structural fix |
|-------|---------|---------------|
| **Asymmetric transport hardening** | Mixer applied `stripInternalEnvelopes` but not `sanitizeResultObject` | Shared `sanitizeTransportEgress()` + egress audit table |
| **Edge-only enforcement** | Tenant ACL checked at bridge but not in chain sub-dispatches | Transitive propagation through all dispatch paths |
| **Encoding bypass** | `::127.0.0.1` → `::7f00:1` bypassed IPv4 SSRF checks | Decode-then-validate pipeline for all IP representations |
| **Silent auth degradation** | Vault daemon unreachable → requests proceed unauthenticated | Fail-closed: throw on daemon failure |
| **Hostname vs IP gap** | `localhost` not blocked (only `127.0.0.1` was) | Hostname denylist alongside IP range catalog |
| **Drift via copy-paste** | Per-boundary sanitization diverged over time | Centralized function + audit table |

---

## How release-gate thinking replaced scan anxiety

Early rounds of adversarial scanning produced findings faster than they could be triaged. The instinct was to treat every finding as a blocker. This led to churn without convergence.

The shift: findings were sorted into **blockers** (trust boundary violations that allow real exploitation on documented paths) and **follow-ups** (theoretical risks, defense-in-depth improvements, documentation gaps). A release gate framework (see [release-gate.md](release-gate.md)) formalized the decision rules.

The result: the final beta shipped with zero open blockers and a documented set of known limitations — not because every conceivable risk was eliminated, but because the remaining risks were honestly scoped and the trust boundaries were enforced on all documented paths.

---

## Further reading

- [SECURITY.md](../SECURITY.md) — Current security posture, controls, known limitations
- [Trust model](trust-model.md) — Trust topology and assumptions
- [Release gate](release-gate.md) — Release discipline framework
- [SAFE-DEFAULTS.md](SAFE-DEFAULTS.md) — Controls reference and deployment checklist
- [SPEC.md §7](../SPEC.md#7-security-model) — Normative security model
