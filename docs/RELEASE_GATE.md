# Release Gate

How 40mcp decides what blocks a release and what doesn't.

This document distills the release discipline developed during multiple rounds of adversarial security scanning. The process produced a framework for triaging findings that is reusable across future releases.

---

## The problem release gates solve

Adversarial scanning generates findings faster than a team can fix them. Without a decision framework, every finding feels like a blocker, leading to one of two failure modes:

1. **Scan anxiety** — Every finding is treated as critical. The release never ships because there's always one more thing to fix.
2. **Scan fatigue** — Findings pile up unaddressed. The release ships with real vulnerabilities because the team stopped reading the reports.

A release gate replaces both failure modes with a structured decision: *"Is this finding a trust-boundary violation that allows real exploitation on a documented code path?"*

---

## What counts as a release blocker

A finding is a **blocker** if it meets ALL of these criteria:

1. **Trust boundary violation** — The finding crosses a documented trust boundary (see [trust-model.md](trust-model.md))
2. **Exploitable on a documented path** — The attack works through 40mcp's public API, CLI, or documented config patterns
3. **Real impact** — The exploit produces credential exposure, unauthorized access, data exfiltration, or code execution

### Hard blocker categories

| Category | Example | Why it blocks |
|----------|---------|---------------|
| **SSRF to cloud metadata** | `assertSafeUrl` bypass reaching `169.254.169.254` | Credential theft from cloud environments |
| **Credential exposure** | Auth tokens in stdout, vault plaintext leak | Direct secret compromise |
| **Prompt injection forwarding** | Upstream text reaching LLM without sanitization | Adversarial control of LLM behavior |
| **Tenant isolation failure** | Tenant A accessing Tenant B's data or tools | Multi-tenant trust violation |
| **Silent auth degradation** | Vault daemon down → requests proceed unauthenticated | Security boundary silently removed |
| **Policy gate bypass** | `require_approval` tool executing without approval | Authorization boundary violated |

---

## What does NOT block a release

A finding is a **follow-up** (not a blocker) if any of these apply:

| Criterion | Example | Disposition |
|-----------|---------|-------------|
| **Theoretical, no demonstrated exploit** | "This *could* be exploited if..." without a working PoC | Document as known limitation |
| **Requires compromised environment** | Attacker has shell access to the host | Out of threat model (trusted operator assumption) |
| **Defense-in-depth improvement** | Adding a second validation layer where one already works | Track as enhancement |
| **Documentation gap** | Missing caveat in README, unclear threat model section | Fix in docs, don't block code release |
| **Operator misconfiguration** | Using `allowPrivate: true` in production | Document the risk; operator is trusted |
| **Protocol limitation** | MCP stdio has no authentication | Out of 40mcp's control |

---

## Decision rule for new findings

```
New finding arrives
    │
    ├─ Does it cross a trust boundary?
    │   NO → Follow-up (document if interesting)
    │
    ├─ Is there a working exploit on a documented path?
    │   NO → Follow-up (document as theoretical risk)
    │
    ├─ Does the exploit produce real impact?
    │   NO → Follow-up (defense-in-depth)
    │
    └─ YES to all three → BLOCKER
        │
        ├─ Can it be fixed without architectural change?
        │   YES → Fix in this release
        │   NO  → Evaluate: document as known limitation
        │         with explicit scope boundary
```

---

## Blocker vs follow-up: worked examples

### Blocker: SSRF via `::127.0.0.1`

- **Trust boundary:** Outbound URL validation (bridge → upstream API)
- **Exploit:** `::127.0.0.1` normalizes to `::7f00:1` via WHATWG URL parser, bypassing IPv4 loopback checks
- **Impact:** SSRF to localhost services, potential cloud metadata access
- **Decision:** BLOCKER — trust boundary violation with working exploit
- **Fix:** `tryDecodeIPv4FromIPv6` decodes and re-validates

### Follow-up: DNS rebinding via bridge `baseUrl`

- **Trust boundary:** Outbound URL validation
- **Exploit:** Hostname resolves to safe IP at load time, private IP at dispatch time
- **Impact:** Potential SSRF to internal services
- **Decision:** FOLLOW-UP — requires specific network conditions (attacker-controlled DNS), and `connectSse` now pins resolved IPs. Bridge `baseUrl` validated at load time; runtime mitigation requires network-level controls.
- **Disposition:** Documented as known limitation in SECURITY.md

### Blocker: Mixer missing result sanitization

- **Trust boundary:** Transport egress (bridge → LLM)
- **Exploit:** Upstream MCP server returns `"Ignore all previous instructions..."`, forwarded verbatim
- **Impact:** Prompt injection reaches LLM without sanitization
- **Decision:** BLOCKER — trust boundary violation on documented path
- **Fix:** Replace `stripInternalEnvelopes` with `sanitizeTransportEgress` in mixer handler

### Follow-up: `/health` session count exposure

- **Trust boundary:** None (informational endpoint)
- **Exploit:** Attacker learns number of active SSE sessions
- **Impact:** Reconnaissance value only — no direct exploitation
- **Decision:** FOLLOW-UP — no trust boundary violation
- **Disposition:** Disabled by default (`exposeSessionCount: false`)

---

## Pre-1.0 vs 1.0 expectations

| Aspect | Pre-1.0 | 1.0 |
|--------|---------|-----|
| **Security blockers** | Zero open | Zero open |
| **Known limitations** | Documented in SECURITY.md | Documented + mitigations where feasible |
| **Test coverage** | Invariant suite covers all security-critical paths | Same + CI-enforced on every PR |
| **Trust matrix** | All scenarios pass locally | All scenarios pass in CI |
| **Framing** | "Security controls (see SAFE-DEFAULTS.md)" | Same — no overclaiming |
| **Breaking changes** | Possible with notice | Semver-protected |

The key difference: pre-1.0 is "we believe this is correct and have tested it thoroughly." 1.0 is "we have also automated the verification and committed to stability."

---

## The trust matrix

The trust matrix is a suite of 11 end-to-end scenarios that exercise the three-tier trust model:

| Tier | Scenarios |
|------|-----------|
| Sovereign → Operator | Vault seal/unseal, vault rotation, daemon auth |
| Operator → Bridge | Policy gate enforcement, tenant isolation, config validation |
| Bridge → Upstream | SSRF blocking, schema sanitization, response sanitization |

The matrix must pass at 11/11 before any release. A failing scenario is an automatic blocker regardless of the decision tree above — it means a trust boundary is not holding.

---

## Further reading

- [SECURITY.md](../SECURITY.md) — Current security posture
- [Security evolution](security-evolution.md) — How the hardening process worked
- [Trust model](trust-model.md) — The three-tier topology these gates protect
