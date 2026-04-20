# Lineage Note

This public repository was repackaged from an earlier development history to exclude development-only tooling, experimentation artifacts, and non-public infrastructure. Design decisions, security learnings, and release criteria were intentionally preserved in the documentation.

---

## What was removed

- **Private commit history** — Raw development commits, scan-round churn, and experimentation branches were not carried forward. The public history starts clean.
- **Internal harness** — The development environment included private orchestration, memory, and security-gating tooling that drove the adversarial review process. None of it is part of the 40mcp product and none is included.
- **Raw scan reports** — Multiple rounds of adversarial scanning produced detailed findings. The findings are not published; the lessons and fixes are.
- **Internal issue/PR discussion** — Private issue threads and review comments are not carried forward. The design rationale they contained is preserved in the lineage docs.

## What was preserved

- **The code** — All source code, tests, configs, and examples ship as-is from the final pre-release state.
- **Security posture** — [SECURITY.md](../SECURITY.md) documents the current controls, threat model, known limitations, and disclosure process.
- **Design intelligence** — Four lineage documents preserve the reasoning behind the code's current shape:
  - [Security evolution](security-evolution.md) — Lessons from multiple rounds of adversarial hardening
  - [Trust model](trust-model.md) — The three-tier trust topology and its assumptions
  - [Release gate](release-gate.md) — The decision framework for blocker vs follow-up triage
  - [SAFE-DEFAULTS.md](SAFE-DEFAULTS.md) — Controls reference and deployment checklist
- **Test suite** — A comprehensive test suite including a dedicated security invariant suite that covers SSRF, sanitization, tenant isolation, vault, webhook, policy, and schema boundaries (exact count tracked in CI).
- **Trust matrix** — 11 end-to-end scenarios exercising the three-tier trust model.
- **Changelog** — Full version history with security fixes documented.

## Why a fresh repository

The private history served its purpose: it enabled rapid iteration, aggressive adversarial review, and a development workflow that included orchestration tools not intended for public release. Carrying that history forward would:

1. **Expose development-only tooling** that is not part of the 40mcp product
2. **Create noise** that obscures the actual product evolution
3. **Include artifacts** (scan reports, harness configs, experiment branches) that have no value to users or contributors

A fresh repository is not an attempt to hide mistakes — the security evolution document explicitly describes the failure classes that were found and fixed. It is a curation decision: ship the intelligence, not the noise.

## For contributors

If you're contributing to 40mcp and want to understand *why* the code has a particular defensive shape, start with:

1. [Security evolution](security-evolution.md) — The six core lessons
2. [Trust model](trust-model.md) — The trust topology that controls are designed to protect
3. [SECURITY.md](../SECURITY.md) — The current posture and known limitations
4. `src/security/invariants/` — The test suite that enforces the security contract

These documents are living artifacts. If you discover a new lesson during development, add it to the appropriate document.
