# 40mcp vs FastMCP

## What this is

40mcp and [FastMCP](https://github.com/jlowin/fastmcp) both bridge external APIs into the MCP protocol, and both are actively maintained. They differ by stack, architecture, and the operator archetype they optimize for. This page names those differences plainly — it is not a dunk, and it is not a benchmark. Where 40mcp is behind, the table says so.

---

## At a glance

| Capability | 40mcp | FastMCP |
|---|---|---|
| Stack | Node.js (>=18) | Python (>=3.10) |
| License | MIT | Apache-2.0 *(last verified 2026-04-19)* |
| REST bridge | Yes | Yes |
| OpenAPI ingest | Yes — 3.x + Swagger 2.x | Yes — via `FastMCP.from_openapi` |
| GraphQL ingest | Yes — introspection loader | Partial — community/custom; no first-class loader |
| HAR loader (browser traffic → tools) | Yes — unique, no spec needed | No |
| Reverse bridge (MCP → REST + auto-OpenAPI) | Yes | Partial — MCP-as-ASGI exists; no auto-OpenAPI emission |
| Multi-tenant per-call auth | Yes — per-call auth context, allowlist/blocklist | No — available only via middleware |
| Policy gates on tool dispatch | Yes — `allow` / `deny` / `require_approval` / `log_only` | No — upstream closed this as not-planned |
| Sealed credential vault | Yes — AES-256-GCM envelope, JIT JWT, daemon mode | No |
| Token-aware response shaping | Yes — `pick` / `omit` / `limit` / `tokenBudget` | No |
| Compound tool chains as first-class tools | Yes — `chain` config, depth-guarded | Partial — expressible via middleware / manual composition |
| Webhook ingestion → tool dispatch | Yes — HMAC-validated | No |
| OAuth 2.1 / DCR provider shims | Partial — header / bearer / basic / generic OAuth2 | Yes — broad provider set (GitHub, Google, Azure, WorkOS, Auth0, …) |
| OTEL / structured tracing | Partial — structured logs today, OTEL on roadmap | Yes |
| MCP Apps / UI resources (`ui://`) | No — explicit non-goal | Yes |

---

## Use 40mcp when…

- You need **multi-tenant isolation** — per-call auth context, allowlist/blocklist per tenant.
- You need **policy governance** — human-in-the-loop approval gates on dangerous tools before dispatch.
- You care about **token budgets** — response shaping that caps context burn before tools dump 50k tokens of JSON into the model.
- You need **HAR-based API archaeology** — adopting an API that has no OpenAPI spec, only browser traffic.
- You need a **sealed credential vault** — AES-256-GCM envelope encryption with JIT JWTs and a daemon that never exposes the master passphrase to bridge processes.
- Your operator stack is **Node.js** and you want one production dependency (`@modelcontextprotocol/sdk`) plus Node builtins.

## Use FastMCP when…

- Your codebase is **Python-first** and you want decorator ergonomics (`@mcp.tool`) over config files.
- You want the **widest OAuth / IdP provider surface available today** — GitHub, Google, Azure, WorkOS, Auth0, and friends ship as first-class providers.
- You want **MCP Apps / UI resources** (`ui://`) — interactive UI surfaced to the client.
- You want **in-process FastAPI → MCP conversion** so an existing FastAPI app can be re-exposed as MCP tools without a separate bridge process.

---

## Deliberate divergence

40mcp bets on **policy, multi-tenancy, and production-safe defaults**: sealed credentials, approval gates, token-aware shaping, SSRF blocks, input validation, and a vault daemon model that keeps the master passphrase out of any bridge process. It assumes the operator is shipping a surface to agents they don't fully trust.

FastMCP bets on **OAuth provider breadth, decorator ergonomics, and a UI-resource future**. It assumes the operator is a Python author composing tools and wants the ceiling raised on what MCP clients can render.

Neither bet is wrong. They optimize for different users. A team running an internal Python service with GitHub-authenticated users will reach for FastMCP and be right. A team publishing a multi-tenant MCP surface over SSE with gated write tools and a credential vault will reach for 40mcp and be right.

## Not a benchmark

This is a capability comparison, not a performance claim. Neither project publishes production-workload benchmarks, and this document does not attempt to. If throughput, cold-start, or memory footprint matters for your deployment, measure both against your own workload — both are fast enough that architecture and feature fit will dominate the decision.

---

*Something out of date or unfair? Open an issue. We'd rather correct this page than leave it wrong.*
