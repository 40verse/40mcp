# Migrating from FastMCP

> **Status:** migration preview. This guide maps the main FastMCP primitives to their closest 40mcp equivalents and calls out intentional differences.

## When this page applies

FastMCP is a Python-first framework for building MCP servers. 40mcp is a Node-first bridge that turns REST, GraphQL, and HAR recordings into MCP tool surfaces. This page maps FastMCP primitives to the closest 40mcp equivalent and flags where the two products diverge on purpose.

## Primitives at a glance

| FastMCP concept | 40mcp equivalent | Notes |
|---|---|---|
| `FastMCP()` / `@tool` | `createRestBridge` + tool entries in a JSON config | Tools are declared as config, not decorated functions. Programmatic: `createRestBridge({ name, baseUrl, tools, auth })`. |
| `from_openapi(...)` | `loadOpenApiSpec(...)` | OpenAPI 3.x / Swagger 2.x → MCP tools. CLI: `40mcp from-openapi ./spec.json`. |
| `from_fastapi(...)` | *No direct equivalent.* | 40mcp bridges REST/GraphQL/HAR rather than importing route tables from a running Python app. If your start point is a live FastAPI app, export its OpenAPI spec and use `loadOpenApiSpec`. |
| `create_proxy(...)` | `connectStdio`, `connectSse`, or `40mcp link` CLI | A 40mcp "frontdoor" links N upstream MCP servers behind one authenticated surface. See [BRIDGE_VS_FRONTDOOR.md](./BRIDGE_VS_FRONTDOOR.md). |
| `add_middleware(...)` | `hooks.beforeRequest` / `afterRequest` at the HTTP boundary; `beforeDispatch` / `afterDispatch` at the dispatch boundary (both available as of 0.1.0-beta.7) | Hooks run around the outgoing HTTP call and, as of 0.1.0-beta.7, around tool dispatch itself. |
| `AuthProvider` | Per-call tenant scope + policy gates + sealed vault | 40mcp splits "who is calling" from "is the call allowed" from "what credential gets forwarded." See below. |

Where a cell says "no direct equivalent," we mean it literally — we would rather tell you than paper over the gap.

## Where the products diverge on purpose

40mcp is not FastMCP-in-Node. A few places it explicitly differs:

1. **Multi-tenant per-call auth is first-class, not a plugin.** Every dispatch carries a tenant scope; allowlists, blocklists, and credential selection resolve per call. See [trust-model.md](./trust-model.md).
2. **Policy gates gate tool dispatch, not just auth.** A tool can be marked `require_approval` independent of auth state, and the gate runs before the HTTP request leaves the process. See [SAFE-DEFAULTS.md](./SAFE-DEFAULTS.md).
3. **The HAR loader reverse-engineers APIs that have no spec.** Point 40mcp at a browser HAR and it infers tool definitions from observed traffic.
4. **The sealed vault is an at-rest secret store, not `process.env`.** Credentials are envelope-encrypted with AES-256-GCM and unsealed just-in-time. See the "Sealed Vault" section in [README.md](../README.md).
5. **The reverse bridge auto-publishes OpenAPI.** `40mcp reverse` takes a bridge and re-exposes it as REST + an OpenAPI document — the "tesseract" shape in [CONCEPT.md](../CONCEPT.md).

## Migrating an existing FastMCP config

A typical FastMCP server declares a handful of `@tool`-decorated functions and optionally pulls in an OpenAPI spec via `from_openapi`. The 40mcp equivalent is a JSON config: a top-level object with a `baseUrl`, an `auth` block (header / bearer / basic / OAuth2, sourced from env vars), and a `tools` array where each entry names the tool, its HTTP method and path, its input schema, and optionally a `response` transform for token-aware shaping. If you were using `from_openapi`, the direct path is `40mcp generate ./spec.json --out my-api.json` (deterministic, no LLM) followed by `40mcp serve my-api.json`. Hand-written tools port over one-for-one: parameters become an input schema, the HTTP call becomes `method` + `path`, and any post-processing becomes either a `response` transform or a `hooks.afterRequest` function.

## What 40mcp does not claim to be

In the spirit of [SPEC.md §3](../SPEC.md):

- **No agent runtime.** We do not embed or call an LLM.
- **No UI resource scheme** (no `ui://`, no rendered artifacts). Tool outputs are data.
- **No orchestration.** This isnt a harness, its a tool for your harness.

If those are things you need, FastMCP v3 (and its surrounding Python ecosystem) is a reasonable tool for the job. 40mcp is intentionally narrower.

## Where to go next

- [README.md](../README.md) — install, golden path, feature matrix.
- [SPEC.md](../SPEC.md) — security model, operational limits, non-goals.
- [docs/BRIDGE_VS_FRONTDOOR.md](./BRIDGE_VS_FRONTDOOR.md) — `serve` vs `link`.
- [docs/FRONTDOOR.md](./FRONTDOOR.md) — published SSE deployment patterns.
- [docs/COMPARISON.md](./COMPARISON.md) — side-by-side feature comparison across MCP bridges.
