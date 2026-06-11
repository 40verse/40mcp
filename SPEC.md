# 40mcp — Product Specification

> **This is the normative document.** README covers usage; CONCEPT.md covers vision; this document covers the release contract and what must be true before a 1.0 stable release.
>
> Version: see [`package.json`](package.json).

---

## 1. Problem Statement

MCP (Model Context Protocol) is Anthropic's open standard — often called "USB-C for AI" — that lets clients like Claude Desktop, Cursor, and others securely call external tools. Most of the world's functionality lives behind REST APIs, GraphQL endpoints, or undocumented HTTP surfaces. The gap between "an API exists" and "an LLM can use it" is the problem 40mcp solves.

**Primary use cases:**

1. **Rapid tool exposure** — Turn any documented API (OpenAPI, GraphQL) into an MCP server without writing code.
2. **Undocumented API discovery** — Capture real browser traffic (HAR) and generate tool definitions automatically.
3. **Production bridging** — Deploy a multi-tenant, token-budget-aware, security-hardened MCP layer in front of existing APIs.
4. **API archaeology** — Point at a legacy system with no documentation; generate a machine-readable contract from behavioral evidence. (See §11.)

**Who this is for:** Backend developers, AI engineers, and platform teams who need to expose existing HTTP infrastructure to LLM-based agents.

**The category 40mcp occupies:** There is no established name for this class of tool. It is not an API gateway (no rate limiting, no auth server), not an MCP server generator (no static codegen), and not a middleware proxy (no runtime traffic handling). Closest description: **agentic API adapter** — a layer that makes existing HTTP infrastructure legible to LLM agents without requiring teams to rewrite, re-document, or redeploy anything.

---

## 2. 1.0 Scope

### Shipped commands (CLI)

| Command | What it does |
|---------|-------------|
| `serve <config>` | Start MCP server from a JSON/JS config file |
| `from <input>` | Auto-detect format (OpenAPI, GraphQL, HAR, plugin) and start |
| `from-openapi <spec>` | OpenAPI 3.x / Swagger 2.x → MCP server |
| `from-graphql <endpoint>` | GraphQL introspection → MCP server |
| `from-har <file>` | HAR traffic recording → MCP server |
| `mix <c1> <c2> [...]` | Combine N API configs into one MCP server |
| `reverse <config>` | MCP tools → REST API + auto-generated OpenAPI spec |
| `link <.mcp.json\|cmd>` | Connect to existing MCP servers, re-expose tools |
| `generate <spec\|--describe>` | Generate config from spec (deterministic) or LLM prompt |
| `inspect <config>` | List tools without starting server |
| `validate <config>` | Validate config; report errors and warnings |
| `init` | Scaffold a starter config interactively |
| `doctor <config>` | Diagnose a config: auth, reachability, tool-shape checks |
| `vault <sub>` | Sealed vault ops — `init`, `seal`, `list`, `rotate`, `rotate-kek`, `delete`, `recover`, `daemon` |
| `settings <sub>` | Settings ops — `show` (display merged settings + env overlays) |

### Shipped modules (programmatic API)

The following exports from `src/index.js` are part of the supported public API:

```
createRestBridge()           Core bridge engine
loadConfig()                 Load .json or .js (ESM) config
loadOpenApiSpec()            OpenAPI 3.x + Swagger 2.x loader
loadGraphqlSchema()          GraphQL introspection loader
loadHarFile()                HAR traffic → tool definitions
loadFromAny()                Auto-detect loader
registerLoader()             Plugin system entry point
listLoaders()                Enumerate registered loaders
createMixer()                Multi-server mixing
executeChain()               Compound tool chains
applyResponseTransform()     Token-aware response shaping
createReverseBridge()        MCP → REST bridge
generateOpenApiSpec()        MCP tool set → OpenAPI 3.1 document
connectStdio()               MCP-to-MCP client (stdio)
connectSse()                 MCP-to-MCP client (SSE)
connectStreamableHttp()      MCP-to-MCP client (Streamable HTTP)
connectFromConfig()          MCP-to-MCP client (from .mcp.json)
connectMany()                Multi-server MCP aggregator
createWebhookListener()      HTTP webhook → tool dispatch
createTenantScope()          Per-call auth context
tenantAuthHook()             Tenant-aware auth-header resolver
createVault()                Sealed credential vault
initVault() / recoverVault() Vault lifecycle helpers
createVaultDaemonClient()    Vault daemon IPC client (no passphrase in bridge processes)
createPolicyGate()           Human-in-the-loop approval
createStdinApprovalHandler() CLI approval prompt
createCallbackApprovalHandler() Programmatic approval (CI, audit, external systems)
validateConfig()             Config validation (throw-free)
assertValidConfig()          Config validation (throws on error)
generatePrompt()             LLM prompt pair generator
generateFromSpec()           Deterministic config generator
parseGeneratedConfig()       Parse LLM-generated config output
tui                          Terminal UI primitives (NO_COLOR compliant)
BridgeError, BridgeErrorCode,
AuthError, ApiError, ChainError,
apiErrorFromStatus()         Structured error surface
AuditEventCode               Frozen enum of audit-log event names
                             (e.g. `TENANT_ACL_DENY`, `POLICY_DENIED`)
```

Transport exports (from `40mcp/transport`): `createStdioTransport`, `createSseTransport`, `createTransport`.

Subpath exports published in `package.json` `exports`: `./loaders`, `./compose`, `./transport`, `./reverse`, `./transforms`, `./webhook`, `./tenant`, `./security`, `./policy`.

### Steering module (removed)

The steering module (`40mcp/steering` — forced-inference write classification for agent memory systems) was removed pre-1.0. It was orthogonal to the bridge by its own definition and widened the 1.0 surface without a consuming use case. The `_steering` envelope key remains **reserved** (see below) so no operator or upstream can shadow it and a future external steering package can reclaim it without a breaking envelope change. Configs that still carry `tool.steering`, the `--steering` flag, or `settings.frontdoor.steering` fail validation with a removal message rather than being silently ignored.

### Reserved envelope keys

The bridge reserves a set of envelope key names that operators must not emit on tool result payloads. Every reserved key is stripped on all egress paths (MCP `CallToolRequestSchema`, mixer `CallToolRequestSchema`, bridge `dispatch()`, reverse bridge REST egress, webhook sync response) via the shared `stripInternalEnvelopes` / `stripEgressEnvelopes` / `sanitizeTransportEgress` walkers in `src/bridge.js`.

The following keys are **reserved — currently unused — will carry the listed metadata in a future minor**. Operators must not emit keys with these names; they are stripped on all egress paths so introducing the feature later cannot be confused with, or shadowed by, an operator- or upstream-emitted value.

- `_trace` — reserved for future OpenTelemetry / W3C traceparent context attached per dispatch.
- `_cost` — reserved for future per-tool cost attribution (tokens, wall-clock latency, upstream spend).
- `_warnings` — reserved for future non-fatal dispatch warnings surfaced alongside successful results.
- `_version` — reserved for future per-tool API version advertised by the bridge on each response.
- `_correlation` — reserved for future cross-instance request correlation identifier.

Reserving these names early means the strip walkers already scrub any collision the day the feature ships, so future enablement is a pure addition rather than a breaking envelope change.

### Tool-name invariant

Tool naming is pinned for the 1.0 line. Operators and community configs can rely on these rules not changing pre-1.0. (For context on why this is locked early: upstream MCP servers have historically shipped breaking separator changes — e.g. FastMCP flipped from `___` to hash-based routing in their issue #3824. 40mcp commits to its convention pre-tag so operator muscle memory survives.)

| Property | Value |
|----------|-------|
| **Separator** | `.` (dot) |
| **Prefix regex** | `^[a-zA-Z0-9_-]{1,64}$` |
| **Tool-name regex** | `^[a-zA-Z0-9_-]{1,64}$` (same charset and bound as prefix) |
| **Fully-qualified form** | `<prefix>.<tool_name>` |
| **Max fully-qualified byte length** | 129 bytes (64 + 1 + 64) |

**Collision behaviour.** Duplicate fully-qualified names across linked upstreams fail loudly at link time. This is already enforced by `src/connect.js` (`connectMany`) and `src/compose/mixer.js` — both raise a `BridgeError` (`CONFIG_INVALID`) naming the conflicting tool and suggesting prefix disambiguation. Collision is caught before the frontdoor publishes any tools; there is no silent drop.

**Commitment.** No naming-scheme change will ship pre-1.0. The separator, charset, length bound, and fully-qualified form above are the contract. Operators can pin muscle memory and scripts against `<prefix>.<tool_name>` with the regex above and expect it to hold through the 1.0 tag.

### Architectural interfaces

40mcp exposes three named seams — `Provider`, `Transform`, and a two-pair `Hooks` taxonomy (HTTP boundary + tool-call boundary) — behind which tool-source loaders, response transforms, and hook points are being renormalised. Each seam is a duck-typed interface; `instanceof` is not required.

#### Provider

Anything that emits `{ tools, resources?, prompts? }`:

```js
interface Provider {
  name: string;           // stable identity for audit logging
  async components(): Promise<{ tools: Tool[], resources?: Resource[], prompts?: Prompt[] }>;
  close?(): Promise<void>; // optional, for providers holding network handles
}
```

Existing loaders (`loadOpenApiSpec`, `loadGraphqlSchema`, `loadHarFile`, `connectStdio`, `connectSse`, `createReverseBridge`) are wrapped into Provider-conformant objects under `src/providers/`. Legacy loader exports are unchanged.

#### Transform

Anything that rewrites components at build-time, dispatch args at call-time, or the result payload at call-time:

```js
interface Transform {
  name: string;
  applyToComponents?(components): components;
  applyToDispatch?(toolName, args, context): args;
  applyToResult?(toolName, result, context): result;
}
```

All three methods are optional; most transforms implement only one. Policy gates and tenant scope are expressible as Transforms.

### Hook taxonomy

40mcp hooks run at two distinct boundaries. The pairs MUST NOT be collapsed — `beforeRequest`/`afterRequest` concern themselves with the HTTP call to the upstream; `beforeDispatch`/`afterDispatch` concern themselves with the MCP `tools/call` that 40mcp is handling. Future features like OTEL instrumentation and RFC 8693 delegation attach to the dispatch pair.

| Hook | Boundary | When it fires | Typical use |
|------|----------|---------------|-------------|
| `beforeRequest` | HTTP | Per outbound HTTP call from bridge to upstream | Auth header injection, request logging, retry prep |
| `afterRequest` | HTTP | Per inbound HTTP response | Response logging, rate-limit metadata |
| `beforeDispatch` | MCP tool-call | Per `tools/call` 40mcp is handling, before the dispatch body | OTEL span start, RFC 8693 delegation token mint, policy DSL enforcement |
| `afterDispatch` | MCP tool-call | Per `tools/call`, after response-transform + sanitize, before MCP egress | OTEL span close, cost attribution, correlation recording |

### Pipeline order

The dispatch pipeline is ordered. Transforms, hooks, and egress sanitization each run at a specific, named position, and extensions are written against these positions. Any ordering change pre-1.0 is a **BREAKING** change and requires a CHANGELOG entry.

```
inbound MCP tools/call
  → auth / tenant resolve
  → Transform.applyToDispatch
  → hooks.beforeDispatch
  → dispatch
      → hooks.beforeRequest
      → outbound HTTP fetch
      → hooks.afterRequest
  → Transform.applyToResult
  → egress-sanitize
  → hooks.afterDispatch
  → outbound MCP tools/call response
```

`egress-sanitize` intentionally runs *after* `Transform.applyToResult` and *before* `hooks.afterDispatch`. It is the reserved-envelope invariant point (see "Reserved envelope keys" above) and it must be downstream of `Transform` so that a Transform cannot reintroduce a reserved key by accident or by malice.

---

## 3. Non-Goals for 1.0

The following are explicitly **not** in scope for the 1.0 release:

- **Federation** — Multiple 40mcp instances discovering and meshing with each other.
- **Live monitoring** — HAR-mode proxy that continuously refines tool definitions from live traffic.
- **VS Code extension** — Visual tool definition builder.
- **Workflow engine integration** — Hosted workflow orchestration backed by 40mcp. Omitted from this release surface.
- **gRPC / WebSocket / SOAP loaders** — Plugin system ships; these specific loaders do not.
- **Shopify / Twilio community configs** — May be added post-1.0.
- **LLM runtime** — 40mcp generates configs and prompts; it does not embed or call an LLM itself.
- **Authentication server** — 40mcp forwards credentials; it is not an OAuth2 authorization server.
- **Built-in rate limiting or circuit breaking** — Left to downstream APIs or external gateways (e.g., AWS API Gateway, nginx, Kong).

---

## 4. Compatibility Matrix

### Runtime

| Requirement | Constraint |
|-------------|-----------|
| Node.js | `>=18.0.0` (>=20 recommended for production) |
| npm | `>=8.0.0` (ships with Node 18) |
| OS | Linux, macOS, Windows |
| Architecture | x64, arm64 |

### Tested Node versions

| Version | Status |
|---------|--------|
| 18.x LTS (Hydrogen) | Supported |
| 20.x LTS (Iron) | Supported |
| 22.x (Current) | Supported |

### Dependencies

| Package | Version | Role |
|---------|---------|------|
| `@modelcontextprotocol/sdk` | `^1.29.0` | MCP wire protocol |

Everything else is Node.js built-ins (`node:http`, `node:crypto`, `node:fs`, etc.).

### MCP SDK compatibility

40mcp exposes standard MCP `Server` and `Client` objects from the SDK. It is compatible with any MCP client that speaks the Model Context Protocol (Claude Desktop, Cursor, Windsurf, VS Code Copilot, etc.).

---

## 5. Pre-1.0 API Stability

All surfaces documented in §2 are functional and covered by the test suite. Until a `1.0.0` release, this project follows pre-1.0 semver: minor version bumps may include breaking changes; patch versions are backwards-compatible fixes.

One module carries an explicit "may change between minor releases" caveat pre-1.0:

- **AI generation — prompt mode (`generatePrompt`)** — Prompt format is not locked.

Everything else is intended to remain interface-compatible across minor releases pre-1.0 where practical, and may gain new options.

### Verification status

Each integration surface below has an acceptance test. These tests run under `npm run test:all`.

| Surface | Coverage |
|---------|----------|
| **Reverse bridge** | Round-trip: generate OpenAPI spec, reload via `loadOpenApiSpec`, verify tool parity |
| **Multi-tenant** | Concurrent isolation and access controls |
| **Sealed vault** | Management API covering set, rotate, delete, list, and token operations |
| **Policy gates × tenants** | Per-tenant decisions with policy enforcement |
| **MCP linking** | Tool collision detection and collision handling |
| **Webhook ingestion** | HMAC validation and event routing |

Note: See integration test suite for comprehensive coverage.

---

## 6. Config Contract

### Schema versioning

Config files do not currently include a `$schema` version field. The implied version is `1`. When a breaking schema change is required, a `"version": 2` field will be added and a migration guide published.

### Validation behavior

`40mcp validate <config>` exits `0` (valid) or `1` (invalid). Warnings are non-fatal. Errors block `serve`.

### Deprecation policy

- Deprecated config fields will emit a `WARN` via `validate` for one minor release cycle before removal.
- No config field will be removed in a patch release.
- Breaking schema changes increment the major version.

### Config loading

Configs can be `.json` or `.js` (ESM default export). The `.js` form allows dynamic values (env lookups, computed baseUrl).

---

## 7. Security Model

### What 40mcp is designed to enforce on documented paths

- **Credential logging prevention** — Auth headers, bearer tokens, basic auth credentials, and vault passphrases are not written to stdout, stderr, or log files on documented code paths. Untested operator extensions or custom middleware are outside this scope.
- **No plaintext storage (sealed vault path)** — When using the sealed vault, API keys are encrypted with AES-256-GCM at rest. Plaintext keys do not persist to disk on that path. Credentials passed via env vars or unsupported operator patterns are outside this scope.
- **URL scheme validation** — `loadOpenApiSpec` and `loadGraphqlSchema` reject `file://` and `data:` URLs when loading remote specs, reducing SSRF surface on those loaders.
- **Input validation** — Tool arguments are validated against the tool's `inputSchema` before dispatch. Malformed inputs are rejected with structured errors.
- **Injection hardening** — Path parameters, query strings, and body fields are serialized, not interpolated into shell or SQL contexts. 40mcp does not exec user input.
- **Policy gates** — `require_approval` tools block execution until a human approves the call.
- **Upstream schema sanitization** — `connectStdio`/`connectSse` strip `$ref`, `$schema`, `$defs`, and prototype-poisoning keys (`__proto__`, `constructor`, `prototype`) from upstream MCP server tool schemas before re-exposing them (`src/core/sanitize.js`, shared with the OpenAPI/GraphQL/HAR loaders). Prevents schema-based prototype pollution and unbounded memory consumption from adversarial upstream servers.
- **Prompt-injection pattern detection** — Tool and parameter descriptions sourced from untrusted specs/upstreams pass through `hasPromptInjection` / `sanitizeDescription` (`src/core/sanitize.js`). Common "ignore previous instructions" and role-hijack markers are neutralised before being surfaced to the MCP client.
- **SSE idle connection eviction** — SSE transport closes connections that receive no messages for `idleTimeoutMs` (default 5 min). Mitigates Slow Loris resource exhaustion.
- **Plain HTTP warning + connection-time IP pinning** — `connectSse` emits a stderr warning when the target URL uses plain HTTP to a non-loopback host. It additionally resolves and pins plain-HTTP transport URLs to the connection-time IP for the session, reducing mid-session DNS rebinding risk on that path (`src/connect.js`). This is a path-specific mitigation, not a blanket DNS-rebinding guarantee — see the "DNS rebinding risk (known limitation)" note below.
- **Reverse-bridge anti-sniffing / anti-framing headers** — every response from `createReverseBridge` sets `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`, applied uniformly across success, error, CORS, and 404 paths (`src/reverse/server.js`). Prevents MIME-sniffing based XSS on error bodies and clickjacking of any future HTML surface.
- **CRLF refusal on hook-supplied headers** — `beforeRequest` hooks and tenant auth hooks that return new request headers have both keys and values validated. Keys must match `[a-zA-Z0-9-]+`; values may not contain control characters below 0x20 (except `\t`) or the NUL byte. Stops header-injection attempts at the bridge boundary, independent of the underlying fetch runtime (`src/core/client.js`).

### What 40mcp does not guarantee

- **The security of downstream APIs.** 40mcp forwards requests; it cannot enforce the security posture of the API it wraps.
- **Authentication of MCP clients.** stdio transport has no authentication; SSE transport inherits whatever the HTTP server provides. Network-level access control is the operator's responsibility.
- **Secrets management at scale.** The sealed vault is suitable for development and single-node deployments. For high-availability or team secrets management, use an external secrets store (HashiCorp Vault, AWS Secrets Manager, etc.) and pass values via env vars.
- **Rate limiting.** 40mcp does not enforce rate limits on tool calls. Downstream API limits apply.

### Threat model

40mcp is designed to be run by a **trusted operator** who controls both the config and the environment. It is not designed to safely execute configs from untrusted sources. Treat a 40mcp config file like executable code.

**Operator trust assumption:** The operator controls the config file, the environment variables, the network environment, and the deployment host. 40mcp enforces controls *within* that perimeter — it does not protect against a compromised operator.

**Inbound surface (MCP client → bridge):**

| Risk | Mitigation |
|------|-----------|
| Prompt injection via tool arguments | Tool args validated against `inputSchema` before dispatch; reserved internal keys (`_tenant`, `_steering`) are stripped |
| Prototype pollution via malformed input | `setByPath` / `getByPath` refuse `__proto__`, `constructor`, `prototype` keys |
| Tenant escalation in multi-tenant mode | `_tenant` is set at the session boundary and propagated internally; callers cannot override it |
| Schema injection from upstream MCP servers | `connectStdio` / `connectSse` strip prototype-poisoning keys from upstream schemas |

**Outbound surface (bridge → upstream API):**

| Risk | Mitigation |
|------|-----------|
| SSRF to cloud metadata (AWS IMDS, GCP, Azure) | `assertSafeUrl` blocks `169.254.x` unconditionally; cloud metadata hosts denied by name |
| SSRF via loopback hostnames (`localhost`) | Loopback hostname denylist; `localhost`, `ip6-localhost`, etc. blocked when `allowPrivate: false` |
| SSRF via private RFC-1918 ranges | Blocked by default at the loader layer (`loadOpenApiSpec`, `loadGraphqlSchema`, `assertSafeUrl`). `createRestBridge` defaults to `allowPrivate: true` so local-dev `baseUrl: http://127.0.0.1` works; set `strictSsrf: true` in production. Cloud metadata is blocked on both layers. |
| SSRF via IPv6 ULA / multicast | `fc00::/7` and `ff00::/8` blocked unconditionally |
| SSRF via IPv4-compatible IPv6 | `::7f00:1` (= `::127.0.0.1`) decoded and re-validated against IPv4 rules |
| Credential exfiltration via env var in URL | Secret-named env vars (`TOKEN`, `PASSWORD`, `API_KEY`, etc.) refused in template substitution |
| Credential exfiltration via embedded URL auth | `user:pass@host` form rejected by URL parser |

**DNS rebinding risk (known limitation):** 40mcp validates URLs at config load and bridge creation time. DNS rebinding attacks — where a hostname resolves to a safe address at validation time but a private address at dispatch time — are not mitigated at the dispatch layer. Operators running on shared or adversarial networks should use `strictSsrf: true` and restrict outbound DNS.

**Prompt injection via configs:** Config `description` fields, tool names, and path templates are passed to MCP clients as-is. A malicious community config can embed instructions that influence an LLM. Review community configs before use — treat them like code, not data.

---

## 8. Operational Limits

| Limit | Default | Config override |
|-------|---------|----------------|
| Chain recursion depth | 10 | `config.chain.maxDepth` |
| Token budget — generator-time default (HAR / `generateFromSpec` / `from-*` CLI) | 4000 tokens | `--token-budget <n>` / `generateFromSpec({ tokenBudget })` |
| Token budget — runtime transform | unset (no truncation) | `tool.response.tokenBudget` on each tool |
| SSE port | 8080 | `--sse <port>` or `config.transport.port` |
| SSE idle timeout | 300000 ms (5 min) | `idleTimeoutMs` on `createSseTransport`; set `0` to disable |
| HAR min observations per endpoint | 1 | `--min-observations <n>` |
| OAuth2 token refresh window | 60 seconds before expiry | Not configurable |
| Concurrent OAuth2 refresh coalescing | All in-flight requests wait for one refresh | Not configurable |

**Request size:** 40mcp forwards the response body from the downstream API. It applies transforms (pick, omit, limit, tokenBudget) before returning to the MCP client, but does not enforce a hard cap on upstream response size. Set `tokenBudget` if downstream payloads are large.

**Timeouts:** 40mcp does not currently set a default HTTP timeout on downstream requests. Use `config.auth.timeout` (ms) if your API can hang.

**SSE sessions:** SSE transport keeps one persistent HTTP connection per MCP client session. Global session limit defaults to 100 (`maxSessions`). Per-IP session limit defaults to 10 (`maxSessionsPerIp`) — returns 429 when exceeded. Idle connections are closed after 5 minutes with no messages (`idleTimeoutMs`, configurable). The `/health` endpoint does not expose session count by default (`exposeSessionCount: false`).

---

## 9. Release Criteria for 1.0.0

All of the following must be true before tagging `1.0.0`:

### Tests

- [x] `npm run test:all` passes with zero failures (exact count tracked in CI; do not hardcode here)
- [x] Integration tests verified in CI (Node 18, 20, 22 matrix)

### CI

- [x] `.github/workflows/ci.yml` added — lint, test matrix (Node 18 / 20 / 22), and packaged-install smoke on every PR
- [ ] CI matrix green on Node 18.x, 20.x, 22.x (Linux) — verified on first public push
- [ ] `npm run smoke-test` passes in CI — verified on first public push

### Packaging

- [x] `npm pack --dry-run` shows correct file set (exact numbers re-checked on tag)
- [x] `npm run smoke-test` passes locally
- [x] No dev-only files shipped (`!src/**/*.test.js`, `!src/red-team/` excluded)

### Documentation

- [x] README leads with install, compatibility, and examples
- [x] SPEC.md complete (this document)
- [ ] CHANGELOG.md entry written for 1.0.0
- [x] Doc references don't hardcode drifting counts

### Publish

- [ ] Version bumped to `1.0.0` in `package.json` and `CHANGELOG.md`
- [ ] `NPM_TOKEN` secret configured in GitHub repository
- [ ] `.github/workflows/publish.yml` added
- [ ] GitHub release created and tagged `v1.0.0`
- [ ] `npm publish` triggered by GitHub release (provenance enabled)

---

## 10. Out of Scope for 1.0

The following items are out of scope for the 1.0 release:

- HAR-mode live proxy (continuous tool refinement from real traffic)
- Federation (multi-instance mesh)
- VS Code extension (visual tool builder)
- Shopify, Twilio community configs
- gRPC / WebSocket / SOAP loader plugins
- Stable `link` and `generate --describe` interfaces

### Version 2.0 trajectory

The integration surfaces (reverse bridge, webhook ingestion, multi-tenant, vault, policy gates, MCP linking) are not independent — they converge on a second-order capability that 1.0 does not name:

**1. Self-configuring** — Reverse bridge + AI generation form a closed loop: capture undocumented traffic (HAR) → generate tool definitions → expose as MCP → re-expose as REST with auto-generated OpenAPI spec. The output is a machine-readable contract for an API that had no contract. 40mcp can reconstruct its own configuration from behavioral evidence. (Proven: `test/self-referential.test.js` end-to-end; `test/self-referential-loop.test.js` smoke.)

**2. Event-reactive** — MCP linking + webhook ingestion compose into an event-driven orchestration bus. An incoming Stripe payment, GitHub push, or PagerDuty alert can trigger a tool call on a linked MCP server — which may itself be another 40mcp instance. This is agent workflow triggering built from two features that appear unrelated.

**3. Policy-governed** — Policy gates + multi-tenant compose into a delegated authorization layer. Different tenants can have different approval requirements for the same tool. Tenant A's `delete_record` is auto-approved; Tenant B's requires human sign-off. This is not a bridge feature — it is a lightweight authorization policy engine for agentic systems.

**V2 in one sentence:** 40mcp 2.0 aims to make many existing APIs governable, composable, and reusable as agent tool surfaces with minimal custom code — self-configuring, event-reactive, and policy-governed by default.

The trajectory is: **bridge (1.0) → fabric (2.0)**.

---

## 11. Architectural Capabilities

This section names three emergent capabilities that exist in 1.0 but are not yet visible from the feature list. They arise at the intersections of existing features.

### 11.1 API Archaeology

**Definition:** Reconstructing machine-readable API contracts from behavioral evidence, with no access to documentation, source code, or developers.

**How it works:**
1. Capture real browser or tool traffic as a HAR file (`from-har` or `createWebhookListener`)
2. Generate tool definitions automatically from the traffic patterns (`loadHarFile`)
3. Optionally run AI generation to annotate descriptions (`generate`)
4. Expose those tools as an MCP server, or as REST with auto-generated OpenAPI spec (`reverse`)

**The result:** A complete, annotated, machine-readable API contract for a system that had none. Teams with undocumented legacy APIs can run 40mcp against production traffic and produce a spec.

**Status:** Fully functional. Proven end-to-end in `test/self-referential.test.js` (live HTTP → HAR → regenerated bridge). A complementary in-memory smoke test, `test/self-referential-loop.test.js`, covers the OpenAPI leg of the same loop (reverse bridge → generated OpenAPI spec → OpenAPI loader → regenerated bridge).

### 11.2 Event-Driven Agent Mesh

**Definition:** A topology where external events (webhooks) trigger tool calls on linked MCP servers, enabling reactive agent workflows without custom code.

**How it works:**
1. `createWebhookListener` receives an HTTP webhook (Stripe, GitHub, PagerDuty, etc.)
2. The webhook payload is dispatched as a tool call argument
3. The tool routes to a linked MCP server via `connectStdio` or `connectMany`
4. That server may itself be another 40mcp instance, creating a cascading chain

**The result:** An event-triggered agent orchestration bus where each node is an independently configured 40mcp server. No message broker required.

**Status:** End-to-end test in [`test/webhook-to-linked-upstream.test.js`](test/webhook-to-linked-upstream.test.js) exercises the full chain: webhook POST → HMAC-validated listener → `connectStdio` dispatch → stdio MCP child upstream → result returned in the HTTP response. Covers unsigned-request rejection, signed-request acceptance, numeric arg pass-through, and 404 on unmatched paths. Broader workflow-orchestration features (retries, cascading triggers across many instances, queue-backed fan-out) remain V2 targets.

### 11.3 Delegated Authorization Fabric

**Definition:** A per-tenant, per-tool authorization layer where different callers get different approval requirements for the same underlying tool.

**How it works:**
1. `createTenantScope` establishes per-call auth context and tool allowlist/blocklist
2. `createPolicyGate` defines approval rules (auto, deny, require_approval) per tool
3. Rules are evaluated per call in the context of the active tenant
4. `createCallbackApprovalHandler` allows programmatic approval (CI, audit logs, external systems)

**The result:** A lightweight authorization policy engine for agentic systems. Tenant A's `delete_record` is auto-approved in staging; Tenant B's requires human sign-off in production. No OPA, no Rego.

**Status:** Components exist. Combined behavior is not yet tested as a composition. This is the primary compliance-focused V2 story.

---

## Appendix: Document Index

| Document | Purpose |
|----------|---------|
| `SPEC.md` | **This file** — normative product contract |
| `README.md` | Usage guide — install, examples, API reference |
| `API.md` | Full programmatic API reference |
| `CONCEPT.md` | Vision and architectural philosophy (the tesseract model) |
| `CONTRIBUTING.md` | Development guide for contributors |
| `CHANGELOG.md` | Version history |
| `SECURITY.md` | Threat model, reporting, and CVE policy |
| `TROUBLESHOOTING.md` | Operator diagnostic guide |
| `docs/SAFE-DEFAULTS.md` | SSRF, prototype pollution, and URL auth hardening rationale |
| `docs/tui-design.md` | TUI implementation reference (terminal UI primitives) |
| `docs/security-evolution.md` | Lessons from adversarial hardening |
| `docs/trust-model.md` | Three-tier trust topology and assumptions |
| `docs/release-gate.md` | Release discipline — blocker vs follow-up framework |
| `docs/lineage-note.md` | Explains this repository's history |
| `docs/ai-workflow.md` | Integration guide for Claude Desktop, Cursor, VS Code |
| `AGENTS.md` | AI agent contributor guide |
| `.github/workflows/` | CI and publish workflows (added post-port) |
