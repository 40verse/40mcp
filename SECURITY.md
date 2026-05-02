# Security Policy

## Supported Versions

| Version | Security fixes |
|---------|---------------|
| `0.1.x` beta (current) | Yes |
| Earlier pre-releases | No — upgrade to the latest `0.1.x` beta |

Pre-1.0 the supported surface is whatever the latest published beta carries. There is no LTS branch below `0.1.x`. When `1.0.0` ships, this table will grow a `1.x (current)` row and the previous beta line will age out per the disclosure policy below.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private security advisory:
**Security → Report a vulnerability** (on the repository page)

Include:
- Description of the vulnerability and potential impact
- Steps to reproduce (PoC config, test case, or script)
- Affected component (`vault`, `bridge`, `chain`, `transport`, `loaders`, etc.)

You will receive an acknowledgment within **72 hours** and a status update within **7 days**.

## Disclosure Policy

We follow coordinated disclosure:

- Reporter receives credit in the advisory and CHANGELOG (unless they prefer anonymity)
- We aim to ship a fix within **90 days** of confirmation (shorter for critical issues)
- Public disclosure is coordinated with the reporter before release
- CVEs are requested for confirmed vulnerabilities with real-world impact

## Scope

**In scope:**
- SSRF via URL validation — `assertSafeUrl`, `loadOpenApiSpec`, `loadGraphqlSchema`, bridge `baseUrl`
- Vault encryption (`src/security/vault.js`) — AES-256-GCM envelope, key derivation, JWT issuance
- Vault-client fail-closed behavior (`src/security/vault-client.js`) — auth hooks must throw on daemon failure, not silently drop credentials
- Auth credential handling (`src/core/client.js`) — credential logging, header injection, OAuth2 flow
- Policy bypass (`src/security/policy.js`) — approval gate circumvention, deny bypass
- Tenant escalation (`src/tenant/scope.js`) — cross-tenant data access via `_tenant` override
- Prototype pollution (`src/core/object.js`) — `__proto__`, `constructor`, `prototype` key injection
- Prompt injection via configs — malicious `description` fields or tool names in community configs (`configs/`)

**Out of scope** (documented non-goals):
- DoS via oversized configs or large upstream responses — not a rate-limiting product
- Downstream API security — 40mcp forwards requests; it cannot harden what it wraps
- MCP client authentication — protocol limitation, not a 40mcp vulnerability
- Secrets management at scale — the vault is single-node by design
- DNS rebinding at dispatch time — URLs are validated at load/creation time, not per-request (see Known Limitations)

## Security Design

40mcp assumes a **trusted operator** who controls both the config and the environment. Treat a config file like executable code.

### Controls (active by default)

| Control | What it protects |
|---------|-----------------|
| Cloud metadata unconditional block | AWS IMDS (`169.254.169.254`), GCP metadata, Azure IMDS, ECS task-role endpoint — blocked on every code path regardless of `allowPrivate` / `strictSsrf` |
| SSRF blocklist at the loader layer (default: strict) | `loadOpenApiSpec`, `loadGraphqlSchema`, and `assertSafeUrl` default to `allowPrivate: false`, refusing loopback (127.x, ::1, `localhost`), RFC-1918, link-local, CGNAT (100.64.0.0/10), and IPv6 ULA/multicast |
| SSRF blocklist at the bridge layer (default: permissive for local dev) | `createRestBridge` defaults to `allowPrivate: true` so local development against `127.0.0.1` works out of the box. Cloud metadata is still blocked unconditionally. **Set `config.strictSsrf: true` (or `config.allowPrivate: false`) in any production deployment that should refuse private/loopback targets.** `doctor` flags this when baseUrl is public but strictSsrf is unset on a non-localhost host. |
| IPv4-compatible IPv6 decode | `::7f00:1` (= `::127.0.0.1`) is decoded and re-validated against IPv4 range rules |
| Loopback hostname denylist | `localhost`, `ip6-localhost`, `localhost.localdomain` blocked when `allowPrivate: false` |
| Prototype pollution guards | `setByPath`/`getByPath` refuse `__proto__`, `constructor`, `prototype` keys |
| Secret-named env var block | Env vars matching `TOKEN`, `PASSWORD`, `API_KEY`, etc. refused in URL template substitution |
| Embedded URL credential block | `user:pass@host` form rejected |
| Input validation | Tool args validated against `inputSchema` before dispatch |
| Vault fail-closed | Auth hooks throw (not silently no-op) when vault daemon is unreachable |
| SSE idle eviction | Connections closed after 5 min idle; mitigates Slow Loris |
| Schema sanitization | `connectStdio`/`connectSse` strip prototype-poisoning keys from upstream schemas |
| Egress chokepoint (audited) | Every outbound fetch in `src/` passes through `assertSafeUrl` before the network call. Enforced programmatically by `src/security/invariants/egress-chokepoint.test.js` — new PRs that add an outbound fetch without the gate fail CI. |

> **The two-layer default.** Loader-layer SSRF (`assertSafeUrl`, `loadOpenApiSpec`, `loadGraphqlSchema`) blocks private ranges by default; bridge-layer dispatch (`createRestBridge`) permits them by default so `baseUrl: "http://127.0.0.1"` during development does not require a flag. Cloud-metadata hosts are blocked on both layers unconditionally. For production: set `strictSsrf: true` on the bridge config, or pin a non-permissive `allowPrivate: false` explicitly.

### Transport-Egress Sanitization Audit

All result-exit paths from 40mcp apply at minimum `stripInternalEnvelopes`. Paths that expose results to an LLM also apply `sanitizeResultObject` (prompt-injection redaction over all string leaves).

| Exit path | `stripInternalEnvelopes` | `sanitizeResultObject` | Notes |
|-----------|:---:|:---:|-------|
| MCP `tools/list` (bridge) | — | ✓ | `sanitizeMcpToolDescription` on each description |
| MCP `tools/list` (mixer) | — | ✓ | `sanitizeMcpToolDescription`; mixer result-egress symmetry documented in the rows below |
| MCP `tools/call` (bridge `CallToolRequestSchema`) | ✓ | ✓ | Both passes in `bridge.js:978–1004` |
| MCP `tools/call` (mixer `CallToolRequestSchema`) | ✓ | ✓ | `sanitizeTransportEgress` |
| `dispatch()` exported (bridge) | ✓ | ✓ | `sanitizeTransportEgress` at `bridge.js:565` |
| `dispatch()` exported (mixer) | — | — | Consumed by the `CallToolRequestSchema` handler above; no separate LLM path |
| Reverse bridge REST egress | ✓ | ✓ | Inherits from `dispatch()` (bridge already applied `sanitizeTransportEgress`); `stripInternalEnvelopes` applied again (idempotent) |
| Webhook sync response | ✓ | ✓ | `sanitizeTransportEgress` in `webhook/listener.js:577` |
| SSE transport | N/A | N/A | Serializes MCP protocol objects, not raw dispatch results; sanitization upstream |
| Chain egress (intermediate steps) | — | — | Steps aggregate into a final result; `dispatch()` or `CallTool` handler sanitizes before external exit |

This audit is enforced programmatically by `src/security/invariants/egress-sanitize.test.js` — new exit paths must register there or fail CI.

**Test coverage:** See sanitization invariant tests.

### Authentication Model (Reverse Bridge)

The reverse bridge (`createReverseBridge`) validates incoming auth headers using **HMAC-SHA256 digest comparison**:

1. Both the expected secret (from `process.env[auth.envVar]`) and the received header value are HMAC-SHA256'd with a cryptographically-random per-process key generated at startup via `randomBytes(32)`.
2. The resulting 32-byte digests are compared with `timingSafeEqual`.

**Why HMAC instead of direct `timingSafeEqual` on the raw strings?** Direct `timingSafeEqual` requires equal-length buffers. Padding to a fixed maximum length leaks the secret's byte-length as a timing oracle — `Buffer.alloc(maxLen)` allocation branches are distinguishable under timing analysis even when the comparison itself is constant-time. HMAC normalizes both inputs to exactly 32 bytes regardless of secret or header length, eliminating the length oracle entirely.

**What this protects:** Timing side-channel attacks that would otherwise reveal the secret's length and byte values through differential response-time measurements.

**What it does NOT protect:** A compromised environment where the env var or HMAC key is readable from the process; brute-force attacks against short secrets; forward-secrecy (the HMAC key is per-process, regenerated on restart).

**Test coverage:** See webhook and reverse bridge invariant tests.

### Known Limitations

- **DNS rebinding (`connectSse` http://):** `connectSse` now resolves the upstream hostname to an IPv4 address at connection time, validates it against the SSRF blocklist, and pins `http://` transports to that IP (reconnects go to the pinned IP, not whatever DNS returns later). HTTPS upstreams are protected by TLS certificate validation. Bridge `baseUrl` and `loadOpenApiSpec`/`loadGraphqlSchema` URLs are still validated at load time only — DNS rebinding via those paths remains a known limitation unless network-level controls are present (e.g. restricted outbound DNS).
- **Operator trust:** The operator controls the config. 40mcp does not protect against a malicious config operator.
- **MCP client auth:** stdio transport is unauthenticated by protocol design. SSE transport inherits whatever the HTTP server provides.
- **`ListTools` is unauthenticated:** MCP protocol design — all clients can enumerate available tools.
- **`connectStdio` executes commands:** The command in the config is exec'd directly — treat `.mcp.json` files like code.
- **`/health` session count:** Not exposed by default. Set `exposeSessionCount: true` in `createSseTransport` for internal/trusted networks only.

### What We Do Not Claim

- 40mcp is not a WAF, API gateway, or network firewall.
- 40mcp does not guarantee protection against a compromised operating environment.
- 40mcp does not prevent prompt injection by upstream APIs into LLM responses — it controls what reaches the LLM tool call boundary, not what the LLM does with the response.
- 40mcp's security invariants cover documented code paths. Operator-provided middleware, custom plugins, or extensions are outside this scope.

See [SPEC.md §7](SPEC.md#7-security-model) for the full security model, [docs/SAFE-DEFAULTS.md](docs/SAFE-DEFAULTS.md) for the deployment checklist, [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md) for the three-tier trust topology, and [docs/SECURITY_EVOLUTION.md](docs/SECURITY_EVOLUTION.md) for the design history behind these controls.

## Security Contacts

The only supported channel for security reports is the GitHub private
security advisory flow described above under **Reporting a
Vulnerability** (Security → Report a vulnerability on the repository
page). Do not email or DM individual maintainers — those channels are
not monitored for security reports and your report may be lost.

For non-sensitive questions about the security model, open a regular
GitHub Discussion or issue. For coordinated disclosure of a confirmed
vulnerability, the repository advisory thread is the canonical record.
