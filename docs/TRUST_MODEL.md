# Trust Model

How 40mcp reasons about trust across its boundaries.

---

## Trust topology

40mcp operates at the intersection of three trust tiers:

```
┌─────────────────────────────────────────┐
│  Tier 1 — Sovereign Operator            │
│  Controls: config, env, deployment host │
│  Trust level: FULL                      │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Tier 2 — Bridge Runtime          │  │
│  │  Controls: dispatch, transforms,  │  │
│  │  sanitization, policy enforcement │  │
│  │  Trust level: ENFORCED            │  │
│  │                                   │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  Tier 3 — Upstream APIs     │  │  │
│  │  │  Controls: nothing          │  │  │
│  │  │  Trust level: UNTRUSTED     │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Tier 1 — Trusted operator

The operator controls the config file, environment variables, network environment, and deployment host. 40mcp does not protect against a malicious operator. A config file should be treated like executable code — it determines which APIs are called, what credentials are used, and what tools are exposed to the LLM.

**What the operator is trusted to do:**
- Write valid, non-malicious config files
- Store credentials securely (vault or env vars)
- Control network access to/from the bridge
- Review community configs before deploying them

**What 40mcp enforces even for the operator:**
- Cloud metadata endpoints (169.254.x) are blocked unconditionally — no config override
- Prototype-poisoning keys (`__proto__`, `constructor`, `prototype`) are stripped unconditionally
- `file://` and `data://` URL schemes are rejected unconditionally

### Tier 2 — Bridge runtime (enforced controls)

The bridge runtime enforces security controls on documented code paths. These controls protect against exploitation of the bridge itself, not against a compromised environment.

| Control | Protects against |
|---------|-----------------|
| `assertSafeUrl` | SSRF — loopback, private ranges, cloud metadata, alternative IP encodings |
| `sanitizeTransportEgress` | Prompt injection via upstream response data |
| `sanitizeMcpToolDescription` | Prompt injection via tool descriptions |
| Schema sanitization | Prototype pollution via upstream MCP schemas |
| Input validation | Malformed tool arguments reaching upstream APIs |
| Vault encryption | Credential exposure from disk access |
| Policy gates | Unauthorized execution of dangerous tools |
| Tenant scoping | Cross-tenant data access in multi-tenant mode |

### Tier 3 — Untrusted upstream

Upstream APIs and MCP servers are untrusted. Their responses may contain:
- Prompt injection attempts (adversarial text targeting the LLM)
- Prototype pollution payloads (in MCP schemas)
- Oversized responses (memory exhaustion)
- Malformed JSON (parser exploitation)

40mcp sanitizes upstream data before it reaches the LLM. It does not trust upstream schemas, descriptions, or response bodies.

---

## Config as executable-risk input

A 40mcp config file determines:
- Which URLs the bridge will call (potential SSRF vector)
- Which credentials are attached to requests (potential exfiltration vector)
- What tool descriptions reach the LLM (potential prompt injection vector)
- What chain logic executes (potential unauthorized action vector)

**Community configs (`configs/`) are treated as untrusted until reviewed.** Description fields can embed adversarial LLM instructions. Chain definitions can sequence dangerous operations. The bridge sanitizes descriptions at runtime, but operators should review configs before deployment.

---

## Transport boundaries

40mcp has five transport boundaries where data crosses trust tiers:

| Boundary | Direction | Trust transition |
|----------|-----------|-----------------|
| MCP client → bridge (stdio/SSE) | Inbound | LLM → Tier 2 |
| Bridge → upstream API (HTTP) | Outbound | Tier 2 → Tier 3 |
| Upstream MCP server → bridge (stdio/SSE) | Inbound | Tier 3 → Tier 2 |
| Bridge → MCP client (result) | Outbound | Tier 2 → LLM |
| Webhook → bridge (HTTP POST) | Inbound | External → Tier 2 |

Every outbound-to-LLM boundary applies `sanitizeTransportEgress`. Every inbound-from-upstream boundary applies schema sanitization. See [SECURITY.md](../SECURITY.md) for the complete transport-egress audit table.

---

## Composition boundaries

Composition creates internal trust boundaries that are easy to overlook:

### Chains (`executeChain`)

A chain dispatches multiple tool calls in sequence. Each step's output feeds the next step's input. Security controls must propagate through the chain:
- Tenant context propagates to all sub-dispatches
- Policy gates evaluate at each step, not just the entry point
- Chain depth is bounded (`MAX_CHAIN_DEPTH = 10`) to prevent unbounded recursion

### Mixer (`createMixer`)

A mixer combines tools from multiple upstream MCP servers into a single bridge. Each upstream server is independently untrusted:
- Schemas from all upstreams are sanitized before re-exposure
- Duplicate tool names are detected and deduplicated (first registration wins)
- Result sanitization applies to all upstream responses, not just the outer bridge

### Webhook → tool dispatch

Webhook ingestion creates an entry point from external HTTP into tool dispatch. The webhook boundary enforces:
- HMAC signature validation on inbound payloads
- Replay window checking (optional)
- Route disclosure prevention (routes hidden by default)
- Result sanitization on sync responses

---

## Tenant, policy, vault, and reverse bridge assumptions

### Tenant isolation

Multi-tenant mode sets `_tenant` at the session boundary. The tenant context is:
- Set once per session, not per call
- Propagated internally through all dispatch paths (including chains)
- Not overridable by the MCP client — callers cannot inject `_tenant` in tool arguments

**Assumption:** The session establishment mechanism correctly identifies the tenant. 40mcp enforces isolation once the tenant is set; it does not authenticate the tenant identity itself.

### Policy gates

Policy gates block tool execution until a human approves the call. The gate:
- Evaluates per tool call, not per session
- Applies to the resolved tool (after chain step resolution)
- Blocks on `require_approval`; auto-approves on `auto`; denies on `deny`

**Assumption:** The approval handler is trusted. The built-in stdin handler is suitable for development; production deployments should implement a handler connected to an appropriate approval workflow.

### Sealed vault

The vault encrypts API keys with AES-256-GCM at rest. The vault daemon architecture separates key material:
- The daemon holds the passphrase and KEK
- Bridge processes authenticate via Unix socket IPC
- Bridge processes receive scoped, short-lived JWTs
- Bridge processes never hold the passphrase or KEK

**Assumption:** The deployment host is not compromised. The vault protects against disk access to the encrypted file, not against a process with access to the daemon socket or the bridge's memory.

### Reverse bridge

The reverse bridge exposes MCP tools as REST endpoints with an auto-generated OpenAPI spec. Authentication uses HMAC-SHA256 constant-time comparison:
- Per-process random HMAC key generated at startup (`randomBytes(32)`)
- Both expected and received values are HMAC'd to exactly 32 bytes
- Compared with `timingSafeEqual` — no length oracle

**Assumption:** The auth secret is strong and stored securely. The reverse bridge does not enforce minimum secret complexity.

---

## What 40mcp enforces on documented paths

- Credential logging prevention (auth headers, tokens, vault passphrases never written to stdout/stderr)
- No plaintext credential storage (sealed vault path)
- SSRF blocking on all URL validation points
- Input validation before upstream dispatch
- Injection hardening (serialization, not interpolation)
- Schema sanitization on upstream MCP connections
- Result sanitization on all LLM-facing exit paths
- Tenant isolation across composition boundaries

## What 40mcp explicitly does not guarantee

- Security of downstream APIs (40mcp forwards; it cannot harden what it wraps)
- MCP client authentication (protocol limitation)
- Secrets management at scale (single-node vault)
- Rate limiting (left to downstream APIs or external gateways)
- Protection against prompt injection that originates in upstream API response content and is semantically valid (sanitization catches known patterns, not novel attacks)
- DNS rebinding at dispatch time for bridge `baseUrl` (validated at load time only; `connectSse` pins resolved IPs for `http://` transports)
- Protection against a compromised operator or deployment host

---

## Further reading

- [SECURITY.md](../SECURITY.md) — Controls, threat model, known limitations
- [Security evolution](security-evolution.md) — How the security posture was developed
- [SAFE-DEFAULTS.md](SAFE-DEFAULTS.md) — What's on/off by default
- [SPEC.md §7](../SPEC.md#7-security-model) — Normative security model
