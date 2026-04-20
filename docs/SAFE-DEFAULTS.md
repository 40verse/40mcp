# Safe Defaults for 40mcp

This document describes the protections enabled by default on documented 40mcp code paths. It does not change the trusted-operator assumption.

40mcp is an API-to-MCP bridge with security controls built in. This document defines what is safe by default and what requires explicit opt-in.

## What's Safe By Default

These protections are **enabled without configuration**. Do not disable them without explicit security review.

### SSRF Protection (assertSafeUrl)

`assertSafeUrl` defaults to `allowPrivate: false`. Every loader (`loadOpenApiSpec`, `loadGraphqlSchema`) and the `connectSse` connection-time check invoke it with that default, so those paths block:

| Category | Details |
|----------|---------|
| **Loopback** | 127.0.0.0/8, ::1 |
| **RFC-1918 Private** | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 |
| **Link-Local** | 169.254.0.0/16, fe80::/10 |
| **Cloud Metadata** | 169.254.169.254 (AWS IMDS), 169.254.170.2 (Azure), 169.254.6.254 (GCP), 169.254.169.253 (Oracle), any IPv6 with fe80:: prefix |
| **CGNAT** | 100.64.0.0/10 |
| **IPv6 ULA** | fc00::/7 |
| **IPv6 Multicast** | ff00::/8 |

To access local APIs during development, explicitly pass `allowPrivate: true`.

**Bridge layer exception.** `createRestBridge` dispatches with `allowPrivate: true` by default so `baseUrl: http://127.0.0.1:<port>` works for local development without extra flags. Cloud-metadata hosts remain blocked unconditionally. Set `strictSsrf: true` (or `allowPrivate: false`) on the bridge config in production — `40mcp doctor` flags the non-localhost-without-strictSsrf combination.

#### Alternative IPv4 representations

`assertSafeUrl` also blocks non-standard IPv4 forms that bypass naive hostname string matching:

| Form | Example | Resolves to | Outcome |
|------|---------|-------------|---------|
| Hex-integer | `0x7f000001` | `127.0.0.1` | BLOCKED — loopback |
| Decimal-integer | `2130706433` | `127.0.0.1` | BLOCKED — loopback |
| Octal-prefix | `0177.0.0.1` | `127.0.0.1` | BLOCKED — loopback |

All three forms are decoded and re-validated against the full IPv4 catalog (loopback, RFC-1918, CGNAT, cloud metadata). Test coverage: alternative-representation probes in `src/security/invariants/ssrf.test.js`.

### Prototype Pollution Prevention

`setByPath` and `getByPath` refuse to touch:
- `__proto__`
- `constructor`
- `prototype`

These checks are enforced on documented code paths. Upstream MCP schemas are also sanitized to strip these keys.

### Input Validation

All tool arguments are validated against `inputSchema` before dispatch. Invalid arguments are rejected before reaching the upstream API.

### URL Scheme Filtering

`loadOpenApiSpec` and `loadGraphqlSchema` reject:
- `file://` URLs (local file access)
- `data://` URLs (inline data)

Only `http://` and `https://` are accepted.

### Credential Logging Protection

Secrets are **never** logged to stdout/stderr:
- HTTP Authorization headers stripped
- Bearer tokens redacted
- Vault passphrases never printed
- Credentials in URLs (`user:pass@host`) are blocked at URL validation time

### Session Eviction (SSE)

Server-sent event connections are automatically closed after **5 minutes of idle time**. Stale connections do not accumulate.

### Schema Sanitization

Upstream MCP schemas are stripped of:
- `$ref` references (to prevent external schema injection)
- `$schema` declarations
- `__proto__`, `constructor`, `prototype` keys

### Redirect-URI Allowlist Validator (`matchesAllowedRedirect`)

`src/security/redirect.js` exports `matchesAllowedRedirect(uri, allowlist)` for use by future OAuth / webhook callback flows. It is **reserved — not yet wired into a call site**; shipping the validator now means future PRs can bolt it onto any callback URL handling without inventing a validator at merge time.

Rules (component-wise comparison against each allowlist entry):
- **Scheme** — case-insensitive; must be `http` or `https` on both sides.
- **Host** — case-insensitive; wildcard pattern `*.example.com` matches exactly one label (`a.example.com` yes, `a.b.example.com` no, bare `example.com` no).
- **Port** — exact match, with scheme defaults resolved (`https://x` and `https://x:443` are equivalent).
- **Path** — exact-prefix at segment boundaries (`/foo` matches `/foo` and `/foo/bar` but NOT `/foobar`). Case-sensitive. Trailing slash on the pattern is ignored.
- **RFC 8252 loopback** — `http://127.0.0.1`, `http://localhost`, `http://[::1]` with no explicit port and root path match any port on that host.
- **Rejections** — userinfo (`user:pass@host`) on either side, literal or percent-encoded dot-segments (`./..`, `%2e%2e`), non-ASCII hostnames (caller must pre-punycode), and non-http(s) schemes.

Non-goals: it does NOT normalize percent-encoding beyond the WHATWG `URL` parser, does NOT follow redirects, and does NOT verify the host resolves to a safe address — pair with `assertSafeUrl` when the callback target is fetched. See the JSDoc in `src/security/redirect.js` for the authoritative description.

## What Requires Explicit Opt-In

These features are **off by default** for good reason. Enable only when needed and documented in your deployment config.

### allowPrivate: true

Enables loopback (127.0.0.1, ::1) and RFC-1918 addresses (10.x, 172.16.x, 192.168.x).

**Use case:** Local development with localhost APIs, internal staging environments.

```javascript
assertSafeUrl(url, { allowPrivate: true })
```

**`createRestBridge` default.** The bridge dispatch path defaults to `allowPrivate: true` so local-dev `baseUrl` values work without extra flags. For public-facing deployments, either pass `strictSsrf: true` (preferred — also hardens future dispatch-time checks) or set `allowPrivate: false` explicitly. `40mcp doctor` warns when a non-localhost `baseUrl` is configured without either.

**Never enable in production without explicit justification.**

### strictSsrf: true

Activates extra-strict SSRF validation beyond default blocks. Useful for internet-facing bridges.

```javascript
const bridge = createRestBridge(spec, { strictSsrf: true })
```

**Use case:** Bridge is exposed to untrusted traffic.

### exposeSessionCount: true

Enables `/health` endpoint to return active session count. Defaults to false.

```javascript
const transport = createSseTransport({ exposeSessionCount: true })
```

**Use case:** Internal monitoring dashboards in trusted networks only. Do not expose to the internet.

### Sealed Vault (Optional Encryption)

Sealed vault is an opt-in feature. Environment variables work but are less safe in production.

```javascript
const vault = new Vault({
  sealKey: process.env.VAULT_SEAL_KEY
})
```

**Use case:** Production deployments where API keys must not be readable from the filesystem.

### Policy Gates

Per-tool policies are **not configured by default**. Enable on destructive operations:

```javascript
const bridge = createRestBridge(spec, {
  policies: {
    'DELETE /resource/{id}': { requireApproval: true }
  }
})
```

**Use case:** Prevent accidental deletion of critical resources.

## What Is Never Safe

These blocks are **not user-configurable** on documented code paths:

| Block | Reason |
|-------|--------|
| Cloud metadata endpoints (169.254.x.x, GCP, Azure, Oracle) | Prevents credential theft via IMDS attacks |
| IPv6 ULA/multicast (fc00::/7, ff00::/8) | Prevents local network escape |
| Prototype pollution (`__proto__`, `constructor`) | Prevents object-graph poisoning |
| file:// and data:// URL schemes | Prevents local file access and inline data injection |
| Credentials in URLs | Prevents accidental credential logging/forwarding |

## Deployment Checklist

- [ ] All upstream API endpoints use HTTPS (not HTTP)
- [ ] API keys stored in sealed vault, not plaintext env vars (production only)
- [ ] Set `strictSsrf: true` if bridge is internet-facing
- [ ] Vault seal key stored separately from application secrets (not in .env)
- [ ] Policy gates configured for destructive operations (DELETE, POST to critical endpoints)
- [ ] `allowPrivate: true` disabled in production unless explicitly justified
- [ ] `exposeSessionCount: true` disabled in production
- [ ] Vault passphrase rotated quarterly like a password
- [ ] Incoming requests validated against OpenAPI schema before tool dispatch
- [ ] SSE connections monitored; idle eviction set to 5 min or less
- [ ] SSRF guard validates alternative IPv4 representations (hex `0x7f000001`, decimal `2130706433`, octal-prefix `0177.0.0.1`) — these are blocked by `assertSafeUrl` without operator configuration; verify no downstream proxy strips or re-interprets the host before the guard runs

## Reference

See also:
- `src/core/env.js` — SSRF blocking logic (`assertSafeUrl`)
- `src/security/vault.js` — Credential encryption
- `src/bridge.js` — Tool dispatch and validation
- `src/core/sanitize.js` — Schema and input sanitization
