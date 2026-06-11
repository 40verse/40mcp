# Published Frontdoor MCP

Aggregate multiple private upstream MCP servers behind a single authenticated
SSE endpoint. One public port, multiple backends, application-layer auth.

This is the recommended frontdoor deployment shape for hosted 40mcp when one
public endpoint aggregates multiple private upstreams — a Railway app, a
Docker container, or a Fly machine that fronts several private MCP servers and
presents them as one tool surface to a remote MCP client (GPT Actions,
claude.ai, Cursor, etc.).

The separation of concerns is the point:

- **Backend bridges own credentials and execution.** Each upstream 40mcp
  holds its own sealed vault, calls the underlying API, and runs tool
  workflows. Credentials never leave the upstream process.
- **The frontdoor owns publication, namespace, and the inbound access
  boundary.** It decides which tools are public, how they're named, and
  who is allowed to call them. It does not hold upstream credentials.

`link --sse` is the transport; the frontdoor is an authority boundary.

```
GPT / remote MCP client
  │
  ▼
frontdoor 40mcp  (:8080, SSE, bearer-auth)
  │
  ├──▶ github 40mcp    (stdio child, private)
  └──▶ twitter 40mcp   (stdio child, private)
```

## Quick start

Create a `frontdoor.mcp.json` that lists the private upstreams as stdio
children. Nothing public is declared here — `40mcp link` spawns each
upstream as a child process and wires them into the frontdoor:

```json
{
  "mcpServers": {
    "github": {
      "command": "40mcp",
      "args": ["serve", "/etc/40mcp/github.json", "--vault-bearer", "github-pat"]
    },
    "twitter": {
      "command": "40mcp",
      "args": ["serve", "/etc/40mcp/twitter.json", "--vault-bearer", "twitter-oauth"]
    }
  }
}
```

Publish the linked surface:

```bash
export FRONTDOOR_TOKEN="$(openssl rand -hex 32)"
40mcp link frontdoor.mcp.json \
  --sse 8080 \
  --host 0.0.0.0 \
  --require-bearer-env FRONTDOOR_TOKEN
```

Remote clients connect with:

```
GET  http://<host>:8080/sse          Authorization: Bearer $FRONTDOOR_TOKEN
POST http://<host>:8080/message      Authorization: Bearer $FRONTDOOR_TOKEN
```

## Option A — stdio child upstreams (recommended)

The quick-start shape above. The frontdoor spawns each upstream as a
stdio child process. No internal ports, no internal networking. Each
child holds its own credentials and talks to the frontdoor through
stdin/stdout MCP. This is the right fit for a single-container deploy
(one Railway service, one Docker image, one Fly machine).

## Option B — local-only internal SSE listeners

When an upstream is already running as its own SSE process — for
example, a sidecar container, a supervised service, or a bridge that
needs to outlive a single frontdoor launch — the frontdoor can link to
it over loopback instead of spawning it.

1. Start each upstream bound to loopback so it is not reachable from
   outside the container:

   ```bash
   40mcp serve /etc/40mcp/github.json --sse 8083 --host 127.0.0.1
   40mcp serve /etc/40mcp/twitter.json --sse 8084 --host 127.0.0.1
   ```

2. Point `frontdoor.mcp.json` at the loopback URLs. Because these URLs
   are private IPs, the upstream connector's SSRF guard requires an
   explicit opt-in per entry:

   ```json
   {
     "mcpServers": {
       "github": {
         "url": "http://127.0.0.1:8083/sse",
         "options": { "allowPrivate": true }
       },
       "twitter": {
         "url": "http://127.0.0.1:8084/sse",
         "options": { "allowPrivate": true }
       }
     }
   }
   ```

3. Publish the frontdoor as before:

   ```bash
   40mcp link frontdoor.mcp.json --sse 8080 --host 0.0.0.0 \
     --require-bearer-env FRONTDOOR_TOKEN
   ```

Only port `8080` is published; `8083` and `8084` stay on loopback.

Trade-offs vs. Option A:

- More moving parts inside the container. You need a supervisor
  (s6, tini + sh wrapper, systemd unit, Docker `depends_on`) to keep
  the internal SSE upstreams alive, since the frontdoor no longer
  owns their lifecycle.
- Better when an upstream's startup cost is high, when multiple
  frontdoors want to share a single upstream, or when the upstream
  is in a different language runtime.
- Same public surface and the same bearer-auth guarantees as Option A.

If you're building one Railway service and want the simplest thing
that works, use Option A. Reach for Option B when the upstream
genuinely wants its own process lifecycle.

## Flags

| Flag | What it does |
|---|---|
| `--sse <port>` | Publish the linked surface over SSE instead of stdio. |
| `--host <host>` | Bind host. Default `127.0.0.1`. Use `0.0.0.0` for a public container. |
| `--require-bearer-env <ENV>` | Single-token auth: read the token from an env var. Preferred — never shows up in `ps`. |
| `--require-bearer <token>` | Single-token auth literal. Discouraged. |
| `--bearer-file <path>` | Multi-token auth: JSON `{ principal: token }`. Each principal can be revoked independently; successful auth events carry the principal name. |
| `--max-sessions-per-principal <N>` | Concurrent SSE session cap per principal in multi-token mode (default `5`). Composes with the per-IP cap. |
| `--policy <path>` | Policy gate — JSON `{ toolPolicies: { "<tool>": "allow\|deny\|log_only\|require_approval" }, ... }`. Runs before the upstream dispatch. Embedded `tool.policy` annotations on linked tools are also honored when `--policy` is passed (even pointing at an empty `{}` file). |
| `--tenant-map <path>` | Per-principal tenant scope — JSON `{ "<principal>": { tenantId, allowlist?, blocklist? } }`. Requires `--bearer-file`. |
| `--allowed-origin <o[,o2]>` | Comma-separated CORS origins. Only needed for browser clients; non-browser MCP clients do not send `Origin`. |
| `--only <a,b>` / `--skip <a,b>` | Filter which upstream *servers* to connect. |
| `--allow-tool <g[,g2]>` | Glob allowlist for *tools* at the frontdoor. Matches the fully-prefixed name (e.g. `github.get_*`). |
| `--deny-tool <g[,g2]>` | Glob denylist for tools. Wins when both flags match. |
| `--health-detail` | `/health` returns per-upstream liveness instead of a bare `{status:"ok"}`. |
| `--name <name>` | Server name advertised to the MCP client. |

At most one of `--require-bearer-env` / `--require-bearer` / `--bearer-file`
may be set. If `--require-bearer-env` is set but the env var is empty, or
if `--bearer-file` is empty / malformed / contains duplicate tokens, the
command exits with a clear error before binding. This prevents a
misconfigured deploy from silently publishing an unauthenticated
frontdoor.

The command refuses to bind a non-loopback host without inbound auth.

## Per-principal auth (multi-token)

Single-token auth is enough for one remote client. Multi-token auth is
useful when more than one consumer talks to the same frontdoor and you
want to:

- revoke one consumer's access without rotating everyone else's token
- tag successful auth events with a human-readable principal so the log
  tells you *who* connected, not just that someone did

The file format is a flat JSON object mapping principal → token:

```json
{
  "gpt-actions":    "tok_alice_...",
  "claude-desktop": "tok_bob_...",
  "internal-ci":    "tok_carol_..."
}
```

Principal names must match `^[a-zA-Z0-9_-]{1,64}$` so they can't forge
log lines. Tokens must be unique across principals (the transport
returns the first matching principal on successful auth, so two
principals sharing a token would report non-deterministically).

```bash
40mcp link frontdoor.mcp.json --sse 8080 --host 0.0.0.0 \
  --bearer-file /etc/40mcp/frontdoor-tokens.json
```

Write the file with `0600` permissions and keep it off the container
image — mount it at runtime from a secret manager (Railway secret file,
Docker secret, Fly `[mounts]` volume, Kubernetes `Secret` mount).

### Scale guidance

Token comparison iterates every entry on every authenticated request to
keep the timing discipline (no early-out leak of "matched earlier in
the map"). That makes auth cost linear in the number of principals —
fine for the intended scale of *a handful to a few dozen consumers*
per frontdoor (one per remote MCP client, plus a couple of internal
ones). If you genuinely need hundreds or thousands of credentials on a
single frontdoor, that calls for a different structure (e.g. signed
JWTs verified against a small public-key set) — open a separate issue
rather than scaling this map.

### What principal attribution covers in this release

- `sse.auth_ok` — carries the matched `principal`
- `sse.session_open` / `sse.session_close` — carry the `principal` that
  opened the session
- Operator logs can correlate a session's tool calls to the principal
  via the shared `sessionId` field on `sse.session_open` and adjacent
  `frontdoor.tool_call` lines

### What principals ride through to tool calls

As of this release, `frontdoor.tool_call` events carry the calling
principal and `sessionId` directly — the transport layer stashes the
authenticated principal on each session and re-enters an
`AsyncLocalStorage` context for every POST /message, so the downstream
CallTool handler reads it without needing access to the underlying
HTTP request. Tenant resolution (below) uses the same context.

### Per-principal session cap

With multi-token auth, the more useful rate-limit key is the principal,
not the IP — one consumer roams across networks, and one IP can hide
many consumers behind corporate NAT. `--max-sessions-per-principal`
caps concurrent SSE sessions attributed to a single token, composing
with the per-IP cap so a misbehaving consumer can't monopolise the
pool by spreading requests across IPs:

```bash
40mcp link frontdoor.mcp.json --sse 8080 --host 0.0.0.0 \
  --bearer-file /etc/40mcp/frontdoor-tokens.json \
  --max-sessions-per-principal 3
```

The default is `5`. That's a practical frontdoor value for common
remote MCP clients (a consumer or two, plus reconnect overlap), not a
protocol-level assertion about how many sessions a consumer "should"
have — raise or lower it to match your workload.

When the cap trips, the rejected request returns `429 Too many
sessions for this principal` and the transport emits
`sse.rate_limit_hit { reason: "per_principal_cap", principal, clientIp }`.
Single-token mode and unauthenticated paths leave `principal === null`
and skip this gate — the per-IP cap remains their only bound.

### What this cap is, and is not

This is *session fairness per principal* at the frontdoor. Specifically:

- it bounds concurrent SSE sessions attributable to one credential
- it composes with the per-IP cap, not replaces it
- it trips before transport allocation, so exhausted principals can't
  influence the global pool

It is *not yet*:

- per-principal call-rate fairness (requests/sec, tokens/min)
- per-principal concurrency on tool execution (one call in flight per
  principal, queueing the rest)

Those are workload-governance concerns and belong to the broader
authority-boundary work. Session cap is the right
first knob; the rest can layer on top without changing the shape.

## Authority boundary: policy, tenant

The frontdoor is more than a transport — it's the publication boundary
for a set of private upstreams. Two knobs shape what the published
surface actually *does* on a per-call basis:

### `--policy <path>` — deny dangerous tools at the frontdoor

A policy gate wraps tool dispatch and can allow, deny, or log-only
individual calls *at the frontdoor*, even when the upstream would
accept them. Useful when an upstream exposes a tool you want available
elsewhere but not through this frontdoor.

```json
{
  "toolPolicies": {
    "github.delete_repo":   "deny",
    "github.create_issue":  "log_only",
    "github.merge_pull_request": "require_approval",
    "twitter.send_dm":      "deny"
  },
  "defaultPolicy": "allow"
}
```

Supported verdicts: `allow`, `deny`, `log_only`, `require_approval`.
Policy decisions emit `frontdoor.policy` and `frontdoor.policy_denied`
events tagged with the calling principal.

Embedded `tool.policy` annotations on linked tool definitions are also
honored when `--policy` is passed. Sidecar `toolPolicies` entries win
over embedded annotations for the same tool, so the JSON file remains
the authoritative override. Passing `--policy` at an empty `{}` file is
the minimum opt-in to enforce embedded annotations alone.

**Limitation — `require_approval` currently denies.** On a *published*
frontdoor there is no interactive operator at stdin to approve a call,
so the policy module's `require_approval` verdict is treated as
`deny` with a `no_approval_handler` reason. Plumbing a real
asynchronous approval channel (webhook, Slack, PagerDuty) is a named
follow-up.

### `--tenant-map <path>` — bind a tenant scope per principal

When the frontdoor is authenticated via `--bearer-file`, each inbound
principal can be mapped to a tenant context that enforces an
allowlist / blocklist and supplies tenant metadata to downstream
hooks:

```json
{
  "gpt-actions": {
    "tenantId":  "customer-A",
    "allowlist": ["github.get_*", "twitter.search_*"]
  },
  "internal-ci": {
    "tenantId":  "platform-ops",
    "blocklist": ["github.delete_*"]
  }
}
```

The tenant is resolved per call from the session's authenticated
principal. A request from a principal not in the map is rejected with
`AUTH_MISSING`. `--tenant-map` requires `--bearer-file`; passing it
with `--require-bearer-env` / `--require-bearer` is a usage error (no
principal to key off).

### Dispatch order

```
client → policy gate → tenant scope → raw dispatch → upstream MCP server
```

Policy runs first (coarse allow/deny at the frontdoor), tenant next
(per-principal allowlist/blocklist, tenant metadata injection), then
raw dispatch hits the upstream.

### Interaction with `--allow-tool` / `--deny-tool`

`--allow-tool` and `--deny-tool` filter the *published tool surface*
— the client never sees filtered tools in `tools/list` and a
`tools/call` for one returns `MethodNotFound`. Policy and tenant scope
operate on calls for *listed* tools. So `--deny-tool` removes a tool
entirely; `--policy` `deny` keeps it advertised but blocks the call
with a policy error; tenant `allowlist` can remove it per-principal.
Layer them however the operator needs.

## What inbound auth covers

* `GET /sse` — requires `Authorization: Bearer <token>` before any session
  slot or per-IP counter is touched.
* `POST /message` — same gate, so an attacker with a stale `sessionId`
  cannot dispatch tool calls.
* `GET /health` — always open (orchestrators need it for liveness probes).
* `OPTIONS` — always open (CORS preflight).

Token comparison is constant-time. Expected and received tokens are both
hashed to 32-byte HMAC-SHA256 digests with a per-process random key and
compared with `crypto.timingSafeEqual`, so neither length nor content leaks
through timing.

## What inbound auth does NOT cover

* **CORS is not auth.** `allowedOrigins` restricts which browser origins can
  attach the bearer from a browser, but non-browser MCP clients do not send
  `Origin` and are unaffected.
* **TLS is not built in.** Terminate TLS at your platform's edge (Railway,
  Fly, nginx, Caddy, Cloudflare). `--host 0.0.0.0` binds plain HTTP.
* **Upstreams are trusted.** The frontdoor forwards tool calls to whatever
  upstream responds for a given tool name. Give each upstream its own vault
  scope and only the secrets it needs.

## Narrowing the published tool surface

`--only` / `--skip` filter whole upstream *servers*. To pick individual
*tools* at the frontdoor without reconfiguring the upstreams, use
`--allow-tool` and `--deny-tool`. Both accept comma-separated glob
patterns and match against the fully-prefixed tool name
(`<upstream>.<tool>`). `*` matches any run of characters; everything else
is literal. `--deny-tool` wins when both flags match the same tool.

```bash
40mcp link frontdoor.mcp.json --sse 8080 --host 0.0.0.0 \
  --require-bearer-env FRONTDOOR_TOKEN \
  --allow-tool 'github.get_*,twitter.search_*' \
  --deny-tool  'github.delete_*'
```

The filter applies to both `tools/list` (so a compliant client only sees
the narrowed surface) *and* `tools/call` (so a stale or guessing client
that names a filtered tool gets `MethodNotFound` instead of reaching the
upstream). Use `40mcp link <cfg> --inspect --allow-tool ...` to preview
the filtered list without starting the frontdoor.

## Health

`/health` always returns `200 {"status":"ok"}` so orchestrator liveness
probes keep working even when the bearer gate is active. By default the
payload is intentionally minimal — an anonymous probe cannot enumerate
which upstreams are wired in.

Pass `--health-detail` to opt the endpoint into a per-upstream report:

```json
{
  "status": "ok",
  "upstreams": [
    { "source": "stdio:node /app/github.js", "status": "ok" },
    { "source": "stdio:node /app/twitter.js", "status": "degraded" }
  ]
}
```

Per-upstream `status` is one of:

- `ok` — most recent dispatch to the upstream succeeded (or none has happened yet)
- `degraded` — most recent dispatch threw; next success flips it back
- `closed` — the upstream has been shut down

`--health-detail` is meant for trusted probe paths — an orchestrator
doing a liveness check, an internal dashboard, a log-aggregator probe
behind an auth gate. The payload reveals which upstreams are wired in
and their current status to anyone who can reach `/health`. Leave it
off when the port sits directly on the public internet without a
probing proxy in front.

## Observability

The frontdoor emits structured lines on stderr (prefix `[40mcp:event]`,
JSON body) that a log aggregator can pipe to SIEM. This is *transport
and tool-call observability* — enough to see who hit the SSE gate, who
got in, which tools ran, and whether they errored. It is not yet a
full principal-aware authority audit trail; per-principal attribution
arrives with multi-token auth.

- `sse.auth_ok` — bearer passed, with `path` and `clientIp`
- `sse.auth_failed` — bearer missing or wrong
- `sse.session_open` / `sse.session_close` — SSE lifecycle
- `sse.rate_limit_hit` — global or per-IP cap tripped
- `frontdoor.tool_call` — tool name, outcome (`ok` / `error` / `not_found`),
  duration, and a truncated error message on failure

Every event is a single line of valid JSON after the prefix. See
`src/core/events.js` for the exact shape.

## Railway / single-container deployment

A Railway service exposes exactly one public port. The frontdoor fits that
shape directly — upstreams run as stdio child processes inside the same
container and never open a port.

`railway.json` / `Dockerfile` sketch:

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 8080
CMD ["40mcp", "link", "/app/frontdoor.mcp.json", \
     "--sse", "8080", \
     "--host", "0.0.0.0", \
     "--require-bearer-env", "FRONTDOOR_TOKEN"]
```

Railway env vars:

| Name | Value |
|---|---|
| `FRONTDOOR_TOKEN` | Random 32-byte hex. Rotate regularly. |
| `VAULT_PASSPHRASE` | Passphrase for the upstream vault, if used. |
| `GITHUB_PAT` / `TWITTER_OAUTH_*` | Upstream credentials. Prefer sealed vault entries over raw env vars. |

A Railway deploy rotates bearer tokens by updating `FRONTDOOR_TOKEN` and
triggering a redeploy. Remote clients receive a new token out-of-band.

## Alternatives considered

* **`40mcp publish` subcommand** — a dedicated command was considered. We
  chose to extend `link --sse` because the only operator ritual that differs
  is "where does the transport go" — stdio vs. SSE. A second command would
  duplicate upstream-connection flags for no gain.
* **Origin-only auth** — rejected. CORS does not apply to non-browser MCP
  clients, which is the primary target for a remote frontdoor.
* **TLS at the bridge** — out of scope. Every supported platform
  (Railway, Fly, Cloud Run, nginx) terminates TLS upstream and passes plain
  HTTP inward; rebuilding that inside 40mcp would duplicate well-solved
  infrastructure and introduce a cert-management burden.
