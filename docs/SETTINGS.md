# `40mcp.settings.json`

Runtime behavior for a 40mcp instance. Ports, limits, auth wiring, policy paths, telemetry — everything that changes between environments without changing what the service actually exposes.

If you're new, read [CONFIGURATION_MODEL.md](CONFIGURATION_MODEL.md) first for the topology-vs-runtime split.

---

## Quick start

```bash
cd my-bridge/
40mcp init           # generates bridge.json and (optionally) 40mcp.settings.json
40mcp serve bridge.json
```

`40mcp.settings.json` is auto-discovered when it sits next to the bridge config or in the current working directory. To override the path explicitly:

```bash
40mcp serve bridge.json --settings /etc/40mcp/settings.json
```

Inspect what's live:

```bash
40mcp settings show
```

---

## Shape: three clusters

```jsonc
{
  "instance":  { /* operator metadata */ },
  "bridge":    { /* `40mcp serve` runtime */ },
  "frontdoor": { /* `40mcp link` runtime */ }
}
```

- `instance.*` — display name + tags. Appears on banners, `/health`, and audit entries.
- `bridge.*` — consumed by `40mcp serve`. Transport, dispatch limits, request/response size caps, network (SSRF), vault.
- `frontdoor.*` — consumed by `40mcp link`. Transport, auth, SSE session caps, surface filters, policy/tenant/steering paths, telemetry.

A `40mcp serve` instance that publishes itself as SSE is still a bridge — it reads `bridge.*`, not `frontdoor.*`. See [BRIDGE_VS_FRONTDOOR.md](BRIDGE_VS_FRONTDOOR.md).

---

## Which fields are operators actually going to touch?

Most operators change these first:

| Field | Why |
|---|---|
| `instance.name` | Appears on banners and audit entries. |
| `bridge.transport.{type,port,host}` | Switch a bridge from stdio to SSE. |
| `bridge.limits.dispatch.maxConcurrent` | Raise / lower the in-flight cap for heavy workloads. |
| `frontdoor.transport.{port,host}` | Port the frontdoor binds on. |
| `frontdoor.auth.requireBearerEnv` | Bearer auth for the published frontdoor. |
| `frontdoor.limits.sse.maxConnections` | Tighten connection caps on public SSE. |
| `frontdoor.{policy,tenantMap,steering}.path` | Wire policy / tenant / steering documents without re-specifying at every `--flag`. |
| `frontdoor.telemetry.{audit,events}` | Silence the stderr audit/event channels in environments that pipe them elsewhere. |

The rest are available but rarely needed in normal operation.

---

## Recipes

### 1. Local bridge (stdio) with display metadata

Minimal — you just want the audit trail and banners to show a friendly name.

```json
{
  "instance": { "name": "Local Dev", "tags": ["dev"] }
}
```

```bash
40mcp serve bridge.json
# → [bridge] MCP server started — N tools [Local Dev dev]
```

### 2. Published bridge over SSE

Run the bridge as its own SSE server on `:9000`.

```json
{
  "instance": { "name": "GitHub Bridge" },
  "bridge": {
    "transport": { "type": "sse", "host": "127.0.0.1", "port": 9000 }
  }
}
```

```bash
40mcp serve github.json
curl http://127.0.0.1:9000/health
# → {"status":"ok","instance":{"name":"GitHub Bridge"}}
```

### 3. Frontdoor driven entirely from settings

No `--sse` flag at the command line — the frontdoor activates because `frontdoor.transport.type === "sse"`.

```json
{
  "instance": { "name": "Prod Frontdoor", "tags": ["prod"] },
  "frontdoor": {
    "transport": { "type": "sse", "host": "0.0.0.0", "port": 8080 },
    "network":   { "allowedOrigins": ["https://app.example.com"] }
  }
}
```

```bash
40mcp link frontdoor.mcp.json
# → [40mcp] Frontdoor published — N tools at http://0.0.0.0:8080 [Prod Frontdoor prod]
```

> ⚠️ A non-loopback host without any auth refuses to start — see recipe 4.

### 4. Frontdoor with bearer auth, all in settings

```json
{
  "instance": { "name": "Prod Frontdoor", "tags": ["prod"] },
  "frontdoor": {
    "transport": { "type": "sse", "host": "0.0.0.0", "port": 8080 },
    "auth":      { "requireBearerEnv": "FRONTDOOR_TOKEN" },
    "limits":    { "sse": { "maxConnections": 250 } },
    "policy":    { "path": "/etc/40mcp/policy.json" },
    "telemetry": { "audit": true, "events": true }
  }
}
```

```bash
export FRONTDOOR_TOKEN="$(openssl rand -hex 32)"
40mcp link frontdoor.mcp.json
```

### 5. CLI override for one-off debugging

Operator wants to flip the frontdoor to a different port temporarily without editing the settings file:

```bash
40mcp link frontdoor.mcp.json --sse 9090
# CLI flag wins over settings.frontdoor.transport.port
```

### 6. Env shadow example

`MAX_SSE_CONNECTIONS` is one of the few keys with an explicit env overlay. When set, it wins over settings:

```bash
# settings says 100, env says 500 → 500 wins
export MAX_SSE_CONNECTIONS=500
40mcp link frontdoor.mcp.json
```

`40mcp doctor` flags this shadow so operators aren't surprised:

```
WARNING: frontdoor.limits.sse.maxConnections=100 in settings, but MAX_SSE_CONNECTIONS=500 in env will override it
```

### 7. Non-loopback without auth — fails fast

Operator error case — the instance refuses to publish an unauthenticated frontdoor on a public host:

```json
{
  "frontdoor": { "transport": { "type": "sse", "host": "0.0.0.0", "port": 8080 } }
}
```

```bash
40mcp link frontdoor.mcp.json
# → Error: Refusing to publish linked frontdoor on a non-loopback host without inbound auth.
```

`40mcp doctor` catches this before you try to start the process.

---

## Validation

`40mcp.settings.json` is validated on load. Invalid files exit the process with an actionable message. Common categories:

- Unknown top-level key (only `instance`, `bridge`, `frontdoor` are accepted).
- Wrong type (string where integer expected, etc.).
- Invalid enum (`transport.type` must be `stdio` or `sse`).
- Invalid combination (e.g. `frontdoor.auth.*` is meaningful only when `frontdoor.transport.type === "sse"`).

Run `40mcp doctor <config>` to surface any settings-aware runtime drift before you start the instance. See [COMMANDS/settings-and-doctor.md](COMMANDS/settings-and-doctor.md).

---

## Secrets

Secrets **do not live in `40mcp.settings.json`**. Use:

- Env vars for straightforward tokens.
- The 40mcp sealed vault for credentials you want encrypted at rest. See [SAFE-DEFAULTS.md](SAFE-DEFAULTS.md).
- A multi-token `bearer-file` (referenced by path in settings) for per-principal frontdoor auth.

`40mcp settings show` surfaces `VAULT_DAEMON_SECRET` / `VAULT_PASSPHRASE` only as `<set>` / `<unset>` so the output is safe to pipe into a log or ticket.

---

## Related docs

- [CONFIGURATION_MODEL.md](CONFIGURATION_MODEL.md) — topology vs runtime, identity, precedence.
- [BRIDGE_VS_FRONTDOOR.md](BRIDGE_VS_FRONTDOOR.md) — which cluster applies when.
- [COMMANDS/settings-and-doctor.md](COMMANDS/settings-and-doctor.md) — inspection and drift-checking.
- [FRONTDOOR.md](FRONTDOOR.md) — published SSE deployment patterns.
