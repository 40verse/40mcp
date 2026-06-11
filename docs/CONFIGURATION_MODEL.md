# Configuration Model

40mcp separates *what* a service does from *how* it runs. Two files own those concerns, plus a third explicit-override layer:

| Layer | File / source | Owns |
|---|---|---|
| Topology | bridge config (`bridge.json`, `github.json`, …) or `.mcp.json` | API/tool shape, upstream command, baseUrl, auth kind |
| Runtime | `40mcp.settings.json` | Transport, limits, auth wiring, policy/tenant paths, vault, telemetry |
| Override | CLI flags | Explicit one-off overrides for a specific invocation |

Env vars sit between runtime and CLI, but **only for keys that have an explicit env overlay** in the code. See *Precedence* below.

---

## The three config surfaces

There are exactly **three** distinct config surfaces. They are never merged with each other — each is consumed by a different code path. This is the single ownership table; everything below elaborates it.

| Surface | Example file | Shape (key) | Describes | Read by | Owns (authoritative for) |
|---|---|---|---|---|---|
| **Bridge config** | `bridge.json`, `github.json` | top-level `tools[]` (+ `baseUrl`, `auth`) | One REST/GraphQL API and the MCP tools it exposes | `serve`, `from-*`/`from`, `reverse`, `inspect`, `validate`, `mix` | Tool/topology shape: baseUrl, auth kind, tool definitions, response transforms, policy annotations |
| **Link config** | `.mcp.json`, `*.mcp.json` | top-level `mcpServers{}` map | A set of upstream MCP servers to spawn and stitch together | `link` | Upstream identity (entry key = namespace), spawn command/args, transport to each upstream |
| **Settings** | `40mcp.settings.json` | `bridge`/`frontdoor`/`instance` blocks | How *this running instance* behaves | every command, via `loadAndApplySettings` | Runtime: transport, limits, auth wiring, policy/tenant paths, vault, telemetry, instance metadata |

**What overrides what.** Bridge config and link config are *inputs to a command* — only one of the two applies to any given invocation (you either `serve` a bridge config or `link` a link config). Settings layer onto whichever command you ran, and CLI flags layer on top of settings:

```
CLI flag  >  env var (where an overlay exists)  >  settings.json  >  config/default
```

Bridge config and settings own **disjoint** concerns: the bridge config never sets a port or a concurrency limit (that's settings), and settings never define a tool (that's the bridge config). Where a runtime knob *can* be expressed both ways (e.g. transport), settings win over the bridge config's static value, and a CLI flag wins over settings — see *Precedence* below.

### Schema version field (`configVersion`)

Bridge configs may carry an optional `"configVersion": 1`. It is the **config-schema** version, set to `1` today, and is **distinct from `"version"`** — `version` is the MCP server-version string (e.g. `"1.0.0"`) shown to MCP clients. The field is named `configVersion` rather than `version` because the latter was already taken; see [SPEC.md §6](../SPEC.md#6-config-contract). When omitted, the implied version is `1`. `validate` accepts `configVersion: 1` silently and errors on any other value. `40mcp init` and `generateFromSpec` emit it.

### Ambiguous files (`tools` + `mcpServers` together)

A single file that contains **both** a `tools` array and an `mcpServers` map is ambiguous and is never merged. `serve`/`from`/`reverse`/`inspect` read `tools` and ignore `mcpServers`; `link` reads `mcpServers` and ignores `tools`. `validate` emits a warning naming which surface wins. Split such a file into a bridge config and a link config.

---

## Topology vs runtime

### Bridge config (topology)

Defines the API surface. "This is a GitHub bridge, it talks to `api.github.com`, it exposes these tools, it authenticates with a bearer from `$GITHUB_TOKEN`." Topology rarely changes between staging and prod.

```json
{
  "name": "github",
  "baseUrl": "https://api.github.com",
  "auth": { "type": "bearer", "envVar": "GITHUB_TOKEN" },
  "tools": [ { "name": "get_repo", "method": "GET", "path": "/repos/{owner}/{repo}", "inputSchema": {...} } ]
}
```

### `40mcp.settings.json` (runtime)

Defines how the running instance behaves — ports, limits, auth wiring, policy paths, telemetry. Runtime *does* change between environments.

```json
{
  "instance": { "name": "GitHub Production", "tags": ["prod"] },
  "bridge": {
    "transport": { "type": "sse", "host": "0.0.0.0", "port": 8080 },
    "limits": { "dispatch": { "maxConcurrent": 100 } }
  },
  "frontdoor": {
    "auth": { "requireBearerEnv": "FRONTDOOR_TOKEN" },
    "telemetry": { "audit": true, "events": true }
  }
}
```

### `.mcp.json` (topology, multi-upstream)

For `40mcp link`, a `.mcp.json` lists upstream MCP servers as commands to spawn. The **entry key is the canonical identity** (see *Identity model* below).

```json
{
  "mcpServers": {
    "github-prod":  { "command": "40mcp", "args": ["serve", "/etc/40mcp/github.json"] },
    "twitter-prod": { "command": "40mcp", "args": ["serve", "/etc/40mcp/twitter.json"] }
  }
}
```

---

## Identity model

**One canonical identity per upstream. Display metadata is separate.**

| Field | Source | Role |
|---|---|---|
| `.mcp.json` entry key | `.mcp.json` | Canonical machine identity. Namespace prefix for tool names (`github-prod.get_repo`). Used as the key for audit/health/events. |
| `instance.name` | `40mcp.settings.json` `instance.name` | Friendly display label (e.g. `"GitHub Production"`). Appears on stderr banners, `/health`, and audit entries. |
| `instance.tags` | `40mcp.settings.json` `instance.tags` | Operator metadata — tags like `"prod"`, `"source-control"`. Surfaces on `/health` and in audit/event entries. Not used for dispatch filtering. |

### Rules

- Every upstream has exactly one canonical identity: its `.mcp.json` entry key.
- `instance.name` never replaces the entry key — it is a display string only.
- Body-level `prefix` on a `.mcp.json` entry is **rejected**. The entry key is the prefix; duplicating it in the body created silent-override confusion and is no longer accepted.
- Tool names are fully prefixed: `<entry-key>.<tool-name>`.
- Collisions across upstreams are detected at link time and fail loudly.

> Tool names follow the invariant in [SPEC.md §2 — Tool-name invariant](../SPEC.md#tool-name-invariant). Pre-1.0 no scheme change will ship.

Example: `.mcp.json` entry key `github-prod` + settings `instance.name: "GitHub Production"` + `instance.tags: ["prod"]` produces:

- namespace: `github-prod.list_repos`
- audit entry: `{"tool":"github-prod.list_repos","instance":{"name":"GitHub Production","tags":["prod"]},...}`
- stderr banner: `[40mcp] Frontdoor published — N tools at <url> [GitHub Production prod]`

---

## Precedence

```
CLI flag  >  env var (where an overlay exists)  >  settings.json  >  default
```

- **CLI always wins** for the flags a command actually accepts, because a typed-at-the-terminal flag should never be silently ignored.
- **Env only wins where a real overlay exists.** 40mcp does not apply a blanket env-over-settings precedence — only the specific keys in the table below read env at their consumption site. Adding env overlays is deliberate; the `ENV_OVERLAY` table in `src/config/settings-show.js` is the single source of truth.
- **Settings > default.** Any key present in a loaded `40mcp.settings.json` overrides the built-in default.

### Current env overlays

| Env var | Path (as shown by `settings show`) | Is a valid settings-file key? |
|---|---|---|
| `MAX_SSE_CONNECTIONS` | `frontdoor.limits.sse.maxConnections` | Yes — env wins over settings at runtime |
| `VAULT_DAEMON_SECRET` | `bridge.vault.daemonSecret` | **No** — provenance-only row |
| `VAULT_PASSPHRASE` | `bridge.vault.passphrase` | **No** — provenance-only row |

`MAX_SSE_CONNECTIONS` maps to an actual `40mcp.settings.json` key; setting it in env overrides what's in the file. `VAULT_DAEMON_SECRET` and `VAULT_PASSPHRASE` are **runtime-only secrets** — they are surfaced by `settings show` so operators can see at a glance whether the daemon secret / passphrase is available, but they are **not** valid settings-file keys. Putting them in `40mcp.settings.json` will be rejected by the validator.

Any other setting follows `CLI > settings.json > default` with no env layer.

### Inspecting effective values

Use `40mcp settings show` to print the merged settings tree with per-key provenance (`env:<VAR>` / `settings.json:<path>` / `default`). It answers "why is it using this value?" for the layers it knows about. It does **not** know about arbitrary CLI flags, because CLI flags are only resolved in a real `serve` / `link` invocation. See [`docs/COMMANDS/settings-and-doctor.md`](COMMANDS/settings-and-doctor.md) for scope and limits.

---

## When to reach for which file

- **Change what the service exposes** (new tool, new API) → edit bridge config.
- **Change how it runs** (port, host, limits, auth wiring, policy) → edit `40mcp.settings.json`.
- **One-off override for a single run** → pass a CLI flag.
- **Inject a secret** → env var (or vault — see [SAFE-DEFAULTS.md](SAFE-DEFAULTS.md)).

---

## Related docs

- [SETTINGS.md](SETTINGS.md) — operator-first `40mcp.settings.json` guide and recipes.
- [BRIDGE_VS_FRONTDOOR.md](BRIDGE_VS_FRONTDOOR.md) — when to use `serve` vs `link`.
- [COMMANDS/settings-and-doctor.md](COMMANDS/settings-and-doctor.md) — `settings show` and `doctor` scope.
- [FRONTDOOR.md](FRONTDOOR.md) — published SSE deployment patterns.
