# Bridge vs Frontdoor

Two shapes, two commands, two clusters in `40mcp.settings.json`. Knowing which applies when is the single most important mental model in 40mcp.

---

## The distinction

| | Bridge | Frontdoor |
|---|---|---|
| Command | `40mcp serve` | `40mcp link` |
| Settings cluster | `bridge.*` | `frontdoor.*` |
| What it does | Turns **one** API into MCP tools | Publishes **N** upstream MCP servers behind a single authenticated surface |
| Topology input | Bridge config (`github.json`, `twitter.json`) | `.mcp.json` listing upstream MCP servers |
| Default transport | stdio | stdio |
| Typical deployment | Embedded in one MCP client, or a private SSE sidecar | Public SSE endpoint for remote MCP clients |
| Holds upstream credentials? | Yes | No — frontdoor owns publication, not execution |

---

## Bridge (`40mcp serve`)

A bridge **is an API**. It reads a bridge config, talks HTTP to one baseUrl, and exposes the result as MCP tools. Every 40mcp instance you run against a REST API, GraphQL endpoint, HAR recording, or OpenAPI spec is a bridge.

```
┌─────────┐        ┌─────────┐        ┌─────────┐
│ MCP     │ stdio  │ bridge  │ HTTP   │  API    │
│ client  │◄──────►│ 40mcp   │◄──────►│ (e.g.   │
│         │        │ serve   │        │ GitHub) │
└─────────┘        └─────────┘        └─────────┘
```

A bridge can also publish itself over SSE. That does **not** make it a frontdoor — it's still one API, still `bridge.*` settings, still `40mcp serve`. The `--sse` flag is about *transport*, not about *role*.

```
┌─────────┐  HTTP/SSE  ┌─────────┐   HTTP   ┌─────────┐
│ client  │◄──────────►│ bridge  │◄────────►│   API   │
│         │            │  (self- │          │         │
│         │            │ published)│        │         │
└─────────┘            └─────────┘          └─────────┘
```

**Settings:** `bridge.*` controls transport, dispatch limits, request/response size caps, SSRF/network, and vault.

## Frontdoor (`40mcp link`)

A frontdoor **is a façade**. It links multiple upstream MCP servers (each typically a bridge) and re-exposes them under one authenticated surface. It doesn't call any upstream API itself — it's an authority boundary and a namespace-collapser.

```
            ┌──────────────┐
            │   frontdoor  │
            │   40mcp link │
┌────────┐  │   :8080 SSE  │  stdio   ┌──────────────┐
│ remote │  │  bearer auth │◄────────►│ github       │
│ client │◄►│              │          │ 40mcp serve  │
│        │  │              │  stdio   ├──────────────┤
└────────┘  │              │◄────────►│ twitter      │
            │              │          │ 40mcp serve  │
            └──────────────┘          └──────────────┘
```

The separation is the point:

- **Upstream bridges** hold credentials and execute tools.
- **The frontdoor** owns publication, namespace, and inbound access. It does not hold upstream credentials.

**Settings:** `frontdoor.*` controls transport, bearer/multi-token auth, SSE session caps, tool surface filters, policy/tenant/steering paths, and telemetry.

See [FRONTDOOR.md](FRONTDOOR.md) for deployment patterns and auth modes.

---

## Rule of thumb

| If you are… | You are configuring a… |
|---|---|
| Turning one REST/GraphQL API into MCP tools | Bridge |
| Running multiple bridges, exposing them through one endpoint | Frontdoor |
| Publishing a single bridge over SSE with no aggregation | Bridge (still) — `--sse` is just transport |

When in doubt: **does your config list multiple upstreams?** If yes, it's a frontdoor (`link`). If no, it's a bridge (`serve`).

---

## Settings overlap

`instance.*` applies to both. Every other key belongs to exactly one cluster:

- `bridge.limits.dispatch.*`, `bridge.network.strictSsrf`, `bridge.vault.*` — bridge only.
- `frontdoor.auth.*`, `frontdoor.surface.allowTools`, `frontdoor.policy.path`, `frontdoor.telemetry.*` — frontdoor only.
- `bridge.transport.*` and `frontdoor.transport.*` are parallel — the right one applies depending on which command runs.

Mixing them is a common operator mistake. `40mcp settings show` reports the merged tree with provenance so you can confirm which cluster is active.

---

## Where `doctor` and `settings show` fit

Both commands reason across runtime settings — not just the bridge config. That means they can surface cross-layer problems that would only show up at startup or first request otherwise:

- `doctor` checks config + settings + env-shadow drift + runtime safety combinations (non-loopback SSE without auth, tenant-map without multi-token auth, vault daemon without a secret, etc.).
- `settings show` prints the merged settings + env overlays + defaults with per-key provenance.

See [COMMANDS/settings-and-doctor.md](COMMANDS/settings-and-doctor.md).

---

## Related docs

- [CONFIGURATION_MODEL.md](CONFIGURATION_MODEL.md) — the full topology/runtime/override model.
- [SETTINGS.md](SETTINGS.md) — operator-first settings guide.
- [FRONTDOOR.md](FRONTDOOR.md) — published-frontdoor deployment patterns.
