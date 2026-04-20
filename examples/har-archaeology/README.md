# Example: HAR Archaeology

Turn undocumented API traffic into runnable MCP tools — no spec required.

## What this demonstrates

You capture real browser traffic to an undocumented (or poorly documented) API, then let 40mcp reverse-engineer the tool definitions from the requests. The HAR file IS the spec.

## Step 1 — Record traffic

Open Chrome DevTools (F12), go to the Network tab, and interact with the target API or web app as you normally would. When done:

1. Right-click any request in the Network panel
2. Select **Save all as HAR with content**
3. Save as `recording.har`

For APIs with auth headers, make sure to log in first so the session is captured in the HAR.

> **Security — HAR files capture auth credentials.** Your session tokens, API keys, and `Authorization` headers will be embedded in the `.har` file in plaintext. Before committing or sharing the HAR or any generated config:
> 1. Redact auth headers from the HAR file (see [Auth Headers in HAR](../../TROUBLESHOOTING.md#auth-headers-in-har) in TROUBLESHOOTING.md for the `jq` redaction command)
> 2. Replace any plaintext token values in the generated config with `seal://` vault IDs
>
> Treat an unredacted HAR file like a plaintext credential dump. If one is committed to git, rotate all captured keys immediately.

## Step 2 — Generate MCP tools

```bash
npx 40mcp from-har recording.har --min-observations 3
```

`--min-observations 3` filters out one-off requests — only endpoints seen 3+ times across the recording are promoted to tools. Lower the threshold for APIs you called only once.

40mcp will print the detected tools and start an MCP server:

```
Detected 7 tools from recording.har (34 requests, 12 unique endpoints)
  GET  /api/users           → list_users
  GET  /api/users/:id       → get_user
  POST /api/orders          → create_order
  ...
```

## Step 3 — Inspect or export

To see what was generated without starting a server:

```bash
npx 40mcp inspect --from-har recording.har
```

To save a reusable config file:

```bash
npx 40mcp generate recording.har --out my-api.json
npx 40mcp serve my-api.json
```

## How it works

`loadHarFile` reads the HAR's `entries` array, groups requests by method + path pattern (`:param` detection via UUID/integer heuristics), extracts request/response schemas from the captured JSON bodies, and emits tool definitions. Authentication headers from the recording are extracted as config hints — **do not commit the generated config before replacing plaintext auth values with `seal://` vault IDs** (see Step 1 warning above).

## Full archaeology loop

For maximum coverage — including reconstructing a machine-readable OpenAPI spec from an API with no documentation at all — see the self-referential loop example:

```
recording.har → from-har → MCP server → reverse → OpenAPI spec
```

See [examples/self-referential-loop](../self-referential-loop/README.md).
