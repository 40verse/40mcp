# AI Workflow Integration

How to wire 40mcp into Claude Desktop, Cursor, VS Code, and other MCP clients.

---

## The idea

You have APIs. Your AI agent can't call them directly. 40mcp bridges the gap — it turns any API into MCP tools that your agent can use, with token-aware response shaping so the results don't blow up the context window.

```
Your AI Agent  ←→  40mcp  ←→  Any REST API / GraphQL / MCP Server
```

---

## Claude Desktop

### Option 1: Community config (fastest)

Add to your Claude Desktop MCP settings (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["40mcp", "serve", "configs/github.json"],
      "env": { "GITHUB_TOKEN": "" }
    }
  }
}
```

Set `GITHUB_TOKEN` in your shell environment. The empty string in the config tells 40mcp to read it from the environment at runtime — never put actual tokens in config files.

### Option 2: Your own OpenAPI spec

```json
{
  "mcpServers": {
    "my-api": {
      "command": "npx",
      "args": ["40mcp", "from-openapi", "/path/to/swagger.json"],
      "env": { "API_KEY": "" }
    }
  }
}
```

### Option 3: Link existing MCP servers through 40mcp

If you already have MCP servers but want token-aware shaping, policy gates, or a unified namespace:

```json
{
  "mcpServers": {
    "bridge": {
      "command": "npx",
      "args": ["40mcp", "link", "/path/to/.mcp.json"]
    }
  }
}
```

This connects to all servers defined in the `.mcp.json` and re-exposes their tools through 40mcp with response transforms and policy controls.

---

## Cursor

Cursor uses the same `.mcp.json` format. Add to your project root:

```json
{
  "mcpServers": {
    "stripe": {
      "command": "npx",
      "args": ["40mcp", "serve", "configs/stripe.json"],
      "env": { "STRIPE_SECRET_KEY": "" }
    }
  }
}
```

Cursor will detect the MCP server and make the tools available in the agent panel.

---

## VS Code (MCP extension)

VS Code MCP extensions read from `.mcp.json` in the workspace root. Same format as Cursor:

```json
{
  "mcpServers": {
    "linear": {
      "command": "npx",
      "args": ["40mcp", "serve", "configs/linear.json"],
      "env": { "LINEAR_API_KEY": "" }
    }
  }
}
```

---

## Claude Code (CLI)

Claude Code reads `.mcp.json` from the project root automatically. Add 40mcp as a server:

```json
{
  "mcpServers": {
    "notion": {
      "command": "npx",
      "args": ["40mcp", "serve", "configs/notion.json"],
      "env": { "NOTION_API_KEY": "" }
    }
  }
}
```

Claude Code will pick it up on next session start.

---

## SSE transport (remote deployment)

For shared or remote deployments, run 40mcp as an SSE server:

```bash
npx 40mcp serve configs/github.json --sse 8080
```

Then point your MCP client to `http://localhost:8080/sse` (or your deployed URL). This works with any MCP client that supports SSE transport.

---

## Multiple APIs in one server

Use `mix` to combine several APIs into a single MCP server:

```bash
npx 40mcp mix configs/github.json configs/linear.json configs/slack.json
```

Or as a single `.mcp.json` entry:

```json
{
  "mcpServers": {
    "all-apis": {
      "command": "npx",
      "args": ["40mcp", "mix", "configs/github.json", "configs/linear.json", "configs/slack.json"],
      "env": {
        "GITHUB_TOKEN": "",
        "LINEAR_API_KEY": "",
        "SLACK_BOT_TOKEN": ""
      }
    }
  }
}
```

---

## Token-aware response shaping

Add response transforms to any tool to control how much context it consumes:

```json
{
  "tools": [
    {
      "name": "list_issues",
      "response": {
        "pick": ["number", "title", "state"],
        "limit": 25,
        "tokenBudget": 4000,
        "summary": "Showing {shown} of {total} issues"
      }
    }
  ]
}
```

Without transforms, a `list_issues` call returning 500 issues burns 50k+ tokens. With them, the agent gets a focused 4k-token summary.

---

## Policy gates (human-in-the-loop)

Mark dangerous tools for approval before execution:

```json
{
  "tools": [
    {
      "name": "delete_repository",
      "policy": "require_approval"
    }
  ]
}
```

When the agent tries to call `delete_repository`, execution pauses until a human approves.

---

## From browser traffic (no spec needed)

Record your browser traffic as a HAR file, then:

```bash
npx 40mcp from-har ./recording.har
```

40mcp reverse-engineers tool definitions from the traffic patterns. Useful for undocumented APIs, internal tools, or legacy systems.

---

## Credential handling

**Never put plaintext API keys in config files.** Config files are typically committed to version control.

| Approach | When to use |
|----------|-------------|
| Environment variables | Development and most deployments |
| Sealed vault | Production — AES-256-GCM encryption, zero plaintext on disk |

```bash
# Environment variable (standard)
export GITHUB_TOKEN=<your-github-token>
npx 40mcp serve configs/github.json

# Sealed vault (production)
npx 40mcp vault init
npx 40mcp vault seal GITHUB_TOKEN
npx 40mcp serve configs/github.json --vault
```

---

## Verifying your setup

```bash
# Check what tools are available without starting a server
npx 40mcp inspect configs/github.json

# Validate a config file
npx 40mcp validate configs/github.json

# Generate a config from an OpenAPI spec (deterministic, no LLM)
npx 40mcp generate swagger.json --out my-api.json
```

---

## Available community configs

Community configs ship with 40mcp, covering GitHub, Stripe, Slack, Linear, Notion, Jira, Gmail, Airtable, Discord, HubSpot, Sentry, Twilio, Vercel, Shopify, and more.

[Browse all configs →](../configs/)

Each config includes a `usage` block with required env vars and setup instructions.

---

## Further reading

- [README](../README.md) — Install, features, full API reference
- [SPEC.md](../SPEC.md) — Product specification and stability contract
- [SAFE-DEFAULTS.md](SAFE-DEFAULTS.md) — Security controls active by default
- [CONTRIBUTING.md](../CONTRIBUTING.md) — Development guide
