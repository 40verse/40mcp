# 40mcp

The universal API-to-MCP bridge. **Any API. Any direction. Token-aware.**

A [40verse](https://github.com/40verse) project.

[![npm version](https://img.shields.io/npm/v/40mcp.svg)](https://www.npmjs.com/package/40mcp)
[![GitHub Stars](https://img.shields.io/github/stars/40verse/40mcp.svg)](https://github.com/40verse/40mcp)
[![npm downloads](https://img.shields.io/npm/dm/40mcp.svg)](https://www.npmjs.com/package/40mcp)

**[Community configs →](configs/) · [Specification →](SPEC.md) · [API reference →](API.md) · [Troubleshooting →](TROUBLESHOOTING.md) · [Changelog →](CHANGELOG.md)**

---

## 60-second golden path

One command. No API keys. Two real public MCP upstreams. Proof 40mcp works before you commit to anything:

```bash
npx 40mcp@beta link configs/microsoft-huggingface-bridge.mcp.json
```

**What happens:** 40mcp reads the `.mcp.json`, opens SSE/HTTP connections to Microsoft Learn Docs and HuggingFace's public MCP endpoints, namespaces their tools under `msdocs.*` and `hf.*`, and presents them to your MCP client as one surface. No credentials required — both upstreams are public.

List the tools without starting the bridge:

```bash
npx 40mcp@beta link configs/microsoft-huggingface-bridge.mcp.json --inspect
```

Expected shape (tool names vary upstream-to-upstream — browse [`configs/microsoft-huggingface-bridge.mcp.json`](configs/microsoft-huggingface-bridge.mcp.json) for the reference config):

```
msdocs.microsoft_docs_search        — search Microsoft Learn documentation
msdocs.microsoft_docs_fetch         — fetch a full doc page as markdown
msdocs.microsoft_code_sample_search — search Microsoft/Azure code samples
hf.model_search                     — search HuggingFace models
hf.dataset_search                   — search HuggingFace datasets
…
```

> **Requires Node 18+.** The demo reaches `learn.microsoft.com` and `huggingface.co` — if your network blocks either, the `link` command fails with a clear error rather than hanging.

### The two linking configs the demo uses

The command runs the **aggregator** file in [`configs/`](configs/microsoft-huggingface-bridge.mcp.json), which links the two prefixed upstream entries below as a single MCP surface. You don't run the two config files directly — the aggregator does.

| Config | Upstream | Prefix |
|--------|----------|--------|
| [`configs/microsoftdocs.mcp.json`](configs/microsoftdocs.mcp.json) | `https://learn.microsoft.com/api/mcp` | `msdocs.` |
| [`configs/huggingface.mcp.json`](configs/huggingface.mcp.json) | `https://huggingface.co/mcp` | `hf.` |

Both upstream configs are public, require no credentials, and stay inside the MCP protocol end-to-end. The rest of [`configs/`](configs/) are REST-bridge configs (GitHub, Stripe, Slack, …) rather than MCP-to-MCP linking configs.

### What to try next

- **Give it a real API.** [Serve a community config →](#from-a-community-config) — GitHub, Stripe, Slack, Linear, and 25+ more live under [`configs/`](configs/).
- **Publish it.** [Deploy a single authenticated frontdoor over SSE →](docs/FRONTDOOR.md) for remote MCP clients (GPT Actions, claude.ai, Cursor).
- **Learn the mental model.** [Bridge vs frontdoor →](docs/BRIDGE_VS_FRONTDOOR.md) — `serve` exposes one API; `link` fronts many.

---

## Why 40mcp over basic OpenAPI bridges?

Basic OpenAPI → MCP converters exist and are fine for quick prototypes. 40mcp is the choice when you need advanced features:

| Capability | Basic bridges | 40mcp |
|-----------|--------------|-------|
| Token-aware response shaping | No | Yes — `tokenBudget`, `pick`, `omit`, `limit` |
| Compound tool chains | No | Yes — multi-step sequences as single tools |
| Undocumented API discovery | No | Yes — HAR loader reverse-engineers from traffic |
| Sealed credential vault | No | Yes — AES-256-GCM, zero-plaintext, JIT tokens |
| Human-in-the-loop policy gates | No | Yes — per-tool approval before dispatch |
| Self-referential API archaeology | No | Yes — reverse bridge → HAR → reload → new bridge |
| Multi-tenant auth isolation | No | Yes — per-call auth context, allowlist/blocklist |
| Security controls | Varies | Yes — prototype-safe, SSRF-blocked, injection-hardened, input-validated (see [SAFE-DEFAULTS.md](docs/SAFE-DEFAULTS.md)) |

**Rule of thumb:** Use a basic bridge for a single documented API in development. Use 40mcp when token efficiency matters, the API is undocumented, or you need security controls, policy gates, or composition.

For a head-to-head comparison vs FastMCP specifically, see [docs/COMPARISON.md](docs/COMPARISON.md).

---

## Install

```bash
npm install -g 40mcp@beta     # or: npx 40mcp@beta <command>
```

**Node.js >= 18 required.** Tested on 18.x LTS, 20.x, 22.x. Linux / macOS / Windows. One production dependency (`@modelcontextprotocol/sdk`).

### Release status

| | |
|---|---|
| **Version** | See [`package.json`](package.json) — 0.1.x beta line |
| **Versioning** | [Semver](https://semver.org). Pre-1.0: minor versions may include breaking changes; patch versions are backwards-compatible fixes |
| **Open security blockers** | 0 — see [security advisories](https://github.com/40verse/40mcp/security/advisories) |
| **Supported Node versions** | 18.x LTS · 20.x · 22.x |
| **Test suite** | `npm run test:all` — runs on every PR against Node 18 / 20 / 22 via GitHub Actions |
| **Contract** | See [SPEC.md](SPEC.md) — security model, operational limits, non-goals |

---

## Features

| Feature | What it does |
|---------|-------------|
| **OpenAPI/Swagger loader** | Spec → MCP tools (3.x + 2.x) |
| **GraphQL loader** | Introspection → MCP tools |
| **HAR loader** | Browser traffic → MCP tools (no spec needed) |
| **Plugin system** | `registerLoader()` for gRPC, WebSocket, SOAP, etc. |
| **Response transforms** | Token-aware shaping — pick, omit, limit, tokenBudget |
| **Compound chains** | Multi-call sequences as single tools (depth-guarded) |
| **Server mixing** | Combine N APIs into one MCP server |
| **SSE transport** | Serve remotely, not just stdio |
| **Config validation** | Catch errors before runtime with `40mcp validate` |
| **Authentication** | Header, bearer, basic, OAuth2 (auto-refresh) |
| **AI generation** | Deterministic: spec → config, no LLM needed |
| **TUI** | Spinner, progress, tables, color, NO_COLOR compliant |
| **Reverse bridge** | MCP tools → REST API + auto-generated OpenAPI spec |
| **Webhook ingestion** | HTTP webhooks → tool dispatch with HMAC validation |
| **Multi-tenant** | Per-call auth context, tool allowlist/blocklist |
| **Sealed vault** | AES-256-GCM envelope encryption for API keys |
| **Policy gates** | Human-in-the-loop approval for dangerous actions |
| **MCP linking** | Connect to existing MCP servers, re-expose with policy gates |
| **Steering** (`40mcp/steering`) | Forced-inference write classification for agent memory tools |
| **AI generation (LLM prompt)** | Describe an API → get a prompt pair for any LLM |

See [SPEC.md](SPEC.md) for the full contract and non-goals.

## Other quick-starts

After the golden path above, here are the other entry points by input type:

```bash
npx 40mcp from-openapi ./swagger.json       # Spec → MCP server
npx 40mcp from ./recording.har              # Auto-detect (OpenAPI / GraphQL / HAR)
npx 40mcp serve configs/github.json         # Ship a community config
npx 40mcp link .mcp.json                    # Link to existing MCP servers
npx 40mcp generate spec.json --out api.json # Generate config from spec (deterministic)
```

### AI coding-agent onboarding

Paste this into Claude Code, Cursor, or any coding agent to wire 40mcp into your workflow automatically:

> **Set up 40mcp in my workflow.**
>
> I want to use 40mcp to bridge MCP servers into my AI tooling. Please:
>
> 1. Install: `npm install -g 40mcp` (or run via `npx 40mcp`).
> 2. Read `configs/microsoft-huggingface-bridge.mcp.json` and `test/bridge-microsoft-huggingface.test.js` so you understand the linking model.
> 3. Look at my existing `.mcp.json` (or create one if it doesn't exist).
> 4. Add 40mcp as a linker in front of my current MCP servers so I get token-aware response shaping, policy gates, and a unified tool namespace. Use `connectFromConfig` under the hood.
> 5. Smoke-test with two upstream servers:
>    - **Microsoft Learn Docs** (`https://learn.microsoft.com/api/mcp`) — no auth required, prefix `msdocs.`
>    - **HuggingFace** (`https://huggingface.co/mcp`) — public read-only works without a token, prefix `hf.`
> 6. Run `npx 40mcp link <config> --inspect` and show me the resulting tool list. Confirm dispatch works for `msdocs.microsoft_docs_search` and `hf.model_search`.
> 7. If anything fails (network blocked, etc.) stop and tell me exactly what to do — don't silently skip.
>
> Reference implementation: `configs/microsoft-huggingface-bridge.mcp.json`

## Input-type reference

Every format 40mcp can consume, one section each.

### From an OpenAPI Spec

```bash
npx 40mcp from-openapi ./swagger.json
```

### From Browser Traffic (No Spec)

```bash
npx 40mcp from-har ./recording.har --min-observations 3
```

### From a Community Config

```bash
npx 40mcp serve configs/github.json
```

Configs available across GitHub, Stripe, Slack, Jira, Linear, Notion, and more. [Browse all configs →](configs/)

### Add to `.mcp.json`

```json
{
  "mcpServers": {
    "my-api": {
      "command": "npx",
      "args": ["40mcp", "from-openapi", "./swagger.json"],
      "env": { "API_KEY": "" }
    }
  }
}
```

> **Credential handling:** Leave `"API_KEY": ""` — the value is populated from your shell environment at runtime, not from this file. Never put a plaintext API key as the value here; `.mcp.json` is typically committed to version control. For production use, see [Sealed Vault](#sealed-vault-zero-plaintext-credentials) to manage secrets without exposing them in any environment variable.

### Programmatic

```js
import { createRestBridge, loadOpenApiSpec } from '40mcp';

const { baseUrl, tools } = await loadOpenApiSpec('./swagger.json');
await createRestBridge({
  name: 'my-api',
  baseUrl,
  tools,
  auth: { type: 'bearer', envVar: 'API_TOKEN' }, // credentials from env, not hardcoded
}).start();
```

## Response Transforms (Token-Aware)

MCP tools dump raw JSON into the agent's context. A `list_users` returning 500 users burns 50k tokens. Response transforms shape output before it hits the context window.

```json
{
  "response": {
    "pick": ["id", "name", "email"],
    "limit": 25,
    "summary": "Showing {shown} of {total} users",
    "tokenBudget": 4000
  }
}
```

| Transform | What it does |
|-----------|-------------|
| `pick` | Keep only these fields (dot-notation: `"user.name"`) |
| `omit` | Remove these fields |
| `limit` | Cap array to N items |
| `summary` | Prepend count metadata when truncated |
| `tokenBudget` | Hard cap -- truncate to fit token budget |
| `flatten` | Nested objects -> dot-notation keys |
| `template` | Format each item: `"{name} ({email})"` |

## Compound Tool Chains

Multi-call sequences as a single tool. The bridge resolves `$references`, parallelizes independent steps, and merges results. Recursion depth guard prevents infinite loops.

```json
{
  "name": "get_user_full_profile",
  "chain": [
    { "call": "get_user", "args": { "user_id": "$args.user_id" }, "as": "user" },
    { "call": "list_devices", "args": { "user_id": "$args.user_id" }, "as": "devices" },
    { "call": "get_activity", "args": { "user_id": "$user.id" }, "as": "activity" }
  ]
}
```

## MCP Server Linking

Connect to existing MCP servers and re-expose their tools with 40mcp's features on top:

```bash
40mcp link .mcp.json                    # Connect to all configured servers
40mcp link npx @some/mcp-server         # Connect to a single server

# Publish a linked frontdoor as a single authenticated SSE MCP endpoint.
# Upstreams run as stdio children inside the same process; only this port
# is public. See docs/FRONTDOOR.md for the full deployment guide.
40mcp link frontdoor.mcp.json --sse 8080 --host 0.0.0.0 \
  --require-bearer-env FRONTDOOR_TOKEN
```

```js
import { connectStdio, connectFromConfig } from '40mcp';

// Single server
const server = await connectStdio({
  command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
  prefix: 'fs',
});
console.log(server.tools); // [{ name: 'fs.read_file', ... }]

// From .mcp.json
const cluster = await connectFromConfig(mcpJson.mcpServers);
await cluster.dispatch('github.list_repos', { owner: 'me' });
```

## Security Note

> **Treat a 40mcp config file like executable code.** It controls which APIs are called, which credentials are forwarded, and how tool arguments are processed. Do not load configs from untrusted sources without review. See [SPEC.md](SPEC.md) §7 for the full threat model and security model.

## Sealed Vault (Zero-Plaintext Credentials)

API keys are envelope-encrypted at rest with AES-256-GCM. At runtime, bridges access them via short-lived JWTs — sealed API keys never appear in `process.env` or config files.

**Production: use the vault daemon.** The daemon holds the passphrase in memory; bridge processes authenticate with a scoped `VAULT_DAEMON_SECRET` and receive short-lived JWTs. No process ever holds the master passphrase:

```bash
# Start daemon once (prints VAULT_DAEMON_SECRET — store it securely)
40mcp vault daemon start --background
```

```js
import { createVaultDaemonClient, createRestBridge } from '40mcp';

const vaultClient = createVaultDaemonClient({
  daemonSecret: process.env.VAULT_DAEMON_SECRET, // scoped token, not the passphrase
});

const bridge = createRestBridge({
  hooks: { beforeRequest: vaultClient.createBearerHook('GITHUB_TOKEN') },
  // ...
});
```

**Local development only:** passing `VAULT_PASSPHRASE` directly via env var is the quick-start path. Avoid this in production — the passphrase in an env var is readable by any process in the same environment and will appear in process listings.

```js
// ⚠ Local / development only — do not use in production
const vault = createVault({ path: '.vault.json', passphrase: process.env.VAULT_PASSPHRASE });

// Seal a secret (returns seal:// ID)
const sealId = await vault.set('GITHUB_TOKEN', '<your-github-token>', { service: 'github' });

// Issue a 5-minute JWT credential
const { token } = await vault.issueToken('GITHUB_TOKEN');

// JIT auth hook (unseals per-request, in-memory only)
const hook = vault.createAuthHook({ GITHUB_TOKEN: 'Authorization' });
```

## Human-in-the-Loop Policy Gates

Gate dangerous tool calls with configurable approval:

```js
import { createPolicyGate, createStdinApprovalHandler } from '40mcp';

const gated = createPolicyGate({
  dispatch: bridge.dispatch,
  approvalHandler: createStdinApprovalHandler(), // CLI approval prompt
  toolPolicies: { delete_user: 'require_approval' },
});
```

Tools can declare `"policy": "require_approval"` in their config. Policy rules: `allow`, `deny`, `require_approval`, `log_only`.

## AI-Assisted Config Generation

```bash
# Deterministic: OpenAPI spec → config (no LLM needed)
40mcp generate spec.json --out my-api.json

# LLM-assisted: get prompt pair for any model
40mcp generate --describe "Stripe payments API"
```

```js
import { generatePrompt, parseGeneratedConfig, generateFromSpec } from '40mcp';

// For any LLM
const { system, user } = generatePrompt({ description: 'GitHub REST API' });
// Feed to Claude, GPT, Gemini, local model, etc.

// Deterministic (no LLM)
const config = generateFromSpec(openApiSpec);
```

## Authentication

| Mode | Config |
|------|--------|
| Header | `{ type: 'header', header: 'X-API-Key', envVar: 'API_KEY' }` |
| Bearer | `{ type: 'bearer', envVar: 'TOKEN' }` |
| Basic | `{ type: 'basic', envVar: 'CREDS' }` |
| OAuth2 | `{ type: 'oauth2', tokenUrl: '...', clientIdEnv: '...', clientSecretEnv: '...' }` |

OAuth2 auto-refreshes tokens with expiry-aware caching and concurrent request coalescing.

## CLI Reference

```
40mcp serve <config>                  Start MCP server from config
40mcp from <spec-or-url>              Auto-detect format and start
40mcp from-openapi <spec>             OpenAPI/Swagger -> MCP server
40mcp from-graphql <endpoint>         GraphQL -> MCP server
40mcp from-har <recording.har>        HAR -> MCP server
40mcp mix <c1.json> <c2.json> [...]   Combine APIs into one server
40mcp reverse <config> --port 8080    MCP tools -> REST API
40mcp link <.mcp.json|command>        Link to existing MCP servers
40mcp generate <spec|--describe>      Generate config (AI or deterministic)
40mcp inspect <config>                List tools without starting
40mcp validate <config>               Validate config, report errors
40mcp init                            Interactive starter-config wizard
40mcp doctor <config>                 Auth / reachability / shape diagnostics
40mcp vault <sub>                     Sealed-vault ops (init, seal, list,
                                      rotate, rotate-kek, delete, recover, daemon)
```

## Architecture

Modules mapped to dimensions:

```
D1: The Line (core bridge)
+-- bridge.js              Dispatch engine
+-- core/client.js         API client (auth, OAuth2, timeout)
+-- core/path.js           URL interpolation, query strings
+-- transport/             stdio + SSE

D2: The Plane (loaders + discovery)
+-- openapi.js             OpenAPI 3.x + Swagger 2.x
+-- loaders/graphql.js     GraphQL introspection
+-- loaders/har.js         HAR traffic recording
+-- loaders/registry.js    Plugin system + auto-detection
+-- generate.js            AI-assisted config generation

D3: The Cube (composition + shaping)
+-- compose/chain.js       Compound chains (depth-guarded)
+-- compose/mixer.js       Multi-server mixing
+-- transforms/response.js Token-aware response shaping
+-- connect.js             MCP-to-MCP client connector
+-- webhook/listener.js    Webhook ingestion
+-- tenant/scope.js        Multi-tenant scoping

D4: The Tesseract (self-reference + security)
+-- reverse/server.js      MCP -> REST (+ auto OpenAPI spec)
+-- security/vault.js      Sealed credential vault (envelope encryption)
+-- security/policy.js     Human-in-the-loop gates
+-- validate.js            Config validation
+-- tui.js                 Terminal UI primitives

Meta:
+-- index.d.ts             Full TypeScript declarations
+-- errors.js              Structured error taxonomy (19 codes)
+-- cli.js                 14 subcommands

configs/                   Community configs (see directory for current list)
+-- github.json            GitHub API
+-- stripe.json            Stripe API
+-- slack.json             Slack API
+-- linear.json            Linear API
+-- sentry.json            Sentry API
+-- ...and more            [Browse all configs →](configs/)
```

One dependency: `@modelcontextprotocol/sdk`. All other functionality uses Node builtins. Full TypeScript via `.d.ts`.

## The Tesseract

40mcp builds through four dimensions, where each folds the previous into itself:

```
D1: REST Bridge        D2: Loaders           D3: Composition       D4: Self-Reference
   *------*            ==========            +---------+           +---------+
                       ==========            | Mixer   |          /| Reverse/|
  REST API             OpenAPI               | Chain   |         +---------+ |
     |                 GraphQL               | Shape   |         | Bridge  | |
  MCP Tools            HAR replay            +---------+         | wraps   |/
                          |                      |               +-itself--+
                       MCP Tools             MCP Tools                |
                                                                 loop
```

**D1 -- The Line.** One REST API becomes MCP tools.

**D2 -- The Plane.** Multiple protocols (OpenAPI, GraphQL, HAR, plugins) converge onto one tool surface.

**D3 -- The Cube.** Tools interact. Mixer combines APIs. Chains compose multi-step operations. Transforms shape output.

**D4 -- The Tesseract.** Reverse Bridge inverts direction — MCP tools become REST endpoints. Then: reverse bridge → HAR capture → HAR loader → new bridge. **40mcp wraps itself.**

**Deep dive:** [CONCEPT.md](CONCEPT.md) — why each dimension is a structural transformation, not a feature list.

## Local Development Without API Keys

40mcp works offline against [vercel-labs/emulate](https://github.com/vercel-labs/emulate) — a local API emulator that runs production-fidelity servers for GitHub, Vercel, Slack, Google, Microsoft, and AWS on localhost. No real credentials, no network calls, no rate limits.

> **Repo-only fixtures.** The `.emulate/` directory below lives in the git checkout of this repository and is **not** bundled into the published npm package. To use these seed configs, clone the repo (`git clone https://github.com/40verse/40mcp`) and run the commands from the repo root. Consumers installing via `npm install 40mcp` should point `npx emulate` at their own config and bridge it to 40mcp with their own config files.

```bash
# Inside a git checkout of 40mcp:

# Start emulated APIs
npx emulate --service github,vercel,slack --seed .emulate/emulate.config.yaml

# Start 40mcp pointing at them (pre-built configs included in the repo)
npx 40mcp serve .emulate/configs/github.json   # → localhost:4001
npx 40mcp serve .emulate/configs/vercel.json   # → localhost:4000
npx 40mcp serve .emulate/configs/slack.json    # → localhost:4003

# Or mix into one MCP server
npx 40mcp mix .emulate/configs/github.json .emulate/configs/vercel.json .emulate/configs/slack.json
```

Seed data, CI integration, and file persistence docs live in [`.emulate/README.md`](https://github.com/40verse/40mcp/blob/main/.emulate/README.md) (repo-only).

## Deploy

### One-Click Cloud Deploy

Deploy 40mcp to a cloud platform with your bridge config mounted as a volume or secret:

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/40verse/40mcp)
&nbsp;&nbsp;
[![Deploy to Fly.io](https://www.deploytoflyio.com/button.svg)](https://fly.io/launch?from=github.com/40verse/40mcp)

### Docker

```bash
# Pull the official image
docker pull ghcr.io/40verse/40mcp:latest

# Run with your config
docker run -p 8080:8080 \
  -v ./my-config.json:/config.json:ro \
  --env-file .env \
  ghcr.io/40verse/40mcp:latest

# Or use the docker-compose template
cp examples/docker-compose.yml .
docker compose up
```

See [`examples/docker-compose.yml`](examples/docker-compose.yml) for vault volume, env file, and port mapping.
See [`fly.toml`](fly.toml) and [`railway.json`](railway.json) for platform-specific config.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and PR guidelines.

For AI-assisted contributors: [AGENTS.md](AGENTS.md) covers codebase orientation, architecture rules, and security-critical surfaces.

## Integration Guide

Detailed setup for Claude Desktop, Cursor, VS Code, Claude Code, and SSE deployments: [docs/ai-workflow.md](docs/ai-workflow.md)

## Configuration & Operator Docs

- [docs/CONFIGURATION_MODEL.md](docs/CONFIGURATION_MODEL.md) — topology vs runtime, identity, precedence
- [docs/SETTINGS.md](docs/SETTINGS.md) — `40mcp.settings.json` operator guide with recipes
- [docs/BRIDGE_VS_FRONTDOOR.md](docs/BRIDGE_VS_FRONTDOOR.md) — `serve` vs `link` mental model
- [docs/COMMANDS/settings-and-doctor.md](docs/COMMANDS/settings-and-doctor.md) — `settings show` and `doctor` scope
- [docs/FRONTDOOR.md](docs/FRONTDOOR.md) — published SSE deployment patterns
- [docs/TESTING.md](docs/TESTING.md) — operator testing strategy for bridges, frontdoors, tenants, and policy gates
- [docs/COMPARISON.md](docs/COMPARISON.md) — 40mcp vs FastMCP capability matrix
- [docs/MIGRATION_FROM_FASTMCP.md](docs/MIGRATION_FROM_FASTMCP.md) — FastMCP → 40mcp primitive mapping and divergences

## License

MIT. 40mcp is MIT-licensed and fully usable for self-hosting. Hosted or commercial layers may exist separately, but the core bridge remains open source.
