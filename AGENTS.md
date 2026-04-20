# AGENTS.md

Guide for using AI coding agents (Claude Code, Cursor, Copilot, etc.) to contribute to the 40mcp codebase.

---

## Quick orientation

```
src/
├── bridge.js        Core dispatch engine (tools/call → HTTP → result)
├── cli.js           CLI (serve, from-openapi, mix, reverse, vault, init, doctor, etc.)
├── errors.js        Structured error codes
├── validate.js      Config validation
├── core/            Client, path interpolation, env guards, types
├── loaders/         OpenAPI, GraphQL, HAR, plugin registry
├── transforms/      Token-aware response shaping (pick, omit, limit, tokenBudget)
├── compose/         Chains (multi-step) + mixer (multi-server)
├── transport/       Stdio + SSE transport
├── reverse/         MCP → REST bridge
├── webhook/         Webhook ingestion
├── tenant/          Multi-tenant scoping
├── security/        Sealed vault, policy gates, invariant tests
└── steering/        Steering directives

test/                Integration tests (emulate-compatible)
configs/             Community API configs (browse directory for current count)
examples/            Runnable examples and demos
docs/                Reference docs
```

## Before you start

```bash
npm install
npm test            # Unit tests — must pass
npm run lint        # ESLint — must be clean
```

## Development workflow

```bash
npm test                    # Unit tests (src/**/*.test.js)
npm run test:integration    # Integration tests (test/*.test.js)
npm run test:all            # Everything
npm run test:invariants     # Security invariant suite only
npm run lint                # ESLint check
npm run lint:fix            # Auto-fix lint issues
npm run check:loc           # File size thresholds
npm run verify              # lint + test:all + npm pack dry-run
```

## Architecture rules

These constraints define the project's shape. Respect them in all contributions:

1. **One dependency** — `@modelcontextprotocol/sdk` is the only runtime dependency. Do not add npm packages.
2. **Pure ESM** — `"type": "module"` in package.json. No CommonJS.
3. **Node built-in test runner** — `node:test` + `node:assert`. No Jest, Vitest, or Mocha.
4. **JSDoc + index.d.ts** — No TypeScript source. Types are provided via JSDoc comments and a hand-maintained `src/index.d.ts`.
5. **Snake_case tools, camelCase JS** — Tool names use `snake_case` (MCP convention). JavaScript functions use `camelCase`.
6. **Config is code** — Treat config files like executable code. Never trust user-supplied configs without validation.

## Security-critical surfaces

If you're editing these files, you're touching security-load-bearing code. Run `npm run test:invariants` after every change:

| File | What it guards |
|------|---------------|
| `src/core/env.js` | SSRF protection (`assertSafeUrl`) |
| `src/core/object.js` | Prototype pollution guards |
| `src/core/sanitize.js` | Prompt injection defense |
| `src/bridge.js` | Core dispatch + transport egress sanitization |
| `src/security/vault.js` | Credential encryption (AES-256-GCM) |
| `src/security/vault-client.js` | Vault daemon IPC (fail-closed) |
| `src/security/policy.js` | Human-in-the-loop approval gates |
| `src/compose/mixer.js` | Multi-server mixing + egress sanitization |
| `src/webhook/listener.js` | Webhook ingestion + HMAC validation |
| `src/connect.js` | MCP-to-MCP client (SSRF + schema sanitization) |
| `src/reverse/server.js` | Reverse bridge (auth + timing-safe comparison) |
| `src/tenant/scope.js` | Multi-tenant isolation |

The invariant test suite (`src/security/invariants/`) is the regression safety net. If you fix a security issue, add an invariant test in the same commit.

## How to add a community config

1. Create `configs/<service>.json` following existing patterns (see `configs/github.json`)
2. Include `usage` block with required env vars and setup instructions
3. Add token-budgeted response transforms on heavy endpoints
4. Mark write/delete operations with `"policy": "require_approval"`
5. Validate: `npx 40mcp validate configs/<service>.json`
6. Add the service to the README configs table

## How to add a loader plugin

```js
import { registerLoader } from '40mcp';

registerLoader({
  name: 'my-format',
  detect: (input) => /* return true if this loader handles the input */,
  load: async (input, options) => {
    return { baseUrl: 'https://api.example.com', tools: [...] };
  },
});
```

## Trust model (for security work)

40mcp uses a three-tier trust model:

| Tier | Who | Trust level |
|------|-----|-------------|
| Sovereign operator | Controls config + env + host | Fully trusted |
| Bridge runtime | Dispatch, transforms, sanitization | Enforced controls |
| Upstream APIs | External HTTP services + MCP servers | Untrusted |

Security controls enforce boundaries between tiers. See [docs/trust-model.md](docs/trust-model.md) for the full topology and [SECURITY.md](SECURITY.md) for controls and known limitations.

## File size policy

| Type | Review threshold | Hard limit |
|------|-----------------|------------|
| Source (`.js`) | > 800 LOC | > 2,500 LOC |
| Test (`.test.js`) | > 600 LOC | > 1,000 LOC (must split) |

Run `npm run check:loc` before submitting.

## PR checklist

- [ ] `npm run lint` passes
- [ ] `npm run test:all` passes
- [ ] `npm run check:loc` passes
- [ ] `npx 40mcp validate` passes on any new/changed configs
- [ ] Security-critical changes include invariant tests
- [ ] No new npm dependencies added
