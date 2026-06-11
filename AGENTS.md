# AGENTS.md

Guide for using AI coding agents (Claude Code, Cursor, Copilot, etc.) to contribute to the 40mcp codebase.

---

## Quick orientation

```
src/
├── bridge.js        Core dispatch engine (tools/call → HTTP → result)
├── cli.js           CLI (serve, from-openapi, mix, reverse, vault, init, doctor, etc.)
├── connect.js       MCP-to-MCP client
├── errors.js        Structured error codes
├── generate.js      Code generation utilities
├── validate.js      Config validation
├── config/          Settings scaffold, show, and mutation helpers
├── core/            Client, path interpolation, env guards, types
├── loaders/         GraphQL, HAR, plugin registry
├── providers/       Provider-level OpenAPI loading
├── transforms/      Token-aware response shaping (pick, omit, limit, tokenBudget)
├── compose/         Chains (multi-step) + mixer (multi-server)
├── transport/       Stdio + SSE transport
├── reverse/         MCP → REST bridge
├── webhook/         Webhook ingestion
├── tenant/          Multi-tenant scoping
├── security/        Sealed vault, policy gates, invariant tests
└── red-team/        Adversarial + fuzzing test suite

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

Security controls enforce boundaries between tiers. See [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md) for the full topology and [SECURITY.md](SECURITY.md) for controls and known limitations.

## File size policy

| Type | Review threshold | Hard limit |
|------|-----------------|------------|
| Source (`.js`) | > 800 LOC | > 2,500 LOC |
| Test (`.test.js`) | > 600 LOC | > 1,000 LOC (must split) |

Run `npm run check:loc` before submitting.

## CI review

### Job map

| Job | Runs on | What it checks |
|-----|---------|---------------|
| `Lint + pack` | ubuntu / Node 22 | ESLint, LOC thresholds, `npm pack --dry-run` |
| `Test (Node 18/20/22)` | ubuntu matrix | Full test suite across three LTS versions |
| `Test (macOS, Node 22)` | macos-latest | Same suite, catches path/symlink divergence |
| `Smoke (packaged install)` | ubuntu / Node 22 | Installs the packed tarball, runs `scripts/smoke-test.sh` |

### Reproducing a failure locally

```bash
# Lint + pack
npm run lint
npm run check:loc
npm pack --dry-run --ignore-scripts

# Tests (pick version via nvm/fnm if needed)
npm run test:all          # all unit + integration
npm run test:invariants   # security invariants only — run after any security-critical edit

# Smoke
bash scripts/smoke-test.sh
```

### Triage guide

**Lint failure** — auto-fixable. Run `npm run lint:fix`, review the diff, commit.

**LOC threshold exceeded** — not auto-fixable. The file needs splitting or the threshold needs a deliberate raise in `scripts/check-loc.js`. Do not raise thresholds without a justification comment.

**Test failure on Node 18 only** — likely a Node 18 incompatibility: no `fetch` globals (use `http`/`https` or pass explicit IPv4 URLs), no `structuredClone`, no `ReadableStream` web API. Check `scripts/run-tests.mjs` for version guards.

**Test failure on macOS only** — usually a path issue. `/tmp` and `/var` are symlinks to `/private/tmp` and `/private/var` on macOS. Use `fs.realpathSync` or `path.resolve` before comparing paths.

**Smoke failure** — the packaged tarball is broken. Check that the `files` field in `package.json` includes everything the CLI needs at runtime, and that no runtime import resolves to a path excluded by the tarball.

**Security invariant failure** — do not auto-fix without reading the invariant. These tests encode trust-boundary contracts. A failing invariant means a documented security control is no longer holding. Apply the release gate decision tree from `docs/RELEASE_GATE.md` before touching the code.

**Trust matrix failure** (`npm run trust-matrix`) — automatic release blocker. All 11 scenarios must pass. Do not mark a PR ready while any trust matrix scenario fails.

### What an agent can fix autonomously

- Lint errors (`npm run lint:fix` + manual cleanup)
- Failing unit tests caused by a logic regression in non-security code
- Node version compatibility issues (fetch URLs, built-in API availability)
- macOS path canonicalization failures

### What requires human sign-off

- Any change to `src/security/`, `src/core/env.js`, `src/core/sanitize.js`, or `src/core/object.js`
- Raising a LOC hard limit
- A failing security invariant or trust matrix scenario
- Adding or removing files from the `files` field in `package.json`
- Any new runtime dependency (the answer is almost always no — see architecture rule #1)

## PR checklist

- [ ] `npm run lint` passes
- [ ] `npm run test:all` passes
- [ ] `npm run check:loc` passes
- [ ] `npx 40mcp validate` passes on any new/changed configs
- [ ] Security-critical changes include invariant tests
- [ ] No new npm dependencies added
