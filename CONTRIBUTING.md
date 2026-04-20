# Contributing to 40mcp

Thanks for your interest in contributing!

## Quick Start

```bash
git clone https://github.com/40verse/40mcp
cd 40mcp
npm install
npm test
```

## Development

```bash
npm test                    # Unit tests
npm run test:integration    # Integration tests (emulate-compatible)
npm run test:all            # Everything
npm run lint                # ESLint check
npm run lint:fix            # Auto-fix lint issues
```

## Adding a Community Config

1. Create `configs/<service>.json` following the existing patterns (see `configs/github.json`)
2. Include token-budgeted response transforms on heavy endpoints
3. Mark dangerous/write actions with `"policy": "require_approval"`
4. Test with `40mcp validate configs/<service>.json`
5. Add the service to the README table

## Adding a Custom Loader Plugin

```js
import { registerLoader } from '40mcp';

registerLoader({
  name: 'my-format',
  detect: (input) => /* return true if this loader handles the input */,
  load: async (input, options) => {
    // Parse input → return { baseUrl, tools }
    return { baseUrl: 'https://api.example.com', tools: [...] };
  },
});
```

## Code Style

- Pure ESM (`"type": "module"` in package.json)
- Node.js built-in `node:test` for testing
- JSDoc for type documentation (+ `index.d.ts` for TypeScript consumers)
- No dependencies beyond `@modelcontextprotocol/sdk`
- Snake_case for tool names, camelCase for JS functions

## Architecture

```
src/
├── bridge.js        Core dispatch engine
├── errors.js        Structured error taxonomy
├── validate.js      Config validation
├── core/            Client, path interpolation, types
├── loaders/         OpenAPI, GraphQL, HAR, plugin registry
├── transforms/      Response shaping
├── compose/         Chains + mixer
├── transport/       Stdio + SSE
├── reverse/         MCP → REST
├── webhook/         Webhook ingestion
├── tenant/          Multi-tenant scoping
├── security/        Sealed vault + policy gates
└── cli.js           CLI (14 subcommands)
```

## Lint

```bash
npm run lint          # Check for lint errors
npm run lint:fix      # Auto-fix where possible
```

## Config Naming Convention

Two distinct bridge types live under `configs/`:

| Suffix | Type | What it does |
|--------|------|-------------|
| `configs/*.json` | REST bridge | Wraps a REST API as MCP tools (existing behavior) |
| `configs/*.mcp.json` | MCP linking | Connects to an existing MCP server and re-exposes its tools |

When adding a new integration, use the right suffix so users can immediately tell whether they need to spin up a REST bridge or just link an existing MCP server.

## File Size Policy (LOC Thresholds)

Large files are harder to review, more likely to accumulate unrelated concerns, and more prone to introducing security regressions. The LOC check (`npm run check:loc`) enforces these thresholds:

| Type | Review | Justify | Refactor | Hard limit |
|------|--------|---------|----------|------------|
| Source (`.js`) | > 800 | > 1 200 | > 1 600 | > 2 500 |
| Test (`.test.js`) | > 600 | > 1 000 | > 1 500 | > 2 000 (must split) |
| Docs (`.md`) | > 300 | — | — | — |

**Justify**: Include a note in the PR body explaining why splitting would harm cohesion.
**Must split**: Tests over 2 000 lines must be broken into separate surface files before merge (see `src/security/invariants/` for the canonical split pattern).

The test threshold is deliberately more generous than source because: (a) a single invariant or integration suite legitimately covers many tightly-coupled surfaces where splitting reduces regression coverage, and (b) test files multiply faster than source files so artificial low ceilings push fragmentation without improving readability. The hard limit still exists to prevent true god-files.

### Refactor Watchlist

Files currently above thresholds that need attention in future PRs:

| File | LOC | Type | Priority | Notes |
|------|-----|------|----------|-------|
| `src/security/invariants/sanitize.test.js` | ~1 939 | test | Low | Justified exception: 10 coupled sanitization surfaces. Would be FAIL if split threshold were 1 500. |
| `src/bridge.test.js` | ~1 836 | test | Medium | Split candidate: `construction.test.js` + `hooks.test.js` + `shutdown.test.js` + `cancellation.test.js`. Four clean describes + module-scope helpers. |
| `src/red-team/mcp-specific.test.js` | ~1 236 | test | Medium | Split candidate: `protocol.test.js` + `lifecycle.test.js`. Pre-existing debt. |
| `src/cli.js` | ~1 951 | source | Medium | Review: extract subcommand handlers (`cmdServe`, `cmdLink`, `cmdFromOpenApi`, …) into `src/commands/` directory. |
| `src/security/vault.js` | ~1 153 | source | Low | Review: consider splitting key-ops from passphrase derivation. |
| `src/bridge.js` | ~1 431 | source | Medium | Review: core dispatch — splitting needs care. Above the justify threshold. |
| `src/connect.js` | ~989 | source | Low | Review: upstream connector — approaching justify threshold. |

**How to remove an entry from this list:**
1. Split the file OR demonstrate it's below threshold in a follow-up PR.
2. Remove the row and update `scripts/check-loc.js` `JUSTIFIED_EXCEPTIONS` accordingly.
3. If keeping the file whole, document the justification here and add a `JUSTIFIED_EXCEPTIONS` entry with a review date.

## Pull Requests

- Include tests for new features
- Run `npm run lint` to check for style issues, then `npm run test:all` and `npm run check:loc` before submitting
- Use `40mcp validate` on any new configs
- Keep the single-dependency constraint (no new npm deps)

## License

MIT — see [LICENSE](LICENSE).
