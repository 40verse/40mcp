# 40mcp × emulate

Offline, no-credential MCP development using [vercel-labs/emulate](https://github.com/vercel-labs/emulate).

`emulate` runs production-fidelity local API servers for GitHub, Vercel, Slack, Google, Microsoft, and AWS. Point 40mcp at them and you get a complete MCP tool loop with no real API keys, no network calls, and no rate limits.

## Quick Start

```bash
# 1. Start the emulated APIs you need
npx emulate --service github,vercel,slack --seed .emulate/emulate.config.yaml

# Services are now running:
#   GitHub  → http://localhost:4001
#   Vercel  → http://localhost:4000
#   Slack   → http://localhost:4003

# 2. Start 40mcp pointing at the emulated services
npx 40mcp serve .emulate/configs/github.json
npx 40mcp serve .emulate/configs/vercel.json
npx 40mcp serve .emulate/configs/slack.json

# Or mix them all into one MCP server:
npx 40mcp mix .emulate/configs/github.json .emulate/configs/vercel.json .emulate/configs/slack.json
```

No real tokens required. Emulate accepts any non-empty string as a bearer token.

## What's in this folder

```
.emulate/
  emulate.config.yaml     # Seed data — users, repos, projects, channels
  configs/
    github.json           # 40mcp config → localhost:4001
    vercel.json           # 40mcp config → localhost:4000
    slack.json            # 40mcp config → localhost:4003
  state/                  # gitignored — file persistence (if enabled)
  .gitignore
  README.md               # this file
```

## Emulate service → port map

| Service   | Port | 40mcp config |
|-----------|------|-------------|
| Vercel    | 4000 | `.emulate/configs/vercel.json` |
| GitHub    | 4001 | `.emulate/configs/github.json` |
| Google    | 4002 | — |
| Slack     | 4003 | `.emulate/configs/slack.json` |
| Apple     | 4004 | — |
| Microsoft | 4005 | — |
| AWS       | 4006 | — |

## Seeded test data

The `emulate.config.yaml` pre-seeds:

- **GitHub**: user `dev`, repos `my-app` + `api-service`, 2 open issues, 1 open PR
- **Vercel**: team `my-team`, 2 projects, 2 deployments (READY)
- **Slack**: workspace `Dev Workspace`, channels `#general` `#engineering` `#deployments`, 1 user

Edit the YAML to add more data. Changes take effect on the next `emulate` start.

## File persistence (optional)

By default emulate state is in-memory only — it resets on restart. To persist state across restarts:

```typescript
// emulate.setup.ts
import { createEmulator } from 'emulate'
import { filePersistence } from '@emulators/core'

const github = await createEmulator({
  service: 'github',
  port: 4001,
  seed: require('./emulate.config.yaml'),
  persistence: filePersistence('.emulate/state/github.json'),
})
```

## CI integration

```typescript
// vitest.setup.ts
import { createEmulator } from 'emulate'

let github, vercel, slack

beforeAll(async () => {
  ;[github, vercel, slack] = await Promise.all([
    createEmulator({ service: 'github', port: 4001 }),
    createEmulator({ service: 'vercel', port: 4000 }),
    createEmulator({ service: 'slack',  port: 4003 }),
  ])
  // 40mcp configs in .emulate/configs/ already point to these ports.
  // No env var overrides needed.
})

afterEach(async () => {
  await Promise.all([github.reset(), vercel.reset(), slack.reset()])
})

afterAll(async () => {
  await Promise.all([github.close(), vercel.close(), slack.close()])
})
```

## Adding more services

Emulate currently supports: `github`, `vercel`, `google`, `slack`, `apple`, `microsoft`, `aws`.

To add a 40mcp config for a new emulated service, copy an existing config from `.emulate/configs/`, update `baseUrl` to the correct port, and adjust `tools` to match your test scenarios.
