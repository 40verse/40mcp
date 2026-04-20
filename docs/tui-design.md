# TUI_DESIGN.md — 40mcp Terminal UI Vision

## Philosophy

The goal is not a "pretty CLI". The goal is a terminal tool that developers
screenshot and share — the same category as `htop`, `lazygit`, and `k9s`.

What makes those tools feel magical:
- **Density without noise.** Every pixel earns its place.
- **Live state.** The screen reflects reality right now, not at launch time.
- **Discoverable shortcuts.** You can see what keys do without reading docs.
- **Instant feedback.** Actions feel immediate, not batched.
- **Zero friction to quit.** `q` always works.

40mcp has a structural advantage: it is the bridge between an API and an AI
agent. That pipeline is inherently observable — requests flow through a known
dispatch layer. The TUI should make that pipeline visible.

---

## Implementation Architecture

### File: `src/tui.js` (zero dependencies)

```js
export const tui = {
  // Environment detection
  isNoColor,      // process.env.NO_COLOR is set
  isTTY,          // stderr is a real terminal
  isMcpStdio,     // stdout consumed as MCP wire

  // Primitives
  color(code, str),
  bold(str),
  dim(str),
  cursor,             // .hide(), .show(), .up(n), .clear()

  // Components
  spinner(label),     // { update(label), stop(finalMsg) }
  progress(label, total), // { tick(), set(n), done() }
  table(headers, rows),
  tree(node),
  box(title, lines),

  // Interactive
  menu(title, items),     // arrow-key menu -> Promise<selectedIndex>
  prompt(question, defaultVal),
  confirm(question),

  // Dashboard
  dashboard(config),      // { update(state), destroy() }

  // AX helpers
  jsonOutput(obj),        // JSON to stdout (bypasses TUI)
  fatal(msg, code),       // styled error + process.exit(code)
};
```

### AX Safety Rule

All TUI output writes to `process.stderr`. The single exception is
`jsonOutput()`, which writes to `process.stdout`. When running as an MCP
stdio server, `stdout` is the MCP wire — nothing else may touch it.

### NO_COLOR Compliance

When `NO_COLOR` is set or stderr is not a TTY, `color()` and `bold()` are
identity functions. Structural characters (borders, tree lines) still render.

---

## Exit Code Contract

| Code | Meaning | Example |
|------|---------|---------|
| 0 | Success | Server started, inspect complete |
| 1 | Configuration error | Bad JSON, missing required field |
| 2 | Network error | Failed to fetch OpenAPI spec |
| 3 | Auth error | Token env var not set |
| 4 | User abort | Ctrl+C in interactive mode |

---

## Screen 1: Interactive Mode (`40mcp` with no args)

When stderr is a TTY and no arguments provided:

```
┌─────────────────────────────────────────────────────────┐
│  40mcp  ·  universal API-to-MCP bridge                  │
│  v0.2.0                                                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  What do you want to do?                                │
│                                                         │
│  ▶  Create from OpenAPI spec                            │
│     Create from GraphQL introspection                   │
│     Create from HAR recording                           │
│     Mix multiple servers                                │
│     Reverse: expose tools as REST                       │
│     Inspect a config                                    │
│     ─────────────────────────────────────               │
│     Help / docs                                         │
│                                                         │
│  ↑↓ navigate   Enter select   q quit                    │
└─────────────────────────────────────────────────────────┘
```

Sub-flow after selecting "Create from OpenAPI spec":

```
┌─────────────────────────────────────────────────────────┐
│  Create from OpenAPI                                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Spec path or URL:                                      │
│  > https://petstore.swagger.io/v2/swagger.json█         │
│                                                         │
│  Enter confirm   Esc back                               │
└─────────────────────────────────────────────────────────┘
```

Tool preview after fetch:

```
┌─────────────────────────────────────────────────────────┐
│  OpenAPI Preview — petstore.swagger.io                  │
├─────────────────────────────────────────────────────────┤
│  24 tools generated                                     │
│                                                         │
│  NAME                    METHOD   PATH                  │
│  ──────────────────────────────────────────────────     │
│  add_pet                 POST     /pet                  │
│  update_pet              PUT      /pet                  │
│  find_pets_by_status     GET      /pet/findByStatus     │
│  get_pet_by_id           GET      /pet/{petId}          │
│  delete_pet              DELETE   /pet/{petId}          │
│  ... 19 more                                            │
│                                                         │
│  Auth: none detected                                    │
│  Base URL: https://petstore.swagger.io/v2               │
│                                                         │
│  Enter start server   f filter tags   s save config     │
│  Esc back                                               │
└─────────────────────────────────────────────────────────┘
```

---

## Screen 2: Serve Dashboard (`40mcp serve config.json --sse 8080`)

The screenshot-worthy screen. Replaces the current single-line startup log.

```
┌──────────────────────────────────────────────────────────────┐
│  40mcp  ·  stripe-bridge  v1.0.0                  running   │
├──────────────┬───────────┬──────────────┬────────────────────┤
│  TOOLS       │  CLIENTS  │  REQ/SEC     │  AVG LATENCY       │
│  47          │  3        │  12.4        │  340ms             │
├──────────────┴───────────┴──────────────┴────────────────────┤
│  TRANSPORT   SSE :8080                                       │
│  BASE URL    https://api.stripe.com/v1                       │
│  AUTH        bearer  ·  env:STRIPE_KEY  ✓ set               │
├──────────────────────────────────────────────────────────────┤
│  ACTIVITY                                                    │
│                                                              │
│  12:04:31  ●  create_charge        args:{amount,currency}    │
│              ↳ 200  341ms  1.2kb → 280 tokens saved         │
│  12:04:28  ●  list_customers       args:{limit:10}           │
│              ↳ 200  298ms  8.4kb → 1,240 tokens saved       │
│  12:04:25  ●  retrieve_customer    args:{customer:cus_xxx}   │
│              ↳ 200  187ms  2.1kb → 380 tokens saved         │
│  12:04:19  ●  list_charges         args:{limit:5}            │
│              ↳ 200  201ms  4.8kb → 720 tokens saved         │
│  12:04:12  ◌  list_charges         [pending...]              │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│  q quit   t tools   l logs   r reload   ? help               │
└──────────────────────────────────────────────────────────────┘
```

**Color coding:**
- `●` green=2xx, yellow=4xx, red=5xx
- Latency: green < 200ms, yellow 200-1000ms, red > 1s
- "tokens saved" = (raw - transformed) / 4, rendered dim

**Keyboard shortcuts:**
- `q` clean shutdown
- `t` toggle tools list
- `l` cycle log level: activity → verbose → silent
- `r` hot-reload config from disk
- `?` overlay help

**Non-TTY fallback** (CI, Docker, piped):
```
[40mcp] level=info  event=ready     name=stripe-bridge tools=47 transport=sse port=8080
[40mcp] level=info  event=tool_call name=create_charge status=200 latency_ms=341
```

---

## Screen 3: Inspect Explorer (`40mcp inspect config.json`)

Tree view with expand/collapse and inline detail pane:

```
  stripe-bridge  v1.0.0  ·  47 tools
  ──────────────────────────────────────────────────────────────────

  ▶ charges  (5 tools)
  ▶ customers  (8 tools)
  ▼ payment_intents  (7 tools)
    ├── create_payment_intent      POST  /v1/payment_intents
    ├── retrieve_payment_intent    GET   /v1/payment_intents/:id
  ► ├── update_payment_intent      POST  /v1/payment_intents/:id
    ├── confirm_payment_intent     POST  /v1/payment_intents/:id/confirm
    ├── cancel_payment_intent      POST  /v1/payment_intents/:id/cancel
    ├── capture_payment_intent     POST  /v1/payment_intents/:id/capture
    └── list_payment_intents       GET   /v1/payment_intents
  ▶ refunds  (3 tools)

  ↑↓ navigate   Enter expand/inspect   / search   j json   q quit
```

**"Try call" sub-mode** — Enter on a tool opens inline argument prompts:

```
  ┌─────────────────────────────────────────────────────┐
  │  Try: update_payment_intent                         │
  ├─────────────────────────────────────────────────────┤
  │  intent  > pi_3NxK2KLkdIwHu7ix0ABC123█             │
  │  amount  > 2500                                     │
  │  currency> usd                                      │
  │                                                     │
  │  Enter send   Esc cancel                            │
  └─────────────────────────────────────────────────────┘
```

**Chain DAG view** — press `c` on a chain tool:

```
  CHAIN: checkout_flow
  ─────────────────────

  [create_cart] ──────────────────────────────┐
        │                                     │
        ▼                                     ▼
  [add_item_to_cart] ─────────────────> [apply_coupon]
        │
        ▼
  [create_payment_intent]
        │
        ▼
  [confirm_payment_intent]

  5 steps  ·  2 branches  ·  1 merge point
```

`--json` flag preserves current stdout JSON dump behavior.

---

## Screen 4: HAR Interactive Selector (`40mcp from-har recording.har`)

```
  HAR Recording — recording.har
  ─────────────────────────────────────────────────────────────────
  156 requests  ·  23 unique endpoints

  [x]  GET   /api/users              5 obs   → list_users
  [x]  POST  /api/users              3 obs   → create_user
  [x]  GET   /api/users/:id          8 obs   → get_user
  [ ]  GET   /api/assets/logo.png    1 obs   → (static, skip?)
  [ ]  GET   /api/_health            12 obs  → (infra, skip?)
  [x]  POST  /api/sessions           4 obs   → create_session
  [x]  DELETE /api/sessions/:id      2 obs   → delete_session
  [x]  GET   /api/posts              6 obs   → list_posts

  8 of 23 selected  ·  8 tools will be generated

  Space toggle   a all   Enter confirm   / filter   q quit
```

Endpoints matching `/_`, `/health`, `/static`, `/assets` pre-deselected.
1-observation endpoints marked dim with `(low confidence)`.

---

## Screen 5: Progress Indicators

**Spinner** (fetch operations):
```
  ⠙ Fetching spec from https://api.stripe.com/openapi.json...
  ✓ Fetched spec  (204ms)
```

**Progress bar** (HAR parsing):
```
  Parsing HAR  [████████████░░░░░░░░]  60%  93/156 requests
```

**NO_COLOR fallback**:
```
  [ ... ] Fetching spec...
  Parsing HAR  60%  (93/156)
```

---

## Agent Experience (AX) Design

### `--json` Flag

Every command gains `--json` for programmatic consumers:

| Command | `--json` output |
|---------|----------------|
| `inspect` | Full tool list (existing behavior) |
| `from-openapi --json` | `{ name, baseUrl, toolCount, tools[] }` then exits |
| `from-graphql --json` | Same shape |
| `from-har --json` | `{ baseUrl, toolCount, tools[], skipped[] }` |
| `serve --json` | Emits `{ listening: true, port, tools }` then continues |

### Detection Logic

```js
const isMcpStdio = !process.stdout.isTTY;
const isTTY = process.stderr.isTTY;
const isNoColor = process.env.NO_COLOR !== undefined || !isTTY;
```

When `isMcpStdio`: no dashboard, no cursor manipulation, log lines only.

---

## Implementation Phases

### Phase 1: `src/tui.js` Foundation
ANSI primitives, spinner, progress bar, table, fatal.
Zero command changes — just the utility module.
Immediately upgrades all loaders with spinners and result tables.

### Phase 2: Serve Dashboard
Instrument `bridge.js` dispatch to emit events (tool name, latency, status).
Dashboard refresh loop with `setInterval(...).unref()`.
Ring buffer for last 20 requests.

### Phase 3: Inspect Explorer
Tree view with expand/collapse.
Raw keypress mode (`stdin.setRawMode`).
Detail pane + try-call sub-mode.

### Phase 4: Interactive Mode
No-args entrypoint with arrow-key menu.
Sub-flows call existing `cmdFromOpenApi()` etc.

### Phase 5: HAR Selection UI
Checklist before auto-convert.
TTY-only; non-TTY falls back to current behavior.

---

## What Makes This "Killer"

The **serve dashboard** is the screenshot moment. An AI engineer running
`claude-code` against their API sees their agent's tool calls reflected in
real time — latency, status, token savings. That feedback loop is the thing
that gets shared.

The **inspect try-call** is Postman for MCP tools — exercise any tool
without writing a client.

The **HAR selection UI** is a genuinely new interaction: drop a `.har` file,
cherry-pick endpoints, watch tools generate live.

Zero external dependencies. That is itself a kind of good design.
