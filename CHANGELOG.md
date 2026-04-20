# Changelog

## 0.1.1-beta.0

_Released 2026-04-19._

This marks the beginning of the repo, but it's not the beginning of the story. See [`docs/lineage-note.md`](docs/lineage-note.md) for more detail about why this repo has been given a fresh start for the public repo.

Inherits the `0.1.0-beta.7` feature set.

### Policy gate — embedded `tool.policy` honored alongside sidecar policy JSON

The bridge's `require_approval` re-check at dispatch no longer rejects approved top-level calls. It now fires only for **chain sub-dispatches** (which can't re-trigger interactive approval mid-chain) — matching the original intent stated in the comment at the call site. Top-level calls either go through `createPolicyGate` (which either approves or denies upstream) or are made by callers who explicitly chose to skip the gate.

To make the check actually effective, pass `tools` into `createPolicyGate` so the gate can extract embedded `tool.policy` annotations:

```js
import { createPolicyGate } from '40mcp';

const gatedDispatch = createPolicyGate({
  dispatch: bridge.dispatch,
  tools: config.tools,                // ← required for embedded tool.policy to be honored
  approvalHandler: async (ctx) => 'approve',
});
```

Both `40mcp serve <config> --policy <path>` and `40mcp link --policy <path>` now honor embedded `tool.policy` annotations alongside the sidecar `toolPolicies` rules. The gate activates when `--policy <path>` is passed (even `--policy` pointing at an empty `{}` file — the minimum to opt into embedded enforcement). Without `--policy`, embedded annotations are metadata only, matching prior behavior.

`serve` uses a deny-with-audit default `approvalHandler` because the stdio/SSE transports have no interactive channel to prompt an operator. Callers who need real approval flows (webhook, Slack, stdin for one-shot CLIs) use the library API with a custom `approvalHandler`:

```js
import { createRestBridge, createPolicyGate, loadConfig } from '40mcp';

const config = await loadConfig('configs/sentry.json');
const bridge = await createRestBridge({
  ...config,
  wrapDispatch: (raw) => createPolicyGate({
    dispatch: raw,
    tools: config.tools,
    approvalHandler: async (ctx) => await promptUser(ctx),
  }),
}).start();
```

`createRestBridge` gained a `wrapDispatch` option — the injection point above. The hook receives the bridge's raw dispatch closure post-construction and the returned function is used for both the MCP CallTool handler AND the exported `bridge.dispatch`.

### Security — `serve --sse` gains bearer auth and refuses non-loopback without it

`cmdServe` accepted `--sse --host 0.0.0.0` with no auth, silently publishing an unauthenticated MCP endpoint (every session logged with `principal: null`). `cmdLink` already refused this — `cmdServe` now mirrors that check and adds the bearer flags:

- **New:** `serve --require-bearer-env <ENV>` reads a token from the env var; single-token mode
- **New:** `serve --require-bearer <token>` literal (discouraged — leaks via `ps`)
- **New:** non-loopback bind without either flag fatals at startup: *"Refusing to publish serve on a non-loopback host without inbound auth."*
- `require-bearer` plumbs through `config.transport.requireBearer` → `createSseTransport` (same path `link` uses)
- Bearer-file / multi-principal is intentionally `link`-only — `serve` publishes a single REST bridge, so per-principal attribution doesn't add value there.

Before this change, `docker run 40mcp:beta serve /config.json --sse 8080 --host 0.0.0.0` would expose the bridge unauthenticated on the container network.

### Consumer — dotted tool names accepted so 40mcp clients can consume 40mcp frontdoors

`connectSse` / `connectStreamableHttp` validated upstream tool names against `/^[a-zA-Z0-9_-]{1,64}$/` (no dots), but `link` publishes prefixed names as `${prefix}.${toolname}`. A 40mcp client connecting to a 40mcp frontdoor was rejected with *"Connected tool has invalid name … must be alphanumeric + underscore/hyphen, max 64 chars"* — self-incompatible tooling.

Relaxed to `/^[a-zA-Z0-9_\-.]{1,64}$/`. Dots are inert for the hardening this regex exists for (path traversal, shell metacharacters, log-line forgery, prototype keys), so allowing them is safe.

### Known limitation — `serve --sse` is single-session

`cmdServe` uses one shared `Server` instance across SSE sessions; the MCP SDK's `Server.connect(transport)` rejects a second attachment while the first is active, so a second concurrent client sees *"Already connected to a transport"* until the first drains. `cmdLink` works around this with a `serverFactory: buildServer` callback that mints a fresh `Server` per session; `cmdServe` doesn't yet plumb one through. Tracked as a follow-up — operators needing multi-client SSE should use `link` or a reverse proxy fronting multiple `serve` instances.

### Security — sidecar `toolPolicies` now enforced transitively through compose chains

Sidecar `toolPolicies` rules passed via `--policy` only wrapped the top-level dispatch. Compose-chain sub-dispatches went through the bridge's internal dispatcher, which re-checked only the embedded `tool.policy` field — so a chain step to a sidecar-denied tool would bypass the gate. Reproducer: with `toolPolicies: { danger: 'deny' }` and a `chain_wrapper → danger` chain, the inner call reached the network instead of being blocked. Embedded `policy: 'deny'` on the same tool correctly blocked.

Fix: `serve --policy` now compiles sidecar rules into embedded `tool.policy` via the new `mergeToolPolicies(tools, toolPolicies)` helper before bridge construction. Sidecar still wins over embedded (same precedence `createPolicyGate` uses). Chain sub-dispatches then hit the bridge's existing per-dispatch re-check and are blocked the same way embedded policy is.

Library callers who pass sidecar policies through `createRestBridge` themselves should import the helper and do the same:

```js
import { createRestBridge, createPolicyGate, mergeToolPolicies, loadConfig } from '40mcp';

const config = await loadConfig('configs/sentry.json');
mergeToolPolicies(config.tools, sidecar.toolPolicies || {});
const bridge = await createRestBridge({
  ...config,
  wrapDispatch: (raw) => createPolicyGate({
    dispatch: raw,
    tools: config.tools,
    toolPolicies: sidecar.toolPolicies,
    approvalHandler: async (ctx) => 'approve',
  }),
}).start();
```

`link --policy` is unaffected — linked upstream tools don't carry local `chain` arrays, so the bypass surface doesn't exist there.

### Shipped community configs — approval annotations on clearly destructive tools

Eleven clearly-side-effecting tools across four community configs now carry `"policy": "require_approval"`:

- `configs/sentry.json`: `create_project`, `update_issue`, `delete_issue`, `resolve_issue`, `create_release`, `finalize_release`
- `configs/slack.json`: `send_message`, `delete_message`
- `configs/github.json`: `merge_pull_request`
- `configs/stripe.json`: `create_payment_intent`, `create_refund`

The annotations take effect when the caller wires `createPolicyGate` (library path) or uses `40mcp serve --policy` / `40mcp link --policy` with the config. Without a gate the annotations are documentation only.

### Security hardening — vault passphrase strength gate on every entry point

`validatePassphraseStrength` (minimum 16 characters, at least 3 of lowercase / uppercase / digits / symbols, entropy floor, no sequential or repeated character runs) now runs on every path that sets or uses a master passphrase, not only `initVault`:

- `createVault({ passphrase })` — validates on construction
- `vault.rotateKEK(newPassphrase)` — validates before KEK derivation
- `recoverVault({ newPassphrase })` — validates before touching vault state

This closes a gap where `createVault` and the two rotation paths silently accepted weak passphrases. The genesis public release ships with this policy in effect; there are no pre-existing public vaults to migrate.

### Golden path — `npx 40mcp <command> configs/<file>` works from any CWD

`link` and `loadConfig` (used by `serve`, `inspect`, `validate`, `mix`) now fall back to the installed-package root when a config path is not found in CWD. The README's one-command `npx 40mcp@beta link configs/microsoft-huggingface-bridge.mcp.json` now works from arbitrary directories, not only from a cloned repo checkout.

### Transport change — default to Streamable HTTP for URL upstreams

`connectFromConfig` / `connectMany` / `40mcp link` now default URL-based `.mcp.json` entries to the **Streamable HTTP** transport (the current MCP transport spec) rather than the legacy SSE transport. This fixes the README golden path against `learn.microsoft.com/api/mcp` and `huggingface.co/mcp`, both of which returned `405` to the legacy SSE `GET /sse` handshake.

- New exported function: `connectStreamableHttp(config)` — mirrors `connectSse`'s security wrapping (SSRF validation, DNS-rebind IP pinning, egress-strip wrapping, plain-HTTP warning) on top of the SDK's `StreamableHTTPClientTransport`.
- New optional config field: `transport: "streamable-http" | "sse"` on URL entries. Default is `"streamable-http"`. Set to `"sse"` to talk to legacy SSE-only servers.
- `connectSse(...)` remains supported and unchanged for callers who construct it directly.

## 0.1.0-beta.7

Beta of the Provider / Transform / Hooks architecture. Shipped `bridge.close({ timeoutMs })` graceful shutdown that drains in-flight dispatches, tool cancellation that threads `AbortSignal` through `bridge.dispatch(name, args, { signal })` into the upstream fetch, and three new `doctor` runtime-safety warnings (bridge SSE non-loopback, reverse non-loopback without auth, vault path outside allowlist). Security parity against FastMCP's SSRF / sanitize / outbound-chokepoint story is now programmatically test-enforced, not code-review-enforced.
