# Testing 40mcp deployments

## What this covers

This guide is for operators and integrators who need to test a 40mcp
deployment: a bridge against an upstream API, a frontdoor composing
multiple primitives, tenant isolation, and policy gates. It is **not**
a guide to testing your upstream APIs themselves (use their own test
harnesses) or to unit-testing the business logic of a specific tool.
The patterns below are the same ones the 40mcp test suite uses; every
section cites a real file in this repository so you can copy the
shape directly.

## Test a bridge against an HTTP mock

Start a `node:http` mock server on an ephemeral port, point your
bridge config's `baseUrl` at it, and assert that `bridge.dispatch()`
returns the shaped result you expect.

```js
import { createServer } from 'node:http';
import { createRestBridge } from '40mcp';

const mock = createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify([{ id: 1, full_name: 'acme/widget' }]));
});
await new Promise((r) => mock.listen(0, '127.0.0.1', r));
const baseUrl = `http://127.0.0.1:${mock.address().port}`;

const bridge = createRestBridge({ ...config, baseUrl });
const repos = await bridge.dispatch('list_repos', {});
// assert shape, teardown mock.close()
```

This keeps tests deterministic and offline. The full pattern —
including response-transform assertions and a standalone GitHub-style
mock — lives in
[`test/emulate-integration.test.js`](../test/emulate-integration.test.js).
Remember to `delete config.strictSsrf` (or keep it and target a
loopback address) because shipped configs refuse non-public hosts by
default.

## Test a frontdoor end-to-end

When your system under test composes multiple 40mcp primitives
(webhook listener + linked upstream + HMAC gate + stdio transport),
drive it from the outside. A single test can POST a webhook, walk
through HMAC validation, dispatch into a stdio MCP child, and assert
the tool result comes back in the HTTP response.

The reference example is
[`test/webhook-to-linked-upstream.test.js`](../test/webhook-to-linked-upstream.test.js).
It spawns
[`test/helpers/stdio-echo-upstream.mjs`](../test/helpers/stdio-echo-upstream.mjs)
via `connectStdio`, wires it into `createWebhookListener` with a
`response: 'sync'` route, and asserts on the HTTP response body.

Use this pattern whenever you want coverage that proves the full
composition works: unit tests of the pieces in isolation will not
catch a broken seam between them (missing HMAC header propagation,
argument coercion loss, unwrap mismatches, etc.).

## Test tenant isolation

Tenant tests must prove two things: each tenant receives its own
context on every call, and concurrent calls from different tenants
never bleed state. The pattern is to fire `Promise.all([...])` with
multiple tenant IDs hitting the same bridge, then assert that each
returned response reflects its tenant's auth context and nothing
else.

See
[`test/multi-tenant-isolation.test.js`](../test/multi-tenant-isolation.test.js),
which wraps a bridge in `createTenantScope`, resolves different auth
bearers per `tenantId`, and asserts `dataA.auth !== dataB.auth`. It
also covers per-tenant allowlists and blocklists. For
policy × tenant interactions, see
[`test/policy-tenant-composition.test.js`](../test/policy-tenant-composition.test.js).

## Test policy gates

To exercise a `deny` verdict, construct a bridge config with
`toolPolicies: { dangerous_tool: 'deny' }`, dispatch the tool, and
assert the call rejects with a `POLICY_DENIED` error. The shipped
implementation throws `BridgeError(BridgeErrorCode.POLICY_DENIED,
'Tool "…" is blocked by policy')` and writes a `deny` audit event
before the dispatch ever reaches the bridge.

```js
import { createPolicyGate } from '40mcp';

const gated = createPolicyGate({
  dispatch,
  toolPolicies: { dangerous_tool: 'deny' },
});
await assert.rejects(
  () => gated('dangerous_tool', {}),
  (err) => err.message.includes('blocked by policy'),
);
```

The full set of allow / deny / `log_only` / `require_approval` cases
lives in
[`src/security/policy.test.js`](../src/security/policy.test.js), and
the frontdoor integration in
[`test/frontdoor-policy-tenant.test.js`](../test/frontdoor-policy-tenant.test.js).

## Standing up a fake stdio MCP upstream

For any test that needs a real MCP server on the other end of
`connectStdio`, use the reusable helper
[`test/helpers/stdio-echo-upstream.mjs`](../test/helpers/stdio-echo-upstream.mjs).
It exposes two deterministic tools (`echo_text`, `sum_numbers`) and
exits cleanly on stdin EOF.

```js
import { connectStdio } from '40mcp';

const upstream = await connectStdio({
  command: 'node',
  args: ['./helpers/stdio-echo-upstream.mjs'],
  prefix: 'echo',
});
// upstream.dispatch('echo.echo_text', { text: 'hi' })
// upstream.close() when done
```

Because the helper is a real MCP server (not an in-process stub),
tests against it catch transport-level regressions that a mock
dispatcher would miss.

## What good test hygiene looks like

- **Deterministic fixtures.** Pin responses in the mock; never assert
  on wall-clock time or ordering derived from `Date.now()`.
- **No live-network-by-default.** Tests must pass offline. Gate any
  external-network path behind an explicit env var and soft-skip
  when it is absent.
- **Always close transports and HTTP servers.** Call `upstream.close()`
  and `server.close()` in `after()`. On Node HTTP servers, also call
  `closeAllConnections()` so keep-alive sockets do not pin the event
  loop past the final assertion.
- **Use `test.timeout` sparingly.** A long timeout hides a real hang;
  fix the root cause (an unclosed socket, an unflushed child) instead
  of extending the deadline.
- **Avoid shared module-level state.** Give each test its own bridge,
  tenant scope, and port. Cross-test state is the easiest way to get
  a green suite that fails in CI under parallelism.

## Related docs

- [docs/BRIDGE_VS_FRONTDOOR.md](BRIDGE_VS_FRONTDOOR.md) — `serve` vs
  `link` mental model
- [docs/FRONTDOOR.md](FRONTDOOR.md) — published SSE deployment
  patterns
- [docs/SETTINGS.md](SETTINGS.md) — `40mcp.settings.json` operator
  guide with recipes
