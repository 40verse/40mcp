/**
 * Production Failure Simulation — Autoresearch Scenario Suite
 *
 * This suite simulates real production failure modes discovered through
 * reasoning about 40mcp's seam map:
 *
 *   Seam 1 — Spec  → Tool Definitions   (translation fidelity)
 *   Seam 2 — Args  → HTTP Request       (parameter mapping)
 *   Seam 3 — HTTP Response → MCP Result (response transform)
 *   Auth   — Vault → Runtime Secret     (credential lifecycle)
 *   Compose — N APIs → Unified Surface  (mixer/chain)
 *
 * Autoresearch loop:
 *   GENERATE scenarios → SPAWN bridge against mock → SCORE result →
 *   HARVEST failures → FIX seam → EXPAND scenario set → REPEAT
 *
 * Each scenario is labelled with:
 *   [SEAM]    — which bridge seam is under test
 *   [STATUS]  — PROBE (expected to pass) | CANARY (expected to surface a known gap)
 *
 * A CANARY that passes means the gap was fixed. A PROBE that fails means we
 * found a regression. Either way, the test is informative.
 *
 * Run:
 *   node --test test/scenarios/index.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRestBridge } from '../../src/bridge.js';
import { createMixer } from '../../src/compose/mixer.js';
import {
  schemaDriftApi,
  arrayFormatApi,
  errorAs200Api,
  tokenExpiryApi,
  largeResponseApi,
} from './mocks.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Parse bridge result — dispatch returns string or object depending on transform. */
function parse(result) {
  return typeof result === 'string' ? JSON.parse(result) : result;
}

// ─── Scenario 1: Schema Drift ─────────────────────────────────────────────────
// [SEAM 3 — HTTP Response → MCP Result]
// [STATUS: PROBE]
//
// The spec declares {name, email, role} as required strings.
// The live API returns null for all of them.
//
// Desired behavior: bridge passes the response through without crashing.
// The LLM receives the null values and can reason about the drift itself.
// A crash here would be a silent data loss — the agent gets no result at all.

describe('Scenario 1: Schema Drift', () => {
  let mock, bridge;

  before(async () => {
    mock = await schemaDriftApi();
    bridge = createRestBridge({
      name: 'schema-drift-api',
      version: '1.0.0',
      baseUrl: `http://127.0.0.1:${mock.port}`,
      tools: [{
        name: 'get_user',
        description: 'Get user by ID.',
        method: 'GET',
        path: '/users/:id',
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'integer', description: 'User ID' } },
          required: ['id'],
        },
      }],
    });
  });

  after(() => mock.server.close());

  it('returns null fields without crashing', async () => {
    const result = await bridge.dispatch('get_user', { id: 1 });
    const body = parse(result);

    // Bridge must not throw — null from live API should surface to LLM
    assert.strictEqual(body.id, 1, 'id field should be present');
    assert.strictEqual(body.name, null, 'null name should pass through');
    assert.strictEqual(body.email, null, 'null email should pass through');
    assert.strictEqual(body.role, null, 'null role should pass through');
  });

  it('handles null for different IDs consistently', async () => {
    const [r1, r2] = await Promise.all([
      bridge.dispatch('get_user', { id: 1 }),
      bridge.dispatch('get_user', { id: 99 }),
    ]);
    const [b1, b2] = [parse(r1), parse(r2)];
    assert.strictEqual(b1.name, null);
    assert.strictEqual(b2.name, null);
    assert.notEqual(b1.id, b2.id, 'IDs should differ');
  });
});

// ─── Scenario 2: Array Serialization ─────────────────────────────────────────
// [SEAM 2 — Args → HTTP Request]
// [STATUS: PROBE — formerly CANARY, fixed by adding collectionFormat support]
//
// The API requires comma-separated arrays: ?tags=a,b,c
// Tool definitions can now opt specific array properties into delimited
// serialization via OpenAPI 2.0 `collectionFormat` or OpenAPI 3.0
// `style + explode`. `qs()` honors the hint and joins on the right delimiter.
//
// Desired behavior: bridge serializes arrays as comma-separated when the
// schema declares `collectionFormat: 'csv'`.
// Default (no hint) remains repeated params, matching OpenAPI defaults.

describe('Scenario 2: Array Serialization', () => {
  let mock, bridge;

  before(async () => {
    mock = await arrayFormatApi();
    bridge = createRestBridge({
      name: 'array-format-api',
      version: '1.0.0',
      baseUrl: `http://127.0.0.1:${mock.port}`,
      tools: [{
        name: 'list_items',
        description: 'List items by tags.',
        method: 'GET',
        path: '/items',
        inputSchema: {
          type: 'object',
          properties: {
            tags: {
              type: 'array',
              items: { type: 'string' },
              // OpenAPI 2.0 hint — qs() joins on commas instead of repeating.
              collectionFormat: 'csv',
              description: 'Filter tags (comma-separated in request)',
            },
          },
        },
      }],
    });
  });

  after(() => mock.server.close());

  it('serializes array args as comma-separated query params', async () => {
    // With collectionFormat: 'csv', qs() joins on commas. The mock rejects
    // repeated params with HTTP 400, so any regression to repeat-style here
    // will surface as a thrown dispatch error.
    const result = await bridge.dispatch('list_items', { tags: ['alpha', 'beta', 'gamma'] });
    const body = parse(result);
    assert.ok(Array.isArray(body.items), 'should return items array');
    assert.equal(body.items.length, 3, 'should return 3 filtered items');

    // Cross-check that the wire format was actually comma-joined, not just
    // accidentally accepted. The mock records the last URL it received.
    const sent = mock.getLastQuery();
    assert.ok(
      sent.includes('tags=alpha%2Cbeta%2Cgamma') || sent.includes('tags=alpha,beta,gamma'),
      `expected comma-joined tags on the wire, got: ${sent}`,
    );
  });

  it('handles single-item array without serialization issues', async () => {
    // Single item — no comma needed, repeated vs comma is the same
    const result = await bridge.dispatch('list_items', { tags: ['solo'] });
    const body = parse(result);
    assert.ok(Array.isArray(body.items));
    assert.equal(body.items.length, 1);
  });

  it('handles empty array gracefully', async () => {
    const result = await bridge.dispatch('list_items', { tags: [] });
    const body = parse(result);
    assert.ok(Array.isArray(body.items));
    assert.equal(body.items.length, 0);
  });
});

// ─── Scenario 3: Error as 200 ─────────────────────────────────────────────────
// [SEAM 3 — HTTP Response → MCP Result]
// [STATUS: PROBE]
//
// HTTP 200, body is {success: false, error: "..."}.
// No HTTP error code to detect failure on — this is entirely invisible to the
// bridge's HTTP layer.
//
// Desired behavior: bridge does NOT throw (200 is 200). The body reaches the
// LLM intact, including success:false, so the LLM can handle it.
// Worst case: bridge strips or reshapes the body, hiding the error from the LLM.

describe('Scenario 3: Error as 200', () => {
  let mock, bridge;

  before(async () => {
    mock = await errorAs200Api();
    bridge = createRestBridge({
      name: 'error-as-200-api',
      version: '1.0.0',
      baseUrl: `http://127.0.0.1:${mock.port}`,
      tools: [{
        name: 'get_order',
        description: 'Get order by ID.',
        method: 'GET',
        path: '/orders/:id',
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
        },
      }],
    });
  });

  after(() => mock.server.close());

  it('does not throw on HTTP 200 with error body', async () => {
    // Must not throw — HTTP 200 is a success at the transport layer
    const result = await bridge.dispatch('get_order', { id: 'ord_99' });
    assert.ok(result !== undefined, 'should return a result');
  });

  it('passes application-level error fields through to the LLM', async () => {
    const result = await bridge.dispatch('get_order', { id: 'ord_99' });
    const body = parse(result);

    // LLM must be able to see the failure signal
    assert.strictEqual(body.success, false, 'success flag must reach LLM');
    assert.ok(body.error, 'error message must reach LLM');
    assert.ok(body.code, 'error code must reach LLM');
  });
});

// ─── Scenario 4: Token Expiry ──────────────────────────────────────────────────
// [SEAM: Auth — Vault → Runtime Secret]
// [STATUS: PROBE]
//
// Valid token for the first 2 calls. Token expires on the 3rd call.
// Bridge has no OAuth2 refresh — it holds a static token.
//
// Desired behavior: calls 1-2 succeed; call 3 surfaces a clean, structured
// error (not an unhandled crash). The error message should give the LLM enough
// context to understand auth failed — not a generic JS exception.

describe('Scenario 4: Token Expiry', () => {
  let mock, bridge;

  before(async () => {
    mock = await tokenExpiryApi({ expiresAfter: 2 });
    bridge = createRestBridge({
      name: 'token-expiry-api',
      version: '1.0.0',
      baseUrl: `http://127.0.0.1:${mock.port}`,
      auth: { type: 'bearer', value: 'valid-token-xyz' },
      tools: [{
        name: 'get_resource',
        description: 'Fetch a protected resource.',
        method: 'GET',
        path: '/resource',
        inputSchema: { type: 'object', properties: {} },
      }],
    });
  });

  after(() => mock.server.close());

  it('succeeds on calls within the token lifetime', async () => {
    const r1 = await bridge.dispatch('get_resource', {});
    const r2 = await bridge.dispatch('get_resource', {});
    assert.ok(parse(r1).data, 'first call should succeed');
    assert.ok(parse(r2).data, 'second call should succeed');
  });

  it('surfaces a clean error when the token expires — no crash', async () => {
    // Exhaust token lifetime (calls 1-2 may have been used above)
    // Drain remaining calls until we hit expiry
    let expiryError;
    for (let i = 0; i < 5; i++) {
      try {
        await bridge.dispatch('get_resource', {});
      } catch (e) {
        expiryError = e;
        break;
      }
    }

    assert.ok(expiryError, 'should eventually throw after token expires');

    // The error must be structured — not a raw network failure or JS crash
    const msg = expiryError.message || '';
    const isStructured = (
      msg.includes('401') ||
      msg.includes('Unauthorized') ||
      msg.includes('token') ||
      msg.includes('expired') ||
      // McpError wraps it
      expiryError.code !== undefined
    );
    assert.ok(
      isStructured,
      `Error should reference auth failure, got: "${msg}"`,
    );
  });
});

// ─── Scenario 5: Mixer Collision ──────────────────────────────────────────────
// [SEAM: Compose — N APIs → Unified Surface]
// [STATUS: PROBE]
//
// Two API configs both define a tool named 'get_user' with no prefix.
// In strict mode, the mixer must detect this and throw a clear, actionable
// error naming the duplicate tool AND the conflicting servers.
//
// Default mode (not strict) is warn-and-skip so that a single bad
// server config does not crash the entire bridge in production. Dev/CI should
// pass `strict: true` to fail fast.

describe('Scenario 5: Mixer Collision', () => {
  const baseConfig = {
    name: 'collision-test',
    strict: true,
    servers: [
      {
        name: 'api-users',
        baseUrl: 'http://127.0.0.1:19999',
        tools: [{
          name: 'get_user',
          description: 'Get user from users service.',
          method: 'GET',
          path: '/users/:id',
          inputSchema: { type: 'object', properties: { id: { type: 'integer' } }, required: ['id'] },
        }],
      },
      {
        name: 'api-profiles',
        baseUrl: 'http://127.0.0.1:19998',
        tools: [{
          name: 'get_user',
          description: 'Get user from profiles service.',
          method: 'GET',
          path: '/profiles/:id',
          inputSchema: { type: 'object', properties: { id: { type: 'integer' } }, required: ['id'] },
        }],
      },
    ],
  };

  it('throws on duplicate tool name without prefix', () => {
    assert.throws(
      () => createMixer(baseConfig),
      (err) => {
        // Error must name the duplicate tool
        assert.ok(
          err.message.includes('get_user'),
          `Error should name the duplicate tool, got: "${err.message}"`,
        );
        // Error should reference at least one server name for actionability
        const referencesServer = (
          err.message.includes('api-users') ||
          err.message.includes('api-profiles') ||
          err.message.includes('server')
        );
        assert.ok(
          referencesServer,
          `Error should reference the offending server, got: "${err.message}"`,
        );
        return true;
      },
    );
  });

  it('resolves collision cleanly when prefixes are added', async () => {
    // Fix: add distinct prefixes — mixer should construct without error
    const fixed = {
      name: 'collision-fixed',
      servers: [
        { ...baseConfig.servers[0], prefix: 'users' },
        { ...baseConfig.servers[1], prefix: 'profiles' },
      ],
    };

    let mixer;
    assert.doesNotThrow(() => { mixer = createMixer(fixed); });

    // dispatch must exist and be callable
    assert.equal(typeof mixer.dispatch, 'function', 'mixer.dispatch should be a function');

    // A non-existent tool should throw "Unknown tool" — proves the dispatch table was built
    await assert.rejects(
      () => mixer.dispatch('nonexistent_tool', {}),
      (err) => {
        assert.ok(err.message.includes('nonexistent_tool'), 'error should name the unknown tool');
        return true;
      },
    );

    // Prefixed tools should be in the dispatch table — they throw a connection error (no
    // real HTTP server at those ports), NOT an "Unknown tool" error
    const usersErr = await mixer.dispatch('users.get_user', { id: 1 }).catch(e => e);
    assert.ok(
      !usersErr.message.includes('Unknown tool'),
      'users.get_user should be registered (not "Unknown tool"), got: ' + usersErr.message,
    );

    const profilesErr = await mixer.dispatch('profiles.get_user', { id: 1 }).catch(e => e);
    assert.ok(
      !profilesErr.message.includes('Unknown tool'),
      'profiles.get_user should be registered (not "Unknown tool"), got: ' + profilesErr.message,
    );
  });
});

// ─── Scenario 6: Large Response ───────────────────────────────────────────────
// [SEAM 3 — HTTP Response → MCP Result]
// [STATUS: PROBE]
//
// The API returns 1000 items with rich per-item data (~200KB total).
// The bridge tool is configured with tokenBudget to truncate the response.
//
// Desired behavior: truncated result is still parseable; it carries metadata
// indicating how many items were dropped; no crash; LLM can reason about
// the truncation rather than getting a corrupted or silent empty result.

describe('Scenario 6: Large Response', () => {
  let mock, bridge, bridgeUnbudgeted;

  before(async () => {
    mock = await largeResponseApi();
    const base = {
      name: 'large-response-api',
      version: '1.0.0',
      baseUrl: `http://127.0.0.1:${mock.port}`,
    };

    // Budgeted: tokenBudget set to truncate the 1000-item list
    bridge = createRestBridge({
      ...base,
      tools: [{
        name: 'list_records',
        description: 'List all records.',
        method: 'GET',
        path: '/records',
        inputSchema: { type: 'object', properties: {} },
        response: { tokenBudget: 2000, summary: true },
      }],
    });

    // Unbudgeted: no transform — raw response for comparison
    bridgeUnbudgeted = createRestBridge({
      ...base,
      name: 'large-response-api-raw',
      tools: [{
        name: 'list_records',
        description: 'List all records.',
        method: 'GET',
        path: '/records',
        inputSchema: { type: 'object', properties: {} },
      }],
    });
  });

  after(() => mock.server.close());

  it('does not crash on a 200KB response', async () => {
    const result = await bridge.dispatch('list_records', {});
    assert.ok(result !== undefined, 'should return a result');
  });

  it('truncates the response when tokenBudget is set', async () => {
    const result = await bridge.dispatch('list_records', {});
    const body = parse(result);

    // truncateByBudget wraps the result: { _truncated: true, items: [...], _original_count: N }
    assert.ok(body._truncated === true, 'result should carry _truncated flag');
    assert.ok(Array.isArray(body.items), 'truncated result should have items array');
    assert.ok(body.items.length < 1000, `items should be truncated below 1000, got ${body.items.length}`);
    assert.ok(body.items.length > 0, 'items should not be empty after truncation');
  });

  it('returns parseable items after truncation', async () => {
    const result = await bridge.dispatch('list_records', {});
    const body = parse(result);

    // Each remaining item in body.items should have the expected shape
    const first = body.items[0];
    assert.ok(first.id, 'item should have id');
    assert.ok(first.title, 'item should have title');
  });

  it('unbudgeted bridge returns all 1000 records', async () => {
    const result = await bridgeUnbudgeted.dispatch('list_records', {});
    const body = parse(result);
    assert.ok(Array.isArray(body));
    assert.equal(body.length, 1000, 'without budget, all records should return');
  });
});

// ─── Scenario 7: Live Public API (JSONPlaceholder) ───────────────────────────
// [SEAM: End-to-end — Spec → Args → HTTP → Response → MCP]
// [STATUS: PROBE — live network]
//
// Hits https://jsonplaceholder.typicode.com, a free no-auth sandbox API used
// across the JS ecosystem for integration tests. Exercises the full bridge
// pipeline against real DNS, TLS, and HTTP — no mock in the loop. This catches
// regressions that are invisible to in-process mocks (proxy handling, default
// headers, redirect behavior, real-world JSON shapes, response truncation
// against payloads we did not author).
//
// Skipping rules:
//   - Skips automatically when the network is unreachable (so default
//     `npm test` stays green offline / in sandboxed CI).
//   - Set OFFLINE=1 to force-skip without probing.
//
// To always require this scenario (e.g. nightly CI):
//   LIVE_API_TESTS=1 npm run test:integration

const LIVE_API_BASE = 'https://jsonplaceholder.typicode.com';
const LIVE_REQUIRED = process.env.LIVE_API_TESTS === '1';
const FORCED_OFFLINE = process.env.OFFLINE === '1';

async function probeLiveApi() {
  if (FORCED_OFFLINE) return false;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(`${LIVE_API_BASE}/posts/1`, { signal: ctrl.signal });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

describe('Scenario 7: Live Public API (JSONPlaceholder)', () => {
  let bridge, online;

  before(async () => {
    online = await probeLiveApi();
    if (!online && LIVE_REQUIRED) {
      throw new Error(
        'LIVE_API_TESTS=1 was set but jsonplaceholder.typicode.com is unreachable',
      );
    }
    bridge = createRestBridge({
      name: 'jsonplaceholder',
      version: '1.0.0',
      baseUrl: LIVE_API_BASE,
      tools: [
        {
          name: 'get_post',
          description: 'Fetch a single post by id.',
          method: 'GET',
          path: '/posts/:id',
          inputSchema: {
            type: 'object',
            properties: { id: { type: 'integer' } },
            required: ['id'],
          },
        },
        {
          name: 'list_posts',
          description: 'List all posts (~100 entries).',
          method: 'GET',
          path: '/posts',
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'list_posts_truncated',
          description: 'Same as list_posts, but token-budgeted.',
          method: 'GET',
          path: '/posts',
          inputSchema: { type: 'object', properties: {} },
          response: { tokenBudget: 500, summary: true },
        },
        {
          name: 'filter_comments',
          description: 'Filter comments by post id (server-side query param).',
          method: 'GET',
          path: '/comments',
          inputSchema: {
            type: 'object',
            properties: { postId: { type: 'integer' } },
            required: ['postId'],
          },
        },
      ],
    });
  });

  it('fetches a single post end-to-end', async (t) => {
    if (!online) return t.skip('jsonplaceholder unreachable — skipping live test');
    const result = await bridge.dispatch('get_post', { id: 1 });
    const body = parse(result);
    assert.equal(body.id, 1, 'id round-trips through the bridge');
    assert.equal(typeof body.title, 'string', 'title is a real string from the upstream');
    assert.equal(typeof body.userId, 'number', 'userId is a number from the upstream');
  });

  it('lists posts and returns a real array', async (t) => {
    if (!online) return t.skip('jsonplaceholder unreachable — skipping live test');
    const result = await bridge.dispatch('list_posts', {});
    const body = parse(result);
    assert.ok(Array.isArray(body), 'response is an array');
    assert.ok(body.length >= 50, `expected at least 50 posts, got ${body.length}`);
    assert.ok(body[0].id && body[0].title, 'items carry id + title');
  });

  it('truncates a real upstream payload when tokenBudget is set', async (t) => {
    if (!online) return t.skip('jsonplaceholder unreachable — skipping live test');
    const result = await bridge.dispatch('list_posts_truncated', {});
    const body = parse(result);
    // Truncation wraps the array into { _truncated, items, _original_count }
    assert.ok(body._truncated === true, 'tokenBudget should fire on a 100-post payload');
    assert.ok(Array.isArray(body.items), 'truncated body still has items');
    assert.ok(body.items.length > 0, 'at least one item should survive truncation');
    assert.ok(body.items.length < 100, 'fewer items than the full upstream list');
  });

  it('passes query params through to the live server', async (t) => {
    if (!online) return t.skip('jsonplaceholder unreachable — skipping live test');
    const result = await bridge.dispatch('filter_comments', { postId: 1 });
    const body = parse(result);
    assert.ok(Array.isArray(body), 'comments response is an array');
    assert.ok(body.length > 0, 'post 1 has comments');
    // Server-side filter must hold — every comment should belong to post 1.
    for (const c of body) {
      assert.equal(c.postId, 1, `expected postId=1, got ${c.postId}`);
    }
  });
});
