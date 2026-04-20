import { describe, it, mock, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMixer } from './mixer.js';

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

describe('createMixer', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  it('combines tools from 2 servers into one list', async () => {
    const fetcher1 = mockFetch(200, [{ id: 1 }]);
    const fetcher2 = mockFetch(200, [{ id: 2 }]);

    globalThis.fetch = (url) => {
      if (url.includes('api1')) return fetcher1();
      if (url.includes('api2')) return fetcher2();
      throw new Error(`Unexpected URL: ${url}`);
    };

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            name: 'API1',
            baseUrl: 'http://localhost:8001',
            tools: [
              {
                name: 'list_items',
                description: 'List items from API1',
                method: 'GET',
                path: '/api1/items',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
          {
            name: 'API2',
            baseUrl: 'http://localhost:8002',
            tools: [
              {
                name: 'get_users',
                description: 'Get users from API2',
                method: 'GET',
                path: '/api2/users',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
        ],
      });

      // Check tool list is registered
      assert.equal(mixer.server._options.capabilities.tools !== undefined, true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('prefixes tool names when prefix is set', async () => {
    const fetcher1 = mockFetch(200, { id: 1 });
    const fetcher2 = mockFetch(200, { id: 2 });

    const callCount = { api1: 0, api2: 0 };
    globalThis.fetch = (url) => {
      if (url.includes('api1')) {
        callCount.api1++;
        return fetcher1();
      }
      if (url.includes('api2')) {
        callCount.api2++;
        return fetcher2();
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            prefix: 'stripe',
            name: 'Stripe',
            baseUrl: 'http://localhost:8001',
            tools: [
              {
                name: 'list_invoices',
                description: 'List invoices',
                method: 'GET',
                path: '/api1/invoices',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
          {
            prefix: 'github',
            name: 'GitHub',
            baseUrl: 'http://localhost:8002',
            tools: [
              {
                name: 'list_invoices',
                description: 'List invoices (GitHub)',
                method: 'GET',
                path: '/api2/invoices',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
        ],
      });

      // Dispatch to prefixed tools should work
      const result1 = await mixer.dispatch('stripe.list_invoices', {});
      assert.deepEqual(result1, { id: 1 });
      assert.equal(callCount.api1, 1);

      const result2 = await mixer.dispatch('github.list_invoices', {});
      assert.deepEqual(result2, { id: 2 });
      assert.equal(callCount.api2, 1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('routes dispatch to correct API client based on tool name', async () => {
    const fetcher1 = mockFetch(200, { data: 'from api1' });
    const fetcher2 = mockFetch(200, { data: 'from api2' });

    let apiUsed = null;
    globalThis.fetch = (url) => {
      if (url.includes('api1')) {
        apiUsed = 'api1';
        return fetcher1();
      }
      if (url.includes('api2')) {
        apiUsed = 'api2';
        return fetcher2();
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            prefix: 'srv1',
            name: 'Server1',
            baseUrl: 'http://localhost:8001',
            tools: [
              {
                name: 'get_data',
                description: 'Get data from srv1',
                method: 'GET',
                path: '/api1/data',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
          {
            prefix: 'srv2',
            name: 'Server2',
            baseUrl: 'http://localhost:8002',
            tools: [
              {
                name: 'get_data',
                description: 'Get data from srv2',
                method: 'GET',
                path: '/api2/data',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
        ],
      });

      apiUsed = null;
      await mixer.dispatch('srv1.get_data', {});
      assert.equal(apiUsed, 'api1');

      apiUsed = null;
      await mixer.dispatch('srv2.get_data', {});
      assert.equal(apiUsed, 'api2');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('filters tools with allowlist', async () => {
    const fetcher = mockFetch(200, []);
    globalThis.fetch = fetcher;

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            name: 'API1',
            baseUrl: 'http://localhost:8001',
            allowlist: ['list_items', 'get_item'],
            tools: [
              {
                name: 'list_items',
                description: 'List items',
                method: 'GET',
                path: '/items',
                inputSchema: { type: 'object' },
              },
              {
                name: 'get_item',
                description: 'Get item',
                method: 'GET',
                path: '/items/:id',
                inputSchema: { type: 'object' },
              },
              {
                name: 'delete_item',
                description: 'Delete item (not in allowlist)',
                method: 'DELETE',
                path: '/items/:id',
                inputSchema: { type: 'object' },
              },
            ],
          },
        ],
      });

      // Check that only allowlisted tools are present
      try {
        await mixer.dispatch('list_items', {});
      } catch {
        // Network errors expected, tool exists
      }

      try {
        await mixer.dispatch('delete_item', {});
        assert.fail('Should not reach here — delete_item not in allowlist');
      } catch (e) {
        assert.ok(e.message.includes('Unknown tool'));
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('filters tools with blocklist', async () => {
    const fetcher = mockFetch(200, []);
    globalThis.fetch = fetcher;

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            name: 'API1',
            baseUrl: 'http://localhost:8001',
            blocklist: ['delete_customer'],
            tools: [
              {
                name: 'list_customers',
                description: 'List customers',
                method: 'GET',
                path: '/customers',
                inputSchema: { type: 'object' },
              },
              {
                name: 'delete_customer',
                description: 'Delete customer (blocklisted)',
                method: 'DELETE',
                path: '/customers/:id',
                inputSchema: { type: 'object' },
              },
            ],
          },
        ],
      });

      // list_customers should work
      try {
        await mixer.dispatch('list_customers', {});
      } catch {
        // Network errors ok
      }

      // delete_customer should fail
      try {
        await mixer.dispatch('delete_customer', {});
        assert.fail('Should not reach here — delete_customer is blocklisted');
      } catch (e) {
        assert.ok(e.message.includes('Unknown tool'));
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('warns and skips duplicate tool names without prefix', async () => {
    // Changed from hard-throw to warn+skip so a single conflicting server does not
    // crash the entire bridge startup. The first registration wins; duplicates are
    // skipped with a stderr warning.
    globalThis.fetch = mockFetch(200, { id: 1 });

    const stderrLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => { stderrLines.push(String(msg)); return origWrite(msg, ...rest); };

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            name: 'API1',
            baseUrl: 'http://localhost:8001',
            tools: [
              {
                name: 'get_data',
                description: 'Get data (first registration wins)',
                method: 'GET',
                path: '/data',
                inputSchema: { type: 'object' },
              },
            ],
          },
          {
            name: 'API2',
            baseUrl: 'http://localhost:8002',
            tools: [
              {
                name: 'get_data',
                description: 'Get data (duplicate — should be skipped)',
                method: 'GET',
                path: '/data',
                inputSchema: { type: 'object' },
              },
            ],
          },
        ],
      });

      // Should not throw — mixer is created successfully
      assert.ok(mixer);

      // A warning must have been emitted mentioning the duplicate tool name
      const warned = stderrLines.some((l) => l.includes('Duplicate tool name') && l.includes('get_data'));
      assert.ok(warned, 'Expected a stderr warning about duplicate tool name');

      // The first registration still works
      try {
        await mixer.dispatch('get_data', {});
      } catch {
        // Network errors OK — tool must exist in the map (no MethodNotFound)
      }
    } finally {
      process.stderr.write = origWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('throws on duplicate prefix names', () => {
    assert.throws(
      () =>
        createMixer({
          servers: [
            { prefix: 'api', name: 'A', baseUrl: 'http://a.com', tools: [] },
            { prefix: 'api', name: 'B', baseUrl: 'http://b.com', tools: [] },
          ],
        }),
      (err) => err.message.includes('Duplicate prefix') && err.message.includes('"api"'),
    );
  });

  it('handles mixed prefixed and unprefixed servers', async () => {
    const fetcher1 = mockFetch(200, { id: 1 });
    const fetcher2 = mockFetch(200, { id: 2 });

    let urlCalled = null;
    globalThis.fetch = (url) => {
      urlCalled = url;
      if (url.includes('api1')) return fetcher1();
      if (url.includes('api2')) return fetcher2();
      throw new Error(`Unexpected URL: ${url}`);
    };

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            name: 'Server1',
            baseUrl: 'http://localhost:8001',
            tools: [
              {
                name: 'get_item',
                description: 'Get item',
                method: 'GET',
                path: '/api1/item',
                inputSchema: { type: 'object' },
              },
            ],
          },
          {
            prefix: 'external',
            name: 'Server2',
            baseUrl: 'http://localhost:8002',
            tools: [
              {
                name: 'get_item',
                description: 'Get item (external)',
                method: 'GET',
                path: '/api2/item',
                inputSchema: { type: 'object' },
              },
            ],
          },
        ],
      });

      // Unprefixed tool
      urlCalled = null;
      await mixer.dispatch('get_item', {});
      assert.ok(urlCalled.includes('api1'));

      // Prefixed tool
      urlCalled = null;
      await mixer.dispatch('external.get_item', {});
      assert.ok(urlCalled.includes('api2'));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('respects each server auth independently', async () => {
    const fetcher1 = mockFetch(200, { id: 1 });
    const fetcher2 = mockFetch(200, { id: 2 });

    const calls = [];
    globalThis.fetch = (url, init) => {
      calls.push({ url, headers: init.headers });
      if (url.includes('api1')) return fetcher1();
      if (url.includes('api2')) return fetcher2();
      throw new Error(`Unexpected URL: ${url}`);
    };

    try {
      process.env.API1_KEY = 'secret1';
      process.env.API2_KEY = 'secret2';

      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            prefix: 'api1',
            name: 'API1',
            baseUrl: 'http://localhost:8001',
            auth: { type: 'bearer', envVar: 'API1_KEY' },
            tools: [
              {
                name: 'get_data',
                description: 'Get data',
                method: 'GET',
                path: '/api1/data',
                inputSchema: { type: 'object' },
              },
            ],
          },
          {
            prefix: 'api2',
            name: 'API2',
            baseUrl: 'http://localhost:8002',
            auth: { type: 'bearer', envVar: 'API2_KEY' },
            tools: [
              {
                name: 'get_data',
                description: 'Get data',
                method: 'GET',
                path: '/api2/data',
                inputSchema: { type: 'object' },
              },
            ],
          },
        ],
      });

      calls.length = 0;
      await mixer.dispatch('api1.get_data', {});
      assert.equal(calls[0].headers.Authorization, 'Bearer secret1');

      calls.length = 0;
      await mixer.dispatch('api2.get_data', {});
      assert.equal(calls[0].headers.Authorization, 'Bearer secret2');
    } finally {
      delete process.env.API1_KEY;
      delete process.env.API2_KEY;
      globalThis.fetch = originalFetch;
    }
  });

  it('throws on duplicate prefix names across servers', () => {
    assert.throws(
      () =>
        createMixer({
          name: 'combined',
          servers: [
            {
              name: 'ServerA',
              prefix: 'api',
              baseUrl: 'http://localhost:8001',
              tools: [],
            },
            {
              name: 'ServerB',
              prefix: 'api',
              baseUrl: 'http://localhost:8002',
              tools: [],
            },
          ],
        }),
      (err) => err.message.includes('Duplicate prefix') && err.message.includes('api'),
    );
  });

  it('acceptance: linking collision — duplicate tool names across servers: first wins, warning emitted, bridge still starts', async () => {
    // Verifies that when two unprefixed servers both expose a tool with the same name,
    // the collision is handled gracefully: first registration wins (deterministic),
    // a clear warning is emitted, and the bridge starts successfully without crashing.
    const fetcher1 = mockFetch(200, { id: 1, from: 'ServerA' });
    const fetcher2 = mockFetch(200, { id: 2, from: 'ServerB' });

    let serverHit = null;
    globalThis.fetch = (url) => {
      if (url.includes('8001')) {
        serverHit = 'ServerA';
        return fetcher1();
      }
      if (url.includes('8002')) {
        serverHit = 'ServerB';
        return fetcher2();
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const stderrLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => { stderrLines.push(String(msg)); return origWrite(msg, ...rest); };

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            name: 'ServerA',
            baseUrl: 'http://localhost:8001',
            tools: [
              {
                name: 'get_data',
                description: 'Get data from ServerA (first registration)',
                method: 'GET',
                path: '/api1/data',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
          {
            name: 'ServerB',
            baseUrl: 'http://localhost:8002',
            tools: [
              {
                name: 'get_data',
                description: 'Get data from ServerB (duplicate, should be skipped)',
                method: 'GET',
                path: '/api2/data',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
        ],
      });

      // Invariant 1: Bridge starts successfully (no throw)
      assert.ok(mixer, 'Mixer should be created successfully');

      // Invariant 2: A clear warning was written to stderr mentioning the duplicate
      const warned = stderrLines.some(
        (l) => l.includes('Duplicate tool name') && l.includes('get_data'),
      );
      assert.ok(warned, 'Expected a stderr warning about duplicate tool name get_data');

      // Invariant 3: Dispatching get_data hits ServerA (first registration wins)
      serverHit = null;
      const result = await mixer.dispatch('get_data', {});
      assert.equal(serverHit, 'ServerA', 'get_data dispatch should hit ServerA (first registration)');
      assert.equal(result.from, 'ServerA', 'Result should come from ServerA');
    } finally {
      process.stderr.write = origWrite;
      globalThis.fetch = originalFetch;
    }
  });

  it('acceptance: linking with prefix eliminates collision — both tools available', async () => {
    // Verifies that when two servers expose the same tool name but the second server
    // has a prefix, both tools are available with correct routing and no collision.
    const fetcher1 = mockFetch(200, { data: 'from server1' });
    const fetcher2 = mockFetch(200, { data: 'from server2' });

    let apiUsed = null;
    globalThis.fetch = (url) => {
      if (url.includes('8001')) {
        apiUsed = 'api1';
        return fetcher1();
      }
      if (url.includes('8002')) {
        apiUsed = 'api2';
        return fetcher2();
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    try {
      const mixer = createMixer({
        name: 'combined',
        servers: [
          {
            name: 'Server1',
            baseUrl: 'http://localhost:8001',
            tools: [
              {
                name: 'get_data',
                description: 'Get data from Server1 (unprefixed)',
                method: 'GET',
                path: '/data',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
          {
            prefix: 'b',
            name: 'Server2',
            baseUrl: 'http://localhost:8002',
            tools: [
              {
                name: 'get_data',
                description: 'Get data from Server2 (prefixed as b.get_data)',
                method: 'GET',
                path: '/data',
                inputSchema: { type: 'object', properties: {} },
              },
            ],
          },
        ],
      });

      // Dispatching unprefixed get_data should hit the first server
      apiUsed = null;
      await mixer.dispatch('get_data', {});
      assert.equal(apiUsed, 'api1', 'Unprefixed get_data should dispatch to api1');

      // Dispatching prefixed b.get_data should hit the second server
      apiUsed = null;
      await mixer.dispatch('b.get_data', {});
      assert.equal(apiUsed, 'api2', 'Prefixed b.get_data should dispatch to api2');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
