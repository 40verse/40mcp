/**
 * MCP-to-API round trip proof.
 *
 * Approach:
 *   1. Spin up a real local HTTP server (the "API")
 *   2. Build a bridge config pointing at it
 *   3. Call bridge.dispatch() directly — this exercises the full bridge stack:
 *      arg validation → path interpolation → auth header injection →
 *      real HTTP request → response parsing → transform → return
 *   4. Assert the response is what the server returned
 *
 * No mocking. Every hop is real.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRestBridge } from '../src/bridge.js';

// ─── Realistic mock API ───────────────────────────────────────────────────────

function createRealisticApi({ requireAuth = false } = {}) {
  const users = Array.from({ length: 50 }, (_, i) => ({
    id: i + 1,
    name: `User ${i + 1}`,
    email: `user${i + 1}@example.com`,
    department: i % 3 === 0 ? 'engineering' : i % 3 === 1 ? 'design' : 'product',
    active: i % 5 !== 0,
    metadata: { created: '2025-01-01', tags: ['internal'] },
  }));

  return createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    // Auth check
    if (requireAuth) {
      const authHeader = req.headers['x-api-key'] || req.headers['authorization'];
      if (!authHeader || authHeader === 'Bearer invalid') {
        res.writeHead(401);
        return res.end(JSON.stringify({ error: 'Unauthorized', code: 'AUTH_REQUIRED' }));
      }
    }

    const url = new URL(req.url, `http://${req.headers.host}`);

    // GET /users — returns large list
    if (req.method === 'GET' && url.pathname === '/users') {
      const dept = url.searchParams.get('department');
      const list = dept ? users.filter((u) => u.department === dept) : users;
      res.writeHead(200);
      return res.end(JSON.stringify(list));
    }

    // GET /users/:id
    const userMatch = url.pathname.match(/^\/users\/(\d+)$/);
    if (req.method === 'GET' && userMatch) {
      const user = users.find((u) => u.id === parseInt(userMatch[1]));
      if (!user) { res.writeHead(404); return res.end(JSON.stringify({ error: 'User not found', id: userMatch[1] })); }
      res.writeHead(200);
      return res.end(JSON.stringify(user));
    }

    // POST /users
    if (req.method === 'POST' && url.pathname === '/users') {
      let body = '';
      req.on('data', (d) => { body += d; });
      req.on('end', () => {
        try {
          const data = JSON.parse(body || '{}');
          if (!data.name) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'name is required' }));
          }
          const user = { id: users.length + 1, ...data };
          users.push(user);
          res.writeHead(201);
          res.end(JSON.stringify(user));
        } catch {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    // DELETE /users/:id
    const deleteMatch = url.pathname.match(/^\/users\/(\d+)$/);
    if (req.method === 'DELETE' && deleteMatch) {
      res.writeHead(204);
      return res.end('');
    }

    // GET /rate-limited — simulates 429
    if (url.pathname === '/rate-limited') {
      res.writeHead(429);
      res.setHeader('Retry-After', '60');
      return res.end(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }));
    }

    // GET /slow — simulates slow response for timeout testing
    if (url.pathname === '/slow') {
      setTimeout(() => {
        res.writeHead(200);
        res.end(JSON.stringify({ slow: true }));
      }, 2000);
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found', path: url.pathname }));
  });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('MCP-to-API round trip', () => {
  let server;
  let port;
  let baseUrl;
  let bridge;

  before(async () => {
    server = createRealisticApi();
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;

    bridge = createRestBridge({
      name: 'test-api',
      version: '1.0.0',
      baseUrl,
      tools: [
        {
          name: 'list_users',
          description: 'List all users.',
          method: 'GET',
          path: '/users',
          inputSchema: {
            type: 'object',
            properties: {
              department: { type: 'string', description: 'Filter by department' },
            },
          },
        },
        {
          name: 'get_user',
          description: 'Get a user by ID.',
          method: 'GET',
          path: '/users/:user_id',
          inputSchema: {
            type: 'object',
            properties: {
              user_id: { type: 'integer' },
            },
            required: ['user_id'],
          },
        },
        {
          name: 'create_user',
          description: 'Create a new user.',
          method: 'POST',
          path: '/users',
          inputSchema: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              email: { type: 'string' },
              department: { type: 'string' },
            },
            required: ['name'],
          },
        },
      ],
    });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it('GET with no args returns the full list', async () => {
    const result = await bridge.dispatch('list_users', {});
    const users = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(Array.isArray(users), 'Should return an array');
    assert.equal(users.length, 50, 'Should return all 50 users');
  });

  it('GET with query param filters results', async () => {
    const result = await bridge.dispatch('list_users', { department: 'engineering' });
    const users = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(Array.isArray(users));
    assert.ok(users.every((u) => u.department === 'engineering'), 'All returned users should be in engineering');
  });

  it('GET with path parameter returns single resource', async () => {
    const result = await bridge.dispatch('get_user', { user_id: 1 });
    const user = typeof result === 'string' ? JSON.parse(result) : result;
    assert.equal(user.id, 1);
    assert.equal(user.name, 'User 1');
  });

  it('404 from API produces a structured error, not a crash', async () => {
    await assert.rejects(
      () => bridge.dispatch('get_user', { user_id: 9999 }),
      (err) => {
        assert.ok(err.message, 'Should have an error message');
        return true;
      },
    );
  });

  it('POST sends body and returns 201 with created resource', async () => {
    const result = await bridge.dispatch('create_user', {
      name: 'Dave',
      email: 'dave@example.com',
      department: 'product',
    });
    const user = typeof result === 'string' ? JSON.parse(result) : result;
    assert.equal(user.name, 'Dave');
    assert.ok(user.id, 'Created user should have an ID');
  });

  it('response transform: pick reduces payload to specified fields', async () => {
    const bridge2 = createRestBridge({
      name: 'transformed',
      baseUrl,
      tools: [
        {
          name: 'list_users_slim',
          description: 'List users (slim)',
          method: 'GET',
          path: '/users',
          inputSchema: { type: 'object', properties: {} },
          response: {
            pick: ['id', 'name'],
            limit: 5,
          },
        },
      ],
    });

    const result = await bridge2.dispatch('list_users_slim', {});
    const users = typeof result === 'string' ? JSON.parse(result) : result;

    assert.ok(Array.isArray(users));
    assert.ok(users.length <= 5, `Should be capped at 5, got ${users.length}`);
    assert.ok(users.every((u) => 'id' in u && 'name' in u), 'Should have id and name');
    assert.ok(users.every((u) => !('email' in u)), 'Should NOT have email (picked out)');
    assert.ok(users.every((u) => !('metadata' in u)), 'Should NOT have metadata (picked out)');
  });

  it('response transform: tokenBudget truncates large response', async () => {
    const bridge3 = createRestBridge({
      name: 'budgeted',
      baseUrl,
      tools: [
        {
          name: 'list_users_budget',
          description: 'List users with token budget',
          method: 'GET',
          path: '/users',
          inputSchema: { type: 'object', properties: {} },
          response: { tokenBudget: 500 },
        },
      ],
    });

    const result = await bridge3.dispatch('list_users_budget', {});
    const text = typeof result === 'string' ? result : JSON.stringify(result);
    // 500 tokens ≈ ~2000 chars — the full 50-user list is much larger
    assert.ok(text.length < 3000, `Response should be truncated by tokenBudget, got ${text.length} chars`);
  });
});

describe('MCP-to-API: auth forwarding', () => {
  let server;
  let port;
  let baseUrl;

  before(async () => {
    server = createRealisticApi({ requireAuth: true });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it('bearer token from env is forwarded to API', async () => {
    process.env._TEST_API_TOKEN = 'test-token-abc';

    const bridge = createRestBridge({
      name: 'auth-test',
      baseUrl,
      auth: { type: 'bearer', envVar: '_TEST_API_TOKEN' },
      tools: [{
        name: 'list_users',
        method: 'GET',
        path: '/users',
        description: 'List users',
        inputSchema: { type: 'object', properties: {} },
      }],
    });

    const result = await bridge.dispatch('list_users', {});
    const users = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(Array.isArray(users), 'Should succeed with valid bearer token');

    delete process.env._TEST_API_TOKEN;
  });

  it('missing auth token causes 401 error', async () => {
    delete process.env._TEST_MISSING_TOKEN;

    const bridge = createRestBridge({
      name: 'no-auth',
      baseUrl,
      auth: { type: 'bearer', envVar: '_TEST_MISSING_TOKEN' },
      tools: [{
        name: 'list_users',
        method: 'GET',
        path: '/users',
        description: 'List users',
        inputSchema: { type: 'object', properties: {} },
      }],
    });

    await assert.rejects(
      () => bridge.dispatch('list_users', {}),
      (err) => {
        assert.ok(err.message, 'Should throw on 401');
        return true;
      },
    );
  });
});
