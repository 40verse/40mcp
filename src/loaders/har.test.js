import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadHarFile } from './har.js';

// ─── Mock HAR object helpers ───────────────────────────────────────────────

function createMockHar(entries) {
  return {
    log: {
      version: '1.2',
      creator: { name: 'test' },
      entries: entries || [],
    },
  };
}

function createEntry(method, url, queryString = [], postData = null, responseBody = null) {
  return {
    request: {
      method,
      url,
      queryString,
      postData,
    },
    response: {
      status: 200,
      content: {
        mimeType: 'application/json',
        text: responseBody || '{}',
      },
    },
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('loadHarFile', () => {
  it('extracts base URL from entries', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/users/456'),
    ]);

    const { baseUrl } = await loadHarFile(har);
    assert.equal(baseUrl, 'https://api.example.com');
  });

  it('generates simple GET tool with correct name and method', async () => {
    const har = createMockHar([createEntry('GET', 'https://api.example.com/api/users')]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
    assert.equal(tools[0].name, 'list_users');
    assert.equal(tools[0].method, 'GET');
    assert.equal(tools[0].path, '/api/users');
  });

  it('infers POST tool for create operations', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/users', [], {
        mimeType: 'application/json',
        text: '{"name":"John","email":"john@example.com"}',
      }),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
    assert.equal(tools[0].name, 'create_users');
    assert.equal(tools[0].method, 'POST');
  });

  it('infers body parameters from POST request', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/users', [], {
        mimeType: 'application/json',
        text: '{"name":"John","email":"john@example.com"}',
      }),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.ok(tool.inputSchema.properties.name);
    assert.ok(tool.inputSchema.properties.email);
  });

  it('detects path parameters from numeric IDs', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/users/456'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
    assert.equal(tools[0].path, '/api/users/:param_1');
    assert.ok(tools[0].inputSchema.properties.param_1);
  });

  it('detects path parameters from UUID format', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/550e8400-e29b-41d4-a716-446655440000'),
      createEntry('GET', 'https://api.example.com/api/users/6ba7b810-9dad-11d1-80b4-00c04fd430c8'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].path, '/api/users/:param_1');
  });

  it('collects query parameters across multiple entries', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users?limit=10', [{ name: 'limit', value: '10' }]),
      createEntry('GET', 'https://api.example.com/api/users?limit=20', [{ name: 'limit', value: '20' }]),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.ok(tool.inputSchema.properties.limit);
  });

  it('infers integer type for numeric query parameters', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users?limit=10', [{ name: 'limit', value: '10' }]),
      createEntry('GET', 'https://api.example.com/api/users?limit=20', [{ name: 'limit', value: '20' }]),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.equal(tool.inputSchema.properties.limit.type, 'integer');
  });

  it('deduplicates endpoints seen multiple times', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/users/456'),
      createEntry('GET', 'https://api.example.com/api/users/789'),
      createEntry('GET', 'https://api.example.com/api/users/101'),
      createEntry('GET', 'https://api.example.com/api/users/102'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
    assert.equal(tools[0]._observations, 5);
  });

  it('generates correct verb for GET with singular noun', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/user/123'),
      createEntry('GET', 'https://api.example.com/api/user/456'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].name, 'get_user');
  });

  it('generates create verb for POST', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/users', [], {
        mimeType: 'application/json',
        text: '{"name":"John"}',
      }),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].name, 'create_users');
  });

  it('generates update verb for PUT', async () => {
    const har = createMockHar([
      createEntry('PUT', 'https://api.example.com/api/users/123', [], {
        mimeType: 'application/json',
        text: '{"name":"John"}',
      }),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].name, 'update_users');
  });

  it('generates delete verb for DELETE', async () => {
    const har = createMockHar([createEntry('DELETE', 'https://api.example.com/api/users/123')]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].name, 'delete_users');
  });

  it('confidence is low for 1 observation', async () => {
    const har = createMockHar([createEntry('GET', 'https://api.example.com/api/users/123')]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0]._confidence, 'low');
  });

  it('confidence is medium for 3-4 observations', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/users/456'),
      createEntry('GET', 'https://api.example.com/api/users/789'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0]._confidence, 'medium');
  });

  it('confidence is high for 5+ observations', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/1'),
      createEntry('GET', 'https://api.example.com/api/users/2'),
      createEntry('GET', 'https://api.example.com/api/users/3'),
      createEntry('GET', 'https://api.example.com/api/users/4'),
      createEntry('GET', 'https://api.example.com/api/users/5'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0]._confidence, 'high');
  });

  it('filters by include pattern', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/products/456'),
    ]);

    const { tools } = await loadHarFile(har, { include: ['users'] });
    assert.equal(tools.length, 1);
    assert.ok(tools[0].path.includes('users'));
  });

  it('filters by exclude pattern', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/admin/456'),
    ]);

    const { tools } = await loadHarFile(har, { exclude: ['admin'] });
    assert.equal(tools.length, 1);
    assert.ok(tools[0].path.includes('users'));
  });

  it('filters by HTTP methods', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users'),
      createEntry('POST', 'https://api.example.com/api/users'),
      createEntry('DELETE', 'https://api.example.com/api/users/123'),
    ]);

    const { tools } = await loadHarFile(har, { methods: ['GET'] });
    assert.ok(tools.every((t) => t.method === 'GET'));
  });

  it('respects minObservations filter', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('POST', 'https://api.example.com/api/posts'),
      createEntry('POST', 'https://api.example.com/api/posts'),
      createEntry('POST', 'https://api.example.com/api/posts'),
    ]);

    const { tools } = await loadHarFile(har, { minObservations: 3 });
    assert.equal(tools.length, 1);
    assert.equal(tools[0].name, 'create_posts');
  });

  it('includes observations count in tool metadata', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/users/456'),
      createEntry('GET', 'https://api.example.com/api/users/789'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0]._observations, 3);
  });

  it('marks required parameters from every entry', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users?limit=10&offset=0', [
        { name: 'limit', value: '10' },
        { name: 'offset', value: '0' },
      ]),
      createEntry('GET', 'https://api.example.com/api/users?limit=20&offset=10', [
        { name: 'limit', value: '20' },
        { name: 'offset', value: '10' },
      ]),
      createEntry('GET', 'https://api.example.com/api/users?limit=30', [{ name: 'limit', value: '30' }]),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.ok(tool.inputSchema.required.includes('limit'));
    assert.ok(!tool.inputSchema.required.includes('offset'));
  });

  it('infers boolean type for true/false values', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users?active=true', [{ name: 'active', value: 'true' }]),
      createEntry('GET', 'https://api.example.com/api/users?active=false', [{ name: 'active', value: 'false' }]),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.equal(tool.inputSchema.properties.active.type, 'boolean');
  });

  it('handles nested path parameters correctly', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/orgs/123/users/456'),
      createEntry('GET', 'https://api.example.com/api/orgs/789/users/101'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].path, '/api/orgs/:param_1/users/:param_2');
  });

  it('preserves non-ID path segments', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123/profile'),
      createEntry('GET', 'https://api.example.com/api/users/456/profile'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].path, '/api/users/:param_1/profile');
  });

  it('handles empty entries gracefully', async () => {
    const har = createMockHar([]);
    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 0);
  });

  it('handles HAR with missing log.entries', async () => {
    const har = { log: {} };
    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 0);
  });

  it('includes inputSchema in all tools', async () => {
    const har = createMockHar([createEntry('GET', 'https://api.example.com/api/users')]);

    const { tools } = await loadHarFile(har);
    assert.ok(tools[0].inputSchema);
    assert.equal(tools[0].inputSchema.type, 'object');
    assert.ok(tools[0].inputSchema.properties !== undefined);
    assert.ok(Array.isArray(tools[0].inputSchema.required));
  });

  it('handles query string with multiple values for same param', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/search?tag=javascript&tag=nodejs', [
        { name: 'tag', value: 'javascript' },
        { name: 'tag', value: 'nodejs' },
      ]),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.ok(tool.inputSchema.properties.tag);
  });

  it('generates description with observation count', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/users/456'),
      createEntry('GET', 'https://api.example.com/api/users/789'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.ok(tools[0].description.includes('3 observations'));
  });

  it('combines query params and body params in schema', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/users?notify=true', [{ name: 'notify', value: 'true' }], {
        mimeType: 'application/json',
        text: '{"name":"John","email":"john@example.com"}',
      }),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.ok(tool.inputSchema.properties.notify);
    assert.ok(tool.inputSchema.properties.name);
    assert.ok(tool.inputSchema.properties.email);
  });

  it('handles multiple HTTP methods for different operations on same resource', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('POST', 'https://api.example.com/api/users', [], {
        mimeType: 'application/json',
        text: '{"name":"John"}',
      }),
      createEntry('PUT', 'https://api.example.com/api/users/456', [], {
        mimeType: 'application/json',
        text: '{"name":"Jane"}',
      }),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 3);
    const methods = tools.map((t) => t.method);
    assert.ok(methods.includes('GET'));
    assert.ok(methods.includes('POST'));
    assert.ok(methods.includes('PUT'));
  });

  it('ignores entries with missing request data', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      { response: { status: 200 } }, // Missing request
      createEntry('GET', 'https://api.example.com/api/users/456'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
    assert.equal(tools[0]._observations, 2);
  });

  it('handles numeric values in body', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/users', [], {
        mimeType: 'application/json',
        text: '{"age":30,"salary":50000}',
      }),
      createEntry('POST', 'https://api.example.com/api/users', [], {
        mimeType: 'application/json',
        text: '{"age":25,"salary":45000}',
      }),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.equal(tool.inputSchema.properties.age.type, 'integer');
    assert.equal(tool.inputSchema.properties.salary.type, 'integer');
  });

  it('handles float values in parameters', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/items?price=19.99', [{ name: 'price', value: '19.99' }]),
      createEntry('GET', 'https://api.example.com/api/items?price=29.50', [{ name: 'price', value: '29.50' }]),
    ]);

    const { tools } = await loadHarFile(har);
    const tool = tools[0];
    assert.equal(tool.inputSchema.properties.price.type, 'number');
  });

  it('handles mixed include and exclude filters', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/123'),
      createEntry('GET', 'https://api.example.com/api/posts/456'),
      createEntry('GET', 'https://api.example.com/api/admin/users/789'),
    ]);

    const { tools } = await loadHarFile(har, { include: ['users'], exclude: ['admin'] });
    assert.equal(tools.length, 1);
    assert.ok(tools[0].path.includes('users'));
    assert.ok(!tools[0].path.includes('admin'));
  });

  it('does not infer parameter if segment is consistent across all entries', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users/profile/view'),
      createEntry('GET', 'https://api.example.com/api/users/profile/view'),
    ]);

    const { tools } = await loadHarFile(har);
    assert.equal(tools[0].path, '/api/users/profile/view');
  });
});

// ─── Security Controls ───────────────────────────────────────────────────────

describe('security controls', () => {
  it('filters chrome-extension:// URLs', async () => {
    const har = createMockHar([
      createEntry('GET', 'chrome-extension://abc123/background.js'),
      createEntry('GET', 'https://api.example.com/api/users'),
    ]);
    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
    assert.ok(tools[0].path.includes('users'));
  });

  it('filters moz-extension:// URLs', async () => {
    const har = createMockHar([
      createEntry('GET', 'moz-extension://abc123/content.js'),
      createEntry('GET', 'https://api.example.com/api/users'),
    ]);
    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
    assert.ok(tools[0].path.includes('users'));
  });

  it('filters ms-browser-extension:// URLs', async () => {
    const har = createMockHar([
      createEntry('GET', 'ms-browser-extension://xyz/tracker.js'),
      createEntry('GET', 'https://api.example.com/api/items'),
    ]);
    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1);
  });

  it('filters entries below minRequestTimeMs when opt-in enabled', async () => {
    const har = createMockHar([
      { ...createEntry('GET', 'https://api.example.com/api/telemetry'), time: 2 },
      createEntry('GET', 'https://api.example.com/api/users'),
    ]);
    const { tools } = await loadHarFile(har, { minRequestTimeMs: 5 });
    assert.equal(tools.length, 1);
    assert.ok(tools[0].path.includes('users'));
  });

  it('does not filter by timing when minRequestTimeMs is not set (default)', async () => {
    const har = createMockHar([
      { ...createEntry('GET', 'https://api.example.com/api/users'), time: 0 },
    ]);
    const { tools } = await loadHarFile(har);
    assert.equal(tools.length, 1); // timing filter is opt-in — not applied by default
  });

  it('does not filter entries without timing data even when minRequestTimeMs set', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/users'), // no time field
    ]);
    const { tools } = await loadHarFile(har, { minRequestTimeMs: 5 });
    assert.equal(tools.length, 1); // no time field → not filtered
  });

  it('does not filter entries above the minRequestTimeMs threshold', async () => {
    const har = createMockHar([
      { ...createEntry('GET', 'https://api.example.com/api/users'), time: 120 },
    ]);
    const { tools } = await loadHarFile(har, { minRequestTimeMs: 5 });
    assert.equal(tools.length, 1);
  });

  it('strips sensitive query param: token', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/data', [
        { name: 'limit', value: '10' },
        { name: 'token', value: 'secret-abc123' },
      ]),
    ]);
    const { tools } = await loadHarFile(har);
    assert.ok(tools[0].inputSchema.properties.limit, 'safe param should be included');
    assert.ok(!tools[0].inputSchema.properties.token, 'token should be stripped');
  });

  it('strips sensitive query param: authorization', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/data', [
        { name: 'q', value: 'search' },
        { name: 'authorization', value: 'Bearer xyz' },
      ]),
    ]);
    const { tools } = await loadHarFile(har);
    assert.ok(tools[0].inputSchema.properties.q);
    assert.ok(!tools[0].inputSchema.properties.authorization);
  });

  it('strips sensitive body param: password', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/login', [], {
        mimeType: 'application/json',
        text: '{"username":"john","password":"hunter2","remember":true}',
      }),
    ]);
    const { tools } = await loadHarFile(har);
    const props = tools[0].inputSchema.properties;
    assert.ok(props.username, 'username should be included');
    assert.ok(props.remember, 'remember should be included');
    assert.ok(!props.password, 'password should be stripped');
  });

  it('strips sensitive body param: secret', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/auth', [], {
        mimeType: 'application/json',
        text: '{"client_id":"app1","client_secret":"supersecret"}',
      }),
    ]);
    const { tools } = await loadHarFile(har);
    const props = tools[0].inputSchema.properties;
    assert.ok(props.client_id, 'client_id should be included');
    assert.ok(!props.client_secret, 'client_secret should be stripped');
  });

  it('strips query params with injection characters in name', async () => {
    const har = createMockHar([
      createEntry('GET', 'https://api.example.com/api/search', [
        { name: 'q', value: 'test' },
        { name: '<script>alert(1)</script>', value: 'xss' },
        { name: "'; DROP TABLE users; --", value: 'sqli' },
      ]),
    ]);
    const { tools } = await loadHarFile(har);
    const props = tools[0].inputSchema.properties;
    assert.ok(props.q, 'safe param q should be included');
    assert.ok(!props['<script>alert(1)</script>'], 'XSS param name should be stripped');
    assert.ok(!props["'; DROP TABLE users; --"], 'SQL injection param name should be stripped');
  });

  it('strips body params with injection characters in name', async () => {
    const har = createMockHar([
      createEntry('POST', 'https://api.example.com/api/data', [], {
        mimeType: 'application/json',
        text: '{"name":"John","key with spaces":"bad","valid_key":"ok"}',
      }),
    ]);
    const { tools } = await loadHarFile(har);
    const props = tools[0].inputSchema.properties;
    assert.ok(props.name, 'name should be included');
    assert.ok(props.valid_key, 'valid_key should be included');
    assert.ok(!props['key with spaces'], 'param name with spaces should be stripped');
  });

  it('caps entries at MAX_ENTRIES (2000) to prevent resource exhaustion', async () => {
    const entries = Array.from({ length: 2001 }, (_, i) =>
      createEntry('GET', `https://api.example.com/api/items/${i}`),
    );
    const har = createMockHar(entries);
    const { tools } = await loadHarFile(har);
    const totalObs = tools.reduce((sum, t) => sum + t._observations, 0);
    assert.ok(totalObs <= 2000, `Expected at most 2000 observations, got ${totalObs}`);
  });
});
