import { test } from 'node:test';
import assert from 'node:assert';
import { createReverseBridge } from '../reverse/server.js';
import { createSseTransport } from '../transport/sse.js';
import { createApiClient } from '../core/client.js';

// ============================================================================
// REVERSE BRIDGE AUTH BYPASS TESTS
// ============================================================================

test('reverse-bridge: GET /health should be open (no auth)', async () => {
  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Health endpoint should NOT require auth
    const res = await fetch(`http://127.0.0.1:${port}/api/health`);
    assert.strictEqual(res.status, 200, 'health endpoint should return 200 without auth');
    const data = await res.json();
    assert.strictEqual(data.status, 'ok', 'health endpoint should work without auth');
  } finally {
    httpServer.close();
  }
});

test('reverse-bridge: GET /api/tools requires auth (no header)', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // No auth header - should get 401
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`);
    assert.strictEqual(res.status, 401, 'should reject GET /tools without auth header');
    const data = await res.json();
    assert.strictEqual(data.error, 'Unauthorized', 'error message should be Unauthorized');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: GET /api/tools requires auth (wrong header value)', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Wrong header value - should get 401
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
      headers: { 'X-API-Key': 'wrong_secret' },
    });
    assert.strictEqual(res.status, 401, 'should reject GET /tools with wrong key');
    const data = await res.json();
    assert.strictEqual(data.error, 'Unauthorized', 'error message should be Unauthorized');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: GET /api/tools succeeds with correct auth', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: { type: 'object' } }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Correct auth - should get 200
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
      headers: { 'X-API-Key': 'secret123' },
    });
    assert.strictEqual(res.status, 200, 'should allow GET /tools with correct auth');
    const data = await res.json();
    assert.ok(Array.isArray(data.tools), 'should return tools array');
    assert.strictEqual(data.tools.length, 1, 'should return 1 tool');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: Auth header name is case-insensitive', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Send header in different case - HTTP headers are case-insensitive
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
      headers: { 'x-api-key': 'secret123' },
    });
    assert.strictEqual(res.status, 200, 'should accept lowercase header name');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: Empty auth header is rejected', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Empty header value
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
      headers: { 'X-API-Key': '' },
    });
    assert.strictEqual(res.status, 401, 'should reject empty auth header');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: Partial match in auth header is rejected (constant-time check)', async () => {
  process.env.API_KEY = 'secret123456';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Partial key match - should be rejected
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
      headers: { 'X-API-Key': 'secret123' }, // Missing "456"
    });
    assert.strictEqual(res.status, 401, 'should reject partial auth key match');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: POST /api/tools/:name requires auth (no header)', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({ result: 'ok' }),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // POST without auth - should get 401
    const res = await fetch(`http://127.0.0.1:${port}/api/tools/test_tool`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ param: 'value' }),
    });
    assert.strictEqual(res.status, 401, 'should reject POST tool call without auth');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: POST /api/tools/:name succeeds with correct auth', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async (name, args) => ({ name, args }),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // POST with correct auth - should succeed
    const res = await fetch(`http://127.0.0.1:${port}/api/tools/test_tool`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'secret123',
      },
      body: JSON.stringify({ param: 'value' }),
    });
    assert.strictEqual(res.status, 200, 'should allow POST tool call with correct auth');
    const data = await res.json();
    assert.strictEqual(data.result.name, 'test_tool', 'dispatch should be called');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: GET /api/openapi.json requires auth', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // No auth - should get 401
    const res = await fetch(`http://127.0.0.1:${port}/api/openapi.json`);
    assert.strictEqual(res.status, 401, 'should reject OpenAPI spec without auth');

    // With auth - should succeed
    const resAuth = await fetch(`http://127.0.0.1:${port}/api/openapi.json`, {
      headers: { 'X-API-Key': 'secret123' },
    });
    assert.strictEqual(resAuth.status, 200, 'should allow OpenAPI spec with auth');
    const data = await resAuth.json();
    assert.strictEqual(data.openapi, '3.0.0', 'should return valid OpenAPI spec');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: OPTIONS preflight does not bypass auth check', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // OPTIONS to protected endpoint - should still work (CORS preflight is allowed)
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
      method: 'OPTIONS',
    });
    // OPTIONS for paths under basePath now returns 204 (RFC-conformant) instead of 200.
    // Unauthenticated preflight is still allowed for legitimate CORS negotiation.
    assert.strictEqual(res.status, 204, 'OPTIONS should return 204 (CORS preflight)');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

test('reverse-bridge: Missing envVar causes auth to fail', async () => {
  delete process.env.MISSING_KEY;

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'MISSING_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Even with header sent, if envVar is missing, auth fails
    const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
      headers: { 'X-API-Key': 'some_value' },
    });
    assert.strictEqual(res.status, 401, 'should reject if env var is missing');
  } finally {
    httpServer.close();
  }
});

test('reverse-bridge: AUTH prevents null bytes in header (fetch layer defense)', async () => {
  process.env.API_KEY = 'secret123';

  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'test_tool', description: 'A test tool', inputSchema: {} }],
    dispatch: async () => ({}),
    port: 0,
    auth: { header: 'X-API-Key', envVar: 'API_KEY' },
  });

  const { httpServer, url } = await bridge.start();
  const port = httpServer.address().port;

  try {
    // Attempt null byte injection (fetch layer should reject it)
    let error = null;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/tools`, {
        headers: { 'X-API-Key': 'secret123\x00admin' },
      });
    } catch (e) {
      error = e;
    }
    assert.ok(error && error.message.includes('invalid header'), 'fetch should reject null bytes in header');
  } finally {
    httpServer.close();
    delete process.env.API_KEY;
  }
});

// ============================================================================
// SSE SESSION HIJACKING TESTS
// ============================================================================

test('sse: Connect with valid sessionId', async () => {
  const mockServer = {
    connect: async () => {},
  };

  const transport = await createSseTransport(mockServer, {
    port: 0,
    host: '127.0.0.1',
    path: '/sse',
    messagePath: '/message',
  });

  const port = transport.httpServer.address().port;

  try {
    // Connect with valid sessionId
    const res = await fetch(`http://127.0.0.1:${port}/sse?sessionId=session-123`, {
      signal: AbortSignal.timeout(500),
    }).catch(e => e);

    // Should either connect (200) or timeout (because SSE keeps stream open)
    // The important thing is it doesn't reject the sessionId
    assert.ok(res && (res.status === 200 || res.name === 'AbortError'), 'should accept valid sessionId');
  } finally {
    transport.httpServer.close();
  }
});

test('sse: Reject invalid sessionId format (path traversal)', async () => {
  const mockServer = {
    connect: async () => {},
  };

  const transport = await createSseTransport(mockServer, {
    port: 0,
    host: '127.0.0.1',
    path: '/sse',
    messagePath: '/message',
  });

  const port = transport.httpServer.address().port;

  try {
    // Path traversal attack in sessionId
    const res = await fetch(`http://127.0.0.1:${port}/sse?sessionId=../../secret`);
    assert.strictEqual(res.status, 400, 'should reject sessionId with path traversal');
  } finally {
    transport.httpServer.close();
  }
});

test('sse: Reject sessionId exceeding max length', async () => {
  const mockServer = {
    connect: async () => {},
  };

  const transport = await createSseTransport(mockServer, {
    port: 0,
    host: '127.0.0.1',
    path: '/sse',
    messagePath: '/message',
  });

  const port = transport.httpServer.address().port;

  try {
    // sessionId > 128 chars (max allowed)
    const longSessionId = 'a'.repeat(129);
    const res = await fetch(`http://127.0.0.1:${port}/sse?sessionId=${longSessionId}`);
    assert.strictEqual(res.status, 400, 'should reject sessionId > 128 chars');
  } finally {
    transport.httpServer.close();
  }
});

test('sse: Reject sessionId with invalid characters', async () => {
  const mockServer = {
    connect: async () => {},
  };

  const transport = await createSseTransport(mockServer, {
    port: 0,
    host: '127.0.0.1',
    path: '/sse',
    messagePath: '/message',
  });

  const port = transport.httpServer.address().port;

  try {
    // sessionId with special chars (only alphanumeric, _, - allowed)
    const res = await fetch(`http://127.0.0.1:${port}/sse?sessionId=session@123#abc`);
    assert.strictEqual(res.status, 400, 'should reject sessionId with invalid chars');
  } finally {
    transport.httpServer.close();
  }
});

test('sse: POST message without sessionId returns 404', async () => {
  const mockServer = {
    connect: async () => {},
  };

  const transport = await createSseTransport(mockServer, {
    port: 0,
    host: '127.0.0.1',
    path: '/sse',
    messagePath: '/message',
  });

  const port = transport.httpServer.address().port;

  try {
    // POST to message endpoint without sessionId - session not found
    const res = await fetch(`http://127.0.0.1:${port}/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: 'test' }),
    });
    assert.strictEqual(res.status, 404, 'should reject POST message without sessionId');
  } finally {
    transport.httpServer.close();
  }
});

test('sse: POST message to non-existent sessionId returns 404', async () => {
  const mockServer = {
    connect: async () => {},
  };

  const transport = await createSseTransport(mockServer, {
    port: 0,
    host: '127.0.0.1',
    path: '/sse',
    messagePath: '/message',
  });

  const port = transport.httpServer.address().port;

  try {
    // POST to message endpoint with unknown sessionId
    const res = await fetch(`http://127.0.0.1:${port}/message?sessionId=nonexistent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: 'test' }),
    });
    assert.strictEqual(res.status, 404, 'should reject POST to non-existent session');
  } finally {
    transport.httpServer.close();
  }
});

test('sse: Health endpoint hides session count by default (patched)', async () => {
  const mockServer = {
    connect: async () => {},
  };

  // Default: exposeSessionCount is false — sessions must not appear in health response
  const transport = await createSseTransport(mockServer, {
    port: 0,
    host: '127.0.0.1',
    path: '/sse',
    messagePath: '/message',
  });

  const port = transport.httpServer.address().port;

  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.strictEqual(res.status, 200, 'health endpoint should work');
    const data = await res.json();
    assert.strictEqual(data.status, 'ok', 'health should return ok');
    assert.ok(!('sessions' in data), 'session count must not be exposed by default');

    // With exposeSessionCount: true, the count is available for trusted internal monitoring
    transport.httpServer.close();
    const transport2 = await createSseTransport(mockServer, {
      port: 0,
      host: '127.0.0.1',
      exposeSessionCount: true,
    });
    const port2 = transport2.httpServer.address().port;
    try {
      const res2 = await fetch(`http://127.0.0.1:${port2}/health`);
      const data2 = await res2.json();
      assert.strictEqual(typeof data2.sessions, 'number', 'session count exposed when opted in');
    } finally {
      transport2.httpServer.close();
    }
  } catch (err) {
    transport.httpServer.close();
    throw err;
  }
});

// ============================================================================
// CLIENT AUTH LEAKAGE TESTS
// ============================================================================

test('client: buildHeaders with missing envVar does not send credential', async () => {
  delete process.env.TEST_TOKEN;

  const client = await import('../core/client.js');

  const { buildHeaders } = await import('../core/client.js');

  // Access the private function by importing and testing indirectly
  // We'll test via createApiClient behavior
  const apiClient = client.createApiClient('http://localhost:8080', {
    type: 'bearer',
    envVar: 'TEST_TOKEN',
  });

  // Create a mock fetch to capture headers
  let capturedHeaders = null;
  const originalFetch = global.fetch;
  global.fetch = async (url, init) => {
    capturedHeaders = init.headers;
    return { ok: true, status: 200, text: async () => '{"ok":true}' };
  };

  try {
    await apiClient('GET', '/test');
    // When envVar doesn't exist and no fallback value, Authorization header should not be set
    assert.ok(!capturedHeaders['Authorization'], 'should not send Authorization header when env var is missing');
  } finally {
    global.fetch = originalFetch;
  }
});

test('client: Bearer token formatted correctly in Authorization header', async () => {
  process.env.TEST_TOKEN = 'my-secret-token-xyz';

  const client = await import('../core/client.js');
  const apiClient = client.createApiClient('http://localhost:8080', {
    type: 'bearer',
    envVar: 'TEST_TOKEN',
  });

  let capturedHeaders = null;
  const originalFetch = global.fetch;
  global.fetch = async (url, init) => {
    capturedHeaders = init.headers;
    return { ok: true, status: 200, text: async () => '{"ok":true}' };
  };

  try {
    await apiClient('GET', '/test');
    assert.strictEqual(
      capturedHeaders['Authorization'],
      'Bearer my-secret-token-xyz',
      'Authorization header should use Bearer format'
    );
  } finally {
    global.fetch = originalFetch;
    delete process.env.TEST_TOKEN;
  }
});

test('client: Basic auth formatted correctly in Authorization header', async () => {
  process.env.TEST_CREDS = 'user:password';

  const client = await import('../core/client.js');
  const apiClient = client.createApiClient('http://localhost:8080', {
    type: 'basic',
    envVar: 'TEST_CREDS',
  });

  let capturedHeaders = null;
  const originalFetch = global.fetch;
  global.fetch = async (url, init) => {
    capturedHeaders = init.headers;
    return { ok: true, status: 200, text: async () => '{"ok":true}' };
  };

  try {
    await apiClient('GET', '/test');
    const expected = `Basic ${Buffer.from('user:password').toString('base64')}`;
    assert.strictEqual(
      capturedHeaders['Authorization'],
      expected,
      'Authorization header should use Basic auth format'
    );
  } finally {
    global.fetch = originalFetch;
    delete process.env.TEST_CREDS;
  }
});

test('client: Custom header auth sent correctly', async () => {
  process.env.API_KEY_VALUE = 'custom-api-key';

  const client = await import('../core/client.js');
  const apiClient = client.createApiClient('http://localhost:8080', {
    type: 'header',
    header: 'X-Custom-Key',
    envVar: 'API_KEY_VALUE',
  });

  let capturedHeaders = null;
  const originalFetch = global.fetch;
  global.fetch = async (url, init) => {
    capturedHeaders = init.headers;
    return { ok: true, status: 200, text: async () => '{"ok":true}' };
  };

  try {
    await apiClient('GET', '/test');
    assert.strictEqual(
      capturedHeaders['X-Custom-Key'],
      'custom-api-key',
      'Custom header should contain auth value'
    );
  } finally {
    global.fetch = originalFetch;
    delete process.env.API_KEY_VALUE;
  }
});

test('client: Rejects invalid baseUrl scheme (SSRF prevention)', async () => {
  const client = await import('../core/client.js');

  // ftp:// scheme should be rejected
  assert.throws(
    () => client.createApiClient('ftp://localhost:8080'),
    /Invalid baseUrl scheme/,
    'should reject ftp:// scheme'
  );

  // file:// scheme should be rejected
  assert.throws(
    () => client.createApiClient('file:///etc/passwd'),
    /Invalid baseUrl scheme/,
    'should reject file:// scheme'
  );

  // Valid schemes should not throw
  assert.doesNotThrow(
    () => client.createApiClient('http://localhost:8080'),
    'should allow http://'
  );

  assert.doesNotThrow(
    () => client.createApiClient('https://localhost:8080'),
    'should allow https://'
  );
});

test('client: Invalid custom header name rejected (injection prevention)', async () => {
  const client = await import('../core/client.js');

  // Header name with CRLF - should be rejected
  assert.throws(
    () => client.createApiClient('http://localhost:8080', {
      type: 'header',
      header: 'X-Key\r\nInjected: value',
      envVar: 'SOME_KEY',
    }),
    /Invalid auth header name/,
    'should reject header with CRLF'
  );

  // Header name with spaces - should be rejected
  assert.throws(
    () => client.createApiClient('http://localhost:8080', {
      type: 'header',
      header: 'X Key',
      envVar: 'SOME_KEY',
    }),
    /Invalid auth header name/,
    'should reject header with spaces'
  );

  // Valid header names should work
  assert.doesNotThrow(
    () => client.createApiClient('http://localhost:8080', {
      type: 'header',
      header: 'X-Custom-Key',
      envVar: 'SOME_KEY',
    }),
    'should allow valid header name'
  );
});
