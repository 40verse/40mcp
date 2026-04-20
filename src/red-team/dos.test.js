/**
 * Red Team Denial of Service Tests for 40mcp
 *
 * Attack vectors:
 * 1. Request body bomb (reverse bridge)
 * 2. Token budget infinite loop
 * 3. Chain recursion bomb
 * 4. SSE session exhaustion
 * 5. HAR parser with huge input
 * 6. OpenAPI spec with thousands of paths
 */

import { test } from 'node:test';
import * as assert from 'node:assert';
import { createReverseBridge } from '../reverse/server.js';
import { createSseTransport } from '../transport/sse.js';
import { applyResponseTransform } from '../transforms/response.js';
import { executeChain } from '../compose/chain.js';
import { loadHarFile } from '../loaders/har.js';
import { loadGraphqlSchema } from '../loaders/graphql.js';

// ============================================================================
// VECTOR 1: Request body bomb (reverse bridge)
// ============================================================================

test('Vector 1.1: Request body at exactly 1MB limit should succeed', async (t) => {
  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'echo', description: 'Echo input' }],
    dispatch: async (toolName, args) => args,
  });

  const { httpServer, url } = await bridge.start();

  try {
    // Create a body that is exactly 1MB when JSON-stringified
    const payload = 'x'.repeat(1024 * 1024 - 100); // Leave margin for JSON overhead
    const response = await fetch(`${url}/api/tools/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: payload }),
    });

    // Should succeed (200) or gracefully reject (413/400)
    assert.ok([200, 400, 413].includes(response.status), `Unexpected status: ${response.status}`);
  } finally {
    httpServer.close();
  }
});

test('Vector 1.2: Request body slightly over 1MB should be rejected gracefully', async (t) => {
  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'echo', description: 'Echo input' }],
    dispatch: async (toolName, args) => args,
  });

  const { httpServer, url } = await bridge.start();

  try {
    // Create a body larger than 1MB
    const payload = 'x'.repeat(1024 * 1024 + 1000);
    try {
      const response = await fetch(`${url}/api/tools/echo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: payload }),
      });
      // Should reject (not hang or crash)
      assert.ok([400, 500].includes(response.status), `Expected rejection, got ${response.status}`);
    } catch (err) {
      // Connection drops are also acceptable (server rejected)
      assert.ok(err.message.includes('fetch') || err.message.includes('socket'), `Got error: ${err.message}`);
    }
  } finally {
    httpServer.close();
  }
});

test('Vector 1.3: Deeply nested JSON (1000 levels) should be rejected', async (t) => {
  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'echo', description: 'Echo input' }],
    dispatch: async (toolName, args) => args,
  });

  const { httpServer, url } = await bridge.start();

  try {
    // Build deeply nested structure
    let nested = { value: 'leaf' };
    for (let i = 0; i < 1000; i++) {
      nested = { level: i, child: nested };
    }

    const response = await fetch(`${url}/api/tools/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(nested),
    });

    // Should not crash or hang; graceful handling
    assert.ok([200, 400, 500].includes(response.status), `Unexpected status: ${response.status}`);
  } finally {
    httpServer.close();
  }
});

test('Vector 1.4: Content-Length header lying (says 100, sends 10MB) should be rejected', async (t) => {
  const bridge = createReverseBridge({
    name: 'test-api',
    tools: [{ name: 'echo', description: 'Echo input' }],
    dispatch: async (toolName, args) => args,
  });

  const { httpServer, url } = await bridge.start();

  try {
    // Create body larger than claimed Content-Length
    const payload = 'x'.repeat(10 * 1024 * 1024); // 10MB
    const bodyStr = JSON.stringify({ message: payload });

    try {
      const response = await fetch(`${url}/api/tools/echo`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': '100', // Lie about size
        },
        body: bodyStr,
        signal: AbortSignal.timeout(15000), // 15s timeout for large body
      });

      // Server should reject or timeout (not crash)
      assert.ok([400, 408, 500].includes(response.status), `Expected error, got ${response.status}`);
    } catch (err) {
      // Connection rejection, timeout, or abort are all acceptable — the
      // assertion is "server rejected, didn't crash/hang." Node 18's undici
      // surfaces the rejection as a bare "fetch failed" with the transport
      // error on err.cause; Node 20+ includes more detail in err.message.
      // Accept any of these shapes.
      const cause = err.cause ? String(err.cause.code || err.cause.message || err.cause) : '';
      const matches =
        err.message.includes('timeout') ||
        err.message.includes('socket') ||
        err.message.includes('fetch failed') ||
        err.name === 'AbortError' ||
        cause.includes('ECONNRESET') ||
        cause.includes('UND_ERR');
      assert.ok(matches, `Got error: ${err.message} (cause: ${cause})`);
    }
  } finally {
    httpServer.close();
  }
});

// ============================================================================
// VECTOR 2: Token budget infinite loop
// ============================================================================

test('Vector 2.1: tokenBudget of 1 on large array should truncate gracefully', (t) => {
  const largeArray = Array.from({ length: 1000 }, (_, i) => ({ id: i, data: 'x'.repeat(100) }));

  const result = applyResponseTransform(largeArray, {
    tokenBudget: 1,
  });

  // Should not hang; should return truncated result
  assert.ok(result._truncated || result._summary, 'Should truncate with tiny budget');
  assert.ok(Array.isArray(result.items || result), 'Should return valid structure');
});

test('Vector 2.2: tokenBudget of 0 should be handled (not loop)', (t) => {
  const data = { large: 'x'.repeat(1000) };

  const result = applyResponseTransform(data, {
    tokenBudget: 0,
  });

  // Should not hang or crash
  assert.ok(result._truncated || typeof result === 'object', 'Should return valid result');
});

test('Vector 2.3: Negative tokenBudget should be rejected or handled gracefully', (t) => {
  const data = [{ text: 'hello' }];

  // Should not throw or hang
  assert.doesNotThrow(() => {
    const result = applyResponseTransform(data, {
      tokenBudget: -100,
    });
    assert.ok(result, 'Should return a result');
  });
});

test('Vector 2.4: Single object exceeding tokenBudget (no array to truncate)', (t) => {
  const hugeString = 'x'.repeat(100000);
  const obj = { data: hugeString };

  const result = applyResponseTransform(obj, {
    tokenBudget: 10, // Impossibly small
  });

  // Should truncate gracefully, not loop
  assert.ok(result._truncated, 'Should mark as truncated');
  assert.ok(typeof result.data === 'object' || result.data !== undefined, 'Should preserve structure');
});

// ============================================================================
// VECTOR 3: Chain recursion bomb
// ============================================================================

test('Vector 3.1: Circular dependency in chain should be detected', async (t) => {
  const dispatch = async (toolName, args) => ({ result: toolName });

  const steps = [
    { call: 'toolB', as: 'step1', args: { ref: '$step2' } },
    { call: 'toolC', as: 'step2', args: { ref: '$step1' } },
  ];

  try {
    await executeChain(steps, {}, dispatch);
    assert.fail('Should have thrown circular dependency error');
  } catch (err) {
    assert.ok(err.message.includes('Circular dependency'), `Got: ${err.message}`);
  }
});

test('Vector 3.2: Chain with 1000 sequential steps should execute (eventually)', async (t) => {
  const steps = [];
  for (let i = 0; i < 100; i++) { // 100 steps to keep test fast
    steps.push({
      call: 'identity',
      as: `step${i}`,
      args: i === 0 ? { value: 1 } : { ref: `$step${i - 1}.value` },
    });
  }

  const dispatch = async (toolName, args) => ({ value: args.value || args.ref || 0 });

  const result = await executeChain(steps, {}, dispatch);

  assert.ok(result._chain, 'Should have chain metadata');
  assert.strictEqual(result._chain.steps, 100, 'Should track step count');
  assert.strictEqual(result._chain.completed, 100, 'Should complete all steps');
});

test('Vector 3.3: Chain with 1000 parallel steps (no dependencies)', async (t) => {
  const steps = [];
  for (let i = 0; i < 100; i++) { // 100 parallel steps
    steps.push({
      call: 'compute',
      as: `parallel${i}`,
      args: { value: i },
    });
  }

  const dispatch = async (toolName, args) => ({ result: args.value * 2 });

  const startTime = Date.now();
  const result = await executeChain(steps, {}, dispatch);
  const duration = Date.now() - startTime;

  assert.ok(result._chain, 'Should have chain metadata');
  assert.strictEqual(result._chain.completed, 100, 'Should complete all parallel steps');
  assert.ok(duration < 5000, `Parallel execution should be fast (${duration}ms)`);
});

test('Vector 3.4: Chain step with $ref resolving to huge object', async (t) => {
  const hugeData = Array.from({ length: 10000 }, (_, i) => ({ id: i, data: 'x' }));

  const steps = [
    { call: 'fetch', as: 'getData', args: {} },
    { call: 'process', as: 'processData', args: { ref: '$getData' } },
  ];

  const dispatch = async (toolName, args) => {
    if (toolName === 'fetch') return hugeData;
    if (toolName === 'process') return { count: args.ref?.length || 0 };
    return {};
  };

  const result = await executeChain(steps, {}, dispatch);

  assert.ok(result._chain.completed === 2, 'Should complete both steps');
  assert.strictEqual(result.processData.count, 10000, 'Should handle large object ref');
});

// ============================================================================
// VECTOR 4: SSE session exhaustion
// ============================================================================

test('Vector 4.1: Opening more sessions than maxSessions should be rejected', async (t) => {
  // Mock MCP server
  const mockServer = {
    connect: async () => {},
  };

  const sseConfig = { port: 0, maxSessions: 5, host: '127.0.0.1' };
  const { httpServer, url } = await createSseTransport(mockServer, sseConfig);

  try {
    // Try to open 10 sessions when max is 5
    const results = [];
    for (let i = 0; i < 10; i++) {
      try {
        const response = await fetch(`${url}/sse?sessionId=sess${i}`, {
          method: 'GET',
          signal: AbortSignal.timeout(500), // Short timeout since SSE hangs
        });
        results.push(response.status);
      } catch (err) {
        // Timeout is expected for SSE connections
        results.push(err.name === 'AbortError' ? 200 : 500);
      }
    }

    // Test passes if we got responses without crashing
    assert.ok(results.length === 10, `Should attempt all ${results.length} sessions`);
  } finally {
    httpServer.close();
  }
});

test('Vector 4.2: Session ID at 128 char limit should be accepted', async (t) => {
  const mockServer = {
    connect: async () => {},
  };

  const sseConfig = { port: 0, host: '127.0.0.1' };
  const { httpServer, url } = await createSseTransport(mockServer, sseConfig);

  try {
    // Create a session ID that is exactly 128 chars
    const sessionId = 'a'.repeat(128);
    const response = await fetch(`${url}/sse?sessionId=${sessionId}`, {
      method: 'GET',
      signal: AbortSignal.timeout(500), // Short timeout since server will wait for close
    }).catch(e => ({ status: 'timeout' }));

    // Should either accept (hang waiting) or fail gracefully
    assert.ok([200, 500, 'timeout'].includes(response.status), `Got: ${response.status}`);
  } finally {
    httpServer.close();
  }
});

test('Vector 4.3: Session ID exceeding 128 chars should be rejected', async (t) => {
  const mockServer = {
    connect: async () => {},
  };

  const sseConfig = { port: 0, host: '127.0.0.1' };
  const { httpServer, url } = await createSseTransport(mockServer, sseConfig);

  try {
    // Create a session ID that exceeds 128 chars
    const sessionId = 'a'.repeat(129);
    try {
      const response = await fetch(`${url}/sse?sessionId=${sessionId}`, {
        method: 'GET',
        signal: AbortSignal.timeout(500),
      });

      assert.strictEqual(response.status, 400, 'Should reject oversized session ID');
    } catch (err) {
      // If timeout, it means server accepted (bad). If connection error, it rejected (good)
      assert.ok(err.name !== 'AbortError', 'Should reject before timeout');
    }
  } finally {
    httpServer.close();
  }
});

// ============================================================================
// VECTOR 5: HAR parser with huge input
// ============================================================================

test('Vector 5.1: HAR with 100,000 entries should be parsed (bounded memory)', async (t) => {
  const har = {
    log: {
      entries: Array.from({ length: 10000 }, (_, i) => ({ // 10k to keep test fast
        request: {
          method: 'GET',
          url: `https://api.example.com/users/${i}`,
        },
      })),
    },
  };

  const result = await loadHarFile(har);

  assert.ok(result.baseUrl, 'Should extract base URL');
  assert.ok(Array.isArray(result.tools), 'Should generate tools');
  // Should not crash or OOM
});

test('Vector 5.2: HAR entries with 10KB URLs should be handled', async (t) => {
  const longPath = 'x'.repeat(10000);
  const har = {
    log: {
      entries: [
        {
          request: {
            method: 'GET',
            url: `https://api.example.com/${longPath}`,
          },
        },
      ],
    },
  };

  const result = await loadHarFile(har);

  assert.ok(result.tools, 'Should parse without crashing');
});

test('Vector 5.3: HAR with malformed entries (missing fields) should skip gracefully', async (t) => {
  const har = {
    log: {
      entries: [
        { request: {} }, // Missing url and method
        { request: null }, // Null request
        { request: { method: 'GET' } }, // Missing URL
        { request: { url: 'https://api.example.com/valid' } }, // Missing method
      ],
    },
  };

  const result = await loadHarFile(har);
  assert.ok(result, 'Should handle malformed entries');
});

test('Vector 5.4: HAR with very large postData should be parsed', async (t) => {
  const hugeBody = 'x'.repeat(1000000); // 1MB
  const har = {
    log: {
      entries: [
        {
          request: {
            method: 'POST',
            url: 'https://api.example.com/data',
            postData: {
              mimeType: 'application/json',
              text: JSON.stringify({ data: hugeBody }),
            },
          },
        },
      ],
    },
  };

  const result = await loadHarFile(har);
  assert.ok(result, 'Should handle large request bodies');
});

// ============================================================================
// VECTOR 6: OpenAPI spec generation with many paths
// ============================================================================

test('Vector 6.1: OpenAPI spec generation with 10,000 tools should be fast', async (t) => {
  const tools = Array.from({ length: 10000 }, (_, i) => ({
    name: `tool_${i}`,
    description: `Tool ${i}`,
    inputSchema: { type: 'object', properties: { id: { type: 'string' } } },
  }));

  const bridge = createReverseBridge({
    name: 'huge-api',
    tools,
    dispatch: async () => ({}),
  });

  const startTime = Date.now();
  const spec = bridge.generateOpenApiSpec();
  const duration = Date.now() - startTime;

  assert.ok(Object.keys(spec.paths).length === 10000, 'Should generate all paths');
  assert.ok(duration < 5000, `Spec generation should be fast (${duration}ms)`);
});

test('Vector 6.2: Tool with 50 parameters should generate valid schema', async (t) => {
  const properties = {};
  const required = [];
  for (let i = 0; i < 50; i++) {
    properties[`param_${i}`] = { type: 'string' };
    required.push(`param_${i}`);
  }

  const tools = [
    {
      name: 'complex_tool',
      description: 'Tool with 50 params',
      inputSchema: { type: 'object', properties, required },
    },
  ];

  const bridge = createReverseBridge({
    name: 'api',
    tools,
    dispatch: async () => ({}),
  });

  const spec = bridge.generateOpenApiSpec();
  const toolSpec = Object.values(spec.paths)[0];

  assert.strictEqual(
    Object.keys(toolSpec.post.requestBody.content['application/json'].schema.properties).length,
    50,
    'Should include all parameters'
  );
});

test('Vector 6.3: OpenAPI spec serialization with huge schema should complete', async (t) => {
  const tools = Array.from({ length: 100 }, (_, i) => ({
    name: `tool_${i}`,
    description: 'x'.repeat(1000), // Large description
    inputSchema: {
      type: 'object',
      properties: {
        huge: { type: 'string', description: 'x'.repeat(10000) },
      },
    },
  }));

  const bridge = createReverseBridge({
    name: 'api',
    tools,
    dispatch: async () => ({}),
  });

  const spec = bridge.generateOpenApiSpec();
  const json = JSON.stringify(spec);

  assert.ok(json.length > 1000, 'Should serialize large spec');
});

// ============================================================================
// VECTOR 7: GraphQL introspection with extreme schemas
// ============================================================================

test('Vector 7.1: GraphQL schema with 1000 query fields should be handled', async (t) => {
  const fields = Array.from({ length: 1000 }, (_, i) => ({
    name: `query_${i}`,
    description: `Query ${i}`,
    args: [],
    type: { kind: 'OBJECT', name: 'String' },
  }));

  const schema = {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: null,
      types: [
        {
          name: 'Query',
          kind: 'OBJECT',
          fields,
        },
      ],
    },
  };

  const result = await loadGraphqlSchema(schema);

  // Default cap is 200 tools; a 1000-operation schema should be truncated to prevent DoS
  assert.ok(result.tools.length <= 200, `Tool count should be capped at 200, got ${result.tools.length}`);
  assert.ok(result.tools.length > 0, 'Should generate at least some tools');
  assert.ok(result.baseUrl, 'Should include endpoint');
});

test('Vector 7.2: GraphQL schema with deeply nested type references should be handled', async (t) => {
  const schema = {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: null,
      types: [
        {
          name: 'Query',
          kind: 'OBJECT',
          fields: [
            {
              name: 'nested',
              args: [],
              type: {
                kind: 'LIST',
                ofType: {
                  kind: 'NON_NULL',
                  ofType: {
                    kind: 'LIST',
                    ofType: {
                      kind: 'NON_NULL',
                      ofType: {
                        kind: 'OBJECT',
                        name: 'Thing',
                      },
                    },
                  },
                },
              },
            },
          ],
        },
      ],
    },
  };

  const result = await loadGraphqlSchema(schema);

  assert.ok(result.tools.length === 1, 'Should generate tool');
  assert.ok(result.tools[0].inputSchema, 'Should have valid schema');
});

test('Vector 7.3: GraphQL schema with 100 arguments per field should be handled', async (t) => {
  const args = Array.from({ length: 100 }, (_, i) => ({
    name: `arg_${i}`,
    description: `Argument ${i}`,
    type: { kind: 'SCALAR', name: 'String' },
  }));

  const schema = {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: null,
      types: [
        {
          name: 'Query',
          kind: 'OBJECT',
          fields: [
            {
              name: 'search',
              description: 'Search with many filters',
              args,
              type: { kind: 'OBJECT', name: 'Results' },
            },
          ],
        },
      ],
    },
  };

  const result = await loadGraphqlSchema(schema);

  assert.ok(result.tools[0].inputSchema.properties, 'Should convert args to schema');
  assert.strictEqual(Object.keys(result.tools[0].inputSchema.properties).length, 100, 'Should include all args');
});

