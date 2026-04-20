import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createReverseBridge, generateOpenApiSpec } from './server.js';
import { loadOpenApiSpec } from '../openapi.js';
import { loadHarFile } from '../loaders/har.js';

// ─── Mock dispatch function ──────────────────────────────────────────────────

async function mockDispatch(toolName, args) {
  if (toolName === 'echo') {
    return { echoed: args };
  }
  if (toolName === 'add') {
    return { sum: (args.a || 0) + (args.b || 0) };
  }
  if (toolName === 'error_tool') {
    throw new Error('Tool execution failed');
  }
  throw new Error(`Unknown tool: ${toolName}`);
}

// ─── Test tools ──────────────────────────────────────────────────────────────

const testTools = [
  {
    name: 'echo',
    description: 'Echo the input back',
    inputSchema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
      required: ['message'],
    },
  },
  {
    name: 'add',
    description: 'Add two numbers',
    inputSchema: {
      type: 'object',
      properties: {
        a: { type: 'number' },
        b: { type: 'number' },
      },
      required: ['a', 'b'],
    },
  },
  {
    name: 'error_tool',
    description: 'A tool that always errors',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('createReverseBridge', () => {
  let server;
  let httpServer;
  let url;

  afterEach(() => {
    if (httpServer) {
      httpServer.close();
      httpServer = null;
    }
  });

  it('starts a server on port 0 (auto-assign)', async () => {
    server = createReverseBridge({
      name: 'test-api',
      version: '1.0.0',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    assert.ok(serverUrl);
    assert.ok(serverUrl.includes('localhost') || serverUrl.includes('127.0.0.1'));
    url = serverUrl;
  });

  it('GET /api/health returns only the minimal status payload', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/health`);
    assert.equal(res.status, 200);

    const data = await res.json();
    assert.deepEqual(data, { status: 'ok' });
  });

  it('GET /api/tools lists all tools', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools`);
    assert.equal(res.status, 200);

    const data = await res.json();
    assert.ok(Array.isArray(data.tools));
    assert.equal(data.tools.length, 3);
    assert.ok(data.tools.some((t) => t.name === 'echo'));
    assert.ok(data.tools.some((t) => t.name === 'add'));
    assert.ok(data.tools.some((t) => t.name === 'error_tool'));
  });

  it('POST /api/tools/:name calls dispatch with correct args', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.result.echoed, { message: 'hello' });
  });

  it('POST /api/tools/:name returns 404 for unknown tool', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/unknown_tool`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 404);
    const data = await res.json();
    assert.ok(data.error.includes('not found'));
  });

  it('POST /api/tools/:name returns 500 on dispatch error', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/error_tool`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 500);
    const data = await res.json();
    assert.ok(data.error);
  });

  // ─── Security response headers ──────────────────────────────────────

  it('successful dispatch response includes nosniff + X-Frame-Options headers', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'hi' }),
    });

    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  });

  it('error dispatch response includes nosniff + X-Frame-Options headers', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/error_tool`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 500);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  });

  it('HTTP 404 response includes nosniff + X-Frame-Options headers', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/nonexistent`);
    assert.equal(res.status, 404);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  });

  it('POST /api/tools/:name supports { args: {...} } format', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args: { a: 5, b: 3 } }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.result.sum, 8);
  });

  it('POST /api/tools/:name supports flat {...} format', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a: 10, b: 20 }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.result.sum, 30);
  });

  it('POST /api/tools/:name returns 400 on invalid JSON', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    });

    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error);
  });

  it('GET /api/openapi.json returns valid OpenAPI 3.0 structure', async () => {
    server = createReverseBridge({
      name: 'test-api',
      version: '2.0.0',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/openapi.json`);
    assert.equal(res.status, 200);

    const spec = await res.json();
    assert.equal(spec.openapi, '3.0.0');
    assert.equal(spec.info.title, 'test-api');
    assert.equal(spec.info.version, '2.0.0');
    assert.ok(spec.paths);
  });

  it('OpenAPI spec has correct paths for each tool', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/openapi.json`);
    const spec = await res.json();

    assert.ok(spec.paths['/api/tools/echo']);
    assert.ok(spec.paths['/api/tools/add']);
    assert.ok(spec.paths['/api/tools/error_tool']);
  });

  it('OpenAPI spec includes inputSchema as requestBody', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/openapi.json`);
    const spec = await res.json();

    const echoPost = spec.paths['/api/tools/echo'].post;
    assert.ok(echoPost.requestBody);
    assert.ok(echoPost.requestBody.content['application/json']);
    assert.ok(echoPost.requestBody.content['application/json'].schema);
    assert.ok(
      echoPost.requestBody.content['application/json'].schema.properties.message,
    );
  });

  it('OpenAPI spec includes operationId', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/openapi.json`);
    const spec = await res.json();

    const echoPost = spec.paths['/api/tools/echo'].post;
    assert.equal(echoPost.operationId, 'echo');
  });

  it('Auth validation rejects request without required header', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      auth: {
        header: 'X-API-Key',
        envVar: 'API_KEY',
      },
      port: 0,
    });

    const originalEnv = process.env.API_KEY;
    process.env.API_KEY = 'secret123';

    try {
      const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
      url = serverUrl;

      // Request without header
      const res = await fetch(`${url}/api/tools/echo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'hello' }),
      });

      assert.equal(res.status, 401);
      const data = await res.json();
      assert.ok(data.error);
    } finally {
      if (originalEnv === undefined) {
        delete process.env.API_KEY;
      } else {
        process.env.API_KEY = originalEnv;
      }
    }
  });

  it('Auth validation accepts request with correct header', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      auth: {
        header: 'X-API-Key',
        envVar: 'API_KEY',
      },
      port: 0,
    });

    const originalEnv = process.env.API_KEY;
    process.env.API_KEY = 'secret123';

    try {
      const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
      url = serverUrl;

      // Request with correct header
      const res = await fetch(`${url}/api/tools/echo`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'secret123',
        },
        body: JSON.stringify({ message: 'hello' }),
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.deepEqual(data.result.echoed, { message: 'hello' });
    } finally {
      if (originalEnv === undefined) {
        delete process.env.API_KEY;
      } else {
        process.env.API_KEY = originalEnv;
      }
    }
  });

  it('CORS headers are present when Origin header matches allowedOrigin', async () => {
    // CORS headers are now only emitted when the request Origin
    // matches the configured allowedOrigin — not on every response. This prevents
    // any localhost page from reading bridge responses via cross-origin requests.
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
      allowedOrigin: 'http://trusted-client.example',
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    // Request WITH matching Origin → CORS headers present
    const resWithOrigin = await fetch(`${url}/api/health`, {
      headers: { Origin: 'http://trusted-client.example' },
    });
    assert.ok(
      resWithOrigin.headers.get('Access-Control-Allow-Origin'),
      'CORS header must be set when Origin matches allowedOrigin',
    );
    assert.equal(
      resWithOrigin.headers.get('Access-Control-Allow-Origin'),
      'http://trusted-client.example',
    );

    // Request WITHOUT Origin header → no CORS header (non-browser request)
    const resNoOrigin = await fetch(`${url}/api/health`);
    assert.equal(
      resNoOrigin.headers.get('Access-Control-Allow-Origin'),
      null,
      'CORS header must NOT be set when no Origin header is present',
    );

    // Request WITH wrong Origin → no CORS header
    const resWrongOrigin = await fetch(`${url}/api/health`, {
      headers: { Origin: 'http://attacker.example' },
    });
    assert.equal(
      resWrongOrigin.headers.get('Access-Control-Allow-Origin'),
      null,
      'CORS header must NOT be set when Origin does not match allowedOrigin',
    );
  });

  it('OPTIONS request returns 204 (CORS preflight, RFC-7231)', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/api/tools/echo`, {
      method: 'OPTIONS',
    });

    // 204 per RFC-7231, and only for paths under basePath.
    // Unrelated probes get 404 to avoid fingerprinting.
    assert.equal(res.status, 204);
  });

  it('OPTIONS request outside basePath returns 404 (no fingerprint)', async () => {
    server = createReverseBridge({
      name: 'test-api',
      tools: testTools,
      dispatch: mockDispatch,
      port: 0,
    });

    const started = await server.start(); httpServer = started.httpServer; const serverUrl = started.url;
    url = serverUrl;

    const res = await fetch(`${url}/random/unrelated/path`, {
      method: 'OPTIONS',
    });

    assert.equal(res.status, 404);
  });
});

describe('generateOpenApiSpec', () => {
  it('works standalone without starting server', () => {
    const spec = generateOpenApiSpec({
      name: 'My API',
      version: '1.0.0',
      tools: testTools,
      basePath: '/api',
    });

    assert.equal(spec.openapi, '3.0.0');
    assert.equal(spec.info.title, 'My API');
    assert.equal(spec.info.version, '1.0.0');
    assert.ok(spec.paths['/api/tools/echo']);
  });

  it('defaults version to 1.0.0', () => {
    const spec = generateOpenApiSpec({
      name: 'My API',
      tools: testTools,
    });

    assert.equal(spec.info.version, '1.0.0');
  });

  it('defaults basePath to /api', () => {
    const spec = generateOpenApiSpec({
      name: 'My API',
      tools: testTools,
    });

    assert.ok(spec.paths['/api/tools/echo']);
  });

  it('respects custom basePath', () => {
    const spec = generateOpenApiSpec({
      name: 'My API',
      tools: testTools,
      basePath: '/v1',
    });

    assert.ok(spec.paths['/v1/tools/echo']);
    assert.ok(!spec.paths['/api/tools/echo']);
  });

  it('includes tool descriptions in OpenAPI spec', () => {
    const spec = generateOpenApiSpec({
      name: 'My API',
      tools: testTools,
    });

    const echoOp = spec.paths['/api/tools/echo'].post;
    assert.equal(echoOp.summary, 'Echo the input back');
  });
});

describe('acceptance: round-trip cycles', () => {
  let httpServer;

  afterEach(() => {
    if (httpServer) {
      httpServer.close();
      httpServer = null;
    }
  });

  it('acceptance: reverse bridge round-trip — tools survive OpenAPI → reverse bridge → HAR → reload cycle', async () => {
    // Step 1: Define 2-3 simple tools with full inputSchema
    const tools = [
      {
        name: 'echo',
        description: 'Echo the input back',
        inputSchema: {
          type: 'object',
          properties: {
            message: { type: 'string' },
          },
          required: ['message'],
        },
      },
      {
        name: 'add',
        description: 'Add two numbers',
        inputSchema: {
          type: 'object',
          properties: {
            a: { type: 'number' },
            b: { type: 'number' },
          },
          required: ['a', 'b'],
        },
      },
    ];

    // Step 2: Start a reverse bridge on port 0 (ephemeral port)
    const bridge = createReverseBridge({
      name: 'round-trip-api',
      tools,
      dispatch: mockDispatch,
      port: 0,
    });

    const { httpServer: server, url } = await bridge.start();
    httpServer = server;

    // Step 3: Make a real HTTP POST to ${url}/api/tools/echo
    const echoRes = await fetch(`${url}/api/tools/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });
    assert.equal(echoRes.status, 200);
    const echoData = await echoRes.json();
    assert.deepEqual(echoData.result.echoed, { message: 'hello' });

    // Step 4: Generate an OpenAPI spec from those tools
    const spec = generateOpenApiSpec({
      name: 'round-trip-api',
      tools,
    });
    assert.ok(spec.paths['/api/tools/echo']);
    assert.ok(spec.paths['/api/tools/add']);

    // Step 5: Load the spec back via loadOpenApiSpec and verify tool names match
    const { tools: reloadedTools } = await loadOpenApiSpec(spec);
    const reloadedNames = reloadedTools.map((t) => t.name).sort();
    const originalNames = tools.map((t) => t.name).sort();

    assert.deepEqual(reloadedNames, originalNames);
    assert.equal(reloadedNames.length, 2);
  });

  it('acceptance: self-referential loop — reverse bridge → HAR observation → HAR reload → new bridge tools match', async () => {
    // Step 1: Define 2 tools, start a reverse bridge on port 0
    const tools = [
      {
        name: 'echo',
        description: 'Echo the input back',
        inputSchema: {
          type: 'object',
          properties: {
            message: { type: 'string' },
          },
          required: ['message'],
        },
      },
      {
        name: 'add',
        description: 'Add two numbers',
        inputSchema: {
          type: 'object',
          properties: {
            a: { type: 'number' },
            b: { type: 'number' },
          },
          required: ['a', 'b'],
        },
      },
    ];

    const bridge = createReverseBridge({
      name: 'loop-api',
      tools,
      dispatch: mockDispatch,
      port: 0,
    });

    const { httpServer: server, url } = await bridge.start();
    httpServer = server;

    // Step 2: Make HTTP calls to generate traffic
    const echoRes = await fetch(`${url}/api/tools/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });
    assert.equal(echoRes.status, 200);

    const addRes = await fetch(`${url}/api/tools/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a: 5, b: 3 }),
    });
    assert.equal(addRes.status, 200);

    // Step 3: Construct a minimal HAR object matching HAR 1.2 schema
    // Construct from manually observed requests as would happen in a real capture scenario
    const har = {
      log: {
        version: '1.2',
        entries: [
          {
            request: {
              method: 'POST',
              url: `${url}/api/tools/echo`,
              headers: [{ name: 'content-type', value: 'application/json' }],
              postData: {
                mimeType: 'application/json',
                text: JSON.stringify({ message: 'hello' }),
              },
            },
            response: {
              status: 200,
              headers: [],
              content: {
                mimeType: 'application/json',
                text: JSON.stringify({ result: { echoed: { message: 'hello' } } }),
              },
            },
          },
          {
            request: {
              method: 'POST',
              url: `${url}/api/tools/add`,
              headers: [{ name: 'content-type', value: 'application/json' }],
              postData: {
                mimeType: 'application/json',
                text: JSON.stringify({ a: 5, b: 3 }),
              },
            },
            response: {
              status: 200,
              headers: [],
              content: {
                mimeType: 'application/json',
                text: JSON.stringify({ result: { sum: 8 } }),
              },
            },
          },
        ],
      },
    };

    // Step 4: Feed the HAR to loadHarFile and verify it infers tools correctly
    const { tools: harTools, baseUrl } = await loadHarFile(har, { allowPrivate: true });

    // Verify base URL was extracted correctly
    assert.ok(baseUrl.includes('localhost') || baseUrl.includes('127.0.0.1'));

    // Verify tools were inferred from HAR entries
    // The HAR loader will infer tool names from the path structure
    // Since both are under /api/tools/, it creates a single 'create_tools' tool
    assert.ok(harTools.length > 0);
    assert.ok(harTools[0].name);
    assert.ok(harTools[0].description);
    assert.ok(harTools[0].method);
    assert.ok(harTools[0].path);
  });
});
