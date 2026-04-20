/**
 * Stress-test scenarios for 40mcp.
 *
 * Each scenario is an async function that returns a result object with:
 *   { wallMs, rssStart, rssEnd, latency, statusCounts, errors, notes }
 *
 * Scenarios run sequentially so RSS deltas are meaningful and ports don't
 * collide. Each scenario stands up its own server instance, drives load,
 * then tears the server down cleanly.
 */

import { performance } from 'node:perf_hooks';
import { createHmac, randomBytes } from 'node:crypto';
import { writeFile, unlink, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createReverseBridge } from '../../src/reverse/server.js';
import { createWebhookListener } from '../../src/webhook/listener.js';
import { validateToolArgs } from '../../src/bridge.js';
import { loadOpenApiSpec } from '../../src/openapi.js';

import { drive, summarize, rssMiB, httpPost, httpGet, makeAgent, sleep } from './harness.mjs';

const LOOPBACK = '127.0.0.1';

/**
 * Pick a random ephemeral port in the 30000–39999 range. Avoids collisions
 * with common dev services and leaves the kernel picking the exact slot
 * via `port: 0` would be nicer, but the reverse/webhook factories take
 * a fixed port and the Node http server's 'listening' event is the only
 * way to learn the bound port — we just scan until one binds.
 */
async function pickPort() {
  return 30000 + Math.floor(Math.random() * 10000);
}

/**
 * Start a 40mcp factory handle (returned by createReverseBridge /
 * createWebhookListener). Both factories expose `.start()` which resolves
 * to `{ httpServer, url }`. We extract the bound port from httpServer.address()
 * so scenarios that need to issue requests know where to send them.
 */
async function startHandle(handle, timeoutMs = 5000) {
  const result = await Promise.race([
    handle.start(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('listen timeout')), timeoutMs)),
  ]);
  const addr = result.httpServer.address();
  return { httpServer: result.httpServer, url: result.url, port: addr.port };
}

/** Close a server promise-style. */
function closeServer(server) {
  return new Promise((resolve) => {
    if (!server || !server.close) return resolve();
    // Destroy any lingering keep-alive sockets so close() resolves promptly.
    if (server.closeAllConnections) server.closeAllConnections();
    server.close(() => resolve());
  });
}

// ─── 1. Reverse bridge: happy-path HTTP → MCP tool dispatch ─────────────

export async function reverseBridgeHappyPath({ total = 10000, concurrency = 64 } = {}) {
  let dispatchCount = 0;

  const handle = createReverseBridge({
    name: 'stress-reverse',
    tools: [
      {
        name: 'echo',
        description: 'Echo args.',
        inputSchema: {
          type: 'object',
          properties: { msg: { type: 'string' } },
          required: ['msg'],
        },
      },
    ],
    // Synchronous dispatch — returns a canned result. We're benchmarking
    // the bridge's HTTP + validation + envelope-stripping layer, not the
    // upstream API roundtrip.
    dispatch: async (name, args) => {
      dispatchCount += 1;
      return { echoed: args.msg, at: dispatchCount };
    },
    port: await pickPort(),
  });

  const { httpServer, port } = await startHandle(handle);

  const agent = makeAgent(concurrency);
  const body = JSON.stringify({ args: { msg: 'hello-world' } });
  const rssStart = rssMiB();
  const t0 = performance.now();

  const { latencies, errors, statusCounts, bytes } = await drive({
    total,
    concurrency,
    task: () => httpPost({ agent, host: LOOPBACK, port, path: '/api/tools/echo', body }),
  });

  const wallMs = performance.now() - t0;
  agent.destroy();
  await closeServer(httpServer);

  return {
    wallMs,
    rssStart,
    rssEnd: rssMiB(),
    latency: summarize(latencies),
    statusCounts,
    errors,
    notes: `bytesReceived=${bytes}, dispatches=${dispatchCount}`,
  };
}

// ─── 2. Reverse bridge: input validation under load ────────────────────

export async function reverseBridgeValidation({ total = 5000, concurrency = 64 } = {}) {
  const handle = createReverseBridge({
    name: 'stress-validation',
    tools: [
      {
        name: 'typed',
        inputSchema: {
          type: 'object',
          properties: {
            count: { type: 'integer' },
            label: { type: 'string' },
            active: { type: 'boolean' },
          },
          required: ['count', 'label'],
        },
      },
    ],
    dispatch: async () => ({ ok: true }),
    port: await pickPort(),
  });
  const { httpServer, port } = await startHandle(handle);

  const agent = makeAgent(concurrency);
  // Mix of valid + each kind of invalid body. The bridge must reject
  // NaN, prototype pollution, reserved envelope keys, and type mismatches.
  const payloads = [
    JSON.stringify({ args: { count: 42, label: 'ok' } }),                 // valid
    JSON.stringify({ args: { count: 'not-an-int', label: 'x' } }),       // bad type
    JSON.stringify({ args: { count: 5 } }),                              // missing required
    JSON.stringify({ args: { count: Number.NaN, label: 'x' } }),         // NaN numeric (becomes null in JSON)
    JSON.stringify({ args: { count: 1, label: 'x', __proto__: { polluted: true } } }), // proto
    JSON.stringify({ args: { count: 1, label: 'x', _tenant: 'evil' } }), // reserved
  ];

  const rssStart = rssMiB();
  const t0 = performance.now();

  const { latencies, errors, statusCounts } = await drive({
    total,
    concurrency,
    task: (i) => httpPost({
      agent, host: LOOPBACK, port, path: '/api/tools/typed',
      body: payloads[i % payloads.length],
    }),
  });

  const wallMs = performance.now() - t0;
  agent.destroy();
  await closeServer(httpServer);

  return {
    wallMs,
    rssStart,
    rssEnd: rssMiB(),
    latency: summarize(latencies),
    statusCounts,
    errors,
    // errors here are expected — the important invariant is that every
    // malformed request got a 400/422 and not a 500 or a hang.
    notes: 'Rejections are expected; counted as "errors" per drive() default. Look at status mix.',
  };
}

// ─── 3. Reverse bridge: large payload (response-shaping downstream) ───

export async function reverseBridgeLargePayload({ total = 500, concurrency = 16 } = {}) {
  // Build a ~64 KiB canned response once, reuse it across dispatches.
  const bigItem = { id: 0, desc: 'x'.repeat(256), tags: Array.from({ length: 8 }, () => 'tag') };
  const bigResult = Array.from({ length: 200 }, (_, i) => ({ ...bigItem, id: i }));

  const handle = createReverseBridge({
    name: 'stress-large',
    tools: [{ name: 'big', inputSchema: { type: 'object', properties: {} } }],
    dispatch: async () => bigResult,
    port: await pickPort(),
  });
  const { httpServer, port } = await startHandle(handle);

  const agent = makeAgent(concurrency);
  const body = JSON.stringify({ args: {} });
  const rssStart = rssMiB();
  const t0 = performance.now();

  const { latencies, errors, statusCounts, bytes } = await drive({
    total,
    concurrency,
    task: () => httpPost({ agent, host: LOOPBACK, port, path: '/api/tools/big', body }),
  });

  const wallMs = performance.now() - t0;
  agent.destroy();
  await closeServer(httpServer);

  return {
    wallMs,
    rssStart,
    rssEnd: rssMiB(),
    latency: summarize(latencies),
    statusCounts,
    errors,
    notes: `total bytes received=${bytes} (≈${(bytes / 1024 / 1024).toFixed(1)}MiB)`,
  };
}

// ─── 4. Webhook HMAC sync dispatch (the hot path through validateSecret) ─

export async function webhookHmacSync({ total = 5000, concurrency = 32 } = {}) {
  const secretEnv = '__STRESS_WEBHOOK_SECRET__';
  process.env[secretEnv] = 'super-secret-value';
  let dispatched = 0;

  const handle = createWebhookListener({
    name: 'stress-webhook',
    port: await pickPort(),
    host: LOOPBACK,
    dispatch: async () => {
      dispatched += 1;
      return { ok: true };
    },
    routes: [
      {
        path: '/hooks/stress',
        tool: 'my_tool',
        response: 'sync',
        secret: { type: 'hmac', envVar: secretEnv, header: 'x-sig', replayWindow: false },
      },
    ],
    maxInFlightPerRoute: 1000,
    maxInFlightGlobal: 2000,
  });
  const { httpServer, port } = await startHandle(handle);

  const agent = makeAgent(concurrency);
  const rssStart = rssMiB();
  const t0 = performance.now();

  const { latencies, errors, statusCounts } = await drive({
    total,
    concurrency,
    task: (i) => {
      const body = JSON.stringify({ event: 'push', n: i });
      const sig = 'sha256=' + createHmac('sha256', 'super-secret-value').update(body).digest('hex');
      return httpPost({
        agent, host: LOOPBACK, port, path: '/hooks/stress',
        body, headers: { 'x-sig': sig },
      });
    },
  });

  const wallMs = performance.now() - t0;
  agent.destroy();
  await closeServer(httpServer);
  delete process.env[secretEnv];

  return {
    wallMs,
    rssStart,
    rssEnd: rssMiB(),
    latency: summarize(latencies),
    statusCounts,
    errors,
    notes: `dispatches=${dispatched}`,
  };
}

// ─── 5. Webhook HMAC failure (tampered body) ───────────────────────────

export async function webhookHmacFailure({ total = 3000, concurrency = 32 } = {}) {
  const secretEnv = '__STRESS_WEBHOOK_SECRET_FAIL__';
  process.env[secretEnv] = 'correct-secret';
  let dispatched = 0;

  const handle = createWebhookListener({
    name: 'stress-webhook-fail',
    port: await pickPort(),
    host: LOOPBACK,
    dispatch: async () => {
      dispatched += 1;
      return { ok: true };
    },
    routes: [
      {
        path: '/hooks/stress',
        tool: 'my_tool',
        response: 'sync',
        secret: { type: 'hmac', envVar: secretEnv, header: 'x-sig', replayWindow: false },
      },
    ],
  });
  const { httpServer, port } = await startHandle(handle);

  const agent = makeAgent(concurrency);
  const rssStart = rssMiB();
  const t0 = performance.now();

  const { latencies, errors, statusCounts } = await drive({
    total,
    concurrency,
    task: (i) => {
      const body = JSON.stringify({ event: 'push', n: i });
      // Sign with the WRONG secret — every request must be rejected 401.
      const sig = createHmac('sha256', 'wrong-secret').update(body).digest('hex');
      return httpPost({
        agent, host: LOOPBACK, port, path: '/hooks/stress',
        body, headers: { 'x-sig': sig },
      });
    },
  });

  const wallMs = performance.now() - t0;
  agent.destroy();
  await closeServer(httpServer);
  delete process.env[secretEnv];

  return {
    wallMs,
    rssStart,
    rssEnd: rssMiB(),
    latency: summarize(latencies),
    statusCounts,
    errors,
    // Every request is expected to fail with 401. This is the "attack load"
    // scenario — ensures HMAC failure path is constant-time-enough and
    // doesn't leak memory or back up the event loop.
    notes: `expected all 401, dispatches=${dispatched} (must be 0)`,
  };
}

// ─── 6. validateToolArgs microbenchmark ────────────────────────────────

export async function validateArgsMicrobench({ iterations = 500_000 } = {}) {
  // Representative schema: the kind of thing a REST-over-MCP bridge gets
  // from OpenAPI for an endpoint like POST /users.
  const schema = {
    type: 'object',
    properties: {
      id: { type: 'integer' },
      name: { type: 'string' },
      email: { type: 'string' },
      age: { type: 'integer' },
      active: { type: 'boolean' },
      tags: { type: 'array' },
      prefs: { type: 'object' },
    },
    required: ['id', 'name', 'email'],
  };
  const goodArgs = { id: 42, name: 'alice', email: 'a@ex.com', age: 30, active: true, tags: ['a'], prefs: {} };
  const badArgs = { id: 'not-int', name: 'alice', email: 'a@ex.com' };

  const rssStart = rssMiB();
  const t0 = performance.now();
  let pass = 0;
  let fail = 0;
  for (let i = 0; i < iterations; i += 1) {
    const r = validateToolArgs(i & 15 ? goodArgs : badArgs, schema);
    if (r === null) pass += 1;
    else fail += 1;
  }
  const wallMs = performance.now() - t0;
  const rssEnd = rssMiB();

  // Synthesize a latency summary so it slots into the same report format.
  const mean = wallMs / iterations;
  return {
    wallMs,
    rssStart,
    rssEnd,
    latency: { count: iterations, min: 0, mean: Math.round(mean * 1000) / 1000, p50: 0, p95: 0, p99: 0, max: 0 },
    statusCounts: { pass, fail },
    errors: 0,
    notes: `mean ${Math.round((iterations / (wallMs / 1000)))} ops/sec; pass=${pass} fail=${fail}`,
  };
}

// ─── 7. OpenAPI loader with a large spec ───────────────────────────────

export async function openApiLargeSpec({ toolCount = 2000 } = {}) {
  const dir = await mkdtemp(join(tmpdir(), '40mcp-stress-'));
  const specPath = join(dir, `big-spec-${randomBytes(4).toString('hex')}.json`);

  // Build a synthetic OpenAPI 3.0 spec with N distinct operations.
  const paths = {};
  for (let i = 0; i < toolCount; i += 1) {
    paths[`/res${i}/{id}`] = {
      get: {
        operationId: `getRes${i}`,
        summary: `Read resource ${i}`,
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'verbose', in: 'query', schema: { type: 'boolean' } },
        ],
        responses: {
          200: {
            description: 'ok',
            content: {
              'application/json': {
                schema: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' } } },
              },
            },
          },
        },
      },
    };
  }

  const spec = {
    openapi: '3.0.0',
    info: { title: 'stress-spec', version: '1.0.0' },
    servers: [{ url: 'https://example.test' }],
    paths,
  };

  await writeFile(specPath, JSON.stringify(spec));

  const rssStart = rssMiB();
  const t0 = performance.now();
  const loaded = await loadOpenApiSpec(specPath);
  const wallMs = performance.now() - t0;
  const rssEnd = rssMiB();

  await unlink(specPath).catch(() => {});

  const latency = {
    count: 1,
    min: Math.round(wallMs * 100) / 100,
    mean: Math.round(wallMs * 100) / 100,
    p50: Math.round(wallMs * 100) / 100,
    p95: Math.round(wallMs * 100) / 100,
    p99: Math.round(wallMs * 100) / 100,
    max: Math.round(wallMs * 100) / 100,
  };
  return {
    wallMs,
    rssStart,
    rssEnd,
    latency,
    statusCounts: { loaded: 1 },
    errors: 0,
    notes: `input tools=${toolCount}, parsed tools=${loaded?.tools?.length ?? '?'}, ms/tool=${(wallMs / toolCount).toFixed(3)}`,
  };
}

// ─── 8. Reverse bridge auth rejection under load ──────────────────────

export async function reverseBridgeAuthRejection({ total = 4000, concurrency = 64 } = {}) {
  const tokenEnv = '__STRESS_REVERSE_TOKEN__';
  process.env[tokenEnv] = 'the-real-token';

  const handle = createReverseBridge({
    name: 'stress-auth',
    tools: [{ name: 'echo', inputSchema: { type: 'object', properties: { msg: { type: 'string' } } } }],
    dispatch: async () => ({ ok: true }),
    port: await pickPort(),
    auth: { envVar: tokenEnv, header: 'x-stress-token' },
  });
  const { httpServer, port } = await startHandle(handle);

  const agent = makeAgent(concurrency);
  const body = JSON.stringify({ args: { msg: 'x' } });
  const rssStart = rssMiB();
  const t0 = performance.now();

  const { latencies, errors, statusCounts } = await drive({
    total,
    concurrency,
    task: (i) => httpPost({
      agent, host: LOOPBACK, port, path: '/api/tools/echo', body,
      // Alternate between no token, wrong token, and wrong length
      headers: i % 3 === 0
        ? {}
        : i % 3 === 1
          ? { 'x-stress-token': 'wrong-token' }
          : { 'x-stress-token': 'x' },
    }),
  });

  const wallMs = performance.now() - t0;
  agent.destroy();
  await closeServer(httpServer);
  delete process.env[tokenEnv];

  return {
    wallMs,
    rssStart,
    rssEnd: rssMiB(),
    latency: summarize(latencies),
    statusCounts,
    errors,
    notes: 'expected all 401 (constant-time comparison path)',
  };
}
