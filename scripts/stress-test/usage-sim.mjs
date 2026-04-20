/**
 * Realistic-usage simulation for 40mcp.
 *
 * Simulates a mixed workload hitting a reverse bridge for a bounded
 * wall-clock duration, with a traffic mix that approximates what a
 * production bridge deployment would see:
 *
 *   60%  small GET-shaped lookups        (1–3 KB body,  2 KB response)
 *   20%  medium POST-shaped creates      (5 KB body,   5 KB response)
 *   10%  list-with-filter calls          (3 KB body,  40 KB response)
 *    5%  large reports                   (1 KB body, ~256 KB response)
 *    3%  invalid / client-bug retries    (malformed body, should 400)
 *    2%  unauthorized probes             (missing token, should 401)
 *
 * These are not bench rps targets — the simulation runs for a fixed
 * duration and reports what it actually saw so you can sanity-check
 * the mix, latency by class, and whether any request bucket leaked
 * 5xx / uncaught errors.
 */

import { performance } from 'node:perf_hooks';

import { createReverseBridge } from '../../src/reverse/server.js';
import { httpPost, makeAgent, summarize, rssMiB } from './harness.mjs';

const LOOPBACK = '127.0.0.1';

/** Workload mix — buckets must sum to 100. */
const DEFAULT_MIX = [
  { name: 'lookup_small',   weight: 60, kind: 'lookup',  auth: true,  valid: true },
  { name: 'create_medium',  weight: 20, kind: 'create',  auth: true,  valid: true },
  { name: 'list_filter',    weight: 10, kind: 'list',    auth: true,  valid: true },
  { name: 'report_large',   weight: 5,  kind: 'report',  auth: true,  valid: true },
  { name: 'client_error',   weight: 3,  kind: 'lookup',  auth: true,  valid: false },
  { name: 'unauth_probe',   weight: 2,  kind: 'lookup',  auth: false, valid: true },
];

/** Build a bucket lookup table so each iteration picks O(1). */
function buildRoulette(mix) {
  const table = [];
  for (const b of mix) {
    for (let i = 0; i < b.weight; i += 1) table.push(b);
  }
  return table;
}

/**
 * Stand up a reverse bridge with 4 synthetic tools that mirror the
 * four "kind" response profiles. Each tool returns a canned blob so
 * we can measure response-size impact on latency without any JSON
 * generation cost in the dispatch loop.
 */
async function startSim({ authToken }) {
  // Auth env var MUST be set before createReverseBridge so the factory
  // doesn't log an alarming "auth.envVar is not set" warning at startup.
  process.env.__USAGE_SIM_TOKEN__ = authToken;

  // Canned responses, pre-built once.
  const smallResult = { id: 'abc123', name: 'widget', qty: 42 };
  const mediumResult = Array.from({ length: 20 }, (_, i) => ({ id: i, label: `x${i}`, meta: { a: 1, b: 2 } }));
  const listResult = Array.from({ length: 150 }, (_, i) => ({
    id: i, title: `t${i}`, desc: 'y'.repeat(64), tags: ['a', 'b', 'c'],
  }));
  const reportResult = {
    summary: Array.from({ length: 200 }, (_, i) => ({ id: i, val: Math.random() })),
    details: Array.from({ length: 200 }, () => 'q'.repeat(512)),
  };

  const handle = createReverseBridge({
    name: 'usage-sim',
    tools: [
      { name: 'lookup', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
      { name: 'create', inputSchema: { type: 'object', properties: { name: { type: 'string' }, payload: { type: 'object' } }, required: ['name'] } },
      { name: 'list',   inputSchema: { type: 'object', properties: { filter: { type: 'object' } } } },
      { name: 'report', inputSchema: { type: 'object', properties: { range: { type: 'string' } } } },
    ],
    dispatch: async (name /*, args */) => {
      switch (name) {
        case 'lookup':  return smallResult;
        case 'create':  return mediumResult;
        case 'list':    return listResult;
        case 'report':  return reportResult;
        default: return { ok: true };
      }
    },
    port: 34500 + Math.floor(Math.random() * 1500),
    auth: { envVar: '__USAGE_SIM_TOKEN__', header: 'x-token' },
  });
  const { httpServer } = await handle.start();
  const port = httpServer.address().port;
  return { httpServer, port };
}

/** Build a request body + path + headers for a given bucket. */
function buildRequest(bucket, iteration, authToken) {
  const base = { headers: { 'Content-Type': 'application/json' } };
  if (bucket.auth) base.headers['x-token'] = authToken;

  switch (bucket.kind) {
    case 'lookup':
      base.path = '/api/tools/lookup';
      base.body = bucket.valid
        ? JSON.stringify({ args: { id: `rec-${iteration}` } })
        : '{"args":{"wrong-shape":true}}'; // missing required "id"
      break;
    case 'create':
      base.path = '/api/tools/create';
      base.body = JSON.stringify({
        args: {
          name: `item-${iteration}`,
          payload: { when: Date.now(), data: 'x'.repeat(256), nested: { a: 1, b: [1, 2, 3] } },
        },
      });
      break;
    case 'list':
      base.path = '/api/tools/list';
      base.body = JSON.stringify({ args: { filter: { status: 'active', tags: ['a', 'b'], pageSize: 50 } } });
      break;
    case 'report':
      base.path = '/api/tools/report';
      base.body = JSON.stringify({ args: { range: 'last-7-days' } });
      break;
    default:
      base.path = '/api/tools/lookup';
      base.body = '{"args":{"id":"x"}}';
  }
  return base;
}

/**
 * Run the simulation for `durationMs` with `concurrency` workers.
 */
export async function runUsageSim({ durationMs = 10_000, concurrency = 32, mix = DEFAULT_MIX } = {}) {
  const authToken = 'sim-token-' + Math.random().toString(36).slice(2, 10);
  const { httpServer, port } = await startSim({ authToken });
  const agent = makeAgent(concurrency);
  const roulette = buildRoulette(mix);

  // Per-bucket stats.
  const stats = Object.create(null);
  for (const b of mix) stats[b.name] = { count: 0, bytes: 0, latencies: [], errors: 0, statuses: {} };
  const overall = { count: 0, errors: 0, bytes: 0, statuses: {} };

  const rssStart = rssMiB();
  const t0 = performance.now();
  const deadline = t0 + durationMs;
  let iteration = 0;

  async function worker() {
    while (performance.now() < deadline) {
      const i = iteration++;
      const bucket = roulette[i % roulette.length];
      const req = buildRequest(bucket, i, authToken);
      const t1 = performance.now();
      try {
        const res = await httpPost({
          agent, host: LOOPBACK, port, path: req.path, headers: req.headers, body: req.body,
        });
        const dt = performance.now() - t1;
        const s = stats[bucket.name];
        s.count += 1;
        s.latencies.push(dt);
        s.bytes += res.bytes || 0;
        s.statuses[res.status] = (s.statuses[res.status] || 0) + 1;
        if (!res.ok) s.errors += 1;

        overall.count += 1;
        overall.statuses[res.status] = (overall.statuses[res.status] || 0) + 1;
        if (!res.ok) overall.errors += 1;
        overall.bytes += res.bytes || 0;
      } catch (err) {
        stats[bucket.name].errors += 1;
        overall.errors += 1;
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  const wallMs = performance.now() - t0;
  agent.destroy();
  await new Promise((r) => {
    httpServer.closeAllConnections?.();
    httpServer.close(() => r());
  });
  delete process.env.__USAGE_SIM_TOKEN__;

  // Finalize stats: attach percentiles, clean up latencies arrays.
  const perBucket = [];
  for (const b of mix) {
    const s = stats[b.name];
    perBucket.push({
      bucket: b.name,
      weight: b.weight,
      count: s.count,
      actual_pct: overall.count > 0 ? Math.round((s.count / overall.count) * 1000) / 10 : 0,
      latency_ms: summarize(s.latencies),
      bytes: s.bytes,
      errors: s.errors,
      statuses: s.statuses,
    });
  }

  return {
    wallMs,
    rssStart,
    rssEnd: rssMiB(),
    concurrency,
    overall: {
      count: overall.count,
      rps: Math.round((overall.count / (wallMs / 1000)) * 10) / 10,
      errors: overall.errors,
      bytes: overall.bytes,
      statuses: overall.statuses,
    },
    per_bucket: perBucket,
  };
}
