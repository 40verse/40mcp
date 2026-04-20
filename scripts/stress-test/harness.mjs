/**
 * Shared utilities for 40mcp stress tests.
 *
 * Provides:
 *   - Percentile/statistics helpers
 *   - A concurrent-load driver (N workers, bounded total requests)
 *   - A memory / wall-clock / latency collector
 *   - A human-readable + JSON scenario result formatter
 *
 * Deliberately zero-dependency — uses only node:http, node:crypto, and
 * node:perf_hooks so it can run in any container that has Node >= 18.
 */

import { performance } from 'node:perf_hooks';
import { request as httpRequest, Agent } from 'node:http';

/** Sleep `ms` milliseconds. */
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** RSS in MiB, rounded to 1 decimal. */
export function rssMiB() {
  return Math.round((process.memoryUsage().rss / 1024 / 1024) * 10) / 10;
}

/** Return {p50, p95, p99, max, min, mean} for an array of numbers (ms). */
export function summarize(samples) {
  if (samples.length === 0) {
    return { p50: 0, p95: 0, p99: 0, max: 0, min: 0, mean: 0, count: 0 };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const pct = (p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    count: sorted.length,
    min: round(sorted[0]),
    mean: round(sum / sorted.length),
    p50: round(pct(50)),
    p95: round(pct(95)),
    p99: round(pct(99)),
    max: round(sorted[sorted.length - 1]),
  };
}

const round = (n) => Math.round(n * 100) / 100;

/**
 * Drive N concurrent workers that each issue tasks from a shared pool.
 *
 * @param {object} opts
 * @param {number} opts.total - total number of iterations
 * @param {number} opts.concurrency - how many workers run in parallel
 * @param {(iteration:number)=>Promise<{ok:boolean, status?:number, bytes?:number}>} opts.task
 * @returns {Promise<{latencies:number[], errors:number, statusCounts:Record<string,number>, bytes:number}>}
 */
export async function drive({ total, concurrency, task }) {
  const latencies = [];
  const statusCounts = Object.create(null);
  let errors = 0;
  let bytes = 0;
  let next = 0;

  async function worker() {
    while (true) {
      const i = next++;
      if (i >= total) return;
      const t0 = performance.now();
      try {
        const res = await task(i);
        const dt = performance.now() - t0;
        latencies.push(dt);
        const key = String(res?.status ?? (res?.ok ? 'ok' : 'err'));
        statusCounts[key] = (statusCounts[key] || 0) + 1;
        if (!res?.ok) errors += 1;
        if (res?.bytes) bytes += res.bytes;
      } catch (err) {
        latencies.push(performance.now() - t0);
        errors += 1;
        statusCounts.exception = (statusCounts.exception || 0) + 1;
      }
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);
  return { latencies, errors, statusCounts, bytes };
}

/**
 * Shared keep-alive HTTP agent for load generation. A dedicated agent with
 * high maxSockets prevents socket exhaustion from tripping the harness itself.
 */
export function makeAgent(concurrency) {
  return new Agent({ keepAlive: true, maxSockets: concurrency + 8, maxFreeSockets: concurrency });
}

/**
 * Low-level HTTP POST with keep-alive. Returns {ok,status,bodyLen}.
 * Rejects only on network/parse errors; HTTP 4xx/5xx return ok:false.
 */
export function httpPost({ agent, host, port, path, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const buf = typeof body === 'string' ? Buffer.from(body) : body;
    const req = httpRequest(
      {
        agent,
        host,
        port,
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': buf ? buf.length : 0,
          ...headers,
        },
      },
      (res) => {
        let len = 0;
        res.on('data', (chunk) => {
          len += chunk.length;
        });
        res.on('end', () => {
          resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, bytes: len });
        });
      },
    );
    req.on('error', reject);
    if (buf) req.write(buf);
    req.end();
  });
}

/** GET variant for completeness. */
export function httpGet({ agent, host, port, path, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { agent, host, port, path, method: 'GET', headers },
      (res) => {
        let len = 0;
        res.on('data', (chunk) => {
          len += chunk.length;
        });
        res.on('end', () => {
          resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, bytes: len });
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/** Format a scenario result as a compact console banner. */
export function renderBanner(name, r) {
  const lat = r.latency || summarize(r.latencies || []);
  const rps = r.wallMs > 0 ? ((lat.count || 0) / (r.wallMs / 1000)).toFixed(1) : '—';
  const rssDelta = (r.rssEnd - r.rssStart).toFixed(1);
  const statuses = Object.entries(r.statusCounts || {})
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');
  return [
    `── ${name} ───────────────────────────────────`,
    `  ops=${lat.count}  wall=${r.wallMs.toFixed(0)}ms  rps=${rps}  errors=${r.errors || 0}`,
    `  latency ms: min=${lat.min}  p50=${lat.p50}  p95=${lat.p95}  p99=${lat.p99}  max=${lat.max}`,
    `  rss: start=${r.rssStart}MiB  end=${r.rssEnd}MiB  delta=${rssDelta}MiB`,
    statuses ? `  statuses: ${statuses}` : '',
  ]
    .filter(Boolean)
    .join('\n');
}

/** Normalize a scenario result for JSON output. */
export function normalizeResult(name, r) {
  const lat = r.latency || summarize(r.latencies || []);
  return {
    scenario: name,
    ops: lat.count,
    wall_ms: Math.round(r.wallMs),
    rps: r.wallMs > 0 ? Math.round((lat.count / (r.wallMs / 1000)) * 10) / 10 : 0,
    errors: r.errors || 0,
    statuses: r.statusCounts || {},
    latency_ms: lat,
    rss_start_mib: r.rssStart,
    rss_end_mib: r.rssEnd,
    rss_delta_mib: Math.round((r.rssEnd - r.rssStart) * 10) / 10,
    notes: r.notes || null,
  };
}
