#!/usr/bin/env node
/**
 * 40mcp stress-test runner.
 *
 * Runs each scenario sequentially, prints a human-readable banner per
 * scenario, and writes `scripts/stress-test/results/latest.json` plus
 * a markdown summary at `scripts/stress-test/results/latest.md`.
 *
 * Usage:
 *   node scripts/stress-test/run.mjs            # full run (~60s)
 *   node scripts/stress-test/run.mjs --smoke    # fast smoke (~10s)
 *   node scripts/stress-test/run.mjs --only 1,4 # run scenarios 1 and 4
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  reverseBridgeHappyPath,
  reverseBridgeValidation,
  reverseBridgeLargePayload,
  webhookHmacSync,
  webhookHmacFailure,
  validateArgsMicrobench,
  openApiLargeSpec,
  reverseBridgeAuthRejection,
} from './scenarios.mjs';
import { renderBanner, normalizeResult, rssMiB } from './harness.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(__dirname, 'results');

const args = new Set(process.argv.slice(2));
const SMOKE = args.has('--smoke');
const onlyArg = process.argv.find((a) => a.startsWith('--only='));
const ONLY = onlyArg ? new Set(onlyArg.slice('--only='.length).split(',')) : null;

/** Scenario registry — order determines execution sequence. */
const SCENARIOS = [
  {
    id: '1',
    name: 'reverse-bridge/happy-path',
    about: 'Reverse bridge HTTP→MCP dispatch, small payload, keep-alive.',
    run: () => reverseBridgeHappyPath(SMOKE ? { total: 2000, concurrency: 32 } : { total: 10000, concurrency: 64 }),
  },
  {
    id: '2',
    name: 'reverse-bridge/input-validation',
    about: 'Mixed valid + 5 attack-shaped invalid bodies (NaN, proto, reserved keys, wrong type).',
    run: () => reverseBridgeValidation(SMOKE ? { total: 1500, concurrency: 32 } : { total: 6000, concurrency: 64 }),
  },
  {
    id: '3',
    name: 'reverse-bridge/large-payload',
    about: '~64 KiB response per call; stresses JSON serialization + envelope stripping.',
    run: () => reverseBridgeLargePayload(SMOKE ? { total: 200, concurrency: 16 } : { total: 800, concurrency: 32 }),
  },
  {
    id: '4',
    name: 'webhook/hmac-sync',
    about: 'Valid HMAC-SHA256 webhooks, sync dispatch, sustained load.',
    run: () => webhookHmacSync(SMOKE ? { total: 1500, concurrency: 16 } : { total: 6000, concurrency: 32 }),
  },
  {
    id: '5',
    name: 'webhook/hmac-failure',
    about: 'Tampered signatures → 401 under attack load; ensures validateSecret is constant-cost.',
    run: () => webhookHmacFailure(SMOKE ? { total: 1000, concurrency: 16 } : { total: 4000, concurrency: 32 }),
  },
  {
    id: '6',
    name: 'validate-tool-args/microbench',
    about: 'In-process throughput of the bridge validator (pure CPU).',
    run: () => validateArgsMicrobench(SMOKE ? { iterations: 100_000 } : { iterations: 1_000_000 }),
  },
  {
    id: '7',
    name: 'openapi/large-spec',
    about: 'Load synthetic OpenAPI 3.0 spec with thousands of operations.',
    run: () => openApiLargeSpec(SMOKE ? { toolCount: 500 } : { toolCount: 3000 }),
  },
  {
    id: '8',
    name: 'reverse-bridge/auth-rejection',
    about: 'All requests hit the checkAuth path with missing/wrong-length/wrong-value tokens.',
    run: () => reverseBridgeAuthRejection(SMOKE ? { total: 1500, concurrency: 32 } : { total: 5000, concurrency: 64 }),
  },
];

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const baselineRss = rssMiB();
  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  40mcp stress test  ${SMOKE ? '[SMOKE MODE]' : '[FULL MODE]'}`);
  console.log(`  node ${process.version}  rss=${baselineRss}MiB  cpu cores=${(await import('node:os')).cpus().length}`);
  console.log('══════════════════════════════════════════════════════════════');

  const results = [];
  const runAt = new Date().toISOString();
  const wallT0 = Date.now();

  for (const s of SCENARIOS) {
    if (ONLY && !ONLY.has(s.id)) continue;
    console.log('');
    console.log(`▶ [${s.id}] ${s.name}`);
    console.log(`   ${s.about}`);
    try {
      const r = await s.run();
      console.log(renderBanner(s.name, r));
      results.push({ id: s.id, about: s.about, ...normalizeResult(s.name, r) });
    } catch (err) {
      console.error(`  !! scenario failed: ${err.message}`);
      console.error(err.stack);
      results.push({ id: s.id, scenario: s.name, about: s.about, error: err.message });
    }
    // Give the event loop a beat to drain between scenarios.
    await new Promise((r) => setTimeout(r, 250));
  }

  const totalWall = Date.now() - wallT0;

  const summary = {
    run_at: runAt,
    node_version: process.version,
    platform: process.platform,
    arch: process.arch,
    total_wall_ms: totalWall,
    mode: SMOKE ? 'smoke' : 'full',
    baseline_rss_mib: baselineRss,
    final_rss_mib: rssMiB(),
    scenarios: results,
  };

  const jsonPath = resolve(OUT_DIR, 'latest.json');
  const mdPath = resolve(OUT_DIR, 'latest.md');
  await writeFile(jsonPath, JSON.stringify(summary, null, 2));
  await writeFile(mdPath, renderMarkdown(summary));

  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  Done in ${(totalWall / 1000).toFixed(1)}s.`);
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  MD:   ${mdPath}`);
  console.log('══════════════════════════════════════════════════════════════');
}

function renderMarkdown(summary) {
  const lines = [];
  lines.push(`# 40mcp stress test results`);
  lines.push('');
  lines.push(`- **Run at:** ${summary.run_at}`);
  lines.push(`- **Node:** ${summary.node_version} (${summary.platform}/${summary.arch})`);
  lines.push(`- **Mode:** ${summary.mode}`);
  lines.push(`- **Total wall:** ${(summary.total_wall_ms / 1000).toFixed(1)}s`);
  lines.push(`- **Baseline RSS:** ${summary.baseline_rss_mib} MiB → **final:** ${summary.final_rss_mib} MiB`);
  lines.push('');
  lines.push('| # | Scenario | Ops | RPS | p50 | p95 | p99 | Errors | ΔRSS |');
  lines.push('|---|----------|-----|-----|-----|-----|-----|--------|------|');
  for (const s of summary.scenarios) {
    if (s.error) {
      lines.push(`| ${s.id} | ${s.scenario} | — | — | — | — | — | FAIL | — |`);
      continue;
    }
    lines.push(
      `| ${s.id} | ${s.scenario} | ${s.ops} | ${s.rps} | ${s.latency_ms.p50} | ${s.latency_ms.p95} | ${s.latency_ms.p99} | ${s.errors} | ${s.rss_delta_mib} |`,
    );
  }
  lines.push('');
  lines.push('## Scenario detail');
  for (const s of summary.scenarios) {
    lines.push('');
    lines.push(`### ${s.id}. ${s.scenario}`);
    lines.push('');
    if (s.about) lines.push(`_${s.about}_`);
    if (s.error) {
      lines.push('');
      lines.push('**FAILED**: ' + s.error);
      continue;
    }
    lines.push('');
    lines.push('```');
    lines.push(`ops=${s.ops}  wall=${s.wall_ms}ms  rps=${s.rps}  errors=${s.errors}`);
    lines.push(`latency ms: min=${s.latency_ms.min} p50=${s.latency_ms.p50} p95=${s.latency_ms.p95} p99=${s.latency_ms.p99} max=${s.latency_ms.max}`);
    lines.push(`rss: ${s.rss_start_mib}MiB → ${s.rss_end_mib}MiB (Δ ${s.rss_delta_mib}MiB)`);
    lines.push(`statuses: ${JSON.stringify(s.statuses)}`);
    if (s.notes) lines.push(`notes: ${s.notes}`);
    lines.push('```');
  }
  lines.push('');
  return lines.join('\n');
}

main().catch((err) => {
  console.error('stress runner crashed:', err);
  process.exit(1);
});
