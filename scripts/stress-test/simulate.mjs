#!/usr/bin/env node
/**
 * 40mcp combined attack-surface + usage simulator.
 *
 * Runs two independent passes and writes a markdown + JSON report:
 *
 *   1. Attack-surface probes (scripts/stress-test/attack-surface.mjs)
 *      — one probe per hardening invariant; PASS / FAIL / ERROR verdict
 *
 *   2. Realistic usage simulation (scripts/stress-test/usage-sim.mjs)
 *      — 6-bucket mixed workload for a bounded wall-clock window,
 *        per-bucket latency + status histogram
 *
 * Usage:
 *   node scripts/stress-test/simulate.mjs            # full (~15s)
 *   node scripts/stress-test/simulate.mjs --fast     # 5s usage window
 *   node scripts/stress-test/simulate.mjs --probes   # probes only
 *   node scripts/stress-test/simulate.mjs --usage    # usage only
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runAllProbes, PROBES } from './attack-surface.mjs';
import { runUsageSim } from './usage-sim.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(__dirname, 'results');

const args = new Set(process.argv.slice(2));
const FAST = args.has('--fast');
const PROBES_ONLY = args.has('--probes');
const USAGE_ONLY = args.has('--usage');

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  40mcp simulation  [${FAST ? 'FAST' : 'FULL'}]`);
  console.log(`  node ${process.version}  probes=${PROBES.length}`);
  console.log('══════════════════════════════════════════════════════════════');

  let probeResults = null;
  let usage = null;
  const t0 = Date.now();

  // ── Pass 1: attack-surface probes ────────────────────────────────
  if (!USAGE_ONLY) {
    console.log('');
    console.log('▶ Attack-surface probes');
    probeResults = await runAllProbes({ verbose: true });
    const pass = probeResults.filter((r) => r.outcome === 'PASS').length;
    const fail = probeResults.filter((r) => r.outcome === 'FAIL').length;
    const err  = probeResults.filter((r) => r.outcome === 'ERROR').length;
    console.log('');
    console.log(`  ── probes: ${pass} PASS, ${fail} FAIL, ${err} ERROR (of ${probeResults.length})`);
  }

  // ── Pass 2: usage simulation ─────────────────────────────────────
  if (!PROBES_ONLY) {
    console.log('');
    console.log('▶ Usage simulation');
    const duration = FAST ? 5_000 : 10_000;
    usage = await runUsageSim({ durationMs: duration, concurrency: 32 });
    console.log('');
    console.log(`  wall=${Math.round(usage.wallMs)}ms  ops=${usage.overall.count}  rps=${usage.overall.rps}  errors=${usage.overall.errors}`);
    console.log(`  statuses: ${JSON.stringify(usage.overall.statuses)}`);
    console.log(`  rss: ${usage.rssStart}MiB → ${usage.rssEnd}MiB`);
    console.log('');
    console.log('  per-bucket:');
    for (const b of usage.per_bucket) {
      const lat = b.latency_ms;
      console.log(
        `    ${b.bucket.padEnd(14)} weight=${String(b.weight).padStart(2)}%  ` +
        `actual=${String(b.actual_pct).padStart(4)}%  n=${String(b.count).padStart(5)}  ` +
        `p50=${lat.p50}ms p95=${lat.p95}ms p99=${lat.p99}ms  ` +
        `errors=${b.errors}`,
      );
    }
  }

  const totalWall = Date.now() - t0;

  const summary = {
    run_at: new Date().toISOString(),
    node_version: process.version,
    platform: process.platform,
    arch: process.arch,
    total_wall_ms: totalWall,
    mode: FAST ? 'fast' : 'full',
    probes: probeResults,
    usage,
  };

  await writeFile(resolve(OUT_DIR, 'simulate-latest.json'), JSON.stringify(summary, null, 2));
  await writeFile(resolve(OUT_DIR, 'simulate-latest.md'), renderMarkdown(summary));

  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  Done in ${(totalWall / 1000).toFixed(1)}s.`);
  console.log(`  JSON: ${resolve(OUT_DIR, 'simulate-latest.json')}`);
  console.log(`  MD:   ${resolve(OUT_DIR, 'simulate-latest.md')}`);
  console.log('══════════════════════════════════════════════════════════════');
}

function renderMarkdown(s) {
  const lines = [];
  lines.push('# 40mcp simulation report');
  lines.push('');
  lines.push(`- **Run at:** ${s.run_at}`);
  lines.push(`- **Node:** ${s.node_version} (${s.platform}/${s.arch})`);
  lines.push(`- **Mode:** ${s.mode}`);
  lines.push(`- **Total wall:** ${(s.total_wall_ms / 1000).toFixed(1)}s`);
  lines.push('');

  if (s.probes) {
    const pass = s.probes.filter((r) => r.outcome === 'PASS').length;
    const fail = s.probes.filter((r) => r.outcome === 'FAIL').length;
    const err  = s.probes.filter((r) => r.outcome === 'ERROR').length;
    lines.push('## 1. Attack-surface probes');
    lines.push('');
    lines.push(`**Totals:** ${pass} PASS · ${fail} FAIL · ${err} ERROR (of ${s.probes.length})`);
    lines.push('');
    // Group by boundary
    const byBoundary = new Map();
    for (const r of s.probes) {
      if (!byBoundary.has(r.boundary)) byBoundary.set(r.boundary, []);
      byBoundary.get(r.boundary).push(r);
    }
    for (const [boundary, probes] of byBoundary) {
      lines.push(`### ${boundary}`);
      lines.push('');
      lines.push('| ID | Family | Outcome | Description | Detail |');
      lines.push('|----|--------|---------|-------------|--------|');
      for (const r of probes) {
        const icon = r.outcome === 'PASS' ? '✓ PASS' : r.outcome === 'FAIL' ? '✗ FAIL' : '! ERROR';
        lines.push(`| ${r.id} | ${r.family} | ${icon} | ${r.description} | \`${r.detail}\` |`);
      }
      lines.push('');
    }
  }

  if (s.usage) {
    lines.push('## 2. Usage simulation');
    lines.push('');
    lines.push(`- **Wall:** ${Math.round(s.usage.wallMs)} ms`);
    lines.push(`- **Total ops:** ${s.usage.overall.count}  (**${s.usage.overall.rps} rps**)`);
    lines.push(`- **Errors:** ${s.usage.overall.errors}`);
    lines.push(`- **Status mix:** \`${JSON.stringify(s.usage.overall.statuses)}\``);
    lines.push(`- **RSS:** ${s.usage.rssStart} MiB → ${s.usage.rssEnd} MiB`);
    lines.push('');
    lines.push('### Per-bucket breakdown');
    lines.push('');
    lines.push('| Bucket | Target % | Actual % | Count | p50 ms | p95 ms | p99 ms | Bytes | Errors | Statuses |');
    lines.push('|--------|----------|----------|-------|--------|--------|--------|-------|--------|----------|');
    for (const b of s.usage.per_bucket) {
      const lat = b.latency_ms;
      const kb = (b.bytes / 1024).toFixed(0);
      lines.push(
        `| ${b.bucket} | ${b.weight}% | ${b.actual_pct}% | ${b.count} | ${lat.p50} | ${lat.p95} | ${lat.p99} | ${kb} KiB | ${b.errors} | \`${JSON.stringify(b.statuses)}\` |`,
      );
    }
    lines.push('');
  }
  return lines.join('\n');
}

main().catch((err) => {
  console.error('simulate runner crashed:', err);
  process.exit(1);
});
