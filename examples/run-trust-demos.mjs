#!/usr/bin/env node
/**
 * 40mcp trust-proof suite — aggregate runner.
 *
 * Runs the four killer demos sequentially and produces one unified
 * JSON + stdout report. Each demo is a self-contained Node script
 * that exits non-zero on any failure; the runner forwards exit codes.
 *
 * The four demos prove four distinct halves of the 40mcp thesis:
 *
 *   1. examples/three-tier-trust            — application-layer gating
 *      survives network compromise; bounded blast radius
 *
 *   2. examples/concurrent-tenant-isolation — per-tenant policy by
 *      composition; zero context bleed under concurrent load
 *
 *   3. examples/hostile-upstream-quarantine — per-field surgical
 *      sanitization; utility preserved alongside neutralization
 *
 *   4. examples/legacy-har-roundtrip        — full tesseract loop:
 *      legacy → HAR → tools → policy → reverse bridge → client
 *      → upstream, with round-trip integrity
 *
 * Run:
 *   node examples/run-trust-demos.mjs
 *
 * Or via npm:
 *   npm run trust-demos
 *
 * Exit code:
 *   0  all demos passed
 *   1  one or more demos failed
 *
 * Output:
 *   stdout  human-readable per-demo verdicts
 *   examples/results/trust-demos-latest.json  aggregate report
 */

import { spawn } from 'node:child_process';
import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const OUT_DIR = resolve(__dirname, 'results');

const DEMOS = [
  {
    id: 'three-tier-trust',
    title: 'Three-tier trust topology',
    proves: 'application-layer gating survives network compromise',
    script: 'examples/three-tier-trust/run.mjs',
    report: 'examples/three-tier-trust/results/three-tier-latest.json',
  },
  {
    id: 'concurrent-tenant-isolation',
    title: 'Concurrent tenant isolation',
    proves: 'per-tenant policy by composition; zero bleed under load',
    script: 'examples/concurrent-tenant-isolation/run.mjs',
    report: 'examples/concurrent-tenant-isolation/results/concurrent-tenant-latest.json',
  },
  {
    id: 'hostile-upstream-sanitize',
    title: 'Hostile upstream sanitize-in-place',
    proves: 'per-field surgical sanitization; utility preserved',
    script: 'examples/hostile-upstream-quarantine/run.mjs',
    report: 'examples/hostile-upstream-quarantine/results/quarantine-latest.json',
  },
  {
    id: 'legacy-har-roundtrip',
    title: 'Legacy HAR round-trip',
    proves: 'full tesseract loop: legacy → HAR → tools → policy → reverse → client',
    script: 'examples/legacy-har-roundtrip/run.mjs',
    report: 'examples/legacy-har-roundtrip/results/roundtrip-latest.json',
  },
];

function runDemo(demo) {
  return new Promise((resolveFn) => {
    const child = spawn('node', [demo.script], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('close', (code) => {
      // Extract the "── N PASS · M FAIL" footer line from stdout.
      const summaryMatch = stdout.match(/──\s+(\d+)\s+PASS[^\d]+(\d+)\s+FAIL/i);
      const pass = summaryMatch ? parseInt(summaryMatch[1], 10) : null;
      const fail = summaryMatch ? parseInt(summaryMatch[2], 10) : null;
      resolveFn({
        id: demo.id,
        title: demo.title,
        proves: demo.proves,
        exit_code: code,
        pass, fail,
        ok: code === 0,
        stdout_tail: stdout.split('\n').slice(-30).join('\n'),
        stderr_tail: stderr ? stderr.split('\n').slice(-5).join('\n') : '',
      });
    });
  });
}

async function readReport(path) {
  try {
    return JSON.parse(await readFile(resolve(REPO_ROOT, path), 'utf-8'));
  } catch {
    return null;
  }
}

async function main() {
  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  40mcp trust-proof suite');
  console.log(`  ${DEMOS.length} demos · run sequentially · aggregate report`);
  console.log('══════════════════════════════════════════════════════════════');

  const results = [];
  const t0 = Date.now();

  for (const demo of DEMOS) {
    console.log('');
    console.log(`▶ ${demo.title}`);
    console.log(`    ${demo.proves}`);
    const result = await runDemo(demo);
    const icon = result.ok ? '✓' : '✗';
    const status = result.pass != null
      ? `${result.pass} PASS · ${result.fail} FAIL`
      : `exit ${result.exit_code}`;
    console.log(`  ${icon} ${status}`);
    if (!result.ok && result.stdout_tail) {
      console.log('    --- last 30 lines of stdout ---');
      result.stdout_tail.split('\n').forEach((l) => console.log(`    ${l}`));
    }
    // Attach the full per-demo report from disk.
    result.full_report = await readReport(demo.report);
    results.push(result);
  }

  const wallMs = Date.now() - t0;
  const totalPass = results.reduce((a, r) => a + (r.pass || 0), 0);
  const totalFail = results.reduce((a, r) => a + (r.fail || 0), 0);
  const allOk = results.every((r) => r.ok);

  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  ${results.filter((r) => r.ok).length}/${results.length} demos passed · ${totalPass} checks PASS · ${totalFail} checks FAIL · wall=${wallMs}ms`);
  console.log('══════════════════════════════════════════════════════════════');

  await mkdir(OUT_DIR, { recursive: true });
  const summary = {
    run_at: new Date().toISOString(),
    wall_ms: wallMs,
    totals: {
      demos_total: results.length,
      demos_passed: results.filter((r) => r.ok).length,
      demos_failed: results.filter((r) => !r.ok).length,
      checks_pass: totalPass,
      checks_fail: totalFail,
    },
    all_ok: allOk,
    demos: results.map((r) => ({
      id: r.id,
      title: r.title,
      proves: r.proves,
      ok: r.ok,
      pass: r.pass,
      fail: r.fail,
      exit_code: r.exit_code,
      report: r.full_report,
    })),
  };
  await writeFile(resolve(OUT_DIR, 'trust-demos-latest.json'), JSON.stringify(summary, null, 2));
  console.log(`  results/trust-demos-latest.json`);
  console.log('');

  if (!allOk) process.exit(1);
}

main().catch((err) => {
  console.error('trust-demos runner crashed:', err);
  process.exit(1);
});
