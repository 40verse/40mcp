#!/usr/bin/env node
/**
 * Trust matrix runner.
 *
 * Executes every adversarial composition scenario in
 * `src/security/trust-matrix/` and writes a human-readable JSON +
 * markdown report to `scripts/stress-test/results/trust-matrix-latest.{json,md}`.
 *
 * CI wires this as a distinct named step:
 *   npm run trust-matrix
 *
 * The trust report is the artifact: it answers "did the bridge hold
 * its trust boundaries against this round's adversarial scenarios?"
 * with a per-scenario PASS/FAIL/ERROR verdict and a human-readable
 * threat story for every scenario.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runTrustMatrix } from '../src/security/trust-matrix/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(__dirname, 'stress-test', 'results');

async function main() {
  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  40mcp trust matrix — adversarial composition test suite');
  console.log(`  node ${process.version}`);
  console.log('══════════════════════════════════════════════════════════════');
  console.log('');

  const t0 = Date.now();
  const report = await runTrustMatrix({ verbose: true });
  const wallMs = Date.now() - t0;

  console.log('');
  console.log(
    `  ── ${report.totals.pass} PASS · ${report.totals.fail} FAIL · ${report.totals.error} ERROR ` +
    `(of ${report.totals.total}) in ${(wallMs / 1000).toFixed(1)}s`,
  );
  console.log('══════════════════════════════════════════════════════════════');

  await mkdir(OUT_DIR, { recursive: true });
  await writeFile(resolve(OUT_DIR, 'trust-matrix-latest.json'), JSON.stringify(report, null, 2));
  await writeFile(resolve(OUT_DIR, 'trust-matrix-latest.md'), renderMd(report));

  console.log(`  JSON: ${resolve(OUT_DIR, 'trust-matrix-latest.json')}`);
  console.log(`  MD:   ${resolve(OUT_DIR, 'trust-matrix-latest.md')}`);
  console.log('');

  // Exit non-zero if any scenario failed, so CI can gate on this.
  if (report.totals.fail > 0 || report.totals.error > 0) {
    process.exit(1);
  }
}

function renderMd(report) {
  const lines = [
    '# 40mcp trust matrix',
    '',
    '> Adversarial composition test suite.',
    '',
    `- **Run at:** ${report.run_at}`,
    `- **Totals:** ${report.totals.pass} PASS · ${report.totals.fail} FAIL · ${report.totals.error} ERROR (of ${report.totals.total})`,
    '',
    '## Scenarios',
    '',
    '| ID | Boundary | Verdict | Story | Detail |',
    '|----|----------|---------|-------|--------|',
  ];
  for (const s of report.scenarios) {
    const icon = s.verdict === 'pass' ? '✓' : s.verdict === 'fail' ? '✗' : '!';
    const detail = (s.detail || '').replace(/\|/g, '\\|').slice(0, 200);
    const story = (s.story || '').replace(/\|/g, '\\|').slice(0, 140);
    lines.push(`| \`${s.id}\` | ${s.boundary} | ${icon} ${s.verdict.toUpperCase()} | ${story} | \`${detail}\` |`);
  }
  return lines.join('\n');
}

main().catch((err) => {
  console.error('trust-matrix runner crashed:', err);
  process.exit(1);
});
