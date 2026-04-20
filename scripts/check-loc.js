#!/usr/bin/env node
/**
 * LOC (Lines of Code) watch script — enforces file-size thresholds defined in
 * CONTRIBUTING.md.  Runs as part of CI via `npm run check:loc`.
 *
 * Exit codes:
 *   0 — all files within thresholds (or only warnings emitted)
 *   1 — at least one file requires refactoring (above the hard limit)
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ─── Thresholds (lines 1-indexed, inclusive blank lines) ────────────────────

const THRESHOLDS = {
  source: {
    review:    800,   // flag in PR review
    justify:  1200,   // must document in PR why it stays whole
    refactor: 1600,   // refactor candidate (warning)
    debt:     2500,   // architectural debt (hard fail)
  },
  test: {
    review:   600,    // flag in PR review (WARN)
    justify: 1000,    // must document in PR why it stays whole (WARN)
    refactor: 1500,   // refactor candidate (WARN)
    split:   2000,    // must split (hard fail)
  },
  docs: {
    review:   300,    // flag in PR review
  },
};

// ─── Justified exceptions ────────────────────────────────────────────────────
// Files that exceed thresholds but have documented justification.
// Format: relative path from repo root → explanation string.
// Each entry MUST have a corresponding note in CONTRIBUTING.md § Refactor Watchlist.

const JUSTIFIED_EXCEPTIONS = {
  'src/security/invariants/sanitize.test.js':
    'Covers 10 tightly-coupled sanitization surfaces (input validation, reserved-key ' +
    'denylist, CRLF/control chars, audit-log safety, prompt-injection, JSON Schema, ' +
    'spawn-env, egress strip, description caps, path safety). Splitting would break ' +
    'cross-surface regression coverage. Reviewed: 2026-04.',
  'src/red-team/mcp-specific.test.js':
    'Pre-existing debt — tracked in CONTRIBUTING.md refactor watchlist. ' +
    'Candidate for split into mcp-specific/protocol.test.js + mcp-specific/lifecycle.test.js. ' +
    'Added to watchlist: 2026-04.',
};

// ─── Directories to scan ─────────────────────────────────────────────────────

// `new URL('..').pathname` returns "/C:/..." on Windows, which `path.join`
// then mangles into "\C:\...". Use fileURLToPath so the path is a proper
// filesystem path on every platform — otherwise the walk silently finds zero
// files on Windows and every LOC violation passes locally.
const ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/[\\/]$/, '');

const SCAN_DIRS = ['src', 'test', 'examples', 'docs'];

// Patterns to exclude (generated files, node_modules, etc.)
const EXCLUDE_PATTERNS = [
  /node_modules/,
  /\.min\./,
  /dist\//,
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function countLines(filePath) {
  try {
    const content = readFileSync(filePath, 'utf8');
    return content.split('\n').length;
  } catch {
    return 0;
  }
}

function classifyFile(filePath) {
  const rel = relative(ROOT, filePath);
  if (rel.endsWith('.test.js') || rel.endsWith('.test.ts') ||
      rel.endsWith('.spec.js') || rel.endsWith('.spec.ts')) {
    return 'test';
  }
  const ext = extname(filePath);
  if (['.md', '.mdx', '.rst', '.txt'].includes(ext)) return 'docs';
  if (['.js', '.ts', '.mjs', '.cjs'].includes(ext)) return 'source';
  return null;
}

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (EXCLUDE_PATTERNS.some((p) => p.test(full))) continue;
    if (stat.isDirectory()) {
      yield* walk(full);
    } else if (stat.isFile()) {
      yield full;
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const RESET  = '\x1b[0m';
const YELLOW = '\x1b[33m';
const RED    = '\x1b[31m';
const GREEN  = '\x1b[32m';
const BOLD   = '\x1b[1m';

let warnings = 0;
let failures = 0;
const rows = [];

for (const dir of SCAN_DIRS) {
  for (const file of walk(join(ROOT, dir))) {
    const kind = classifyFile(file);
    if (!kind) continue;

    const loc  = countLines(file);
    const rel  = relative(ROOT, file);
    const thresholds = THRESHOLDS[kind] ?? {};
    const justification = JUSTIFIED_EXCEPTIONS[rel];

    if (kind === 'test') {
      if (loc > thresholds.split) {
        if (justification) {
          rows.push({ level: 'SKIP', kind, loc, rel, msg: `justified exception — ${justification.slice(0, 80)}…` });
        } else {
          rows.push({ level: 'FAIL', kind, loc, rel, msg: `>${thresholds.split} — must split (threshold: ${thresholds.split})` });
          failures++;
        }
      } else if (loc > thresholds.refactor) {
        rows.push({ level: 'WARN', kind, loc, rel, msg: `>${thresholds.refactor} — refactor candidate` });
        warnings++;
      } else if (loc > thresholds.justify) {
        rows.push({ level: 'WARN', kind, loc, rel, msg: `>${thresholds.justify} — justify keeping whole in PR` });
        warnings++;
      } else if (loc > thresholds.review) {
        rows.push({ level: 'WARN', kind, loc, rel, msg: `>${thresholds.review} — review recommended` });
        warnings++;
      }
    } else if (kind === 'source') {
      if (loc > thresholds.debt) {
        rows.push({ level: 'FAIL', kind, loc, rel, msg: `>${thresholds.debt} — architectural debt, must refactor` });
        failures++;
      } else if (loc > thresholds.refactor) {
        rows.push({ level: 'WARN', kind, loc, rel, msg: `>${thresholds.refactor} — refactor candidate` });
        warnings++;
      } else if (loc > thresholds.justify) {
        rows.push({ level: 'WARN', kind, loc, rel, msg: `>${thresholds.justify} — justify keeping whole in PR` });
        warnings++;
      } else if (loc > thresholds.review) {
        rows.push({ level: 'INFO', kind, loc, rel, msg: `>${thresholds.review} — flag in review` });
      }
    } else if (kind === 'docs') {
      if (loc > thresholds.review) {
        rows.push({ level: 'INFO', kind, loc, rel, msg: `>${thresholds.review} — consider splitting` });
      }
    }
  }
}

// Sort: FAIL first, then WARN, then INFO; within each group, descending LOC
const ORDER = { FAIL: 0, WARN: 1, INFO: 2 };
rows.sort((a, b) => ORDER[a.level] - ORDER[b.level] || b.loc - a.loc);

if (rows.length === 0) {
  console.log(`${GREEN}${BOLD}✓ LOC check passed — all files within thresholds${RESET}`);
  process.exit(0);
}

console.log(`\n${BOLD}LOC Watchlist${RESET}\n`);
console.log(`${'Level'.padEnd(6)}  ${'LOC'.padStart(5)}  ${'Kind'.padEnd(6)}  File`);
console.log('─'.repeat(72));

const CYAN = '\x1b[36m';
for (const { level, loc, kind, rel, msg } of rows) {
  const color = level === 'FAIL' ? RED : level === 'WARN' ? YELLOW : level === 'SKIP' ? CYAN : RESET;
  console.log(`${color}${level.padEnd(6)}${RESET}  ${String(loc).padStart(5)}  ${kind.padEnd(6)}  ${rel}`);
  console.log(`${''.padEnd(6)}  ${''.padStart(5)}  ${''.padEnd(6)}  ${color}↳ ${msg}${RESET}`);
}

console.log('─'.repeat(72));
console.log(`\n${BOLD}${warnings} warning(s), ${failures} failure(s)${RESET}\n`);

if (failures > 0) {
  console.error(`${RED}${BOLD}LOC check FAILED — ${failures} file(s) exceed hard limits${RESET}`);
  process.exit(1);
}
