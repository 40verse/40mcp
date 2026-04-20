#!/usr/bin/env node
/**
 * Community config lint — scans all configs/ JSON files for prompt injection
 * patterns in tool description fields.
 *
 * Uses `hasPromptInjection` from src/core/sanitize.js — the same function
 * applied at runtime — so Cyrillic homoglyph, zero-width character, and
 * NFKC normalization bypasses are caught here too.
 *
 * Run: node scripts/lint-configs.js
 *
 * Exits 0 if clean, 1 if any suspicious descriptions are found.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hasPromptInjection } from '../src/core/sanitize.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIGS_DIR = join(__dirname, '..', 'configs');

function collectDescriptions(obj, path = '') {
  const hits = [];
  if (Array.isArray(obj)) {
    obj.forEach((item, i) => hits.push(...collectDescriptions(item, `${path}[${i}]`)));
  } else if (obj && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      const childPath = path ? `${path}.${key}` : key;
      if (key === 'description' && typeof value === 'string') {
        if (hasPromptInjection(value)) {
          hits.push({ path: childPath, value });
        }
      } else {
        hits.push(...collectDescriptions(value, childPath));
      }
    }
  }
  return hits;
}

const files = readdirSync(CONFIGS_DIR).filter((f) => f.endsWith('.json'));
let totalViolations = 0;

for (const file of files) {
  const filePath = join(CONFIGS_DIR, file);
  let config;
  try {
    config = JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`[LINT ERROR] ${file}: invalid JSON — ${err.message}`);
    totalViolations++;
    continue;
  }

  const hits = collectDescriptions(config);
  if (hits.length > 0) {
    console.error(`[LINT FAIL] ${file}: ${hits.length} suspicious description(s):`);
    for (const hit of hits) {
      console.error(`  at ${hit.path}: "${hit.value.slice(0, 120)}"`);
    }
    totalViolations += hits.length;
  }
}

if (totalViolations === 0) {
  console.log(`[LINT OK] ${files.length} config(s) scanned — no prompt injection patterns found.`);
  process.exit(0);
} else {
  console.error(`\n[LINT FAIL] ${totalViolations} violation(s) across ${files.length} config(s). Review and fix before merging.`);
  process.exit(1);
}
