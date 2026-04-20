/**
 * Security invariant — egress chokepoint
 *
 * Every outbound HTTP fetch inside `src/` MUST pass through `assertSafeUrl`
 * at the URL boundary before the network call. The FastMCP GHSA-vv7q CVSS
 * 10.0 advisory was exactly this class of bug: SSRF-via-path-params in the
 * OpenAPI director where opt-in SSRF was missed in one path. To close the
 * opt-in-impossible hole, we audit every call site and enforce the gate
 * programmatically — a new PR that adds a `fetch(`/`http.request(`/
 * `https.request(`/`http.get(`/`https.get(` call to any non-test file in
 * `src/` without `assertSafeUrl` in the same module fails CI.
 *
 * Intentional exceptions (e.g. a helper that validates through another
 * wrapper, or a health-check to a fixed loopback) can opt out by marking
 * the call site with `// egress-chokepoint: exempt — <reason>` on the
 * same line. The reason MUST be specific — do not weaken the gate.
 *
 * @module security/invariants/egress-chokepoint
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = join(__dir, '../..');

/**
 * Recursively walk a directory and return every `*.js` file that is NOT a
 * `*.test.js` file. Used to enumerate the non-test source surface of
 * `src/` without touching test harnesses or generated artefacts.
 */
function walkJsFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...walkJsFiles(full));
    } else if (st.isFile() && entry.endsWith('.js') && !entry.endsWith('.test.js')) {
      out.push(full);
    }
  }
  return out;
}

// Match an outbound network call. Intentionally conservative — we match on
// the call-site token (`fetch(`, `http.request(`, etc.) rather than on an
// imported symbol, because the goal is to catch *any* new call regardless
// of how `fetch` reached scope (global, import, destructured).
const OUTBOUND_CALL_RE = /\b(?:fetch|http\.request|https\.request|http\.get|https\.get)\s*\(/;

// A line is considered exempt if it carries the chokepoint marker. Keeping
// the marker literal rather than regex-escaped makes the grep-ability of
// the convention obvious to reviewers.
const EXEMPT_MARKER = 'egress-chokepoint: exempt';

// String-literal and comment noise: lines that only mention the token in
// prose (doc comments, error messages, markdown-ish strings) must not
// trigger the invariant. A line that matches `OUTBOUND_CALL_RE` but whose
// leading non-whitespace is a comment delimiter is dropped.
function isCommentLine(line) {
  const trimmed = line.trimStart();
  return trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
}

describe('egress chokepoint invariant', () => {
  it('every outbound fetch in src/ is gated by assertSafeUrl (or explicitly exempt)', () => {
    const files = walkJsFiles(SRC_ROOT);
    const offences = [];

    for (const file of files) {
      const src = readFileSync(file, 'utf8');
      const gated = src.includes('assertSafeUrl');
      const lines = src.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!OUTBOUND_CALL_RE.test(line)) continue;
        if (isCommentLine(line)) continue;
        if (line.includes(EXEMPT_MARKER)) continue;
        // The gate is file-level: if `assertSafeUrl` appears anywhere in the
        // module, the call site is considered to have had the boundary
        // check applied (either directly or at construction time, as in
        // OAuth2TokenManager). This is the same contract the audit
        // uses — file-scoped, not call-scoped.
        if (gated) continue;
        const rel = file.slice(SRC_ROOT.length + 1);
        offences.push(`${rel}:${i + 1}  ${line.trim()}`);
      }
    }

    assert.equal(
      offences.length,
      0,
      `Outbound HTTP call without assertSafeUrl gate in the same module.\n` +
      `Add assertSafeUrl(url, { allowPrivate, label }) before the fetch, ` +
      `or mark the call site with "// ${EXEMPT_MARKER} — <reason>" if the ` +
      `target is truly exempt (e.g. a fixed local socket).\n\nOffenders:\n` +
      offences.map((o) => `  ${o}`).join('\n'),
    );
  });
});
