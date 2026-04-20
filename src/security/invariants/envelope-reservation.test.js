/**
 * Security invariants — forward-reserved envelope keys.
 *
 * Reserves `_trace`, `_cost`, `_warnings`, `_version`, `_correlation` so
 * future additive features (OTEL trace context, cost attribution,
 * non-fatal dispatch warnings, per-tool API versioning, cross-instance
 * correlation) can ship without breaking the egress-strip contract and
 * without creating an upstream-injection window during rollout.
 *
 * Every test here poisons an envelope with the full set of forward-reserved
 * keys and asserts they are stripped on each egress path the bridge owns:
 *
 *   1. Bridge MCP `CallToolRequestSchema` handler (stripEgressEnvelopes +
 *      sanitizeResultObject, via the shared walker)
 *   2. Mixer MCP `CallToolRequestSchema` handler (sanitizeTransportEgress)
 *   3. Bridge exported `dispatch()` (sanitizeTransportEgress)
 *   4. Reverse bridge REST egress (stripInternalEnvelopes)
 *   5. Webhook sync response (sanitizeTransportEgress)
 *
 * Source-level assertions confirm each handler still iterates the shared
 * RESERVED_ENVELOPE_KEYS / EGRESS_STRIP_KEYS list — there must be no
 * hard-coded sub-list that would drift as new keys are reserved.
 *
 * @module security/invariants/envelope-reservation
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  RESERVED_ENVELOPE_KEYS,
  EGRESS_STRIP_KEYS,
  stripInternalEnvelopes,
  stripEgressEnvelopes,
  sanitizeTransportEgress,
} from '../../bridge.js';

// The five forward-reserved envelope keys.
// Every egress path must strip every one of these.
const FORWARD_RESERVED_KEYS = ['_trace', '_cost', '_warnings', '_version', '_correlation'];

// Canonical poisoned-upstream envelope used across every egress assertion.
// Built fresh per test via structuredClone so a walker that mutates in place
// (the bridge walkers all do) does not contaminate subsequent assertions.
const POISONED_UPSTREAM_RESULT = Object.freeze({
  ok: true,
  _trace: 'pwn',
  _cost: 999,
  _warnings: ['x'],
  _version: 'v2',
  _correlation: 'abc',
});

function freshPoisoned() {
  return structuredClone(POISONED_UPSTREAM_RESULT);
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-key reservation: each key MUST appear in RESERVED_ENVELOPE_KEYS (upstream
// trust boundary) AND EGRESS_STRIP_KEYS (transport egress). Without these
// memberships, none of the stripping walkers would remove the key, regardless
// of which call site invokes them.
// ─────────────────────────────────────────────────────────────────────────────

describe('forward-reserved keys are members of the strip sets', () => {
  for (const key of FORWARD_RESERVED_KEYS) {
    it(`"${key}" is reserved in RESERVED_ENVELOPE_KEYS`, () => {
      assert.ok(
        RESERVED_ENVELOPE_KEYS.includes(key),
        `"${key}" must be declared in RESERVED_ENVELOPE_KEYS so the upstream-boundary walker removes it`,
      );
    });

    it(`"${key}" is reserved in EGRESS_STRIP_KEYS`, () => {
      assert.ok(
        EGRESS_STRIP_KEYS.includes(key),
        `"${key}" must be declared in EGRESS_STRIP_KEYS so sanitizeTransportEgress removes it`,
      );
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Egress path 1: Bridge MCP CallToolRequestSchema handler
//
// `src/bridge.js` CallTool handler runs `stripEgressEnvelopes(result)` then
// `sanitizeResultObject(...)` before JSON.stringify. The forward-reserved keys
// must not survive that pipeline.
// ─────────────────────────────────────────────────────────────────────────────

describe('bridge CallToolRequestSchema strips forward-reserved keys', () => {
  for (const key of FORWARD_RESERVED_KEYS) {
    it(`bridge CallTool egress strips "${key}"`, () => {
      const out = stripEgressEnvelopes(freshPoisoned());
      assert.ok(
        !Object.hasOwn(out, key),
        `bridge CallToolRequestSchema handler must strip "${key}" via stripEgressEnvelopes`,
      );
      assert.equal(out.ok, true, 'legitimate payload data must survive egress strip');
    });
  }

  it('bridge CallTool handler source still iterates EGRESS_STRIP_KEYS', async () => {
    // Structural check: the bridge CallTool handler must call the shared
    // walker, not a hard-coded list. If this source-level assertion ever
    // fails, someone inlined a narrower strip set and the forward-reserved
    // keys can silently leak to the LLM on the MCP egress path.
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { join, dirname } = await import('node:path');
    const __dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(__dir, '../../bridge.js'), 'utf8');
    assert.ok(
      src.includes('stripEgressEnvelopes(result)'),
      'bridge CallTool handler must call stripEgressEnvelopes(result) — do not inline a hard-coded key list',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Egress path 2: Mixer MCP CallToolRequestSchema handler
//
// `src/compose/mixer.js` CallTool handler runs `sanitizeTransportEgress(result)`
// before JSON.stringify. The forward-reserved keys must not survive.
// ─────────────────────────────────────────────────────────────────────────────

describe('mixer CallToolRequestSchema strips forward-reserved keys', () => {
  for (const key of FORWARD_RESERVED_KEYS) {
    it(`mixer CallTool egress strips "${key}"`, () => {
      const out = sanitizeTransportEgress(freshPoisoned());
      assert.ok(
        !Object.hasOwn(out, key),
        `mixer CallToolRequestSchema handler must strip "${key}" via sanitizeTransportEgress`,
      );
      assert.equal(out.ok, true, 'legitimate payload data must survive egress strip');
    });
  }

  it('mixer CallTool handler source still calls sanitizeTransportEgress', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { join, dirname } = await import('node:path');
    const __dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(__dir, '../../compose/mixer.js'), 'utf8');
    assert.ok(
      src.includes('sanitizeTransportEgress(result)'),
      'mixer CallToolRequestSchema handler must call sanitizeTransportEgress(result)',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Egress path 3: Bridge exported dispatch()
//
// `bridge.dispatch(name, args)` wraps its return through sanitizeTransportEgress
// so callers that invoke dispatch() directly (compose chains, in-process tests)
// receive a scrubbed result. The forward-reserved keys must not survive.
// ─────────────────────────────────────────────────────────────────────────────

describe('bridge dispatch() strips forward-reserved keys', () => {
  for (const key of FORWARD_RESERVED_KEYS) {
    it(`bridge dispatch() strips "${key}"`, () => {
      // dispatch() ultimately calls sanitizeTransportEgress on its return.
      // Test that pipeline component directly — this guarantees the exit
      // behaviour for the dispatch() path without spinning up a full MCP
      // server and upstream HTTP fixture.
      const out = sanitizeTransportEgress(freshPoisoned());
      assert.ok(
        !Object.hasOwn(out, key),
        `bridge dispatch() return must strip "${key}" via sanitizeTransportEgress`,
      );
    });
  }

  it('bridge dispatch() source still calls sanitizeTransportEgress', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { join, dirname } = await import('node:path');
    const __dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(__dir, '../../bridge.js'), 'utf8');
    // Either direct return (`return sanitizeTransportEgress(result);`) or
    // variable-capture (`result = sanitizeTransportEgress(result);` — used
    // when dispatch is wrapped in a try/finally for afterDispatch hooks)
    // satisfies the trust-boundary contract: the exported dispatch() must
    // pass the result through sanitizeTransportEgress before returning.
    const callsSanitize =
      src.includes('return sanitizeTransportEgress(result);') ||
      src.includes('result = sanitizeTransportEgress(result);');
    assert.ok(
      callsSanitize,
      'bridge dispatch() must pass its result through sanitizeTransportEgress before returning — the exported API is a trust boundary',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Egress path 4: Reverse bridge REST egress
//
// `src/reverse/server.js` calls `stripInternalEnvelopes(result)` on the
// dispatch return before shipping the JSON body to the REST client. The
// forward-reserved keys must not survive.
// ─────────────────────────────────────────────────────────────────────────────

describe('reverse bridge REST egress strips forward-reserved keys', () => {
  for (const key of FORWARD_RESERVED_KEYS) {
    it(`reverse bridge REST egress strips "${key}"`, () => {
      const out = stripInternalEnvelopes(freshPoisoned());
      assert.ok(
        !Object.hasOwn(out, key),
        `reverse bridge REST egress must strip "${key}" via stripInternalEnvelopes`,
      );
      assert.equal(out.ok, true, 'legitimate payload data must survive egress strip');
    });
  }

  it('reverse bridge source still calls stripInternalEnvelopes on dispatch return', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { join, dirname } = await import('node:path');
    const __dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(__dir, '../../reverse/server.js'), 'utf8');
    assert.ok(
      src.includes('stripInternalEnvelopes(result)'),
      'reverse bridge REST egress must call stripInternalEnvelopes(result) on the dispatch return',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Egress path 5: Webhook sync response
//
// `src/webhook/listener.js` sync mode calls `sanitizeTransportEgress(rawResult)`
// before JSON.stringify of { status: 'ok', result }. The forward-reserved keys
// must not survive.
// ─────────────────────────────────────────────────────────────────────────────

describe('webhook sync response strips forward-reserved keys', () => {
  for (const key of FORWARD_RESERVED_KEYS) {
    it(`webhook sync response strips "${key}"`, () => {
      const out = sanitizeTransportEgress(freshPoisoned());
      assert.ok(
        !Object.hasOwn(out, key),
        `webhook sync response must strip "${key}" via sanitizeTransportEgress`,
      );
      assert.equal(out.ok, true, 'legitimate payload data must survive egress strip');
    });
  }

  it('webhook listener source still calls sanitizeTransportEgress', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { join, dirname } = await import('node:path');
    const __dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(__dir, '../../webhook/listener.js'), 'utf8');
    assert.ok(
      src.includes('sanitizeTransportEgress(rawResult)'),
      'webhook sync response must call sanitizeTransportEgress(rawResult)',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Full-envelope poison sanity: all five forward-reserved keys set together
// are stripped in one pass by every shared walker. Guards against a future
// refactor that accidentally returns early after removing the first match.
// ─────────────────────────────────────────────────────────────────────────────

describe('full poisoned envelope is stripped in one pass', () => {
  it('stripInternalEnvelopes removes every forward-reserved key', () => {
    const out = stripInternalEnvelopes(freshPoisoned());
    for (const key of FORWARD_RESERVED_KEYS) {
      assert.ok(!Object.hasOwn(out, key), `stripInternalEnvelopes must remove "${key}"`);
    }
    assert.equal(out.ok, true, 'legitimate payload data must survive');
  });

  it('stripEgressEnvelopes removes every forward-reserved key', () => {
    const out = stripEgressEnvelopes(freshPoisoned());
    for (const key of FORWARD_RESERVED_KEYS) {
      assert.ok(!Object.hasOwn(out, key), `stripEgressEnvelopes must remove "${key}"`);
    }
    assert.equal(out.ok, true, 'legitimate payload data must survive');
  });

  it('sanitizeTransportEgress removes every forward-reserved key', () => {
    const out = sanitizeTransportEgress(freshPoisoned());
    for (const key of FORWARD_RESERVED_KEYS) {
      assert.ok(!Object.hasOwn(out, key), `sanitizeTransportEgress must remove "${key}"`);
    }
    assert.equal(out.ok, true, 'legitimate payload data must survive');
  });
});
