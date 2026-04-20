/**
 * Security invariants — webhook listener surface
 *
 * Tests for parseWebhookTimestamp (timestamp format enforcement,
 * digit-count caps, and overflow prevention).
 *
 * @module security/invariants/webhook
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { parseWebhookTimestamp, _validateSecretForTesting as validateSecret } from '../../webhook/listener.js';

// ─────────────────────────────────────────────────────────────────────────────
// Webhook timestamp validation
// ─────────────────────────────────────────────────────────────────────────────

describe('webhook timestamp invariants', () => {
  it('parseWebhookTimestamp rejects non-digit content', () => {
    assert.equal(parseWebhookTimestamp('not-a-number'), null);
    assert.equal(parseWebhookTimestamp('123abc'), null);
  });

  it('parseWebhookTimestamp caps digit count to 13', () => {
    // 14 digits is too many — reject to prevent overflow-adjacent games.
    assert.equal(parseWebhookTimestamp('12345678901234'), null);
  });

  it('parseWebhookTimestamp accepts 10-digit unix seconds', () => {
    const v = parseWebhookTimestamp('1700000000');
    assert.equal(v, 1700000000 * 1000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Webhook header timing-oracle fix
// ─────────────────────────────────────────────────────────────────────────────

// Helper: make a fake request with the given headers
function fakeReq(headers = {}) {
  return { headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])) };
}

// Helper: build a 'header'-type route config with an inline secret value
function headerRoute(secret, headerName = 'x-webhook-secret') {
  return { secret: { type: 'header', value: secret, header: headerName } };
}

describe('webhook secret comparison timing oracle fix', () => {
  it('validateSecret header: accepts correct secret', () => {
    const route = headerRoute('my-secret-value');
    const req = fakeReq({ 'x-webhook-secret': 'my-secret-value' });
    const result = validateSecret(req, null, null, route);
    assert.strictEqual(result.ok, true, 'Exact match must return ok:true');
  });

  it('validateSecret header: rejects same-length wrong secret', () => {
    // Same byte-length as 'my-secret-value' (16 bytes) but different value
    const route = headerRoute('my-secret-value');
    const req = fakeReq({ 'x-webhook-secret': 'my-secret-OTHER' });
    const result = validateSecret(req, null, null, route);
    assert.strictEqual(result.ok, false, 'Same-length wrong value must return ok:false');
    assert.strictEqual(result.reason, 'header_mismatch');
  });

  it('validateSecret header: rejects shorter secret', () => {
    const route = headerRoute('my-secret-value');
    const req = fakeReq({ 'x-webhook-secret': 'short' });
    const result = validateSecret(req, null, null, route);
    assert.strictEqual(result.ok, false, 'Shorter value must return ok:false');
    assert.strictEqual(result.reason, 'header_mismatch');
  });

  it('validateSecret header: rejects longer secret', () => {
    const route = headerRoute('my-secret-value');
    const req = fakeReq({ 'x-webhook-secret': 'my-secret-value-extended-by-attacker' });
    const result = validateSecret(req, null, null, route);
    assert.strictEqual(result.ok, false, 'Longer value must return ok:false');
    assert.strictEqual(result.reason, 'header_mismatch');
  });

  it('validateSecret header: rejects missing secret header', () => {
    const route = headerRoute('my-secret-value');
    const req = fakeReq({}); // no header at all
    const result = validateSecret(req, null, null, route);
    assert.strictEqual(result.ok, false, 'Missing header must return ok:false');
    assert.strictEqual(result.reason, 'header_mismatch');
  });

  it('listener.js does not use length-equality short-circuit before timingSafeEqual', async () => {
    // Security fix: the header/query secret comparison used
    // `expected.length === received.length && crypto.timingSafeEqual(...)` which
    // leaks the expected secret length via timing side-channel. The fix: HMAC-SHA256
    // both sides with a per-process random key so both digests are always 32 bytes.
    //
    // This test verifies the contract: the source code must not contain the
    // length-oracle pattern for the header and query cases.
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { join, dirname } = await import('node:path');
    const __dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(__dir, '../../webhook/listener.js'), 'utf8');

    // The timing-oracle pattern: `buffer.length === other.length && timingSafeEqual`
    // must not appear in the actual code (excluding comment lines).
    // Strip single-line comment lines before checking.
    const codeOnly = src.split('\n').filter((line) => !/^\s*\/\//.test(line)).join('\n');
    const lengthOracleRe = /expected\.length\s*===\s*received\.length/g;
    const matches = [...codeOnly.matchAll(lengthOracleRe)];
    assert.strictEqual(
      matches.length,
      0,
      `Found ${matches.length} length-oracle pattern(s) in listener.js code — all secret comparisons must use HMAC normalization`,
    );
  });
});
