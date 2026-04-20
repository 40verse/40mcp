import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { matchesAllowedRedirect } from './redirect.js';

// ─── Exact match ────────────────────────────────────────────────────────────

describe('matchesAllowedRedirect — exact match', () => {
  it('matches identical https URI', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb', ['https://app.example.com/cb']),
      true,
    );
  });

  it('matches identical http URI', () => {
    assert.equal(
      matchesAllowedRedirect('http://app.example.com/cb', ['http://app.example.com/cb']),
      true,
    );
  });

  it('matches when candidate path extends pattern path at a segment boundary', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb/sub', ['https://app.example.com/cb']),
      true,
    );
  });

  it('returns true when at least one of several allowlist entries matches', () => {
    assert.equal(
      matchesAllowedRedirect('https://b.example.com/cb', [
        'https://a.example.com/cb',
        'https://b.example.com/cb',
        'https://c.example.com/cb',
      ]),
      true,
    );
  });
});

// ─── Wildcard host ──────────────────────────────────────────────────────────

describe('matchesAllowedRedirect — wildcard host', () => {
  it('matches a single-label subdomain', () => {
    assert.equal(
      matchesAllowedRedirect('https://tenant.example.com/cb', ['https://*.example.com/cb']),
      true,
    );
  });

  it('does not match multi-label subdomain (wildcard is single-label)', () => {
    assert.equal(
      matchesAllowedRedirect('https://a.b.example.com/cb', ['https://*.example.com/cb']),
      false,
    );
  });

  it('does not match the bare apex host', () => {
    assert.equal(
      matchesAllowedRedirect('https://example.com/cb', ['https://*.example.com/cb']),
      false,
    );
  });

  it('does not match when the label is empty', () => {
    // `https://.example.com` would parse to hostname `.example.com` which
    // must not satisfy the `*.example.com` pattern.
    assert.equal(
      matchesAllowedRedirect('https://.example.com/cb', ['https://*.example.com/cb']),
      false,
    );
  });
});

// ─── Loopback (RFC 8252) ────────────────────────────────────────────────────

describe('matchesAllowedRedirect — RFC 8252 loopback', () => {
  it('bare 127.0.0.1 pattern matches any port', () => {
    assert.equal(
      matchesAllowedRedirect('http://127.0.0.1:54321/cb', ['http://127.0.0.1']),
      true,
    );
  });

  it('bare localhost pattern matches any port', () => {
    assert.equal(
      matchesAllowedRedirect('http://localhost:9999/cb', ['http://localhost']),
      true,
    );
  });

  it('bare ::1 pattern matches any port', () => {
    assert.equal(
      matchesAllowedRedirect('http://[::1]:8080/cb', ['http://[::1]']),
      true,
    );
  });

  it('loopback allowance does not apply to https', () => {
    // Loopback is an http-only RFC 8252 exception.
    assert.equal(
      matchesAllowedRedirect('https://127.0.0.1:54321/cb', ['https://127.0.0.1']),
      false,
    );
  });

  it('loopback allowance does not apply across loopback aliases', () => {
    assert.equal(
      matchesAllowedRedirect('http://localhost:9999/cb', ['http://127.0.0.1']),
      false,
    );
  });

  it('loopback pattern with explicit port falls back to strict port match', () => {
    assert.equal(
      matchesAllowedRedirect('http://127.0.0.1:9000/cb', ['http://127.0.0.1:8080']),
      false,
    );
    assert.equal(
      matchesAllowedRedirect('http://127.0.0.1:8080/cb', ['http://127.0.0.1:8080']),
      true,
    );
  });
});

// ─── Rejections ─────────────────────────────────────────────────────────────

describe('matchesAllowedRedirect — rejections', () => {
  it('rejects on scheme mismatch', () => {
    assert.equal(
      matchesAllowedRedirect('http://app.example.com/cb', ['https://app.example.com/cb']),
      false,
    );
  });

  it('rejects on host mismatch', () => {
    assert.equal(
      matchesAllowedRedirect('https://evil.com/cb', ['https://app.example.com/cb']),
      false,
    );
  });

  it('rejects on port mismatch', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com:8443/cb', ['https://app.example.com:9443/cb']),
      false,
    );
  });

  it('rejects path-prefix-but-not-segment-boundary (/foo vs /foobar)', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/foobar', ['https://app.example.com/foo']),
      false,
    );
  });

  it('rejects URIs with userinfo in the candidate', () => {
    assert.equal(
      matchesAllowedRedirect('https://u:p@app.example.com/cb', ['https://app.example.com/cb']),
      false,
    );
  });

  it('rejects allowlist entries with userinfo', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb', ['https://u:p@app.example.com/cb']),
      false,
    );
  });

  it('rejects candidate with a literal `.` path segment', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/a/./b', ['https://app.example.com/a']),
      false,
    );
  });

  it('rejects candidate with a literal `..` path segment', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/a/../b', ['https://app.example.com']),
      false,
    );
  });

  it('rejects percent-encoded dot-segments (%2e%2e)', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/a/%2e%2e/b', ['https://app.example.com/a']),
      false,
    );
  });

  it('rejects non-ASCII (raw unicode) hostname', () => {
    assert.equal(
      matchesAllowedRedirect('https://例え.jp/cb', ['https://例え.jp/cb']),
      false,
    );
  });

  it('accepts already-punycoded hostnames (ASCII)', () => {
    assert.equal(
      matchesAllowedRedirect('https://xn--r8jz45g.jp/cb', ['https://xn--r8jz45g.jp/cb']),
      true,
    );
  });

  it('rejects with an empty allowlist', () => {
    assert.equal(matchesAllowedRedirect('https://app.example.com/cb', []), false);
  });

  it('rejects with a non-array allowlist', () => {
    assert.equal(matchesAllowedRedirect('https://app.example.com/cb', null), false);
    assert.equal(matchesAllowedRedirect('https://app.example.com/cb', undefined), false);
  });

  it('rejects non-http(s) schemes', () => {
    assert.equal(
      matchesAllowedRedirect('javascript:alert(1)', ['https://app.example.com/cb']),
      false,
    );
    assert.equal(
      matchesAllowedRedirect('file:///etc/passwd', ['https://app.example.com/cb']),
      false,
    );
    assert.equal(
      matchesAllowedRedirect('data:text/plain,hi', ['https://app.example.com/cb']),
      false,
    );
  });

  it('rejects malformed URIs', () => {
    assert.equal(matchesAllowedRedirect('not a url', ['https://app.example.com/cb']), false);
    assert.equal(matchesAllowedRedirect('', ['https://app.example.com/cb']), false);
  });

  it('rejects non-string candidate', () => {
    assert.equal(matchesAllowedRedirect(42, ['https://app.example.com/cb']), false);
    assert.equal(matchesAllowedRedirect(null, ['https://app.example.com/cb']), false);
  });
});

// ─── Edge cases ─────────────────────────────────────────────────────────────

describe('matchesAllowedRedirect — edge cases', () => {
  it('trailing slash on pattern is ignored', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb', ['https://app.example.com/cb/']),
      true,
    );
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb/', ['https://app.example.com/cb']),
      true,
    );
  });

  it('missing port matches explicit default port for https', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb', ['https://app.example.com:443/cb']),
      true,
    );
    assert.equal(
      matchesAllowedRedirect('https://app.example.com:443/cb', ['https://app.example.com/cb']),
      true,
    );
  });

  it('missing port matches explicit default port for http', () => {
    assert.equal(
      matchesAllowedRedirect('http://app.example.com/cb', ['http://app.example.com:80/cb']),
      true,
    );
    assert.equal(
      matchesAllowedRedirect('http://app.example.com:80/cb', ['http://app.example.com/cb']),
      true,
    );
  });

  it('scheme comparison is case-insensitive', () => {
    assert.equal(
      matchesAllowedRedirect('HTTPS://app.example.com/cb', ['https://app.example.com/cb']),
      true,
    );
  });

  it('host comparison is case-insensitive', () => {
    assert.equal(
      matchesAllowedRedirect('https://APP.Example.COM/cb', ['https://app.example.com/cb']),
      true,
    );
  });

  it('path comparison is case-sensitive', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/CB', ['https://app.example.com/cb']),
      false,
    );
  });

  it('root path pattern matches any path on the same origin', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/anywhere', ['https://app.example.com/']),
      true,
    );
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/anywhere', ['https://app.example.com']),
      true,
    );
  });

  it('malformed entries in the allowlist do not poison the check', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb', [
        'not a url',
        'javascript:alert(1)',
        'https://app.example.com/cb',
      ]),
      true,
    );
  });

  it('query string and fragment on the candidate are ignored', () => {
    assert.equal(
      matchesAllowedRedirect('https://app.example.com/cb?state=x#y', [
        'https://app.example.com/cb',
      ]),
      true,
    );
  });

  it('wildcard host works with matching scheme and port', () => {
    assert.equal(
      matchesAllowedRedirect('https://tenant.example.com:8443/cb', [
        'https://*.example.com:8443/cb',
      ]),
      true,
    );
  });

  it('wildcard host still enforces port match', () => {
    assert.equal(
      matchesAllowedRedirect('https://tenant.example.com:9443/cb', [
        'https://*.example.com:8443/cb',
      ]),
      false,
    );
  });
});
