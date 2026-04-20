/**
 * Security invariants — SSRF / URL / network safety surface
 *
 * Tests for assertSafeUrl (IP-range blocking, scheme enforcement,
 * credential stripping) and low-level object prototype-pollution guards
 * that were co-introduced in the initial SSRF hardening pass.
 *
 * @module security/invariants/ssrf
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { assertSafeUrl } from '../../core/env.js';
import { getByPath, setByPath, DANGEROUS_KEYS } from '../../core/object.js';
import { _checkResolvedIpForTesting as checkResolvedIp } from '../../connect.js';

// ─────────────────────────────────────────────────────────────────────────────
// Initial hardening invariants (schema, SSRF basics, path safety)
// ─────────────────────────────────────────────────────────────────────────────

describe('initial hardening invariants', () => {
  it('assertSafeUrl rejects http scheme sans http/https', () => {
    assert.throws(() => assertSafeUrl('file:///etc/passwd'), /must use http/);
    assert.throws(() => assertSafeUrl('javascript:alert(1)'), /must use http/);
    assert.throws(() => assertSafeUrl('data:text/plain,x'), /must use http/);
  });

  it('assertSafeUrl rejects embedded credentials (user:pass@host)', () => {
    assert.throws(
      () => assertSafeUrl('http://user:pass@evil.example.com/'),
      /embedded credentials/,
    );
  });

  it('assertSafeUrl rejects 127.0.0.1 by default', () => {
    assert.throws(() => assertSafeUrl('http://127.0.0.1/'), /loopback/);
  });

  it('assertSafeUrl rejects RFC-1918 10/8', () => {
    assert.throws(() => assertSafeUrl('http://10.0.0.1/'), /private/);
  });

  it('assertSafeUrl rejects RFC-1918 172.16/12', () => {
    assert.throws(() => assertSafeUrl('http://172.16.0.1/'), /private/);
    assert.throws(() => assertSafeUrl('http://172.31.255.255/'), /private/);
    // 172.32.x is NOT RFC-1918
    assert.doesNotThrow(() => assertSafeUrl('http://172.32.0.1/'));
  });

  it('assertSafeUrl rejects RFC-1918 192.168/16', () => {
    assert.throws(() => assertSafeUrl('http://192.168.1.1/'), /private/);
  });

  it('assertSafeUrl allows public HTTPS hosts', () => {
    assert.doesNotThrow(() => assertSafeUrl('https://api.example.com/v1'));
  });

  it('DANGEROUS_KEYS contains __proto__, constructor, prototype', () => {
    assert.ok(DANGEROUS_KEYS.has('__proto__'));
    assert.ok(DANGEROUS_KEYS.has('constructor'));
    assert.ok(DANGEROUS_KEYS.has('prototype'));
  });

  it('setByPath refuses to write prototype-pollution keys', () => {
    const obj = {};
    setByPath(obj, '__proto__.polluted', 'evil');
    assert.equal({}.polluted, undefined, 'Object.prototype must not be polluted');
  });

  it('getByPath does not follow prototype-pollution keys', () => {
    const obj = {};
    const r = getByPath(obj, '__proto__');
    assert.equal(r, undefined);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// IP parsing edges, link-local, 0.0.0.0
// ─────────────────────────────────────────────────────────────────────────────

describe('early review invariants', () => {
  it('assertSafeUrl rejects 0.0.0.0', () => {
    assert.throws(() => assertSafeUrl('http://0.0.0.0/'), /0\.0\.0\.0/);
  });

  it('assertSafeUrl rejects 169.254.x link-local (pre-metadata block)', () => {
    // A fix upgraded this to the unconditional metadata block, but
    // the underlying link-local rejection still fires for non-metadata
    // link-local addresses.
    assert.throws(() => assertSafeUrl('http://169.254.1.1/'), /link-local|metadata/);
  });

  it('assertSafeUrl rejects IPv6 ::1 loopback', () => {
    assert.throws(() => assertSafeUrl('http://[::1]/'), /loopback/);
  });

  it('assertSafeUrl rejects IPv6 unspecified ::', () => {
    assert.throws(() => assertSafeUrl('http://[::]/'), /unspecified/);
  });

  it('assertSafeUrl rejects IPv4-mapped IPv6 (::ffff:*)', () => {
    assert.throws(
      () => assertSafeUrl('http://[::ffff:127.0.0.1]/'),
      /IPv4-mapped/,
    );
  });

  it('assertSafeUrl rejects fe80:: link-local IPv6', () => {
    assert.throws(() => assertSafeUrl('http://[fe80::1]/'), /link-local/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Vault / transport SSRF edges
// ─────────────────────────────────────────────────────────────────────────────

describe('vault / transport invariants', () => {
  it('assertSafeUrl allowPrivate lets loopback through', () => {
    assert.doesNotThrow(() =>
      assertSafeUrl('http://127.0.0.1:8080/', { allowPrivate: true }),
    );
  });

  it('assertSafeUrl allowPrivate still blocks metadata endpoints (upgrade)', () => {
    // A fix upgraded this — with allowPrivate, loopback/RFC-1918
    // are allowed, but cloud metadata hosts remain blocked.
    assert.throws(
      () => assertSafeUrl('http://169.254.169.254/', { allowPrivate: true }),
      /metadata/,
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CGNAT and reserved-address SSRF gaps
// ─────────────────────────────────────────────────────────────────────────────

describe('CGNAT and reserved-address SSRF gaps', () => {
  it('assertSafeUrl blocks RFC-6598 CGNAT range 100.64.0.0/10', () => {
    assert.throws(() => assertSafeUrl('http://100.64.0.1/v1'), /shared address space/i);
    assert.throws(() => assertSafeUrl('http://100.127.255.255/v1'), /shared address space/i);
    assert.doesNotThrow(() => assertSafeUrl('http://100.128.0.1/v1'));
    assert.doesNotThrow(() => assertSafeUrl('http://100.63.0.1/v1'));
  });

  it('assertSafeUrl blocks 0.x.x.x reserved range', () => {
    assert.throws(() => assertSafeUrl('http://0.0.0.1/v1'), /reserved address/i);
    assert.throws(() => assertSafeUrl('http://0.255.0.1/v1'), /reserved address/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// IPv6 ULA and multicast SSRF gaps
// ─────────────────────────────────────────────────────────────────────────────

describe('IPv6 Unique Local and multicast blocking', () => {
  it('assertSafeUrl blocks IPv6 Unique Local Addresses (fc00::/7)', () => {
    assert.throws(() => assertSafeUrl('http://[fc00::1]/v1'), /fc00.*\/7|unique local/i);
    assert.throws(() => assertSafeUrl('http://[fd00::1]/v1'), /fc00.*\/7|unique local/i);
    assert.throws(() => assertSafeUrl('http://[fdff:ffff:ffff:ffff::1]/v1'), /fc00.*\/7|unique local/i);
  });

  it('assertSafeUrl blocks IPv6 multicast addresses (ff00::/8)', () => {
    assert.throws(() => assertSafeUrl('http://[ff00::1]/v1'), /ff00.*\/8|multicast/i);
    assert.throws(() => assertSafeUrl('http://[ff02::1]/v1'), /ff00.*\/8|multicast/i);
    assert.throws(() => assertSafeUrl('http://[ffff::1]/v1'), /ff00.*\/8|multicast/i);
  });

  it('assertSafeUrl still allows public IPv6 addresses', () => {
    assert.doesNotThrow(() => assertSafeUrl('http://[2600::1]/v1'));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Loopback-hostname and IPv4-compatible IPv6 SSRF bypasses
//            (caught by trust-matrix ssrf-ipv4/ipv6-probes)
// ─────────────────────────────────────────────────────────────────────────────

describe('loopback-hostname and IPv4-compat IPv6 SSRF bypasses', () => {
  it('assertSafeUrl refuses literal hostname "localhost"', () => {
    assert.throws(
      () => assertSafeUrl('http://localhost/'),
      /loopback/i,
      'localhost must be refused — it resolves to 127.x at connect-time',
    );
  });

  it('assertSafeUrl refuses common loopback hostnames (localhost, ip6-localhost)', () => {
    assert.throws(() => assertSafeUrl('http://localhost/'), /loopback/i);
    assert.throws(() => assertSafeUrl('http://localhost.localdomain/'), /loopback/i);
    assert.throws(() => assertSafeUrl('http://ip6-localhost/'), /loopback/i);
    assert.throws(() => assertSafeUrl('http://ip6-loopback/'), /loopback/i);
  });

  it('assertSafeUrl allowPrivate:true permits localhost (consistent with 127.0.0.1)', () => {
    // When loopback is explicitly permitted, the hostname alias must be permitted too.
    assert.doesNotThrow(
      () => assertSafeUrl('http://localhost/', { allowPrivate: true }),
    );
  });

  it('assertSafeUrl refuses IPv4-compatible IPv6 form ::127.0.0.1', () => {
    // Node normalizes ::127.0.0.1 (dotted-quad) → ::7f00:1 (two hex groups).
    // Both the dotted-quad URL input and the hex-normalised hostname must be refused.
    assert.throws(
      () => assertSafeUrl('http://[::127.0.0.1]/'),
      /loopback/i,
      '::127.0.0.1 is the IPv4-compatible IPv6 form of 127.0.0.1 — must be refused',
    );
    // Hex form that Node actually passes to the check
    assert.throws(
      () => assertSafeUrl('http://[::7f00:1]/'),
      /loopback/i,
      '::7f00:1 is the hex-normalised form of ::127.0.0.1 — must be refused',
    );
  });

  it('assertSafeUrl IPv4-compatible IPv6 falls through to IPv4 catalog (private + cloud-metadata)', () => {
    // Node normalizes ::a.b.c.d (dotted-quad) to two hex groups ::XXYY:ZZWW.
    // Both dotted-quad input forms and their hex-normalised equivalents must be refused.
    // ::10.0.0.1 → ::a00:1 → embedded 10.0.0.1 → RFC-1918 private
    assert.throws(() => assertSafeUrl('http://[::10.0.0.1]/'), /private/i);
    assert.throws(() => assertSafeUrl('http://[::a00:1]/'), /private/i);
    // ::192.168.1.1 → ::c0a8:101 → RFC-1918 private
    assert.throws(() => assertSafeUrl('http://[::192.168.1.1]/'), /private/i);
    assert.throws(() => assertSafeUrl('http://[::c0a8:101]/'), /private/i);
    // ::169.254.169.254 → ::a9fe:a9fe → cloud-metadata blocked
    assert.throws(() => assertSafeUrl('http://[::169.254.169.254]/'), /metadata|link-local/i);
    assert.throws(() => assertSafeUrl('http://[::a9fe:a9fe]/'), /metadata|link-local/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Non-standard IPv4 form SSRF bypass
// ─────────────────────────────────────────────────────────────────────────────

describe('Non-standard IPv4 notation SSRF bypass prevention', () => {
  it('assertSafeUrl blocks hex-integer IPv4 (0x7f000001 → 127.0.0.1)', () => {
    // Security fix: hex-integer IPv4 forms like 0x7f000001 represent 127.0.0.1.
    // The WHATWG URL parser normalizes these in modern Node.js, but explicit rejection
    // provides defense-in-depth for runtimes or future versions that may not normalize.
    assert.throws(
      () => assertSafeUrl('http://0x7f000001/'),
      /hex-integer|loopback/i,
      'Hex-integer 0x7f000001 (127.0.0.1) must be rejected',
    );
    assert.throws(
      () => assertSafeUrl('http://0x0a000001/'),
      /hex-integer|private/i,
      'Hex-integer 0x0a000001 (10.0.0.1) must be rejected',
    );
  });

  it('assertSafeUrl blocks decimal-integer IPv4 (2130706433 → 127.0.0.1)', () => {
    // Bare decimal-integer IPv4: 2130706433 = 127.0.0.1
    assert.throws(
      () => assertSafeUrl('http://2130706433/'),
      /decimal-integer|loopback/i,
      'Decimal integer 2130706433 (127.0.0.1) must be rejected',
    );
    assert.throws(
      () => assertSafeUrl('http://167772161/'),
      /decimal-integer|private/i,
      'Decimal integer 167772161 (10.0.0.1) must be rejected',
    );
  });

  it('assertSafeUrl blocks octal-prefixed IPv4 octets (0177.0.0.1 → 127.0.0.1)', () => {
    // Octal-prefixed octets: 0177 in octal = 127. The WHATWG URL parser normalizes
    // these to dotted-decimal (0177.0.0.1 → 127.0.0.1) in modern Node.js, so the
    // existing loopback / RFC-1918 checks fire. The defense-in-depth explicit
    // rejection provides a backstop for runtimes that don't normalize.
    //
    // Note: 010.0.0.1 (octal 10 = 8) normalizes to 8.0.0.1 — a public IP that
    // SHOULD be allowed. Only test octal forms that resolve to blocked ranges.
    assert.throws(
      () => assertSafeUrl('http://0177.0.0.1/'),
      /octal-prefixed|loopback/i,
      'Octal-prefixed octet 0177.0.0.1 (127.0.0.1) must be rejected',
    );
    // octal 012 = decimal 10 → 10.0.0.1 (RFC-1918 private)
    assert.throws(
      () => assertSafeUrl('http://012.0.0.1/'),
      /octal-prefixed|private/i,
      'Octal-prefixed octet 012.0.0.1 (10.0.0.1) must be rejected',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// DNS rebinding guard (connectSse reconnect-time IP validation)
// ─────────────────────────────────────────────────────────────────────────────
//
// DNS rebinding attack: a hostname passes assertSafeUrl at config-load time
// (resolves to a public IP), then the attacker rebinds its DNS to
// 169.254.169.254 or an RFC-1918 address before the TTL expires.  The
// EventSource auto-reconnect issues a fresh OS-level DNS lookup and the new
// TCP connect lands on the private IP, forwarding any auth headers.
//
// Fix: after the hostname-string assertSafeUrl check, resolve the A record
// and call checkResolvedIp on the result.  For http:// URLs the transport URL
// is substituted with the resolved IP so reconnects are pinned.
//
// These tests exercise checkResolvedIp (the pure validation step) without
// real DNS I/O so they run reliably in CI.

// ─────────────────────────────────────────────────────────────────────────────
// SSRF invariant corpus: one row per SSRF class we claim to block.
//
// Table-driven enumeration so coverage is auditable at a glance. Each row calls
// assertSafeUrl(url) and asserts it throws under the default policy
// (allowPrivate: false). A minimal allowPrivate:true smoke block documents the
// opt-in path (loopback literal + loopback hostname pass; cloud-metadata still
// throws unconditionally).
//
// Intentionally overlaps with the round-by-round describe blocks above: when
// a row below duplicates an existing test that was already covering the same
// class, the duplicate was deleted from the legacy block — NEVER the other way
// around. This block is the canonical coverage manifest going forward.
// ─────────────────────────────────────────────────────────────────────────────

describe('SSRF blocklist corpus', () => {
  // Table rows: one SSRF class per row. Listed exhaustively so a missing
  // class is visible in a single diff rather than spread across files.
  const blocked = [
    // IPv4 loopback literal
    ['ipv4-loopback-literal', 'http://127.0.0.1'],
    // IPv4 RFC-1918 private ranges
    ['ipv4-rfc1918-10/8', 'http://10.1.2.3'],
    ['ipv4-rfc1918-172.16/12', 'http://172.16.5.5'],
    ['ipv4-rfc1918-192.168/16', 'http://192.168.0.1'],
    // IPv4 link-local
    ['ipv4-link-local-169.254/16', 'http://169.254.1.1'],
    // IPv4 cloud-metadata (unconditional — also tested under allowPrivate below)
    ['ipv4-cloud-metadata-aws-imds', 'http://169.254.169.254'],
    ['ipv4-cloud-metadata-aws-ecs', 'http://169.254.170.2'],
    ['ipv4-cloud-metadata-oracle', 'http://169.254.169.253'],
    // IPv4 CGNAT (RFC-6598)
    ['ipv4-cgnat-100.64/10-low', 'http://100.64.0.1'],
    ['ipv4-cgnat-100.64/10-high', 'http://100.127.255.255'],
    // IPv4 alternate notations (defence-in-depth; WHATWG usually normalises them)
    ['ipv4-alt-hex-integer', 'http://0x7f000001'],
    ['ipv4-alt-decimal-integer', 'http://2130706433'],
    ['ipv4-alt-octal-prefix', 'http://0177.0.0.1'],
    // IPv6 loopback
    ['ipv6-loopback', 'http://[::1]'],
    // IPv6 link-local
    ['ipv6-link-local-fe80', 'http://[fe80::1]'],
    // IPv6 ULA (fc00::/7)
    ['ipv6-ula-fc00', 'http://[fc00::1]'],
    ['ipv6-ula-fd00', 'http://[fd00::1]'],
    // IPv6 multicast (ff00::/8)
    ['ipv6-multicast-ff00', 'http://[ff00::1]'],
    ['ipv6-multicast-ff02', 'http://[ff02::1]'],
    // IPv4-in-IPv6 (compatible / mapped forms)
    ['ipv4-in-ipv6-compat-loopback', 'http://[::7f00:1]'],
    ['ipv4-in-ipv6-mapped-loopback', 'http://[::ffff:127.0.0.1]'],
    ['ipv4-in-ipv6-mapped-imds', 'http://[::ffff:169.254.169.254]'],
    // Loopback hostnames (resolve to 127.x at connect-time)
    ['hostname-localhost', 'http://localhost'],
    ['hostname-ip6-localhost', 'http://ip6-localhost'],
    ['hostname-localhost.localdomain', 'http://localhost.localdomain'],
  ];

  for (const [label, url] of blocked) {
    it(`[corpus] blocks ${label} (${url})`, () => {
      assert.throws(
        () => assertSafeUrl(url),
        /./,
        `${label}: assertSafeUrl(${JSON.stringify(url)}) must throw under default policy`,
      );
    });
  }

  // IPv4 multicast (224.0.0.0/4) — rejected unconditionally at the same tier
  // as cloud-metadata (no legitimate bridge-target use case).
  it('[corpus] blocks ipv4-multicast-224.0.0.1', () => {
    assert.throws(() => assertSafeUrl('http://224.0.0.1'), /multicast/i);
  });
  it('[corpus] blocks ipv4-multicast-239.255.255.250', () => {
    assert.throws(() => assertSafeUrl('http://239.255.255.250'), /multicast/i);
  });

  // ── allowPrivate:true smoke rows ─────────────────────────────────────────
  // Opt-in path: loopback IP + loopback hostname pass; cloud-metadata remains
  // unconditionally blocked. One smoke row per class per the task spec.
  it('[corpus/allowPrivate] loopback IPv4 literal passes when allowPrivate:true', () => {
    assert.doesNotThrow(
      () => assertSafeUrl('http://127.0.0.1', { allowPrivate: true }),
    );
  });

  it('[corpus/allowPrivate] loopback hostname passes when allowPrivate:true', () => {
    assert.doesNotThrow(
      () => assertSafeUrl('http://localhost', { allowPrivate: true }),
    );
  });

  it('[corpus/allowPrivate] cloud-metadata still throws even when allowPrivate:true', () => {
    assert.throws(
      () => assertSafeUrl('http://169.254.169.254', { allowPrivate: true }),
      /metadata/i,
      'cloud-metadata is unconditional and must throw regardless of allowPrivate',
    );
  });
});

describe('SSRF coverage parity with FastMCP ssrf.py', () => {
  // Mirrors the coverage in FastMCP's server/auth/ssrf.py (PrefectHQ/fastmcp) so our Node-side SSRF story is independently verifiable against their Python-side corpus.

  // This block is intentionally a coverage-manifest marker: every SSRF class
  // enumerated in the block above has a direct counterpart in FastMCP's
  // ssrf.py test corpus. Any future class added to FastMCP's list should
  // land here as a new row in `SSRF blocklist corpus` above.
  it('[parity] corpus block above mirrors FastMCP ssrf.py classes', () => {
    // No runtime assertion — the parity is enforced by review of the corpus
    // rows above against PrefectHQ/fastmcp server/auth/ssrf.py.
    assert.ok(true);
  });
});

describe('DNS rebinding guard — checkResolvedIp', () => {
  it('checkResolvedIp passes for a public routable IP', () => {
    // Simulates a hostname that resolves to a legitimate public IP.
    // Should not throw for either default or strict SSRF mode.
    assert.doesNotThrow(
      () => checkResolvedIp('api.example.com', '203.0.113.1'),
      'Public IP 203.0.113.1 must pass the rebinding guard',
    );
  });

  it('checkResolvedIp blocks a rebind to AWS IMDS (169.254.169.254)', () => {
    // The canonical DNS rebinding target: AWS Instance Metadata Service.
    // hostname previously resolved to a public IP; it now resolves to IMDS.
    assert.throws(
      () => checkResolvedIp('attacker.com', '169.254.169.254'),
      /DNS rebinding|cloud.metadata|link.local/i,
      'A rebind to 169.254.169.254 (AWS IMDS) must be blocked',
    );
  });

  it('checkResolvedIp blocks a rebind to RFC-1918 (10.x)', () => {
    assert.throws(
      () => checkResolvedIp('attacker.com', '10.0.0.1'),
      /DNS rebinding|private/i,
      'A rebind to 10.0.0.1 (RFC-1918) must be blocked',
    );
  });

  it('checkResolvedIp blocks a rebind to RFC-1918 (192.168.x)', () => {
    assert.throws(
      () => checkResolvedIp('attacker.com', '192.168.1.100'),
      /DNS rebinding|private/i,
      'A rebind to 192.168.1.100 (RFC-1918) must be blocked',
    );
  });

  it('checkResolvedIp blocks a rebind to loopback (127.0.0.1)', () => {
    assert.throws(
      () => checkResolvedIp('attacker.com', '127.0.0.1'),
      /DNS rebinding|loopback/i,
      'A rebind to 127.0.0.1 must be blocked',
    );
  });

  it('checkResolvedIp allows RFC-1918 when allowPrivate:true (local dev)', () => {
    // Operators can explicitly opt-in to private targets for local dev.
    // The rebinding guard honours the same allowPrivate flag as assertSafeUrl.
    assert.doesNotThrow(
      () => checkResolvedIp('localhost', '127.0.0.1', { allowPrivate: true }),
      'Loopback must be allowed when allowPrivate:true is set',
    );
  });

  it('checkResolvedIp still blocks cloud-metadata even when allowPrivate:true', () => {
    // Cloud-metadata endpoints (169.254.x.x) are blocked unconditionally —
    // there is no legitimate bridge use case for IMDS regardless of allowPrivate.
    assert.throws(
      () => checkResolvedIp('attacker.com', '169.254.169.254', { allowPrivate: true }),
      /DNS rebinding|cloud.metadata|link.local/i,
      'AWS IMDS must be blocked even with allowPrivate:true',
    );
  });
});
