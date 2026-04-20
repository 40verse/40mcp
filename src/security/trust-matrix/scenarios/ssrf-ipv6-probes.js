/**
 * ssrf-ipv6-probes — full set of IPv6 SSRF probes fail closed.
 *
 * Threat: IPv6 address space has more classes that need explicit blocking.
 *
 * Defense: `assertSafeUrl` in `src/core/env.js` covers the full IPv6 catalog.
 * This scenario asserts the catalog is complete.
 */

import { assertSafeUrl } from '../../../core/env.js';

const IPV6_PROBES = [
  // Loopback
  'http://[::1]/',
  // Unspecified
  'http://[::]/',
  // IPv4-mapped IPv6 (loopback via mapping)
  'http://[::ffff:127.0.0.1]/',
  'http://[::ffff:7f00:1]/',
  // IPv4-compatible IPv6 (deprecated, RFC 4291 §2.5.5.1 — fix)
  // Node normalizes dotted-quad → hex before assertSafeUrl sees the host.
  // Both the dotted-quad input form and the hex-normalised form must be probed.
  'http://[::127.0.0.1]/',        // dotted-quad input → Node normalizes to ::7f00:1
  'http://[::7f00:1]/',           // hex-normalised form (what Node actually passes)
  'http://[::10.0.0.1]/',         // RFC-1918 dotted-quad input
  'http://[::a00:1]/',            // RFC-1918 hex-normalised
  'http://[::169.254.169.254]/',  // IMDS dotted-quad input
  'http://[::a9fe:a9fe]/',        // IMDS hex-normalised
  // Link-local fe80::/10
  'http://[fe80::1]/',
  'http://[fe80::a00:27ff:fe6e:7d70]/',
  // Unique local fc00::/7 (unique local or multicast)
  'http://[fc00::1]/',
  'http://[fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/',
  // Unique local fd00::/8 (unique local or multicast)
  'http://[fd00::1]/',
  'http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/',
  // Multicast ff00::/8 (unique local or multicast)
  'http://[ff00::1]/',
  'http://[ff02::1]/',          // all-nodes link-local multicast
  'http://[ff02::2]/',          // all-routers link-local multicast
  // Embedded credentials → loopback
  'http://attacker:pass@[::1]/',
];

export default {
  id: 'ssrf-ipv6-probes',
  boundary: 'ssrf-guard',
  story:
    'Full IPv6 SSRF probe set hits assertSafeUrl, including unique local or multicast ' +
    '(ULA fc00::/7, fd00::/8, multicast ff00::/8) and IPv4-compatible addresses ' +
    '(::a.b.c.d in both dotted-quad input and hex-normalised forms). Every ' +
    'loopback, link-local, ULA, multicast, IPv4-mapped, and IPv4-compatible URL must throw.',

  async run() {
    const passing = [];
    const failing = [];
    for (const url of IPV6_PROBES) {
      try {
        assertSafeUrl(url, { allowPrivate: false, label: 'trust-matrix' });
        failing.push(url);
      } catch {
        passing.push(url);
      }
    }
    if (failing.length === 0) {
      return {
        verdict: 'pass',
        detail: `${passing.length}/${IPV6_PROBES.length} IPv6 SSRF probes refused`,
      };
    }
    return {
      verdict: 'fail',
      detail: `${failing.length} IPv6 SSRF probes leaked: ${failing.slice(0, 6).join(', ')}${failing.length > 6 ? ', ...' : ''}`,
    };
  },
};
