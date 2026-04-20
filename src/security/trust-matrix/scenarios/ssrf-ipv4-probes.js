/**
 * ssrf-ipv4-probes — full set of IPv4 SSRF probes fail closed.
 *
 * Threat: an attacker who can influence a URL flowing into 40mcp's
 * outbound request stack (OpenAPI server URL, HAR baseUrl, connect
 * SSE URL, redirect Location header, env-var template substitution)
 * tries to point it at private/loopback/cloud-metadata addresses to
 * exfiltrate internal data or escalate to instance-credential APIs.
 *
 * Defense: `assertSafeUrl` in `src/core/env.js` blocks every
 * documented IPv4 SSRF class. This scenario exhaustively probes the
 * IPv4 catalog and asserts ALL of them throw.
 */

import { assertSafeUrl } from '../../../core/env.js';

const IPV4_PROBES = [
  // Loopback — literal IPs
  'http://127.0.0.1/',
  'http://127.0.0.2/',
  'http://127.255.255.255/',
  // Loopback — hostname aliases (DNS-alias bypass closed)
  'http://localhost/',
  'http://localhost.localdomain/',
  'http://ip6-localhost/',
  'http://ip6-loopback/',
  // RFC-1918 private
  'http://10.0.0.1/',
  'http://10.255.255.255/',
  'http://172.16.0.1/',
  'http://172.31.255.255/',
  'http://192.168.0.1/',
  'http://192.168.255.255/',
  // Link-local
  'http://169.254.0.1/',
  'http://169.254.169.254/',           // AWS / GCP / Azure IMDS
  'http://169.254.170.2/',             // AWS ECS task metadata
  // Cloud metadata absolute hostnames (alternative to literal IPs)
  'http://metadata.google.internal/',
  'http://metadata/',                  // GCP shorthand
  // Unspecified / "any"
  'http://0.0.0.0/',
  // Decimal-encoded loopback (legacy bypass)
  'http://2130706433/',                // == 127.0.0.1
  // Octal-encoded loopback (Node URL parser may handle)
  'http://0177.0.0.1/',
  // Hex-encoded loopback
  'http://0x7f.0.0.1/',
  // file://
  'file:///etc/passwd',
  // gopher (legacy SSRF)
  'gopher://127.0.0.1/',
  // Embedded credentials → loopback
  'http://attacker:pass@127.0.0.1/',
];

export default {
  id: 'ssrf-ipv4-probes',
  boundary: 'ssrf-guard',
  story:
    'Full IPv4 SSRF probe set hits assertSafeUrl. Every loopback (literal IPs ' +
    'and hostname aliases: localhost, ip6-localhost, ip6-loopback), RFC-1918, ' +
    'link-local, cloud-metadata, decimal-encoded, octal-encoded, hex-encoded, ' +
    'file://, gopher://, and embedded-creds URL must throw.',

  async run() {
    const passing = [];
    const failing = [];
    for (const url of IPV4_PROBES) {
      try {
        // allowPrivate: false — strict SSRF policy
        assertSafeUrl(url, { allowPrivate: false, label: 'trust-matrix' });
        // No throw == probe FAILED to refuse a known-bad URL
        failing.push(url);
      } catch {
        passing.push(url);
      }
    }
    if (failing.length === 0) {
      return {
        verdict: 'pass',
        detail: `${passing.length}/${IPV4_PROBES.length} IPv4 SSRF probes refused`,
      };
    }
    return {
      verdict: 'fail',
      detail: `${failing.length} IPv4 SSRF probes leaked: ${failing.slice(0, 6).join(', ')}${failing.length > 6 ? ', ...' : ''}`,
    };
  },
};
