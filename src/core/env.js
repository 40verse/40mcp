/**
 * Environment variable resolution and URL validation utilities.
 *
 * @module core/env
 */

/**
 * Env var names matching common secret-material patterns are blocked from
 * baseUrl-style template substitution. An otherwise-unremarkable config
 * (e.g. an openly shared OpenAPI spec with templated `servers[0].url`) could
 * otherwise exfiltrate credentials via the resolved URL's path or query string
 * on every dispatched call.
 *
 * The denylist is conservative — the patterns match env vars that are almost
 * always secret in practice. Operators who need to use one of these names as
 * a NON-secret URL component can opt in per-call via
 * `resolveEnvVars(template, label, { allowSecretNames: true })`.
 */
const SECRET_ENV_NAME_PATTERN =
  /(^|_)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|PASSPHRASE|SESSION|COOKIE|AUTH|BEARER|DSN|CONNECTION_?STRING|KUBECONFIG|DATABASE_?URL|REDIS_?URL|MONGO_?URL|AMQP_?URL|SMTP_?URL|POSTGRES_?URL|MYSQL_?URL|RABBITMQ_?URL)($|_)/i;

/**
 * Resolve environment variables in a template string.
 * Supports ${VAR} and $VAR syntax. Warns to stderr when a referenced var is unset.
 * After substitution, scans for residual placeholders and warns about unresolved references.
 *
 * @param {string} template - Template with ${VAR} or $VAR references
 * @param {string} [label] - Label prefix for warning messages
 * @param {object} [opts]
 * @param {boolean} [opts.allowSecretNames=false] - Opt in to substituting env
 *   var names that match the credential denylist (default: reject with warning).
 * @returns {string} Template with env vars substituted
 */
export function resolveEnvVars(template, label = null, opts = {}) {
  if (!template || typeof template !== 'string') {
    return template;
  }

  const prefix = label ? `[${label}]` : '[env]';
  const allowSecretNames = opts.allowSecretNames === true;

  if (opts.allowSecretNames === true) {
    process.stderr.write(
      `${prefix} SECURITY WARNING: allowSecretNames=true is set — secret-named env vars CAN be substituted into templates. ` +
      `This is unsafe in production. Only use for trusted internal configs.\n`,
    );
  }

  // Replace ${VAR} and $VAR with env values. Support both uppercase and
  // lowercase variable names (the regex pattern previously only matched
  // uppercase, allowing lowercase like ${aws_secret_access_key} to pass
  // through as literal placeholders).
  const resolved = template.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (match, varName) => {
    // Refuse to substitute secret-named env vars into templated strings
    // (which are typically baseUrl values that flow into the request URL).
    // A malicious config cannot smuggle `${AWS_SECRET_ACCESS_KEY}` into a
    // query string to exfil the secret on every outbound call.
    if (!allowSecretNames && SECRET_ENV_NAME_PATTERN.test(varName)) {
      const masked = varName.length > 4 ? varName.slice(0, 4) + '****' : '****';
      process.stderr.write(
        `${prefix} SECURITY: refusing to substitute secret-named env var "${masked}" into template — ` +
        `this value would be sent over the wire. Move the secret into auth.envVar or a header instead.\n`,
      );
      return '';
    }
    const value = process.env[varName];
    if (!value) {
      // Mask var name to prevent enumeration: show first 4 chars + ****
      const masked = varName.length > 4 ? varName.slice(0, 4) + '****' : '****';
      process.stderr.write(`${prefix} WARNING: env var "${masked}" is not set\n`);
    }
    return value || '';
  });

  // Warn about any remaining unresolved placeholders
  if (/\$\{?[A-Za-z_]/.test(resolved)) {
    process.stderr.write(`${prefix} WARNING: template contains unresolved placeholder — substitution may have failed\n`);
  }

  return resolved;
}

/**
 * Loopback hostname denylist: hostnames that unconditionally resolve to
 * loopback. Blocking by name closes the trivial DNS-bypass where an attacker
 * registers a domain (or controls /etc/hosts) pointing `localhost` to
 * 127.x — bypassing all literal-IP guards in assertSafeUrl.
 *
 * These are checked AFTER the allowPrivate short-circuit, so when
 * allowPrivate:true the behaviour is consistent with 127.x being allowed
 * (both the IP literal and its canonical hostname pass).
 */
const LOOPBACK_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
]);

/**
 * Single normalization funnel for IPv6 addresses that embed an IPv4 address.
 *
 * Node's URL parser normalizes dotted-quad IPv4-compatible and IPv4-mapped
 * forms into hex before assertSafeUrl ever sees the hostname:
 *
 *   ::127.0.0.1 (IPv4-compat, RFC 4291 §2.5.5.1) → ::7f00:1   (two hex groups)
 *   ::ffff:127.0.0.1 (IPv4-mapped)                → ::ffff:7f00:1 (three hex groups)
 *
 * The ::ffff: case is rejected outright (no legitimate outbound use case).
 * The two-hex-group case is decoded back to dotted-quad and re-validated
 * through the IPv4 catalog — loopback, RFC-1918, CGNAT, cloud-metadata
 * are all blocked without duplicating any rules.
 *
 * **Future address shapes must flow through this function, not grow new
 * ad-hoc branches in assertSafeUrl.** This is the single normalization
 * point for "IPv6 that is really an IPv4 address".
 *
 * @param {string} host - Bracket-stripped hostname from URL.hostname
 * @returns {string|null} Dotted-quad IPv4 string if decoded, null otherwise
 */
function tryDecodeIPv4FromIPv6(host) {
  // IPv4-compatible IPv6: ::XXYY:ZZWW (exactly two hex groups after ::)
  // Node normalizes ::a.b.c.d → this form; dotted-quad regex would never match.
  const m = host.match(/^::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (!m) return null;
  const hi = parseInt(m[1], 16);
  const lo = parseInt(m[2], 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

/**
 * Hosts that ALWAYS receive metadata / identity credentials on cloud
 * platforms. These MUST be rejected even when `allowPrivate: true` —
 * a legitimate operator never needs to bridge against the IMDS directly,
 * and the only purpose of allowing them would be credential exfil.
 * Hostnames are lowercased for comparison; IP literals appear in both
 * bare and bracketed forms.
 */
const CLOUD_METADATA_HOSTS = new Set([
  '169.254.169.254',  // AWS IMDS, Azure, GCP, Oracle, Alibaba
  '169.254.170.2',    // AWS ECS/Fargate task role credentials
  '169.254.170.23',   // AWS IMDSv2 extended
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
]);

/**
 * Validate that a URL is safe (https/http, not private/loopback).
 * Blocks RFC-1918 (10.x, 172.16-31.x, 192.168.x), loopback (127.x, ::1),
 * link-local (169.254.x), and 0.0.0.0 unless allowPrivate is true.
 *
 * Cloud-metadata hosts (AWS/GCP/Azure IMDS, ECS task-role endpoint, etc.)
 * are rejected UNCONDITIONALLY regardless of `allowPrivate` — there is no
 * legitimate operator use case for bridging against the metadata service,
 * and it's the primary exfiltration vector for SSRF attacks.
 *
 * IPv4 multicast (224.0.0.0/4) and IPv6 multicast (ff00::/8) are likewise
 * rejected UNCONDITIONALLY — multicast has no legitimate bridge-target use
 * case and only enables SSRF against link-local discovery services.
 *
 * ## Address normalization design
 *
 * All address-class decisions flow through two normalization paths:
 *
 * 1. **Hostname aliases** (`localhost`, `ip6-localhost`, …) — checked via
 *    `LOOPBACK_HOSTNAMES` after the `allowPrivate` short-circuit. Consistent
 *    with literal-IP treatment: allowPrivate:true permits both 127.x and its
 *    hostname alias.
 *
 * 2. **IPv6-encoded IPv4** (`::a.b.c.d`, `::ffff:a.b.c.d`) — normalized
 *    through `tryDecodeIPv4FromIPv6`. The decoded dotted-quad is re-validated
 *    by this function so loopback, RFC-1918, CGNAT, and cloud-metadata are
 *    blocked without duplicating rules.
 *
 * Future address shapes MUST extend one of these two paths rather than
 * adding new ad-hoc branches here.
 *
 * @param {string} url - URL to validate
 * @param {object} [options]
 * @param {boolean} [options.allowPrivate=false] - Allow RFC-1918 + loopback (metadata hosts still blocked)
 * @param {string} [options.label='url'] - Label for error messages
 * @throws {Error} If URL is invalid or violates policy
 */
export function assertSafeUrl(url, { allowPrivate = false, label = 'url' } = {}) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid ${label}: not a valid URL`);
  }

  // Check protocol
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Invalid ${label}: must use http:// or https://`);
  }

  // Block URLs with embedded credentials (user:pass@host)
  if (parsed.username || parsed.password) {
    throw new Error(`Invalid ${label}: URLs with embedded credentials (user:pass@host) are not allowed`);
  }

  // IPv6 literals come back bracketed from URL.hostname (e.g., "[::1]")
  const normalizedHost = parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']')
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname;

  // Reject non-standard IPv4 notation forms that bypass the dotted-decimal
  // blocklist. Although the WHATWG URL parser (Node.js v18+) normalizes
  // these forms to standard dotted-decimal before they reach this function,
  // explicit rejection is a defence-in-depth policy choice:
  //
  //   1. Runtime portability — future Node.js versions, Bun, Deno, or a
  //      bundled URL polyfill may not normalize these forms. Explicit
  //      rejection means the blocklist stays correct regardless.
  //   2. Operator clarity — seeing a rejection for 0x7f000001 makes the
  //      correct form (127.0.0.1) explicit.
  //   3. Known consequence — some non-standard forms resolving to PUBLIC
  //      addresses (e.g. 010.0.0.1 in octal) will be rejected. Operators
  //      needing such an address must write it in standard dotted-decimal.
  //
  // Hex integers: "0x7f000001" — single number, hex-prefixed.
  if (/^0x[0-9a-f]+$/i.test(normalizedHost)) {
    throw new Error(`Invalid ${label}: hex-integer IPv4 notation is not allowed — use dotted-decimal`);
  }
  // Decimal integers: "2130706433" — bare decimal number without dots.
  if (/^\d+$/.test(normalizedHost)) {
    throw new Error(`Invalid ${label}: decimal-integer IPv4 notation is not allowed — use dotted-decimal`);
  }
  // Octal-prefixed octets: any octet starting with "0" followed by more digits
  // (e.g. "0177.0.0.1" where 0177 is octal 127). Per the policy above, this
  // rejects ALL leading-zero octets, including ones that resolve to public IPs.
  if (/(?:^|\.)0\d/.test(normalizedHost)) {
    throw new Error(`Invalid ${label}: octal-prefixed IPv4 octets are not allowed — use dotted-decimal`);
  }

  // ALWAYS reject cloud-metadata hostnames, regardless of allowPrivate.
  // There is no legitimate operator use case for bridging against IMDS,
  // and it is the primary SSRF credential-exfiltration target on every
  // major cloud platform (AWS, GCP, Azure, Oracle, Alibaba).
  if (CLOUD_METADATA_HOSTS.has(normalizedHost.toLowerCase())) {
    throw new Error(
      `Invalid ${label}: cloud metadata endpoint "${normalizedHost}" is always blocked — ` +
      `it is the primary SSRF credential-exfiltration target.`,
    );
  }

  // Block IPv6 Unique Local Addresses (fc00::/7) and multicast (ff00::/8)
  // UNCONDITIONALLY — before the allowPrivate short-circuit. These are the
  // IPv6 equivalents of RFC-1918 private ranges and IPv4 multicast. Docker
  // and most cloud platforms assign ULA addresses internally, so they are
  // the primary IPv6 SSRF bypass vector.
  if (/^f[cd]/i.test(normalizedHost)) {
    throw new Error(
      `Invalid ${label}: IPv6 Unique Local Addresses (fc00::/7) are not allowed`,
    );
  }
  if (/^ff/i.test(normalizedHost)) {
    throw new Error(
      `Invalid ${label}: IPv6 multicast addresses (ff00::/8) are not allowed`,
    );
  }

  // Block IPv4 multicast (224.0.0.0/4 — first octet 224-239 inclusive)
  // UNCONDITIONALLY, at the same tier as cloud-metadata. Multicast has no
  // legitimate bridge-target use case; allowing it would only enable SSRF
  // against link-local discovery services (SSDP 239.255.255.250, mDNS
  // 224.0.0.251, etc.). Checked before the allowPrivate short-circuit so
  // the rejection is not overridable.
  {
    const ipv4MulticastMatch = normalizedHost.match(/^(\d+)\.\d+\.\d+\.\d+$/);
    if (ipv4MulticastMatch) {
      const firstOctet = Number(ipv4MulticastMatch[1]);
      if (firstOctet >= 224 && firstOctet <= 239) {
        throw new Error(
          `Invalid ${label}: IPv4 multicast addresses (224.0.0.0/4) are not allowed`,
        );
      }
    }
  }

  if (allowPrivate) {
    return; // Skip remaining IP validation if private IPs are allowed (metadata already rejected above).
  }

  // Block loopback hostnames. `localhost` resolves to
  // 127.x at connect-time but passes all literal-IP guards at parse-time.
  // The check is placed AFTER the allowPrivate short-circuit so that
  // allowPrivate:true treats `localhost` the same as `127.0.0.1` (both
  // permitted). When allowPrivate:false (the default) both are refused.
  if (LOOPBACK_HOSTNAMES.has(normalizedHost.toLowerCase())) {
    throw new Error(
      `Invalid ${label}: hostname "${normalizedHost}" resolves to loopback — use 127.0.0.1 explicitly or set allowPrivate:true`,
    );
  }

  // IPv6 unspecified addresses
  if (normalizedHost === '::' || normalizedHost === '::0') {
    throw new Error(`Invalid ${label}: unspecified IPv6 address not allowed`);
  }

  // IPv4-mapped IPv6 addresses (::ffff:127.0.0.1 / ::ffff:7f00:1 / etc.)
  // Node normalizes dotted-quad suffixes to hex-packed form, so we cannot reliably
  // decode back to IPv4 octets for range checks. Reject all IPv4-mapped IPv6 outright;
  // there is no legitimate outbound use case for IPv4-mapped IPv6 literals in URLs.
  if (/^::ffff:/i.test(normalizedHost)) {
    throw new Error(`Invalid ${label}: IPv4-mapped IPv6 addresses (::ffff:*) are not allowed`);
  }

  // IPv4-compatible IPv6 — normalized through the single
  // `tryDecodeIPv4FromIPv6` funnel. Node converts ::a.b.c.d → ::XXYY:ZZWW
  // (two hex groups). The decoded IPv4 is re-validated through this function.
  {
    const embeddedIPv4 = tryDecodeIPv4FromIPv6(normalizedHost);
    if (embeddedIPv4) {
      return assertSafeUrl(`http://${embeddedIPv4}/`, { allowPrivate, label });
    }
  }

  // IPv6 loopback
  if (normalizedHost === '::1') {
    throw new Error(`Invalid ${label}: loopback addresses (::1) are not allowed`);
  }

  // IPv6 link-local
  if (normalizedHost.startsWith('fe80:')) {
    throw new Error(`Invalid ${label}: link-local addresses are not allowed`);
  }

  // IPv6 Unique Local Addresses (fc00::/7) — RFC-4193, equivalent to RFC-1918 for IPv6
  // Covers fc00::/8 and fd00::/8 (the most common ULA range)
  if (/^f[cd]/i.test(normalizedHost)) {
    throw new Error(
      `Invalid ${label}: IPv6 Unique Local Addresses (fc00::/7) are not allowed`,
    );
  }

  // IPv6 multicast (ff00::/8)
  if (/^ff/i.test(normalizedHost)) {
    throw new Error(
      `Invalid ${label}: IPv6 multicast addresses (ff00::/8) are not allowed`,
    );
  }

  // IPv4 validation
  const ipv4Match = normalizedHost.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const [, a, b, c, d] = ipv4Match.map(Number);

    // 0.0.0.0
    if (a === 0 && b === 0 && c === 0 && d === 0) {
      throw new Error(`Invalid ${label}: 0.0.0.0 is not allowed`);
    }

    // 127.x.x.x (loopback)
    if (a === 127) {
      throw new Error(`Invalid ${label}: loopback addresses (127.x.x.x) are not allowed`);
    }

    // 10.x.x.x (RFC-1918)
    if (a === 10) {
      throw new Error(`Invalid ${label}: private addresses (10.0.0.0/8) are not allowed`);
    }

    // 172.16-31.x.x (RFC-1918)
    if (a === 172 && b >= 16 && b <= 31) {
      throw new Error(`Invalid ${label}: private addresses (172.16.0.0/12) are not allowed`);
    }

    // 192.168.x.x (RFC-1918)
    if (a === 192 && b === 168) {
      throw new Error(`Invalid ${label}: private addresses (192.168.0.0/16) are not allowed`);
    }

    // 169.254.x.x (link-local)
    if (a === 169 && b === 254) {
      throw new Error(`Invalid ${label}: link-local addresses (169.254.0.0/16) are not allowed`);
    }

    // 100.64.0.0/10 — RFC-6598 Shared Address Space (CGNAT) used by AWS VPC,
    // Tailscale, and other cloud providers for internal infrastructure.
    if (a === 100 && b >= 64 && b <= 127) {
      throw new Error(`Invalid ${label}: shared address space (100.64.0.0/10) is not allowed`);
    }

    // 0.x.x.x — reserved range used as SSRF bypass on some platforms.
    // Extend beyond 0.0.0.0 to cover the full 0.x.x.x range.
    if (a === 0) {
      throw new Error(`Invalid ${label}: reserved address range (0.0.0.0/8) is not allowed`);
    }
  }
}
