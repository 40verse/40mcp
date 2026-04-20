/**
 * Redirect-URI allowlist validator.
 *
 * Component-wise comparison of an incoming redirect URI against a set of
 * operator-configured patterns. Semantics are modeled on FastMCP's
 * `server/auth/redirect_validation.py`:
 *
 *   - Scheme: case-insensitive, must be `http` or `https` on both sides.
 *   - Host:   case-insensitive. Wildcard patterns of the form `*.example.com`
 *             match exactly one label prefix (`a.example.com` yes,
 *             `a.b.example.com` no, bare `example.com` no).
 *   - Port:   exact match. A missing port on the allowlist pattern matches
 *             only a missing port on the candidate (or the scheme's default
 *             port made explicit — i.e. `https://x` matches `https://x:443`
 *             and vice-versa). RFC 8252 loopback is the documented
 *             exception (see below).
 *   - Path:   exact-prefix with segment boundaries. The pattern path is
 *             split on `/`; the candidate path must begin with the same
 *             segments. `/foo` therefore matches `/foo` and `/foo/bar` but
 *             NOT `/foobar`. Path comparison is case-sensitive.
 *
 * Hard rejections (regardless of allowlist):
 *   - `userinfo` present (`user:pass@host`) on either side.
 *   - Dot-segments (`.` or `..`) anywhere in the parsed path of either side.
 *   - Non-ASCII hostnames. The caller must pre-encode with punycode if
 *     IDN support is required.
 *   - Schemes other than `http` / `https`.
 *
 * RFC 8252 loopback exception:
 *   If an allowlist entry is `http://127.0.0.1`, `http://localhost`, or
 *   `http://[::1]` with no explicit port and no path (or path `/`), then
 *   ANY port on that host matches. This mirrors the loopback OAuth client
 *   flow where the redirect listener binds to an ephemeral port.
 *
 * Non-goals (documented so future callers pick the right tool):
 *   - Does NOT normalize percent-encoding beyond what the WHATWG `URL`
 *     parser already does.
 *   - Does NOT follow HTTP redirects.
 *   - Does NOT verify the hostname resolves to a safe address — use
 *     `assertSafeUrl` from `src/core/env.js` for SSRF protection. A URI
 *     can match an allowlist entry and still point at a private or
 *     metadata address; both checks are complementary.
 *   - Does NOT validate query strings or fragments; those components are
 *     ignored entirely on both sides.
 *
 * @module security/redirect
 */

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);
const DEFAULT_PORTS = { 'http:': '80', 'https:': '443' };
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

/**
 * ASCII-only check for the raw URI string. The WHATWG `URL` parser silently
 * punycodes IDN hostnames at parse time, so inspecting `parsed.hostname`
 * cannot detect a non-ASCII input — we have to look at the bytes before
 * parsing. Raw unicode anywhere in the URI fails; an already-punycoded
 * `xn--…` label is ASCII and passes.
 * @param {string} uri
 * @returns {boolean}
 */
function isAsciiUri(uri) {
  for (let i = 0; i < uri.length; i++) {
    if (uri.charCodeAt(i) > 0x7f) return false;
  }
  return true;
}

/**
 * True if the raw URI string contains a `.` or `..` path segment.
 *
 * The WHATWG `URL` parser resolves dot-segments during parsing
 * (`/a/./b` -> `/a/b`, `/a/../b` -> `/b`), so we have to scan the raw
 * input. This scan stops at the first `?` or `#` so query/fragment
 * content is ignored. We check both the raw and percent-decoded form so
 * `%2e` / `%2E` variants cannot slip through.
 * @param {string} uri
 * @returns {boolean}
 */
function hasDotSegment(uri) {
  // Locate the start of the path: after `://`, past the authority.
  const schemeEnd = uri.indexOf('://');
  if (schemeEnd === -1) return false;
  const authorityStart = schemeEnd + 3;
  let pathStart = -1;
  for (let i = authorityStart; i < uri.length; i++) {
    const ch = uri.charCodeAt(i);
    if (ch === 0x2f /* / */) { pathStart = i; break; }
    if (ch === 0x3f /* ? */ || ch === 0x23 /* # */) return false;
  }
  if (pathStart === -1) return false;

  let pathEnd = uri.length;
  for (let i = pathStart; i < uri.length; i++) {
    const ch = uri.charCodeAt(i);
    if (ch === 0x3f || ch === 0x23) { pathEnd = i; break; }
  }
  const rawPath = uri.slice(pathStart, pathEnd);

  const candidates = [rawPath];
  try {
    const decoded = decodeURIComponent(rawPath);
    if (decoded !== rawPath) candidates.push(decoded);
  } catch {
    return true; // malformed percent-encoding — treat as suspicious
  }
  for (const p of candidates) {
    const segments = p.split('/');
    for (const seg of segments) {
      if (seg === '.' || seg === '..') return true;
    }
  }
  return false;
}

/**
 * Parse a URI string and return its normalized components, or `null` if
 * the URI is malformed, has userinfo, has dot-segments, has a non-ASCII
 * host, or uses a non-http(s) scheme.
 * @param {string} uri
 * @returns {{scheme: string, hostname: string, port: string, pathname: string} | null}
 */
function parseRedirect(uri) {
  if (typeof uri !== 'string' || uri.length === 0) return null;

  // Must be ASCII before we hand the string to the URL parser — the parser
  // silently punycodes IDN hosts, which would hide a non-ASCII input.
  if (!isAsciiUri(uri)) return null;

  // Dot-segments are resolved during URL parsing, so we scan the raw
  // input first.
  if (hasDotSegment(uri)) return null;

  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    return null;
  }

  if (!ALLOWED_SCHEMES.has(parsed.protocol)) return null;

  // WHATWG URL exposes userinfo as `username`/`password`; both empty when
  // the URI has no `user:pass@` segment.
  if (parsed.username !== '' || parsed.password !== '') return null;

  // Normalize port: empty means "scheme default". We keep empty-string here
  // and resolve to the default when comparing, so operators can write either
  // `https://x` or `https://x:443` interchangeably on either side.
  return {
    scheme: parsed.protocol, // includes trailing `:`
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port,
    pathname: parsed.pathname || '/',
  };
}

/**
 * Normalize a port string to its explicit value (resolving the scheme
 * default when the port is empty).
 * @param {string} scheme
 * @param {string} port
 * @returns {string}
 */
function normalizePort(scheme, port) {
  return port === '' ? DEFAULT_PORTS[scheme] || '' : port;
}

/**
 * True when the candidate hostname matches the pattern hostname, including
 * the single-label wildcard form `*.example.com`.
 * @param {string} patternHost
 * @param {string} candidateHost
 * @returns {boolean}
 */
function hostMatches(patternHost, candidateHost) {
  if (patternHost === candidateHost) return true;
  if (patternHost.startsWith('*.')) {
    const suffix = patternHost.slice(2);
    if (suffix.length === 0) return false;
    // Candidate must be `<label>.<suffix>` where `<label>` is non-empty and
    // contains no dots. A bare `<suffix>` or multi-label prefix does not
    // match — matching a single label is the FastMCP rule.
    if (!candidateHost.endsWith('.' + suffix)) return false;
    const label = candidateHost.slice(0, candidateHost.length - suffix.length - 1);
    if (label.length === 0) return false;
    if (label.includes('.')) return false;
    return true;
  }
  return false;
}

/**
 * True when `candidatePath` is a segment-boundary prefix of `patternPath`.
 * Both inputs are URL-parsed pathnames (leading `/`, no query/fragment).
 * Trailing slashes on the pattern are ignored so `/cb` and `/cb/` are
 * treated the same.
 * @param {string} patternPath
 * @param {string} candidatePath
 * @returns {boolean}
 */
function pathMatches(patternPath, candidatePath) {
  // Strip a single trailing slash from the pattern for comparison, but keep
  // the root `/` intact.
  let pattern = patternPath;
  if (pattern.length > 1 && pattern.endsWith('/')) {
    pattern = pattern.slice(0, -1);
  }
  if (pattern === '/' || pattern === '') {
    // Root pattern matches any path.
    return true;
  }
  if (candidatePath === pattern) return true;
  // Segment boundary: candidate must start with `pattern/`.
  return candidatePath.startsWith(pattern + '/');
}

/**
 * True when the allowlist pattern is a bare RFC 8252 loopback entry —
 * `http://127.0.0.1`, `http://localhost`, or `http://[::1]` with no
 * explicit port and root path.
 * @param {{scheme: string, hostname: string, port: string, pathname: string}} pattern
 * @returns {boolean}
 */
function isBareLoopback(pattern) {
  if (pattern.scheme !== 'http:') return false;
  if (pattern.port !== '') return false;
  if (pattern.pathname !== '/' && pattern.pathname !== '') return false;
  // `URL` stores `[::1]` as `[::1]` in `hostname`; normalize for comparison.
  const host = pattern.hostname;
  return LOOPBACK_HOSTS.has(host) || host === '::1';
}

/**
 * True when `candidate` and `pattern` are loopback-compatible: same scheme
 * (`http:`), same loopback hostname, and the pattern is the bare form that
 * accepts any port.
 * @param {{scheme: string, hostname: string, port: string, pathname: string}} pattern
 * @param {{scheme: string, hostname: string, port: string, pathname: string}} candidate
 * @returns {boolean}
 */
function loopbackMatches(pattern, candidate) {
  if (!isBareLoopback(pattern)) return false;
  if (candidate.scheme !== 'http:') return false;
  // Compare on normalized loopback hostnames. `URL` already lowercases.
  if (candidate.hostname !== pattern.hostname) return false;
  // Loopback pattern accepts any port and any path (root pattern matches
  // everything under pathMatches anyway, but we keep the explicit branch
  // so the intent is clear).
  return true;
}

/**
 * Determine whether `uri` matches at least one entry in `allowlist`.
 *
 * @param {string} uri - Candidate redirect URI from the client.
 * @param {string[]} allowlist - Operator-configured allowed redirect URIs.
 *   Each entry is itself parsed with the same rules as the candidate.
 * @returns {boolean} `true` when a match is found, `false` otherwise.
 *   Malformed input (either the URI or every entry of the allowlist)
 *   returns `false` rather than throwing — the caller should treat a
 *   `false` return as "reject this request".
 */
export function matchesAllowedRedirect(uri, allowlist) {
  if (!Array.isArray(allowlist) || allowlist.length === 0) return false;

  const candidate = parseRedirect(uri);
  if (!candidate) return false;

  for (const entry of allowlist) {
    const pattern = parseRedirect(entry);
    if (!pattern) continue;

    // Scheme — case-insensitive; `URL` already lowercases the protocol.
    if (pattern.scheme !== candidate.scheme) continue;

    // RFC 8252 loopback: bare loopback pattern accepts any port.
    if (loopbackMatches(pattern, candidate)) return true;

    // Host — exact or wildcard.
    if (!hostMatches(pattern.hostname, candidate.hostname)) continue;

    // Port — compare with scheme defaults resolved so `https://x` and
    // `https://x:443` are equivalent.
    const patternPort = normalizePort(pattern.scheme, pattern.port);
    const candidatePort = normalizePort(candidate.scheme, candidate.port);
    if (patternPort !== candidatePort) continue;

    // Path — segment-boundary prefix.
    if (!pathMatches(pattern.pathname, candidate.pathname)) continue;

    return true;
  }

  return false;
}
