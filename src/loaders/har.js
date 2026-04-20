import { readFile, stat } from 'node:fs/promises';
import { extractPathParams } from '../core/path.js';
import { DANGEROUS_KEYS } from '../core/object.js';
import { assertSafeUrl } from '../core/env.js';

/** Headers that commonly carry live credentials. */
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-session-token',
  'proxy-authorization',
  'api-key',
]);

/** Hard cap on entries processed to prevent resource exhaustion from adversarially large HARs. */
const MAX_ENTRIES = 2_000;
// Per-entry caps on extracted parameters. An attacker can submit a HAR whose
// postData.text is a JSON object with millions of keys, each passing the
// SAFE_PARAM_NAME filter at O(1). Without per-entry caps the bodyParams /
// queryParams maps grow unbounded.
const MAX_BODY_KEYS_PER_ENTRY = 50;
const MAX_QUERY_PARAMS_PER_ENTRY = 256;

/** Browser extension URL schemes — these are never legitimate API calls. */
const BLOCKED_SCHEMES = new Set([
  'chrome-extension:',
  'moz-extension:',
  'ms-browser-extension:',
  'safari-extension:',
  'safari-web-extension:',
]);

/**
 * Sensitive parameter names that must never be inferred as tool inputs.
 * These carry auth/session credentials that would leak into tool definitions.
 */
const SENSITIVE_PARAM_NAMES = new Set([
  'token', 'access_token', 'refresh_token', 'id_token',
  'auth', 'authorization',
  'cookie', 'session', 'session_id', 'sessionid',
  'api_key', 'apikey',
  'password', 'passwd', 'secret', 'credentials',
  'private_key', 'client_secret',
]);

/**
 * Safe parameter name pattern. Allows typical API identifiers (snake_case, camelCase, kebab-case).
 * Blocks names with injection characters: quotes, angle brackets, semicolons, whitespace, CRLF.
 */
const SAFE_PARAM_NAME = /^[a-zA-Z_][a-zA-Z0-9_-]*$/;

/** Check if a parameter name is a known sensitive credential/session field. */
function isSensitiveParam(name) {
  return SENSITIVE_PARAM_NAMES.has(name.toLowerCase());
}

/**
 * Load a HAR file and infer MCP tool definitions from recorded HTTP traffic.
 * @param {string|object} harOrPath - Path to .har file or parsed HAR object
 * @param {object} [options]
 * @param {string[]} [options.include] - Only include URLs matching these patterns
 * @param {string[]} [options.exclude] - Exclude URLs matching these patterns
 * @param {string[]} [options.methods] - Only include these HTTP methods
 * @param {number} [options.minObservations] - Min times a pattern must be seen (default: 1)
 * @returns {Promise<{ baseUrl: string, tools: ToolDef[] }>}
 */
export async function loadHarFile(harOrPath, options = {}) {
  let har;
  const opts = {
    include: options.include || [],
    exclude: options.exclude || [],
    methods: options.methods || ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    minObservations: options.minObservations || 1,
    minRequestTimeMs: options.minRequestTimeMs, // opt-in: filter entries below this latency (ms)
    allowPrivate: options.allowPrivate === true, // SSRF opt-out for dev HARs
  };

  if (typeof harOrPath === 'string') {
    const MAX_HAR_SIZE = 50 * 1024 * 1024; // 50 MB
    const fileStat = await stat(harOrPath);
    if (fileStat.size > MAX_HAR_SIZE) {
      throw new Error(`HAR file exceeds maximum allowed size of 50 MB (got ${(fileStat.size / 1024 / 1024).toFixed(1)} MB): ${harOrPath}`);
    }
    const content = await readFile(harOrPath, 'utf-8');
    har = JSON.parse(content);
  } else {
    har = harOrPath;
  }

  // Validate the input shape. For pre-parsed HAR objects the file-size gate is
  // bypassed. Reject malformed shapes and pre-allocated entry arrays larger
  // than 10x MAX_ENTRIES so callers cannot smuggle a huge in-memory HAR through
  // the programmatic API.
  if (!har || typeof har !== 'object') {
    throw new Error('HAR input must be a path or a parsed HAR object');
  }
  const rawEntries = har.log?.entries;
  if (rawEntries != null && !Array.isArray(rawEntries)) {
    throw new Error('HAR log.entries must be an array');
  }
  const ENTRY_HARD_CEILING = MAX_ENTRIES * 10;
  if (Array.isArray(rawEntries) && rawEntries.length > ENTRY_HARD_CEILING) {
    throw new Error(`HAR log.entries exceeds hard ceiling of ${ENTRY_HARD_CEILING} (got ${rawEntries.length})`);
  }

  // Cap entries before any processing to bound memory and CPU usage.
  const entries = (rawEntries || []).slice(0, MAX_ENTRIES);

  // Filter entries by include/exclude, methods, extension schemes, and timing anomalies.
  const filtered = entries.filter((entry) => {
    const method = entry.request?.method?.toUpperCase() || 'GET';
    const url = entry.request?.url || '';

    if (!opts.methods.includes(method)) return false;
    if (opts.include.length && !opts.include.some((p) => url.includes(p))) return false;
    if (opts.exclude.length && opts.exclude.some((p) => url.includes(p))) return false;

    // Block browser extension URLs — these are never legitimate API traffic.
    if (url) {
      try {
        if (BLOCKED_SCHEMES.has(new URL(url).protocol)) return false;
      } catch {
        return false;
      }
    }

    // Opt-in: filter entries below a caller-supplied latency threshold.
    // Useful for dropping synthetic extension-injected requests (often 0ms).
    // Not on by default — loopback HTTP can legitimately complete in < 5ms.
    if (typeof opts.minRequestTimeMs === 'number' && typeof entry.time === 'number' && entry.time < opts.minRequestTimeMs) return false;

    return true;
  });

  // Extract base URL
  const baseUrl = extractBaseUrl(filtered);

  // Validate the extracted baseUrl before it flows into `createRestBridge` as
  // the dispatch target. A hostile HAR recording with entries targeting
  // `http://169.254.169.254/...` would otherwise silently become the bridge's
  // dispatch baseUrl. Metadata hosts are blocked unconditionally; loopback/
  // RFC-1918 permitted by default because HARs are commonly captured from
  // local dev servers.
  if (baseUrl) {
    try {
      assertSafeUrl(baseUrl, {
        // Secure-by-default — require explicit opt-in for private addresses.
        // The previous default was inverted (omitting a flag allowed RFC-1918
        // addresses), making SSRF the default posture. Individual HAR entry URLs
        // (below) were already secure-by-default.
        allowPrivate: opts.allowPrivate === true,
        label: 'har baseUrl',
      });
    } catch (err) {
      throw new Error(err.message);
    }
  }

  // Group entries by method + path template
  const groups = groupByPathTemplate(filtered, baseUrl);

  // Filter by minObservations
  const filtered_groups = Array.from(groups.values()).filter((group) => {
    return group.entries.length >= opts.minObservations;
  });

  // Generate tools from groups
  const tools = filtered_groups.map((group) => {
    return generateTool(group, baseUrl);
  });

  // Warn if HAR contains live credential headers — they may be embedded in tool configs
  const credentialHeaders = detectCredentialHeaders(entries);
  if (credentialHeaders.length > 0) {
    process.stderr.write(
      `[40mcp] WARNING: HAR file contains live credential headers: ${credentialHeaders.join(', ')}. ` +
      `These will NOT be embedded in tool definitions, but review the source HAR for sensitive data before sharing.\n`,
    );
  }

  return { baseUrl, tools };
}

/**
 * Scan HAR entries for request headers that commonly carry credentials.
 * Returns sorted list of unique header names found.
 */
function detectCredentialHeaders(entries) {
  const found = new Set();
  for (const entry of entries) {
    const headers = entry.request?.headers || [];
    for (const header of headers) {
      const name = (header.name || '').toLowerCase();
      if (SENSITIVE_HEADERS.has(name)) {
        found.add(name);
      }
    }
  }
  return Array.from(found).sort();
}

/**
 * Extract the most common base URL (scheme + host + port).
 */
function extractBaseUrl(entries) {
  const baseUrls = new Map();

  for (const entry of entries) {
    const url = entry.request?.url || '';
    if (!url) continue;

    try {
      const parsed = new URL(url);
      const base = `${parsed.protocol}//${parsed.host}`;
      baseUrls.set(base, (baseUrls.get(base) || 0) + 1);
    } catch {
      // Skip invalid URLs
    }
  }

  if (baseUrls.size === 0) return '';

  let mostCommon = '';
  let maxCount = 0;
  for (const [base, count] of baseUrls) {
    if (count > maxCount) {
      maxCount = count;
      mostCommon = base;
    }
  }

  return mostCommon;
}

/**
 * Group entries by method + path template.
 * Returns { 'GET:/api/users/:id': { entries: [...], method: 'GET', pathTemplate: '/api/users/:id' } }
 */
function groupByPathTemplate(entries, _baseUrl) {
  // First pass: collect entries by method + path structure (segment count + fixed prefix)
  const structureGroups = new Map(); // method:segmentCount:fixedPrefix -> [entries]

  for (const entry of entries) {
    const method = entry.request?.method?.toUpperCase() || 'GET';
    const url = entry.request?.url || '';

    if (!url) continue;

    let pathname = '';
    try {
      const parsed = new URL(url);
      pathname = parsed.pathname;
    } catch {
      continue;
    }

    const segments = pathname.split('/').filter((s) => s.length > 0);
    // Group by segment structure, but for same-structure paths, keep them together
    const structureKey = `${method}:${segments.length}`;

    if (!structureGroups.has(structureKey)) {
      structureGroups.set(structureKey, []);
    }
    structureGroups.get(structureKey).push(entry);
  }

  // Second pass: infer path templates and group by template
  const result = new Map();
  for (const [structureKey, structureEntries] of structureGroups) {
    const [method] = structureKey.split(':');

    if (!structureEntries[0]?.request?.url) continue;

    let firstPathname = '';
    try {
      const parsed = new URL(structureEntries[0].request.url);
      firstPathname = parsed.pathname;
    } catch {
      continue;
    }

    const pathTemplate = inferPathTemplate(firstPathname, structureEntries);
    const templateKey = `${method}:${pathTemplate}`;

    if (!result.has(templateKey)) {
      result.set(templateKey, {
        method,
        pathTemplate,
        entries: [],
      });
    }

    result.get(templateKey).entries.push(...structureEntries);
  }

  return result;
}

/**
 * Infer path template by analyzing entries and replacing varying ID-like segments.
 */
function inferPathTemplate(firstPath, entries) {
  // Split by / to get segments
  const firstSegments = firstPath.split('/').filter((s) => s.length > 0);

  if (firstSegments.length === 0) return firstPath;

  // For each segment position, check if values vary
  const segmentValues = new Map(); // position -> Set of values
  for (const entry of entries) {
    const url = entry.request?.url || '';
    let pathname = '';
    try {
      const parsed = new URL(url);
      pathname = parsed.pathname;
    } catch {
      continue;
    }

    const segments = pathname.split('/').filter((s) => s.length > 0);
    for (let i = 0; i < segments.length; i++) {
      if (!segmentValues.has(i)) {
        segmentValues.set(i, new Set());
      }
      // Remove query string if present
      const segment = segments[i].split('?')[0];
      segmentValues.get(i).add(segment);
    }
  }

  // Build template: replace segments with varying ID-like values with :param_N
  const template = [];
  let paramCounter = 0;
  for (let i = 0; i < firstSegments.length; i++) {
    const values = segmentValues.get(i);
    if (!values) {
      template.push(firstSegments[i]);
      continue;
    }

    // If more than 1 unique value and values look like IDs, replace with parameter
    if (values.size > 1 && isIdLike(values)) {
      paramCounter++;
      template.push(`:param_${paramCounter}`);
    } else {
      template.push(firstSegments[i]);
    }
  }

  // Reconstruct path
  let result = '/' + template.join('/');

  // Handle query string (keep as-is, we'll infer params separately)
  const queryIndex = firstPath.indexOf('?');
  if (queryIndex !== -1) {
    result += firstPath.substring(queryIndex);
  }

  return result;
}

/**
 * Check if a set of values look like IDs (numeric, UUID, or alphanumeric patterns).
 */
function isIdLike(values) {
  const sample = Array.from(values).slice(0, 5);

  const allNumeric = sample.every((v) => /^\d+$/.test(v));
  const allUuid = sample.every((v) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v));
  const allAlphanumeric = sample.every((v) => /^[a-zA-Z0-9_-]+$/.test(v));

  return allNumeric || allUuid || (allAlphanumeric && values.size > 1);
}

/**
 * Generate a tool definition from a group of entries.
 */
function generateTool(group, _baseUrl) {
  const { method, pathTemplate, entries } = group;

  // Extract parameters from query strings and request bodies
  const { queryParams, bodyParams } = extractParameters(entries);

  // Determine required parameters
  const requiredParams = determineRequired(entries, queryParams, bodyParams);

  // Infer types
  const properties = {};
  for (const [param, values] of Object.entries(queryParams)) {
    properties[param] = inferType(values);
  }
  for (const [param, values] of Object.entries(bodyParams)) {
    properties[param] = inferType(values);
  }

  // Extract path parameters
  const pathParams = extractPathParams(pathTemplate);
  for (const param of pathParams) {
    if (!(param in properties)) {
      properties[param] = { type: 'string' };
    }
  }

  // Generate tool name
  const toolName = generateToolName(method, pathTemplate);

  // Generate description
  const description = `${method} ${pathTemplate} (inferred from ${entries.length} observation${entries.length === 1 ? '' : 's'})`;

  // Calculate confidence
  const confidence = getConfidence(entries.length);

  const tool = {
    name: toolName,
    description,
    method,
    path: pathTemplate,
    inputSchema: {
      type: 'object',
      properties,
      required: Array.from(requiredParams),
    },
    _confidence: confidence,
    _observations: entries.length,
  };

  return tool;
}

/**
 * Extract query and body parameters from entries.
 */
function extractParameters(entries) {
  // SAFE_PARAM_NAME (`^[a-zA-Z_]`) allows names beginning with `_` including
  // `__proto__`. A HAR entry containing `{"__proto__": "x"}` would walk into
  // Object.prototype on the first `bodyParams[key]` read. Use null-proto
  // accumulators and reject DANGEROUS_KEYS explicitly as defence-in-depth.
  const queryParams = Object.create(null);
  const bodyParams = Object.create(null);

  // Global cumulative cap — prevents unbounded param accumulation across entries
  // even when each entry stays within per-entry limits.
  const MAX_CUMULATIVE_PARAMS = 5_000;

  for (const entry of entries) {
    // Check cumulative cap before extracting this entry's params. The previous
    // check fired after adding each entry, allowing the last entry to push
    // the total over the limit. Pre-checking stops before any overshoot.
    if (Object.keys(queryParams).length + Object.keys(bodyParams).length >= MAX_CUMULATIVE_PARAMS) {
      process.stderr.write(`[har] WARNING: cumulative parameter count reached ${MAX_CUMULATIVE_PARAMS} — truncating\n`);
      break;
    }

    const request = entry.request || {};

    // Extract query parameters (capped per entry)
    if (Array.isArray(request.queryString)) {
      const capped = request.queryString.slice(0, MAX_QUERY_PARAMS_PER_ENTRY);
      for (const param of capped) {
        const name = param.name || '';
        const value = param.value || '';
        // Strip sensitive auth/session params and names with injection characters.
        if (isSensitiveParam(name) || !SAFE_PARAM_NAME.test(name)) continue;
        if (DANGEROUS_KEYS.has(name)) continue;
        if (!queryParams[name]) queryParams[name] = [];
        queryParams[name].push(value);
      }
    }

    // Extract body parameters
    if (request.postData) {
      const mimeType = request.postData.mimeType || '';
      const text = request.postData.text || '';

      if (mimeType.includes('application/json') && text) {
        // Size-bound the JSON text before parsing using Buffer.byteLength rather
        // than text.length — string length counts UTF-16 code units, so
        // surrogate-pair content can be ~2x the UTF-8 byte cost.
        const MAX_BODY_BYTES = 256 * 1024;
        if (Buffer.byteLength(text, 'utf8') > MAX_BODY_BYTES) continue;
        try {
          const body = JSON.parse(text);
          // Cap per-entry key count. Iterate with a counter so we never
          // materialize Object.entries() of a million-key body — the prior
          // `.slice(0, N)` variant still allocated the full entries array before
          // slicing.
          if (body && typeof body === 'object' && !Array.isArray(body)) {
            let n = 0;
            for (const key of Object.keys(body)) {
              if (n >= MAX_BODY_KEYS_PER_ENTRY) break;
              n += 1;
              if (isSensitiveParam(key) || !SAFE_PARAM_NAME.test(key)) continue;
              if (DANGEROUS_KEYS.has(key)) continue;
              const value = body[key];
              if (!bodyParams[key]) bodyParams[key] = [];
              bodyParams[key].push(value);
            }
          }
        } catch {
          // Skip invalid JSON
        }
      }
    }

  }

  return { queryParams, bodyParams };
}

/**
 * Determine which parameters are required (appear in all entries).
 */
function determineRequired(entries, queryParams, bodyParams) {
  const required = new Set();

  for (const [param, values] of Object.entries(queryParams)) {
    if (values.length === entries.length) {
      required.add(param);
    }
  }

  for (const [param, values] of Object.entries(bodyParams)) {
    if (values.length === entries.length) {
      required.add(param);
    }
  }

  return required;
}

/**
 * Infer JSON Schema type from observed values.
 */
function inferType(values) {
  if (!values || values.length === 0) return { type: 'string' };

  const sample = values.slice(0, 10);

  const allNumbers = sample.every((v) => {
    if (typeof v === 'number') return true;
    if (typeof v === 'string') return /^-?\d+(\.\d+)?$/.test(v);
    return false;
  });

  const allBooleans = sample.every((v) => v === true || v === false || v === 'true' || v === 'false');

  if (allBooleans) return { type: 'boolean' };
  if (allNumbers) {
    const hasFloat = sample.some((v) => {
      if (typeof v === 'number') return !Number.isInteger(v);
      if (typeof v === 'string') return /\.\d+/.test(v);
      return false;
    });
    return { type: hasFloat ? 'number' : 'integer' };
  }

  return { type: 'string' };
}

/**
 * Generate tool name from HTTP method and path template.
 */
function generateToolName(method, pathTemplate) {
  // Filter out param placeholders and segments that look like raw IDs (numeric, UUID)
  const isIdSegment = (s) =>
    /^\d+$/.test(s) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
  const segments = pathTemplate
    .split('/')
    .filter((s) => s.length > 0 && !s.startsWith(':') && !isIdSegment(s));
  const lastNoun = segments.length > 0 ? segments[segments.length - 1] : 'resource';

  let verb = 'call';
  if (method === 'GET') {
    const isPlural = lastNoun.endsWith('s') || lastNoun.endsWith('es');
    verb = isPlural ? 'list' : 'get';
  } else if (method === 'POST') {
    verb = 'create';
  } else if (method === 'PUT' || method === 'PATCH') {
    verb = 'update';
  } else if (method === 'DELETE') {
    verb = 'delete';
  }

  return `${verb}_${lastNoun}`.toLowerCase();
}

/**
 * Get confidence level based on observation count.
 */
function getConfidence(count) {
  if (count >= 5) return 'high';
  if (count >= 3) return 'medium';
  return 'low';
}
