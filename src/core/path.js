import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

/**
 * Delimiter table for OpenAPI 2.0 collectionFormat values that join into a
 * single value. `multi` (the default) uses repeated params and is handled
 * via URLSearchParams.append(), so it is intentionally absent here.
 */
const ARRAY_DELIMITERS = {
  csv: ',',
  ssv: ' ',
  tsv: '\t',
  pipes: '|',
};

/**
 * Build a query string from an object, omitting undefined/null/empty values.
 *
 * Arrays default to OpenAPI `multi` style (repeated params: ?tags=a&tags=b).
 * Pass `options.arrayFormats` to opt specific keys into a delimited style:
 *
 *   qs({ tags: ['a', 'b'] }, { arrayFormats: { tags: 'csv' } })
 *     → '?tags=a%2Cb'  (decoded: ?tags=a,b)
 *
 * Supported formats: 'csv', 'ssv', 'tsv', 'pipes', 'multi' (default).
 */
export function qs(params, options) {
  const arrayFormats = (options && options.arrayFormats) || null;
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      const format = arrayFormats ? arrayFormats[k] : null;
      const delimiter = format ? ARRAY_DELIMITERS[format] : undefined;
      if (delimiter !== undefined) {
        // Join into a single value using the configured delimiter.
        const parts = v.filter((item) => item !== undefined && item !== null).map(String);
        if (parts.length > 0) p.set(k, parts.join(delimiter));
      } else {
        // Default: repeated params (`multi` style).
        for (const item of v) {
          if (item !== undefined && item !== null) p.append(k, String(item));
        }
      }
    } else {
      p.set(k, String(v));
    }
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

/**
 * Walk a tool's inputSchema for array properties carrying an OpenAPI-style
 * serialization hint and produce an arrayFormats map suitable for qs().
 *
 * Recognized hints (per property):
 *   - `collectionFormat: 'csv' | 'ssv' | 'tsv' | 'pipes' | 'multi'` (OpenAPI 2.0)
 *   - `style: 'form', explode: false`                                (OpenAPI 3.0 → 'csv')
 *   - `style: 'spaceDelimited'` / `'pipeDelimited'`                  (OpenAPI 3.0)
 */
export function buildArrayFormats(inputSchema) {
  if (!inputSchema || typeof inputSchema !== 'object') return null;
  const props = inputSchema.properties;
  if (!props || typeof props !== 'object') return null;
  const formats = {};
  let any = false;
  for (const [name, schema] of Object.entries(props)) {
    if (!schema || schema.type !== 'array') continue;
    let format = null;
    if (typeof schema.collectionFormat === 'string') {
      format = schema.collectionFormat;
    } else if (schema.style === 'form' && schema.explode === false) {
      format = 'csv';
    } else if (schema.style === 'spaceDelimited') {
      format = 'ssv';
    } else if (schema.style === 'pipeDelimited') {
      format = 'pipes';
    }
    if (format && format !== 'multi') {
      formats[name] = format;
      any = true;
    }
  }
  return any ? formats : null;
}

/** Extract :param placeholders from a path template. */
export function extractPathParams(pathTemplate) {
  const matches = pathTemplate.match(/:([a-zA-Z_][a-zA-Z0-9_]*)/g);
  return matches ? matches.map((m) => m.slice(1)) : [];
}

/** Interpolate :param placeholders in a path with URI-encoded values.
 *
 * Many upstream servers double-decode `%2F` back to `/`, turning an
 * attacker-controlled path parameter into a real path traversal.
 * `encodeURIComponent` alone is NOT sufficient defence. Reject literal
 * `/`, `\`, `..`, and NUL bytes in path parameter values at the source.
 * Operators with a legitimate need for slashes in a path segment can opt
 * in by setting `tool.allowPathSlashes: true` on that tool definition.
 *
 * @param {string} pathTemplate
 * @param {object} args
 * @param {object} [opts]
 * @param {boolean} [opts.allowSlashes] - Permit `/` and `\` in values
 */
export function interpolatePath(pathTemplate, args, opts = {}) {
  return pathTemplate.replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, (_, key) => {
    const val = args[key];
    if (val === undefined || val === null) {
      throw new McpError(ErrorCode.InvalidParams, `Missing required path parameter: ${key}`);
    }
    const str = String(val);
    if (str.includes('\0')) {
      throw new McpError(ErrorCode.InvalidParams, `Path parameter "${key}" contains a NUL byte`);
    }
    // Decode percent-encoded values before traversal checks. `.%2e` and `%2e%2e`
    // pass literal `..` and `/` guards because `encodeURIComponent` does NOT
    // re-encode an already-encoded `%` — the sequence reaches the upstream
    // intact, and many proxies (nginx, express) double-decode `/.%2e/` → `/../`.
    let decoded;
    try {
      decoded = decodeURIComponent(str);
    } catch {
      throw new McpError(ErrorCode.InvalidParams, `Path parameter "${key}" contains malformed percent-encoding`);
    }
    if (!opts.allowSlashes && /[/\\]/.test(decoded)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Path parameter "${key}" contains a path separator — set tool.allowPathSlashes:true to permit`,
      );
    }
    if (!opts.allowSlashes && (decoded === '..' || decoded.includes('/../') || decoded.includes('/..') || decoded.includes('../'))) {
      throw new McpError(ErrorCode.InvalidParams, `Path parameter "${key}" contains ".." — path traversal sequences are not permitted`);
    }
    // Guard against `str` containing a literal `%` followed by traversal
    // sequences that survive `decodeURIComponent` (double-encoded).
    if (str.includes('%2e%2e') || str.includes('%2E%2E') || str.includes('%2e.') || str.includes('.%2e') || str.includes('%2f') || str.includes('%2F')) {
      if (!opts.allowSlashes) {
        throw new McpError(ErrorCode.InvalidParams, `Path parameter "${key}" contains percent-encoded traversal sequences`);
      }
    }
    // Block double-encoded percent (`%25`) as a targeted defense against
    // double-encoding traversal attacks (.%252e → .%2e → ../). The specific-
    // pattern checks above already catch all known traversal sequences
    // (%2e%2e, %2f, .%2e, etc.). Legitimate URL-encoded values like email
    // addresses (user%40example.com) and product codes don't contain %25.
    if (!opts.allowSlashes && str.includes('%25')) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Path parameter "${key}" contains double-encoded percent (%25) — potential traversal bypass`,
      );
    }
    return encodeURIComponent(str);
  });
}

/** Remap keys using a mapping object. Keys not in the map pass through as-is. */
export function remapKeys(obj, map) {
  if (!obj || typeof obj !== 'object') return Object.create(null);
  if (!map) {
    const copy = Object.create(null);
    for (const [k, v] of Object.entries(obj)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      copy[k] = v;
    }
    return copy;
  }
  const result = Object.create(null);
  for (const [k, v] of Object.entries(obj)) {
    // Block dangerous input keys
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    const key = map[k] || k;
    // Block dangerous output keys
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    result[key] = v;
  }
  return result;
}

/**
 * Shared dispatch logic: resolve path params, map remaining args to query/body, call API.
 * Used by both bridge.js and mixer.js to eliminate duplication.
 *
 * @param {object} tool - Tool definition (method, path, queryMap, bodyMap)
 * @param {object} args - Tool call arguments
 * @param {Function} apiClient - API client function(method, path, body, tenant, opts?)
 * @param {object} [opts] - Per-call options forwarded to the apiClient
 * @param {AbortSignal} [opts.signal] - External cancellation signal
 * @returns {Promise<any>} API response
 */
export async function dispatchToolCall(tool, args, apiClient, opts) {
  // Per-call options are threaded verbatim onto apiClient's 5th arg so the
  // outbound fetch can compose the external cancellation signal with its
  // internal timeout controller. Omitted / undefined => unchanged behaviour.
  const callOpts = opts || undefined;
  // Validateshould require tool.path for non-chain tools, but if a tool config
  // bypasses that gate (mutated post-construction, programmatic API, etc.)
  // `pathTemplate.match()` and `pathTemplate.replace()` would crash with
  // "Cannot read properties of undefined". Surface a clean InvalidParams error.
  if (typeof tool.path !== 'string' || tool.path.length === 0) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Tool "${tool.name || '(unnamed)'}" has no path defined`,
    );
  }
  const method = (tool.method || 'GET').toUpperCase();
  const pathTemplate = tool.path;

  // 1. Extract path params from args
  const pathParamNames = new Set(extractPathParams(pathTemplate));
  const path = interpolatePath(pathTemplate, args, { allowSlashes: tool.allowPathSlashes === true });

  // 2. Separate remaining args (not consumed by path, strip internal metadata)
  const remaining = {};
  const tenant = args._tenant || null;
  for (const [k, v] of Object.entries(args)) {
    if (k === '_tenant') continue;
    if (!pathParamNames.has(k) && v !== undefined && v !== null) {
      remaining[k] = v;
    }
  }

  // GraphQL dispatch — send as POST with query/variables body
  if (tool.graphql) {
    const op = tool.graphql.operation;
    const keyword = tool.graphql.type === 'mutation' ? 'mutation' : 'query';
    return apiClient('POST', path, { query: `${keyword} { ${op} }`, variables: remaining }, tenant, callOpts);
  }

  // 3. Route remaining args to query or body based on HTTP method
  if (method === 'GET' || method === 'HEAD') {
    const mapped = remapKeys(remaining, tool.queryMap);
    // Translate inputSchema array-style hints into qs() arrayFormats. After
    // remapKeys, the keys may have been renamed — re-key the format map to the
    // post-rename names so qs() finds them.
    const rawFormats = buildArrayFormats(tool.inputSchema);
    let qsOptions;
    if (rawFormats) {
      const queryMap = tool.queryMap || null;
      const remapped = {};
      for (const [origKey, fmt] of Object.entries(rawFormats)) {
        const finalKey = (queryMap && queryMap[origKey]) || origKey;
        remapped[finalKey] = fmt;
      }
      qsOptions = { arrayFormats: remapped };
    }
    return apiClient(method, `${path}${qs(mapped, qsOptions)}`, undefined, tenant, callOpts);
  } else {
    const mapped = remapKeys(remaining, tool.bodyMap);
    return apiClient(method, path, mapped, tenant, callOpts);
  }
}

/** Convert camelCase/PascalCase/kebab-case to snake_case. */
export function toSnakeCase(str) {
  return str
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1_$2')
    .replace(/[-.\s]+/g, '_')
    .toLowerCase()
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '');
}
