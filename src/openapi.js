import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { toSnakeCase } from './core/path.js';
import { assertSafeUrl } from './core/env.js';
import { sanitizeDescription, sanitizeToolName } from './core/sanitize.js';
import { DANGEROUS_KEYS } from './core/object.js';

/**
 * Cap OpenAPI spec size at 50 MB before `readFile`. Without this, pointing the
 * loader at `/dev/zero` or a 2 GB JSON blob OOM-kills the bridge process before
 * `JSON.parse` even runs.
 */
const MAX_OPENAPI_FILE_BYTES = 50 * 1024 * 1024;

/**
 * Resolve `$ref` references safely without crossing the prototype chain.
 * A hostile spec with `{"$ref":"#/constructor/prototype"}` would otherwise
 * walk into Object.prototype. Guard every path segment against DANGEROUS_KEYS
 * so reference resolution cannot escape into inherited properties.
 *
 * Returns the resolved value or `null` if the walk hit a dangerous segment
 * or a nullish intermediate.
 */
function resolveRefPath(refPath, spec) {
  let resolved = spec;
  for (const seg of refPath) {
    if (resolved == null) return null;
    if (DANGEROUS_KEYS.has(seg)) return null;
    // Only read own properties — never inherited. Prevents `constructor`
    // from resolving to `Object.prototype.constructor` even if not in
    // the DANGEROUS_KEYS set.
    if (!Object.prototype.hasOwnProperty.call(resolved, seg)) return null;
    resolved = resolved[seg];
  }
  return resolved ?? null;
}

/**
 * Load an OpenAPI 3.x or Swagger 2.x spec and convert to 40mcp tool definitions.
 *
 * @param {string|object} specOrPath - Path to spec file (.json/.yaml) or parsed spec object
 * @param {object} [options]
 * @param {string[]} [options.include]     - Only include operations matching these operationIds or paths
 * @param {string[]} [options.exclude]     - Exclude operations matching these operationIds or paths
 * @param {string[]} [options.tags]        - Only include operations with these tags
 * @param {string[]} [options.methods]     - Only include these HTTP methods (default: all)
 * @param {Function} [options.nameTransform] - Custom function to transform operation names
 * @param {boolean} [options.allowPrivate=false] - Allow extracted base URL to point at RFC-1918 / loopback / link-local hosts
 * @param {boolean} [options.strict=false]       - Throw on duplicate tool names instead of warn-and-skip
 * @returns {Promise<{ baseUrl: string, tools: object[] }>}
 */
export async function loadOpenApiSpec(specOrPath, options = {}) {
  let spec;

  if (typeof specOrPath === 'string') {
    const abs = resolve(specOrPath);
    if (/\.ya?ml$/i.test(abs)) {
      throw new Error(
        `YAML specs are not yet supported. Convert to JSON first:\n  npx js-yaml "${specOrPath}" > spec.json`,
      );
    }
    // Enforce a size cap BEFORE readFile so a hostile or accidental large file
    // can't OOM the process.
    const st = await stat(abs);
    if (st.size > MAX_OPENAPI_FILE_BYTES) {
      throw new Error(
        `OpenAPI spec file too large: ${st.size} bytes > ${MAX_OPENAPI_FILE_BYTES} limit. ` +
        `If this is legitimate, split the spec or raise the cap.`,
      );
    }
    const raw = await readFile(abs, 'utf-8');
    spec = JSON.parse(raw);
  } else {
    spec = specOrPath;
  }

  const isSwagger2 = !!spec.swagger;
  const { baseUrl, fromSpec } = extractBaseUrl(spec, isSwagger2);

  // SSRF guard: when the base URL was extracted from the spec (not the fallback),
  // validate it against the same policy used by the GraphQL/CLI loaders. A spec with
  // `servers: [{url: "http://169.254.169.254/..."}]` would otherwise cause every
  // dispatched tool call to hit cloud metadata or other internal infrastructure.
  if (fromSpec) {
    assertSafeUrl(baseUrl, {
      allowPrivate: options.allowPrivate === true,
      label: 'openapi server url',
    });
  }
  const paths = spec.paths || {};
  const tools = [];

  const allowedMethods = new Set(
    (options.methods || ['get', 'post', 'put', 'patch', 'delete']).map((m) => m.toLowerCase()),
  );

  for (const [pathTemplate, pathItem] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (method.startsWith('x-') || !allowedMethods.has(method)) continue;
      if (!operation || typeof operation !== 'object') continue;

      // Filter by tags
      if (options.tags?.length) {
        const opTags = operation.tags || [];
        if (!options.tags.some((t) => opTags.includes(t))) continue;
      }

      // Filter by include/exclude
      const opId = operation.operationId || '';
      if (options.include?.length) {
        if (!options.include.some((p) => opId.includes(p) || pathTemplate.includes(p))) continue;
      }
      if (options.exclude?.length) {
        if (options.exclude.some((p) => opId.includes(p) || pathTemplate.includes(p))) continue;
      }

      const tool = operationToTool(pathTemplate, method, operation, spec, isSwagger2, options);
      if (tool) tools.push(tool);
    }
  }

  // Dedup: warn-and-skip (or throw in strict mode) for tool names that collide
  // after toSnakeCase + sanitizeToolName normalization. Mirrors mixer.js:255–267.
  // Collision check runs after include/exclude/tag filters and after nameTransform,
  // so only actually-registered names are compared.
  const seenNames = new Map(); // name → first path seen
  const deduped = [];
  for (const tool of tools) {
    if (seenNames.has(tool.name)) {
      const firstPath = seenNames.get(tool.name);
      const msg =
        `OpenAPI operationId produces duplicate tool name "${tool.name}" ` +
        `(first: "${firstPath}", now: "${tool.path}"). Use distinct operationIds ` +
        `or the "nameTransform" option to disambiguate.`;
      if (options.strict) {
        throw new Error(msg);
      }
      process.stderr.write(`[40mcp:openapi] WARNING: ${msg} — skipping duplicate.\n`);
      continue;
    }
    seenNames.set(tool.name, tool.path);
    deduped.push(tool);
  }

  return { baseUrl, tools: deduped };
}

/**
 * Extract base URL from spec.
 * @returns {{baseUrl: string, fromSpec: boolean}} `fromSpec` is true when the URL was
 *   derived from spec data (and therefore needs SSRF validation); false when the
 *   localhost fallback was used because the spec declared no server.
 */
function extractBaseUrl(spec, isSwagger2) {
  if (isSwagger2) {
    const fromSpec = !!spec.host;
    const scheme = spec.schemes?.[0] || 'https';
    const host = spec.host || 'localhost';
    const basePath = spec.basePath || '';
    return { baseUrl: `${scheme}://${host}${basePath}`, fromSpec };
  }

  // OpenAPI 3.x
  const server = spec.servers?.[0];
  if (server?.url) {
    return { baseUrl: server.url, fromSpec: true };
  }
  return { baseUrl: 'http://localhost', fromSpec: false };
}

/** Convert an OpenAPI operation to a bridge tool definition. */
function operationToTool(pathTemplate, method, operation, spec, isSwagger2, options) {
  const operationId = operation.operationId || `${method}_${pathTemplate.replace(/[^a-zA-Z0-9]/g, '_')}`;

  // Build tool name: snake_case from operationId, strip path traversal characters,
  // then NFKC-normalize and filter to the MCP-safe charset to defeat zero-width
  // and homoglyph shadowing.
  const sanitizedOperationId = operationId.replace(/[/.\\]/g, '_');
  const rawName = options.nameTransform
    ? options.nameTransform(operationId, method, pathTemplate)
    : toSnakeCase(sanitizedOperationId);
  const name = sanitizeToolName(rawName);
  if (!name) return null; // empty/all-non-ASCII tool names are dropped

  // Sanitize description: spec-supplied summary/description fields flow into
  // the LLM tool list verbatim. Run them through the prompt-injection scanner
  // and replace matches with a neutral placeholder.
  const rawDescription = operation.summary || operation.description || `${method.toUpperCase()} ${pathTemplate}`;
  const description = sanitizeDescription(rawDescription, { label: 'openapi' });

  // Convert OpenAPI {param} to bridge :param syntax
  const bridgePath = pathTemplate.replace(/\{([^}]+)\}/g, ':$1');

  // Share a single `seen` Set across parameter-ref resolution and requestBody-ref
  // resolution for this operation so an attacker-crafted spec cannot spend the
  // 10-hop `MAX_REF_DEPTH` budget twice (once per call site). Previously each
  // function created its own Set, giving up to 2x the intended depth budget.
  const seen = new Set();

  // Collect parameters
  const parameters = resolveParameters(operation.parameters || [], spec, isSwagger2, seen);
  const { properties, required } = parametersToSchema(parameters);

  // For request body (OpenAPI 3.x), merge body fields into the schema
  const bodyMap = {};
  if (!isSwagger2 && operation.requestBody) {
    const bodySchema = extractRequestBodySchema(operation.requestBody, spec, seen);
    if (bodySchema?.properties) {
      for (const [prop, propSchema] of Object.entries(bodySchema.properties)) {
        const snakeName = toSnakeCase(prop);
        properties[snakeName] = simplifySchema(propSchema);
        if (snakeName !== prop) bodyMap[snakeName] = prop;
        if (bodySchema.required?.includes(prop)) required.push(snakeName);
      }
    }
  }

  // For Swagger 2.x body parameter
  if (isSwagger2) {
    const bodyParam = parameters.find((p) => p.in === 'body');
    if (bodyParam?.schema?.properties) {
      for (const [prop, propSchema] of Object.entries(bodyParam.schema.properties)) {
        const snakeName = toSnakeCase(prop);
        properties[snakeName] = simplifySchema(propSchema);
        if (snakeName !== prop) bodyMap[snakeName] = prop;
        if (bodyParam.schema.required?.includes(prop)) required.push(snakeName);
      }
    }
  }

  // Build queryMap for GET params that need renaming
  const queryMap = {};
  for (const param of parameters) {
    if (param.in === 'query') {
      const snakeName = toSnakeCase(param.name);
      if (snakeName !== param.name) queryMap[snakeName] = param.name;
    }
  }

  const tool = {
    name,
    description,
    method: method.toUpperCase(),
    path: bridgePath,
    inputSchema: {
      type: 'object',
      properties,
      required: [...new Set(required)],
    },
  };

  if (Object.keys(queryMap).length > 0) tool.queryMap = queryMap;
  if (Object.keys(bodyMap).length > 0) tool.bodyMap = bodyMap;

  return tool;
}

/** Maximum $ref resolution depth to prevent circular reference DoS */
const MAX_REF_DEPTH = 10;

/** Resolve $ref in parameters. */
function resolveParameters(params, spec, _isSwagger2, seen = new Set()) {
  return params.reduce((acc, p) => {
    if (p.$ref) {
      if (seen.has(p.$ref) || seen.size >= MAX_REF_DEPTH) {
        process.stderr.write(`[40mcp] warning: circular or deep $ref skipped: ${p.$ref}\n`);
        return acc;
      }
      seen.add(p.$ref);
      const refPath = p.$ref.replace('#/', '').split('/');
      const resolved = resolveRefPath(refPath, spec);
      if (resolved == null) return acc;
      acc.push(resolved);
    } else {
      acc.push(p);
    }
    return acc;
  }, []);
}

/** Convert OpenAPI parameters to JSON Schema properties. */
function parametersToSchema(parameters) {
  // Build `properties` without a prototype so a spec-supplied parameter named
  // e.g. `constructor` or `__proto__` cannot shadow inherited Object keys.
  // `validateToolArgs` now uses hasOwnProperty, but defence-in-depth here
  // prevents downstream consumers from accidentally walking the chain.
  const properties = Object.create(null);
  const required = [];

  for (const param of parameters) {
    if (!param || !param.name) continue; // Skip null/malformed parameters
    if (param.in === 'body') continue; // Handled separately
    if (param.in === 'header' || param.in === 'cookie') continue; // Skip header/cookie params

    const snakeName = toSnakeCase(param.name);
    // Drop any parameter whose converted name collides with a reserved
    // JS object key. Without this, `toSnakeCase("constructor")` ==
    // "constructor" sets `properties.constructor` which, on a plain
    // object, would shadow `Object.prototype.constructor` — a
    // footgun for any downstream code still using `args[key]` reads.
    if (DANGEROUS_KEYS.has(snakeName)) {
      process.stderr.write(
        `[40mcp] openapi: dropped parameter "${param.name}" — reserved JS object key\n`,
      );
      continue;
    }
    properties[snakeName] = {
      type: param.schema?.type || param.type || 'string',
      description: param.description || undefined,
    };
    if (param.schema?.enum || param.enum) {
      properties[snakeName].enum = param.schema?.enum || param.enum;
    }
    if (param.required) required.push(snakeName);
  }

  return { properties, required };
}

/** Extract JSON Schema from OpenAPI 3.x requestBody. */
function extractRequestBodySchema(requestBody, spec, seen = new Set()) {
  if (requestBody.$ref) {
    if (seen.has(requestBody.$ref) || seen.size >= MAX_REF_DEPTH) {
      process.stderr.write(`[40mcp] warning: circular or deep $ref skipped: ${requestBody.$ref}\n`);
      return null;
    }
    seen.add(requestBody.$ref);
    const refPath = requestBody.$ref.replace('#/', '').split('/');
    const resolved = resolveRefPath(refPath, spec);
    if (resolved == null) return null;
    requestBody = resolved;
  }

  const content = requestBody.content || {};
  const jsonContent = content['application/json'] || content['*/*'];
  if (!jsonContent?.schema) return null;

  let schema = jsonContent.schema;
  if (schema.$ref) {
    if (seen.has(schema.$ref) || seen.size >= MAX_REF_DEPTH) {
      process.stderr.write(`[40mcp] warning: circular or deep $ref skipped: ${schema.$ref}\n`);
      return null;
    }
    seen.add(schema.$ref);
    const refPath = schema.$ref.replace('#/', '').split('/');
    const resolved = resolveRefPath(refPath, spec);
    if (resolved == null) return null;
    schema = resolved;
  }

  return schema;
}

/**
 * Simplify a schema for MCP tool inputSchema (drop deep nesting).
 * Preserve all JSON Schema constraints that `validateToolArgs` enforces.
 */
function simplifySchema(schema) {
  const result = { type: schema.type || 'string' };
  if (schema.description) result.description = schema.description;
  if (schema.enum) result.enum = schema.enum;
  if (schema.default !== undefined) result.default = schema.default;
  // Preserve validation constraints so validateToolArgs enforces them.
  if (schema.pattern !== undefined) result.pattern = schema.pattern;
  if (schema.minLength !== undefined) result.minLength = schema.minLength;
  if (schema.maxLength !== undefined) result.maxLength = schema.maxLength;
  if (schema.minimum !== undefined) result.minimum = schema.minimum;
  if (schema.maximum !== undefined) result.maximum = schema.maximum;
  if (schema.exclusiveMinimum !== undefined) result.exclusiveMinimum = schema.exclusiveMinimum;
  if (schema.exclusiveMaximum !== undefined) result.exclusiveMaximum = schema.exclusiveMaximum;
  if (schema.multipleOf !== undefined) result.multipleOf = schema.multipleOf;
  if (schema.minItems !== undefined) result.minItems = schema.minItems;
  if (schema.maxItems !== undefined) result.maxItems = schema.maxItems;
  if (schema.uniqueItems !== undefined) result.uniqueItems = schema.uniqueItems;
  if (schema.format !== undefined) result.format = schema.format;
  return result;
}

// toSnakeCase imported from core/path.js (S5: shared utility)
