import { toSnakeCase } from '../core/path.js';
import { assertSafeUrl } from '../core/env.js';
import { sanitizeDescription, sanitizeToolName } from '../core/sanitize.js';
import { DANGEROUS_KEYS } from '../core/object.js';

/**
 * Load a GraphQL schema and convert to 40mcp tool definitions.
 *
 * @param {string|object} endpointOrSchema - GraphQL endpoint URL or parsed introspection result
 * @param {object} [options]
 * @param {string[]} [options.include] - Only include operations matching these names
 * @param {string[]} [options.exclude] - Exclude operations matching these names
 * @param {string[]} [options.types] - 'query' | 'mutation' | both (default: both)
 * @param {object} [options.headers] - Headers for introspection request (e.g., auth)
 * @param {Function} [options.nameTransform] - Custom name transform
 * @returns {Promise<{ baseUrl: string, tools: object[] }>}
 */
export async function loadGraphqlSchema(endpointOrSchema, options = {}) {
  let schema;
  let endpoint;

  if (typeof endpointOrSchema === 'string') {
    endpoint = endpointOrSchema;
    assertSafeUrl(endpoint, { allowPrivate: options.allowPrivate === true, label: 'graphql endpoint' });
    schema = await fetchIntrospection(endpoint, options.headers);
  } else {
    schema = endpointOrSchema;
    endpoint = options.endpoint || '/graphql';
  }

  const maxTools = options.maxTools || 200;
  const tools = [];
  const introspection = schema.__schema || schema;

  // Determine which operation types to include
  const includeQuery = !options.types || options.types.includes('query');
  const includeMutation = !options.types || options.types.includes('mutation');

  // Process query type
  if (includeQuery && introspection.queryType) {
    const queryTypeName = introspection.queryType.name;
    const queryType = introspection.types.find((t) => t.name === queryTypeName);
    if (queryType?.fields) {
      for (const field of queryType.fields) {
        if (tools.length >= maxTools) break;
        const tool = fieldToTool(field, 'query', endpoint, options);
        if (tool) tools.push(tool);
      }
    }
  }

  // Process mutation type
  if (includeMutation && introspection.mutationType) {
    const mutationTypeName = introspection.mutationType.name;
    const mutationType = introspection.types.find((t) => t.name === mutationTypeName);
    if (mutationType?.fields) {
      for (const field of mutationType.fields) {
        if (tools.length >= maxTools) break;
        const tool = fieldToTool(field, 'mutation', endpoint, options);
        if (tool) tools.push(tool);
      }
    }
  }

  if (tools.length >= maxTools) {
    process.stderr.write(
      `[40mcp] WARNING: GraphQL schema has more than ${maxTools} operations. ` +
      `Only the first ${maxTools} tools were generated. Use options.maxTools to increase the limit, ` +
      `or options.include/exclude to filter specific operations.\n`,
    );
  }

  return { baseUrl: endpoint, tools };
}

/**
 * Fetch introspection result from a GraphQL endpoint.
 */
async function fetchIntrospection(endpoint, headers = {}) {
  const query = `
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            description
            args {
              name
              description
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
              }
              defaultValue
            }
            type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  `;

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify({ query }),
    signal: AbortSignal.timeout(30_000),
  });

  if (!response.ok) {
    throw new Error(`GraphQL introspection failed: ${response.status} ${response.statusText}`);
  }

  const json = await response.json();
  if (json.errors) {
    throw new Error(`GraphQL introspection error: ${JSON.stringify(json.errors)}`);
  }

  // Validate the introspection result structure before trusting it.
  // An attacker-controlled endpoint could return arbitrary JSON to poison the schema loader.
  if (!json.data || typeof json.data !== 'object') {
    throw new Error(`GraphQL introspection response from "${endpoint}" is missing a "data" field`);
  }
  const schemaField = json.data.__schema;
  if (!schemaField || typeof schemaField !== 'object') {
    throw new Error(`GraphQL introspection response from "${endpoint}" is missing "__schema"`);
  }
  if (schemaField.types !== undefined && !Array.isArray(schemaField.types)) {
    throw new Error(`GraphQL introspection "__schema.types" from "${endpoint}" must be an array`);
  }
  if (schemaField.queryType !== undefined && (typeof schemaField.queryType !== 'object' || Array.isArray(schemaField.queryType))) {
    throw new Error(`GraphQL introspection "__schema.queryType" from "${endpoint}" must be an object`);
  }
  if (schemaField.mutationType !== undefined && schemaField.mutationType !== null && (typeof schemaField.mutationType !== 'object' || Array.isArray(schemaField.mutationType))) {
    throw new Error(`GraphQL introspection "__schema.mutationType" from "${endpoint}" must be an object or null`);
  }

  return json.data;
}

/**
 * Convert a GraphQL field (query or mutation) to a tool definition.
 */
function fieldToTool(field, operationType, endpoint, options) {
  // Filter by include/exclude
  if (options.include?.length) {
    if (!options.include.some((p) => field.name.includes(p))) return null;
  }
  if (options.exclude?.length) {
    if (options.exclude.some((p) => field.name.includes(p))) return null;
  }

  const rawName = options.nameTransform ? options.nameTransform(field.name, operationType) : toSnakeCase(field.name);
  const name = sanitizeToolName(rawName);
  if (!name) return null; // drop fields whose names normalize to empty (homoglyph defence)

  // Sanitize description: GraphQL field descriptions are attacker-controlled
  // when the schema comes from an untrusted endpoint and flow into the LLM
  // tool list verbatim.
  const rawDescription = field.description || `${operationType === 'query' ? 'Query' : 'Mutation'}: ${field.name}`;
  const description = sanitizeDescription(rawDescription, { label: 'graphql' });

  const { properties, required } = argsToSchema(field.args || []);

  // Validate field.name is a valid GraphQL identifier before storing as
  // `operation` — it is later string-interpolated into a GraphQL query body.
  // An attacker-controlled introspection response can return any string as a
  // field name; without this guard an adversary can inject arbitrary GraphQL
  // syntax (e.g. `foo } mutation { deleteAll`).
  const GQL_NAME_RE = /^[_A-Za-z][_0-9A-Za-z]*$/;
  if (!GQL_NAME_RE.test(field.name)) {
    process.stderr.write(
      `[40mcp] graphql: dropped field "${sanitizeToolName(field.name) || '(unnamed)'}" — invalid GraphQL identifier\n`,
    );
    return null;
  }

  const tool = {
    name,
    description,
    method: operationType === 'mutation' ? 'MUTATION' : 'QUERY',
    path: endpoint,
    graphql: {
      operation: field.name, // safe: GQL_NAME_RE validated above
      type: operationType,
    },
    inputSchema: {
      type: 'object',
      properties,
      required: [...new Set(required)],
    },
  };

  return tool;
}

/**
 * Convert GraphQL field arguments to JSON Schema properties.
 */
function argsToSchema(args) {
  // Build `properties` without a prototype so an attacker-controlled GraphQL
  // introspection response containing an argument named `__proto__` /
  // `constructor` / `prototype` cannot rebind the prototype of the generated
  // schema object. V8 treats `plain.__proto__ = x` as a setter that rewrites
  // the prototype, not as a regular own-property assignment.
  const properties = Object.create(null);
  const required = [];

  for (const arg of args) {
    if (!arg || typeof arg.name !== 'string') continue;
    if (DANGEROUS_KEYS.has(arg.name)) {
      process.stderr.write(
        `[40mcp] graphql: dropped argument "${arg.name}" — reserved JS object key\n`,
      );
      continue;
    }
    const propSchema = typeToJsonSchema(arg.type);
    properties[arg.name] = propSchema;
    if (propSchema._required) {
      required.push(arg.name);
      delete propSchema._required;
    }
    if (arg.description) {
      // Argument descriptions are also attacker-controlled when the schema comes
      // from an untrusted endpoint. Apply the same sanitizeDescription guard
      // used for field-level descriptions above.
      propSchema.description = sanitizeDescription(arg.description, { label: 'graphql arg' });
    }
  }

  return { properties, required };
}

/**
 * Convert a GraphQL type to JSON Schema type definition.
 * Handles NON_NULL and LIST wrappers recursively.
 * An attacker-controlled introspection response can return arbitrarily deep
 * NON_NULL/LIST wrapper chains that could cause a stack overflow. Flatten
 * anything deeper than MAX_GQL_TYPE_DEPTH.
 */
const MAX_GQL_TYPE_DEPTH = 20;

function typeToJsonSchema(gqlType, _depth = 0) {
  if (!gqlType) return { type: 'string' };
  if (_depth > MAX_GQL_TYPE_DEPTH) return { type: 'string' }; // flatten over-nested types

  // Handle NON_NULL wrapper
  if (gqlType.kind === 'NON_NULL') {
    const inner = typeToJsonSchema(gqlType.ofType, _depth + 1);
    inner._required = true;
    return inner;
  }

  // Handle LIST wrapper
  if (gqlType.kind === 'LIST') {
    return {
      type: 'array',
      items: typeToJsonSchema(gqlType.ofType, _depth + 1),
    };
  }

  // Handle scalar/enum types
  const scalarMapping = {
    String: 'string',
    Int: 'integer',
    Float: 'number',
    Boolean: 'boolean',
    ID: 'string',
  };

  if (scalarMapping[gqlType.name]) {
    return { type: scalarMapping[gqlType.name] };
  }

  // INPUT_OBJECT or other complex types: use object type
  if (gqlType.kind === 'INPUT_OBJECT' || gqlType.kind === 'OBJECT') {
    return { type: 'object' };
  }

  // Default for unknown types
  return { type: 'string' };
}

// toSnakeCase imported from core/path.js (S5: shared utility)
