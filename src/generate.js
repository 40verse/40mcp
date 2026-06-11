/**
 * AI-assisted tool definition — describe what you want, get a 40mcp config.
 *
 * Generates a structured system prompt + user prompt that any LLM can use
 * to produce a valid 40mcp tool config. Model-agnostic — works with Claude,
 * GPT, Gemini, local models, or any chat completion API.
 *
 * @module generate
 */

import { validateConfig } from './validate.js';
import { toSnakeCase } from './core/path.js';
import { assertSafeUrl } from './core/env.js';
import { sanitizeDescription } from './core/sanitize.js';
import { DANGEROUS_KEYS } from './core/object.js';

/**
 * The system prompt that teaches an LLM how to generate 40mcp configs.
 * Produces valid, well-formed tool configurations.
 */
export const GENERATE_SYSTEM_PROMPT = `You are a 40mcp config generator. You produce JSON tool configurations for the 40mcp universal API-to-MCP bridge.

## Output Format

You MUST output ONLY valid JSON — no markdown, no explanation, no code fences. The JSON must be a complete 40mcp config:

{
  "configVersion": 1,
  "name": "service-name",
  "version": "1.0.0",
  "baseUrl": "https://api.example.com",
  "auth": { "type": "bearer", "envVar": "SERVICE_API_KEY" },
  "tools": [ ... ]
}

(\`configVersion\` is the config-schema version — currently always 1 — and is distinct from \`version\`, which is the MCP server-version string shown to clients.)

## Tool Definition Schema

Each tool in the "tools" array:

{
  "name": "snake_case_name",
  "description": "Clear description of what this tool does. Be specific — AI agents read this.",
  "method": "GET|POST|PUT|PATCH|DELETE",
  "path": "/api/resource/:param_name",
  "queryMap": { "tool_arg_name": "api_query_param" },
  "bodyMap": { "tool_arg_name": "api_body_field" },
  "response": { "pick": ["field1", "field2"], "limit": 25, "summary": true, "tokenBudget": 4000 },
  "policy": "require_approval",
  "inputSchema": {
    "type": "object",
    "properties": {
      "param_name": { "type": "string", "description": "What this param does" }
    },
    "required": ["param_name"]
  }
}

## Rules

1. **Tool names**: snake_case, verb_noun format (list_users, get_order, create_issue)
2. **Path params**: Use :param_name syntax. Every path param MUST appear in inputSchema.properties
3. **queryMap**: For GET requests, map tool arg names to API query parameter names when they differ
4. **bodyMap**: For POST/PUT/PATCH, map tool arg names to API body field names when they differ
5. **Response transforms**: Use "pick" to select only useful fields (reduce token usage). Use "limit" on list endpoints. Use "tokenBudget" on heavy endpoints.
6. **Auth**: Use envVar for credentials, NEVER hardcode values. Common patterns:
   - Bearer: { "type": "bearer", "envVar": "SERVICE_TOKEN" }
   - API Key header: { "type": "header", "header": "X-API-Key", "envVar": "SERVICE_KEY" }
   - Basic: { "type": "basic", "envVar": "SERVICE_CREDS" }
   - OAuth2: { "type": "oauth2", "tokenUrl": "...", "clientIdEnv": "...", "clientSecretEnv": "..." }
7. **Policy gating**: Add "policy": "require_approval" to tools that:
   - Create, update, or delete resources
   - Spend money or transfer assets
   - Send messages to external parties
   - Modify permissions or access control
8. **Descriptions**: Write for AI agents. Include what the tool returns, not just what it does.
9. **inputSchema**: Always include type, properties, required. Use enums for fixed choices.
10. **Compound chains**: For multi-step operations, use chain definitions:
    { "name": "full_profile", "chain": [{ "call": "get_user", "as": "user", "args": { "id": "$args.id" } }, ...] }

## Common Patterns

- List endpoints: GET with limit/offset query params, response transform with pick + limit + summary
- Detail endpoints: GET with :id path param, response transform with pick
- Create endpoints: POST with bodyMap, policy: require_approval
- Search endpoints: GET with query param mapped via queryMap
- Pagination: Use queryMap for cursor/offset params`;

/**
 * Build a user prompt for the LLM from the user's description.
 *
 * @param {object} options
 * @param {string} options.description - Natural language description of the API
 * @param {string} [options.baseUrl] - Known base URL
 * @param {string} [options.authType] - Known auth type
 * @param {string} [options.apiDocs] - Paste of API documentation text
 * @param {string[]} [options.endpoints] - Known endpoint list
 * @param {string} [options.style] - 'minimal' | 'comprehensive' (default: comprehensive)
 * @returns {string} User prompt
 */
export function buildGeneratePrompt(options) {
  const { description, baseUrl, authType, apiDocs, endpoints, style = 'comprehensive' } = options;

  let prompt = `Generate a 40mcp config for: ${description}\n\n`;

  if (baseUrl) prompt += `Base URL: ${baseUrl}\n`;
  if (authType) prompt += `Auth type: ${authType}\n`;

  if (endpoints && endpoints.length > 0) {
    prompt += `\nKnown endpoints:\n`;
    for (const ep of endpoints) {
      prompt += `- ${ep}\n`;
    }
  }

  if (apiDocs) {
    prompt += `\nAPI documentation:\n${apiDocs.slice(0, 8000)}\n`;
  }

  if (style === 'minimal') {
    prompt += `\nGenerate only the most essential 3-5 tools for this API.`;
  } else {
    prompt += `\nGenerate a comprehensive config covering all major CRUD operations, list/search endpoints, and any useful compound chains.`;
  }

  prompt += `\nInclude response transforms (pick, limit, tokenBudget) to keep token usage efficient.`;
  prompt += `\nMark write operations with "policy": "require_approval".`;
  prompt += `\nOutput ONLY the JSON config — no markdown, no explanation.`;

  return prompt;
}

/**
 * Parse and validate LLM-generated config output.
 * Handles common LLM output issues (markdown fences, preamble text, etc.)
 *
 * @param {string} llmOutput - Raw LLM response text
 * @returns {{ config: object|null, valid: boolean, errors: string[], warnings: string[] }}
 */
export function parseGeneratedConfig(llmOutput) {
  if (!llmOutput || typeof llmOutput !== 'string') {
    return { config: null, valid: false, errors: ['Empty LLM output'], warnings: [] };
  }

  // Strip markdown code fences
  let cleaned = llmOutput.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*\n?/m, '');
  cleaned = cleaned.replace(/\n?```\s*$/m, '');

  // Try to find JSON object in the output
  const jsonStart = cleaned.indexOf('{');
  const jsonEnd = cleaned.lastIndexOf('}');

  if (jsonStart === -1 || jsonEnd === -1) {
    return { config: null, valid: false, errors: ['No JSON object found in LLM output'], warnings: [] };
  }

  const jsonStr = cleaned.substring(jsonStart, jsonEnd + 1);

  let config;
  try {
    config = JSON.parse(jsonStr);
  } catch (err) {
    return { config: null, valid: false, errors: [`JSON parse error: ${err.message}`], warnings: [] };
  }

  // Validate with 40mcp validator
  const validation = validateConfig(config);

  return {
    config: validation.valid ? config : null,
    valid: validation.valid,
    errors: validation.errors,
    warnings: validation.warnings,
  };
}

/**
 * Generate a complete prompt pair (system + user) for any LLM.
 *
 * Usage with Claude API:
 *   const { system, user } = generatePrompt({ description: 'Stripe payments API' });
 *   const response = await anthropic.messages.create({
 *     model: 'claude-sonnet-4-20250514',
 *     system,
 *     messages: [{ role: 'user', content: user }],
 *   });
 *   const { config } = parseGeneratedConfig(response.content[0].text);
 *
 * Usage with OpenAI API:
 *   const { system, user } = generatePrompt({ description: 'GitHub REST API' });
 *   const response = await openai.chat.completions.create({
 *     model: 'gpt-4o',
 *     messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
 *   });
 *   const { config } = parseGeneratedConfig(response.choices[0].message.content);
 *
 * @param {object} options - Same as buildGeneratePrompt
 * @returns {{ system: string, user: string }}
 */
export function generatePrompt(options) {
  return {
    system: GENERATE_SYSTEM_PROMPT,
    user: buildGeneratePrompt(options),
  };
}

/**
 * Generate a config from an OpenAPI spec using the structured prompt.
 * This is a deterministic fallback — no LLM needed, just smart defaults.
 *
 * @param {object} spec - Parsed OpenAPI spec
 * @param {object} [options]
 * @param {boolean} [options.policyGateWrites=true] - Add require_approval to write endpoints
 * @param {boolean} [options.addTransforms=true] - Add response transforms
 * @param {number} [options.tokenBudget=4000] - Default token budget for list endpoints
 * @returns {object} 40mcp config
 */
export function generateFromSpec(spec, options = {}) {
  const {
    policyGateWrites = true,
    addTransforms = true,
    tokenBudget = 4000,
  } = options;

  const info = spec.info || {};
  const servers = spec.servers || [];
  const baseUrl = servers[0]?.url || '';

  // SSRF guard: validate spec-derived base URL against the same policy used by
  // openapi.js. A spec with servers[0].url = "http://169.254.169.254/..." would
  // otherwise cause every dispatched tool call to hit cloud metadata or other
  // internal infrastructure. Only validate when the spec actually supplies a URL.
  if (baseUrl) {
    assertSafeUrl(baseUrl, {
      allowPrivate: options.allowPrivate === true,
      label: 'generateFromSpec server url',
    });
  }

  const paths = spec.paths || {};

  const tools = [];

  for (const [pathTemplate, methods] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (['get', 'post', 'put', 'patch', 'delete'].indexOf(method.toLowerCase()) === -1) continue;

      const httpMethod = method.toUpperCase();
      const operationId = operation.operationId || generateOperationId(httpMethod, pathTemplate);
      const name = toSnakeCase(operationId);

      const tool = {
        name,
        // Sanitize description: spec-supplied summary/description fields flow into
        // the LLM tool list verbatim. Run through the prompt-injection scanner and
        // replace matches with a neutral placeholder. Mirrors openapi.js:188-189.
        description: sanitizeDescription(
          operation.summary || operation.description || `${httpMethod} ${pathTemplate}`,
          { label: 'generateFromSpec' },
        ),
        method: httpMethod,
        path: pathTemplate.replace(/\{([^}]+)\}/g, ':$1'),
        // Use null-prototype object so spec-controlled parameter names (e.g.
        // "__proto__", "constructor") cannot shadow Object.prototype keys.
        // Mirrors openapi.js parametersToSchema (openapi.js:287).
        inputSchema: { type: 'object', properties: Object.create(null), required: [] },
      };

      // Extract parameters
      const params = [...(operation.parameters || []), ...(methods.parameters || [])];
      const queryMap = {};

      for (const param of params) {
        if (!param || !param.name) continue;
        const propName = toSnakeCase(param.name);
        // Drop any parameter whose converted name collides with a reserved
        // JS object key. Mirrors openapi.js parametersToSchema:300-305.
        if (DANGEROUS_KEYS.has(propName)) {
          process.stderr.write(
            `[40mcp] generateFromSpec: dropped parameter "${param.name}" — reserved JS object key\n`,
          );
          continue;
        }
        tool.inputSchema.properties[propName] = {
          type: param.schema?.type || 'string',
          description: param.description || param.name,
        };
        if (param.schema?.enum) {
          tool.inputSchema.properties[propName].enum = param.schema.enum;
        }
        if (param.required) {
          tool.inputSchema.required.push(propName);
        }
        if (param.in === 'query' && propName !== param.name) {
          queryMap[propName] = param.name;
        }
      }

      if (Object.keys(queryMap).length > 0) {
        tool.queryMap = queryMap;
      }

      // Extract request body for POST/PUT/PATCH
      if (operation.requestBody && ['POST', 'PUT', 'PATCH'].includes(httpMethod)) {
        const content = operation.requestBody.content?.['application/json'];
        if (content?.schema?.properties) {
          const bodyMap = {};
          for (const [fieldName, fieldSchema] of Object.entries(content.schema.properties)) {
            const propName = toSnakeCase(fieldName);
            // Drop reserved JS object keys. Mirrors openapi.js parametersToSchema:300-305.
            if (DANGEROUS_KEYS.has(propName)) {
              process.stderr.write(
                `[40mcp] generateFromSpec: dropped body field "${fieldName}" — reserved JS object key\n`,
              );
              continue;
            }
            tool.inputSchema.properties[propName] = {
              type: fieldSchema.type || 'string',
              description: fieldSchema.description || fieldName,
            };
            if (propName !== fieldName) {
              bodyMap[propName] = fieldName;
            }
          }
          if (content.schema.required) {
            for (const req of content.schema.required) {
              const snaked = toSnakeCase(req);
              if (!tool.inputSchema.required.includes(snaked)) {
                tool.inputSchema.required.push(snaked);
              }
            }
          }
          if (Object.keys(bodyMap).length > 0) {
            tool.bodyMap = bodyMap;
          }
        }
      }

      // Add response transforms for list endpoints
      if (addTransforms && httpMethod === 'GET') {
        const responseSchema = operation.responses?.['200']?.content?.['application/json']?.schema;
        if (responseSchema?.type === 'array' || responseSchema?.properties?.items || responseSchema?.properties?.data) {
          tool.response = { limit: 25, summary: true, tokenBudget };
        }
      }

      // Policy gate write operations
      if (policyGateWrites && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(httpMethod)) {
        tool.policy = 'require_approval';
      }

      tools.push(tool);
    }
  }

  // Detect auth from securityDefinitions / components.securitySchemes
  let auth;
  const schemes = spec.components?.securitySchemes || spec.securityDefinitions || {};
  const firstScheme = Object.values(schemes)[0];
  if (firstScheme) {
    if (firstScheme.type === 'http' && firstScheme.scheme === 'bearer') {
      auth = { type: 'bearer', envVar: `${toEnvVar(info.title || 'API')}_TOKEN` };
    } else if (firstScheme.type === 'apiKey') {
      // Strip CRLF from spec-supplied header name to prevent HTTP response splitting.
      // A spec with name: "X-API-Key\r\nInjected-Header: evil" would otherwise
      // write a raw newline into the HTTP header on every outbound call.
      const rawHeaderName = typeof firstScheme.name === 'string'
        ? firstScheme.name.replace(/[\r\n]/g, '')
        : 'X-API-Key';
      auth = { type: 'header', header: rawHeaderName || 'X-API-Key', envVar: `${toEnvVar(info.title || 'API')}_KEY` };
    } else if (firstScheme.type === 'oauth2') {
      const flows = firstScheme.flows || {};
      const ccFlow = flows.clientCredentials || flows.application;
      if (ccFlow) {
        auth = {
          type: 'oauth2',
          tokenUrl: ccFlow.tokenUrl,
          clientIdEnv: `${toEnvVar(info.title || 'API')}_CLIENT_ID`,
          clientSecretEnv: `${toEnvVar(info.title || 'API')}_CLIENT_SECRET`,
          scope: Object.keys(ccFlow.scopes || {}).join(' '),
        };
      }
    }
  }

  return {
    // configVersion is the schema version (issue #47), distinct from the
    // server-version string carried by `version`. Emit it explicitly so
    // generated configs are pinned to the schema they were written against.
    configVersion: 1,
    name: toSnakeCase(info.title || 'api-bridge'),
    version: info.version || '1.0.0',
    baseUrl,
    ...(auth ? { auth } : {}),
    tools,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function toEnvVar(str) {
  // An OpenAPI spec's `info.title` flows into this function unbounded.
  // Cap the result at 64 characters so an attacker-crafted 100k-character title
  // can't produce absurd env var names. Fall back to `API` when the title
  // normalizes to empty or to an `_`-only string (which would collide with
  // the POSIX `$_` builtin).
  const cleaned = String(str || '').replace(/[^a-zA-Z0-9]+/g, '_').toUpperCase();
  const trimmed = cleaned.replace(/^_+|_+$/g, '');
  if (!trimmed) return 'API';
  return trimmed.slice(0, 64);
}

function generateOperationId(method, path) {
  const allParts = path.split('/').filter(Boolean);
  const nonParamParts = allParts.filter((p) => !p.startsWith('{') && !p.startsWith(':'));
  const resource = nonParamParts[nonParamParts.length - 1] || 'resource';
  const hasIdParam = allParts.some((p) => p.startsWith('{') || p.startsWith(':'));
  switch (method) {
    case 'GET': return hasIdParam ? `get_${resource}` : `list_${resource}`;
    case 'POST': return `create_${resource}`;
    case 'PUT': case 'PATCH': return `update_${resource}`;
    case 'DELETE': return `delete_${resource}`;
    default: return `${method.toLowerCase()}_${resource}`;
  }
}
