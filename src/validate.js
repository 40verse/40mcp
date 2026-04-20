/**
 * Config validation — catch misconfigurations early with actionable errors.
 *
 * @module validate
 */

import { BridgeError, BridgeErrorCode } from './errors.js';
import { hasPromptInjection } from './core/sanitize.js';

const VALID_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const VALID_AUTH_TYPES = new Set(['header', 'bearer', 'basic', 'oauth2', 'sealed', 'sealed-bearer']);
const VALID_TRANSPORT_TYPES = new Set(['stdio', 'sse']);
const VALID_POLICY_VALUES = new Set(['allow', 'deny', 'require_approval', 'log_only']);
const VALID_STEERING_KEYS = new Set(['write', 'prehook', 'posthook', 'authority']);
const TOOL_NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_]*$/;
const PATH_PARAM_PATTERN = /:([a-zA-Z_][a-zA-Z0-9_]*)/;

/**
 * Validate a bridge config and return actionable errors/warnings.
 *
 * @param {object} config - BridgeConfig object
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateConfig(config) {
  const errors = [];
  const warnings = [];

  if (!config || typeof config !== 'object') {
    return { valid: false, errors: ['Config must be an object'], warnings: [] };
  }

  // Name
  if (config.name && typeof config.name !== 'string') {
    errors.push('config.name must be a string');
  }

  // BaseUrl
  if (!config.baseUrl && !(Array.isArray(config.tools) && config.tools.every((t) => t.chain))) {
    errors.push('config.baseUrl is required (unless all tools are chain-only)');
  }
  if (config.baseUrl && typeof config.baseUrl === 'string') {
    if (!config.baseUrl.startsWith('http://') && !config.baseUrl.startsWith('https://') && !config.baseUrl.startsWith('${')) {
      warnings.push(`config.baseUrl "${config.baseUrl}" does not start with http:// or https:// — is this intentional?`);
    }
  }

  // Auth
  if (config.auth) {
    if (!VALID_AUTH_TYPES.has(config.auth.type)) {
      errors.push(`config.auth.type "${config.auth.type}" is invalid. Must be one of: ${[...VALID_AUTH_TYPES].join(', ')}`);
    }
    if (config.auth.type === 'header' && !config.auth.header) {
      errors.push('config.auth.header is required when auth.type is "header"');
    }
    if (config.auth.type === 'oauth2' && !config.auth.tokenUrl) {
      errors.push('config.auth.tokenUrl is required when auth.type is "oauth2"');
    }
    if (config.auth.type === 'sealed') {
      if (!config.auth.name) errors.push('config.auth.name is required when auth.type is "sealed"');
      if (!config.auth.header) errors.push('config.auth.header is required when auth.type is "sealed"');
    }
    if (config.auth.type === 'sealed-bearer') {
      if (!config.auth.name) errors.push('config.auth.name is required when auth.type is "sealed-bearer"');
    }
    if (config.auth.value && !config.auth.envVar) {
      warnings.push('config.auth.value is set without auth.envVar — credentials may be committed to source control. Use envVar instead.');
    }
  }

  // Transport
  if (config.transport) {
    if (config.transport.type && !VALID_TRANSPORT_TYPES.has(config.transport.type)) {
      errors.push(`config.transport.type "${config.transport.type}" is invalid. Must be: ${[...VALID_TRANSPORT_TYPES].join(', ')}`);
    }
    if (config.transport.type === 'sse' && config.transport.port !== undefined) {
      // Require an integer in the valid range. NaN is typeof 'number' but
      // NaN < 0 and NaN > 65535 are both false, so it would pass a naive
      // numeric check. Similarly, a typo upstream like parseInt("abc") could
      // produce NaN. httpServer.listen(NaN, ...) would bind to an OS-chosen
      // random port, masking the operator's intent.
      if (
        !Number.isInteger(config.transport.port) ||
        config.transport.port < 0 ||
        config.transport.port > 65535
      ) {
        errors.push('config.transport.port must be an integer between 0 and 65535');
      }
    }
  }

  // Tools
  if (!Array.isArray(config.tools)) {
    errors.push('config.tools must be an array');
  } else {
    // Pre-collect all non-chain tool names so chain validation can reference them
    const allToolNames = new Set(config.tools.filter((t) => t.name && !t.chain).map((t) => t.name));
    const toolNames = new Set();

    for (let i = 0; i < config.tools.length; i++) {
      const tool = config.tools[i];
      const prefix = `tools[${i}]`;

      // Name
      if (!tool.name) {
        errors.push(`${prefix}: name is required`);
      } else {
        if (!TOOL_NAME_PATTERN.test(tool.name)) {
          warnings.push(`${prefix}: name "${tool.name}" should be snake_case (letters, numbers, underscores)`);
        }
        if (toolNames.has(tool.name)) {
          errors.push(`${prefix}: duplicate tool name "${tool.name}"`);
        }
        toolNames.add(tool.name);
      }

      // Chain tools vs regular tools
      if (tool.chain) {
        // Chain tool
        if (!Array.isArray(tool.chain)) {
          errors.push(`${prefix} "${tool.name}": chain must be an array`);
        } else {
          const stepNames = new Set();
          for (let j = 0; j < tool.chain.length; j++) {
            const step = tool.chain[j];
            if (!step.call) {
              errors.push(`${prefix} "${tool.name}": chain[${j}].call is required`);
            } else if (!allToolNames.has(step.call)) {
              warnings.push(`${prefix} "${tool.name}": chain[${j}].call "${step.call}" does not reference a tool in this config (may be valid if mixing servers)`);
            }
            if (!step.as) errors.push(`${prefix} "${tool.name}": chain[${j}].as is required`);
            if (step.as && stepNames.has(step.as)) {
              errors.push(`${prefix} "${tool.name}": duplicate chain step name "${step.as}"`);
            }
            if (step.as) stepNames.add(step.as);
          }
        }
      } else {
        // Regular tool
        if (!tool.method) {
          errors.push(`${prefix} "${tool.name}": method is required`);
        } else if (!VALID_METHODS.has(tool.method.toUpperCase()) && !tool.graphql) {
          errors.push(`${prefix} "${tool.name}": method "${tool.method}" is invalid. Must be: ${[...VALID_METHODS].join(', ')}`);
        }

        if (!tool.path) {
          errors.push(`${prefix} "${tool.name}": path is required`);
        } else {
          // Check path params are in inputSchema
          const pathParams = [];
          let match;
          const re = new RegExp(PATH_PARAM_PATTERN.source, 'g');
          while ((match = re.exec(tool.path))) {
            pathParams.push(match[1]);
          }
          const schemaProps = Object.keys(tool.inputSchema?.properties || {});
          for (const param of pathParams) {
            if (!schemaProps.includes(param)) {
              warnings.push(`${prefix} "${tool.name}": path param ":${param}" is not in inputSchema.properties`);
            }
          }
        }
      }

      // Policy
      if (tool.policy !== undefined && !VALID_POLICY_VALUES.has(tool.policy)) {
        errors.push(`${prefix} "${tool.name}": policy "${tool.policy}" is invalid. Must be: ${[...VALID_POLICY_VALUES].join(', ')}`);
      }

      // InputSchema
      if (!tool.inputSchema) {
        warnings.push(`${prefix} "${tool.name}": missing inputSchema (will default to empty object)`);
      } else if (tool.inputSchema && typeof tool.inputSchema === 'object') {
        // Verify required ⊆ properties — APIs (Claude, OpenAI) return HTTP 400 if a key
        // listed in required is absent from properties.
        const props = tool.inputSchema.properties || {};
        const required = tool.inputSchema.required;
        if (Array.isArray(required)) {
          const orphans = required.filter((k) => !Object.prototype.hasOwnProperty.call(props, k));
          if (orphans.length > 0) {
            errors.push(
              `${prefix} "${tool.name}": inputSchema.required contains keys not in properties: ${orphans.map((k) => `"${k}"`).join(', ')}. ` +
              `This will cause API 400 errors at runtime.`,
            );
          }
        }
      }

      // Description
      if (!tool.description) {
        warnings.push(`${prefix} "${tool.name}": missing description — AI agents need this to understand the tool`);
      }

      // Steering — optional opt-in. If present, sanity-check shape only;
      // the rich contract lives in src/steering/. This keeps validate.js
      // dependency-free while still catching obvious typos.
      if (tool.steering !== undefined) {
        if (typeof tool.steering !== 'object' || tool.steering === null || Array.isArray(tool.steering)) {
          errors.push(`${prefix} "${tool.name}": steering must be an object`);
        } else {
          for (const key of Object.keys(tool.steering)) {
            if (!VALID_STEERING_KEYS.has(key)) {
              warnings.push(`${prefix} "${tool.name}": steering.${key} is not a recognized key. Known keys: ${[...VALID_STEERING_KEYS].join(', ')}`);
            }
          }
          if (tool.steering.write !== undefined && typeof tool.steering.write !== 'boolean') {
            errors.push(`${prefix} "${tool.name}": steering.write must be a boolean`);
          }
          for (const hookKey of ['prehook', 'posthook']) {
            const hook = tool.steering[hookKey];
            if (hook === undefined || hook === null) continue;
            if (typeof hook !== 'string' && typeof hook !== 'object') {
              errors.push(`${prefix} "${tool.name}": steering.${hookKey} must be a string or object`);
            } else if (typeof hook === 'object' && typeof hook.instructions !== 'string') {
              errors.push(`${prefix} "${tool.name}": steering.${hookKey}.instructions must be a string`);
            }
            // Scan the steering instruction text for prompt-injection patterns —
            // steering strings flow into the LLM context as authoritative
            // instructions, so a malicious community config can use them as
            // a verbatim injection channel (steering scan).
            const text = typeof hook === 'string' ? hook : hook?.instructions;
            if (typeof text === 'string' && hasPromptInjection(text)) {
              errors.push(
                `${prefix} "${tool.name}": steering.${hookKey} contains prompt-injection pattern — ` +
                `steering text is rendered into the agent's context window verbatim and must not contain ` +
                `instructions that override prior context.`,
              );
            }
          }
          if (tool.steering.authority !== undefined && tool.steering.authority !== null) {
            const auth = tool.steering.authority;
            if (typeof auth !== 'string' && typeof auth !== 'object') {
              errors.push(`${prefix} "${tool.name}": steering.authority must be a preset name (string) or an inline spec (object)`);
            } else if (typeof auth === 'object' && !Array.isArray(auth.allowed_memory_types)) {
              errors.push(`${prefix} "${tool.name}": steering.authority.allowed_memory_types must be an array`);
            }
          }
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Validate and throw if config is invalid.
 * @param {object} config
 * @throws {BridgeError} if validation fails
 */
export function assertValidConfig(config) {
  const result = validateConfig(config);
  if (!result.valid) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `Invalid config: ${result.errors.join('; ')}`,
      { errors: result.errors, warnings: result.warnings },
    );
  }
  // Log warnings to stderr
  for (const warning of result.warnings) {
    process.stderr.write(`[40mcp] WARNING: ${warning}\n`);
  }
}
