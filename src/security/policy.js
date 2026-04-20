/**
 * Human-in-the-loop policy gate — intercept and approve/deny tool calls.
 *
 * Wraps a dispatch function with configurable policy rules:
 * - require_approval: blocks until human approves (stdin/callback/webhook)
 * - log_only: logs the call but allows it through
 * - deny: always blocks
 * - allow: always permits (default)
 *
 * Tools declare their policy via the `policy` field in tool config.
 * The policy gate reads this field and enforces the rule.
 *
 * @module security/policy
 */

import { BridgeError, BridgeErrorCode } from '../errors.js';

/**
 * Policy decision.
 * @typedef {'approve' | 'deny' | 'timeout'} PolicyDecision
 */

/**
 * Policy rule types.
 * @typedef {'allow' | 'deny' | 'require_approval' | 'log_only'} PolicyRule
 */

// Valid policy values. An empty-string policy passes the != null check
// but is not a recognised directive; it would fall through to defaultPolicy
// silently. Reject any value not in this set.
const VALID_POLICY_VALUES = new Set(['allow', 'deny', 'require_approval', 'log_only']);

/**
 * Compile sidecar `toolPolicies` into embedded `tool.policy` on the given
 * tool definitions, in place. Sidecar wins over any prior embedded value
 * (matching createPolicyGate's own precedence rule).
 *
 * Why this exists: the bridge's per-dispatch re-check reads only
 * `tool.policy` — it can't see sidecar rules passed to `createPolicyGate`.
 * Chain sub-dispatches only hit that re-check, so without this merge, a
 * sidecar `deny` / `require_approval` on a chained tool is bypassed.
 * Callers that feed sidecar policies through `createRestBridge` should
 * merge them onto tool defs first.
 *
 * @param {Array<object>} tools
 * @param {Record<string, PolicyRule>} toolPolicies
 * @returns {number} number of tools whose policy was set from sidecar
 */
export function mergeToolPolicies(tools, toolPolicies) {
  if (!Array.isArray(tools) || !toolPolicies || typeof toolPolicies !== 'object') {
    return 0;
  }
  let count = 0;
  for (const tool of tools) {
    if (!tool || typeof tool.name !== 'string') continue;
    const rule = toolPolicies[tool.name];
    if (rule === undefined) continue;
    if (typeof rule !== 'string' || !VALID_POLICY_VALUES.has(rule)) {
      process.stderr.write(
        `[policy] WARNING: sidecar toolPolicies["${tool.name}"] has invalid value ` +
        `"${String(rule).slice(0, 16)}" — skipping merge (sidecar ignored for this tool)\n`,
      );
      continue;
    }
    tool.policy = rule;
    count += 1;
  }
  return count;
}

/**
 * Create a policy-gated dispatch wrapper.
 *
 * @param {object} config
 * @param {Function} config.dispatch - Base bridge dispatch function
 * @param {Array<object>} [config.tools] - Tool definitions (auto-extracts tool.policy fields)
 * @param {Record<string, PolicyRule>} [config.toolPolicies] - Per-tool policy overrides: { tool_name: 'require_approval' }
 * @param {Function} [config.approvalHandler] - async (context) => 'approve' | 'deny'. Called for require_approval tools.
 * @param {Function} [config.logger] - (level, message, context) => void. For audit logging.
 * @param {number} [config.approvalTimeoutMs=60000] - Timeout for approval requests (ms)
 * @param {PolicyRule} [config.defaultPolicy='allow'] - Default policy for tools without explicit policy
 * @param {Array<string>} [config.dangerousActions] - Action types that always require approval regardless of tool policy
 * @returns {Function} Policy-gated dispatch function
 *
 * Usage:
 *   const gatedDispatch = createPolicyGate({
 *     dispatch: bridge.dispatch,
 *     tools: config.tools,   // auto-reads tool.policy from each tool definition
 *     approvalHandler: async (ctx) => {
 *       // Show to user, get approval
 *       console.log(`[APPROVAL REQUIRED] ${ctx.tool} with args:`, ctx.args);
 *       return 'approve'; // or 'deny'
 *     },
 *   });
 */
export function createPolicyGate(config) {
  const {
    dispatch,
    tools = [],
    toolPolicies = {},
    approvalHandler,
    logger,
    approvalTimeoutMs = 60_000,
    defaultPolicy = 'allow',
    dangerousActions = [],
  } = config;

  // Auto-extract policies from tool definitions (tool.policy field).
  // Explicit toolPolicies overrides tool-level declarations.
  // Store ALL keys lower-cased so lookup is case-insensitive.
  // `Admin_Delete` must match a `deny` policy on `admin_delete`.
  const resolvedToolPolicies = {};
  // Tool wire-shape metadata — surfaced in approval prompts so reviewers see
  // the resolved HTTP method + path, not just the friendly tool name. A
  // malicious config can name a destructive POST `list_users_report`; the
  // approval UI must show the underlying wire call.
  const toolMeta = {};
  for (const tool of tools) {
    // Use strict null check — falsy values like `''`, `false`, or `0` are skipped
    // by the original `if (tool.policy)` guard, causing a tool that explicitly
    // sets `policy: ''` to fall through to `defaultPolicy='allow'`. Additionally
    // validate that the value is a recognised policy string.
    if (tool.name && tool.policy != null) {
      if (typeof tool.policy !== 'string' || !VALID_POLICY_VALUES.has(tool.policy)) {
        process.stderr.write(`[policy] WARNING: tool "${tool.name}" has invalid policy value "${tool.policy}" — defaulting to "allow"\n`);
        // Skip storing invalid policy values; they fall through to defaultPolicy.
      } else {
        resolvedToolPolicies[tool.name.toLowerCase()] = tool.policy;
      }
    }
    if (tool.name) {
      toolMeta[tool.name.toLowerCase()] = {
        method: tool.method || null,
        path: tool.path || null,
        description: tool.description || null,
      };
    }
  }
  // Normalise caller-supplied toolPolicies keys to lowercase, and apply the
  // same VALID_POLICY_VALUES check used for tool-level declarations above.
  // Previously these values were stored as-is — null, 'BYPASS', or any other
  // garbage passed by a misconfigured caller would be stored and silently
  // treated as an unknown policy (fallthrough to defaultPolicy), defeating the
  // intent of the override. Validate and warn on invalid values.
  for (const [k, v] of Object.entries(toolPolicies)) {
    const normalizedValue = typeof v === 'string' ? v.toLowerCase() : v;
    if (!VALID_POLICY_VALUES.has(normalizedValue)) {
      process.stderr.write(
        `[40mcp] WARNING: toolPolicies["${String(k).slice(0, 32)}"] has invalid value "${String(v).slice(0, 16)}" — ` +
        `expected one of: ${[...VALID_POLICY_VALUES].join(', ')}. Skipping.\n`,
      );
      continue;
    }
    resolvedToolPolicies[k.toLowerCase()] = normalizedValue;
  }

  if (!dispatch) {
    throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, 'Policy gate requires a dispatch function');
  }

  // Built-in dangerous action names matched against tool names.
  // This set is intentionally empty — API-specific dangerous actions should be
  // defined via config.dangerousActions for your own API (see createPolicyGate config).
  const builtinDangerous = new Set();

  const allDangerous = new Set([...builtinDangerous, ...dangerousActions]);

  function log(level, message, context) {
    if (logger) {
      logger(level, message, context);
    } else {
      const prefix = level === 'warn' ? '[WARN]' : level === 'deny' ? '[DENY]' : '[INFO]';
      process.stderr.write(`[policy] ${prefix} ${message}\n`);
    }
  }

  function resolvePolicy(toolName, args) {
    // Explicit tool policy (from toolPolicies config or auto-extracted from tool.policy).
    // Look up by lowercase so `Admin_Delete` matches a `deny` rule on `admin_delete`.
    // Use `in` + `!== undefined` instead of truthy check — a stored policy value
    // of `''` or `false` was previously skipped, silently falling through to defaultPolicy.
    const lowerName = toolName.toLowerCase();
    if (lowerName in resolvedToolPolicies && resolvedToolPolicies[lowerName] !== undefined) {
      return resolvedToolPolicies[lowerName];
    }

    // Check if the action type (inside args) is dangerous.
    // Use ONLY args.action_type — the args.type fallback caused false-positive
    // escalation for tools that use `type` as a plain JSON Schema field unrelated
    // to the dangerous-action semantic.
    const actionType = args?.action_type;
    if (actionType && allDangerous.has(actionType)) {
      return 'require_approval';
    }

    return defaultPolicy;
  }

  async function requestApproval(toolName, args) {
    if (!approvalHandler) {
      // No handler configured — default deny for safety
      log('deny', `No approval handler configured — denying ${toolName}`, { toolName, args });
      return 'deny';
    }

    const meta = toolMeta[toolName.toLowerCase()] || {};
    const context = {
      tool: toolName,
      args,
      // Resolved wire-call metadata so reviewers see what HTTP request will
      // actually fire, not just the (potentially misleading) friendly name.
      method: meta.method,
      path: meta.path,
      description: meta.description,
      timestamp: new Date().toISOString(),
      policy: 'require_approval',
    };

    // Timeout wrapper. Clear the timer when the approvalHandler wins the race
    // to prevent timer leak from closure-captured audit context.
    // Without cleanup, each approved call leaked a live setTimeout for the full
    // approvalTimeoutMs (default 60s), steadily growing the libuv timer heap.
    let timerHandle = null;
    const timeout = new Promise((resolve) => {
      timerHandle = setTimeout(() => resolve('timeout'), approvalTimeoutMs);
    });

    try {
      const decision = await Promise.race([
        approvalHandler(context),
        timeout,
      ]);
      return decision;
    } finally {
      if (timerHandle) clearTimeout(timerHandle);
    }
  }

  return async function policyDispatch(toolName, args, chainOptions) {
    const policy = resolvePolicy(toolName, args);
    // Normalize to lowercase so the audit context and approval prompt always see
    // the wire-call metadata, even when the caller supplies a mixed-case tool name
    // (e.g. `Admin_Delete` → lookup `admin_delete`).
    const meta = toolMeta[toolName.toLowerCase()] || {};

    const auditContext = {
      tool: toolName,
      method: meta.method,
      path: meta.path,
      args: sanitizeForLog(args),
      policy,
      timestamp: new Date().toISOString(),
    };

    switch (policy) {
      case 'allow':
        return dispatch(toolName, args, chainOptions);

      case 'deny':
        log('deny', `BLOCKED: ${toolName} — policy is deny`, auditContext);
        throw new BridgeError(
          BridgeErrorCode.POLICY_DENIED,
          `Tool "${toolName}" is blocked by policy`,
          { tool: toolName, policy: 'deny' },
        );

      case 'log_only':
        log('info', `AUDIT: ${toolName}`, auditContext);
        return dispatch(toolName, args, chainOptions);

      case 'require_approval': {
        log('warn', `APPROVAL REQUIRED: ${toolName}`, auditContext);

        const decision = await requestApproval(toolName, args);

        if (decision === 'approve') {
          log('info', `APPROVED: ${toolName}`, { ...auditContext, decision });
          return dispatch(toolName, args, chainOptions);
        }

        if (decision === 'timeout') {
          log('deny', `TIMEOUT: ${toolName} — approval timed out after ${approvalTimeoutMs}ms`, auditContext);
          throw new BridgeError(
            BridgeErrorCode.API_TIMEOUT,
            `Approval timed out for "${toolName}" after ${approvalTimeoutMs}ms`,
            { tool: toolName, policy: 'require_approval', timeout: approvalTimeoutMs },
          );
        }

        log('deny', `DENIED: ${toolName} — human denied`, { ...auditContext, decision });
        throw new BridgeError(
          BridgeErrorCode.POLICY_DENIED,
          `Tool "${toolName}" was denied by policy approval`,
          { tool: toolName, policy: 'require_approval', decision },
        );
      }

      default:
        // Unknown policy — deny for safety
        log('deny', `BLOCKED: ${toolName} — unknown policy: ${policy}`, auditContext);
        throw new BridgeError(
          BridgeErrorCode.CONFIG_INVALID,
          `Unknown policy "${policy}" for tool "${toolName}"`,
          { tool: toolName, policy },
        );
    }
  };
}

/**
 * Create a stdin-based approval handler for CLI use.
 * Prints the action details and waits for y/n input.
 *
 * @returns {Function} approvalHandler
 */
export function createStdinApprovalHandler() {
  return async (context) => {
    const { tool, args, timestamp, method, path } = context;

    process.stderr.write('\n');
    process.stderr.write('╔══════════════════════════════════════════════════╗\n');
    process.stderr.write('║  🛡️  POLICY GATE — APPROVAL REQUIRED            ║\n');
    process.stderr.write('╠══════════════════════════════════════════════════╣\n');
    process.stderr.write(`║  Tool:  ${tool.padEnd(40)}║\n`);
    // Show the resolved wire call so a malicious config that names a
    // destructive POST `list_users_report` can't slip past a human reviewer
    // who only sees the friendly tool name.
    if (method || path) {
      const wire = `${method || '?'} ${path || '?'}`;
      process.stderr.write(`║  Wire:  ${wire.slice(0, 40).padEnd(40)}║\n`);
    }
    process.stderr.write(`║  Time:  ${timestamp.padEnd(40)}║\n`);
    process.stderr.write('╠══════════════════════════════════════════════════╣\n');

    const argLines = JSON.stringify(args, null, 2).split('\n');
    for (const line of argLines.slice(0, 15)) {
      process.stderr.write(`║  ${line.padEnd(48)}║\n`);
    }
    if (argLines.length > 15) {
      process.stderr.write(`║  ... (${argLines.length - 15} more lines)`.padEnd(50) + '║\n');
    }

    process.stderr.write('╠══════════════════════════════════════════════════╣\n');
    process.stderr.write('║  Approve? (y/n):                                 ║\n');
    process.stderr.write('╚══════════════════════════════════════════════════╝\n');

    return new Promise((resolve) => {
      process.stdin.setEncoding('utf-8');
      process.stdin.once('data', (data) => {
        const answer = data.trim().toLowerCase();
        resolve(answer === 'y' || answer === 'yes' ? 'approve' : 'deny');
      });
    });
  };
}

/**
 * Create a callback-based approval handler (for web UIs / webhooks).
 *
 * @param {Function} callback - async (context) => 'approve' | 'deny'
 * @returns {Function} approvalHandler
 */
export function createCallbackApprovalHandler(callback) {
  return callback;
}

/**
 * Strip sensitive fields from args before logging.
 * @private
 */
function sanitizeForLog(args) {
  if (!args || typeof args !== 'object') return args;
  const sensitiveTerms = [
    'password', 'secret', 'token', 'api_key', 'apikey', 'webhook_secret',
    'access_token', 'refresh_token', 'client_secret', 'authorization',
    'bearer', 'private_key', 'session', 'cookie', 'passphrase',
  ];
  // Recurse up to MAX_REDACT_DEPTH levels (previously hard-capped at 1, so
  // `args.config.credentials.token` escaped redaction). Depth cap is kept
  // (not unbounded) to prevent pathological nesting from blowing the stack.
  const MAX_REDACT_DEPTH = 6;
  // Truncate large string values so a 100 MB attacker-supplied non-sensitive
  // payload field cannot cause an OOM allocation when serializing args for
  // the approval prompt. Each string is capped at 1 KiB with an explicit
  // "[truncated N bytes]" marker.
  const MAX_VALUE_CHARS = 1024;

  function redactObject(obj, depth) {
    if (obj == null) return obj;
    if (typeof obj === 'string') {
      return obj.length > MAX_VALUE_CHARS
        ? `${obj.slice(0, MAX_VALUE_CHARS)}…[truncated ${obj.length - MAX_VALUE_CHARS} chars]`
        : obj;
    }
    if (typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) {
      return depth > 0 ? obj.map((v) => redactObject(v, depth - 1)) : obj;
    }
    const out = { ...obj };
    for (const key of Object.keys(out)) {
      const lk = key.toLowerCase();
      if (sensitiveTerms.some((term) => lk.includes(term))) {
        out[key] = '***REDACTED***';
      } else if (depth > 0 && out[key] && typeof out[key] === 'object') {
        out[key] = redactObject(out[key], depth - 1);
      } else if (typeof out[key] === 'string') {
        out[key] = redactObject(out[key], depth);
      }
    }
    return out;
  }

  const sanitized = redactObject(args, MAX_REDACT_DEPTH);
  // Strip _tenant internals
  if (sanitized && sanitized._tenant) {
    sanitized._tenant = { tenantId: sanitized._tenant.tenantId, auth: '***REDACTED***' };
  }
  return sanitized;
}
