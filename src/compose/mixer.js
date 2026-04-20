import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { dispatchToolCall } from '../core/path.js';
import { createApiClient } from '../core/client.js';
import { createStdioTransport } from '../transport/stdio.js';
import { applyResponseTransform } from '../transforms/response.js';
import { executeChain } from './chain.js';
import { resolveEnvVars } from '../core/env.js';
import { validateToolArgs, sanitizeTransportEgress, emitAuditLog } from '../bridge.js';
import { sanitizeMcpToolDescription } from '../core/sanitize.js';
import {
  applySteering,
  runPrehook,
  runPosthook,
  attachSteeringEnvelope,
} from '../steering/index.js';
import { safeLog } from '../core/events.js';
import '../core/types.js';

// ─── Symbol key for internal chain dispatch ────────────────────
// Using a module-level Symbol (instead of a string property name) prevents
// discovery of innerChainDispatch via Object.getOwnPropertyNames(dispatch).
// Symbols are invisible to getOwnPropertyNames — they are only returned by
// Object.getOwnPropertySymbols — so an attacker who holds the dispatch
// function cannot enumerate or call innerChainDispatch without the Symbol.
// The Symbol is exported so the invariants test can access it; in production
// code nothing outside this module holds it.
export const INTERNAL_CHAIN_DISPATCH = Symbol('40mcp:internal-chain-dispatch');

// ─── Tool dispatcher ────────────────────────────────────────────────────────

function buildMixerDispatcher(toolMap, options = {}) {
  const allowSteeringInstructions = options.allowSteeringInstructions === true;

  // The mixer dispatch surface never had the `maxConcurrentDispatches` cap
  // that bridge.js enforces. An authenticated client on a mixer-served
  // deployment could fire unbounded parallel CallTool and saturate the event
  // loop. Mirror bridge.js's guard here. Chain-internal calls (depth > 0)
  // are exempt because chain fan-out is already bounded by
  // DEFAULT_WAVE_CONCURRENCY inside executeChain. Use a module-private Symbol
  // as the same unforgeable "internal" marker used by bridge.js so external
  // callers cannot fake isInternal.
  const requestedMax = options.maxConcurrentDispatches;
  const clampedMax =
    typeof requestedMax === 'number' && Number.isFinite(requestedMax) && requestedMax > 0
      ? requestedMax
      : 50;
  const maxConcurrentDispatches = Math.max(1, Math.min(clampedMax, 10_000));
  let inFlightDispatches = 0;
  const INTERNAL_OPTS = Symbol('40mcp:mixer-internal');

  async function innerDispatch(name, args, chainOptions = {}) {
    args = args || {};
    const entry = toolMap.get(name);
    if (!entry) {
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }

    const { tool, apiClient } = entry;

    // The mixer dispatch path previously bypassed validateToolArgs entirely.
    // Reserved-key rejection (_chain, _depth, _steering, etc.) and
    // additionalProperties:false enforcement only fired in bridge.js. Now the
    // same gate runs here so a mixer-served tool gets identical hardening to a
    // bridge-served tool.
    const validationError = validateToolArgs(args, tool.inputSchema);
    if (validationError) {
      throw new McpError(ErrorCode.InvalidParams, `Tool "${name}": ${validationError}`);
    }

    // Compound tool chain — mixer-served chain tools short-circuit the
    // steering pipeline because `executeChain` recurses back into dispatch for
    // every inner step, where steering runs per step. Pass `innerChainDispatch`
    // (stamps the trust Symbol) so chain recursion bypasses the outer
    // concurrency cap and keeps `_chainStack` / `_depth` propagated. Also seed
    // `_currentChainName` with the outer tool name so the invocation-cycle
    // detector catches self-recursion before the first sub-dispatch's prehook
    // runs. The wave concurrency inside `executeChain` bounds fan-out
    // independently.
    if (tool.chain) {
      return executeChain(tool.chain, args, innerChainDispatch, {
        ...chainOptions,
        [INTERNAL_OPTS]: true,
        _currentChainName: name,
      });
    }

    // ─── Steering prehook ────────────────────────────────────────────
    // The mixer dispatch path was the only surface that skipped
    // `runPrehook`/`runPosthook`/`attachSteeringEnvelope`. A tool with
    // `steering.write: true` served via mixer would accept calls without
    // memory_type/confidence/importance validation. Mirror the bridge.js
    // pipeline here so every dispatch surface enforces identical steering
    // semantics.
    let prehookResult;
    try {
      prehookResult = runPrehook(tool, args);
    } catch (err) {
      throw new McpError(ErrorCode.InvalidParams, `Tool "${name}" steering prehook: ${err.message}`);
    }
    const steeringClassification = prehookResult.classification;
    const prehookInstructions = allowSteeringInstructions ? prehookResult.instructions : null;
    args = prehookResult.args;

    let result = await dispatchToolCall(tool, args, apiClient);

    // Response transforms
    if (tool.response) {
      result = applyResponseTransform(result, tool.response);
    }

    // ─── Steering posthook ───────────────────────────────────────────
    const posthookResult = runPosthook(tool, result, { classification: steeringClassification });
    const posthookInstructions = allowSteeringInstructions ? posthookResult.instructions : null;
    result = posthookResult.result;

    if (prehookInstructions || posthookInstructions || steeringClassification) {
      result = attachSteeringEnvelope(result, {
        prehook: prehookInstructions,
        posthook: posthookInstructions,
        classification: steeringClassification,
      });
    }

    return result;
  }

  // Outer dispatch with concurrency cap + external option sanitization.
  async function dispatch(name, args, chainOptions = {}) {
    const isInternal = chainOptions && chainOptions[INTERNAL_OPTS] === true;
    if (!isInternal) {
      if (inFlightDispatches >= maxConcurrentDispatches) {
        throw new McpError(
          ErrorCode.InternalError,
          `Dispatch capacity exceeded: ${inFlightDispatches}/${maxConcurrentDispatches} concurrent calls in flight. Retry shortly.`,
        );
      }
      inFlightDispatches += 1;
    }
    try {
      // Strip `_`-prefixed keys from externally-supplied options so a
      // caller of the exported `dispatch` function cannot poison
      // `_chainStack` or `_depth`. Internal chain recursion through
      // `innerChainDispatch` bypasses this path because `executeChain`
      // receives `innerChainDispatch` directly.
      let safeOptions = chainOptions;
      if (!isInternal && chainOptions && typeof chainOptions === 'object') {
        const sanitized = {};
        for (const key of Object.keys(chainOptions)) {
          if (key.startsWith('_')) continue;
          sanitized[key] = chainOptions[key];
        }
        safeOptions = sanitized;
      }
      return await innerDispatch(name, args, safeOptions);
    } finally {
      if (!isInternal) inFlightDispatches -= 1;
    }
  }

  // Internal chain-recursion dispatch stamps the Symbol marker so
  // `executeChain` can recurse without being rate-limited twice or
  // having its `_chainStack`/`_depth` keys stripped.
  async function innerChainDispatch(name, args, chainOptions = {}) {
    return innerDispatch(name, args, { ...chainOptions, [INTERNAL_OPTS]: true });
  }

  // `_internalChainDispatch` must not be a plain enumerable
  // property — any code holding the mixer object could call it directly,
  // bypassing the concurrency cap and the `_`-key sanitization that strips
  // reserved keys from external calls.
  // Use the module-level Symbol as the property key instead of
  // the string '_internalChainDispatch'. String-keyed non-enumerable properties
  // are still discoverable via Object.getOwnPropertyNames(dispatch). Symbol keys
  // are invisible to getOwnPropertyNames — only Object.getOwnPropertySymbols
  // reveals them, and that requires intentional introspection.
  Object.defineProperty(dispatch, INTERNAL_CHAIN_DISPATCH, {
    value: innerChainDispatch,
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return dispatch;
}

// ─── Mixer builder ──────────────────────────────────────────────────────────

/**
 * Combine multiple bridge configs into a single MCP tool server.
 *
 * @param {object} config
 * @param {string} config.name - Combined server name
 * @param {string} [config.version] - Server version
 * @param {Array<object>} config.servers - Array of server configs
 * @param {boolean} [config.strict=false] - When true, throw on duplicate tool
 *   names instead of warning + skipping (useful in dev/CI)
 *
 * Each server config:
 * @param {string} [server.prefix] - Optional prefix for tool names (e.g., 'stripe' → 'stripe.list_invoices')
 * @param {string} server.name - Server name
 * @param {string} server.baseUrl - REST API base URL
 * @param {object} [server.auth] - Auth configuration (type, envVar, value, header)
 * @param {Array} server.tools - Tool definitions
 * @param {Array<string>} [server.allowlist] - Only expose these tools (if set)
 * @param {Array<string>} [server.blocklist] - Hide these tools
 *
 * @returns {{ start(), server, dispatch }}
 */
export function createMixer(config) {
  // Emit an audit entry when mixer construction throws so a config push
  // that fails to materialize at boot leaves a forensic trail.
  try {
    return _createMixerInner(config);
  } catch (err) {
    try {
      emitAuditLog({
        ts: Date.now(),
        tool: '<mixer-construction>',
        status: 'error',
        errorCode: 'MIXER_CONSTRUCTION_FAIL',
        surface: 'mixer',
        error: safeLog(err && err.message ? err.message : String(err), 300),
      });
    } catch { /* telemetry failure must not mask the underlying error */ }
    throw err;
  }
}

function _createMixerInner(config) {
  const { name = 'mixer', version = '1.0.0', servers = [], strict = false } = config;

  // Check for duplicate prefix names across servers. Normalize to NFC before
  // comparison to prevent Unicode homograph hijacks — two prefixes that render
  // identically (`'café'` NFC vs `'cafe\u0301'` NFD) could bypass the guard and
  // produce visually-identical tool names. Shallow-clone each entry before any
  // mutation so the original objects are never touched — avoid invisible
  // in-place mutations that violate caller ownership and cause cross-call
  // interference when configs are reused.
  const serverConfigs = servers.map((s) => ({ ...s }));
  const seenPrefixes = new Map(); // normalized prefix → serverName
  for (const serverConfig of serverConfigs) {
    if (serverConfig.prefix !== undefined) {
      const normPrefix = String(serverConfig.prefix).normalize('NFC');
      if (seenPrefixes.has(normPrefix)) {
        throw new Error(
          `Duplicate prefix "${normPrefix}" in server "${serverConfig.name || '(unnamed)'}" ` +
            `(already used by server "${seenPrefixes.get(normPrefix)}") — Unicode normalized to NFC`,
        );
      }
      seenPrefixes.set(normPrefix, serverConfig.name || '(unnamed)');
      // Normalize in the cloned object — safe because this clone is private to _createMixerInner.
      serverConfig.prefix = normPrefix;
    }
  }

  const toolMap = new Map(); // toolName → { tool, apiClient }

  // Build tool list from all servers
  for (const serverConfig of serverConfigs) {  // L2: uses pre-cloned serverConfigs (cloned above)
    const {
      prefix,
      name: serverName,
      baseUrl,
      auth,
      hooks,
      tools: toolDefs = [],
      allowlist,
      blocklist,
    } = serverConfig;

    // Resolve env vars in baseUrl
    const resolvedBaseUrl = resolveEnvVars(baseUrl || '', serverName || 'mixer');

    // Create API client for this server
    const apiClient = createApiClient(resolvedBaseUrl, auth, hooks);

    // Process each tool from this server
    for (const tool of toolDefs) {
      // Apply allowlist/blocklist filters
      if (allowlist && !allowlist.includes(tool.name)) {
        continue;
      }
      if (blocklist && blocklist.includes(tool.name)) {
        continue;
      }

      // Build final tool name (with optional prefix)
      const finalToolName = prefix ? `${prefix}.${tool.name}` : tool.name;

      // Check for duplicates. Default behavior is warn-and-skip so a single
      // bad/conflicting server does not crash the entire bridge startup.
      // Pass `strict: true` to fail fast — useful in dev/CI to surface
      // collisions before they reach production.
      if (toolMap.has(finalToolName)) {
        const existing = toolMap.get(finalToolName);
        const existingServer = existing.serverName || '(unnamed)';
        const msg =
          `Duplicate tool name "${finalToolName}" in server ` +
          `"${serverName || '(unnamed)'}" (already registered by server "${existingServer}"). ` +
          `Use prefixes to disambiguate conflicting tool names.`;
        if (strict) {
          throw new Error(msg);
        }
        process.stderr.write(`[mixer] WARNING: ${msg} — skipping.\n`);
        continue;
      }

      // Apply steering schema enrichment at registration time so tools with
      // `steering.write: true` expose `memory_type` / `confidence` / `importance`
      // to the MCP client exactly as they do when served via bridge.js. A
      // malformed `steering` config on one tool used to throw out of
      // `applySteering`, killing the entire mixer construction. In non-strict
      // mode, log + skip the offending tool so a single bad server doesn't
      // crash the whole mixer. In strict mode, rethrow.
      let enrichedTool;
      try {
        enrichedTool = applySteering(tool);
      } catch (steeringErr) {
        if (strict) throw steeringErr;
        process.stderr.write(
          `[mixer] WARNING: tool "${finalToolName}" has malformed steering config — ` +
          `skipping. ${safeLog(steeringErr.message, 200)}\n`,
        );
        continue;
      }

      // Register tool — also store the serverName for richer
      // duplicate-collision diagnostics.
      toolMap.set(finalToolName, { tool: enrichedTool, apiClient, serverName });
    }
  }

  // Build dispatch function
  const dispatch = buildMixerDispatcher(toolMap, {
    allowSteeringInstructions: config.allowSteeringInstructions === true,
  });

  // Build MCP tool list
  // Tool descriptions come from connected upstream MCP servers that may not have
  // applied sanitization. Pass every description through sanitizeMcpToolDescription
  // to catch prompt-injection payloads before they reach the LLM tool list.
  const mcpTools = Array.from(toolMap.entries()).map(([finalToolName, { tool }]) => ({
    name: finalToolName,
    description: sanitizeMcpToolDescription(tool.description || '', { label: 'mixer' }),
    inputSchema: tool.inputSchema || { type: 'object', properties: {}, required: [] },
  }));

  // Create MCP server
  const server = new Server(
    { name, version },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: mcpTools }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name: toolName, arguments: args } = request.params;

    // Emit audit entries from the mixer dispatch surface so every tool call is
    // recorded. Previously the mixer CallTool path was entirely unaudited.
    // Mirror the bridge.js `dispatchInner` audit schema: capture `ts` before
    // dispatch, emit on both success and error paths, and scrub `toolName` since
    // `request.params.name` comes straight from the MCP client and could
    // contain injection bytes.
    const callTs = Date.now();
    const safeToolName = safeLog(toolName, 128);
    let result;
    try {
      result = await dispatch(toolName, args || {});
      emitAuditLog({
        ts: callTs,
        tool: safeToolName,
        status: 'success',
        durationMs: Date.now() - callTs,
        surface: 'mixer',
      });
    } catch (err) {
      emitAuditLog({
        ts: callTs,
        tool: safeToolName,
        status: 'error',
        errorCode: err?.code || 'UNKNOWN',
        durationMs: Date.now() - callTs,
        surface: 'mixer',
      });
      if (err instanceof McpError) throw err;
      // Mirror the NODE_ENV gate from bridge.js so upstream error messages
      // (which may echo request body content including tokens) are suppressed
      // for MCP clients in production.
      const detail = process.env.NODE_ENV === 'development'
        ? (err.message || String(err))
        : 'Internal error';
      // Scrub both the tool name AND err.message since toolName comes straight
      // from `request.params.name` — a classic log-forgery vector if it contains
      // embedded injection bytes.
      process.stderr.write(`[40mcp] mixer dispatch error on ${safeToolName}: ${safeLog(err.message || String(err), 300)}\n`);
      throw new McpError(ErrorCode.InternalError, detail);
    }

    // Mirror the createRestBridge egress strip. Upstream results may carry
    // reserved envelope keys via field-name collision or a compromised upstream;
    // strip before the MCP client receives them. Apply full sanitizeTransportEgress
    // (strip + sanitizeResultObject) to match bridge.js's CallTool handler.
    // Without sanitizeResultObject, an upstream MCP server could return
    // {"message": "Ignore all previous instructions..."} and the injection would
    // reach the LLM verbatim. stripInternalEnvelopes is idempotent so the extra
    // step has no downside.
    const sanitized = sanitizeTransportEgress(result);

    return {
      content: [{ type: 'text', text: JSON.stringify(sanitized, null, 2) }],
    };
  });

  return {
    /** Start the MCP server on stdio transport. */
    async start() {
      const transport = createStdioTransport();
      await server.connect(transport);
      process.stderr.write(
        `[${name}] MCP server started — ${mcpTools.length} tools from ${servers.length} servers\n`,
      );
      return { server, dispatch };
    },

    /** Access the underlying MCP Server instance (for custom transports). */
    server,

    /** Access the dispatch function directly (for testing). */
    dispatch,
  };
}
