#!/usr/bin/env node

/**
 * 40mcp CLI — The universal API-to-MCP bridge.
 *
 * Usage:
 * 40mcp serve config.json # Start from config (stdio)
 * 40mcp serve config.json --sse 8080 # Start with SSE transport
 * 40mcp from-openapi spec.json # OpenAPI spec → MCP server
 * 40mcp from-graphql https://api.example.com/graphql # GraphQL → MCP server
 * 40mcp from-har recording.har # HAR traffic → MCP server
 * 40mcp mix server1.json server2.json # Mix multiple APIs
 * 40mcp reverse config.json --port 8080 # MCP tools → REST API
 * 40mcp inspect config.json # List tools without starting
 */

import { readFile, writeFile, access, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { homedir, platform } from 'node:os';
import { createInterface } from 'node:readline';
import { createVault, initVault, recoverVault } from './security/vault.js';
import { startDaemon, defaultSocketPath, defaultPidPath } from './security/vault-daemon.js';
import { createVaultDaemonClient } from './security/vault-client.js';
import { createRestBridge } from './bridge.js';
import { VERSION } from './version.js';
import { loadConfig } from './config.js';
import { loadOpenApiSpec } from './openapi.js';
import { assertSafeUrl } from './core/env.js';
import { loadGraphqlSchema } from './loaders/graphql.js';
import { loadHarFile } from './loaders/har.js';
import { createMixer } from './compose/mixer.js';
import { createReverseBridge } from './reverse/server.js';
import { loadFromAny } from './loaders/registry.js';
import { validateConfig } from './validate.js';
import { generateFromSpec, generatePrompt } from './generate.js';
import { connectStdio, connectFromConfig } from './connect.js';
import { loadSettings, pick, parseByteSize } from './config/settings.js';
import { setTelemetryConfig, setInstanceMetadata, instanceBannerSuffix } from './core/events.js';

/** Hard ceiling for frontdoor JSON file size. Mirrors MAX_CONFIG_FILE_BYTES in config.js. */
const MAX_FRONTDOOR_FILE_BYTES = 16 * 1024 * 1024;

const args = process.argv.slice(2);
const command = args[0];

// --version / -v
if (command === '--version' || command === '-v') {
 const __dirname = dirname(fileURLToPath(import.meta.url));
 const pkg = JSON.parse(await readFile(resolve(__dirname, '../package.json'), 'utf-8'));
 process.stdout.write(`${pkg.name} v${pkg.version}\n`);
 process.exit(0);
}

if (!command || command === '--help' || command === '-h') {
 printHelp();
 process.exit(command ? 0 : 1);
}

const flags = parseFlags(args.slice(1));
const positional = positionalArgs(args.slice(1));

process.on('unhandledRejection', (err) => {
 fatal(err?.message || String(err));
});

switch (command) {
 case 'serve':
 await cmdServe(positional[0], flags);
 break;
 case 'from-openapi':
 await cmdFromOpenApi(positional[0], flags);
 break;
 case 'from-graphql':
 await cmdFromGraphql(positional[0], flags);
 break;
 case 'from-har':
 await cmdFromHar(positional[0], flags);
 break;
 case 'from':
 await cmdFromAny(positional[0], flags);
 break;
 case 'mix':
 await cmdMix(positional, flags);
 break;
 case 'reverse':
 await cmdReverse(positional[0], flags);
 break;
 case 'inspect':
 await cmdInspect(positional[0], flags);
 break;
 case 'validate':
 await cmdValidate(positional[0], flags);
 break;
 case 'generate':
 await cmdGenerate(positional[0], flags);
 break;
 case 'link':
 await cmdLink(positional[0], flags);
 break;
 case 'vault':
 await cmdVault(args.slice(1), flags);
 break;
 case 'init':
 await cmdInit(flags);
 break;
 case 'doctor':
 await cmdDoctor(positional[0], flags);
 break;
 case 'settings':
 await cmdSettings(positional[0], flags);
 break;
 default:
 // Legacy: treat first arg as config file (backwards compat with mcp-rest-bridge)
 if (args[0] && !args[0].startsWith('-')) {
 await cmdServe(args[0], flags);
 } else {
 process.stderr.write(`Unknown command: ${command}\n`);
 printHelp();
 process.exit(1);
 }
}

// ─── Commands ──────────────────────────────────────────────────────────────

async function cmdServe(configPath, flags) {
 if (!configPath || configPath.startsWith('--')) fatal('Usage: 40mcp serve <config.json|config.js>');
 const config = await loadConfig(configPath);
 const { settings, source: settingsSource, warnings: settingsWarnings } = await loadAndApplySettings(flags, configPath);
 if (settingsSource) process.stderr.write(`[40mcp] Loaded settings from ${settingsSource}\n`);
 for (const w of settingsWarnings) process.stderr.write(`[40mcp] settings WARNING: ${w}\n`);

 // Transport — CLI (--sse / --port / --host) > settings.bridge.transport > default.
 const sseFlag = flags.sse ?? flags.port;
 const settingsTransport = settings.bridge.transport;
 if (sseFlag !== undefined || settingsTransport.type === 'sse') {
  const cliPort = sseFlag !== undefined ? parseInt(sseFlag, 10) : undefined;
  const port = pick(
   Number.isFinite(cliPort) ? cliPort : undefined,
   settingsTransport.port,
   8080,
  );
  const host = pick(flags.host, settingsTransport.host);

  // Bearer auth — parity with `link`. Without this, `serve --sse --host 0.0.0.0`
  // would silently publish unauthenticated. Supports --require-bearer-env (env
  // var lookup, preferred) and --require-bearer (literal, discouraged — leaks
  // via ps). Bearer-file (multi-principal) is intentionally link-only.
  let bearerToken;
  const bearerSources = ['require-bearer-env', 'require-bearer']
   .filter((k) => flags[k] !== undefined && flags[k] !== false);
  if (bearerSources.length > 1) {
   fatal(`Only one of --require-bearer-env / --require-bearer may be set (got ${bearerSources.map((s) => `--${s}`).join(', ')}).`);
  }
  if (flags['require-bearer-env']) {
   const envName = String(flags['require-bearer-env']);
   const token = process.env[envName];
   if (!token) {
    fatal(`--require-bearer-env ${envName} is set but $${envName} is empty. Set the env var or use --require-bearer.`);
   }
   bearerToken = token;
  } else if (flags['require-bearer']) {
   bearerToken = String(flags['require-bearer']);
  }

  // Refuse non-loopback bind without auth — matches the cmdLink check so
  // `serve` can't be turned into an unauthenticated proxy by a host flag alone.
  if (!bearerToken && host && host !== '127.0.0.1' && host !== 'localhost') {
   fatal('Refusing to publish serve on a non-loopback host without inbound auth.\n' +
    'Pass --require-bearer-env <ENV> (recommended) or --require-bearer <token>, or bind to 127.0.0.1.');
  }

  config.transport = {
   type: 'sse',
   port,
   ...(host ? { host } : {}),
   ...(bearerToken ? { requireBearer: bearerToken } : {}),
  };
 }

 // Dispatch limits — CLI > settings > default.
 const maxConcurrent = pick(
  flags['max-concurrent'] !== undefined ? parseIntStrict(flags['max-concurrent'], '--max-concurrent') : undefined,
  settings.bridge.limits.dispatch.maxConcurrent,
 );
 if (maxConcurrent !== undefined) config.maxConcurrentDispatches = maxConcurrent;

 const requestTimeoutMs = pick(
  flags['request-timeout-ms'] !== undefined ? parseIntStrict(flags['request-timeout-ms'], '--request-timeout-ms') : undefined,
  settings.bridge.limits.dispatch.requestTimeoutMs,
 );
 const requestMaxBytes = coerceBytes(settings.bridge.limits.request.maxBytes, 'settings.bridge.limits.request.maxBytes');
 const responseMaxBytes = coerceBytes(settings.bridge.limits.response.maxBytes, 'settings.bridge.limits.response.maxBytes');
 if (requestTimeoutMs !== undefined || requestMaxBytes !== undefined || responseMaxBytes !== undefined) {
  config.hooks = {
   ...(config.hooks || {}),
   ...(requestTimeoutMs !== undefined ? { timeoutMs: requestTimeoutMs } : {}),
   ...(requestMaxBytes !== undefined ? { maxRequestBytes: requestMaxBytes } : {}),
   ...(responseMaxBytes !== undefined ? { maxResponseBytes: responseMaxBytes } : {}),
  };
 }

 // Network — CLI > settings.
 const strictSsrf = pick(
  flags['strict-ssrf'] === true ? true : undefined,
  settings.bridge.network.strictSsrf,
 );
 if (strictSsrf !== undefined) config.strictSsrf = strictSsrf;
 const allowPrivate = pick(
  flags['allow-private'] === true ? true : undefined,
  settings.bridge.network.allowPrivate,
 );
 if (allowPrivate !== undefined) config.allowPrivate = allowPrivate;

 await applyVaultAuth(config, flags, settings);

 // Policy gate — activates when --policy <path> is given. The gate wraps
 // the bridge's dispatch so embedded `tool.policy` annotations AND the
 // sidecar rules in the --policy JSON are both enforced through the MCP
 // server's CallTool handler. The default approval handler denies with
 // audit (serve has no interactive channel to prompt for approval over
 // stdio / SSE). Operators who need a real approval flow use the library
 // API with their own approvalHandler.
 const policyPath = flags.policy;
 if (policyPath) {
 const policyConfig = await loadFrontdoorJson(policyPath, '--policy');
 if (policyConfig) {
 const { createPolicyGate, mergeToolPolicies } = await import('./security/policy.js');
 const serveTools = config.tools || [];
 // Compile sidecar toolPolicies into embedded tool.policy BEFORE bridge
 // construction. The bridge's per-dispatch re-check reads only tool.policy,
 // so without this merge, chain sub-dispatches tunnel through sidecar deny /
 // require_approval rules.
 mergeToolPolicies(serveTools, policyConfig.toolPolicies || {});
 config.wrapDispatch = (rawDispatch) => createPolicyGate({
 dispatch: rawDispatch,
 tools: serveTools,
 toolPolicies: policyConfig.toolPolicies || {},
 dangerousActions: policyConfig.dangerousActions || [],
 defaultPolicy: policyConfig.defaultPolicy || 'allow',
 approvalHandler: async (ctx) => {
 process.stderr.write(
 `[40mcp] policy: require_approval denied for "${ctx.tool}" — ` +
 `\`serve\` has no interactive approval channel; wire a custom ` +
 `approvalHandler via the library API if a real approval flow is needed\n`,
 );
 return 'deny';
 },
 logger: (level, message, context) => {
 process.stderr.write(
 `[40mcp] policy ${level}: ${message}${context?.tool ? ` (tool=${context.tool})` : ''}\n`,
 );
 },
 });
 const embeddedCount = serveTools.filter((t) => t && t.policy != null).length;
 const sidecarCount = Object.keys(policyConfig.toolPolicies || {}).length;
 process.stderr.write(
 `[40mcp] Policy gate enabled — ${embeddedCount} embedded tool.policy + ${sidecarCount} sidecar rule(s)\n`,
 );
 }
 }

 const bridge = await createRestBridge(config).start();

 // Install SIGTERM/SIGINT handlers so an orchestrator-initiated shutdown
 // (systemd, docker stop, k8s preStop) gets a clean close of the HTTP server
 // before the process dies. Without this, vault saves in progress could leave
 // orphaned `${vaultPath}.tmp.*` files and partial HTTP writes. The handler is
 // idempotent — a second signal while closing forces immediate exit.
 let shuttingDown = false;
 const shutdown = (signal) => {
 if (shuttingDown) {
 process.stderr.write(`[40mcp] ${signal} again — force exit\n`);
 process.exit(1);
 }
 shuttingDown = true;
 process.stderr.write(`[40mcp] ${signal} received — shutting down gracefully\n`);
 const srv = bridge && bridge.httpServer;
 if (srv && typeof srv.close === 'function') {
 try { srv.close(() => process.exit(0)); } catch { process.exit(0); }
 // Hard timeout in case connections refuse to drain
 setTimeout(() => process.exit(0), 10_000).unref();
 } else {
 process.exit(0);
 }
 };
 process.on('SIGTERM', () => shutdown('SIGTERM'));
 process.on('SIGINT', () => shutdown('SIGINT'));
}

async function cmdFromOpenApi(specPath, flags) {
 if (!specPath) fatal('Usage: 40mcp from-openapi <spec.json|url>');

 let spec;
 if (specPath.startsWith('http://') || specPath.startsWith('https://')) {
 try {
 assertSafeUrl(specPath, { allowPrivate: flags['allow-private'] === true, label: 'spec url' });
 } catch (err) {
 fatal(`${err.message} (use --allow-private to override)`);
 }
 const res = await fetch(specPath);
 if (!res.ok) fatal(`Failed to fetch spec: ${res.status}`);
 spec = await res.json();
 } else {
 spec = specPath;
 }

 const opts = buildFilterOpts(flags);
 const { baseUrl, tools } = await loadOpenApiSpec(spec, opts);

 const config = buildServerConfig(flags, baseUrl, tools, 'openapi-bridge');
 await applyVaultAuth(config, flags);
 logToolCount(config.name, tools.length);
 await createRestBridge(config).start();
}

async function cmdFromGraphql(endpoint, flags) {
 if (!endpoint) fatal('Usage: 40mcp from-graphql <endpoint-url>');

 const headers = {};
 if (flags['auth-bearer-env']) {
 const token = process.env[flags['auth-bearer-env']] || '';
 if (token) headers['Authorization'] = `Bearer ${token}`;
 }
 if (flags['auth-header'] && flags['auth-env']) {
 const val = process.env[flags['auth-env']] || '';
 if (val) headers[flags['auth-header']] = val;
 }

 const opts = {...buildFilterOpts(flags), headers };
 opts.allowPrivate = flags['allow-private'] === true;
 const { baseUrl: gqlBaseUrl, tools } = await loadGraphqlSchema(endpoint, opts);

 const config = buildServerConfig(flags, gqlBaseUrl, tools, 'graphql-bridge');
 await applyVaultAuth(config, flags);
 logToolCount(config.name, tools.length);
 await createRestBridge(config).start();
}

async function cmdFromHar(harPath, flags) {
 if (!harPath) fatal('Usage: 40mcp from-har <recording.har>');

 const opts = buildFilterOpts(flags);
 if (flags['min-observations']) opts.minObservations = parseInt(flags['min-observations'], 10);

 const { baseUrl, tools } = await loadHarFile(harPath, opts);

 const config = buildServerConfig(flags, baseUrl, tools, 'har-bridge');
 await applyVaultAuth(config, flags);
 logToolCount(config.name, tools.length);
 await createRestBridge(config).start();
}

async function cmdFromAny(input, flags) {
 if (!input) fatal('Usage: 40mcp from <spec-or-url>');

 let specInput;
 if (input.startsWith('http://') || input.startsWith('https://')) {
 try {
 assertSafeUrl(input, { allowPrivate: flags['allow-private'] === true, label: 'spec url' });
 } catch (err) {
 fatal(`${err.message} (use --allow-private to override)`);
 }
 const res = await fetch(input);
 if (!res.ok) fatal(`Failed to fetch: ${res.status}`);
 specInput = await res.json();
 } else if (input.endsWith('.json') || input.endsWith('.yaml') || input.endsWith('.yml') || input.endsWith('.har')) {
 specInput = input;
 } else {
 specInput = input;
 }

 const opts = buildFilterOpts(flags);
 opts.allowPrivate = flags['allow-private'] === true;
 const { baseUrl, tools } = await loadFromAny(specInput, opts);

 const config = buildServerConfig(flags, baseUrl, tools, 'auto-bridge');
 await applyVaultAuth(config, flags);
 logToolCount(config.name, tools.length);
 await createRestBridge(config).start();
}

async function cmdMix(configPaths, flags) {
 if (configPaths.length < 2) fatal('Usage: 40mcp mix <config1.json> <config2.json> [...]');

 const servers = await Promise.all(configPaths.map((p) => loadConfig(p)));

 const mixer = createMixer({
 name: flags.name || '40mcp-mixed',
 version: flags.version || '1.0.0',
 servers,
 });

 process.stderr.write(`[40mcp] Mixed ${servers.length} servers\n`);
 await mixer.start();
}

async function cmdReverse(configPath, flags) {
 if (!configPath) fatal('Usage: 40mcp reverse <config.json> [--port 8080]');

 const config = await loadConfig(configPath);
 const bridge = createRestBridge(config);
 const parsedPort = parseInt(flags.port, 10);
 const port = Number.isFinite(parsedPort) ? parsedPort : 8080;

 const reverse = createReverseBridge({
 name: config.name || 'reverse-bridge',
 version: config.version || '1.0.0',
 tools: config.tools || [],
 dispatch: bridge.dispatch,
 port,
 });

 const { url } = await reverse.start();
 process.stderr.write(`[40mcp] Reverse bridge at ${url}\n`);
 process.stderr.write(`[40mcp] OpenAPI spec: ${url}/api/openapi.json\n`);
}

async function cmdInspect(configPath, _flags) {
 if (!configPath) fatal('Usage: 40mcp inspect <config.json>');

 const config = await loadConfig(configPath);

 // Shape check: `inspect` targets 40mcp REST-bridge configs (those with a
 // `tools` array). Point users at the right command for other shapes so
 // `inspect package.json` doesn't print a hollow summary with toolCount:0.
 if (!Array.isArray(config.tools)) {
  if (config.mcpServers && typeof config.mcpServers === 'object') {
   fatal(`"${configPath}" looks like an MCP-link config (has "mcpServers"). Use: 40mcp link "${configPath}" --inspect`);
  }
  fatal(`"${configPath}" does not appear to be a 40mcp config (no "tools" array). Try: 40mcp validate "${configPath}" for detailed diagnostics.`);
 }
 const tools = config.tools;

 process.stdout.write(JSON.stringify({
 name: config.name,
 version: config.version,
 baseUrl: config.baseUrl,
 toolCount: tools.length,
 tools: tools.map((t) => ({
 name: t.name,
 method: t.method,
 path: t.path,
 description: t.description,
 args: Object.keys(t.inputSchema?.properties || {}),
 })),
 }, null, 2) + '\n');
}

async function cmdLink(input, flags) {
 if (!input) fatal('Usage: 40mcp link <.mcp.json|command> [args...]\n\n 40mcp link.mcp.json Connect to all servers in.mcp.json (stdio out)\n 40mcp link.mcp.json --sse 8080 \\\n --require-bearer-env FRONTDOOR_TOKEN Publish linked frontdoor over authenticated SSE\n 40mcp link npx @microsoft/mcp-azure Connect to a single MCP server');

 const { settings, source: settingsSource, warnings: settingsWarnings } =
  await loadAndApplySettings(flags, input.endsWith('.json') ? input : null);
 if (settingsSource) process.stderr.write(`[40mcp] Loaded settings from ${settingsSource}\n`);
 for (const w of settingsWarnings) process.stderr.write(`[40mcp] settings WARNING: ${w}\n`);

 // Mode 1:.mcp.json file — connect to all servers
 if (input.endsWith('.json')) {
 // Resolve the config path against CWD first, then fall back to the
 // installed package root. The fallback makes commands like
 //   npx 40mcp@beta link configs/microsoft-huggingface-bridge.mcp.json
 // work from any directory, not just a repo checkout.
 const cwdPath = resolve(process.cwd(), input);
 const packagePath = resolve(dirname(fileURLToPath(import.meta.url)), '..', input);
 let raw;
 try {
 raw = await readFile(cwdPath, 'utf-8');
 } catch (err) {
 if (err.code !== 'ENOENT') throw err;
 try {
 raw = await readFile(packagePath, 'utf-8');
 } catch (err2) {
 if (err2.code !== 'ENOENT') throw err2;
 fatal(`Config not found: "${input}"\n  Tried: ${cwdPath}\n  Tried: ${packagePath}`);
 }
 }
 const parsed = JSON.parse(raw);
 const mcpServers = parsed.mcpServers || parsed;

 const connected = await connectFromConfig(mcpServers, {
 only: flags.only ? flags.only.split(',') : undefined,
 skip: flags.skip ? flags.skip.split(',') : undefined,
 });
 const { dispatch, close, connections } = connected;
 let tools = connected.tools;

 // Tool-level allow/deny at the frontdoor. CLI flags win over
 // `settings.frontdoor.surface.{allowTools,denyTools}`. Glob patterns
 // match against the fully-prefixed tool name. `--deny-tool` wins over
 // `--allow-tool` when both match.
 const allowSource = flags['allow-tool'] !== undefined
  ? flags['allow-tool']
  : (settings.frontdoor.surface.allowTools.length
     ? settings.frontdoor.surface.allowTools.join(',')
     : undefined);
 const denySource = flags['deny-tool'] !== undefined
  ? flags['deny-tool']
  : (settings.frontdoor.surface.denyTools.length
     ? settings.frontdoor.surface.denyTools.join(',')
     : undefined);
 const allowMatcher = compileToolGlobs(allowSource);
 const denyMatcher = compileToolGlobs(denySource);
 if (allowMatcher || denyMatcher) {
 const before = tools.length;
 tools = tools.filter((t) => {
 if (denyMatcher && denyMatcher(t.name)) return false;
 if (allowMatcher && !allowMatcher(t.name)) return false;
 return true;
 });
 process.stderr.write(`[40mcp] Tool filter: ${tools.length}/${before} tools after --allow-tool/--deny-tool\n`);
 }

 // Steering was removed. Refuse the flag loudly rather than silently
 // ignoring it — an operator passing --steering expects enforcement.
 if (flags.steering !== undefined) {
 process.stderr.write(
 '[40mcp] Error: --steering is no longer supported — the steering module was removed. ' +
 'Remove the flag, or pin 40mcp to 0.1.x.\n',
 );
 process.exit(1);
 }

 process.stderr.write(`[40mcp] Linked ${tools.length} tools from ${Object.keys(mcpServers).length} servers${instanceBannerSuffix()}\n`);
 for (const tool of tools) {
 process.stderr.write(` ${tool.name} — ${tool.description}\n`);
 }

 // If --inspect, just list and exit
 if (flags.inspect) {
 process.stdout.write(JSON.stringify({ tools: tools.map((t) => ({ name: t.name, description: t.description })) }, null, 2) + '\n');
 await close();
 return;
 }

 // Tool-name set used to enforce the filter at dispatch time too —
 // an inbound CallTool for a filtered name must 404 even though a
 // compliant ListTools already hides it.
 const allowedNames = new Set(tools.map((t) => t.name));

 // Create a bridge that wraps the linked tools
 const { Server } = await import('@modelcontextprotocol/sdk/server/index.js');
 const { CallToolRequestSchema, ListToolsRequestSchema, ErrorCode, McpError } =
 await import('@modelcontextprotocol/sdk/types.js');
 const { emitEvent } = await import('./core/events.js');
 const { currentPrincipal, currentSessionId } = await import('./transport/context.js');

 // Dispatch wrapping. Order is inside-out —
 // outermost wrapper runs first:
 //
 // callDispatch = tenantScope(policyGate(rawDispatch))
 //
 // Tenant scope resolves the principal's tenant context and enforces
 // its allowlist/blocklist before policy decides allow/deny/approve on
 // the individual tool. Raw dispatch then hits the upstream.
 let callDispatch = dispatch;

 const policyPath = pick(flags.policy, settings.frontdoor.policy.path);
 const policyConfig = await loadFrontdoorJson(policyPath, '--policy');
 if (policyConfig) {
 const { createPolicyGate } = await import('./security/policy.js');
 callDispatch = createPolicyGate({
 dispatch: callDispatch,
 // Forward the linked tool list so createPolicyGate extracts any
 // embedded `tool.policy` annotations that upstream servers happen
 // to publish. Explicit `toolPolicies` from the sidecar --policy
 // JSON overrides per-tool embedded values.
 tools,
 toolPolicies: policyConfig.toolPolicies || {},
 dangerousActions: policyConfig.dangerousActions || [],
 defaultPolicy: policyConfig.defaultPolicy || 'allow',
 // Published frontdoor has no interactive operator at stdin. Until a
 // real approval channel (webhook / Slack / PagerDuty) is plumbed
 // in, treat `require_approval` as deny-with-audit so the behavior
 // is safe-by-default. Tracked as a follow-up.
 approvalHandler: async (ctx) => {
 emitEvent('frontdoor.policy_denied', {
 tool: ctx.tool,
 reason: 'no_approval_handler',
 principal: currentPrincipal(),
 });
 return 'deny';
 },
 logger: (level, message, context) => {
 emitEvent('frontdoor.policy', {
 level, message,
 tool: context?.tool,
 principal: currentPrincipal(),
 });
 },
 });
 process.stderr.write(`[40mcp] Policy gate enabled — ${Object.keys(policyConfig.toolPolicies || {}).length} rules\n`);
 }

 // Tenant map is loaded up front so the file is validated before any
 // transport binds, but the wrap only happens inside the --sse branch
 // (multi-token auth is SSE-only — there's no principal in stdio mode).
 const tenantMapPath = pick(flags['tenant-map'], settings.frontdoor.tenantMap.path);
 const tenantMap = await loadFrontdoorJson(tenantMapPath, '--tenant-map');

 // The frontdoor serves many concurrent MCP clients over SSE. The MCP
 // SDK's `Server` only owns one transport at a time, so we build a
 // fresh Server per inbound session via `buildServer()` (plumbed into
 // `createSseTransport` as `serverFactory`) instead of sharing one.
 // Stdio mode still creates a single Server (one client, one process).
 const buildServer = () => {
 const s = new Server(
 { name: flags.name || '40mcp-link', version: VERSION },
 { capabilities: { tools: {} } },
);
 s.setRequestHandler(ListToolsRequestSchema, listToolsHandler);
 s.setRequestHandler(CallToolRequestSchema, callToolHandler);
 return s;
 };

 const listToolsHandler = async () => ({
 tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
 });

 const callToolHandler = async (request) => {
 const name = request.params.name;
 const principal = currentPrincipal();
 const sessionId = currentSessionId();
 if (!allowedNames.has(name)) {
 emitEvent('frontdoor.tool_call', { tool: name, outcome: 'not_found', principal, sessionId });
 throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
 }
 const startedAt = Date.now();
 try {
 const payload = await callDispatch(name, request.params.arguments || {});
 emitEvent('frontdoor.tool_call', {
 tool: name,
 outcome: 'ok',
 duration_ms: Date.now() - startedAt,
 principal,
 sessionId,
 });
 return { content: [{ type: 'text', text: typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2) }] };
 } catch (err) {
 emitEvent('frontdoor.tool_call', {
 tool: name,
 outcome: 'error',
 duration_ms: Date.now() - startedAt,
 error: err && err.message ? String(err.message).slice(0, 200) : 'unknown',
 principal,
 sessionId,
 });
 throw err;
 }
 };

 // Published frontdoor mode: --sse <port> re-exposes the linked
 // surface as an authenticated SSE MCP server instead of stdio.
 // Also triggered when `settings.frontdoor.transport.type === 'sse'`.
 // See docs/FRONTDOOR.md for the deployment pattern.
 const settingsWantsSse = settings.frontdoor.transport.type === 'sse';
 if (flags.sse !== undefined || settingsWantsSse) {
 const cliPort = flags.sse !== undefined ? parseInt(flags.sse, 10) : undefined;
 const port = pick(
  Number.isFinite(cliPort) ? cliPort : undefined,
  settings.frontdoor.transport.port,
  8080,
 );
 const host = pick(flags.host, settings.frontdoor.transport.host);
 const bearerToken = await resolveFrontdoorBearer(flags, settings);
 const cliOrigins = flags['allowed-origin']
  ? String(flags['allowed-origin']).split(',').map((s) => s.trim()).filter(Boolean)
  : undefined;
 const allowedOrigins = cliOrigins !== undefined
  ? cliOrigins
  : (settings.frontdoor.network.allowedOrigins.length ? settings.frontdoor.network.allowedOrigins : undefined);

 if (!bearerToken && host && host !== '127.0.0.1' && host !== 'localhost') {
 fatal('Refusing to publish linked frontdoor on a non-loopback host without inbound auth.\n' +
 'Pass --require-bearer-env <ENV> (recommended) or --require-bearer <token>, or bind to 127.0.0.1.');
 }

 // Tenant scope per principal. The principal is only
 // defined in multi-token mode (`--bearer-file`), so tenant-map
 // without it is a usage error. Note: the CallTool handler captures
 // `callDispatch` by reference, so this late wrap is picked up on
 // every inbound call.
 if (tenantMap) {
 if (typeof bearerToken !== 'object' || !bearerToken) {
 fatal('--tenant-map requires multi-token auth (--bearer-file). The tenant is resolved from the authenticated principal, which only exists in multi-token mode.');
 }
 const { createTenantScope } = await import('./tenant/scope.js');
 callDispatch = createTenantScope({
 dispatch: callDispatch,
 resolveContext: async () => {
 const principal = currentPrincipal();
 if (!principal) return null;
 return tenantMap[principal] || null;
 },
 });
 process.stderr.write(`[40mcp] Tenant scope enabled — ${Object.keys(tenantMap).length} principal mappings\n`);
 }

 const { createSseTransport } = await import('./transport/sse.js');

 // --health-detail (or `settings.frontdoor.surface.healthDetail`) opts
 // the /health endpoint into a per-upstream liveness report. Without
 // it, /health stays minimal (`{status:"ok"}`) so an anonymous probe
 // can't enumerate the backend layout.
 const healthDetail = pick(
  flags['health-detail'] === true ? true : undefined,
  settings.frontdoor.surface.healthDetail,
 );
 const healthProvider = healthDetail
 ? () => ({
 status: 'ok',
 upstreams: connections.map((c) => ({
 source: c.source,
 status: typeof c.getStatus === 'function' ? c.getStatus() : 'ok',
 })),
 })
 : undefined;

 // Session caps — CLI flag > settings > transport default. `MAX_SSE_CONNECTIONS`
 // env var is consumed inside `createSseTransport` itself and wins over
 // both when only settings was supplied (see transport/sse.js for the
 // precedence split).
 const maxSessionsPerPrincipal = pick(
  flags['max-sessions-per-principal'] !== undefined
   ? parseIntStrict(flags['max-sessions-per-principal'], '--max-sessions-per-principal')
   : undefined,
  settings.frontdoor.limits.sse.maxSessionsPerPrincipal,
 );
 const maxSessionsPerIp = pick(
  flags['max-sessions-per-ip'] !== undefined
   ? parseIntStrict(flags['max-sessions-per-ip'], '--max-sessions-per-ip')
   : undefined,
  settings.frontdoor.limits.sse.maxSessionsPerIp,
 );
 const maxConnections = pick(
  flags['max-connections'] !== undefined
   ? parseIntStrict(flags['max-connections'], '--max-connections')
   : undefined,
  // Env var MAX_SSE_CONNECTIONS wins over settings — keep behavior
  // consistent by reading it here and letting it slot in above settings.
  process.env.MAX_SSE_CONNECTIONS ? parseIntStrict(process.env.MAX_SSE_CONNECTIONS, 'MAX_SSE_CONNECTIONS env') : undefined,
  settings.frontdoor.limits.sse.maxConnections,
 );
 const idleTimeoutMs = pick(
  flags['idle-timeout-ms'] !== undefined
   ? parseIntStrict(flags['idle-timeout-ms'], '--idle-timeout-ms')
   : undefined,
  settings.frontdoor.limits.sse.idleTimeoutMs,
 );

 const { httpServer, url } = await createSseTransport(null, {
 port,
 host,
 requireBearer: bearerToken,
 allowedOrigins,
 healthProvider,
 ...(maxSessionsPerPrincipal !== undefined ? { maxSessionsPerPrincipal } : {}),
 ...(maxSessionsPerIp !== undefined ? { maxSessionsPerIp } : {}),
 ...(maxConnections !== undefined ? { maxConnections } : {}),
 ...(idleTimeoutMs !== undefined ? { idleTimeoutMs } : {}),
 // Multi-client frontdoor — build a fresh Server per inbound
 // SSE session (see buildServer above). The MCP SDK's Server
 // class rejects concurrent transports.
 serverFactory: buildServer,
 });
 const authLabel = !bearerToken
 ? ' (UNAUTHENTICATED)'
 : typeof bearerToken === 'object'
 ? ` (bearer required — ${Object.keys(bearerToken).length} principals)`
 : ' (bearer required)';
 process.stderr.write(`[40mcp] Frontdoor published — ${tools.length} tools at ${url}${authLabel}${instanceBannerSuffix()}\n`);

 // Graceful shutdown so SIGTERM from an orchestrator closes upstream
 // connections AND the published HTTP server cleanly.
 let shuttingDown = false;
 const shutdown = async (signal) => {
 if (shuttingDown) {
 process.stderr.write(`[40mcp] ${signal} again — force exit\n`);
 process.exit(1);
 }
 shuttingDown = true;
 process.stderr.write(`[40mcp] ${signal} received — shutting down frontdoor\n`);

 // Race the drain against a hard deadline so a stuck connection can't
 // hold the process. `httpServer.close` is patched upstream to call
 // `closeAllConnections()` first, so long-lived SSE sessions are cut.
 const drained = (async () => {
 await new Promise((done) => {
 try { httpServer.close(() => done()); } catch { done(); }
 });
 try { await close(); } catch { /* ignore */ }
 })();
 const deadline = new Promise((done) => setTimeout(done, 5_000).unref());
 await Promise.race([drained, deadline]);
 process.exit(0);
 };
 process.on('SIGTERM', () => shutdown('SIGTERM'));
 process.on('SIGINT', () => shutdown('SIGINT'));
 return;
 }

 // Stdio mode: a single Server owns a single stdio transport for the
 // lifetime of the process. No need for the factory pattern here.
 const stdioServer = buildServer();
 const { createStdioTransport: createStdio } = await import('./transport/stdio.js');
 await stdioServer.connect(createStdio());
 process.stderr.write(`[40mcp] Link bridge started — ${tools.length} tools${instanceBannerSuffix()}\n`);
 return;
 }

 // Mode 2: Direct command — connect to single server
 const cmdArgs = positional.slice(1).filter((a) => !a.startsWith('--'));
 const server = await connectStdio({
 command: input,
 args: cmdArgs,
 prefix: flags.prefix,
 });

 process.stderr.write(`[40mcp] Linked to ${input}: ${server.tools.length} tools\n`);
 for (const tool of server.tools) {
 process.stderr.write(` ${tool.name} — ${tool.description}\n`);
 }

 process.stdout.write(JSON.stringify({ tools: server.tools.map((t) => ({ name: t.name, description: t.description })) }, null, 2) + '\n');
 await server.close();
}

async function cmdGenerate(input, flags) {
 if (!input) fatal('Usage: 40mcp generate <spec.json|url|description>\n\nModes:\n 40mcp generate spec.json # Generate from OpenAPI spec (deterministic)\n 40mcp generate --describe "Stripe API" # Output prompt for LLM to generate config\n 40mcp generate --describe "..." --out config.json');

 // Mode 1: --describe flag → output LLM prompt pair
 if (flags.describe || (!input.endsWith('.json') && !input.endsWith('.yaml') && !input.endsWith('.yml') && !input.startsWith('http'))) {
 const description = flags.describe || input;
 const { system, user } = generatePrompt({
 description,
 baseUrl: flags['base-url'],
 authType: flags['auth-type'],
 style: flags.minimal ? 'minimal' : 'comprehensive',
 });

 if (flags.prompt === 'system') {
 process.stdout.write(system + '\n');
 } else if (flags.prompt === 'user') {
 process.stdout.write(user + '\n');
 } else {
 // Output both as JSON for piping to LLM
 process.stdout.write(JSON.stringify({ system, user }, null, 2) + '\n');
 }
 return;
 }

 // Mode 2: spec file → deterministic generation
 let spec;
 if (input.startsWith('http://') || input.startsWith('https://')) {
 try {
 assertSafeUrl(input, { allowPrivate: flags['allow-private'] === true, label: 'spec url' });
 } catch (err) {
 fatal(`${err.message} (use --allow-private to override)`);
 }
 const res = await fetch(input);
 if (!res.ok) fatal(`Failed to fetch spec: ${res.status}`);
 spec = await res.json();
 } else {
 spec = JSON.parse(await readFile(resolve(process.cwd(), input), 'utf-8'));
 }

 const config = generateFromSpec(spec, {
 policyGateWrites: flags['no-policy'] ? false : true,
 addTransforms: flags['no-transforms'] ? false : true,
 tokenBudget: flags['token-budget'] ? parseInt(flags['token-budget'], 10) : 4000,
 });

 const output = JSON.stringify(config, null, 2);

 if (flags.out) {
 const { writeFile: writeOut } = await import('node:fs/promises');
 await writeOut(resolve(process.cwd(), flags.out), output + '\n', 'utf-8');
 process.stderr.write(`[40mcp] Generated ${config.tools.length} tools → ${flags.out}\n`);
 } else {
 process.stdout.write(output + '\n');
 }
}

async function cmdValidate(configPath, _flags) {
 if (!configPath) fatal('Usage: 40mcp validate <config.json>');

 let config;
 try {
 config = await loadConfig(configPath);
 } catch (err) {
 if (err.code === 'ENOENT') {
 fatal(`File not found: ${configPath}`);
 } else if (err instanceof SyntaxError) {
 fatal(`Invalid JSON in ${configPath}: ${err.message}`);
 } else {
 fatal(`Failed to load config: ${err.message}`);
 }
 }
 const result = validateConfig(config);

 if (result.valid) {
 process.stdout.write(`✓ Config is valid — ${config.tools?.length || 0} tools\n`);
 } else {
 process.stdout.write(`✗ Config has ${result.errors.length} error(s):\n`);
 for (const err of result.errors) {
 process.stdout.write(` ERROR: ${err}\n`);
 }
 }

 if (result.warnings.length > 0) {
 process.stdout.write(` ${result.warnings.length} warning(s):\n`);
 for (const warn of result.warnings) {
 process.stdout.write(` WARN: ${warn}\n`);
 }
 }

 process.exit(result.valid ? 0 : 1);
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function parseFlags(args) {
 const flags = {};
 for (let i = 0; i < args.length; i++) {
 if (args[i].startsWith('--')) {
 const key = args[i].slice(2);
 const next = args[i + 1];
 if (next && !next.startsWith('--')) {
 flags[key] = next;
 i++;
 } else {
 flags[key] = true;
 }
 }
 }
 return flags;
}

/** Extract positional (non-flag) arguments from an arg list, skipping flag values. */
function positionalArgs(args) {
 const pos = [];
 for (let i = 0; i < args.length; i++) {
 if (args[i].startsWith('--')) {
 const next = args[i + 1];
 if (next && !next.startsWith('--')) i++; // skip flag value
 } else {
 pos.push(args[i]);
 }
 }
 return pos;
}

/**
 * Load a frontdoor config file (policy, tenant-map) as JSON.
 * Shared shape: exits with a clear error if the file is missing,
 * unreadable, or not a JSON object. Returns `null` when the flag is
 * unset so callers can treat it as "feature not configured."
 */
async function loadFrontdoorJson(flagValue, flagName) {
 if (flagValue === undefined || flagValue === false) return null;
 const filePath = resolve(process.cwd(), String(flagValue));
 let st;
 try {
 st = await stat(filePath);
 } catch (err) {
 fatal(`${flagName} ${filePath}: ${err.message}`);
 }
 if (st.size > MAX_FRONTDOOR_FILE_BYTES) {
 fatal(`${flagName} ${filePath}: file too large (${st.size} > ${MAX_FRONTDOOR_FILE_BYTES} bytes).`);
 }
 let raw;
 try {
 raw = await readFile(filePath, 'utf-8');
 } catch (err) {
 fatal(`${flagName} ${filePath}: ${err.message}`);
 }
 let parsed;
 try {
 parsed = JSON.parse(raw);
 } catch (err) {
 fatal(`${flagName} ${filePath} is not valid JSON: ${err.message}`);
 }
 if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
 fatal(`${flagName} ${filePath} must contain a JSON object.`);
 }
 return parsed;
}

/**
 * Compile a comma-separated list of glob patterns into a matcher function.
 * `*` matches any run of characters; everything else is literal. Match is
 * against the fully-prefixed tool name (e.g. `github.get_repo`). Returns
 * `null` when `raw` is empty / undefined.
 */
function compileToolGlobs(raw) {
 if (!raw) return null;
 const patterns = String(raw).split(',').map((s) => s.trim()).filter(Boolean);
 if (patterns.length === 0) return null;
 const regexes = patterns.map((pat) => {
 const escaped = pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
 return new RegExp(`^${escaped}$`);
 });
 return (name) => regexes.some((re) => re.test(name));
}

/**
 * Resolve the inbound bearer credential for a published frontdoor.
 *
 * --require-bearer-env <ENV> reads a single token from an env var
 * --require-bearer <token> single token literal (discouraged — leaks via ps)
 * --bearer-file <path> JSON `{ principal: token,... }` for multi-token
 * mode; enables per-principal attribution on
 * `sse.auth_ok` / `sse.session_open` events
 *
 * At most one of the three may be set. Returns:
 * - `undefined` when none is set
 * - a string (single-token mode)
 * - an object `{ principal: token,... }` (multi-token mode)
 *
 * Fails fast on empty env vars, malformed files, empty/duplicate tokens,
 * or principal names that can't be safely logged — silently falling
 * through any of these would either publish an unauthenticated frontdoor
 * or emit log lines an attacker can forge.
 */
async function resolveFrontdoorBearer(flags, settings) {
 // Declared inside the function (not module-scope) because this CLI
 // dispatches commands synchronously at top level — a module-level
 // `const` declared below the dispatch would hit temporal dead zone
 // when `cmdLink` runs before the rest of the file finishes loading.
 const PRINCIPAL_NAME_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

 const sources = ['require-bearer-env', 'require-bearer', 'bearer-file']
.filter((k) => flags[k] !== undefined && flags[k] !== false);
 if (sources.length > 1) {
 fatal(`Only one of --require-bearer-env / --require-bearer / --bearer-file may be set (got ${sources.map((s) => `--${s}`).join(', ')}).`);
 }

 // Precedence: CLI flag > settings.frontdoor.auth.*. If none are supplied,
 // return undefined and let the caller decide whether unauthenticated
 // binding is acceptable (the host check further up rejects non-loopback).
 const requireBearerEnv = pick(flags['require-bearer-env'], settings?.frontdoor?.auth?.requireBearerEnv);
 const bearerFile = pick(flags['bearer-file'], settings?.frontdoor?.auth?.bearerFile);

 if (requireBearerEnv && sources.length === 0) {
  const envName = String(requireBearerEnv);
  const token = process.env[envName];
  if (!token) {
   fatal(`settings.frontdoor.auth.requireBearerEnv=${envName} is set but $${envName} is empty.`);
  }
  return token;
 }
 if (flags['require-bearer-env']) {
 const envName = String(flags['require-bearer-env']);
 const token = process.env[envName];
 if (!token) {
 fatal(`--require-bearer-env ${envName} is set but $${envName} is empty. ` +
 'Set the env var or use --bearer-file / --require-bearer.');
 }
 return token;
 }
 if (flags['require-bearer']) {
 return String(flags['require-bearer']);
 }
 const bearerFilePath = flags['bearer-file'] || (sources.length === 0 ? bearerFile : undefined);
 if (bearerFilePath) {
 const filePath = resolve(process.cwd(), String(bearerFilePath));
 let raw;
 try {
 raw = await readFile(filePath, 'utf-8');
 } catch (err) {
 fatal(`--bearer-file ${filePath}: ${err.message}`);
 }
 let parsed;
 try {
 parsed = JSON.parse(raw);
 } catch (err) {
 fatal(`--bearer-file ${filePath} is not valid JSON: ${err.message}`);
 }
 if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
 fatal(`--bearer-file ${filePath} must contain a JSON object mapping principal → token.`);
 }
 const entries = Object.entries(parsed);
 if (entries.length === 0) {
 fatal(`--bearer-file ${filePath} is empty — refusing to publish an unauthenticated frontdoor.`);
 }
 const tokenToPrincipal = new Map();
 const map = {};
 for (const [name, token] of entries) {
 if (!PRINCIPAL_NAME_PATTERN.test(name)) {
 fatal(`--bearer-file ${filePath}: principal name "${String(name).slice(0, 32)}" must match ${PRINCIPAL_NAME_PATTERN.source}.`);
 }
 if (typeof token !== 'string' || token.length === 0) {
 fatal(`--bearer-file ${filePath}: principal "${name}" has an empty or non-string token.`);
 }
 if (tokenToPrincipal.has(token)) {
 // Two principals sharing a token would make auth events
 // non-deterministic (first-match wins). Force operators to fix it.
 fatal(`--bearer-file ${filePath}: principals "${tokenToPrincipal.get(token)}" and "${name}" share the same token.`);
 }
 tokenToPrincipal.set(token, name);
 map[name] = token;
 }
 return map;
 }
 return undefined;
}

function buildFilterOpts(flags) {
 const opts = {};
 if (flags.tags) opts.tags = flags.tags.split(',').map((t) => t.trim());
 if (flags.include) opts.include = flags.include.split(',').map((t) => t.trim());
 if (flags.exclude) opts.exclude = flags.exclude.split(',').map((t) => t.trim());
 if (flags.methods) opts.methods = flags.methods.split(',').map((t) => t.trim());
 return opts;
}

function buildServerConfig(flags, baseUrl, tools, defaultName) {
 const config = {
 name: flags.name || defaultName,
 version: flags.version || '1.0.0',
 baseUrl: flags['base-url'] || baseUrl,
 tools,
 };

 if (flags['auth-header'] || flags['auth-env']) {
 config.auth = {
 type: 'header',
 header: flags['auth-header'] || 'Authorization',
 envVar: flags['auth-env'] || 'API_KEY',
 };
 } else if (flags['auth-bearer-env']) {
 config.auth = {
 type: 'bearer',
 envVar: flags['auth-bearer-env'],
 };
 }

 return config;
}

/**
 * Apply vault-based sealed auth to a bridge config when --vault-secret is set.
 * Mutates config in place — adds config.vault and config.auth.
 *
 * --vault-secret <name> sealed header auth (requires --vault-header)
 * --vault-secret <name> --vault-header X-API-Key header auth
 * --vault-bearer <name> sealed bearer token auth
 */
async function applyVaultAuth(config, flags, settings) {
 const secretName = flags['vault-secret'];
 const bearerName = flags['vault-bearer'];

 if (!secretName && !bearerName) return config;

 const daemonSecret = process.env.VAULT_DAEMON_SECRET || flags['daemon-secret'];
 const socketPath = flags['socket'] || defaultSocketPath();
 // `settings.bridge.vault.daemon=true` demands a daemon secret. Fail fast
 // rather than silently falling back to interactive passphrase mode — the
 // operator's intent is clearly "don't prompt, use the daemon".
 const settingsWantDaemon = settings?.bridge?.vault?.daemon === true;
 if (settingsWantDaemon && !daemonSecret) {
  fatal('settings.bridge.vault.daemon=true but VAULT_DAEMON_SECRET is not set. Start the daemon and export the secret.');
 }

 if (daemonSecret) {
 // Phase 2: use daemon client — bridges never hold passphrase
 const vaultPath = resolveVaultPath(flags, settings);
 config.vault = createVaultDaemonClient({
 socketPath,
 configPath: flags._configPath, // set by caller when loading config file
 daemonSecret,
 // Phase 1 fallback if daemon unavailable
 vaultPath,
 passphrase: process.env.VAULT_PASSPHRASE,
 });
 } else {
 // Phase 1 fallback: direct vault load
 const passphrase = await resolvePassphrase(flags);
 config.vault = createVault({ path: resolveVaultPath(flags, settings), passphrase });
 }

 if (bearerName) {
 config.auth = { type: 'sealed-bearer', name: bearerName };
 } else {
 const header = flags['vault-header'] || 'Authorization';
 config.auth = { type: 'sealed', name: secretName, header };
 }

 return config;
}

function logToolCount(name, count) {
 process.stderr.write(`[40mcp] ${name}: ${count} tools loaded\n`);
}

function fatal(msg) {
 process.stderr.write(`Error: ${msg}\n`);
 process.exit(1);
}

// ─── Settings helpers ──────────────────────────────────────────────────────

/**
 * Load `40mcp.settings.json`, apply process-wide side effects
 * (telemetry gating), and return the merged settings. Discovery precedence is
 * handled inside `loadSettings` — this wrapper exists to shuttle the values
 * from CLI flags into the loader's options shape.
 */
async function loadAndApplySettings(flags, configPath) {
 let result;
 try {
  result = await loadSettings({
   explicitPath: flags.settings,
   configPath,
  });
 } catch (err) {
  fatal(err.message || String(err));
 }
 // Telemetry gating + instance metadata are process-wide side effects —
 // apply them once so every subsequent emit site sees the same policy.
 // Defaults are "on" / null so library consumers outside the CLI are
 // unchanged unless they explicitly opt in.
 setTelemetryConfig(result.settings.frontdoor.telemetry);
 setInstanceMetadata(result.settings.instance);
 return result;
}


function parseIntStrict(value, label) {
 const n = parseInt(value, 10);
 if (!Number.isFinite(n) || n < 1) {
  fatal(`${label} must be a positive integer (got "${value}").`);
 }
 return n;
}

function coerceBytes(value, label) {
 if (value === undefined || value === null) return undefined;
 const n = parseByteSize(value);
 if (n == null || n < 1) fatal(`${label} must be a positive byte size (e.g. "1MB").`);
 return n;
}

// ─── Vault helpers ─────────────────────────────────────────────────────────

function resolveVaultPath(flags, settings) {
 if (flags.vault) return flags.vault;
 if (settings && settings.bridge && settings.bridge.vault && settings.bridge.vault.path) {
  return settings.bridge.vault.path;
 }
 return resolve(homedir(), '.40mcp', 'vault.json');
}

async function resolvePassphrase(_flags) {
 if (process.env.VAULT_PASSPHRASE) return process.env.VAULT_PASSPHRASE;
 // stdin pipe is safe (not visible in ps) — allow it for daemon child processes
 return promptSecret('Vault passphrase: ');
}

async function promptSecret(prompt) {
 if (!process.stdin.isTTY) {
 // Read from stdin pipe
 return new Promise((resolve, reject) => {
 let data = '';
 process.stdin.setEncoding('utf-8');
 process.stdin.on('data', (chunk) => { data += chunk; });
 process.stdin.on('end', () => resolve(data.trim()));
 process.stdin.on('error', reject);
 });
 }

 // TTY: prompt with no echo
 return new Promise((resolve, reject) => {
 const rl = createInterface({ input: process.stdin, output: process.stderr });
 process.stderr.write(prompt);
 // Disable echo
 process.stdin.setRawMode(true);
 let value = '';
 process.stdin.on('data', function handler(char) {
 char = char.toString();
 if (char === '\r' || char === '\n') {
 process.stdin.setRawMode(false);
 process.stdin.removeListener('data', handler);
 process.stderr.write('\n');
 rl.close();
 resolve(value);
 } else if (char === '\u0003') { // Ctrl+C
 process.stdin.setRawMode(false);
 rl.close();
 reject(new Error('Cancelled'));
 } else if (char === '\u007f') { // Backspace
 value = value.slice(0, -1);
 } else {
 value += char;
 }
 });
 });
}

async function cmdVault(vaultArgs, _flags) {
 const subPos = positionalArgs(vaultArgs);
 const subFlags = parseFlags(vaultArgs);
 const sub = subPos[0];

 const vaultPath = resolveVaultPath(subFlags);

 switch (sub) {
 case 'init': {
 const passphrase = await resolvePassphrase(subFlags);
 const { recoveryKey } = await initVault({ path: vaultPath, passphrase });
 process.stderr.write('\n\u26a0\ufe0f RECOVERY KEY \u2014 save this somewhere safe. It will NOT be shown again.\n\n');
 process.stdout.write(`${recoveryKey}\n`);
 process.stderr.write('\nVault initialized. Use `40mcp vault seal <name>` to store secrets.\n');
 break;
 }

 case 'seal': {
 const name = subPos[1];
 if (!name) fatal('Usage: 40mcp vault seal <name>');
 const passphrase = await resolvePassphrase(subFlags);
 const vault = createVault({ path: vaultPath, passphrase });
 const value = await promptSecret(`Value for "${name}": `);
 const sealId = await vault.set(name, value, { cli: true });
 process.stdout.write(`${sealId}\n`);
 break;
 }

 case 'list': {
 const passphrase = await resolvePassphrase(subFlags);
 const vault = createVault({ path: vaultPath, passphrase });
 const entries = await vault.list();
 if (entries.length === 0) {
 process.stdout.write('No sealed secrets.\n');
 } else {
 process.stdout.write(JSON.stringify(entries, null, 2) + '\n');
 }
 break;
 }

 case 'rotate': {
 const name = subPos[1];
 if (!name) fatal('Usage: 40mcp vault rotate <name>');
 const passphrase = await resolvePassphrase(subFlags);
 const vault = createVault({ path: vaultPath, passphrase });
 const newSealId = await vault.rotate(name);
 if (!newSealId) fatal(`Secret not found: ${name}`);
 process.stdout.write(`${newSealId}\n`);
 break;
 }

 case 'rotate-kek': {
 const passphrase = await resolvePassphrase(subFlags);
 const vault = createVault({ path: vaultPath, passphrase });
 const newPassphrase = await promptSecret('New vault passphrase: ');
 const confirm = await promptSecret('Confirm new passphrase: ');
 if (newPassphrase !== confirm) fatal('Passphrases do not match');
 await vault.rotateKEK(newPassphrase);
 process.stderr.write('KEK rotated. Update VAULT_PASSPHRASE to the new value.\n');
 break;
 }

 case 'delete': {
 const name = subPos[1];
 if (!name) fatal('Usage: 40mcp vault delete <name>');
 const passphrase = await resolvePassphrase(subFlags);
 const vault = createVault({ path: vaultPath, passphrase });
 if (!(await vault.has(name))) fatal(`Secret not found: ${name}`);
 await vault.delete(name);
 process.stderr.write(`Deleted: ${name}\n`);
 break;
 }

 case 'recover': {
 process.stderr.write('Enter your recovery key (from vault init):\n');
 const recoveryKey = await promptSecret('Recovery key: ');
 const newPassphrase = await promptSecret('New vault passphrase: ');
 const confirm = await promptSecret('Confirm new passphrase: ');
 if (newPassphrase !== confirm) fatal('Passphrases do not match');
 await recoverVault({ path: vaultPath, recoveryKey, newPassphrase });
 process.stderr.write('Vault recovered. Update VAULT_PASSPHRASE to the new value.\n');
 break;
 }

 case 'daemon': {
 const daemonSub = subPos[1];
 const socketPath = subFlags['socket'] || defaultSocketPath();
 const pidPath = subFlags['pid'] || defaultPidPath();

 switch (daemonSub) {
 case 'start': {
 const passphrase = await resolvePassphrase(subFlags);
 const background = subFlags['background'] || subFlags['b'];

 if (background) {
 // Spawn detached child and exit — passphrase written to stdin, NOT in argv
 const { spawn } = await import('node:child_process');
 const child = spawn(process.execPath, [process.argv[1], 'vault', 'daemon', 'start',
 '--vault', vaultPath, '--socket', socketPath, '--pid', pidPath],
 { detached: true, stdio: ['pipe', 'ignore', 'ignore'] });
 child.stdin.write(passphrase + '\n');
 child.stdin.end();
 child.unref();
 process.stderr.write(`Vault daemon starting (PID ${child.pid})...\n`);
 } else {
 const daemon = await startDaemon({ vaultPath, passphrase, socketPath, pidPath });
 process.stderr.write(`Vault daemon started (pid=${process.pid}).\n`);
 process.stderr.write(`Socket: ${daemon.socketPath}\n`);
 process.stderr.write('VAULT_DAEMON_SECRET is held in-process only. Obtain it via the daemon socket auth handshake; it is never printed to stderr.\n');
 // Keep alive until signal
 await new Promise((resolve) => {
 process.once('SIGINT', () => daemon.close().then(resolve));
 process.once('SIGTERM', () => daemon.close().then(resolve));
 });
 }
 break;
 }

 case 'stop': {
 const secret = process.env.VAULT_DAEMON_SECRET || subFlags['secret'];
 if (!secret) fatal('VAULT_DAEMON_SECRET env var or --secret flag required');
 const { createConnection } = await import('node:net');
 const stopped = await new Promise((resolve) => {
 const sock = createConnection(socketPath);
 let buf = '';
 sock.once('connect', () => {
 sock.write(JSON.stringify({ id: 'stop', type: 'shutdown', daemonSecret: secret }) + '\n');
 });
 sock.on('data', (chunk) => {
 buf += chunk.toString('utf8');
 if (buf.includes('\n')) {
 sock.destroy();
 resolve(true);
 }
 });
 sock.once('error', () => resolve(false));
 });
 process.stderr.write(stopped ? 'Daemon stopped.\n' : 'Daemon not running or wrong secret.\n');
 break;
 }

 case 'status': {
 const { createConnection } = await import('node:net');
 const alive = await new Promise((resolve) => {
 const sock = createConnection(socketPath);
 let buf = '';
 sock.once('connect', () => {
 sock.write(JSON.stringify({ id: 'ping', type: 'ping' }) + '\n');
 });
 sock.on('data', (chunk) => {
 buf += chunk.toString('utf8');
 if (buf.includes('\n')) {
 sock.destroy();
 resolve(true);
 }
 });
 sock.once('error', () => resolve(false));
 });
 process.stdout.write(alive ? 'Daemon is running.\n' : 'Daemon is not running.\n');
 process.exit(alive ? 0 : 1);
 break;
 }

 default:
 process.stderr.write(`Unknown daemon subcommand: ${daemonSub || '(none)'}\n`);
 process.stderr.write('Usage: 40mcp vault daemon <start|stop|status> [--background] [--socket <path>]\n');
 process.exit(1);
 }
 break;
 }

 default:
 process.stderr.write(`Unknown vault subcommand: ${sub || '(none)'}\n`);
 process.stderr.write('Usage: 40mcp vault <init|seal|list|rotate|rotate-kek|delete|recover|daemon>\n');
 process.exit(1);
 }
}

// ─── Init wizard ───────────────────────────────────────────────────────────

async function cmdInit(_flags) {
 const { tui } = await import('./tui.js');

 // Inline readline prompt helper (returns a promise)
 function prompt(question) {
 return new Promise((resolve) => {
 const rl = createInterface({ input: process.stdin, output: process.stderr });
 rl.question(question, (answer) => {
 rl.close();
 resolve(answer.trim());
 });
 });
 }

 async function choose(question, choices) {
 process.stderr.write(`\n${question}\n`);
 choices.forEach((c, i) => process.stderr.write(` ${i + 1}) ${c}\n`));
 while (true) {
 const raw = await prompt(`Choice [1-${choices.length}]: `);
 const n = parseInt(raw, 10);
 if (n >= 1 && n <= choices.length) return n - 1;
 process.stderr.write(` Please enter a number between 1 and ${choices.length}.\n`);
 }
 }

 async function yesNo(question, defaultYes = false) {
 const hint = defaultYes ? '(Y/n)' : '(y/N)';
 const raw = await prompt(`${question} ${hint}: `);
 if (raw === '') return defaultYes;
 return raw.toLowerCase().startsWith('y');
 }

 // ── Step 1: API format ──────────────────────────────────────────────────
 const formatChoices = [
 'OpenAPI/Swagger URL or file path',
 'GraphQL endpoint',
 'HAR recording file',
 'Skip (I\'ll configure manually)',
 ];
 const formatIdx = await choose('What format is your API?', formatChoices);
 const formatKeys = ['openapi', 'graphql', 'har', 'manual'];
 const apiFormat = formatKeys[formatIdx];

 let apiSource = '';
 if (apiFormat !== 'manual') {
 const sourcePrompts = {
 openapi: 'OpenAPI spec URL or file path: ',
 graphql: 'GraphQL endpoint URL: ',
 har: 'HAR recording file path: ',
 };
 apiSource = await prompt(sourcePrompts[apiFormat]);
 }

 // ── Step 2: API name ────────────────────────────────────────────────────
 const rawName = await prompt('\nWhat\'s your API name? [my-api]: ');
 const apiName = rawName || 'my-api';

 // ── Step 3: Auth type ───────────────────────────────────────────────────
 const authChoices = [
 'API key (header)',
 'Bearer token',
 'Basic auth',
 'OAuth2',
 'None',
 ];
 const authIdx = await choose('What auth type does it use?', authChoices);
 const authKeys = ['apikey', 'bearer', 'basic', 'oauth2', 'none'];
 const authType = authKeys[authIdx];

 // ── Step 4: Human approval ──────────────────────────────────────────────
 const needsApproval = await yesNo('\nAny operations that need human approval before running?', false);
 let approvalTools = [];
 if (needsApproval) {
 const raw = await prompt('Enter tool names that require approval (comma-separated): ');
 approvalTools = raw.split(',').map((t) => t.trim()).filter(Boolean);
 }

 // ── Build bridge.json ───────────────────────────────────────────────────
 // `configVersion` is the config-schema version (issue #47), pinned to 1.
 // It is distinct from `version`, the MCP server-version string.
 const bridgeConfig = {
 configVersion: 1,
 name: apiName,
 version: '1.0.0',
 };

 if (apiFormat === 'openapi' && apiSource) {
 bridgeConfig.openapi = apiSource;
 } else if (apiFormat === 'graphql' && apiSource) {
 bridgeConfig.graphql = { endpoint: apiSource };
 } else if (apiFormat === 'har' && apiSource) {
 bridgeConfig.har = apiSource;
 }

 if (authType !== 'none') {
 const authConfigs = {
 apikey: { type: 'header', header: 'X-API-Key', envVar: `${apiName.toUpperCase().replace(/-/g, '_')}_API_KEY` },
 bearer: { type: 'bearer', envVar: `${apiName.toUpperCase().replace(/-/g, '_')}_TOKEN` },
 basic: { type: 'basic', userEnvVar: `${apiName.toUpperCase().replace(/-/g, '_')}_USER`, passEnvVar: `${apiName.toUpperCase().replace(/-/g, '_')}_PASS` },
 oauth2: { type: 'oauth2', tokenEnvVar: `${apiName.toUpperCase().replace(/-/g, '_')}_OAUTH_TOKEN` },
 };
 bridgeConfig.auth = authConfigs[authType];
 }

 if (approvalTools.length > 0) {
 bridgeConfig.tools = approvalTools.map((name) => ({ name, requiresApproval: true }));
 }

 // ── Build.env.example ──────────────────────────────────────────────────
 const envLines = [`# Environment variables for ${apiName}`];
 if (authType === 'apikey') {
 envLines.push(`${apiName.toUpperCase().replace(/-/g, '_')}_API_KEY=your-api-key-here`);
 } else if (authType === 'bearer') {
 envLines.push(`${apiName.toUpperCase().replace(/-/g, '_')}_TOKEN=your-bearer-token-here`);
 } else if (authType === 'basic') {
 envLines.push(`${apiName.toUpperCase().replace(/-/g, '_')}_USER=your-username`);
 envLines.push(`${apiName.toUpperCase().replace(/-/g, '_')}_PASS=your-password`);
 } else if (authType === 'oauth2') {
 envLines.push(`${apiName.toUpperCase().replace(/-/g, '_')}_OAUTH_TOKEN=your-oauth-token`);
 }

 // ── Write files ─────────────────────────────────────────────────────────
 const bridgePath = resolve(process.cwd(), 'bridge.json');
 const envExamplePath = resolve(process.cwd(), '.env.example');

 await writeFile(bridgePath, JSON.stringify(bridgeConfig, null, 2) + '\n', 'utf-8');
 await writeFile(envExamplePath, envLines.join('\n') + '\n', 'utf-8');

 process.stderr.write('\n');
 tui.success(`Generated bridge.json — run: npx 40mcp serve bridge.json`);

 // ── Optional: scaffold 40mcp.settings.json ─────────────────────────────
 const settingsPath = resolve(process.cwd(), '40mcp.settings.json');
 let settingsExists = false;
 try { await access(settingsPath); settingsExists = true; } catch { /* not found */ }
 if (!settingsExists) {
 const scaffoldSettings = await yesNo('Scaffold a 40mcp.settings.json template?', true);
 if (scaffoldSettings) {
  const { buildSettingsScaffold } = await import('./config/settings-scaffold.js');
  await writeFile(settingsPath, buildSettingsScaffold({ instanceName: apiName }), 'utf-8');
  tui.success(`Generated 40mcp.settings.json — runtime knobs (transport, limits, auth, policy)`);
 }
 }

 // ── Claude Desktop integration ──────────────────────────────────────────
 const claudeConfigPaths = platform() === 'darwin'
 ? [resolve(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')]
 : [resolve(homedir(), '.config', 'Claude', 'claude_desktop_config.json')];

 for (const claudeConfigPath of claudeConfigPaths) {
 let claudeConfigExists = false;
 try {
 await access(claudeConfigPath);
 claudeConfigExists = true;
 } catch { /* not found */ }

 if (claudeConfigExists) {
 const addToClaude = await yesNo('\nClaude Desktop detected — add 40mcp to it?', false);
 if (addToClaude) {
 let claudeConfig = {};
 try {
 claudeConfig = JSON.parse(await readFile(claudeConfigPath, 'utf-8'));
 } catch { /* use empty config */ }

 if (!claudeConfig.mcpServers) claudeConfig.mcpServers = {};
 claudeConfig.mcpServers[apiName] = {
 command: 'npx',
 args: ['40mcp', 'serve', bridgePath],
 };

 await writeFile(claudeConfigPath, JSON.stringify(claudeConfig, null, 2) + '\n', 'utf-8');
 tui.success(`Added ${apiName} to Claude Desktop config`);
 }
 break;
 }
 }
}

// ─── Doctor ────────────────────────────────────────────────────────────────

async function cmdSettings(subcommand, flags) {
 if (subcommand !== 'show' && !flags.show) {
  fatal('Usage: 40mcp settings show [--settings <path>] [--json]\n       40mcp settings --show [--settings <path>] [--json]');
 }
 const { buildProvenance, formatProvenance } = await import('./config/settings-show.js');
 let result;
 try {
  result = await loadSettings({ explicitPath: flags.settings });
 } catch (err) {
  fatal(err.message || String(err));
 }
 for (const w of result.warnings) process.stderr.write(`[40mcp] settings WARNING: ${w}\n`);
 const rows = buildProvenance({ settings: result.settings, source: result.source, env: process.env });
 if (flags.json) {
  process.stdout.write(JSON.stringify({ source: result.source, rows }, null, 2) + '\n');
  return;
 }
 // Wording discipline: this is the merged settings tree with known env
 // overlays and default fallthrough — not the fully effective runtime for
 // a specific `serve`/`link` invocation, because CLI flags are only known
 // in that command context. The footer of `formatProvenance` reminds the
 // operator of that gap.
 if (result.source) {
  process.stderr.write(`Loaded from ${result.source}\n`);
 } else {
  process.stderr.write('No 40mcp.settings.json found — showing defaults + env overlays.\n');
 }
 process.stderr.write('(settings + known env overlays + defaults; CLI flags are only resolved in a command context)\n\n');
 process.stdout.write(formatProvenance(rows));
}

async function cmdDoctor(configPath, _flags) {
 if (!configPath) fatal('Usage: 40mcp doctor <config.json>');

 const { tui } = await import('./tui.js');

 let config;
 try {
 config = await loadConfig(configPath);
 } catch (err) {
 if (err.code === 'ENOENT') {
 fatal(`File not found: ${configPath}`);
 } else if (err instanceof SyntaxError) {
 fatal(`Invalid JSON in ${configPath}: ${err.message}`);
 } else {
 fatal(`Failed to load config: ${err.message}`);
 }
 }

 const warnings = [];

 // PII patterns in tool names / descriptions
 const piiPatterns = [
 /\bssn\b/i, /social[_\s-]?security/i, /\bpassword\b/i,
 /credit[_\s-]?card/i, /\bdob\b/i, /date[_\s-]?of[_\s-]?birth/i,
 ];

 const tools = config.tools || [];

 for (const tool of tools) {
 const haystack = `${tool.name || ''} ${tool.description || ''}`;
 for (const pat of piiPatterns) {
 if (pat.test(haystack)) {
 warnings.push(`PII pattern "${pat.source}" found in tool "${tool.name}" name/description`);
 break;
 }
 }
 }

 // Credential headers with literal values (not env var references).
 // An env-ref is any `${VAR}` or `$VAR` token — it may appear standalone
 // (`${GITHUB_TOKEN}`) or embedded after a scheme prefix
 // (`Bearer ${GITHUB_TOKEN}`, `token ${GH_PAT}`, `Basic ${BASIC_CREDS}`).
 // The warning fires only when the header contains no env reference at
 // all, which is a genuine hardcoded credential.
 const envRefPattern = /\$\{?[A-Z_][A-Z0-9_]*\}?/;
 for (const tool of tools) {
 const headers = tool.headers || {};
 for (const [hdr, val] of Object.entries(headers)) {
 const isSensitiveHeader = /^authorization$|^x-api-key$/i.test(hdr);
 const hasEnvRef = typeof val === 'string' && envRefPattern.test(val);
 if (isSensitiveHeader && !hasEnvRef && val) {
 warnings.push(`Tool "${tool.name}" has a literal credential value in header "${hdr}" — use an env var reference instead`);
 }
 }
 }

 // Large response tools — no tokenBudget on likely-large endpoints
 const largePathPattern = /\/(list|all|search|query)(\?|$)/i;
 const idParamPattern = /\/\{[^}]+\}$/;

 for (const tool of tools) {
 const hasTokenBudget = tool.response?.tokenBudget != null;
 if (!hasTokenBudget) {
 const method = (tool.method || '').toUpperCase();
 const path = tool.path || '';
 const likelyLarge = method === 'GET' && (largePathPattern.test(path) || !idParamPattern.test(path));
 if (likelyLarge) {
 warnings.push(`Tool "${tool.name}" (GET ${path}) may return large payloads but has no response.tokenBudget`);
 }
 }
 }

 // Missing auth on non-localhost baseUrl
 if (config.baseUrl) {
 const isLocal = /^https?:\/\/(localhost|127\.|0\.0\.0\.0|::1)/.test(config.baseUrl);
 const hasAuth = Boolean(config.auth);
 if (!isLocal && !hasAuth) {
 warnings.push(`baseUrl "${config.baseUrl}" is not localhost but no auth is configured`);
 }
 // Non-localhost baseUrl without strictSsrf — loopback/private targets
 // would still be permitted by the bridge's default allowPrivate:true.
 // Public production deployments should pin strictSsrf to refuse them.
 if (!isLocal && config.strictSsrf !== true && config.allowPrivate !== false) {
 warnings.push(`baseUrl "${config.baseUrl}" is public but strictSsrf is unset — bridge defaults permit private / loopback targets; set strictSsrf: true to refuse them in production`);
 }
 }

 // Reverse bridge config block — when a reverse listener is defined in the
 // bridge config file, it inherits the same loopback-vs-auth rule the
 // runtime server enforces (see src/reverse/server.js). The config shape
 // is { reverse: { port, host?, auth?: { envVar, header } } }. We only
 // warn; the server itself hard-fails at startup.
 if (config.reverse && typeof config.reverse === 'object') {
 const rv = config.reverse;
 const rvHost = rv.host || '127.0.0.1';
 const rvHostIsLoopback = rvHost === '127.0.0.1' || rvHost === 'localhost' || rvHost === '::1';
 const rvAuthEnv = rv.auth && rv.auth.envVar;
 if (rv.port != null && !rvHostIsLoopback && !rvAuthEnv) {
  warnings.push(`reverse bridge binds ${rvHost}:${rv.port} (non-loopback) but reverse.auth.envVar is unset — the reverse bridge will refuse to start without auth`);
 }
 }

 // Vault path outside the allowlist. Operators can place vaults anywhere,
 // but paths outside CWD and ~/.40mcp/ need extra hardening (ownership,
 // group-read bits). Surface the caveat so deployment scripts can verify.
 if (config.vault && typeof config.vault === 'object' && typeof config.vault.path === 'string' && config.vault.path) {
 const vaultAbs = resolve(config.vault.path);
 const cwdAbs = resolve(process.cwd());
 const homeVaultAbs = resolve(homedir(), '.40mcp');
 const underCwd = vaultAbs === cwdAbs || vaultAbs.startsWith(cwdAbs + '/');
 const underHome = vaultAbs === homeVaultAbs || vaultAbs.startsWith(homeVaultAbs + '/');
 if (!underCwd && !underHome) {
  warnings.push(`vault.path "${vaultAbs}" outside the default allowlist — ensure this path is owned by the service account and is not group-readable`);
 }
 }

 // Settings-aware drift & conflict checks. Load settings with the same
 // discovery rules serve/link use so doctor sees exactly what the running
 // instance would see.
 try {
 const { settings, source: settingsSource, warnings: settingsWarnings } = await loadSettings({
  explicitPath: _flags.settings,
  configPath,
 });
 for (const w of settingsWarnings) warnings.push(`settings: ${w}`);
 if (settingsSource) {
  // Frontdoor published SSE + non-loopback host + no auth → runtime fatal.
  const ft = settings.frontdoor.transport;
  const fa = settings.frontdoor.auth;
  const hasAnyAuth = fa.requireBearerEnv || fa.bearerFile;
  if (ft.type === 'sse' && ft.host && ft.host !== '127.0.0.1' && ft.host !== 'localhost' && ft.host !== '::1' && !hasAnyAuth) {
   warnings.push(`frontdoor.transport binds ${ft.host}:${ft.port ?? '<default>'} (non-loopback) but no frontdoor.auth.* is set — will refuse to publish at runtime`);
  }
  // Bridge SSE + non-loopback host → inbound has no auth surface at all,
  // so publishing there is unsafe regardless. Mirrors the frontdoor check.
  const bt = settings.bridge.transport;
  if (bt.type === 'sse' && bt.host && bt.host !== '127.0.0.1' && bt.host !== 'localhost' && bt.host !== '::1') {
   warnings.push(`bridge.transport binds ${bt.host}:${bt.port ?? '<default>'} (non-loopback) over SSE with no inbound auth — will refuse to publish at runtime`);
  }
  // Tenant map needs multi-token auth.
  if (settings.frontdoor.tenantMap.path && !fa.bearerFile) {
   warnings.push('frontdoor.tenantMap.path is set but frontdoor.auth.bearerFile is not — tenant scoping requires multi-token auth');
  }
  // Vault daemon mode needs the secret.
  if (settings.bridge.vault.daemon && !process.env.VAULT_DAEMON_SECRET) {
   warnings.push('bridge.vault.daemon=true but VAULT_DAEMON_SECRET env var is unset — vault auth will fail at startup');
  }
  // env/settings duplication where env wins — informational so the
  // operator knows the settings file is being shadowed.
  if (process.env.MAX_SSE_CONNECTIONS && settings.frontdoor.limits.sse.maxConnections != null) {
   warnings.push(`frontdoor.limits.sse.maxConnections=${settings.frontdoor.limits.sse.maxConnections} in settings, but MAX_SSE_CONNECTIONS=${process.env.MAX_SSE_CONNECTIONS} in env will override it`);
  }
 }
 } catch (err) {
 // Settings that fail validation are already fatal in loadSettings, but a
 // corrupt file here should just add a doctor warning — the rest of the
 // audit is still useful.
 warnings.push(`settings: ${err.message || String(err)}`);
 }

 // Report
 process.stderr.write('\n');
 if (warnings.length === 0) {
 tui.success('No issues found');
 } else {
 for (const w of warnings) {
 tui.warn(w);
 }
 process.stderr.write('\n');
 process.stderr.write(` ${warnings.length} warning${warnings.length === 1 ? '' : 's'} found\n\n`);
 }
}

function printHelp() {
 process.stderr.write(`
40mcp — The universal API-to-MCP bridge

Commands:
 serve <config> Start MCP server from config file
 from <spec-or-url> Auto-detect format and generate (OpenAPI/GraphQL/HAR/plugin)
 from-openapi <spec> Generate from OpenAPI/Swagger spec
 from-graphql <endpoint> Generate from GraphQL introspection
 from-har <recording.har> Generate from browser traffic
 mix <config1> <config2> [...] Combine multiple APIs into one server
 reverse <config> [--port 8080] Expose MCP tools as REST API
 inspect <config> List tools without starting server
 validate <config> Validate config and report errors/warnings
 generate <spec|--describe> Generate config from OpenAPI spec or LLM prompt
 link <.mcp.json|command> Connect to existing MCP servers and re-expose tools
 vault <subcommand> Manage sealed credential vault
 vault init Create a new vault (returns recovery key)
 vault seal <name> Seal a secret into the vault
 vault list List sealed secrets (names + metadata only)
 vault rotate <name> Re-key a secret with a new DEK
 vault rotate-kek Rotate the master KEK (re-wraps all DEKs)
 vault delete <name> Delete a sealed secret
 vault recover Recover vault access using recovery key
 init Interactive onboarding wizard — generates bridge.json
 doctor <config> Scan config, settings, and env for drift/warnings
 settings show [--settings <p>] Print merged settings + env overlays + defaults (provenance per key)

Options:
 --sse <port> Use SSE transport instead of stdio
 --base-url <url> Override base URL
 --name <name> Server name
 --tags <t1,t2> Filter by tags (OpenAPI)
 --methods <get,post> Filter by HTTP methods
 --include <pattern> Include matching operations
 --exclude <pattern> Exclude matching operations
 --auth-header <name> Auth header name
 --auth-env <var> Env var for auth value
 --auth-bearer-env <v> Env var for bearer token
 --require-bearer-env <v> Inbound bearer token env var for published frontdoor (link --sse)
 --require-bearer <token> Inbound bearer literal for published frontdoor (discouraged)
 --bearer-file <path> JSON {principal: token} for multi-token auth (link --sse)
 --max-sessions-per-principal <N> Concurrent SSE session cap per principal (default 5; multi-token only)
 --policy <path> Policy gate (serve + link) — JSON {toolPolicies, dangerousActions, defaultPolicy}. Honors embedded tool.policy.
 --tenant-map <path> Per-principal tenant scope — JSON {"<principal>": {tenantId, allowlist?, blocklist?}}
 --allowed-origin <o[,o2]> Comma-separated CORS origins for the frontdoor
 --allow-tool <g[,g2]> Glob allowlist for tool names at the frontdoor (link --sse)
 --deny-tool <g[,g2]> Glob denylist for tool names at the frontdoor (link --sse)
 --health-detail Expose per-upstream liveness on /health (link --sse)
 --host <host> Bind host for --sse (default 127.0.0.1)
 --vault-secret <name> Sealed vault secret for header auth (requires --vault-header)
 --vault-bearer <name> Sealed vault secret for bearer token auth
 --vault-header <hdr> Header name for --vault-secret (default: Authorization)
 --vault <path> Vault file path (default: ~/.40mcp/vault.json)
 --port <port> Port for reverse bridge
 --min-observations <n> Min observations for HAR tools

Examples:
 40mcp from ./swagger.json                                     Auto-detect: OpenAPI, GraphQL, HAR, or plugin
 40mcp from-openapi ./swagger.json --auth-header X-API-Key --auth-env API_KEY
 40mcp from-graphql https://api.github.com/graphql --auth-bearer-env GH_TOKEN
 40mcp serve github.json --vault-bearer github-token           Sealed vault bearer auth
 40mcp from-openapi spec.json --vault-secret stripe-key --vault-header X-API-Key
 40mcp from-har ./recording.har --min-observations 3
 40mcp serve configs/github.json                               Use a community config
 40mcp mix stripe.json github.json
 40mcp reverse my-api.json --port 3000

Published frontdoor (see docs/FRONTDOOR.md for the full deployment guide):
 40mcp link frontdoor.mcp.json --sse 8080 --host 0.0.0.0 --require-bearer-env FRONTDOOR_TOKEN
 40mcp link frontdoor.mcp.json --sse 8080 --host 0.0.0.0 --bearer-file /etc/40mcp/tokens.json \\
     --policy /etc/40mcp/policy.json --tenant-map /etc/40mcp/tenants.json
`);
}
