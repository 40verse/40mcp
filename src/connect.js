/**
 * MCP Client Connector — link to existing MCP servers and re-expose their tools.
 *
 * Spawns or connects to upstream MCP servers (stdio or SSE), discovers their tools
 * via ListTools, and makes them available through 40mcp's dispatch system with
 * added capabilities: response transforms, policy gates, sealed vault auth, mixing.
 *
 * This enables 40mcp to act as a meta-bridge / aggregator for the MCP ecosystem.
 *
 * @module connect
 */

import dns from 'node:dns';
import net from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { BridgeError, BridgeErrorCode } from './errors.js';
import { exceedsJsonParseByteLimit, MAX_JSON_PARSE_BYTES } from './connect-size.js';
// Prompt-injection patterns and helpers live in core/sanitize.js so that
// loaders (openapi, graphql, har) and the upstream linker share one policy.
import { hasPromptInjection, sanitizeDescription } from './core/sanitize.js';
import { assertSafeUrl } from './core/env.js';
import { safeLog } from './core/events.js';
import { RESERVED_ENVELOPE_KEYS, MAX_STRIP_DEPTH, emitAuditLog } from './bridge.js';
import { VERSION } from './version.js';

/**
 * Keys an attacker-controlled upstream MCP server must not be able to set
 * on its tool result. Strip any envelope keys that could be used to hijack
 * dispatch behavior or exfiltrate authority.
 */
const UPSTREAM_RESERVED_ENVELOPE_KEYS = RESERVED_ENVELOPE_KEYS;

function stripUpstreamEnvelopes(data, source, toolName, depth = 0) {
  if (depth >= MAX_STRIP_DEPTH) return data;
  if (!data || typeof data !== 'object') return data;
  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i += 1) {
      data[i] = stripUpstreamEnvelopes(data[i], source, toolName, depth + 1);
    }
    return data;
  }
  for (const key of UPSTREAM_RESERVED_ENVELOPE_KEYS) {
    if (key in data) {
      process.stderr.write(
        `[40mcp] SECURITY: stripped ${key} envelope from upstream "${safeLog(source, 128)}" tool "${safeLog(toolName, 128)}" — ` +
        `upstream MCP servers cannot dictate envelope metadata to the local dispatcher.\n`,
      );
      delete data[key];
    }
  }
  for (const k of Object.keys(data)) {
    if (data[k] && typeof data[k] === 'object') {
      data[k] = stripUpstreamEnvelopes(data[k], source, toolName, depth + 1);
    }
  }
  return data;
}

/**
 * Connect to an existing MCP server via stdio (spawns the process).
 *
 * @param {object} config
 * @param {string} config.command - Command to spawn (e.g., 'npx', 'node', 'python')
 * @param {string[]} [config.args] - Command arguments (e.g., ['-y', '@microsoft/mcp-server-azure'])
 * @param {Record<string, string>} [config.env] - Environment variables for the process
 * @param {string} [config.prefix] - Prefix for tool names (e.g., 'azure' → 'azure.list_resources')
 * @param {string[]} [config.allowlist] - Only expose these tools
 * @param {string[]} [config.blocklist] - Hide these tools
 * @param {object} [config.transforms] - Default response transforms for all tools from this server
 * @param {string} [config.policy] - Default policy for all tools ('allow', 'deny', 'require_approval', 'log_only')
 * @returns {Promise<ConnectedServer>}
 *
 * Usage:
 *   const server = await connectStdio({
 *     command: 'npx',
 *     args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
 *     prefix: 'fs',
 *   });
 *   const tools = server.tools; // [{ name: 'fs.read_file', ... }]
 *   const result = await server.dispatch('fs.read_file', { path: '/tmp/test.txt' });
 */
/**
 * Shell interpreters refused by default for the `command` field of
 * connectStdio. A config that sets `command` to one of these is almost
 * certainly a malicious `.mcp.json` trying to pivot to arbitrary shell
 * execution via `args: ["-c", "..."]`. Operators with a legitimate need
 * to run a shell-wrapped MCP server can set `allowShellCommand: true`.
 */
const SHELL_COMMAND_DENYLIST = new Set([
  'sh', 'bash', 'zsh', 'ksh', 'dash', 'fish', 'csh', 'tcsh',
  '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/ksh', '/bin/dash',
  '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/zsh',
  'cmd', 'powershell', 'pwsh',
  // Windows variants — the .exe-stripping check below handles sh.exe, bash.exe, etc.
  'sh.exe', 'bash.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe',
]);

/**
 * Script extensions that are implicitly shell-invoked on Windows by
 * cmd.exe. `.bat` and `.cmd` execute via the command interpreter when
 * launched via certain paths.
 */
const SHELL_SCRIPT_EXTENSIONS = new Set(['.bat', '.cmd', '.ps1']);

/**
 * Sanitize a caller-supplied env dict for a subprocess. Strips any key whose
 * value is not a string, and validates that critical dynamic-loader variables
 * (`PATH`, `LD_PRELOAD`, `DYLD_*`, `NODE_OPTIONS`) are not being set to
 * attacker-controlled values.
 */
function sanitizeSpawnEnv(env) {
  if (!env || typeof env !== 'object') return undefined;
  const DANGEROUS = new Set([
    // Unix dynamic linker
    'PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES',
    'DYLD_LIBRARY_PATH',
    // Node.js — extended to cover all Node/npm injection vectors
    'NODE_OPTIONS',
    'NODE_PATH',               // CJS require() resolution override
    'NODE_EXTRA_CA_CERTS',     // adds CA to trust store → HTTPS MITM primitive
    'NODE_REPL_HISTORY',       // caller-controlled file path
    'NPM_CONFIG_NODE_OPTIONS', // npm → node propagation (NODE_OPTIONS back-channel)
    'NPM_CONFIG_PREFIX',       // npm global module location redirect
    // Python
    'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP',
    // Perl
    'PERL5LIB', 'PERL5OPT',
    // JVM (java, scala, kotlin, groovy)
    'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
    // Ruby
    'RUBYOPT', 'RUBYLIB',
    // Bun
    'BUN_INSTALL', 'BUN_RUNTIME_TRANSPILER_CACHE_PATH',
    // Deno
    'DENO_DIR',
  ]);
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string') continue;
    if (DANGEROUS.has(k)) {
      process.stderr.write(
        `[40mcp] SECURITY: refusing to override dynamic-loader env "${safeLog(k, 64)}" in subprocess env. ` +
        `Remove it from the connectStdio config or trust the parent process env.\n`,
      );
      continue;
    }
    out[k] = v;
  }
  // Merge a minimal safe PATH from the parent so commonly-expected binaries resolve.
  if (process.env.PATH) out.PATH = process.env.PATH;
  return out;
}

export async function connectStdio(config) {
  const { command, args = [], env, prefix, allowlist, blocklist, transforms, policy, allowShellCommand } = config;

  if (!command) {
    throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, 'connectStdio requires a command');
  }
  if (typeof command !== 'string' || command.length === 0) {
    throw new BridgeError(BridgeErrorCode.CONFIG_INVALID, 'connectStdio command must be a non-empty string');
  }
  // Reject shell interpreters by default. A config `{command:"/bin/sh",
  // args:["-c",...]}` is never a legitimate MCP server launch — it's arbitrary
  // code execution via config. Strip .exe before the denylist lookup so
  // `sh.exe`, `SH.EXE`, `./SH`, etc. all normalize to the same key.
  const cmdBasename = command.split(/[\\/]/).pop().toLowerCase();
  const cmdStripped = cmdBasename.endsWith('.exe') ? cmdBasename.slice(0, -4) : cmdBasename;
  // Also reject .bat / .cmd / .ps1 scripts. On Windows these are invoked
  // through the command interpreter when launched by certain paths; on Unix
  // they typically fail ENOENT anyway. Reject uniformly so operators can't
  // accidentally ship a script-wrapped config.
  const cmdExtMatch = cmdBasename.match(/(\.[a-z0-9]+)$/);
  const cmdExt = cmdExtMatch ? cmdExtMatch[1] : '';
  if (
    !allowShellCommand &&
    (
      SHELL_COMMAND_DENYLIST.has(command) ||
      SHELL_COMMAND_DENYLIST.has(cmdBasename) ||
      SHELL_COMMAND_DENYLIST.has(cmdStripped) ||
      SHELL_SCRIPT_EXTENSIONS.has(cmdExt)
    )
  ) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `connectStdio refuses shell interpreter or script "${command}". ` +
      `Shell-wrapped commands are a common supply-chain attack vector via malicious configs. ` +
      `If you really need this, set allowShellCommand: true explicitly.`,
    );
  }
  if (!Array.isArray(args)) {
    throw new BridgeError(BridgeErrorCode.CONFIG_INVALID, 'connectStdio args must be an array');
  }
  for (const a of args) {
    if (typeof a !== 'string') {
      throw new BridgeError(BridgeErrorCode.CONFIG_INVALID, 'connectStdio args entries must all be strings');
    }
  }

  const safeEnv = sanitizeSpawnEnv(env);
  const transport = new StdioClientTransport({
    command,
    args,
    env: safeEnv,
    stderr: 'inherit',
  });

  const client = new Client(
    { name: '40mcp-connector', version: VERSION },
    { capabilities: {} },
  );

  await client.connect(transport);

  return buildConnectedServer(client, transport, { prefix, allowlist, blocklist, transforms, policy, source: `stdio:${command} ${args.join(' ')}` });
}

// ── DNS rebinding guard ─────────────────────────────────────────
//
// assertSafeUrl validates the URL string once at construction time.  A
// public hostname like `attacker.com` passes that check, but an attacker can
// wait for the DNS TTL to expire and rebind the name to 169.254.169.254 (AWS
// IMDS) or another private/cloud-metadata address.  Each EventSource
// auto-reconnect issues a fresh OS-level DNS lookup, so subsequent TCP
// connects land on the newly-advertised IP even though no code ran assertSafeUrl
// again.
//
// Mitigation: after the hostname-string check, resolve the A record and
// validate the resolved IP.  For http:// URLs (no TLS to pin the host
// identity) substitute the resolved IP into the transport URL so that all
// reconnects — including EventSource auto-retries — go to the same IP that
// was validated at construction time.  HTTPS URLs are already protected by
// TLS certificate validation (the cert must match the hostname, not the IP).

/**
 * Validate a pre-resolved IP against the SSRF blocklist.
 *
 * No DNS I/O — takes the hostname (for error messages) and the already-
 * resolved IPv4 address string.  Exported as `_checkResolvedIpForTesting`
 * so the invariant suite can exercise the rebind-block path without network
 * access.
 *
 * @param {string} hostname  Original hostname (used only in error messages)
 * @param {string} resolvedIp  IPv4 address the hostname currently resolves to
 * @param {object} [ssrfOpts]  Same options passed to assertSafeUrl
 * @throws {BridgeError}  When resolvedIp is in a blocked range
 */
function checkResolvedIp(hostname, resolvedIp, ssrfOpts = {}) {
  try {
    assertSafeUrl(`http://${resolvedIp}/`, ssrfOpts);
  } catch (err) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `DNS rebinding guard: "${hostname}" resolved to blocked IP ${resolvedIp} — ${err.message}`,
    );
  }
}

/**
 * DNS-resolve the hostname of a URL string and validate the result.
 * IP-literal hostnames skip the lookup (already validated by assertSafeUrl
 * on the URL string above).
 *
 * @param {string} urlStr  Full URL string
 * @param {object} ssrfOpts  Options forwarded to checkResolvedIp
 * @returns {Promise<string>}  Resolved IPv4 address (or the literal IP)
 */
async function resolveAndCheckHost(urlStr, ssrfOpts) {
  const { hostname } = new URL(urlStr);

  // IP literals are already validated by the caller's assertSafeUrl call.
  if (net.isIP(hostname)) return hostname;

  let address;
  try {
    ({ address } = await dns.promises.lookup(hostname, { family: 4 }));
  } catch (err) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      `connectSse: DNS lookup failed for "${hostname}": ${err.message}`,
    );
  }

  checkResolvedIp(hostname, address, ssrfOpts);
  return address;
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Connect to an existing MCP server via SSE (HTTP endpoint).
 *
 * @param {object} config
 * @param {string} config.url - SSE endpoint URL (e.g., 'http://localhost:8080/sse')
 * @param {Record<string, string>} [config.headers] - Additional headers (auth tokens, etc.)
 * @param {string} [config.prefix] - Prefix for tool names
 * @param {string[]} [config.allowlist] - Only expose these tools
 * @param {string[]} [config.blocklist] - Hide these tools
 * @param {object} [config.transforms] - Default response transforms
 * @param {string} [config.policy] - Default policy
 * @returns {Promise<ConnectedServer>}
 */
export async function connectSse(config) {
  const { url, headers, prefix, allowlist, blocklist, transforms, policy } = config;

  if (!url) {
    throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, 'connectSse requires a url');
  }

  const ssrfOpts = { allowPrivate: config.strictSsrf !== true, label: 'sse url' };

  // Validate the SSE upstream URL BEFORE constructing the transport.
  // Cloud-metadata hosts are blocked unconditionally because there is
  // no legitimate bridge use case for IMDS. Loopback and RFC-1918
  // targets are permitted by default for local dev; set
  // `config.strictSsrf: true` to refuse them too.
  try {
    assertSafeUrl(url, ssrfOpts);
  } catch (err) {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      err.message,
    );
  }

  // Warn when connecting over plain HTTP to a non-loopback host.
  // Emit before DNS resolution so the warning fires even when the lookup fails.
  // Mention the DNS rebinding risk specifically so operators understand
  // why HTTPS is required for production SSE upstreams.
  if (/^http:\/\//i.test(url) && !/^http:\/\/(127\.|localhost)/i.test(url)) {
    process.stderr.write(
      `[40mcp] WARNING: connectSse URL "${safeLog(url, 256)}" uses plain HTTP. ` +
      `Credentials will be transmitted unencrypted and the connection is vulnerable ` +
      `to DNS rebinding attacks (attacker.com → 169.254.169.254 after TTL expiry). ` +
      `Use HTTPS in production.\n`,
    );
  }

  // Resolve the hostname to an IP and validate it. For http:// URLs, substitute
  // the IP into the transport URL so every EventSource auto-reconnect goes to the
  // same IP that was validated at construction time. HTTPS URLs are already
  // protected by TLS certificate validation.
  const resolvedIp = await resolveAndCheckHost(url, ssrfOpts);

  // For http:// (no TLS), pin reconnects to the resolved IP to prevent mid-session
  // DNS rebinding. Build the pinned URL by substituting the hostname with the
  // validated IP, preserving the original Host header.
  let transportUrl = url;
  let transportHeaders = headers;
  if (/^http:\/\//i.test(url) && resolvedIp && !net.isIP(new URL(url).hostname)) {
    const parsed = new URL(url);
    const originalHost = parsed.host; // includes port if present
    parsed.hostname = resolvedIp;
    transportUrl = parsed.toString();
    transportHeaders = { Host: originalHost, ...(headers || {}) };
  }

  // Dynamic import SSE client (may not be available in all SDK versions)
  let SseClientTransport;
  try {
    const mod = await import('@modelcontextprotocol/sdk/client/sse.js');
    SseClientTransport = mod.SSEClientTransport;
  } catch {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      'SSE client transport not available in this MCP SDK version. Use connectStdio instead.',
    );
  }

  const transport = new SseClientTransport(new URL(transportUrl), {
    requestInit: transportHeaders ? { headers: transportHeaders } : undefined,
  });

  const client = new Client(
    { name: '40mcp-connector', version: VERSION },
    { capabilities: {} },
  );

  try {
    await client.connect(transport);
  } catch (err) {
    // Close transport to clear auto-reconnect timers (EventSource retries every 3s)
    await transport.close().catch(() => {});
    throw err;
  }

  return buildConnectedServer(client, transport, { prefix, allowlist, blocklist, transforms, policy, source: `sse:${url}` });
}

/**
 * Connect to an existing MCP server via the Streamable HTTP transport
 * (the current MCP transport spec; SSE is the legacy alternative).
 *
 * Sends MCP messages over HTTP POST and receives responses either as a
 * single JSON body or as an SSE stream that the server opens in reply.
 * Session continuity is carried by the `Mcp-Session-Id` header the SDK
 * manages internally.
 *
 * Security wrapping mirrors `connectSse`: SSRF validation, DNS-rebind
 * pinning for plain-HTTP URLs, egress-strip wrapping, and a plain-HTTP
 * warning. The one transport-level difference is that Streamable HTTP
 * uses `fetch` per request rather than a long-lived EventSource, so the
 * IP-pin substitution still applies to defeat mid-session rebinding.
 *
 * @param {object} config
 * @param {string} config.url - MCP endpoint URL (e.g., 'https://example.com/mcp')
 * @param {Record<string, string>} [config.headers] - Additional headers (auth tokens, etc.)
 * @param {string} [config.prefix] - Prefix for tool names
 * @param {string[]} [config.allowlist] - Only expose these tools
 * @param {string[]} [config.blocklist] - Hide these tools
 * @param {object} [config.transforms] - Default response transforms
 * @param {string} [config.policy] - Default policy
 * @returns {Promise<ConnectedServer>}
 */
export async function connectStreamableHttp(config) {
  const { url, headers, prefix, allowlist, blocklist, transforms, policy } = config;

  if (!url) {
    throw new BridgeError(BridgeErrorCode.CONFIG_MISSING_FIELD, 'connectStreamableHttp requires a url');
  }

  const ssrfOpts = { allowPrivate: config.strictSsrf !== true, label: 'streamable-http url' };

  try {
    assertSafeUrl(url, ssrfOpts);
  } catch (err) {
    throw new BridgeError(BridgeErrorCode.CONFIG_INVALID, err.message);
  }

  if (/^http:\/\//i.test(url) && !/^http:\/\/(127\.|localhost)/i.test(url)) {
    process.stderr.write(
      `[40mcp] WARNING: connectStreamableHttp URL "${safeLog(url, 256)}" uses plain HTTP. ` +
      `Credentials will be transmitted unencrypted and the connection is vulnerable ` +
      `to DNS rebinding attacks (attacker.com → 169.254.169.254 after TTL expiry). ` +
      `Use HTTPS in production.\n`,
    );
  }

  const resolvedIp = await resolveAndCheckHost(url, ssrfOpts);

  let transportUrl = url;
  let transportHeaders = headers;
  if (/^http:\/\//i.test(url) && resolvedIp && !net.isIP(new URL(url).hostname)) {
    const parsed = new URL(url);
    const originalHost = parsed.host;
    parsed.hostname = resolvedIp;
    transportUrl = parsed.toString();
    transportHeaders = { Host: originalHost, ...(headers || {}) };
  }

  let StreamableHttpClientTransport;
  try {
    const mod = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
    StreamableHttpClientTransport = mod.StreamableHTTPClientTransport;
  } catch {
    throw new BridgeError(
      BridgeErrorCode.CONFIG_INVALID,
      'Streamable HTTP client transport not available in this MCP SDK version. Upgrade @modelcontextprotocol/sdk or set `transport: "sse"` on the config entry to use the legacy SSE transport.',
    );
  }

  const transport = new StreamableHttpClientTransport(new URL(transportUrl), {
    requestInit: transportHeaders ? { headers: transportHeaders } : undefined,
  });

  const client = new Client(
    { name: '40mcp-connector', version: VERSION },
    { capabilities: {} },
  );

  try {
    await client.connect(transport);
  } catch (err) {
    await transport.close().catch(() => {});
    throw err;
  }

  return buildConnectedServer(client, transport, { prefix, allowlist, blocklist, transforms, policy, source: `streamable-http:${url}` });
}

/**
 * Dispatch a single URL-based server config to the right transport.
 * Default is `streamable-http` (the current MCP spec); set
 * `serverConfig.transport: "sse"` for legacy SSE servers.
 */
function connectUrlServer(serverConfig) {
  const transport = serverConfig.transport || 'streamable-http';
  if (transport === 'streamable-http') return connectStreamableHttp(serverConfig);
  if (transport === 'sse') return connectSse(serverConfig);
  throw new BridgeError(
    BridgeErrorCode.CONFIG_INVALID,
    `Unknown transport "${transport}" for URL "${serverConfig.url}". Expected "streamable-http" or "sse".`,
  );
}

/**
 * Connect to multiple MCP servers and merge their tools.
 *
 * @param {Array<object>} servers - Array of server connection configs
 *   Each must have either { command, args } (stdio) or { url } (SSE),
 *   plus optional prefix, allowlist, blocklist, transforms, policy.
 * @returns {Promise<{ tools: Array, dispatch: Function, close: Function, connections: Array }>}
 */
export async function connectMany(servers) {
  const allTools = [];
  const dispatchMap = new Map();

  const results = await Promise.allSettled(
    servers.map((serverConfig) =>
      serverConfig.url ? connectUrlServer(serverConfig) : connectStdio(serverConfig),
    ),
  );

  const rejected = results.filter((r) => r.status === 'rejected');
  const fulfilled = results.filter((r) => r.status === 'fulfilled');

  if (rejected.length > 0) {
    // Close any connections that succeeded before the first failure
    for (const r of fulfilled) {
      try { await r.value.close(); } catch { /* best-effort */ }
    }
    throw rejected[0].reason;
  }

  const connections = fulfilled.map((r) => r.value);

  for (const connected of connections) {
    for (const tool of connected.tools) {
      if (dispatchMap.has(tool.name)) {
        throw new BridgeError(
          BridgeErrorCode.CONFIG_INVALID,
          `Duplicate tool name "${tool.name}" across connected servers. Use prefixes to disambiguate.`,
        );
      }
      allTools.push(tool);
      dispatchMap.set(tool.name, connected);
    }
  }

  return {
    tools: allTools,
    connections,

    async dispatch(name, args) {
      const server = dispatchMap.get(name);
      if (!server) {
        throw new BridgeError(BridgeErrorCode.TOOL_NOT_FOUND, `Unknown tool: ${name}`);
      }
      return server.dispatch(name, args);
    },

    /**
     * Graceful shutdown primitive. Forwards `timeoutMs` to
     * each underlying connector so each of them refuses new dispatches,
     * awaits its in-flight work, and closes its transport in parallel.
     * Idempotent — delegates to the per-connector close() which is itself
     * idempotent.
     *
     * @param {{ timeoutMs?: number }} [opts]
     * @returns {Promise<void>}
     */
    async close(opts = {}) {
      // Close all connectors concurrently so the overall wait is bounded
      // by the slowest individual drain rather than their sum.
      await Promise.allSettled(connections.map((c) => c.close(opts)));
    },
  };
}

/**
 * Parse an mcp.json / .mcp.json config file and connect to all servers.
 *
 * @param {object} mcpConfig - Parsed .mcp.json content
 * @param {object} [options]
 * @param {Record<string, string>} [options.prefixes] - { serverName: 'prefix' } overrides
 * @param {string[]} [options.only] - Only connect to these server names
 * @param {string[]} [options.skip] - Skip these server names
 * @returns {Promise<{ tools: Array, dispatch: Function, close: Function }>}
 *
 * Usage:
 *   const config = JSON.parse(fs.readFileSync('.mcp.json', 'utf-8'));
 *   const { tools, dispatch } = await connectFromConfig(config.mcpServers);
 */
export async function connectFromConfig(mcpConfig, options = {}) {
  const {
    prefixes = {},
    only,
    skip,
    // Security options must be forwarded to every per-server entry. Without
    // this, an operator who set `strictSsrf: true` would get permissive mode
    // on every SSE entry because each per-server entry was built without
    // forwarding the top-level options.
    strictSsrf,
    allowShellCommand,
    allowPrivate,
    allowSuspiciousDescriptions,
  } = options;

  // Extract top-level security options so they can be forwarded to every
  // per-server entry. Server-level values (from serverDef) override the global
  // defaults so callers can tighten or loosen policy per entry.
  // Include allowSuspiciousDescriptions in securityOpts so per-server
  // serverDef.options can override it, and all code paths use
  // serverOpts.allowSuspiciousDescriptions consistently.
  const securityOpts = {
    strictSsrf,
    allowShellCommand,
    allowPrivate,
    allowSuspiciousDescriptions,
  };

  const servers = [];

  for (const [name, serverDef] of Object.entries(mcpConfig)) {
    if (only && !only.includes(name)) continue;
    if (skip && skip.includes(name)) continue;

    // `.mcp.json` entry-level `prefix` was never consumed here — the entry
    // key is the canonical prefix. Operators who set it expected it to
    // win, then were silently overridden by the entry key. Reject outright
    // so the confusion surfaces at config load, not after a dispatch miss.
    if (serverDef && typeof serverDef === 'object' && Object.prototype.hasOwnProperty.call(serverDef, 'prefix')) {
      throw new BridgeError(
        BridgeErrorCode.CONFIG_INVALID,
        `.mcp.json entry "${name}" has a "prefix" field. The entry key is the canonical prefix — remove "prefix" from the entry body.`,
      );
    }

    const prefix = prefixes[name] || name;

    if (serverDef.command) {
      // Merge: top-level security opts first, then server-level overrides.
      const serverOpts = { ...securityOpts, ...serverDef.options };
      servers.push({
        command: serverDef.command,
        args: serverDef.args || [],
        env: serverDef.env || undefined,
        prefix,
        // Forward security options so per-server calls honour global policy.
        ...(serverOpts.allowShellCommand !== undefined && { allowShellCommand: serverOpts.allowShellCommand }),
        ...(serverOpts.allowSuspiciousDescriptions !== undefined && { allowSuspiciousDescriptions: serverOpts.allowSuspiciousDescriptions }),
      });
    } else if (serverDef.url) {
      // Merge: top-level security opts first, then server-level overrides.
      const serverOpts = { ...securityOpts, ...serverDef.options };
      servers.push({
        url: serverDef.url,
        headers: serverDef.headers || undefined,
        transport: serverDef.transport,
        prefix,
        // Forward security options so per-server calls honour global policy.
        ...(serverOpts.strictSsrf !== undefined && { strictSsrf: serverOpts.strictSsrf }),
        ...(serverOpts.allowPrivate !== undefined && { allowPrivate: serverOpts.allowPrivate }),
        ...(serverOpts.allowSuspiciousDescriptions !== undefined && { allowSuspiciousDescriptions: serverOpts.allowSuspiciousDescriptions }),
      });
    }
  }

  return connectMany(servers);
}

// ─── Internal ───────────────────────────────────────────────────────────────

/** MCP protocol version this connector expects after handshake */
const EXPECTED_MCP_PROTOCOL = '2024-11-05';

/** JSON Schema keys that are safe to pass through from upstream tool schemas */
const ALLOWED_SCHEMA_KEYS = new Set([
  'type', 'properties', 'required', 'description', 'enum', 'items',
  'additionalProperties', 'title', 'default', 'minimum', 'maximum',
  'minLength', 'maxLength', 'pattern', 'format', 'anyOf', 'oneOf', 'allOf', 'not',
]);

/** Keys that must never appear in a schema (prototype-poisoning / injection) */
const BLOCKED_SCHEMA_KEYS = new Set(['$ref', '$schema', '$defs', '__proto__', 'constructor', 'prototype']);

/**
 * Sanitize an upstream tool inputSchema.
 * Removes $ref (may point to attacker-controlled resources), blocked keys, and
 * caps nesting depth to prevent DoS during downstream schema validation.
 * @private
 * @internal Exported as _sanitizeInputSchemaForTesting for unit tests only.
 */
function sanitizeInputSchema(schema, depth = 0) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema) || depth > 5) {
    return { type: 'object', properties: {} };
  }
  const safe = {};
  for (const [key, value] of Object.entries(schema)) {
    if (BLOCKED_SCHEMA_KEYS.has(key) || !ALLOWED_SCHEMA_KEYS.has(key)) continue;
    if (key === 'properties' && value && typeof value === 'object' && !Array.isArray(value)) {
      safe.properties = {};
      for (const [propName, propSchema] of Object.entries(value)) {
        if (BLOCKED_SCHEMA_KEYS.has(propName)) continue;
        const sanitizedProp = sanitizeInputSchema(propSchema, depth + 1);
        // The top-level tool `description` is already scanned for prompt injection.
        // Parameter descriptions are NOT — an upstream MCP server can embed
        // injection in `properties[k].description` which surfaces verbatim in the
        // LLM context alongside the tool schema. Apply sanitizeDescription so
        // injection patterns become a neutral placeholder (preserves schema shape).
        if (sanitizedProp.description) {
          sanitizedProp.description = sanitizeDescription(sanitizedProp.description, { label: 'tool param' });
        }
        safe.properties[propName] = sanitizedProp;
      }
    } else if (key === 'items' && value && typeof value === 'object') {
      safe.items = sanitizeInputSchema(value, depth + 1);
    } else if ((key === 'anyOf' || key === 'oneOf' || key === 'allOf') && Array.isArray(value)) {
      safe[key] = value.map((s) => sanitizeInputSchema(s, depth + 1));
    } else if (key === 'not' && value && typeof value === 'object') {
      safe.not = sanitizeInputSchema(value, depth + 1);
    } else if (key !== 'required') {
      // 'required' is handled below after properties are sanitized
      safe[key] = value;
    }
  }

  // Filter 'required' to only keys that survived into safe.properties.
  // If a blocked property name (e.g. '__proto__') was stripped from properties
  // but left in required, downstream APIs (Claude, OpenAI) reject with HTTP 400.
  if (Array.isArray(schema.required)) {
    const survivingKeys = new Set(Object.keys(safe.properties || {}));
    const filteredRequired = schema.required.filter(
      (k) => typeof k === 'string' && survivingKeys.has(k),
    );
    if (filteredRequired.length > 0) safe.required = filteredRequired;
  }

  return Object.keys(safe).length > 0 ? safe : { type: 'object', properties: {} };
}

// Named exports for unit testing — signals internal/test-only status
export { sanitizeInputSchema as _sanitizeInputSchemaForTesting };
export { sanitizeSpawnEnv as _sanitizeSpawnEnvForTesting };
// DNS rebinding guard — export the IP validation step for
// invariant testing without requiring real DNS lookups.
export { checkResolvedIp as _checkResolvedIpForTesting };

async function buildConnectedServer(client, transport, options) {
  const { prefix, allowlist, blocklist, transforms, policy, source } = options;

  // Warn if the upstream server negotiated an unexpected MCP protocol version
  try {
    const initResult = client.initializeResult ?? client._initializeResult;
    const pv = initResult?.protocolVersion;
    if (pv && pv !== EXPECTED_MCP_PROTOCOL) {
      process.stderr.write(
        `[40mcp] WARNING: Upstream server "${safeLog(source, 128)}" negotiated MCP protocol version "${safeLog(pv, 64)}", ` +
        `expected "${EXPECTED_MCP_PROTOCOL}". Compatibility issues may occur.\n`,
      );
    }
  } catch { /* protocol version not accessible in this SDK version — skip */ }

  // Discover tools from the upstream server
  const listResult = await client.listTools();
  const upstreamTools = listResult.tools || [];

  // H15 — validate tool names from upstream before registering them.
  // An attacker-controlled MCP server can return tool names with arbitrary
  // characters (newlines, null bytes, prototype keys) that would corrupt the
  // toolMap, forge audit log lines, or pollute the LLM context. Reject any
  // name that doesn't conform to alphanumeric + underscore + hyphen + dot,
  // capped at 64 chars. Dots are allowed so a 40mcp client can consume another
  // 40mcp frontdoor (which publishes prefixed names like `msdocs.search`) — the
  // self-incompatibility was a P0 ecosystem bug. Dots are inert for path,
  // shell, and log-line concerns.
  const VALID_TOOL_NAME = /^[a-zA-Z0-9_\-.]{1,64}$/;

  // Filter and prefix tools
  const tools = [];
  for (const tool of upstreamTools) {
    if (!tool.name || !VALID_TOOL_NAME.test(tool.name)) {
      throw new BridgeError(
        BridgeErrorCode.CONFIG_INVALID,
        `Connected tool has invalid name "${String(tool.name).slice(0, 32)}" — must be alphanumeric + underscore/hyphen/dot, max 64 chars`,
      );
    }

    if (allowlist && !allowlist.includes(tool.name)) continue;
    if (blocklist && blocklist.includes(tool.name)) continue;

    const finalName = prefix ? `${prefix}.${tool.name}` : tool.name;
    const description = tool.description || '';

    // Reject tools whose descriptions look like prompt injection. Upstream
    // MCP servers are not trusted; their descriptions are injected into the
    // LLM context verbatim. Phase-1 review found that the previous "warn but
    // register anyway" behaviour left an unconditional injection channel.
    // Drop the tool entirely so the LLM never sees the
    // payload. Operators that explicitly trust the upstream can opt out via
    // `options.allowSuspiciousDescriptions: true`.
    if (hasPromptInjection(description)) {
      // `finalName` and `source` are upstream-controlled strings. A hostile
      // upstream picks a name with embedded newlines to forge a matching
      // [40mcp] SECURITY: line that looks like a legitimate drop, masking
      // the real attack. Scrub control characters before emit.
      process.stderr.write(
        `[40mcp] SECURITY: tool "${safeLog(finalName, 128)}" from upstream "${safeLog(source, 128)}" was DROPPED — ` +
        `description matched a prompt-injection pattern. Set allowSuspiciousDescriptions:true to override.\n`,
      );
      if (!options.allowSuspiciousDescriptions) {
        continue;
      }
    }

    // Sanitize upstream inputSchema: strip $ref and dangerous keys
    const safeSchema = sanitizeInputSchema(tool.inputSchema) || { type: 'object', properties: {} };

    tools.push({
      name: finalName,
      description,
      inputSchema: safeSchema,
      _upstream: tool.name,
      _source: source,
      _policy: policy,
      _transforms: transforms,
    });
  }

  // Strip prefix for upstream dispatch
  function resolveUpstreamName(name) {
    if (prefix && name.startsWith(`${prefix}.`)) {
      return name.substring(prefix.length + 1);
    }
    return name;
  }

  // Lightweight liveness tracking — flips to 'degraded' on any dispatch
  // failure and back to 'ok' on the next success. Exposed via `getStatus()`
  // so the frontdoor `/health` endpoint can surface per-upstream state
  // without doing an extra RPC probe.
  let _status = 'ok';
  let _lastError = null;

  // Graceful shutdown state. Mirrors the bridge's close()
  // contract: refuse new dispatches, await in-flight up to `timeoutMs`,
  // close the transport, emit `bridge.shutdown_timeout` on deadline.
  // Idempotent: second close() returns the same promise.
  const shutdownState = {
    closing: false,
    inFlight: new Set(),
  };
  let closePromise = null;

  return {
    tools,
    client,
    source,
    getStatus() { return _status; },
    getLastError() { return _lastError; },
    _closed: false,

    async dispatch(name, args) {
      if (shutdownState.closing) {
        emitAuditLog({
          ts: Date.now(),
          event: 'bridge.shutdown_refused',
          tool: name,
          status: 'error',
          errorCode: BridgeErrorCode.SHUTTING_DOWN,
          source,
        });
        throw new BridgeError(
          BridgeErrorCode.SHUTTING_DOWN,
          `Connector "${source}" is shutting down — refusing dispatch of "${name}".`,
        );
      }
      let releaseTracking;
      const tracking = new Promise((resolve) => { releaseTracking = resolve; });
      shutdownState.inFlight.add(tracking);
      try {
        const upstreamName = resolveUpstreamName(name);
        let result;
        try {
          result = await client.callTool({ name: upstreamName, arguments: args || {} });
          _status = 'ok';
          _lastError = null;
        } catch (err) {
          _status = 'degraded';
          _lastError = err && err.message ? String(err.message).slice(0, 200) : 'unknown';
          throw err;
        }

        // Extract text content from MCP response
        let data;
        if (result.content && Array.isArray(result.content)) {
          const textContent = result.content.find((c) => c.type === 'text');
          if (textContent) {
            // Guard against memory exhaustion from oversized upstream responses.
            // Strings larger than 10 MB are returned as-is rather than parsed.
            if (exceedsJsonParseByteLimit(textContent.text)) {
              process.stderr.write(
                `[40mcp] WARNING: upstream tool response exceeds ${MAX_JSON_PARSE_BYTES} bytes — ` +
                `returning as raw string without JSON.parse\n`,
              );
              data = textContent.text;
            } else {
              try {
                data = JSON.parse(textContent.text);
              } catch {
                data = textContent.text;
              }
            }
          } else {
            data = result.content;
          }
        } else {
          data = result;
        }

        // Strip any `_steering` / `_chain` envelope the upstream MCP server
        // might inject into its tool result. The 40mcp envelopes are the
        // operator's authority channel — an attacker-controlled upstream must
        // not be able to dictate agent steering or chain control via returned
        // JSON. Walk arrays too, and strip a second time AFTER response
        // transforms run in case a transform re-introduces a key.
        data = stripUpstreamEnvelopes(data, source, upstreamName);

        // Apply default transforms if configured
        if (transforms && data) {
          const { applyResponseTransform } = await import('./transforms/response.js');
          data = applyResponseTransform(data, transforms);
          data = stripUpstreamEnvelopes(data, source, upstreamName);
        }

        return data;
      } finally {
        shutdownState.inFlight.delete(tracking);
        try { releaseTracking(); } catch { /* never throws */ }
      }
    },

    /**
     * Graceful shutdown primitive. Aligns with the bridge's
     * close() contract: refuses new dispatches, awaits in-flight dispatches
     * up to `timeoutMs` (default 10 s), closes the client transport,
     * emits `bridge.shutdown_timeout` if the deadline elapsed. Idempotent.
     * Never calls `process.exit`.
     *
     * @param {{ timeoutMs?: number }} [opts]
     * @returns {Promise<void>}
     */
    close({ timeoutMs = 10_000 } = {}) {
      if (closePromise) return closePromise;
      shutdownState.closing = true;
      _status = 'closed';

      closePromise = (async () => {
        const snapshot = Array.from(shutdownState.inFlight);
        let timedOut = false;
        if (snapshot.length > 0) {
          await new Promise((resolve) => {
            let settled = false;
            const timer = setTimeout(() => {
              if (settled) return;
              settled = true;
              timedOut = true;
              resolve();
            }, timeoutMs);
            if (typeof timer.unref === 'function') timer.unref();
            Promise.allSettled(snapshot).then(() => {
              if (settled) return;
              settled = true;
              clearTimeout(timer);
              resolve();
            });
          });
        }

        if (timedOut) {
          emitAuditLog({
            ts: Date.now(),
            event: 'bridge.shutdown_timeout',
            inFlightCount: shutdownState.inFlight.size,
            timeoutMs,
            source,
          });
        }

        try {
          await transport.close();
        } catch { /* best-effort */ }
      })();
      return closePromise;
    },
  };
}
