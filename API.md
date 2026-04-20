# 40mcp API Reference

The universal API-to-MCP bridge. Convert any REST API, GraphQL schema, or HAR file into an MCP server.

## Table of Contents

- [Core Bridge](#core-bridge)
- [Configuration](#configuration)
- [Validation](#validation)
- [Terminal UI](#terminal-ui)
- [Schema Loaders](#schema-loaders)
- [Response Transforms](#response-transforms)
- [Composition](#composition)
- [Transport](#transport)
- [Reverse Bridge](#reverse-bridge)
- [Webhooks](#webhooks)
- [Multi-Tenancy](#multi-tenancy)
- [Security](#security)
- [AI-Assisted Generation](#ai-assisted-generation)
- [MCP Client Connector](#mcp-client-connector)
- [Error Codes](#error-codes)
- [Error Classes](#error-classes)
- [Quick Start Examples](#quick-start-examples)
- [Type Definitions](#type-definitions)
- [Agent Steering (Core Configuration Element)](#agent-steering-core-configuration-element)
- [Resources](#resources)

---

## Core Bridge

### `createRestBridge(config)`

Create an MCP server that wraps a REST API.

**Signature:**
```js
function createRestBridge(config: BridgeConfig): BridgeInstance
```

**Parameters:**
- `config` (BridgeConfig) — Server configuration with `baseUrl`, optional `auth`, optional `hooks`, and `tools` array.

**Returns:**
- `BridgeInstance` — Server instance with `start()`, `server`, `dispatch`, and `apiClient` properties.

**Example:**
```js
import { createRestBridge } from '40mcp';

const bridge = createRestBridge({
  name: 'petstore',
  version: '1.0.0',
  baseUrl: 'https://petstore3.swagger.io/api/v3',
  auth: {
    type: 'bearer',
    envVar: 'API_KEY',
  },
  tools: [
    {
      name: 'list_pets',
      description: 'List pets by status.',
      method: 'GET',
      path: '/pet/findByStatus',
      queryMap: { pet_status: 'status' },
      inputSchema: {
        type: 'object',
        properties: {
          pet_status: { type: 'string', enum: ['available', 'pending', 'sold'] },
        },
        required: ['pet_status'],
      },
    },
  ],
});

await bridge.start();
```

**BridgeInstance properties:**
- `server: Server` — The underlying MCP server.
- `dispatch: DispatchFn` — Call tools programmatically: `dispatch(toolName, args)`.
- `apiClient: (method, path, body?) => Promise<any>` — Direct API access.
- `start(): Promise<BridgeStartResult>` — Start the server (stdio transport by default).

**Audit trail:**
Every tool dispatch (both direct REST calls and compound chains) emits a structured `[40mcp:audit]` JSON line to stderr:
```json
{ "ts": 1712663931000, "tool": "get_user", "status": "success", "durationMs": 42 }
{ "ts": 1712663932000, "tool": "delete_user", "status": "error", "errorCode": "HTTP_403", "durationMs": 7 }
```
Fields: `ts` (Unix epoch ms), `tool` (tool name), `status` (`'success'` or `'error'`), `durationMs` (call duration), `errorCode` (only on error). Tool arguments are intentionally omitted — they may contain credentials or PII.

---

## Configuration

### `loadConfig(filePath)`

Load a bridge configuration from a JSON or YAML file.

**Signature:**
```js
function loadConfig(filePath: string): Promise<BridgeConfig>
```

**Parameters:**
- `filePath` (string) — Path to `.json`, `.yaml`, or `.yml` config file.

**Returns:**
- `Promise<BridgeConfig>` — Parsed configuration.

**Example:**
```js
import { loadConfig, createRestBridge } from '40mcp';

const config = await loadConfig('./bridge.json');
const bridge = createRestBridge(config);
await bridge.start();
```

**Config file format (bridge.json):**
```json
{
  "name": "my-api",
  "version": "1.0.0",
  "baseUrl": "https://api.example.com",
  "auth": {
    "type": "bearer",
    "envVar": "API_TOKEN"
  },
  "tools": [
    {
      "name": "get_user",
      "description": "Fetch a user by ID",
      "method": "GET",
      "path": "/users/:user_id",
      "inputSchema": {
        "type": "object",
        "properties": {
          "user_id": { "type": "integer" }
        },
        "required": ["user_id"]
      }
    }
  ]
}
```

---

## Validation

### `validateConfig(config)`

Validate a bridge configuration without throwing errors.

**Signature:**
```js
function validateConfig(config: BridgeConfig | Record<string, any>): ValidationResult
```

**Parameters:**
- `config` — Configuration object to validate.

**Returns:**
- `ValidationResult` — Object with `valid: boolean`, `errors: string[]`, `warnings: string[]`.

**Example:**
```js
import { validateConfig } from '40mcp';

const result = validateConfig(myConfig);
if (!result.valid) {
  console.log('Errors:', result.errors);
  console.log('Warnings:', result.warnings);
}
```

### `assertValidConfig(config)`

Validate a configuration and throw `BridgeError` if invalid.

**Signature:**
```js
function assertValidConfig(config: BridgeConfig | Record<string, any>): void
```

**Parameters:**
- `config` — Configuration to validate.

**Throws:**
- `BridgeError` with code `CONFIG_INVALID` if validation fails.

**Example:**
```js
import { assertValidConfig } from '40mcp';

try {
  assertValidConfig(myConfig);
} catch (err) {
  console.error('Config invalid:', err.message);
}
```

---

## Terminal UI

### `tui` (namespace)

Static methods for rendering terminal output with colors, tables, spinners, and more.

**Signature:**
```js
export const tui: {
  // Detection
  isTTY: boolean;
  isNoColor: boolean;
  isMcpStdio: boolean;
  
  // Colors
  color(text: string, code: number): string;
  bold(text: string): string;
  dim(text: string): string;
  red(text: string): string;
  green(text: string): string;
  yellow(text: string): string;
  blue(text: string): string;
  cyan(text: string): string;
  gray(text: string): string;
  
  // Cursor control
  cursor: { hide(): void; show(): void };
  
  // Interactive widgets
  spinner(label?: string): TuiSpinner;
  progress(current: number, total: number, label?: string): void;
  table(rows: TuiTableRow[], options?: { headers?: string[]; title?: string }): void;
  box(content: string, options?: { title?: string; width?: number }): void;
  toolTable(tools: Array<{ name: string; description?: string }>, options?: { title?: string }): void;
  
  // Output lines
  statusLine(label: string, value: string, options?: { color?: string }): void;
  activityLine(message: string): void;
  banner(title: string, subtitle?: string): void;
  
  // Messages
  fatal(message: string): void;
  success(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  jsonOutput(data: unknown): void;
}
```

**TuiSpinner interface:**
- `start(label?: string): void` — Start spinner.
- `stop(label?: string): void` — Stop and print label.
- `succeed(label?: string): void` — Stop with ✓ and green label.
- `fail(label?: string): void` — Stop with ✗ and red label.

**Examples:**
```js
import { tui } from '40mcp';

// Colors
console.log(tui.green('Success!'));
console.log(tui.red('Error!'));

// Spinner
const spinner = tui.spinner('Loading data...');
spinner.start();
// ... do work ...
spinner.succeed('Data loaded');

// Table
tui.table(
  [
    { name: 'list_pets', description: 'List all pets' },
    { name: 'get_pet', description: 'Get pet by ID' },
  ],
  { title: 'Available Tools' }
);

// Banner
tui.banner('40mcp Server', 'v1.0.0');

// Status
tui.statusLine('API', 'https://api.example.com', { color: 'cyan' });
tui.success('Server ready at http://localhost:3000');
```

---

## Schema Loaders

Auto-generate tools from API specs.

### `loadOpenApiSpec(specOrPath, options?)`

Load an OpenAPI 3.0+ specification and generate tool definitions.

**Signature:**
```js
function loadOpenApiSpec(
  specOrPath: string | object,
  options?: OpenApiLoaderOptions
): Promise<LoaderResult>
```

**Parameters:**
- `specOrPath` — URL, file path, or parsed OpenAPI object.
- `options.include` — Tool name patterns to include (strings or regexes).
- `options.exclude` — Tool name patterns to exclude.
- `options.tags` — OpenAPI tags to include (e.g., `['pet', 'store']`).
- `options.methods` — HTTP methods to include (lowercase: `['get', 'post']`).
- `options.nameTransform` — Custom tool naming: `(operationId, method, pathTemplate) => string`.

**Returns:**
- `Promise<LoaderResult>` — Object with `baseUrl: string` and `tools: ToolDef[]`.

**Example:**
```js
import { createRestBridge, loadOpenApiSpec } from '40mcp';

const { baseUrl, tools } = await loadOpenApiSpec(
  'https://petstore3.swagger.io/api/v3/openapi.json',
  {
    tags: ['pet'],
    methods: ['get', 'post'],
    nameTransform: (opId, method, path) => `${method.toLowerCase()}_${opId}`,
  }
);

const bridge = createRestBridge({
  name: 'petstore',
  baseUrl,
  tools,
});

await bridge.start();
```

### `loadGraphqlSchema(endpointOrSchema, options?)`

Load a GraphQL schema and generate tool definitions for queries and mutations.

**Signature:**
```js
function loadGraphqlSchema(
  endpointOrSchema: string | object,
  options?: GraphqlLoaderOptions
): Promise<LoaderResult>
```

**Parameters:**
- `endpointOrSchema` — GraphQL endpoint URL or introspection result object.
- `options.include` — Field name patterns to include.
- `options.exclude` — Field name patterns to exclude.
- `options.types` — Operation types to include: `['query', 'mutation']`.
- `options.headers` — Headers for introspection request (e.g., auth).
- `options.endpoint` — Override endpoint if passing a schema object.
- `options.nameTransform` — Custom naming: `(fieldName, operationType) => string`.

**Returns:**
- `Promise<LoaderResult>` — Object with `baseUrl` and `tools`.

**Example:**
```js
import { createRestBridge, loadGraphqlSchema } from '40mcp';

const { baseUrl, tools } = await loadGraphqlSchema(
  'https://api.example.com/graphql',
  {
    types: ['query', 'mutation'],
    headers: { 'Authorization': 'Bearer token...' },
  }
);

const bridge = createRestBridge({
  name: 'graphql-api',
  baseUrl,
  tools,
});

await bridge.start();
```

### `loadHarFile(harOrPath, options?)`

Load a HAR (HTTP Archive) file and infer tool definitions from recorded requests.

**Signature:**
```js
function loadHarFile(
  harOrPath: string | object,
  options?: HarLoaderOptions
): Promise<HarLoaderResult>
```

**Parameters:**
- `harOrPath` — Path to `.har` file or parsed HAR object.
- `options.include` — Path patterns to include.
- `options.exclude` — Path patterns to exclude.
- `options.methods` — HTTP methods to include.
- `options.minObservations` — Only include endpoints seen N+ times (default: 1).

**Returns:**
- `Promise<HarLoaderResult>` — Object with `baseUrl` and `tools: HarToolDef[]`.

**HarToolDef additional fields:**
- `_confidence` — Confidence level: `'low'`, `'medium'`, or `'high'`.
- `_observations` — Number of times endpoint was recorded.

**Example:**
```js
import { createRestBridge, loadHarFile } from '40mcp';

const { baseUrl, tools } = await loadHarFile('./recording.har', {
  minObservations: 2, // Only tools seen 2+ times
});

const bridge = createRestBridge({
  name: 'from-har',
  baseUrl,
  tools: tools.filter(t => t._confidence === 'high'),
});

await bridge.start();
```

### `loadFromAny(input, options?)`

Auto-detect and load any supported format (OpenAPI, GraphQL, HAR, etc.).

**Signature:**
```js
function loadFromAny(
  input: string | object,
  options?: Record<string, any>
): Promise<LoaderResult>
```

**Parameters:**
- `input` — URL, file path, or parsed object.
- `options` — Format-specific options (merged with detected options).

**Returns:**
- `Promise<LoaderResult>` — Object with `baseUrl` and `tools`.

**Example:**
```js
import { createRestBridge, loadFromAny } from '40mcp';

// Auto-detect: OpenAPI, GraphQL, HAR, etc.
const { baseUrl, tools } = await loadFromAny(
  'https://api.example.com/spec.json'
);

const bridge = createRestBridge({
  name: 'auto-loaded',
  baseUrl,
  tools,
});

await bridge.start();
```

### `registerLoader(plugin)`

Register a custom schema loader plugin.

**Signature:**
```js
function registerLoader(plugin: LoaderPlugin): void
```

**LoaderPlugin interface:**
```ts
interface LoaderPlugin {
  name: string;
  detect: (input: string | object) => boolean;
  load: (input: string | object, options?: Record<string, any>) => Promise<LoaderResult>;
}
```

**Example:**
```js
import { registerLoader } from '40mcp';

registerLoader({
  name: 'custom-format',
  detect: (input) => {
    return typeof input === 'object' && input.type === 'custom';
  },
  load: async (input, options) => {
    // Convert custom format to tools
    return { baseUrl: input.baseUrl, tools: input.tools };
  },
});
```

### `listLoaders()`

List all registered loaders (built-in and custom).

**Signature:**
```js
function listLoaders(): Array<{ name: string; builtin: boolean }>
```

**Returns:**
- Array of loader metadata.

**Example:**
```js
import { listLoaders } from '40mcp';

const loaders = listLoaders();
console.log('Available loaders:', loaders.map(l => l.name).join(', '));
```

---

## Response Transforms

### `applyResponseTransform(data, transform?)`

Transform API response data using a declarative transform spec.

**Signature:**
```js
function applyResponseTransform(
  data: any,
  transform?: ResponseTransform
): any
```

**ResponseTransform options:**
- `pick: string[]` — Only include these fields (dot notation for nesting: `'user.name'`).
- `omit: string[]` — Exclude these fields.
- `limit: number` — Limit array results to N items.
- `flatten: boolean` — Flatten nested objects one level.
- `summary: boolean | string` — Replace with LLM-generated summary (or custom prompt if string).
- `tokenBudget: number` — Max tokens in output (trucates if exceeded).
- `template: string` — Mustache template to reshape response.

**Example:**
```js
import { applyResponseTransform } from '40mcp';

const response = {
  id: 123,
  name: 'John Doe',
  email: 'john@example.com',
  metadata: { /* huge */ },
  items: [/* array of 1000 items */],
};

const transformed = applyResponseTransform(response, {
  pick: ['id', 'name', 'email'],
  limit: 10,
});
// Result: { id: 123, name: 'John Doe', email: 'john@example.com', items: [first 10] }
```

---

## Composition

### `executeChain(steps, args, dispatch, options?)`

Execute a multi-step tool chain where each step's output feeds into the next.

**Signature:**
```js
function executeChain(
  steps: ChainStep[],
  args: Record<string, any>,
  dispatch: DispatchFn,
  options?: ChainOptions
): Promise<ChainResult>
```

**ChainStep structure:**
```ts
interface ChainStep {
  call: string;           // Tool name to call
  as: string;            // Variable name for this step's result
  args?: Record<string, any>;  // Args (can reference $args and $stepName)
  optional?: boolean;    // Silently skip if fails
}
```

**ChainOptions:**
- `maxDepth` — Max nesting depth (default: 10).
- `response` — ResponseTransform to apply to final result.

**ChainResult:**
```ts
interface ChainResult {
  _chain: {
    steps: number;
    completed: number;
    failed: number;
    errors: Array<{ step: string; message: string }>;
  };
  [stepName: string]: any;  // Results keyed by step 'as' names
}
```

**Optional step failures:**
When a step marked `optional: true` fails, its result is a sanitized error object — not the raw error message — to prevent API tokens or upstream error bodies from leaking to downstream steps:
```json
{ "_error": "step failed", "_error_code": "HTTP_401" }
```
`_error_code` is a safe all-caps alphanumeric code (e.g. `HTTP_401`, `TYPE_ERROR`, `STEP_FAILED`). The full error message is written to stderr only.

**Example:**
```js
import { executeChain } from '40mcp';

const result = await executeChain(
  [
    {
      call: 'get_user',
      as: 'user',
      args: { user_id: '$args.user_id' },
    },
    {
      call: 'get_user_posts',
      as: 'posts',
      args: { user_id: '$user.id' },
    },
    {
      call: 'get_user_comments',
      as: 'comments',
      args: { post_ids: '$posts.*.id' }, // Array spread
      optional: true,
    },
  ],
  { user_id: 42 },
  dispatch,
  { maxDepth: 10 }
);

console.log(result.user);      // From get_user
console.log(result.posts);     // From get_user_posts
console.log(result.comments);  // From get_user_comments (or error if optional)
console.log(result._chain);    // Execution metadata
```

### `createMixer(config)`

Combine multiple API bridges into one MCP server with optional tool name prefixing.

**Signature:**
```js
function createMixer(config: MixerConfig): MixerInstance
```

**MixerConfig structure:**
```ts
interface MixerConfig {
  name?: string;
  version?: string;
  servers: Array<{
    prefix?: string;
    name?: string;
    baseUrl: string;
    auth?: AuthConfig;
    tools: ToolDef[];
    allowlist?: string[];
    blocklist?: string[];
  }>;
}
```

**MixerInstance:**
- `start(): Promise<{ server: Server; dispatch: DispatchFn }>` — Start combined server.
- `server: Server` — The MCP server.
- `dispatch: DispatchFn` — Dispatch to any tool across all servers.

**Duplicate tool names:**
If two servers register the same tool name (without distinct prefixes), the first registration wins and a warning is emitted to stderr — bridge startup is not aborted. Use the `prefix` field to disambiguate tools from conflicting servers.

**Example:**
```js
import { createMixer } from '40mcp';

const mixer = createMixer({
  name: 'multi-api',
  version: '1.0.0',
  servers: [
    {
      prefix: 'pets',
      name: 'petstore',
      baseUrl: 'https://petstore3.swagger.io/api/v3',
      tools: [/* pet tools */],
    },
    {
      prefix: 'todos',
      name: 'jsonplaceholder',
      baseUrl: 'https://jsonplaceholder.typicode.com',
      tools: [/* todo tools */],
    },
  ],
});

const { dispatch } = await mixer.start();

// Tools are now: 'pets.list_pets', 'todos.list_todos', etc.
await dispatch('pets.list_pets', { pet_status: 'available' });
```

---

## Transport

### `createStdioTransport()`

Create a stdio-based MCP transport (for spawning as a CLI tool).

**Signature:**
```js
function createStdioTransport(): StdioServerTransport
```

**Returns:**
- `StdioServerTransport` — Transport instance.

**Example:**
```js
import { createRestBridge, createStdioTransport } from '40mcp';

const bridge = createRestBridge(config);
const transport = createStdioTransport();

await bridge.server.connect(transport);
```

### `createSseTransport(server, options?)`

Create a Server-Sent Events (SSE) transport for HTTP streaming.

**Signature:**
```js
function createSseTransport(
  server: Server,
  options?: SseTransportOptions
): Promise<SseTransportResult>
```

**SseTransportOptions:**
- `port` — HTTP port (default: 3000).
- `host` — Bind address (default: `'localhost'`).
- `path` — SSE endpoint path (default: `'/sse'`).
- `messagePath` — Subpath for message endpoint (default: `'/messages'`).
- `allowedOrigins` — CORS origins.
- `maxSessions` — Max concurrent connections (default: 100).
- `maxSessionsPerIp` — Max concurrent connections per client IP (default: 10). Returns 429 when exceeded. Prevents a single client from exhausting the global session pool.
- `idleTimeoutMs` — Close SSE connections that receive no messages for this many milliseconds (default: 300000 = 5 min). Set to `0` to disable. Mitigates Slow Loris attacks.
- `exposeSessionCount` — Include active session count in `GET /health` response (default: `false`). Only enable on trusted internal networks.

**SseTransportResult:**
- `httpServer: HttpServer` — The underlying Node HTTP server.
- `url: string` — Base URL of the server.

**Example:**
```js
import { createRestBridge, createSseTransport } from '40mcp';

const bridge = createRestBridge(config);
const { httpServer, url } = await createSseTransport(bridge.server, {
  port: 3000,
  allowedOrigins: ['https://example.com'],
});

console.log(`Server running at ${url}`);
```

### `createTransport(type, options?)`

Create a transport factory function (stdio or SSE).

**Signature:**
```js
function createTransport(
  type: 'stdio' | 'sse',
  options?: SseTransportOptions
): (server?: Server) => Promise<StdioServerTransport | SseTransportResult>
```

**Parameters:**
- `type` — Transport type.
- `options` — SSE-specific options (ignored for stdio).

**Returns:**
- Function that takes an MCP server and returns a started transport.

**Example:**
```js
import { createRestBridge, createTransport } from '40mcp';

const bridge = createRestBridge(config);
const transportFactory = createTransport('sse', { port: 3000 });
const { url } = await transportFactory(bridge.server);

console.log(`Server at ${url}`);
```

---

## Reverse Bridge

Convert MCP tools to a REST API.

### `createReverseBridge(config)`

Expose MCP tools as a REST API.

**Signature:**
```js
function createReverseBridge(config: ReverseBridgeConfig): ReverseBridgeInstance
```

**ReverseBridgeConfig:**
- `name`, `version` — API metadata.
- `tools: Array<{ name: string; description?: string; inputSchema?: JsonSchema }>` — Tool definitions.
- `dispatch: DispatchFn` — Dispatch function to call tools.
- `port`, `host` — HTTP server binding.
- `basePath` — API root path (default: `'/api'`).
- `auth?: { header: string; envVar: string }` — Optional auth header injection.
- `allowedOrigin` — CORS origin.

**ReverseBridgeInstance:**
- `start(): Promise<{ httpServer: HttpServer; url: string }>` — Start the REST server.
- `generateOpenApiSpec(): object` — Generate OpenAPI 3.0 spec for the API.

**Example:**
```js
import { createRestBridge, createReverseBridge } from '40mcp';

// Create MCP bridge
const bridge = createRestBridge(config);

// Expose tools as REST API
const reverse = createReverseBridge({
  name: 'my-api',
  version: '1.0.0',
  tools: config.tools,
  dispatch: bridge.dispatch,
  port: 3000,
  basePath: '/api',
});

const { url } = await reverse.start();
console.log(`REST API at ${url}`);
console.log(`OpenAPI spec: ${url}/openapi.json`);
```

**Usage:**
```bash
# Call a tool via REST
curl -X POST http://localhost:3000/api/tools/list_pets \
  -H 'Content-Type: application/json' \
  -d '{"pet_status": "available"}'
```

### `generateOpenApiSpec(config)`

Generate an OpenAPI 3.0 specification from tool definitions.

**Signature:**
```js
function generateOpenApiSpec(config: {
  name?: string;
  version?: string;
  tools: Array<{ name: string; description?: string; inputSchema?: JsonSchema }>;
  basePath?: string;
}): object
```

**Parameters:**
- `config.name`, `config.version` — API info.
- `config.tools` — Tool definitions.
- `config.basePath` — Base path for all operations (default: `/api`).

**Returns:**
- OpenAPI 3.0 object (suitable for JSON export).

**Example:**
```js
import { generateOpenApiSpec } from '40mcp';

const spec = generateOpenApiSpec({
  name: 'My API',
  version: '1.0.0',
  tools: [/* tool defs */],
  basePath: '/api',
});

console.log(JSON.stringify(spec, null, 2));
// Use in Swagger UI, Postman, etc.
```

---

## Webhooks

### `createWebhookListener(config)`

Listen for incoming webhooks and dispatch them as tool calls.

**Signature:**
```js
function createWebhookListener(config: WebhookListenerConfig): WebhookListenerInstance
```

**WebhookListenerConfig:**
- `name`, `port`, `host` — Server metadata.
- `dispatch: DispatchFn` — Tool dispatcher.
- `routes: WebhookRoute[]` — Webhook route definitions.
- `exposeRoutes?: boolean` — Enable the `GET /routes` discovery endpoint (default: `false`). Disabled by default to prevent information disclosure. Enable only on trusted internal networks.

**WebhookRoute structure:**
```ts
interface WebhookRoute {
  path: string;                          // URL path (e.g., '/github')
  method?: string;                       // HTTP method (default: 'POST')
  tool: string;                          // Tool to call
  argMap?: Record<string, string>;       // Body field → tool arg mapping
  filter?: Record<string, string | string[]>;  // Require fields/values
  secret?: WebhookSecret;                // Optional auth
  response?: 'async' | 'sync';           // 'async' = return 202 immediately
}
```

**WebhookSecret structure:**
```ts
interface WebhookSecret {
  type: 'header' | 'hmac' | 'query';
  envVar?: string;
  value?: string;
  header?: string;           // For 'header' type
  param?: string;            // For 'query' type
  replayWindow?: number;     // Replay protection window in seconds (e.g. 300). Validates x-webhook-timestamp header.
  timestampHeader?: string;  // Header containing the Unix timestamp (default: 'x-webhook-timestamp').
}
```

**WebhookListenerInstance:**
- `start(): Promise<{ httpServer: HttpServer; url: string }>` — Start listener.
- `routes: WebhookRoute[]` — Registered routes.

**Example:**
```js
import { createWebhookListener } from '40mcp';

const listener = createWebhookListener({
  name: 'webhooks',
  port: 3001,
  dispatch,
  routes: [
    {
      path: '/github',
      tool: 'process_github_event',
      secret: { type: 'header', header: 'X-Hub-Signature', envVar: 'GITHUB_SECRET' },
      filter: { action: ['opened', 'closed'] },
      argMap: { action: 'action', pull_request: 'pr' },
    },
    {
      path: '/stripe',
      tool: 'handle_stripe_event',
      response: 'async', // Don't wait for tool completion
      secret: { type: 'hmac', envVar: 'STRIPE_SECRET' },
    },
  ],
});

const { url } = await listener.start();
console.log(`Webhooks listening at ${url}`);
```

---

## Multi-Tenancy

### `createTenantScope(config)`

Wrap a dispatch function with per-request tenant context and auth isolation.

**Signature:**
```js
function createTenantScope(config: TenantScopeConfig): ScopedDispatchFn
```

**TenantScopeConfig:**
- `dispatch: DispatchFn` — Base dispatcher.
- `resolveContext: (requestMeta?: any) => Promise<TenantContext | null>` — Async context resolver (from request headers, JWT, etc.).
- `defaults?: Partial<TenantContext>` — Default tenant context.

**TenantContext structure:**
```ts
interface TenantContext {
  tenantId: string;
  auth?: AuthConfig;
  allowlist?: string[];
  blocklist?: string[];
  metadata?: Record<string, any>;
}
```

**ScopedDispatchFn:**
```ts
type ScopedDispatchFn = (
  toolName: string,
  args: Record<string, any>,
  requestMeta?: any
) => Promise<any>
```

**Example:**
```js
import { createTenantScope, createRestBridge } from '40mcp';

const bridge = createRestBridge(config);

const scopedDispatch = createTenantScope({
  dispatch: bridge.dispatch,
  resolveContext: async (meta) => {
    const tenantId = meta?.headers?.['X-Tenant-ID'];
    if (!tenantId) return null;
    
    return {
      tenantId,
      auth: { type: 'bearer', envVar: `TOKEN_${tenantId}` },
      allowlist: [`tenant_${tenantId}_*`],
    };
  },
});

// Use in a web server:
app.post('/dispatch', async (req, res) => {
  try {
    const result = await scopedDispatch(
      req.body.tool,
      req.body.args,
      { headers: req.headers }
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
```

### `tenantAuthHook()`

Create a before-request hook that injects tenant auth headers.

**Signature:**
```js
function tenantAuthHook(): (req: BeforeRequestContext) => Promise<BeforeRequestResult | null>
```

**Returns:**
- Hook function compatible with `BridgeConfig.hooks.beforeRequest`.

**Example:**
```js
import { createRestBridge, tenantAuthHook } from '40mcp';

const bridge = createRestBridge({
  name: 'tenant-api',
  baseUrl: 'https://api.example.com',
  hooks: {
    beforeRequest: tenantAuthHook(),
  },
  tools: [/* ... */],
});
```

---

## Security

### `createVault(config)`

Open an existing sealed credential vault. For new vaults, use [`initVault`](#initvaultconfig) instead.

**Signature:**
```js
function createVault(config: VaultConfig): SealedVault
```

**VaultConfig:**
- `path: string` — Vault file path (e.g., `~/.40mcp/vault.json`).
- `passphrase: string` — Master passphrase (use `VAULT_PASSPHRASE` env var). Must pass the strength rule documented under [`initVault`](#initvaultconfig) — minimum 16 characters, at least 3 of lowercase / uppercase / digits / symbols, with additional entropy and anti-monotone checks. The same rule applies to `rotateKEK` and `recoverVault`.
- `tokenTTL?: number` — JWT token lifetime in seconds (default: 300 / 5 min).

**SealedVault interface:**
```ts
interface SealedVault {
  set(name: string, value: string, metadata?: Record<string, any>): Promise<string>;
  has(name: string): Promise<boolean>;
  list(): Promise<SealedEntry[]>;
  delete(name: string): Promise<void>;
  rotate(name: string): Promise<string | null>;
  rotateKEK(newPassphrase: string): Promise<void>;
  getSealId(name: string): Promise<string | null>;
  getFingerprint(name: string): Promise<string | null>;
  issueToken(name: string, claims?: Record<string, any>): Promise<CredentialToken | null>;
  verifyToken(token: string): Promise<VerifiedToken>;
  createAuthHook(mapping: Record<string, string>): BeforeRequestHook;
  createBearerHook(name: string): BeforeRequestHook;
  unsealConfig(config: object): Promise<object>;
}
```

**Example:**
```js
import { createVault, createRestBridge } from '40mcp';

const vault = createVault({ path: './my.vault', passphrase: process.env.VAULT_PASSPHRASE });

// Use in bridge — sealed header auth
const bridge = createRestBridge({
  name: 'petstore',
  baseUrl: 'https://petstore3.swagger.io/api/v3',
  vault,
  auth: { type: 'sealed', name: 'petstore-key', header: 'X-API-Key' },
  tools: [/* ... */],
});

// Or wire manually via hook
const bridge2 = createRestBridge({
  baseUrl: 'https://api.example.com',
  hooks: { beforeRequest: vault.createAuthHook({ 'api-key': 'X-API-Key' }) },
  tools: [/* ... */],
});
```

---

### `initVault(config)`

Create a **new** vault with a recovery envelope. Returns the vault instance and a one-time recovery key. Store the recovery key safely — it is never shown again.

**Signature:**
```js
async function initVault(config: { path: string; passphrase: string }): Promise<{ vault: SealedVault; recoveryKey: string }>
```

- `passphrase` — Must be at least **16 characters** and use at least **3 of** lowercase, uppercase, digits, and symbols. Additional checks reject highly repetitive passphrases and repeated or sequential character runs. **The same rule is enforced by `createVault`, `rotateKEK`, and `recoverVault`** — every entry point that sets or uses a master passphrase applies the same validator.
- `recoveryKey` format: `xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx` (4 groups of 16 hex chars)
- Throws `Error` if the vault file already exists — use `createVault` to open existing vaults.

**Example:**
```js
import { initVault } from '40mcp';

const { vault, recoveryKey } = await initVault({
  path: './my.vault',
  passphrase: process.env.VAULT_PASSPHRASE,
});

// ⚠️  Save recoveryKey somewhere safe — printed ONCE, not stored in vault
console.log('Recovery key:', recoveryKey);

await vault.set('stripe-key', '<your-stripe-secret-key>');
```

---

### `recoverVault(config)`

Recover vault access after a lost passphrase using the recovery key generated at `initVault` time.

**Signature:**
```js
async function recoverVault(config: {
  path: string;
  recoveryKey: string;
  newPassphrase: string;
}): Promise<SealedVault>
```

- Re-derives the KEK from the recovery key, re-wraps all DEKs under the new passphrase.
- Throws if the vault has no recovery envelope (was created with `createVault`, not `initVault`).
- Throws if the recovery key is incorrect.

**Example:**
```js
import { recoverVault } from '40mcp';

const vault = await recoverVault({
  path: './my.vault',
  recoveryKey: 'a1b2c3d4e5f6a7b8-...',
  newPassphrase: '<set-a-strong-passphrase>',
});
// vault is now open with newPassphrase — update VAULT_PASSPHRASE env var
```

---

### `vault.rotateKEK(newPassphrase)`

Rotate the master key — re-wraps all DEKs under a new KEK without exposing any plaintext values. Recovery capability is preserved automatically.

**Signature:**
```js
vault.rotateKEK(newPassphrase: string): Promise<void>
```

**Example:**
```js
const vault = createVault({ path: './my.vault', passphrase: process.env.VAULT_PASSPHRASE });
await vault.rotateKEK('<set-a-strong-passphrase>');
// Update VAULT_PASSPHRASE to <set-a-strong-passphrase>
```

---

### `vault.rotate(name)`

Re-encrypt a sealed secret with a fresh DEK, without changing the stored value. The old DEK is discarded. JWTs issued before rotation remain valid (they are scoped to the secret name, not the seal ID).

**Signature:**
```js
vault.rotate(name: string): Promise<string | null>
```

**Returns:**
- New seal ID on success, or `null` if the named secret does not exist.

**Example:**
```js
const vault = createVault({ path: './my.vault', passphrase: process.env.VAULT_PASSPHRASE });
const newSealId = await vault.rotate('github-token');
// newSealId is a fresh seal:// URI; original value is unchanged
```

---

### `vault.createBearerHook(name)`

Returns a `beforeRequest` hook that injects `Authorization: Bearer <value>` using a sealed secret — the value is never stored or logged.

**Signature:**
```js
vault.createBearerHook(name: string): BeforeRequestHook
```

**Example:**
```js
const bridge = createRestBridge({
  baseUrl: 'https://api.github.com',
  hooks: { beforeRequest: vault.createBearerHook('github-token') },
  tools: [/* ... */],
});
```

---

### Sealed auth in bridge configs

When `config.vault` is set, `createRestBridge` supports two sealed auth types that inject credentials JIT without ever reading from `process.env`:

```js
// Header auth — injects a named header
createRestBridge({
  vault,
  auth: { type: 'sealed', name: 'my-secret', header: 'X-API-Key' },
  // ...
});

// Bearer auth — injects Authorization: Bearer <value>
createRestBridge({
  vault,
  auth: { type: 'sealed-bearer', name: 'my-token' },
  // ...
});
```

---

### Vault CLI

```bash
# Initialize a new vault (shows recovery key once)
export VAULT_PASSPHRASE=<set-a-strong-passphrase>
40mcp vault init

# Seal a secret (prompts for value — never stored in shell history)
40mcp vault seal github-token

# List sealed secrets (names, seal IDs, fingerprints — no values)
40mcp vault list

# Rotate a secret's DEK (re-key without changing the value)
40mcp vault rotate github-token

# Rotate the master key (rewraps all DEKs under new passphrase)
40mcp vault rotate-kek

# Delete a secret
40mcp vault delete github-token

# Recover from a lost passphrase using recovery key
40mcp vault recover

# Use a custom vault path
40mcp vault --vault /path/to/my.vault seal my-secret
```

Use sealed secrets in any serve or from-* command:

```bash
# Bearer token from vault
40mcp serve github.json --vault-bearer github-token

# Custom header from vault
40mcp from-openapi spec.json --vault-secret stripe-key --vault-header X-API-Key

# Auto-detect format with bearer auth
40mcp from api-spec.json --vault-bearer api-token
```

### Vault Daemon CLI

Run a vault daemon so bridge processes never hold the master passphrase:

```bash
# Start daemon in background (prints daemonSecret — keep it secure)
40mcp vault daemon start --background

# Check if daemon is running
40mcp vault daemon status

# Gracefully stop the daemon
40mcp vault daemon stop

# Use a custom socket path
40mcp vault daemon start --socket /run/40mcp/vault.sock
```

---

### `createVaultDaemonClient(options?)`

Create a vault client that delegates credential access to a running vault daemon over a Unix socket. Bridge processes authenticate with a `daemonSecret` and receive scoped short-lived JWTs. The bridge never holds `VAULT_PASSPHRASE` or the KEK.

Falls back to direct vault access (Phase 1 path) when `vaultPath` + `passphrase` are provided and the daemon socket is unavailable.

**Signature:**
```js
function createVaultDaemonClient(options?: VaultDaemonClientOptions): VaultHookClient
```

**VaultDaemonClientOptions:**
- `socketPath?: string` — Daemon socket path (default: `~/.40mcp/daemon.sock`).
- `configPath?: string` — Bridge config file path, used for scope grounding.
- `daemonSecret?: string` — Hex string returned by `40mcp vault daemon start`.
- `vaultPath?: string` — Fallback vault path (used if daemon is unavailable).
- `passphrase?: string` — Fallback vault passphrase (used if daemon is unavailable).

**VaultHookClient** exposes the same hook interface as `createVault()`:
- `createAuthHook(mapping)` — Header auth hook.
- `createBearerHook(name)` — Bearer auth hook.

**Example:**
```js
import { createVaultDaemonClient, createRestBridge } from '40mcp';

const vaultClient = createVaultDaemonClient({
  daemonSecret: process.env.VAULT_DAEMON_SECRET,
  configPath: './bridge.json',
});

const bridge = createRestBridge({
  name: 'github',
  baseUrl: 'https://api.github.com',
  hooks: { beforeRequest: vaultClient.createBearerHook('github-token') },
  tools: [/* ... */],
});
```

### `createPolicyGate(config)`

Enforce access control policies on tool calls with optional manual approval flow.

**Signature:**
```js
function createPolicyGate(config: PolicyGateConfig): DispatchFn
```

**PolicyGateConfig:**
- `dispatch: DispatchFn` — Underlying dispatcher.
- `toolPolicies?: Record<string, PolicyRule>` — Per-tool policies.
- `approvalHandler?: ApprovalHandler` — Custom approval logic (stdin by default).
- `logger?: (level, message, context?) => void` — Logging callback.
- `approvalTimeoutMs?: number` — Approval timeout (default: 30 sec).
- `defaultPolicy?: PolicyRule` — Default policy for unlisted tools (default: `'allow'`).
- `dangerousActions?: string[]` — Tool names requiring approval.

**PolicyRule values:**
- `'allow'` — Always allow.
- `'deny'` — Always deny.
- `'require_approval'` — Require manual approval.
- `'log_only'` — Allow but log.

**ApprovalHandler:**
```ts
type ApprovalHandler = (context: PolicyApprovalContext) => Promise<PolicyDecision>;

interface PolicyApprovalContext {
  tool: string;
  args: Record<string, any>;
  timestamp: string;
  policy: PolicyRule;
}

type PolicyDecision = 'approve' | 'deny' | 'timeout';
```

**Example:**
```js
import { createPolicyGate, createStdinApprovalHandler } from '40mcp';

const gated = createPolicyGate({
  dispatch: bridge.dispatch,
  toolPolicies: {
    'delete_user': 'require_approval',
    'list_users': 'allow',
    'export_data': 'require_approval',
  },
  approvalHandler: createStdinApprovalHandler(),
  dangerousActions: ['delete_*', 'drop_*'],
  logger: (level, message, context) => {
    console.log(`[${level}] ${message}`, context);
  },
});

// When calling gated dispatch:
// - 'list_users' → calls immediately
// - 'delete_user' → prompts via stdin
// - Unmatched tools → use defaultPolicy
```

### `createStdinApprovalHandler()`

Create an approval handler that prompts the user via stdin.

**Signature:**
```js
function createStdinApprovalHandler(): ApprovalHandler
```

**Returns:**
- `ApprovalHandler` — Interactive stdin approval.

### `createCallbackApprovalHandler(callback)`

Create an approval handler using a custom callback function.

**Signature:**
```js
function createCallbackApprovalHandler(
  callback: ApprovalHandler
): ApprovalHandler
```

**Parameters:**
- `callback` — Your custom approval logic.

**Example:**
```js
import { createCallbackApprovalHandler } from '40mcp';

const handler = createCallbackApprovalHandler(async (context) => {
  // Send approval request to external service
  const response = await fetch('https://approval-service.example.com/request', {
    method: 'POST',
    body: JSON.stringify(context),
  });
  
  const { approved } = await response.json();
  return approved ? 'approve' : 'deny';
});
```

---

## AI-Assisted Generation

### `buildGeneratePrompt(options)`

Build a system + user prompt for LLM-assisted bridge config generation.

**Signature:**
```js
function buildGeneratePrompt(options: GenerateOptions): string
```

**GenerateOptions:**
- `description: string` — Natural language API description.
- `baseUrl?: string` — API base URL.
- `authType?: string` — Auth type hint (e.g., `'bearer'`, `'api_key'`).
- `apiDocs?: string` — Inline API documentation.
- `endpoints?: string[]` — Endpoint paths to document.
- `style?: 'minimal' | 'comprehensive'` — Output style (default: `'comprehensive'`).

**Returns:**
- Single string prompt combining system and user instructions.

**Example:**
```js
import { buildGeneratePrompt } from '40mcp';

const prompt = buildGeneratePrompt({
  description: 'Stripe payment API with customers, charges, and refunds',
  baseUrl: 'https://api.stripe.com/v1',
  authType: 'bearer',
  style: 'comprehensive',
});

// Send to LLM (Claude, GPT-4, etc.)
```

### `generatePrompt(options)`

Build separate system and user prompts for flexibility.

**Signature:**
```js
function generatePrompt(options: GenerateOptions): { system: string; user: string }
```

**Returns:**
- Object with `system` and `user` prompts.

**Example:**
```js
import { generatePrompt } from '40mcp';

const { system, user } = generatePrompt({
  description: 'Twitter API for tweets, users, and timelines',
  baseUrl: 'https://api.twitter.com/2',
  endpoints: [
    'POST /tweets',
    'GET /tweets/:id',
    'GET /users/:id/tweets',
  ],
});

// Use with your LLM API
const response = await llm.generate({ system, user });
const config = parseGeneratedConfig(response);
```

### `parseGeneratedConfig(llmOutput)`

Parse and validate LLM-generated bridge config (JSON or markdown code block).

**Signature:**
```js
function parseGeneratedConfig(llmOutput: string): ParsedGenerateResult
```

**ParsedGenerateResult:**
```ts
interface ParsedGenerateResult {
  config: BridgeConfig | null;
  valid: boolean;
  errors: string[];
  warnings: string[];
}
```

**Example:**
```js
import { parseGeneratedConfig } from '40mcp';

const llmOutput = `
Here's a bridge config for the Twitter API:

\`\`\`json
{
  "name": "twitter",
  "baseUrl": "https://api.twitter.com/2",
  "auth": { "type": "bearer", "envVar": "TWITTER_TOKEN" },
  "tools": [
    {
      "name": "create_tweet",
      "method": "POST",
      "path": "/tweets",
      "inputSchema": { ... }
    }
  ]
}
\`\`\`
`;

const result = parseGeneratedConfig(llmOutput);
if (result.valid) {
  const bridge = createRestBridge(result.config);
  await bridge.start();
} else {
  console.error('Config errors:', result.errors);
}
```

### `generateFromSpec(spec, options?)`

Auto-generate a bridge config from an API spec (OpenAPI, GraphQL, etc.).

**Signature:**
```js
function generateFromSpec(
  spec: object,
  options?: GenerateFromSpecOptions
): BridgeConfig
```

**GenerateFromSpecOptions:**
- `policyGateWrites?: boolean` — Wrap write operations with policy gates.
- `addTransforms?: boolean` — Add smart response transforms.
- `tokenBudget?: number` — Token limit per response.

**Returns:**
- Ready-to-use `BridgeConfig`.

**Example:**
```js
import { generateFromSpec, createRestBridge } from '40mcp';

const spec = await fetch('https://api.example.com/openapi.json')
  .then(r => r.json());

const config = generateFromSpec(spec, {
  policyGateWrites: true,
  addTransforms: true,
});

const bridge = createRestBridge(config);
await bridge.start();
```

### `GENERATE_SYSTEM_PROMPT`

The default system prompt template used for LLM-assisted config generation.

**Type:**
```ts
declare const GENERATE_SYSTEM_PROMPT: string
```

**Usage:**
```js
import { GENERATE_SYSTEM_PROMPT } from '40mcp';

console.log(GENERATE_SYSTEM_PROMPT);
// Use as reference or customize
```

---

## MCP Client Connector

Connect to existing MCP servers and link them together.

### `connectStdio(config)`

Connect to an MCP server spawned via stdio.

**Signature:**
```js
function connectStdio(config: StdioConnectConfig): Promise<ConnectedServer>
```

**StdioConnectConfig:**
- `command: string` — Command to spawn (e.g., `'node'`, `'python'`).
- `args?: string[]` — Command arguments.
- `env?: Record<string, string>` — Environment variables.
- `prefix?: string` — Add prefix to all tool names.
- `allowlist?: string[]` — Only expose these tools.
- `blocklist?: string[]` — Hide these tools.
- `transforms?: ResponseTransform` — Apply to all responses.
- `policy?: PolicyRule` — Default policy for all tools.

**ConnectedServer:**
```ts
interface ConnectedServer {
  tools: ConnectedTool[];
  client: any;
  source: string;
  dispatch(name: string, args: Record<string, any>): Promise<any>;
  close(): Promise<void>;
}
```

**Upstream response size guard:**
Tool responses from upstream MCP servers exceeding 10 MB are returned as a raw string without being parsed through `JSON.parse`. A warning is written to stderr. This prevents memory exhaustion from oversized upstream payloads.

**Example:**
```js
import { connectStdio, createMixer } from '40mcp';

const server = await connectStdio({
  command: 'node',
  args: ['./my-mcp-server.js'],
  prefix: 'my_',
  allowlist: ['get_*', 'list_*'],
});

console.log('Connected tools:', server.tools.map(t => t.name));

// Call a tool
const result = await server.dispatch('my_get_data', { id: 123 });
```

### `connectSse(config)`

Connect to an MCP server via SSE (Server-Sent Events) HTTP endpoint.

**Signature:**
```js
function connectSse(config: SseConnectConfig): Promise<ConnectedServer>
```

**SseConnectConfig:**
- `url: string` — SSE endpoint URL.
- `headers?: Record<string, string>` — Request headers (auth, etc.).
- `prefix?: string` — Tool name prefix.
- `allowlist?, blocklist?, transforms?, policy?` — Same as stdio.

**Example:**
```js
import { connectSse } from '40mcp';

const server = await connectSse({
  url: 'https://api.example.com/sse',
  headers: { 'Authorization': 'Bearer token...' },
  prefix: 'remote_',
});

console.log('Connected:', server.tools.length, 'tools');
await server.close();
```

### `connectMany(servers)`

Connect to multiple MCP servers and merge them into one cluster.

**Signature:**
```js
function connectMany(
  servers: Array<StdioConnectConfig | SseConnectConfig>
): Promise<ConnectedCluster>
```

**ConnectedCluster:**
```ts
interface ConnectedCluster {
  tools: ConnectedTool[];
  connections: ConnectedServer[];
  dispatch(name: string, args: Record<string, any>): Promise<any>;
  close(): Promise<void>;
}
```

**Example:**
```js
import { connectMany } from '40mcp';

const cluster = await connectMany([
  {
    command: 'node',
    args: ['./server1.js'],
    prefix: 'app1',
  },
  {
    url: 'https://remote.example.com/sse',
    prefix: 'app2',
  },
]);

console.log('Total tools:', cluster.tools.length);
await cluster.dispatch('app1.get_data', { id: 1 });
await cluster.dispatch('app2.fetch_info', { query: 'test' });

await cluster.close();
```

### `connectFromConfig(mcpConfig, options?)`

Connect to all MCP servers defined in a standard `.mcp.json` config file.

**Signature:**
```js
function connectFromConfig(
  mcpConfig: Record<string, { command?: string; args?: string[]; env?: Record<string, string>; url?: string; headers?: Record<string, string> }>,
  options?: { prefixes?: Record<string, string>; only?: string[]; skip?: string[] }
): Promise<ConnectedCluster>
```

**Parameters:**
- `mcpConfig` — Object mapping server names to configs.
- `options.prefixes` — Custom prefix for each server.
- `options.only` — Only connect to these servers.
- `options.skip` — Skip these servers.

**Example:**
```js
import { connectFromConfig } from '40mcp';

const config = {
  'local-api': {
    command: 'node',
    args: ['./local.js'],
  },
  'github': {
    command: 'npx',
    args: ['@modelcontextprotocol/server-github'],
    env: { GITHUB_TOKEN: process.env.GITHUB_TOKEN },
  },
  'remote-service': {
    url: 'https://service.example.com/sse',
    headers: { 'Authorization': 'Bearer ...' },
  },
};

const cluster = await connectFromConfig(config, {
  prefixes: { 'local-api': 'local' },
  skip: ['remote-service'],
});

console.log('Connected servers:', cluster.connections.length);
```

---

## Error Codes

All 40mcp error codes (from `BridgeErrorCode`):

| Code | Meaning |
|------|---------|
| `AUTH_MISSING` | Authentication required but not provided. |
| `AUTH_EXPIRED` | Auth token/credentials expired. |
| `AUTH_INVALID` | Auth credentials invalid or malformed. |
| `API_TIMEOUT` | API request timed out. |
| `API_NETWORK` | Network error (DNS, connection refused, etc.). |
| `API_RATE_LIMIT` | API rate limit exceeded. |
| `API_NOT_FOUND` | API endpoint not found (404). |
| `API_SERVER_ERROR` | API server error (5xx). |
| `API_BAD_REQUEST` | Malformed request (400). |
| `CONFIG_INVALID` | Bridge config validation failed. |
| `CONFIG_MISSING_FIELD` | Required config field is missing. |
| `CHAIN_DEPTH_EXCEEDED` | Chain nesting depth limit exceeded. |
| `CHAIN_CIRCULAR_DEPENDENCY` | Circular dependency in chain steps. |
| `CHAIN_STEP_FAILED` | A chain step failed (not marked optional). |
| `CHAIN_REF_UNDEFINED` | Step reference resolves to undefined. |
| `TOOL_NOT_FOUND` | Tool name not found. |
| `TOOL_DEPRECATED` | Tool has been deprecated. |
| `TOOL_VALIDATION` | Tool input validation failed. |
| `TRANSFORM_INVALID` | Response transform is invalid. |

---

## Error Classes

### `BridgeError`

Base error class for all 40mcp errors.

**Constructor:**
```ts
constructor(
  bridgeCode: BridgeErrorCodeValue,
  message: string,
  details?: Record<string, any>
)
```

**Properties:**
- `bridgeCode: BridgeErrorCodeValue` — Error code constant.
- `details: Record<string, any>` — Additional context.
- `message: string` — Error message.

**Methods:**
- `toJSON(): { code: string; message: string; details: Record<string, any> }` — Serialize to JSON.

**Example:**
```js
import { BridgeError, BridgeErrorCode } from '40mcp';

try {
  // ...
} catch (err) {
  if (err instanceof BridgeError) {
    if (err.bridgeCode === BridgeErrorCode.AUTH_MISSING) {
      console.error('Please provide API credentials');
    }
    console.error(err.toJSON());
  }
}
```

### `AuthError`

Error related to authentication.

**Constructor:**
```ts
constructor(
  bridgeCode: BridgeErrorCodeValue,
  message: string,
  details?: Record<string, any>
)
```

**Example:**
```js
import { AuthError } from '40mcp';

try {
  // auth call
} catch (err) {
  if (err instanceof AuthError) {
    console.error('Auth failed:', err.message);
  }
}
```

### `ApiError`

Error from an API call (HTTP error response).

**Constructor:**
```ts
constructor(
  bridgeCode: BridgeErrorCodeValue,
  message: string,
  details?: { statusCode?: number; method?: string; path?: string }
)
```

**Properties:**
- `details.statusCode` — HTTP status code.
- `details.method` — HTTP method.
- `details.path` — Request path.

**Example:**
```js
import { ApiError } from '40mcp';

try {
  // API call
} catch (err) {
  if (err instanceof ApiError) {
    console.error(`${err.details.method} ${err.details.path} failed:`, err.message);
  }
}
```

### `ChainError`

Error during chain execution.

**Constructor:**
```ts
constructor(
  bridgeCode: BridgeErrorCodeValue,
  message: string,
  details?: { step?: string; depth?: number; partialResults?: Record<string, any> }
)
```

**Properties:**
- `details.step` — Which step failed.
- `details.depth` — Current nesting depth.
- `details.partialResults` — Results collected before failure.

**Example:**
```js
import { ChainError } from '40mcp';

try {
  // chain execution
} catch (err) {
  if (err instanceof ChainError) {
    console.error(`Chain failed at step: ${err.details.step}`);
    console.log('Partial results:', err.details.partialResults);
  }
}
```

### `apiErrorFromStatus(status, method, path, detail?)`

Convenience function to create an `ApiError` from an HTTP status code.

**Signature:**
```js
function apiErrorFromStatus(
  status: number,
  method: string,
  path: string,
  detail?: string
): ApiError
```

**Example:**
```js
import { apiErrorFromStatus } from '40mcp';

const error = apiErrorFromStatus(404, 'GET', '/users/999', 'User not found');
throw error;
```

---

## Quick Start Examples

### Basic REST Bridge

```js
import { createRestBridge } from '40mcp';

const bridge = createRestBridge({
  name: 'my-api',
  baseUrl: 'https://api.example.com',
  auth: { type: 'bearer', envVar: 'API_TOKEN' },
  tools: [
    {
      name: 'get_user',
      description: 'Get user by ID',
      method: 'GET',
      path: '/users/:id',
      inputSchema: {
        type: 'object',
        properties: { id: { type: 'integer' } },
        required: ['id'],
      },
    },
  ],
});

await bridge.start();
```

### Auto-load from OpenAPI

```js
import { createRestBridge, loadOpenApiSpec } from '40mcp';

const { baseUrl, tools } = await loadOpenApiSpec(
  'https://api.example.com/openapi.json'
);

const bridge = createRestBridge({ name: 'auto', baseUrl, tools });
await bridge.start();
```

### Chain Multiple Calls

```js
import { createRestBridge } from '40mcp';

const bridge = createRestBridge({
  name: 'chained',
  baseUrl: 'https://api.example.com',
  tools: [
    {
      name: 'get_user_with_posts',
      chain: [
        { call: 'get_user', as: 'user', args: { id: '$args.id' } },
        { call: 'get_posts', as: 'posts', args: { user_id: '$user.id' } },
      ],
      inputSchema: {
        type: 'object',
        properties: { id: { type: 'integer' } },
        required: ['id'],
      },
    },
  ],
});

await bridge.start();
```

### Multi-API Mixer

```js
import { createMixer } from '40mcp';

const mixer = createMixer({
  name: 'multi-api',
  servers: [
    { prefix: 'users', baseUrl: 'https://users.api.example.com', tools: [...] },
    { prefix: 'posts', baseUrl: 'https://posts.api.example.com', tools: [...] },
  ],
});

await mixer.start();
```

### Expose as REST API

```js
import { createRestBridge, createReverseBridge } from '40mcp';

const bridge = createRestBridge(config);
const reverse = createReverseBridge({
  name: 'rest-api',
  tools: config.tools,
  dispatch: bridge.dispatch,
  port: 3000,
});

await reverse.start();
// Now available at: http://localhost:3000/api/tools/{toolName}
```

---

## Type Definitions

All TypeScript types are re-exported from the package root. Import directly:

```js
import {
  BridgeConfig,
  ToolDef,
  AuthConfig,
  ResponseTransform,
  ChainStep,
  BridgeInstance,
  DispatchFn,
  // ... and all others
} from '40mcp';
```

---

## Agent Steering (Core Configuration Element)

40mcp ships with a first-class **agent steering** primitive. Tools declare
`tool.steering` in config to control how the agent is instructed before a
call and what it is told to do with the return. Steering is **stateless** —
the MCP server transforms one call at a time and never holds session state.
All inference happens at the call/return boundary.

### Three steering surfaces

| Surface | Purpose | Source |
|---------|---------|--------|
| `steering.write` | Forced-inference write classification — injects `memory_type`, `confidence`, `importance` into the tool's `inputSchema` as REQUIRED fields and derives a `decay_policy` at write time. | `src/steering/apply.js` |
| `steering.prehook` | Instructions surfaced to the agent **before** the call. Used to steer classification, scoping, or routing. | `src/steering/hooks.js` |
| `steering.posthook` | Instructions surfaced to the agent **after** the call, alongside the result. Tells the agent what to do next. | `src/steering/hooks.js` |

### Config shape

```json
{
  "name": "memory_write",
  "method": "POST",
  "path": "/v1/memory",
  "inputSchema": {
    "type": "object",
    "properties": { "content": { "type": "string" } },
    "required": ["content"]
  },
  "steering": {
    "write": true,
    "prehook": "Classify before committing. Corrections are permanent.",
    "posthook": {
      "instructions": "If memory_type=correction, also append to the session chain.",
      "only_if_classified": true
    }
  }
}
```

### Forced-inference write interface (`steering.write: true`)

When a tool opts into `steering.write`, the bridge:

1. **Merges required fields into `inputSchema`** at bridge construction time:
   - `memory_type` (enum): `correction`, `decision`, `observation`, `inference`, `fact`, `hypothesis`, `assumption`, `reference`
   - `confidence` (number, 0..1)
   - `importance` (number, 0..1)
2. **Rejects the call** at dispatch with `InvalidParams` if any field is
   missing or out of range. The MCP client sees a clear error — no ambiguity.
3. **Derives `decay_policy` at write time** from `memory_type`:

| memory_type | class | halfLifeDays |
|-------------|-------|--------------|
| correction, decision | permanent | — |
| observation, fact, reference | archive | 365 |
| inference | decay | 30 |
| hypothesis | decay | 14 |
| assumption | decay | 60 |

4. **Emits audit events** to stderr as JSON:
   ```
   [40mcp:audit] {"ts":…,"tool":"memory_write","status":"success","steering":{"memory_type":"correction","decay_policy_class":"permanent","importance":1}}
   [40mcp:audit] {"ts":…,"event":"mem_release","tool":"memory_write","steering":{"memory_type":"correction"}}
   ```

This is the **"forced inference at write time"** contract: classification
happens at commit, never post-hoc. Corrections are flagged permanent at birth;
the miner becomes a legacy fallback, not the primary mechanism.

### Prehook / posthook instruction injection

Prehooks and posthooks inject **structured inference instructions** around
each call. The agent reads them and acts — the server never holds state.

- **Prehook** runs before dispatch. If `steering.write` is set, the prehook
  is where classification runs and throws `InvalidParams` on missing fields.
- **Posthook** runs after dispatch. Its instructions ride back in the return
  so the agent sees what to do next. Can be gated with
  `only_if_classified: true`.

When either hook fires, the bridge wraps the result in a steering envelope:

```json
{
  "value": { "...": "original tool result" },
  "_steering": {
    "prehook_instructions": "Classify before committing. Corrections are permanent.",
    "posthook_instructions": "If memory_type=correction, also append to the session chain.",
    "classification": {
      "memory_type": "correction",
      "confidence": 1.0,
      "importance": 1.0,
      "decay_policy": { "class": "permanent", "halfLifeDays": null, "minConfidenceToRetain": 0 }
    }
  }
}
```

Tools without any steering configuration return their bare payload — the
envelope is only added when something steered fires.

### Handle registry as multi-agent coordination surface

Steering reframes handles as a **multi-agent coordination surface** rather
than session state. The orchestrator sees what's in-flight across agents
without materializing payloads. `mem_release` is the stateless completion
signal. TTL is crash recovery, not the primary lifecycle.

40mcp does not bundle a memory backend — any downstream MCP server (or
REST API routed through a 40mcp bridge) can adopt the same contract. The
40mcp-side primitive is the *shape* of steered writes and their envelope.
A downstream memory implementation would typically:

- require `memory_type` + `confidence` + `importance` at `kb_add` / `write`
- persist the derived `decay_policy` on the row
- expose a `mem_release(handleId, outcome)` tool that transitions handles
  from `active` → `released` with `outcome ∈ {persisted, discarded, escalated}`
- track `owning_agent` + `coordination_scope` on each handle

### Example

See `configs/steering.example.json` for a runnable config that wires all
three surfaces together.

### Agentic Memory (`AgenticMemory` class)

`AgenticMemory` is a thin, stateless facade for application code that
wants agentic-memory semantics on top of any dispatch function. It does
not store anything — it shapes calls through `classifyWrite` and
`checkAuthority` and forwards to a user-provided dispatcher (typically
the bridge's `dispatch`, or a downstream MCP tool).

```javascript
import { createRestBridge } from '40mcp';
import { AgenticMemory, AUTHORITIES } from '40mcp/steering';

const bridge = createRestBridge(config);
const memory = new AgenticMemory({
  dispatch: bridge.dispatch,
  authority: AUTHORITIES.RESEARCHER,
  writeTool: 'memory_write',
  releaseTool: 'mem_release',
  readTool: 'memory_read',
});

await memory.write({
  agent_id: 'agent-a',
  content: 'Auth flow diverges on expired tokens',
  memory_type: 'observation',
  confidence: 0.85,
  importance: 0.7,
  coordination_scope: 'auth',
});

await memory.release({ handle_id: 'h-123', outcome: 'persisted' });
```

Methods:

| Method | What it does |
|--------|--------------|
| `write(args)` | Runs `classifyWrite`, then the bound `checkAuthority`, then dispatches to `writeTool`. Throws on classification or authority failure. |
| `release(args)` | Validates `handle_id` and `outcome ∈ {persisted, discarded, escalated}`, then dispatches to `releaseTool`. |
| `read(args)` | Delegates without classification. Reads are not steered. |

No persistence, no caching, no session tracking — `AgenticMemory`
exists so application code has one obvious surface. Use
`createAgenticMemory(opts)` as a factory alternative to `new`.

### Authority Gating

An **Authority** is a capability bundle describing what an agent may
commit to memory. It answers three questions at the write boundary:

1. Which `memory_type`s may this agent commit?
2. What are its `confidence` / `importance` ceilings?
3. Which `coordination_scope`s may it own?

Authority gating runs in the prehook after `classifyWrite`. If a tool
declares `steering.authority`, the bridge consults the gate and rejects
unauthorized calls with `InvalidParams`. It is stateless and
declarative — 40mcp never maintains an agent membership database.

#### Built-in presets

| Preset | Allowed memory_types | Max confidence | Max importance |
|--------|----------------------|----------------|----------------|
| `READONLY` | — | 0 | 0 |
| `OBSERVER` | observation, fact, reference | 0.8 | 0.5 |
| `RESEARCHER` | observer + inference, hypothesis, assumption | 0.9 | 0.8 |
| `DECIDER` | researcher + decision, correction | 1.0 | 1.0 |
| `ROOT` | all | 1.0 | 1.0 |

#### Config shape

Reference a preset by name:

```json
"steering": { "write": true, "authority": "RESEARCHER" }
```

Or define a custom authority inline:

```json
"steering": {
  "write": true,
  "authority": {
    "id": "auth-wing-writer",
    "allowed_memory_types": ["observation", "inference"],
    "max_confidence": 0.9,
    "max_importance": 0.8,
    "allowed_scopes": ["auth", "session"]
  }
}
```

Scope-bounded authorities are how the auth-wing writer gets stopped
from stamping memories into the billing wing without explicit handoff.

#### Using Authority directly

```javascript
import { Authority, AUTHORITIES, checkAuthority } from '40mcp/steering';

const custom = Authority({
  id: 'triage-bot',
  allowed_memory_types: ['observation', 'hypothesis'],
  max_confidence: 0.7,
  max_importance: 0.5,
  allowed_scopes: ['support'],
});

const gate = checkAuthority(custom, {
  memory_type: 'hypothesis',
  confidence: 0.6,
  importance: 0.4,
  coordination_scope: 'support',
});
// { allowed: true, reason: null }
```

`checkAuthority` is a pure function — it never throws. Return value is
`{ allowed, reason }` so callers can choose to reject, downgrade, or
log. The bridge's prehook throws on denial, turning the reason into an
`InvalidParams` error for the MCP client.

### Where it lives

| Concern | File |
|---------|------|
| Enum + decay policy (source of truth) | `src/steering/schema.js` |
| `applySteering` + `classifyWrite` | `src/steering/apply.js` |
| `runPrehook` / `runPosthook` / envelope | `src/steering/hooks.js` |
| `Authority` + `AUTHORITIES` + `checkAuthority` | `src/steering/authority.js` |
| `AgenticMemory` class + `createAgenticMemory` | `src/steering/memory.js` |
| Barrel export | `src/steering/index.js` |
| Dispatcher integration | `src/bridge.js` (`buildDispatcher`) |
| Config validator | `src/validate.js` |

---

## Resources

- **GitHub:** https://github.com/modelcontextprotocol/40mcp
- **Examples:** `./examples/` directory
- **Documentation:** `.mcp.json` integration guide
