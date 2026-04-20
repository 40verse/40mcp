import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { Server as HttpServer } from 'node:http';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

// ─── Core Types ─────────────────────────────────────────────────────────────

export interface ToolDef {
  name: string;
  description: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  queryMap?: Record<string, string>;
  bodyMap?: Record<string, string>;
  inputSchema: JsonSchema;
  response?: ResponseTransform;
  chain?: ChainStep[];
  chainResponse?: ResponseTransform;
  deprecated?: boolean | string;
  successor?: string;
  version?: string;
  removedIn?: string;
  /**
   * Embedded policy annotation. Honored by `createPolicyGate` when `tools` is
   * passed, and by the CLI when `serve --policy` / `link --policy` is used.
   * Without a gate, this is metadata only.
   */
  policy?: PolicyRule;
}

export interface JsonSchema {
  type: string;
  properties?: Record<string, any>;
  required?: string[];
  [key: string]: any;
}

export interface ResponseTransform {
  pick?: string[];
  omit?: string[];
  limit?: number;
  flatten?: boolean;
  summary?: boolean | string;
  tokenBudget?: number;
  template?: string;
}

export interface ChainStep {
  call: string;
  as: string;
  args?: Record<string, any>;
  optional?: boolean;
}

export interface AuthConfig {
  type: 'header' | 'bearer' | 'basic' | 'oauth2' | 'sealed' | 'sealed-bearer';
  header?: string;
  envVar?: string;
  value?: string;
  name?: string;
  tokenUrl?: string;
  clientId?: string;
  clientIdEnv?: string;
  clientSecret?: string;
  clientSecretEnv?: string;
  scope?: string;
  grantType?: string;
}

export interface TransportConfig {
  type?: 'stdio' | 'sse';
  port?: number;
  host?: string;
  allowedOrigins?: string[];
  maxSessions?: number;
}

export interface HooksConfig {
  beforeRequest?: (req: BeforeRequestContext) => Promise<BeforeRequestResult | null> | BeforeRequestResult | null;
  timeoutMs?: number;
}

export interface BeforeRequestContext {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: any;
}

export interface BeforeRequestResult {
  headers?: Record<string, string>;
  body?: any;
}

export interface BridgeConfig {
  name?: string;
  version?: string;
  baseUrl: string;
  auth?: AuthConfig;
  hooks?: HooksConfig;
  transport?: TransportConfig;
  tools: ToolDef[];
  /**
   * Post-construction dispatch wrapper. Receives the bridge's raw dispatch
   * closure and returns the dispatch used for both the MCP CallTool handler
   * and the exported `bridge.dispatch`. Typical use: inject `createPolicyGate`.
   */
  wrapDispatch?: (dispatch: DispatchFn) => DispatchFn;
}

// ─── Bridge ─────────────────────────────────────────────────────────────────

export type DispatchFn = (name: string, args: Record<string, any>, chainOptions?: ChainOptions) => Promise<any>;

export interface BridgeInstance {
  start(): Promise<BridgeStartResult>;
  server: Server;
  dispatch: DispatchFn;
  apiClient: (method: string, path: string, body?: any) => Promise<any>;
}

export interface BridgeStartResult {
  server: Server;
  dispatch: DispatchFn;
  httpServer?: HttpServer;
  url?: string;
  close(): Promise<void>;
}

export function createRestBridge(config: BridgeConfig): BridgeInstance;

// ─── Config ─────────────────────────────────────────────────────────────────

export function loadConfig(filePath: string): Promise<BridgeConfig>;

// ─── Validation ─────────────────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/** Validate a bridge config. Returns errors/warnings without throwing. */
export function validateConfig(config: BridgeConfig | Record<string, any>): ValidationResult;

/** Validate a bridge config. Throws BridgeError if invalid. */
export function assertValidConfig(config: BridgeConfig | Record<string, any>): void;

// ─── TUI ────────────────────────────────────────────────────────────────────

export interface TuiSpinner {
  start(label?: string): void;
  stop(label?: string): void;
  succeed(label?: string): void;
  fail(label?: string): void;
}

export interface TuiProgress {
  (current: number, total: number, label?: string): void;
}

export interface TuiTableRow {
  [key: string]: string | number | boolean;
}

export declare const tui: {
  isTTY: boolean;
  isNoColor: boolean;
  isMcpStdio: boolean;
  color(text: string, code: number): string;
  bold(text: string): string;
  dim(text: string): string;
  red(text: string): string;
  green(text: string): string;
  yellow(text: string): string;
  blue(text: string): string;
  cyan(text: string): string;
  gray(text: string): string;
  cursor: { hide(): void; show(): void };
  spinner(label?: string): TuiSpinner;
  progress(current: number, total: number, label?: string): void;
  table(rows: TuiTableRow[], options?: { headers?: string[]; title?: string }): void;
  box(content: string, options?: { title?: string; width?: number }): void;
  toolTable(tools: Array<{ name: string; description?: string }>, options?: { title?: string }): void;
  statusLine(label: string, value: string, options?: { color?: string }): void;
  activityLine(message: string): void;
  banner(title: string, subtitle?: string): void;
  fatal(message: string): void;
  success(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  jsonOutput(data: unknown): void;
};

// ─── Loaders ────────────────────────────────────────────────────────────────

export interface LoaderResult {
  baseUrl: string;
  tools: ToolDef[];
}

export interface OpenApiLoaderOptions {
  include?: string[];
  exclude?: string[];
  tags?: string[];
  methods?: string[];
  nameTransform?: (operationId: string, method: string, pathTemplate: string) => string;
}

export function loadOpenApiSpec(specOrPath: string | object, options?: OpenApiLoaderOptions): Promise<LoaderResult>;

export interface GraphqlLoaderOptions {
  include?: string[];
  exclude?: string[];
  types?: ('query' | 'mutation')[];
  headers?: Record<string, string>;
  endpoint?: string;
  nameTransform?: (fieldName: string, operationType: string) => string;
}

export function loadGraphqlSchema(endpointOrSchema: string | object, options?: GraphqlLoaderOptions): Promise<LoaderResult>;

export interface HarLoaderOptions {
  include?: string[];
  exclude?: string[];
  methods?: string[];
  minObservations?: number;
}

export interface HarToolDef extends ToolDef {
  _confidence: 'low' | 'medium' | 'high';
  _observations: number;
}

export interface HarLoaderResult {
  baseUrl: string;
  tools: HarToolDef[];
}

export function loadHarFile(harOrPath: string | object, options?: HarLoaderOptions): Promise<HarLoaderResult>;

// ─── Transforms ─────────────────────────────────────────────────────────────

export function applyResponseTransform(data: any, transform?: ResponseTransform): any;

// ─── Compose ────────────────────────────────────────────────────────────────

export interface ChainOptions {
  maxDepth?: number;
  response?: ResponseTransform;
  _depth?: number;
}

export interface ChainResult {
  _chain: {
    steps: number;
    completed: number;
    failed: number;
    errors: Array<{ step: string; message: string }>;
  };
  [key: string]: any;
}

export function executeChain(
  steps: ChainStep[],
  args: Record<string, any>,
  dispatch: DispatchFn,
  options?: ChainOptions,
): Promise<ChainResult>;

export interface MixerServerConfig extends BridgeConfig {
  prefix?: string;
  allowlist?: string[];
  blocklist?: string[];
}

export interface MixerConfig {
  name?: string;
  version?: string;
  servers: MixerServerConfig[];
}

export interface MixerInstance {
  start(): Promise<{ server: Server; dispatch: DispatchFn }>;
  server: Server;
  dispatch: DispatchFn;
}

export function createMixer(config: MixerConfig): MixerInstance;

// ─── Transport ──────────────────────────────────────────────────────────────

export function createStdioTransport(): StdioServerTransport;

export interface SseTransportOptions {
  port?: number;
  host?: string;
  path?: string;
  messagePath?: string;
  allowedOrigins?: string[];
  maxSessions?: number;
  /**
   * Require `Authorization: Bearer <token>` on GET /sse and POST /message.
   * When set, unauthenticated requests receive 401 before touching session
   * or per-IP accounting. /health and OPTIONS preflights remain open.
   *
   * Single-token mode: pass the literal token string.
   * Multi-token mode: pass a `{ principalName: token }` map. Principal
   * names appear on `sse.auth_ok` / `sse.session_open` / `sse.session_close`
   * events so operators can attribute activity to a specific credential
   * and revoke one without rotating the others.
   */
  requireBearer?: string | Record<string, string>;
  /**
   * Optional callback invoked on GET /health. Returns an object that
   * replaces the default `{status:"ok"}` payload — used by the published
   * frontdoor to surface per-upstream liveness. Errors fall back to the
   * default payload so an orchestrator liveness probe never breaks.
   */
  healthProvider?: () => Record<string, unknown>;
  /**
   * Maximum concurrent sessions attributed to a single principal in
   * multi-token mode. Composes with `maxSessionsPerIp`. No-op for
   * unauthenticated requests and for single-token mode. Default: 5.
   */
  maxSessionsPerPrincipal?: number;
}

export interface SseTransportResult {
  httpServer: HttpServer;
  url: string;
}

export function createSseTransport(server: Server, options?: SseTransportOptions): Promise<SseTransportResult>;

export function createTransport(
  type: 'stdio' | 'sse',
  options?: SseTransportOptions,
): (server?: Server) => Promise<StdioServerTransport | SseTransportResult>;

// ─── Reverse Bridge ─────────────────────────────────────────────────────────

export interface ReverseBridgeConfig {
  name?: string;
  version?: string;
  tools: Array<{ name: string; description?: string; inputSchema?: JsonSchema }>;
  dispatch: DispatchFn;
  port?: number;
  basePath?: string;
  host?: string;
  auth?: { header: string; envVar: string };
  allowedOrigin?: string;
}

export interface ReverseBridgeInstance {
  start(): Promise<{ httpServer: HttpServer; url: string }>;
  generateOpenApiSpec(): object;
}

export function createReverseBridge(config: ReverseBridgeConfig): ReverseBridgeInstance;

export function generateOpenApiSpec(config: {
  name?: string;
  version?: string;
  tools: Array<{ name: string; description?: string; inputSchema?: JsonSchema }>;
  basePath?: string;
}): object;

// ─── Webhook ────────────────────────────────────────────────────────────────

export interface WebhookSecret {
  type: 'header' | 'hmac' | 'query';
  envVar?: string;
  value?: string;
  header?: string;
  param?: string;
}

export interface WebhookRoute {
  path: string;
  method?: string;
  tool: string;
  argMap?: Record<string, string>;
  filter?: Record<string, string | string[]>;
  secret?: WebhookSecret;
  response?: 'async' | 'sync';
}

export interface WebhookListenerConfig {
  name?: string;
  port?: number;
  host?: string;
  dispatch: DispatchFn;
  routes: WebhookRoute[];
}

export interface WebhookListenerInstance {
  routes: WebhookRoute[];
  start(): Promise<{ httpServer: HttpServer; url: string }>;
}

export function createWebhookListener(config: WebhookListenerConfig): WebhookListenerInstance;

// ─── Tenant ─────────────────────────────────────────────────────────────────

export interface TenantContext {
  tenantId: string;
  auth?: AuthConfig;
  allowlist?: string[];
  blocklist?: string[];
  metadata?: Record<string, any>;
}

export interface TenantScopeConfig {
  dispatch: DispatchFn;
  resolveContext: (requestMeta?: any) => Promise<TenantContext | null>;
  defaults?: Partial<TenantContext>;
}

export type ScopedDispatchFn = (toolName: string, args: Record<string, any>, requestMeta?: any) => Promise<any>;

export function createTenantScope(config: TenantScopeConfig): ScopedDispatchFn;

export function tenantAuthHook(): (req: BeforeRequestContext) => Promise<BeforeRequestResult | null>;

// ─── Errors ─────────────────────────────────────────────────────────────────

export declare const BridgeErrorCode: {
  readonly AUTH_MISSING: 'AUTH_MISSING';
  readonly AUTH_EXPIRED: 'AUTH_EXPIRED';
  readonly AUTH_INVALID: 'AUTH_INVALID';
  readonly API_TIMEOUT: 'API_TIMEOUT';
  readonly API_NETWORK: 'API_NETWORK';
  readonly API_RATE_LIMIT: 'API_RATE_LIMIT';
  readonly API_NOT_FOUND: 'API_NOT_FOUND';
  readonly API_SERVER_ERROR: 'API_SERVER_ERROR';
  readonly API_BAD_REQUEST: 'API_BAD_REQUEST';
  readonly CONFIG_INVALID: 'CONFIG_INVALID';
  readonly CONFIG_MISSING_FIELD: 'CONFIG_MISSING_FIELD';
  readonly CHAIN_DEPTH_EXCEEDED: 'CHAIN_DEPTH_EXCEEDED';
  readonly CHAIN_CIRCULAR_DEPENDENCY: 'CHAIN_CIRCULAR_DEPENDENCY';
  readonly CHAIN_STEP_FAILED: 'CHAIN_STEP_FAILED';
  readonly CHAIN_REF_UNDEFINED: 'CHAIN_REF_UNDEFINED';
  readonly TOOL_NOT_FOUND: 'TOOL_NOT_FOUND';
  readonly TOOL_DEPRECATED: 'TOOL_DEPRECATED';
  readonly TOOL_VALIDATION: 'TOOL_VALIDATION';
  readonly TRANSFORM_INVALID: 'TRANSFORM_INVALID';
  readonly POLICY_DENIED: 'POLICY_DENIED';
};

export type BridgeErrorCodeValue = typeof BridgeErrorCode[keyof typeof BridgeErrorCode];

/**
 * Audit-log event codes emitted on the `errorCode` field of audit log entries
 * for non-exception audit events (tenant ACL denials, policy gate denials,
 * chain-step policy-approval refusals). Separate from BridgeErrorCode because
 * not every audit event is an error.
 *
 * Wire-format stable: each value is exactly the string emitted on audit
 * entries, so existing SIEM/log consumers matching on these strings work
 * unchanged.
 */
export declare const AuditEventCode: {
  readonly TENANT_ACL_DENY: 'TENANT_ACL_DENY';
  readonly POLICY_DENIED: 'POLICY_DENIED';
  readonly POLICY_APPROVAL_REQUIRED_IN_CHAIN: 'POLICY_APPROVAL_REQUIRED_IN_CHAIN';
};

export type AuditEventCodeValue = typeof AuditEventCode[keyof typeof AuditEventCode];

export declare class BridgeError extends McpError {
  bridgeCode: BridgeErrorCodeValue;
  details: Record<string, any>;
  constructor(bridgeCode: BridgeErrorCodeValue, message: string, details?: Record<string, any>);
  toJSON(): { code: string; message: string; details: Record<string, any> };
}

export declare class AuthError extends BridgeError {
  constructor(bridgeCode: BridgeErrorCodeValue, message: string, details?: Record<string, any>);
}

export declare class ApiError extends BridgeError {
  constructor(
    bridgeCode: BridgeErrorCodeValue,
    message: string,
    details?: { statusCode?: number; method?: string; path?: string },
  );
}

export declare class ChainError extends BridgeError {
  constructor(
    bridgeCode: BridgeErrorCodeValue,
    message: string,
    details?: { step?: string; depth?: number; partialResults?: Record<string, any> },
  );
}

export function apiErrorFromStatus(status: number, method: string, path: string, detail?: string): ApiError;

// ─── Plugin System ──────────────────────────────────────────────────────────

export interface LoaderPlugin {
  name: string;
  detect: (input: string | object) => boolean;
  load: (input: string | object, options?: Record<string, any>) => Promise<LoaderResult>;
}

export function registerLoader(plugin: LoaderPlugin): void;
export function loadFromAny(input: string | object, options?: Record<string, any>): Promise<LoaderResult>;
export function listLoaders(): Array<{ name: string; builtin: boolean }>;

// ─── Security: Vault ────────────────────────────────────────────────────────

export interface VaultConfig {
  path: string;
  passphrase: string;
  tokenTTL?: number;
}

export interface SealedEntry {
  name: string;
  sealId: string;
  fingerprint: string;
  metadata: Record<string, any>;
  created: string;
  rotated?: string;
}

export interface CredentialToken {
  token: string;
  expiresAt: number;
}

export interface VerifiedToken {
  name: string;
  value: string;
  sealId: string;
  claims: Record<string, any>;
}

export interface SealedVault {
  set(name: string, value: string, metadata?: Record<string, any>): Promise<string>;
  issueToken(name: string, claims?: Record<string, any>): Promise<CredentialToken | null>;
  verifyToken(token: string): Promise<VerifiedToken>;
  getSealId(name: string): Promise<string | null>;
  getFingerprint(name: string): Promise<string | null>;
  has(name: string): Promise<boolean>;
  rotate(name: string): Promise<string | null>;
  delete(name: string): Promise<void>;
  list(): Promise<SealedEntry[]>;
  createAuthHook(mapping: Record<string, string>): (req: BeforeRequestContext) => Promise<BeforeRequestResult | null>;
  createBearerHook(name: string): (req: BeforeRequestContext) => Promise<BeforeRequestResult | null>;
  rotateKEK(newPassphrase: string): Promise<void>;
  unsealConfig(config: object): Promise<object>;
}

export function createVault(config: VaultConfig): SealedVault;

export interface InitVaultResult {
  vault: SealedVault;
  recoveryKey: string;
}

export function initVault(config: { path: string; passphrase: string }): Promise<InitVaultResult>;

export function recoverVault(config: { path: string; recoveryKey: string; newPassphrase: string }): Promise<SealedVault>;

export interface VaultDaemonClientConfig {
  socketPath?: string;
  configPath?: string;
  daemonSecret?: string;
  vaultPath?: string;
  passphrase?: string;
}

export interface VaultDaemonClient {
  createAuthHook(mapping: Record<string, string>): (req: BeforeRequestContext) => Promise<BeforeRequestResult | null>;
  createBearerHook(name: string): (req: BeforeRequestContext) => Promise<BeforeRequestResult | null>;
}

export function createVaultDaemonClient(config?: VaultDaemonClientConfig): VaultDaemonClient;

// ─── Security: Policy Gate ──────────────────────────────────────────────────

export type PolicyRule = 'allow' | 'deny' | 'require_approval' | 'log_only';
export type PolicyDecision = 'approve' | 'deny' | 'timeout';

export interface PolicyApprovalContext {
  tool: string;
  args: Record<string, any>;
  timestamp: string;
  policy: PolicyRule;
}

export type ApprovalHandler = (context: PolicyApprovalContext) => Promise<PolicyDecision>;

export interface PolicyGateConfig {
  dispatch: DispatchFn;
  tools?: ToolDef[];
  toolPolicies?: Record<string, PolicyRule>;
  approvalHandler?: ApprovalHandler;
  logger?: (level: string, message: string, context?: any) => void;
  approvalTimeoutMs?: number;
  defaultPolicy?: PolicyRule;
  dangerousActions?: string[];
}

export function createPolicyGate(config: PolicyGateConfig): DispatchFn;
export function createStdinApprovalHandler(): ApprovalHandler;
export function createCallbackApprovalHandler(callback: ApprovalHandler): ApprovalHandler;

/**
 * Compile sidecar `toolPolicies` into embedded `tool.policy` on the given
 * tool definitions, in place. Sidecar wins. Required to close the chain
 * sub-dispatch bypass when feeding sidecar rules through `createRestBridge`
 * — the bridge's per-dispatch re-check reads only `tool.policy`.
 *
 * @returns number of tools whose policy was set from sidecar
 */
export function mergeToolPolicies(tools: ToolDef[], toolPolicies: Record<string, PolicyRule>): number;

// ─── AI-Assisted Generation ─────────────────────────────────────────────────

export declare const GENERATE_SYSTEM_PROMPT: string;

export interface GenerateOptions {
  description: string;
  baseUrl?: string;
  authType?: string;
  apiDocs?: string;
  endpoints?: string[];
  style?: 'minimal' | 'comprehensive';
}

export interface GenerateFromSpecOptions {
  policyGateWrites?: boolean;
  addTransforms?: boolean;
  tokenBudget?: number;
}

export interface ParsedGenerateResult {
  config: BridgeConfig | null;
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export function buildGeneratePrompt(options: GenerateOptions): string;
export function generatePrompt(options: GenerateOptions): { system: string; user: string };
export function parseGeneratedConfig(llmOutput: string): ParsedGenerateResult;
export function generateFromSpec(spec: object, options?: GenerateFromSpecOptions): BridgeConfig;

// ─── MCP Client Connector ───────────────────────────────────────────────────

export interface StdioConnectConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  prefix?: string;
  allowlist?: string[];
  blocklist?: string[];
  transforms?: ResponseTransform;
  policy?: PolicyRule;
}

export interface SseConnectConfig {
  url: string;
  headers?: Record<string, string>;
  /**
   * Transport selection for URL-based upstreams. Defaults to `"streamable-http"`
   * (the current MCP spec). Set to `"sse"` to talk to legacy SSE-only servers.
   */
  transport?: 'streamable-http' | 'sse';
  prefix?: string;
  allowlist?: string[];
  blocklist?: string[];
  transforms?: ResponseTransform;
  policy?: PolicyRule;
}

/** Alias for `SseConnectConfig` — both transports share the same config shape. */
export type StreamableHttpConnectConfig = SseConnectConfig;

export interface ConnectedTool {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  _upstream: string;
  _source: string;
  _policy?: PolicyRule;
  _transforms?: ResponseTransform;
}

export interface ConnectedServer {
  tools: ConnectedTool[];
  client: any;
  source: string;
  dispatch(name: string, args: Record<string, any>): Promise<any>;
  close(): Promise<void>;
}

export interface ConnectedCluster {
  tools: ConnectedTool[];
  connections: ConnectedServer[];
  dispatch(name: string, args: Record<string, any>): Promise<any>;
  close(): Promise<void>;
}

export function connectStdio(config: StdioConnectConfig): Promise<ConnectedServer>;
export function connectSse(config: SseConnectConfig): Promise<ConnectedServer>;
export function connectStreamableHttp(config: StreamableHttpConnectConfig): Promise<ConnectedServer>;
export function connectMany(servers: Array<StdioConnectConfig | SseConnectConfig>): Promise<ConnectedCluster>;
export function connectFromConfig(
  mcpConfig: Record<string, {
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    url?: string;
    headers?: Record<string, string>;
    transport?: 'streamable-http' | 'sse';
  }>,
  options?: { prefixes?: Record<string, string>; only?: string[]; skip?: string[] },
): Promise<ConnectedCluster>;
