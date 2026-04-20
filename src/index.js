/**
 * 40mcp — The universal API-to-MCP bridge.
 * Any API. Any protocol. Token-aware.
 *
 * Usage:
 *
 *   import { createRestBridge } from '40mcp';
 *
 *   createRestBridge({
 *     name: 'my-api',
 *     version: '1.0.0',
 *     baseUrl: 'http://localhost:3000',
 *     auth: { type: 'header', header: 'X-API-Key', envVar: 'API_KEY' },
 *     tools: [ ... ],
 *   }).start();
 */

// Core
export { createRestBridge } from './bridge.js';
export { loadConfig } from './config.js';
export { validateConfig, assertValidConfig } from './validate.js';
export { tui } from './tui.js';
export {
  GENERATE_SYSTEM_PROMPT,
  buildGeneratePrompt,
  parseGeneratedConfig,
  generatePrompt,
  generateFromSpec,
} from './generate.js';

// Loaders
export { loadOpenApiSpec } from './openapi.js';
export { loadGraphqlSchema } from './loaders/graphql.js';
export { loadHarFile } from './loaders/har.js';
export { registerLoader, loadFromAny, listLoaders } from './loaders/registry.js';

/**
 * Providers — Provider interface + OpenAPI reference implementation.
 *
 * The `providers` namespace exposes the Provider contract and adapters that
 * wrap existing loaders. It is the seam future features (OTEL attribution,
 * multi-version tools, progressive disclosure) will attach to.
 *
 * The legacy exports above — `loadOpenApiSpec`, `loadGraphqlSchema`,
 * `loadHarFile`, `connectStdio`, `connectSse`, `createReverseBridge` —
 * remain the stable surface. Provider adapters are additive; no loader's
 * shape or signature changes in this PR.
 */
export * as providers from './providers/index.js';

// Transforms
export { applyResponseTransform } from './transforms/response.js';

/**
 * Transforms — Transform interface.
 *
 * The `transforms` namespace exposes the `Transform` contract and
 * `composeTransforms` helper that future build-time / call-time reshapers
 * will conform to. See SPEC §2 "Pipeline order" for where
 * `applyToDispatch` and `applyToResult` run in the canonical pipeline.
 *
 * The existing `applyResponseTransform` export above remains the stable 1.0
 * surface for token-budget response shaping. Wrapping it behind the new
 * Transform interface is additive and lands in a future PR; no caller's
 * behaviour changes in this one.
 */
export * as transforms from './transforms/index.js';

// Compose
export { executeChain } from './compose/chain.js';
export { createMixer } from './compose/mixer.js';

// Transport
export { createStdioTransport, createSseTransport, createTransport } from './transport/index.js';

// Reverse
export { createReverseBridge, generateOpenApiSpec } from './reverse/server.js';

// Webhook
export { createWebhookListener } from './webhook/listener.js';

// Tenant
export { createTenantScope, tenantAuthHook } from './tenant/scope.js';

// Security
export { createVault, initVault, recoverVault } from './security/vault.js';
export { createVaultDaemonClient } from './security/vault-client.js';
export {
  createPolicyGate,
  createStdinApprovalHandler,
  createCallbackApprovalHandler,
  mergeToolPolicies,
} from './security/policy.js';
// Reserved for future OAuth / webhook callback flows — not yet wired into
// any call site. Validates a redirect URI against an operator-configured
// allowlist using component-wise comparison (scheme, host, port, path).
export { matchesAllowedRedirect } from './security/redirect.js';

// Connect (MCP-to-MCP linking)
export { connectStdio, connectSse, connectStreamableHttp, connectMany, connectFromConfig } from './connect.js';

// Errors
export {
  BridgeError,
  BridgeErrorCode,
  AuditEventCode,
  AuthError,
  ApiError,
  ChainError,
  apiErrorFromStatus,
} from './errors.js';
