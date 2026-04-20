/**
 * 40mcp/tenant — TypeScript declarations for the `./tenant` subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/tenant'`.
 * Canonical declarations live in `../index.d.ts`; re-exported here to keep
 * a single source of truth.
 */

export {
  TenantContext,
  TenantScopeConfig,
  ScopedDispatchFn,
  createTenantScope,
  tenantAuthHook,
} from '../index.js';
