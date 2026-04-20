/**
 * 40mcp/policy — TypeScript declarations for the `./policy` subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/policy'`.
 * Canonical declarations live in `../index.d.ts`; re-exported here to keep
 * a single source of truth.
 */

export {
  PolicyRule,
  PolicyDecision,
  PolicyApprovalContext,
  ApprovalHandler,
  PolicyGateConfig,
  createPolicyGate,
  createStdinApprovalHandler,
  createCallbackApprovalHandler,
} from '../index.js';
