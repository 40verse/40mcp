/**
 * Structured error taxonomy for 40mcp.
 *
 * Provides domain-specific error classes beyond the generic McpError,
 * enabling consumers to catch and handle specific failure modes.
 *
 * @module errors
 */

import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

/**
 * Error codes for 40mcp domain errors.
 * @enum {string}
 */
export const BridgeErrorCode = {
  // Auth errors
  AUTH_MISSING: 'AUTH_MISSING',
  AUTH_EXPIRED: 'AUTH_EXPIRED',
  AUTH_INVALID: 'AUTH_INVALID',

  // API errors
  API_TIMEOUT: 'API_TIMEOUT',
  API_NETWORK: 'API_NETWORK',
  API_RATE_LIMIT: 'API_RATE_LIMIT',
  API_NOT_FOUND: 'API_NOT_FOUND',
  API_SERVER_ERROR: 'API_SERVER_ERROR',
  API_BAD_REQUEST: 'API_BAD_REQUEST',

  // Config errors
  CONFIG_INVALID: 'CONFIG_INVALID',
  CONFIG_MISSING_FIELD: 'CONFIG_MISSING_FIELD',

  // Chain errors
  CHAIN_DEPTH_EXCEEDED: 'CHAIN_DEPTH_EXCEEDED',
  CHAIN_CIRCULAR_DEPENDENCY: 'CHAIN_CIRCULAR_DEPENDENCY',
  CHAIN_STEP_FAILED: 'CHAIN_STEP_FAILED',
  CHAIN_REF_UNDEFINED: 'CHAIN_REF_UNDEFINED',

  // Tool errors
  TOOL_NOT_FOUND: 'TOOL_NOT_FOUND',
  TOOL_DEPRECATED: 'TOOL_DEPRECATED',
  TOOL_VALIDATION: 'TOOL_VALIDATION',

  // Transform errors
  TRANSFORM_INVALID: 'TRANSFORM_INVALID',

  // Policy errors
  POLICY_DENIED: 'POLICY_DENIED',

  // Lifecycle errors
  /**
   * The bridge / connector / reverse-bridge has had `close()` invoked and
   * is refusing new dispatches while it drains in-flight work. The caller
   * should retry against a fresh instance or stop dispatching.
   */
  SHUTTING_DOWN: 'SHUTTING_DOWN',

  // Cancellation / AbortSignal
  ABORTED: 'ABORTED',
};

/**
 * Audit-log event codes — the `errorCode` field value emitted on audit log
 * entries for non-exception audit events (tenant ACL denials, policy gate
 * denials, policy-approval-in-chain refusals, etc.).
 *
 * These are intentionally separate from `BridgeErrorCode` because:
 *   - Not every audit event is an error (e.g. log_only policy gating).
 *   - Audit consumers — SIEM pipelines, log aggregators — want a stable,
 *     exhaustive, enum-shaped taxonomy they can match on without pulling
 *     in the full BridgeErrorCode surface.
 *   - Wire format stability: each value is the exact string already shipping
 *     on audit entries today, so existing consumers grepping for
 *     `"errorCode":"TENANT_ACL_DENY"` keep working unchanged.
 *
 * Frozen to prevent tampering / accidental extension from downstream code.
 *
 * @enum {string}
 */
export const AuditEventCode = Object.freeze({
  /** Tool call rejected by tenant allowlist/blocklist (see src/bridge.js). */
  TENANT_ACL_DENY: 'TENANT_ACL_DENY',
  /** Tool call rejected because policy === 'deny'. Mirrors BridgeErrorCode.POLICY_DENIED. */
  POLICY_DENIED: 'POLICY_DENIED',
  /** Chain sub-step invoked a policy 'require_approval' tool without re-entering the policy gate. */
  POLICY_APPROVAL_REQUIRED_IN_CHAIN: 'POLICY_APPROVAL_REQUIRED_IN_CHAIN',
});

/**
 * Base error class for 40mcp domain errors.
 * Extends McpError so MCP protocol handling works seamlessly.
 */
export class BridgeError extends McpError {
  /**
   * @param {string} bridgeCode - BridgeErrorCode value
   * @param {string} message - Human-readable error message
   * @param {object} [details] - Additional context for debugging
   */
  constructor(bridgeCode, message, details) {
    const mcpCode = mapToMcpErrorCode(bridgeCode);
    super(mcpCode, message);
    this.bridgeCode = bridgeCode;
    this.details = details || {};
  }

  toJSON() {
    return {
      code: this.bridgeCode,
      message: this.message,
      details: this.details,
    };
  }
}

/**
 * Auth-related error.
 */
export class AuthError extends BridgeError {
  constructor(bridgeCode, message, details) {
    super(bridgeCode, message, details);
  }
}

/**
 * API call failure.
 */
export class ApiError extends BridgeError {
  /**
   * @param {string} bridgeCode
   * @param {string} message
   * @param {object} [details]
   * @param {number} [details.statusCode] - HTTP status code
   * @param {string} [details.method] - HTTP method
   * @param {string} [details.path] - Request path
   */
  constructor(bridgeCode, message, details) {
    super(bridgeCode, message, details);
  }
}

/**
 * Chain execution failure.
 */
export class ChainError extends BridgeError {
  /**
   * @param {string} bridgeCode
   * @param {string} message
   * @param {object} [details]
   * @param {string} [details.step] - Failed step name
   * @param {number} [details.depth] - Current chain depth
   * @param {object} [details.partialResults] - Results collected before failure
   */
  constructor(bridgeCode, message, details) {
    super(bridgeCode, message, details);
  }
}

/**
 * Map bridge error codes to MCP protocol error codes.
 * @private
 */
function mapToMcpErrorCode(bridgeCode) {
  switch (bridgeCode) {
    case BridgeErrorCode.AUTH_MISSING:
    case BridgeErrorCode.AUTH_EXPIRED:
    case BridgeErrorCode.AUTH_INVALID:
    case BridgeErrorCode.API_BAD_REQUEST:
    case BridgeErrorCode.TOOL_VALIDATION:
    case BridgeErrorCode.POLICY_DENIED:
      return ErrorCode.InvalidRequest;

    case BridgeErrorCode.TOOL_NOT_FOUND:
      return ErrorCode.MethodNotFound;

    case BridgeErrorCode.API_NOT_FOUND:
      return ErrorCode.InternalError;

    case BridgeErrorCode.ABORTED:
      // MCP protocol does not define a dedicated cancellation code. Map to
      // InternalError so the wire response still carries the BridgeError
      // taxonomy via toJSON() (bridgeCode === 'ABORTED') while remaining a
      // well-formed JSON-RPC error.
      return ErrorCode.InternalError;

    case BridgeErrorCode.CONFIG_INVALID:
    case BridgeErrorCode.CONFIG_MISSING_FIELD:
    case BridgeErrorCode.TRANSFORM_INVALID:
      return ErrorCode.InvalidParams;

    case BridgeErrorCode.SHUTTING_DOWN:
      // Shutting-down is a lifecycle refusal, not a request validity problem.
      // Map to InternalError so MCP clients see a retryable error code rather
      // than misreporting the caller's request as malformed.
      return ErrorCode.InternalError;

    default:
      return ErrorCode.InternalError;
  }
}

/**
 * Create an ApiError from an HTTP response status code.
 * @param {number} status - HTTP status code
 * @param {string} method - HTTP method
 * @param {string} path - Request path
 * @param {string} [detail] - Additional detail from response body
 * @returns {ApiError}
 */
export function apiErrorFromStatus(status, method, path, detail) {
  const base = { statusCode: status, method, path };

  if (status === 401) {
    return new AuthError(BridgeErrorCode.AUTH_INVALID, `Authentication failed on ${method} ${path}`, base);
  }
  if (status === 403) {
    return new AuthError(BridgeErrorCode.AUTH_MISSING, `Forbidden: ${method} ${path}`, base);
  }
  if (status === 404) {
    return new ApiError(BridgeErrorCode.API_NOT_FOUND, `Not found: ${method} ${path}`, base);
  }
  if (status === 429) {
    return new ApiError(BridgeErrorCode.API_RATE_LIMIT, `Rate limited on ${method} ${path}`, base);
  }
  if (status === 400) {
    return new ApiError(BridgeErrorCode.API_BAD_REQUEST, `Bad request on ${method} ${path}${detail ? ': ' + detail : ''}`, base);
  }
  if (status >= 500) {
    return new ApiError(BridgeErrorCode.API_SERVER_ERROR, `Server error ${status} on ${method} ${path}`, base);
  }

  return new ApiError(BridgeErrorCode.API_SERVER_ERROR, `API returned ${status} on ${method} ${path}`, base);
}
