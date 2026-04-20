import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import {
  BridgeError,
  BridgeErrorCode,
  AuthError,
  ApiError,
  ChainError,
  apiErrorFromStatus,
} from './errors.js';

describe('BridgeError', () => {
  it('extends McpError', () => {
    const err = new BridgeError(BridgeErrorCode.CONFIG_INVALID, 'bad config');
    assert.ok(err instanceof McpError);
    assert.ok(err instanceof Error);
  });

  it('stores bridgeCode and details', () => {
    const err = new BridgeError(BridgeErrorCode.API_TIMEOUT, 'timeout', { path: '/users' });
    assert.equal(err.bridgeCode, 'API_TIMEOUT');
    assert.deepEqual(err.details, { path: '/users' });
  });

  it('maps to correct MCP error code', () => {
    const authErr = new BridgeError(BridgeErrorCode.AUTH_MISSING, 'missing');
    assert.equal(authErr.code, ErrorCode.InvalidRequest);

    const toolErr = new BridgeError(BridgeErrorCode.TOOL_NOT_FOUND, 'not found');
    assert.equal(toolErr.code, ErrorCode.MethodNotFound);

    const configErr = new BridgeError(BridgeErrorCode.CONFIG_INVALID, 'invalid');
    assert.equal(configErr.code, ErrorCode.InvalidParams);

    const internalErr = new BridgeError(BridgeErrorCode.API_NETWORK, 'network');
    assert.equal(internalErr.code, ErrorCode.InternalError);
  });

  it('toJSON serializes correctly', () => {
    const err = new BridgeError(BridgeErrorCode.API_TIMEOUT, 'timeout', { ms: 5000 });
    const json = err.toJSON();
    assert.equal(json.code, 'API_TIMEOUT');
    assert.ok(json.message.includes('timeout'));
    assert.deepEqual(json.details, { ms: 5000 });
  });
});

describe('AuthError', () => {
  it('extends BridgeError', () => {
    const err = new AuthError(BridgeErrorCode.AUTH_EXPIRED, 'token expired');
    assert.ok(err instanceof BridgeError);
    assert.ok(err instanceof McpError);
  });
});

describe('ApiError', () => {
  it('extends BridgeError with status details', () => {
    const err = new ApiError(BridgeErrorCode.API_RATE_LIMIT, 'rate limited', {
      statusCode: 429,
      method: 'GET',
      path: '/users',
    });
    assert.ok(err instanceof BridgeError);
    assert.equal(err.details.statusCode, 429);
    assert.equal(err.details.method, 'GET');
  });
});

describe('ChainError', () => {
  it('extends BridgeError with chain details', () => {
    const err = new ChainError(BridgeErrorCode.CHAIN_STEP_FAILED, 'step failed', {
      step: 'get_user',
      depth: 2,
    });
    assert.ok(err instanceof BridgeError);
    assert.equal(err.details.step, 'get_user');
    assert.equal(err.details.depth, 2);
  });
});

describe('apiErrorFromStatus', () => {
  it('returns AuthError for 401', () => {
    const err = apiErrorFromStatus(401, 'GET', '/users');
    assert.ok(err instanceof AuthError);
    assert.equal(err.bridgeCode, BridgeErrorCode.AUTH_INVALID);
  });

  it('returns AuthError for 403', () => {
    const err = apiErrorFromStatus(403, 'GET', '/admin');
    assert.ok(err instanceof AuthError);
    assert.equal(err.bridgeCode, BridgeErrorCode.AUTH_MISSING);
  });

  it('returns ApiError for 404', () => {
    const err = apiErrorFromStatus(404, 'GET', '/users/999');
    assert.ok(err instanceof ApiError);
    assert.equal(err.bridgeCode, BridgeErrorCode.API_NOT_FOUND);
    assert.equal(err.code, ErrorCode.InternalError);
  });

  it('returns ApiError for 429', () => {
    const err = apiErrorFromStatus(429, 'GET', '/users');
    assert.ok(err instanceof ApiError);
    assert.equal(err.bridgeCode, BridgeErrorCode.API_RATE_LIMIT);
  });

  it('returns ApiError for 400 with detail', () => {
    const err = apiErrorFromStatus(400, 'POST', '/users', 'missing field');
    assert.ok(err instanceof ApiError);
    assert.equal(err.bridgeCode, BridgeErrorCode.API_BAD_REQUEST);
    assert.ok(err.message.includes('missing field'));
  });

  it('returns ApiError for 500+', () => {
    const err = apiErrorFromStatus(500, 'GET', '/users');
    assert.ok(err instanceof ApiError);
    assert.equal(err.bridgeCode, BridgeErrorCode.API_SERVER_ERROR);
  });

  it('returns generic ApiError for other status codes', () => {
    const err = apiErrorFromStatus(418, 'GET', '/teapot');
    assert.ok(err instanceof ApiError);
    assert.equal(err.bridgeCode, BridgeErrorCode.API_SERVER_ERROR);
  });
});

describe('BridgeErrorCode enum', () => {
  it('has all expected error codes', () => {
    assert.equal(BridgeErrorCode.AUTH_MISSING, 'AUTH_MISSING');
    assert.equal(BridgeErrorCode.AUTH_EXPIRED, 'AUTH_EXPIRED');
    assert.equal(BridgeErrorCode.AUTH_INVALID, 'AUTH_INVALID');
    assert.equal(BridgeErrorCode.API_TIMEOUT, 'API_TIMEOUT');
    assert.equal(BridgeErrorCode.API_NETWORK, 'API_NETWORK');
    assert.equal(BridgeErrorCode.API_RATE_LIMIT, 'API_RATE_LIMIT');
    assert.equal(BridgeErrorCode.API_NOT_FOUND, 'API_NOT_FOUND');
    assert.equal(BridgeErrorCode.API_SERVER_ERROR, 'API_SERVER_ERROR');
    assert.equal(BridgeErrorCode.API_BAD_REQUEST, 'API_BAD_REQUEST');
    assert.equal(BridgeErrorCode.CHAIN_DEPTH_EXCEEDED, 'CHAIN_DEPTH_EXCEEDED');
    assert.equal(BridgeErrorCode.CHAIN_CIRCULAR_DEPENDENCY, 'CHAIN_CIRCULAR_DEPENDENCY');
    assert.equal(BridgeErrorCode.CHAIN_STEP_FAILED, 'CHAIN_STEP_FAILED');
    assert.equal(BridgeErrorCode.CHAIN_REF_UNDEFINED, 'CHAIN_REF_UNDEFINED');
    assert.equal(BridgeErrorCode.TOOL_NOT_FOUND, 'TOOL_NOT_FOUND');
    assert.equal(BridgeErrorCode.TOOL_DEPRECATED, 'TOOL_DEPRECATED');
    assert.equal(BridgeErrorCode.TOOL_VALIDATION, 'TOOL_VALIDATION');
    assert.equal(BridgeErrorCode.CONFIG_INVALID, 'CONFIG_INVALID');
    assert.equal(BridgeErrorCode.CONFIG_MISSING_FIELD, 'CONFIG_MISSING_FIELD');
    assert.equal(BridgeErrorCode.TRANSFORM_INVALID, 'TRANSFORM_INVALID');
  });
});
