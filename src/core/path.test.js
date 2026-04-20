import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import {
  qs,
  extractPathParams,
  interpolatePath,
  remapKeys,
  dispatchToolCall,
  toSnakeCase,
} from './path.js';

// ─────────────────────────────────────────────────────────────────────────────
// qs() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('qs', () => {
  it('empty params returns empty string', () => {
    assert.equal(qs({}), '');
  });

  it('single param returns query string with ?', () => {
    assert.equal(qs({ id: '123' }), '?id=123');
  });

  it('multiple params returns combined query string', () => {
    const result = qs({ id: '123', name: 'alice' });
    assert.match(result, /^\?/);
    assert.match(result, /id=123/);
    assert.match(result, /name=alice/);
  });

  it('array values append multiple values for same key', () => {
    const result = qs({ ids: ['1', '2', '3'] });
    assert.match(result, /ids=1/);
    assert.match(result, /ids=2/);
    assert.match(result, /ids=3/);
  });

  it('filters out null values', () => {
    const result = qs({ id: '123', skip: null });
    assert.equal(result, '?id=123');
  });

  it('filters out undefined values', () => {
    const result = qs({ id: '123', skip: undefined });
    assert.equal(result, '?id=123');
  });

  it('filters out empty string values', () => {
    const result = qs({ id: '123', name: '' });
    assert.equal(result, '?id=123');
  });

  it('filters out undefined/null items in arrays', () => {
    const result = qs({ ids: ['1', null, '3', undefined] });
    assert.match(result, /ids=1/);
    assert.match(result, /ids=3/);
    assert(!result.includes('null'));
  });

  it('URI encodes special characters', () => {
    const result = qs({ query: 'hello world' });
    // URLSearchParams encodes space as + or %20, both are valid
    assert.match(result, /query=(hello%20world|hello\+world)/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// extractPathParams() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('extractPathParams', () => {
  it('returns empty array when no params', () => {
    const result = extractPathParams('/users/list');
    assert.deepEqual(result, []);
  });

  it('extracts single param', () => {
    const result = extractPathParams('/users/:id');
    assert.deepEqual(result, ['id']);
  });

  it('extracts multiple params', () => {
    const result = extractPathParams('/users/:userId/posts/:postId');
    assert.deepEqual(result, ['userId', 'postId']);
  });

  it('extracts params with numbers', () => {
    const result = extractPathParams('/api/:v1/resource/:id123');
    assert.deepEqual(result, ['v1', 'id123']);
  });

  it('extracts params with underscores', () => {
    const result = extractPathParams('/api/:user_id/:post_id');
    assert.deepEqual(result, ['user_id', 'post_id']);
  });

  it('does not match invalid starting param names (starting with digit)', () => {
    const result = extractPathParams('/api/:123id/:valid');
    assert.deepEqual(result, ['valid']);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// interpolatePath() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('interpolatePath', () => {
  it('single param interpolation', () => {
    const result = interpolatePath('/users/:id', { id: '123' });
    assert.equal(result, '/users/123');
  });

  it('multiple params interpolation', () => {
    const result = interpolatePath('/users/:userId/posts/:postId', { userId: '42', postId: '100' });
    assert.equal(result, '/users/42/posts/100');
  });

  it('URI encodes spaces', () => {
    const result = interpolatePath('/search/:query', { query: 'hello world' });
    assert.equal(result, '/search/hello%20world');
  });

  it('rejects slashes in path parameters by default', () => {
    assert.throws(
      () => interpolatePath('/path/:slug', { slug: 'foo/bar' }),
      (err) => err.message.includes('path separator'),
    );
  });

  it('URI encodes slashes when tool opts into allowSlashes', () => {
    const result = interpolatePath('/path/:slug', { slug: 'foo/bar' }, { allowSlashes: true });
    assert.equal(result, '/path/foo%2Fbar');
  });

  it('rejects `..` in path parameters', () => {
    assert.throws(
      () => interpolatePath('/path/:slug', { slug: '..' }),
      (err) => err.message.includes('..'),
    );
  });

  it('rejects NUL byte in path parameters', () => {
    assert.throws(
      () => interpolatePath('/path/:slug', { slug: 'foo\x00bar' }),
      (err) => err.message.includes('NUL'),
    );
  });

  it('URI encodes @ symbol', () => {
    const result = interpolatePath('/email/:addr', { addr: 'user@example.com' });
    assert.equal(result, '/email/user%40example.com');
  });

  it('throws McpError when param is missing', () => {
    assert.throws(
      () => {
        interpolatePath('/users/:id', {});
      },
      (err) => {
        return (
          err instanceof McpError &&
          err.code === ErrorCode.InvalidParams &&
          err.message.includes('Missing required path parameter: id')
        );
      }
    );
  });

  it('throws McpError when param is null', () => {
    assert.throws(
      () => {
        interpolatePath('/users/:id', { id: null }),
          (err) => {
            return err instanceof McpError && err.code === ErrorCode.InvalidParams;
          };
      }
    );
  });

  it('throws McpError when param is undefined', () => {
    assert.throws(
      () => {
        interpolatePath('/users/:id', { id: undefined }),
          (err) => {
            return err instanceof McpError && err.code === ErrorCode.InvalidParams;
          };
      }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// remapKeys() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('remapKeys', () => {
  it('passthrough without map', () => {
    const result = remapKeys({ id: '123', name: 'alice' }, null);
    assert.equal(result.id, '123');
    assert.equal(result.name, 'alice');
    assert.equal(Object.keys(result).length, 2);
  });

  it('remaps keys with map', () => {
    const result = remapKeys({ id: '123', firstName: 'alice' }, { firstName: 'first_name' });
    assert.equal(result.id, '123');
    assert.equal(result.first_name, 'alice');
    assert(!result.firstName);
  });

  it('passes through keys not in map', () => {
    const result = remapKeys({ id: '123', extra: 'value' }, { id: 'user_id' });
    assert.equal(result.user_id, '123');
    assert.equal(result.extra, 'value');
    assert(!result.id);
  });

  it('blocks __proto__ in input keys', () => {
    const result = remapKeys({ '__proto__': 'danger', id: '123' }, null);
    assert.equal(result.id, '123');
    assert(!result['__proto__']);
  });

  it('blocks constructor in input keys', () => {
    const result = remapKeys({ 'constructor': 'danger', id: '123' }, null);
    assert.equal(result.id, '123');
    assert(result.constructor !== 'danger');
  });

  it('blocks prototype in input keys', () => {
    const result = remapKeys({ 'prototype': 'danger', id: '123' }, null);
    assert.equal(result.id, '123');
    assert(result.prototype !== 'danger');
  });

  it('blocks __proto__ in output keys (mapped)', () => {
    const result = remapKeys({ id: '123' }, { id: '__proto__' });
    assert.equal(Object.keys(result).length, 0);
  });

  it('blocks constructor in output keys (mapped)', () => {
    const result = remapKeys({ id: '123' }, { id: 'constructor' });
    assert.equal(Object.keys(result).length, 0);
  });

  it('blocks prototype in output keys (mapped)', () => {
    const result = remapKeys({ id: '123' }, { id: 'prototype' });
    assert.equal(Object.keys(result).length, 0);
  });

  it('null input returns empty object', () => {
    const result = remapKeys(null, null);
    assert.equal(Object.keys(result).length, 0);
  });

  it('non-object input returns empty object', () => {
    const result = remapKeys('string', null);
    assert.equal(Object.keys(result).length, 0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// dispatchToolCall() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('dispatchToolCall', () => {
  it('GET with query params', async () => {
    const tool = { method: 'GET', path: '/users', queryMap: null };
    const args = { name: 'alice', limit: '10' };

    let capturedCall = null;
    const apiClient = async (method, path, body) => {
      capturedCall = { method, path, body };
      return { success: true };
    };

    const result = await dispatchToolCall(tool, args, apiClient);

    assert.equal(capturedCall.method, 'GET');
    assert.match(capturedCall.path, /^\/users\?/);
    assert.match(capturedCall.path, /name=alice/);
    assert.match(capturedCall.path, /limit=10/);
    assert.deepEqual(result, { success: true });
  });

  it('POST with body', async () => {
    const tool = { method: 'POST', path: '/users', bodyMap: null };
    const args = { name: 'alice', email: 'alice@example.com' };

    let capturedCall = null;
    const apiClient = async (method, path, body) => {
      capturedCall = { method, path, body };
      return { id: 1 };
    };

    const result = await dispatchToolCall(tool, args, apiClient);

    assert.equal(capturedCall.method, 'POST');
    assert.equal(capturedCall.path, '/users');
    assert.equal(capturedCall.body.name, 'alice');
    assert.equal(capturedCall.body.email, 'alice@example.com');
    assert.deepEqual(result, { id: 1 });
  });

  it('extracts path params and passes remaining as query for GET', async () => {
    const tool = { method: 'GET', path: '/users/:userId/posts/:postId', queryMap: null };
    const args = { userId: '42', postId: '100', limit: '5' };

    let capturedCall = null;
    const apiClient = async (method, path) => {
      capturedCall = { method, path };
      return { success: true };
    };

    await dispatchToolCall(tool, args, apiClient);

    assert.equal(capturedCall.path, '/users/42/posts/100?limit=5');
  });

  it('extracts path params and passes remaining as body for POST', async () => {
    const tool = { method: 'POST', path: '/users/:userId', bodyMap: null };
    const args = { userId: '42', email: 'new@example.com' };

    let capturedCall = null;
    const apiClient = async (method, path, body) => {
      capturedCall = { method, path, body };
      return { success: true };
    };

    await dispatchToolCall(tool, args, apiClient);

    assert.equal(capturedCall.path, '/users/42');
    assert.deepEqual(capturedCall.body.email, 'new@example.com');
    assert(capturedCall.body.userId === undefined);
  });

  it('queryMap renames query params', async () => {
    const tool = { method: 'GET', path: '/users', queryMap: { firstName: 'first_name' } };
    const args = { firstName: 'alice' };

    let capturedCall = null;
    const apiClient = async (method, path) => {
      capturedCall = { method, path };
      return { success: true };
    };

    await dispatchToolCall(tool, args, apiClient);

    assert.match(capturedCall.path, /first_name=alice/);
  });

  it('bodyMap renames body params', async () => {
    const tool = { method: 'POST', path: '/users', bodyMap: { firstName: 'first_name' } };
    const args = { firstName: 'alice' };

    let capturedCall = null;
    const apiClient = async (method, path, body) => {
      capturedCall = { method, path, body };
      return { success: true };
    };

    await dispatchToolCall(tool, args, apiClient);

    assert.equal(capturedCall.body.first_name, 'alice');
    assert(capturedCall.body.firstName === undefined);
  });

  it('HEAD routes to query params', async () => {
    const tool = { method: 'HEAD', path: '/users/:id', queryMap: null };
    const args = { id: '123', extra: 'value' };

    let capturedCall = null;
    const apiClient = async (method, path) => {
      capturedCall = { method, path };
      return { success: true };
    };

    await dispatchToolCall(tool, args, apiClient);

    assert.equal(capturedCall.method, 'HEAD');
    assert.match(capturedCall.path, /^\/users\/123\?/);
    assert.match(capturedCall.path, /extra=value/);
  });

  it('filters out null/undefined args', async () => {
    const tool = { method: 'POST', path: '/users', bodyMap: null };
    const args = { name: 'alice', skip: null, omit: undefined };

    let capturedCall = null;
    const apiClient = async (method, path, body) => {
      capturedCall = { method, path, body };
      return { success: true };
    };

    await dispatchToolCall(tool, args, apiClient);

    assert.equal(capturedCall.body.name, 'alice');
    assert(capturedCall.body.skip === undefined);
    assert(capturedCall.body.omit === undefined);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// toSnakeCase() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('toSnakeCase', () => {
  it('converts camelCase', () => {
    assert.equal(toSnakeCase('firstName'), 'first_name');
  });

  it('converts PascalCase', () => {
    assert.equal(toSnakeCase('FirstName'), 'first_name');
  });

  it('converts kebab-case', () => {
    assert.equal(toSnakeCase('first-name'), 'first_name');
  });

  it('handles dots', () => {
    assert.equal(toSnakeCase('first.name'), 'first_name');
  });

  it('handles spaces', () => {
    assert.equal(toSnakeCase('first name'), 'first_name');
  });

  it('handles consecutive caps (APIKey)', () => {
    assert.equal(toSnakeCase('APIKey'), 'api_key');
  });

  it('handles empty string', () => {
    assert.equal(toSnakeCase(''), '');
  });

  it('removes leading/trailing underscores', () => {
    assert.equal(toSnakeCase('_firstName_'), 'first_name');
  });

  it('collapses multiple underscores', () => {
    assert.equal(toSnakeCase('first__name'), 'first_name');
  });

  it('complex case conversion', () => {
    assert.equal(toSnakeCase('XMLHttpRequest'), 'xml_http_request');
  });
});
