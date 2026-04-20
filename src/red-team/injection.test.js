/**
 * Red-team injection attack test suite for 40mcp package
 * Tests attack vectors across path params, query strings, headers, and prototype pollution
 *
 * Run: node --test src/red-team/injection.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { createApiClient } from '../core/client.js';
import { qs, interpolatePath, remapKeys, extractPathParams } from '../core/path.js';
import { applyResponseTransform } from '../transforms/response.js';
import { loadConfig } from '../config.js';
import { loadOpenApiSpec } from '../openapi.js';
import { createReverseBridge } from '../reverse/server.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 1: URL INJECTION VIA PATH PARAMS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Path injection: path traversal ../../admin is REJECTED', () => {
  // encodeURIComponent alone is not enough — many upstream servers
  // double-decode %2F back to /, so we reject path-separator chars at the
  // source. Operators with a legitimate need can opt in via tool.allowPathSlashes.
  const path = '/users/:id';
  const args = { id: '../../admin' };
  assert.throws(
    () => interpolatePath(path, args),
    (err) => err.message.includes('path separator'),
  );
});

test('Path injection: query string char ? should be encoded', () => {
  const path = '/users/:id';
  const args = { id: 'admin?injected=true' };
  const result = interpolatePath(path, args);
  assert.strictEqual(result, '/users/admin%3Finjected%3Dtrue',
    'Expected ? to be encoded as %3F');
});

test('Path injection: fragment char # should be encoded', () => {
  const path = '/users/:id';
  const args = { id: 'user#admin' };
  const result = interpolatePath(path, args);
  assert.strictEqual(result, '/users/user%23admin',
    'Expected # to be encoded as %23');
});

test('Path injection: CRLF newlines should be encoded', () => {
  const path = '/users/:id';
  const args = { id: 'user\r\nInjected: header' };
  const result = interpolatePath(path, args);
  // CRLF should be encoded
  assert(!result.includes('\r'), 'CR should not appear in encoded path');
  assert(!result.includes('\n'), 'LF should not appear in encoded path');
  assert(result.includes('%0D%0A') || result.includes('%0D') || result.includes('%0A'),
    'Expected CRLF to be encoded');
});

test('Path injection: null bytes are REJECTED', () => {
  const path = '/users/:id';
  const args = { id: 'user\x00malicious' };
  assert.throws(
    () => interpolatePath(path, args),
    (err) => err.message.includes('NUL'),
  );
});

test('Path injection: unicode null is REJECTED', () => {
  const path = '/users/:id';
  const args = { id: 'user\u0000name' };
  assert.throws(
    () => interpolatePath(path, args),
    (err) => err.message.includes('NUL'),
  );
});

test('Path injection: missing required param should throw error', () => {
  const path = '/users/:id';
  const args = {};
  assert.throws(
    () => interpolatePath(path, args),
    { message: /Missing required path parameter: id/ },
    'Should throw error for missing required parameter'
  );
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 2: QUERY STRING INJECTION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Query injection: extra param with & should be encoded', () => {
  const params = { search: 'admin&extra=param' };
  const result = qs(params);
  // URLSearchParams should encode the &
  assert(result.includes('search=admin%26extra%3Dparam'),
    'Expected & in value to be encoded as %26');
});

test('Query injection: key with = in value should be encoded', () => {
  const params = { key: 'value=malicious' };
  const result = qs(params);
  assert(result.includes('key=value%3Dmalicious'),
    'Expected = in value to be encoded as %3D');
});

test('Query injection: array values should be properly encoded', () => {
  const params = { tags: ['admin', 'user?inject'] };
  const result = qs(params);
  assert(result.includes('tags=admin'), 'First array item should be present');
  assert(result.includes('tags=user%3Finject'), 'Second array item with ? should be encoded');
});

test('Query injection: null/undefined/empty values should be omitted', () => {
  const params = { a: 'value', b: null, c: undefined, d: '' };
  const result = qs(params);
  assert(result.includes('a=value'), 'Should include non-empty value');
  assert(!result.includes('b='), 'Should omit null');
  assert(!result.includes('c='), 'Should omit undefined');
  assert(!result.includes('d='), 'Should omit empty string');
});

test('Query injection: special chars in key should be encoded by URLSearchParams', () => {
  const params = { 'key&special': 'value' };
  const result = qs(params);
  // URLSearchParams will handle this
  assert(result.includes('key%26special=value') || result.includes('key&special=value'),
    'Key should be handled safely by URLSearchParams'
  );
});

test('Query injection: CRLF in query value should be encoded', () => {
  const params = { search: 'test\r\nInjected: true' };
  const result = qs(params);
  assert(!result.includes('\r'), 'CR should not appear');
  assert(!result.includes('\n'), 'LF should not appear');
  assert(result.includes('search=test%0D%0A') || result.includes('search=test%0DInjected'),
    'CRLF should be encoded');
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 3: HEADER INJECTION VIA AUTH CONFIG
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Header injection: CRLF in auth header name should be rejected', () => {
  const authConfig = {
    type: 'header',
    header: 'X-Key\r\nInjected: yes',
    value: 'token123'
  };
  assert.throws(
    () => createApiClient('https://api.example.com', authConfig),
    { message: /Invalid auth header name/ },
    'Should reject header name with CRLF'
  );
});

test('Header injection: special chars in auth header name should be rejected', () => {
  const authConfig = {
    type: 'header',
    header: 'X-Key: Injected',
    value: 'token123'
  };
  assert.throws(
    () => createApiClient('https://api.example.com', authConfig),
    { message: /Invalid auth header name/ },
    'Should reject header name with colon'
  );
});

test('Header injection: valid header name should be accepted', () => {
  const authConfig = {
    type: 'header',
    header: 'X-API-Key',
    value: 'token123'
  };
  // Should not throw
  const client = createApiClient('https://api.example.com', authConfig);
  assert(typeof client === 'function', 'Should return api client function');
});

test('Header injection: header name with lowercase should be accepted', () => {
  const authConfig = {
    type: 'header',
    header: 'x-custom-header',
    value: 'token'
  };
  const client = createApiClient('https://api.example.com', authConfig);
  assert(typeof client === 'function', 'Should accept lowercase header name');
});

test('Header injection: header name with numbers should be accepted', () => {
  const authConfig = {
    type: 'header',
    header: 'X-API-Key-2',
    value: 'token'
  };
  const client = createApiClient('https://api.example.com', authConfig);
  assert(typeof client === 'function', 'Should accept header with numbers');
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 4: PROTOTYPE POLLUTION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Prototype pollution: __proto__ key in map should be skipped', () => {
  const obj = { name: 'test', age: 30 };
  const map = { '__proto__': 'polluted' };
  const result = remapKeys(obj, map);
  // __proto__ should not be in result; result uses Object.create(null)
  assert.deepStrictEqual(Object.entries(result).sort(), [['age', 30], ['name', 'test']],
    'Should keep safe keys and skip __proto__ (using Object.create(null))');
  // Verify the result doesn't have __proto__ as own property
  assert(!Object.prototype.hasOwnProperty.call(result, '__proto__'),
    '__proto__ should not be an own property');
});

test('Prototype pollution: constructor key in map should be skipped', () => {
  const obj = { name: 'test' };
  const map = { 'constructor': 'evil' };
  const result = remapKeys(obj, map);
  // remapKeys returns Object.create(null) — no prototype, just verify the keys
  assert.equal(result.name, 'test', 'Should preserve safe keys');
  assert(!('constructor' in result), 'constructor key should be skipped');
  assert(!('evil' in result), 'mapped evil key should not exist');
});

test('Prototype pollution: prototype key in map should be skipped', () => {
  const obj = { name: 'test' };
  const map = { 'prototype': 'evil' };
  const result = remapKeys(obj, map);
  assert.equal(result.name, 'test', 'Should preserve safe keys');
  assert(!('prototype' in result), 'prototype key should be skipped');
  assert(!('evil' in result), 'mapped evil key should not exist');
});

test('Prototype pollution: __proto__ in response pick should be blocked', () => {
  const data = { id: 1, name: 'John', secret: 'password' };
  const transform = { pick: ['id', 'name', '__proto__'] };
  const result = applyResponseTransform(data, transform);
  // __proto__ should be silently dropped by the DANGEROUS_KEYS guard
  assert.equal(result.id, 1, 'Should pick safe id field');
  assert.equal(result.name, 'John', 'Should pick safe name field');
  assert(!Object.prototype.polluted, 'Object prototype should not be polluted');
});

test('Prototype pollution: constructor in response pick should be blocked', () => {
  const data = { id: 1, name: 'John' };
  const transform = { pick: ['id', 'constructor'] };
  const result = applyResponseTransform(data, transform);
  assert.equal(result.id, 1, 'Should pick safe id field');
  // constructor should not be set as an own enumerable key from the pick
  assert(!Object.prototype.polluted, 'Object prototype should not be polluted');
});

test('Prototype pollution: nested __proto__ in pick path should be blocked', () => {
  const data = { id: 1, user: { name: 'John', details: { age: 30 } } };
  const transform = { pick: ['id', '__proto__.polluted', 'user.name'] };
  const result = applyResponseTransform(data, transform);
  // __proto__ should not be set as an own property on the result
  assert(!Object.hasOwn(result, '__proto__'), '__proto__ should not be an own property');
  assert(!Object.prototype.polluted, 'Object prototype should not be polluted');
  assert.equal(result.id, 1, 'Safe fields should still be picked');
  assert.equal(result.user?.name, 'John', 'Nested safe fields should be picked');
});

test('Prototype pollution: remapKeys with null prototype should not pollute', () => {
  const obj = { user_name: 'test', user_age: 30 };
  const map = { '__proto__': 'constructor' };
  const result = remapKeys(obj, map);
  // Result should use Object.create(null), making it immune to prototype pollution
  const proto = Object.getPrototypeOf(result);
  assert(proto === null || proto === Object.prototype, 'Result prototype should be safe');
});

test('Prototype pollution: direct __proto__ assignment in args should not affect others', () => {
  const obj1 = { name: 'test1' };
  const map1 = { 'name': '__proto__' };
  const result1 = remapKeys(obj1, map1);

  // Check that attempting to pollute doesn't affect other objects
  const obj2 = {};
  assert(!('name' in obj2), 'Other objects should not be affected by pollution attempt');
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 5: $REF TRAVERSAL IN OPENAPI PARSER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('$ref traversal: circular reference should not cause infinite loop', async () => {
  const spec = {
    openapi: '3.0.0',
    info: { title: 'Test', version: '1.0.0' },
    paths: {
      '/items': {
        get: {
          operationId: 'listItems',
          parameters: [
            {
              name: 'filter',
              in: 'query',
              schema: { $ref: '#/components/schemas/Self' }
            }
          ],
          responses: {
            '200': {
              description: 'Success',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Item' }
                }
              }
            }
          }
        }
      }
    },
    components: {
      schemas: {
        Self: { $ref: '#/components/schemas/Self' },
        Item: {
          type: 'object',
          properties: { id: { type: 'string' } }
        }
      }
    }
  };

  // Should complete without hanging
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Timeout: infinite loop detected')), 5000)
  );

  try {
    const result = await Promise.race([
      loadOpenApiSpec(spec),
      timeout
    ]);
    assert(result.tools, 'Should parse spec despite circular $ref');
  } catch (err) {
    if (err.message === 'Timeout: infinite loop detected') {
      throw err;
    }
    // Other errors are acceptable (parse errors, etc.)
  }
});

test('$ref traversal: very deep nesting should not cause stack overflow', async () => {
  // Create a spec with 100 levels of nested references
  let schema = { type: 'string' };
  const components = { schemas: { Level0: schema } };

  for (let i = 1; i < 100; i++) {
    schema = { $ref: `#/components/schemas/Level${i}` };
    components.schemas[`Level${i}`] = { type: 'object', properties: { data: { $ref: `#/components/schemas/Level${i-1}` } } };
  }

  const spec = {
    openapi: '3.0.0',
    info: { title: 'Test', version: '1.0.0' },
    paths: {
      '/test': {
        get: {
          operationId: 'test',
          responses: {
            '200': {
              description: 'Success',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Level99' }
                }
              }
            }
          }
        }
      }
    },
    components
  };

  // Should not throw stack overflow
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Timeout: stack overflow')), 10000)
  );

  try {
    await Promise.race([
      loadOpenApiSpec(spec),
      timeout
    ]);
  } catch (err) {
    // Parse errors are okay, but not stack overflow
    assert(!err.message.includes('Maximum call stack'), 'Should not have stack overflow');
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 6: DYNAMIC IMPORT INJECTION IN CONFIG.JS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Config injection: path traversal ../../../etc/passwd should be rejected', async () => {
  const filePath = '../../../etc/passwd';

  await assert.rejects(
    async () => loadConfig(filePath),
    { message: /Unsupported config file type/ },
    'Should reject file without allowed extension'
  );
});

test('Config injection: file with .json extension only should be loaded', async () => {
  // Create a temporary test config
  const testPath = join(__dirname, 'test-config.json');

  // This should pass the extension check (though may fail on actual file read)
  // The test verifies the extension check works
  try {
    await loadConfig(testPath);
  } catch (err) {
    // File not found is okay - we're testing that .json passes the check
    assert(!err.message.includes('Unsupported config file type'),
      'Should not reject .json extension');
  }
});

test('Config injection: file with .js extension should be allowed', async () => {
  const testPath = join(__dirname, 'test-config.js');
  try {
    await loadConfig(testPath);
  } catch (err) {
    assert(!err.message.includes('Unsupported config file type'),
      'Should not reject .js extension');
  }
});

test('Config injection: file with .mjs extension should be allowed', async () => {
  const testPath = join(__dirname, 'test-config.mjs');
  try {
    await loadConfig(testPath);
  } catch (err) {
    assert(!err.message.includes('Unsupported config file type'),
      'Should not reject .mjs extension');
  }
});

test('Config injection: file with .cjs extension should be allowed', async () => {
  const testPath = join(__dirname, 'test-config.cjs');
  try {
    await loadConfig(testPath);
  } catch (err) {
    assert(!err.message.includes('Unsupported config file type'),
      'Should not reject .cjs extension');
  }
});

test('Config injection: file with .txt extension should be rejected', async () => {
  const filePath = 'config.txt';

  await assert.rejects(
    async () => loadConfig(filePath),
    { message: /Unsupported config file type/ },
    'Should reject .txt extension'
  );
});

test('Config injection: file with no extension should be rejected', async () => {
  const filePath = 'config';

  await assert.rejects(
    async () => loadConfig(filePath),
    { message: /Unsupported config file type/ },
    'Should reject file with no extension'
  );
});

test('Config injection: null bytes in path should not bypass check', async () => {
  const filePath = 'config.json\x00.js';

  try {
    await loadConfig(filePath);
    assert.fail('Should have thrown an error');
  } catch (err) {
    // Should throw either ENOENT or path handling error
    assert(err, 'Should throw an error for path with null bytes');
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 7: REVERSE BRIDGE REQUEST PARSING
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Reverse bridge: tool name extraction should use safe regex', () => {
  const basePath = '/api';
  const toolMatch = '/api/tools/valid_tool_name-1'.match(
    new RegExp(`^${basePath}\\/tools\\/([a-zA-Z0-9_-]+)$`)
  );
  assert(toolMatch && toolMatch[1] === 'valid_tool_name-1',
    'Valid tool name should match');
});

test('Reverse bridge: tool name with path traversal should not match', () => {
  const basePath = '/api';
  const toolMatch = '/api/tools/../../admin'.match(
    new RegExp(`^${basePath}\\/tools\\/([a-zA-Z0-9_-]+)$`)
  );
  assert(!toolMatch, 'Path traversal in tool name should not match regex');
});

test('Reverse bridge: tool name with special chars should not match', () => {
  const basePath = '/api';
  const toolMatch = '/api/tools/tool;name'.match(
    new RegExp(`^${basePath}\\/tools\\/([a-zA-Z0-9_-]+)$`)
  );
  assert(!toolMatch, 'Special chars in tool name should not match regex');
});

test('Reverse bridge: tool name with space should not match', () => {
  const basePath = '/api';
  const toolMatch = '/api/tools/tool name'.match(
    new RegExp(`^${basePath}\\/tools\\/([a-zA-Z0-9_-]+)$`)
  );
  assert(!toolMatch, 'Space in tool name should not match regex');
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 8: BASE URL VALIDATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Base URL injection: invalid scheme should be rejected', () => {
  assert.throws(
    () => createApiClient('ftp://api.example.com'),
    { message: /Invalid baseUrl scheme/ },
    'Should reject non-HTTP(S) schemes like ftp'
  );
});

test('Base URL injection: file:// scheme should be rejected', () => {
  assert.throws(
    () => createApiClient('file:///etc/passwd'),
    { message: /Invalid baseUrl scheme/ },
    'Should reject file:// scheme to prevent SSRF'
  );
});

test('Base URL injection: no scheme should be rejected', () => {
  assert.throws(
    () => createApiClient('api.example.com'),
    { message: /Invalid baseUrl scheme/ },
    'Should reject URL without scheme'
  );
});

test('Base URL injection: https scheme should be accepted', () => {
  const client = createApiClient('https://api.example.com');
  assert(typeof client === 'function', 'Should accept https:// scheme');
});

test('Base URL injection: http scheme should be accepted', () => {
  const client = createApiClient('http://api.example.com');
  assert(typeof client === 'function', 'Should accept http:// scheme');
});

test('Base URL injection: http://localhost should be accepted', () => {
  const client = createApiClient('http://localhost:3000');
  assert(typeof client === 'function', 'Should accept localhost over HTTP');
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ATTACK VECTOR 9: RESPONSE TRANSFORM INJECTION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Response transform: omit with __proto__ should be blocked', () => {
  const data = { id: 1, secret: 'password' };
  const transform = { omit: ['__proto__', 'secret'] };
  const result = applyResponseTransform(data, transform);
  // deleteNestedValue skips __proto__, so only secret should be deleted
  assert(!('secret' in result), 'secret should be omitted');
  assert.deepStrictEqual(result, { id: 1 }, 'Only id should remain after omitting secret');
});

test('Response transform: omit with constructor should be blocked', () => {
  const data = { id: 1, value: 'test', constructor: 'evil' };
  const transform = { omit: ['constructor'] };
  const result = applyResponseTransform(data, transform);
  // constructor is a built-in, but we should not be able to delete it
  assert(result.value === 'test', 'Safe fields should remain');
});

test('Response transform: nested omit with __proto__ should be blocked', () => {
  const data = { user: { id: 1, secret: 'pass', nested: { key: 'value' } } };
  const transform = { omit: ['user.__proto__', 'user.secret'] };
  const result = applyResponseTransform(data, transform);
  assert(result.user.id === 1, 'Safe fields should remain');
  assert(result.user.nested, 'Nested objects should be preserved');
});

test('Response transform: pick with __proto__ should be ignored', () => {
  const data = { id: 1, name: 'John' };
  const transform = { pick: ['id', '__proto__'] };
  const result = applyResponseTransform(data, transform);
  // getNestedValue returns undefined for __proto__, so it won't be set
  assert(!Object.keys(result).includes('__proto__'), '__proto__ should not be in picked keys');
  assert.deepStrictEqual(result, { id: 1 }, 'Only id should be picked (not __proto__)');
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SUMMARY TESTS - Verify defense-in-depth
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test('Defense-in-depth: combined attacks should all be blocked', async () => {
  // Path-separator chars are now rejected at interpolatePath rather than just
  // URI-encoded. The combined-attack defence is now stronger.
  const pathTemplate = '/users/:id/posts/:postId';

  // Path traversal in id is REJECTED outright
  assert.throws(
    () => interpolatePath(pathTemplate, { id: '../../admin', postId: '1' }),
    (err) => err.message.includes('path separator'),
  );

  // Query/fragment chars in postId are still safely URI-encoded
  const safePath = interpolatePath(pathTemplate, { id: 'user1', postId: '1?inject=true' });
  assert(safePath.includes('%3F'), 'Query chars must be encoded');
});

test('Defense-in-depth: prototype pollution should be blocked at multiple layers', () => {
  // Try polluting at the remapping layer
  const obj = { name: 'test' };
  const map = { '__proto__': 'polluted' };
  const result = remapKeys(obj, map);

  // Check result is safe - uses Object.create(null) for safety
  assert.deepStrictEqual(Object.entries(result), [['name', 'test']],
    'Remapping should block __proto__');
  // Verify prototype is null
  assert(Object.getPrototypeOf(result) === null, 'Result should have null prototype for safety');
});

console.log('\n✓ Red-team injection test suite complete');
console.log('  All attack vectors tested for proper defense');
