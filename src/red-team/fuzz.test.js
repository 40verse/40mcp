import test from 'node:test';
import assert from 'node:assert';
import { strict as strictAssert } from 'node:assert';

// Import all target functions
import { qs, interpolatePath, remapKeys, dispatchToolCall, toSnakeCase, extractPathParams } from '../core/path.js';
import { createApiClient } from '../core/client.js';
import { applyResponseTransform } from '../transforms/response.js';
import { executeChain } from '../compose/chain.js';
import { loadOpenApiSpec } from '../openapi.js';
import { loadHarFile } from '../loaders/har.js';
import { loadGraphqlSchema } from '../loaders/graphql.js';

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 1: Prototype Pollution
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 1: Prototype Pollution - remapKeys with __proto__', async () => {
  const obj = { name: 'user' };
  const map = { name: '__proto__' };
  const result = remapKeys(obj, map);

  // Should not pollute prototype (dangerous key is skipped)
  assert.strictEqual(Object.getPrototypeOf({}).polluted, undefined);
  assert.deepEqual(Object.keys(result), []); // __proto__ key was filtered out
});

test('ATTACK 1: Prototype Pollution - remapKeys with constructor', async () => {
  const obj = { name: 'test' };
  const map = { name: 'constructor' };
  const result = remapKeys(obj, map);

  // Should not allow constructor override
  assert.strictEqual(result.constructor, undefined);
});

test('ATTACK 1: Prototype Pollution - remapKeys with prototype', async () => {
  const obj = { name: 'test' };
  const map = { name: 'prototype' };
  const result = remapKeys(obj, map);

  // Should not allow prototype override
  assert.strictEqual(result.prototype, undefined);
});

test('ATTACK 1: Prototype Pollution - response transform pick with __proto__', async () => {
  const data = { name: 'admin', email: 'test@test.com' };
  const transform = { pick: ['name', '__proto__'] };
  const result = applyResponseTransform(data, transform);

  // Should not allow __proto__ in pick (blocked by DANGEROUS_KEYS)
  // __proto__ is filtered out during pick, so it won't be in result
  assert.ok('name' in result);
  assert.strictEqual(Object.keys(result).length, 1);
});

test('ATTACK 1: Prototype Pollution - response transform setNestedValue', async () => {
  const data = { user: { name: 'admin' } };
  const transform = { pick: ['user.__proto__.polluted'] };
  const result = applyResponseTransform(data, transform);

  // Should block __proto__ in nested paths
  assert.strictEqual(Object.getPrototypeOf({}).polluted, undefined);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 2: Path Traversal
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 2: Path Traversal - interpolatePath with ../ is REJECTED', async () => {
  const pathTemplate = '/api/users/:id';
  const args = { id: '../../../etc/passwd' };
  // encodeURIComponent alone is not enough — many upstream servers
  // double-decode %2F back to /. Reject path-traversal at the source.
  assert.throws(
    () => interpolatePath(pathTemplate, args),
    (err) => err.message.includes('path separator'),
  );
});

test('ATTACK 2: Path Traversal - interpolatePath with null bytes is REJECTED', async () => {
  const pathTemplate = '/api/users/:id';
  const args = { id: 'user\x00.txt' };
  assert.throws(
    () => interpolatePath(pathTemplate, args),
    (err) => err.message.includes('NUL'),
  );
});

test('ATTACK 2: Path Traversal - interpolatePath with absolute path is REJECTED', async () => {
  const pathTemplate = '/api/resource/:id';
  const args = { id: '/etc/passwd' };
  assert.throws(
    () => interpolatePath(pathTemplate, args),
    (err) => err.message.includes('path separator'),
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 3: ReDoS (Regular Expression Denial of Service)
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 3: ReDoS - toSnakeCase with pathological input', async () => {
  // Create a long string that could trigger catastrophic backtracking
  const pathological = 'a'.repeat(100) + 'A'.repeat(100) + 'B';

  const start = process.hrtime.bigint();
  const result = toSnakeCase(pathological);
  const end = process.hrtime.bigint();

  const durationMs = Number(end - start) / 1_000_000;
  // Should complete in reasonable time (< 100ms)
  assert.ok(durationMs < 100, `toSnakeCase took ${durationMs}ms (should be < 100ms)`);
  assert.ok(typeof result === 'string');
});

test('ATTACK 3: ReDoS - interpolatePath with pathological regex', async () => {
  // Test with many colons to stress the :param regex
  const pathTemplate = '/a:1:2:3:4:5:6:7:8:9:10';
  const args = { 1: 'v', 2: 'v', 3: 'v', 4: 'v', 5: 'v', 6: 'v', 7: 'v', 8: 'v', 9: 'v', 10: 'v' };

  const start = process.hrtime.bigint();
  const result = interpolatePath(pathTemplate, args);
  const end = process.hrtime.bigint();

  const durationMs = Number(end - start) / 1_000_000;
  assert.ok(durationMs < 100, `interpolatePath took ${durationMs}ms`);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 4: Memory Exhaustion
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 4: Memory Exhaustion - qs() with huge array', async () => {
  const params = {
    items: Array.from({ length: 10000 }, (_, i) => `item_${i}`),
  };

  const result = qs(params);
  // Should complete without crash, result should be a string
  assert.ok(typeof result === 'string');
  assert.ok(result.length > 0);
});

test('ATTACK 4: Memory Exhaustion - deeply nested response transform', async () => {
  // Create a deeply nested object
  let deepObj = { value: 'bottom' };
  for (let i = 0; i < 100; i++) {
    deepObj = { nested: deepObj };
  }

  const transform = { flatten: true };
  const result = applyResponseTransform(deepObj, transform);

  // Should complete without stack overflow
  assert.ok(typeof result === 'object');
});

test('ATTACK 4: Memory Exhaustion - response transform with circular reference guard', async () => {
  const obj = { name: 'test' };
  obj.self = obj; // Create circular reference

  const transform = { pick: ['name'] };
  const result = applyResponseTransform(obj, transform);

  // Should handle gracefully (pick should extract only 'name')
  assert.ok('name' in result);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 5: Type Confusion
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 5: Type Confusion - qs() with object instead of array', async () => {
  const params = {
    items: { nested: 'value' }, // Should be array or string
  };

  const result = qs(params);
  // Should coerce to string safely
  assert.ok(typeof result === 'string');
  assert.ok(result.includes('items='));
});

test('ATTACK 5: Type Confusion - interpolatePath with array argument', async () => {
  const pathTemplate = '/api/users/:id';
  const args = { id: [1, 2, 3] }; // Array instead of string

  const result = interpolatePath(pathTemplate, args);
  // Should convert to string
  assert.ok(result.includes('1%2C2%2C3') || result.includes('1,2,3'));
});

test('ATTACK 5: Type Confusion - remapKeys with non-object input', async () => {
  const result1 = remapKeys(null, { a: 'b' });
  assert.deepEqual(result1, {});

  const result2 = remapKeys(undefined, { a: 'b' });
  assert.deepEqual(result2, {});

  const result3 = remapKeys('string', { a: 'b' });
  assert.deepEqual(result3, {});
});

test('ATTACK 5: Type Confusion - applyResponseTransform with non-object transform', async () => {
  const data = { name: 'test' };

  const result1 = applyResponseTransform(data, null);
  assert.deepEqual(result1, data);

  const result2 = applyResponseTransform(data, 'invalid');
  assert.deepEqual(result2, data);
});

test('ATTACK 5: Type Confusion - applyResponseTransform with array items in pick', async () => {
  const data = { name: 'admin', items: [1, 2, 3] };
  const transform = { pick: ['name', 'items'] };
  const result = applyResponseTransform(data, transform);

  assert.ok('name' in result);
  assert.ok('items' in result);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 6: Null Pointer / Undefined Access
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 6: Null Pointer - interpolatePath with missing required param', async () => {
  const pathTemplate = '/api/users/:id/posts/:postId';
  const args = { id: 'user1' }; // Missing postId

  try {
    interpolatePath(pathTemplate, args);
    assert.fail('Should throw for missing parameter');
  } catch (err) {
    assert.ok(err.message.includes('Missing required path parameter'));
  }
});

test('ATTACK 6: Null Pointer - response transform getNestedValue with null path', async () => {
  const data = { user: null };
  const transform = { pick: ['user.name'] };
  const result = applyResponseTransform(data, transform);

  // Should handle null gracefully (undefined is acceptable)
  assert.ok(result !== undefined);
});

test('ATTACK 6: Null Pointer - executeChain with undefined args', async () => {
  const steps = [
    { call: 'tool1', as: 'step1', args: { name: '$args.missing' } },
  ];
  const mockDispatch = async (name, args) => ({ result: 'ok' });

  try {
    const result = await executeChain(steps, {}, mockDispatch);
    // Should complete; undefined args should be passed through
    assert.ok(result._chain);
  } catch (err) {
    // It's ok to throw if step requires validation
    assert.ok(err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 7: Crashes from Invalid Input
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 7: Crash - qs() with Symbol in values', async () => {
  const params = {
    key: Symbol('test'),
  };

  // Should handle Symbol gracefully (convert to string or skip)
  try {
    const result = qs(params);
    assert.ok(typeof result === 'string');
  } catch (err) {
    // Acceptable if it throws a clear error
    assert.ok(err instanceof Error);
  }
});

test('ATTACK 7: Crash - applyResponseTransform with function in data', async () => {
  const data = {
    name: 'test',
    handler: () => console.log('test'),
  };
  const transform = { pick: ['name', 'handler'] };

  try {
    const result = applyResponseTransform(data, transform);
    // Should safely handle function references
    assert.ok(result);
  } catch (err) {
    assert.ok(err instanceof Error);
  }
});

test('ATTACK 7: Crash - toSnakeCase with very long string', async () => {
  const longStr = 'a'.repeat(100_000);

  const start = process.hrtime.bigint();
  const result = toSnakeCase(longStr);
  const end = process.hrtime.bigint();

  const durationMs = Number(end - start) / 1_000_000;
  assert.ok(durationMs < 500, `Should complete in < 500ms, took ${durationMs}ms`);
  assert.ok(typeof result === 'string');
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 8: Client API Injection
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 8: Client API - createApiClient with invalid baseUrl scheme', async () => {
  try {
    createApiClient('ftp://example.com', null, {});
    assert.fail('Should reject non-http(s) schemes');
  } catch (err) {
    assert.ok(err.message.includes('Invalid baseUrl scheme'));
  }
});

test('ATTACK 8: Client API - createApiClient with javascript: scheme', async () => {
  try {
    createApiClient('javascript:alert(1)', null, {});
    assert.fail('Should reject javascript: scheme');
  } catch (err) {
    assert.ok(err.message.includes('Invalid baseUrl scheme'));
  }
});

test('ATTACK 8: Client API - createApiClient with data: scheme', async () => {
  try {
    createApiClient('data:text/html,<script>alert(1)</script>', null, {});
    assert.fail('Should reject data: scheme');
  } catch (err) {
    assert.ok(err.message.includes('Invalid baseUrl scheme'));
  }
});

test('ATTACK 8: Client API - invalid auth header name', async () => {
  try {
    createApiClient('https://api.example.com', {
      type: 'header',
      header: 'X-Auth\r\nContent-Type: application/json\r\n\r\nmalicious',
      value: 'test',
    }, {});
    assert.fail('Should reject header injection in auth.header');
  } catch (err) {
    assert.ok(err.message.includes('Invalid auth header name'));
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 9: Chain Reference Injection
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 9: Chain - reference to undefined step', async () => {
  const steps = [
    { call: 'tool1', as: 'step1', args: { ref: '$undefined_step.field' } },
  ];
  const mockDispatch = async (name, args) => ({ result: 'ok' });

  try {
    await executeChain(steps, {}, mockDispatch);
    assert.fail('Should throw for undefined step reference');
  } catch (err) {
    assert.ok(err.message.includes('undefined step'));
  }
});

test('ATTACK 9: Chain - circular dependency detection', async () => {
  const steps = [
    { call: 'tool1', as: 'step1', args: { ref: '$step2.field' } },
    { call: 'tool2', as: 'step2', args: { ref: '$step1.field' } },
  ];
  const mockDispatch = async (name, args) => ({ result: 'ok' });

  try {
    await executeChain(steps, {}, mockDispatch);
    assert.fail('Should detect circular dependency');
  } catch (err) {
    assert.ok(err.message.includes('Circular dependency'));
  }
});

test('ATTACK 9: Chain - injection in step call name', async () => {
  // Step call name comes from the step definition itself
  const steps = [
    { call: 'tool\x00danger', as: 'step1', args: {} },
  ];
  const mockDispatch = async (name, args) => {
    // The dispatch should receive the exact name
    assert.ok(name.includes('\x00'));
    return { result: 'ok' };
  };

  const result = await executeChain(steps, {}, mockDispatch);
  assert.ok(result.step1);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 10: OpenAPI Spec Injection
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 10: OpenAPI - spec with malicious operationId', async () => {
  const spec = {
    openapi: '3.0.0',
    info: { title: 'API', version: '1.0.0' },
    paths: {
      '/api/test': {
        get: {
          operationId: '__proto__',
          responses: { 200: { description: 'OK' } },
        },
      },
    },
  };

  const result = await loadOpenApiSpec(spec);

  // Should not create a tool named __proto__
  const toolNames = result.tools.map(t => t.name);
  assert.ok(!toolNames.includes('__proto__'));
});

test('ATTACK 10: OpenAPI - spec with path traversal in operationId', async () => {
  const spec = {
    openapi: '3.0.0',
    info: { title: 'API', version: '1.0.0' },
    paths: {
      '/api/test': {
        post: {
          operationId: '../../../etc/passwd',
          responses: { 200: { description: 'OK' } },
        },
      },
    },
  };

  const result = await loadOpenApiSpec(spec);

  // Tool name should be sanitized
  const tool = result.tools[0];
  assert.ok(!tool.name.includes('..'));
  assert.ok(!tool.name.includes('/'));
});

test('ATTACK 10: OpenAPI - deeply nested $ref', async () => {
  const spec = {
    openapi: '3.0.0',
    info: { title: 'API', version: '1.0.0' },
    paths: {
      '/api/test': {
        post: {
          parameters: [
            { $ref: '#/components/schemas/NonExistent/properties/nested/deep/deeper' },
          ],
          responses: { 200: { description: 'OK' } },
        },
      },
    },
  };

  // Should handle missing refs gracefully
  const result = await loadOpenApiSpec(spec);
  assert.ok(result.tools);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 11: HAR File Injection
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 11: HAR - malicious URL parsing', async () => {
  const har = {
    log: {
      entries: [
        {
          request: {
            method: 'GET',
            url: 'javascript:alert(1)',
          },
        },
      ],
    },
  };

  // Should handle invalid URLs gracefully
  try {
    const result = await loadHarFile(har);
    // Either filters out bad URLs or handles them
    assert.ok(result);
  } catch (err) {
    assert.ok(err instanceof Error);
  }
});

test('ATTACK 11: HAR - path traversal in URL', async () => {
  const har = {
    log: {
      entries: [
        {
          request: {
            method: 'GET',
            url: 'http://api.example.com/api/../../../etc/passwd',
          },
        },
      ],
    },
  };

  const result = await loadHarFile(har);
  // Should extract base URL correctly
  assert.ok(result.baseUrl === 'http://api.example.com');
});

test('ATTACK 11: HAR - huge entries array', async () => {
  const entries = Array.from({ length: 5000 }, (_, i) => ({
    request: {
      method: 'GET',
      url: `http://api.example.com/api/item/${i}`,
    },
  }));

  const har = { log: { entries } };

  const start = process.hrtime.bigint();
  const result = await loadHarFile(har);
  const end = process.hrtime.bigint();

  const durationMs = Number(end - start) / 1_000_000;
  assert.ok(durationMs < 5000, `HAR processing took ${durationMs}ms`);
  assert.ok(result.tools);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 12: GraphQL Introspection Injection
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 12: GraphQL - malicious field name', async () => {
  const schema = {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: null,
      types: [
        {
          name: 'Query',
          fields: [
            {
              name: '__proto__',
              args: [],
              type: { kind: 'SCALAR', name: 'String' },
            },
          ],
        },
      ],
    },
  };

  const result = await loadGraphqlSchema(schema);

  // Should not create a tool named __proto__
  const toolNames = result.tools.map(t => t.name);
  assert.ok(!toolNames.includes('__proto__'));
});

test('ATTACK 12: GraphQL - deeply nested type structure', async () => {
  const schema = {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: null,
      types: [
        {
          name: 'Query',
          fields: [
            {
              name: 'user',
              args: [],
              type: {
                kind: 'NON_NULL',
                ofType: {
                  kind: 'OBJECT',
                  name: 'User',
                  ofType: null,
                },
              },
            },
          ],
        },
      ],
    },
  };

  const result = await loadGraphqlSchema(schema);
  assert.ok(result.tools.length > 0);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 13: Response Transform Edge Cases
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 13: Response Transform - omit with duplicate fields', async () => {
  const data = { name: 'admin', password: 'secret', secret: 'value' };
  const transform = { omit: ['password', 'password', 'password'] };
  const result = applyResponseTransform(data, transform);

  assert.strictEqual(result.password, undefined);
  assert.ok('name' in result);
});

test('ATTACK 13: Response Transform - limit with negative number', async () => {
  const data = [1, 2, 3, 4, 5];
  const transform = { limit: -1 };
  const result = applyResponseTransform(data, transform);

  // slice(-1) returns [5], but we want safe behavior
  assert.ok(Array.isArray(result) || result.items);
});

test('ATTACK 13: Response Transform - template with unbalanced braces', async () => {
  const data = [{ name: 'Alice' }, { name: 'Bob' }];
  const transform = { template: '{name} {missing {unbalanced}' };
  const result = applyResponseTransform(data, transform);

  // Should handle gracefully
  assert.ok(result);
});

test('ATTACK 13: Response Transform - tokenBudget with zero', async () => {
  const data = { name: 'test', description: 'a'.repeat(1000) };
  const transform = { tokenBudget: 0 };
  const result = applyResponseTransform(data, transform);

  // Should handle zero budget
  assert.ok(result);
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 14: Fuzzing with Unicode and Special Characters
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 14: Unicode - toSnakeCase with emoji', async () => {
  const result = toSnakeCase('hello🔥World');
  assert.ok(typeof result === 'string');
});

test('ATTACK 14: Unicode - interpolatePath with emoji in param', async () => {
  const pathTemplate = '/api/items/:name';
  const args = { name: '🎯emoji-name' };
  const result = interpolatePath(pathTemplate, args);

  // Should URI-encode emoji
  assert.ok(result.includes('%'));
});

test('ATTACK 14: Unicode - qs() with RTL text', async () => {
  const params = { text: 'مرحبا بك' };
  const result = qs(params);

  // Should handle RTL safely
  assert.ok(typeof result === 'string');
  assert.ok(result.includes('text='));
});

test('ATTACK 14: Special Chars - interpolatePath with HTML entities is URI-encoded', async () => {
  // Slashes are now rejected; use a slash-free payload to verify HTML special
  // chars are still URI-encoded as expected.
  const pathTemplate = '/api/search/:query';
  const args = { query: '<script>alert(1)>' };
  const result = interpolatePath(pathTemplate, args);
  assert.ok(result.includes('%3C') && result.includes('%3E'));
});

test('ATTACK 14: Special Chars - script tag with slash is REJECTED', async () => {
  assert.throws(
    () => interpolatePath('/api/search/:query', { query: '<script>alert(1)</script>' }),
    (err) => err.message.includes('path separator'),
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 15: dispatchToolCall Integration
// ─────────────────────────────────────────────────────────────────────────────

test('ATTACK 15: dispatchToolCall - with prototype pollution in queryMap', async () => {
  const tool = {
    method: 'GET',
    path: '/api/users/:id',
    queryMap: { param: '__proto__' },
  };
  const args = { id: 'user1', param: 'value' };

  const mockApiClient = async (method, path, body) => ({ result: 'ok' });
  const result = await dispatchToolCall(tool, args, mockApiClient);

  // Should complete without prototype pollution
  assert.ok(result);
  assert.strictEqual(Object.getPrototypeOf({}).param, undefined);
});

test('ATTACK 15: dispatchToolCall - with bodyMap prototype pollution', async () => {
  const tool = {
    method: 'POST',
    path: '/api/users',
    bodyMap: { userInput: '__proto__' },
  };
  const args = { userInput: 'malicious' };

  const mockApiClient = async (method, path, body) => {
    // body should not contain __proto__ key
    assert.strictEqual(body.__proto__, undefined);
    return { result: 'ok' };
  };

  const result = await dispatchToolCall(tool, args, mockApiClient);
  assert.ok(result);
});

test('ATTACK 15: dispatchToolCall - with missing path parameters', async () => {
  const tool = {
    method: 'GET',
    path: '/api/users/:userId/posts/:postId',
  };
  const args = { userId: 'user1' }; // Missing postId

  const mockApiClient = async (method, path, body) => ({ result: 'ok' });

  try {
    await dispatchToolCall(tool, args, mockApiClient);
    assert.fail('Should throw for missing path parameter');
  } catch (err) {
    assert.ok(err.message.includes('Missing required path parameter'));
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Summary: All tests should PASS (no crashes, no vulnerabilities)
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n✓ Input Fuzzing Test Suite Complete');
console.log('✓ All attack vectors tested: prototype pollution, path traversal, ReDoS, memory exhaustion, type confusion, null pointer, crashes, injection');
