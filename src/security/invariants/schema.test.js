/**
 * Security invariants — schema / loader safety surface
 *
 * Tests for OpenAPI schema loading (duplicate operationId detection,
 * normalization collisions) and GraphQL schema injection/depth safety.
 *
 * @module security/invariants/schema
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// ─────────────────────────────────────────────────────────────────────────────
// OpenAPI duplicate operationId collision detection
// ─────────────────────────────────────────────────────────────────────────────

describe('OpenAPI duplicate operationId collision detection', () => {
  const BASE_SPEC = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    servers: [{ url: 'https://api.example.com' }],
  };

  it('loadOpenApiSpec warns-and-skips duplicate operationId tool names in default mode', async () => {
    const { loadOpenApiSpec } = await import('../../openapi.js');
    const spec = {
      ...BASE_SPEC,
      paths: {
        '/users':       { get: { operationId: 'listUsers', summary: 'public' } },
        '/users/admin': { get: { operationId: 'listUsers', summary: 'admin'  } },
      },
    };
    const { tools } = await loadOpenApiSpec(spec);
    // Duplicate skipped — only the first registration survives
    assert.equal(tools.length, 1);
    assert.equal(tools[0].name, 'list_users');
    assert.equal(tools[0].path, '/users');
  });

  it('loadOpenApiSpec rejects duplicate operationId tool names in strict mode', async () => {
    const { loadOpenApiSpec } = await import('../../openapi.js');
    const spec = {
      ...BASE_SPEC,
      paths: {
        '/users':       { get: { operationId: 'listUsers', summary: 'public' } },
        '/users/admin': { get: { operationId: 'listUsers', summary: 'admin'  } },
      },
    };
    await assert.rejects(
      () => loadOpenApiSpec(spec, { strict: true }),
      /duplicate tool name/,
    );
  });

  it('loadOpenApiSpec detects normalization collisions (listUsers vs list_users vs LIST_USERS)', async () => {
    const { loadOpenApiSpec } = await import('../../openapi.js');
    const spec = {
      ...BASE_SPEC,
      paths: {
        '/a': { get: { operationId: 'listUsers',  summary: 'a' } },
        '/b': { get: { operationId: 'list_users', summary: 'b' } },
        '/c': { get: { operationId: 'LIST_USERS', summary: 'c' } },
      },
    };
    const { tools } = await loadOpenApiSpec(spec);
    // All three normalize to 'list_users' — only the first survives
    assert.equal(tools.length, 1);
    assert.equal(tools[0].name, 'list_users');
  });

  it('loadOpenApiSpec nameTransform disambiguates — no collision when names differ', async () => {
    const { loadOpenApiSpec } = await import('../../openapi.js');
    const spec = {
      ...BASE_SPEC,
      paths: {
        '/a': { get: { operationId: 'listUsers', summary: 'a' } },
        '/b': { get: { operationId: 'listUsers', summary: 'b' } },
      },
    };
    // nameTransform produces distinct names → both tools registered
    const nameTransform = (opId, _method, path) =>
      `${opId}${path.replace(/\//g, '_')}`;
    const { tools } = await loadOpenApiSpec(spec, { nameTransform });
    assert.equal(tools.length, 2);
  });

  it('loadOpenApiSpec strict mode error message includes both paths', async () => {
    const { loadOpenApiSpec } = await import('../../openapi.js');
    const spec = {
      ...BASE_SPEC,
      paths: {
        '/users':       { get: { operationId: 'listUsers', summary: 'public' } },
        '/users/admin': { get: { operationId: 'listUsers', summary: 'admin'  } },
      },
    };
    await assert.rejects(
      () => loadOpenApiSpec(spec, { strict: true }),
      (err) => {
        assert.ok(err.message.includes('/users'), 'error must mention first path');
        assert.ok(err.message.includes('/users/admin'), 'error must mention duplicate path');
        return true;
      },
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GraphQL injection and depth-limit safety
// ─────────────────────────────────────────────────────────────────────────────

describe('GraphQL schema injection and nesting safety', () => {
  // ── CRIT-1: GraphQL injection via unsanitized operation name ─────────────
  it('loadGraphqlSchema drops fields with invalid GraphQL identifier names', async () => {
    const { loadGraphqlSchema } = await import('../../loaders/graphql.js');
    const maliciousSchema = {
      __schema: {
        queryType: { name: 'Query' },
        mutationType: null,
        types: [
          {
            name: 'Query',
            kind: 'OBJECT',
            fields: [
              {
                name: 'listUsers } query { __schema { types { name } } } query { foo',
                description: 'injection payload',
                args: [],
                type: { kind: 'SCALAR', name: 'String', ofType: null },
                isDeprecated: false,
              },
              {
                name: 'validField',
                description: 'clean field',
                args: [],
                type: { kind: 'SCALAR', name: 'String', ofType: null },
                isDeprecated: false,
              },
            ],
          },
        ],
      },
    };
    const result = await loadGraphqlSchema(maliciousSchema, { endpoint: '/graphql' });
    assert.ok(Array.isArray(result.tools));
    // Injection field must be dropped; only validField survives
    for (const tool of result.tools) {
      if (tool.graphql?.operation) {
        assert.match(tool.graphql.operation, /^[_A-Za-z][_0-9A-Za-z]*$/,
          'graphql.operation must be a valid identifier');
      }
    }
    // No tool name may contain brace or space characters
    assert.ok(
      result.tools.every((t) => !/[{}\s]/.test(t.name)),
      'no tool name may contain injection characters',
    );
  });

  // ── HIGH: GraphQL typeToJsonSchema depth limit ────────────────────────────
  it('loadGraphqlSchema survives 100-deep NON_NULL type nesting', async () => {
    const { loadGraphqlSchema } = await import('../../loaders/graphql.js');
    let deepType = { kind: 'SCALAR', name: 'String', ofType: null };
    for (let i = 0; i < 100; i++) deepType = { kind: 'NON_NULL', ofType: deepType };
    const schema = {
      __schema: {
        queryType: { name: 'Query' },
        mutationType: null,
        types: [
          {
            name: 'Query',
            kind: 'OBJECT',
            fields: [
              {
                name: 'deepField',
                description: 'nested type test',
                args: [{ name: 'arg1', description: null, type: deepType }],
                type: { kind: 'SCALAR', name: 'String', ofType: null },
                isDeprecated: false,
              },
            ],
          },
        ],
      },
    };
    await assert.doesNotReject(() => loadGraphqlSchema(schema, { endpoint: '/graphql' }),
      'deeply nested types must not overflow the stack');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HAR cumulative param cap pre-check
// ─────────────────────────────────────────────────────────────────────────────

describe('cumulative parameter cap enforced before overshoot (H3)', () => {
  it('loadHarFile cumulative param count does not exceed 5000', async () => {
    // Earlier implementation: the previous implementation checked the cumulative param count
    // AFTER adding each entry's params, allowing the last entry to push the total
    // up to ~5306 (5000 + 256 query + 50 body). The fix checks BEFORE processing
    // each entry so the total cannot exceed MAX_CUMULATIVE_PARAMS (5000).
    const { loadHarFile } = await import('../../loaders/har.js');
    // 2000 entries (MAX_ENTRIES), each with 4 unique query params → 8000 potential.
    // With the pre-check fix the total must not exceed 5000.
    const entries = Array.from({ length: 2000 }, (_, i) => ({
      request: {
        method: 'GET',
        url: 'https://api.example.com/data',
        queryString: [
          { name: `pa${i}`, value: 'v' },
          { name: `pb${i}`, value: 'v' },
          { name: `pc${i}`, value: 'v' },
          { name: `pd${i}`, value: 'v' },
        ],
        headers: [],
        bodySize: -1,
      },
      response: { status: 200, content: {}, headers: [] },
      time: 10,
    }));
    const har = { log: { entries } };
    const result = await loadHarFile(har, { allowPrivate: false });
    assert.ok(result.tools.length >= 1, 'should produce at least one tool');
    const tool = result.tools[0];
    const paramCount = Object.keys(tool.inputSchema?.properties ?? {}).length;
    assert.ok(paramCount <= 5000,
      `cumulative param count must not exceed 5000 (got ${paramCount}); H3 pre-check may be missing`);
  });
});
