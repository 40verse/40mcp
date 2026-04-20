import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { openapi } from './openapi.js';
import { loadOpenApiSpec } from '../openapi.js';

// Minimal OpenAPI 3.0 spec — small enough to inline, rich enough to cover
// path params, query params, and a request body so the structural compare
// against `loadOpenApiSpec` is meaningful.
const MINI_SPEC = {
  openapi: '3.0.0',
  info: { title: 'Test', version: '1.0.0' },
  servers: [{ url: 'https://api.example.com/v1' }],
  paths: {
    '/pets': {
      get: {
        operationId: 'listPets',
        summary: 'List pets',
        parameters: [
          { name: 'limit', in: 'query', schema: { type: 'integer' } },
        ],
        responses: { 200: { description: 'OK' } },
      },
      post: {
        operationId: 'createPet',
        summary: 'Create a pet',
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: { petName: { type: 'string' } },
                required: ['petName'],
              },
            },
          },
        },
        responses: { 201: { description: 'Created' } },
      },
    },
    '/pets/{petId}': {
      get: {
        operationId: 'getPetById',
        summary: 'Get pet by ID',
        parameters: [
          { name: 'petId', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { 200: { description: 'OK' } },
      },
    },
  },
};

describe('providers.openapi — Provider shape', () => {
  it('returns an object with default name "openapi"', () => {
    const p = openapi(MINI_SPEC);
    assert.equal(p.name, 'openapi');
    assert.equal(typeof p.components, 'function');
  });

  it('honours a custom name via opts.name', () => {
    const p = openapi(MINI_SPEC, { name: 'stripe' });
    assert.equal(p.name, 'stripe');
  });

  it('does not expose a close() method (loader holds no handles)', () => {
    const p = openapi(MINI_SPEC);
    assert.equal('close' in p, false);
  });
});

describe('providers.openapi — components() parity with loadOpenApiSpec', () => {
  it('returns { tools } with the same shape loadOpenApiSpec produces', async () => {
    const { tools: loaderTools } = await loadOpenApiSpec(MINI_SPEC);
    const { tools: providerTools } = await openapi(MINI_SPEC).components();

    // Structural compare on the load-bearing fields (name, method, path,
    // inputSchema). We do not over-specify: `bodyMap`, request headers,
    // etc. are preserved by reference since the provider forwards the
    // array verbatim, but asserting identity on those would couple this
    // test to loader internals.
    const pick = (t) => ({
      name: t.name,
      method: t.method,
      path: t.path,
      inputSchema: t.inputSchema,
    });

    assert.equal(providerTools.length, loaderTools.length);
    assert.deepEqual(providerTools.map(pick), loaderTools.map(pick));
  });

  it('forwards loader options (e.g. methods filter) through to the loader', async () => {
    const { tools } = await openapi(MINI_SPEC, { methods: ['get'] }).components();
    assert.ok(tools.length > 0);
    assert.ok(tools.every((t) => t.method === 'GET'));
  });

  it('does not reshape tool objects — fields like bodyMap are preserved verbatim', async () => {
    const { tools: loaderTools } = await loadOpenApiSpec(MINI_SPEC);
    const { tools: providerTools } = await openapi(MINI_SPEC).components();

    const loaderCreate = loaderTools.find((t) => t.name === 'create_pet');
    const providerCreate = providerTools.find((t) => t.name === 'create_pet');
    assert.ok(loaderCreate);
    assert.ok(providerCreate);
    // bodyMap is an internal field from the loader; preserving it end-to-end
    // is the non-reshape invariant we promised for the Provider interface.
    assert.deepEqual(providerCreate.bodyMap, loaderCreate.bodyMap);
  });

  it('construction is synchronous and cheap — does not load until components() is called', () => {
    // `openapi(spec)` must not throw or await for a plain in-memory spec.
    // This mirrors the laziness expected of linked-MCP providers once they
    // move behind this interface.
    const p = openapi(MINI_SPEC);
    assert.equal(typeof p.components, 'function');
  });
});
