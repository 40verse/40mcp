import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadOpenApiSpec } from './openapi.js';

// ─── Minimal OpenAPI 3.0 spec for testing ───────────────────────────────────

const MINI_SPEC = {
  openapi: '3.0.0',
  info: { title: 'Test', version: '1.0.0' },
  servers: [{ url: 'https://api.example.com/v1' }],
  paths: {
    '/pets': {
      get: {
        operationId: 'listPets',
        summary: 'List all pets',
        tags: ['pets'],
        parameters: [
          { name: 'limit', in: 'query', schema: { type: 'integer' }, description: 'Max results' },
          { name: 'status', in: 'query', schema: { type: 'string', enum: ['available', 'sold'] } },
        ],
        responses: { 200: { description: 'OK' } },
      },
      post: {
        operationId: 'createPet',
        summary: 'Create a pet',
        tags: ['pets'],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  petName: { type: 'string', description: 'Name of the pet' },
                  petStatus: { type: 'string', enum: ['available', 'pending', 'sold'] },
                },
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
        tags: ['pets'],
        parameters: [
          { name: 'petId', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { 200: { description: 'OK' } },
      },
      delete: {
        operationId: 'deletePet',
        summary: 'Delete a pet',
        tags: ['pets'],
        parameters: [
          { name: 'petId', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { 204: { description: 'Deleted' } },
      },
    },
    '/store/inventory': {
      get: {
        operationId: 'getInventory',
        summary: 'Store inventory',
        tags: ['store'],
        responses: { 200: { description: 'OK' } },
      },
    },
  },
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('loadOpenApiSpec', () => {
  it('extracts base URL from servers', async () => {
    const { baseUrl } = await loadOpenApiSpec(MINI_SPEC);
    assert.equal(baseUrl, 'https://api.example.com/v1');
  });

  it('generates tools for all operations', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC);
    assert.equal(tools.length, 5);
    const names = tools.map((t) => t.name);
    assert.ok(names.includes('list_pets'));
    assert.ok(names.includes('create_pet'));
    assert.ok(names.includes('get_pet_by_id'));
    assert.ok(names.includes('delete_pet'));
    assert.ok(names.includes('get_inventory'));
  });

  it('converts {param} to :param in paths', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC);
    const getTool = tools.find((t) => t.name === 'get_pet_by_id');
    assert.equal(getTool.path, '/pets/:petId');
  });

  it('extracts query parameters into inputSchema', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC);
    const listTool = tools.find((t) => t.name === 'list_pets');
    assert.ok(listTool.inputSchema.properties.limit);
    assert.ok(listTool.inputSchema.properties.status);
    assert.deepEqual(listTool.inputSchema.properties.status.enum, ['available', 'sold']);
  });

  it('extracts request body properties for POST', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC);
    const createTool = tools.find((t) => t.name === 'create_pet');
    assert.equal(createTool.method, 'POST');
    assert.ok(createTool.inputSchema.properties.pet_name);
    assert.ok(createTool.inputSchema.properties.pet_status);
    assert.ok(createTool.inputSchema.required.includes('pet_name'));
    // Body map renames snake_case → camelCase
    assert.equal(createTool.bodyMap.pet_name, 'petName');
    assert.equal(createTool.bodyMap.pet_status, 'petStatus');
  });

  it('filters by tags', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC, { tags: ['store'] });
    assert.equal(tools.length, 1);
    assert.equal(tools[0].name, 'get_inventory');
  });

  it('filters by methods', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC, { methods: ['get'] });
    assert.ok(tools.every((t) => t.method === 'GET'));
    assert.equal(tools.length, 3);
  });

  it('filters by include patterns', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC, { include: ['Pet'] });
    const names = tools.map((t) => t.name);
    assert.ok(names.includes('list_pets'));
    assert.ok(names.includes('get_pet_by_id'));
    assert.ok(!names.includes('get_inventory'));
  });

  it('filters by exclude patterns', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC, { exclude: ['delete'] });
    const names = tools.map((t) => t.name);
    assert.ok(!names.includes('delete_pet'));
    assert.ok(names.includes('list_pets'));
  });

  it('marks path params as required', async () => {
    const { tools } = await loadOpenApiSpec(MINI_SPEC);
    const getTool = tools.find((t) => t.name === 'get_pet_by_id');
    assert.ok(getTool.inputSchema.required.includes('pet_id'));
  });
});

// ─── Swagger 2.x ────────────────────────────────────────────────────────────

const SWAGGER2_SPEC = {
  swagger: '2.0',
  info: { title: 'Test', version: '1.0.0' },
  host: 'api.example.com',
  basePath: '/v2',
  schemes: ['https'],
  paths: {
    '/users': {
      get: {
        operationId: 'listUsers',
        summary: 'List users',
        parameters: [
          { name: 'limit', in: 'query', type: 'integer' },
        ],
        responses: { 200: { description: 'OK' } },
      },
    },
    '/users/{userId}': {
      get: {
        operationId: 'getUser',
        summary: 'Get user',
        parameters: [
          { name: 'userId', in: 'path', required: true, type: 'string' },
        ],
        responses: { 200: { description: 'OK' } },
      },
    },
  },
};

describe('loadOpenApiSpec (Swagger 2.x)', () => {
  it('extracts base URL from host + basePath', async () => {
    const { baseUrl } = await loadOpenApiSpec(SWAGGER2_SPEC);
    assert.equal(baseUrl, 'https://api.example.com/v2');
  });

  it('generates tools from Swagger 2.x paths', async () => {
    const { tools } = await loadOpenApiSpec(SWAGGER2_SPEC);
    assert.equal(tools.length, 2);
    assert.equal(tools[0].name, 'list_users');
    assert.equal(tools[1].name, 'get_user');
    assert.equal(tools[1].path, '/users/:userId');
  });
});
