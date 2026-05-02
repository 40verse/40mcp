import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  GENERATE_SYSTEM_PROMPT,
  buildGeneratePrompt,
  parseGeneratedConfig,
  generatePrompt,
  generateFromSpec,
} from './generate.js';

describe('GENERATE_SYSTEM_PROMPT', () => {
  it('contains key structural instructions', () => {
    assert.ok(GENERATE_SYSTEM_PROMPT.includes('snake_case'));
    assert.ok(GENERATE_SYSTEM_PROMPT.includes('inputSchema'));
    assert.ok(GENERATE_SYSTEM_PROMPT.includes('require_approval'));
    assert.ok(GENERATE_SYSTEM_PROMPT.includes('tokenBudget'));
    assert.ok(GENERATE_SYSTEM_PROMPT.includes('queryMap'));
    assert.ok(GENERATE_SYSTEM_PROMPT.includes('bodyMap'));
  });
});

describe('buildGeneratePrompt', () => {
  it('builds prompt from description', () => {
    const prompt = buildGeneratePrompt({ description: 'Stripe payments API' });
    assert.ok(prompt.includes('Stripe payments API'));
    assert.ok(prompt.includes('JSON config'));
  });

  it('includes baseUrl when provided', () => {
    const prompt = buildGeneratePrompt({ description: 'Test', baseUrl: 'https://api.test.com' });
    assert.ok(prompt.includes('https://api.test.com'));
  });

  it('includes authType when provided', () => {
    const prompt = buildGeneratePrompt({ description: 'Test', authType: 'bearer' });
    assert.ok(prompt.includes('bearer'));
  });

  it('includes endpoints list', () => {
    const prompt = buildGeneratePrompt({
      description: 'Test',
      endpoints: ['GET /users', 'POST /users', 'GET /users/:id'],
    });
    assert.ok(prompt.includes('GET /users'));
    assert.ok(prompt.includes('POST /users'));
  });

  it('includes API docs (truncated to 8000 chars)', () => {
    const longDocs = 'x'.repeat(10000);
    const prompt = buildGeneratePrompt({ description: 'Test', apiDocs: longDocs });
    assert.ok(prompt.length < 15000); // Truncated
  });

  it('respects minimal style', () => {
    const prompt = buildGeneratePrompt({ description: 'Test', style: 'minimal' });
    assert.ok(prompt.includes('3-5 tools'));
  });
});

describe('generatePrompt', () => {
  it('returns system and user prompts', () => {
    const { system, user } = generatePrompt({ description: 'GitHub API' });
    assert.ok(system.includes('40mcp config generator'));
    assert.ok(user.includes('GitHub API'));
  });
});

describe('parseGeneratedConfig', () => {
  it('parses valid JSON output', () => {
    const output = JSON.stringify({
      name: 'test',
      baseUrl: 'https://api.test.com',
      tools: [{ name: 'ping', description: 'Ping', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } }],
    });
    const { config, valid } = parseGeneratedConfig(output);
    assert.equal(valid, true);
    assert.equal(config.name, 'test');
    assert.equal(config.tools.length, 1);
  });

  it('strips markdown code fences', () => {
    const output = '```json\n{"name":"test","baseUrl":"https://api.test.com","tools":[{"name":"t","description":"T","method":"GET","path":"/","inputSchema":{"type":"object","properties":{}}}]}\n```';
    const { config, valid } = parseGeneratedConfig(output);
    assert.equal(valid, true);
    assert.equal(config.name, 'test');
  });

  it('handles preamble text before JSON', () => {
    const output = 'Here is the config:\n\n{"name":"test","baseUrl":"https://api.test.com","tools":[{"name":"t","description":"T","method":"GET","path":"/","inputSchema":{"type":"object","properties":{}}}]}';
    const { valid } = parseGeneratedConfig(output);
    assert.equal(valid, true);
  });

  it('returns errors for invalid JSON', () => {
    const { valid, errors } = parseGeneratedConfig('not json at all');
    assert.equal(valid, false);
    assert.ok(errors.length > 0);
  });

  it('returns errors for empty output', () => {
    const { valid, errors } = parseGeneratedConfig('');
    assert.equal(valid, false);
    assert.ok(errors[0].includes('Empty'));
  });

  it('validates generated config and returns warnings', () => {
    const output = JSON.stringify({
      baseUrl: 'https://api.test.com',
      tools: [{ name: 'no_desc', method: 'GET', path: '/' }],
    });
    const { valid, warnings } = parseGeneratedConfig(output);
    assert.equal(valid, true); // Valid but with warnings
    assert.ok(warnings.some((w) => w.includes('description')));
  });
});

describe('generateFromSpec', () => {
  it('generates config from OpenAPI 3.0 spec', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Pet Store', version: '1.0.0' },
      servers: [{ url: 'https://petstore.example.com/api' }],
      paths: {
        '/pets': {
          get: {
            operationId: 'listPets',
            summary: 'List all pets',
            parameters: [
              { name: 'limit', in: 'query', schema: { type: 'integer' }, description: 'Max results' },
            ],
            responses: { 200: { description: 'OK', content: { 'application/json': { schema: { type: 'array' } } } } },
          },
          post: {
            operationId: 'createPet',
            summary: 'Create a pet',
            requestBody: {
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      name: { type: 'string', description: 'Pet name' },
                      species: { type: 'string', description: 'Species' },
                    },
                    required: ['name'],
                  },
                },
              },
            },
            responses: { 201: { description: 'Created' } },
          },
        },
        '/pets/{petId}': {
          get: {
            operationId: 'getPet',
            summary: 'Get a pet by ID',
            parameters: [
              { name: 'petId', in: 'path', required: true, schema: { type: 'string' } },
            ],
            responses: { 200: { description: 'OK' } },
          },
          delete: {
            operationId: 'deletePet',
            summary: 'Delete a pet',
            parameters: [
              { name: 'petId', in: 'path', required: true, schema: { type: 'string' } },
            ],
            responses: { 204: { description: 'Deleted' } },
          },
        },
      },
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer' },
        },
      },
    };

    const config = generateFromSpec(spec);

    assert.equal(config.name, 'pet_store');
    assert.equal(config.baseUrl, 'https://petstore.example.com/api');
    assert.equal(config.auth.type, 'bearer');
    assert.ok(config.auth.envVar.includes('PET_STORE'));

    // Should have 4 tools
    assert.equal(config.tools.length, 4);

    // list_pets should have response transform (it's an array response)
    const listPets = config.tools.find((t) => t.name === 'list_pets');
    assert.ok(listPets);
    assert.ok(listPets.response?.limit);
    assert.ok(listPets.response?.summary);

    // create_pet should have policy gate
    const createPet = config.tools.find((t) => t.name === 'create_pet');
    assert.ok(createPet);
    assert.equal(createPet.policy, 'require_approval');
    assert.ok(createPet.inputSchema.required.includes('name'));

    // get_pet should have path param
    const getPet = config.tools.find((t) => t.name === 'get_pet');
    assert.ok(getPet);
    assert.equal(getPet.path, '/pets/:petId');
    assert.ok(getPet.inputSchema.properties.pet_id);

    // delete_pet should have policy gate
    const deletePet = config.tools.find((t) => t.name === 'delete_pet');
    assert.ok(deletePet);
    assert.equal(deletePet.policy, 'require_approval');
  });

  it('detects API key auth from securitySchemes', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'My API', version: '1.0' },
      servers: [{ url: 'https://api.example.com' }],
      paths: {},
      components: {
        securitySchemes: {
          apiKey: { type: 'apiKey', name: 'X-API-Key', in: 'header' },
        },
      },
    };

    const config = generateFromSpec(spec);
    assert.equal(config.auth.type, 'header');
    assert.equal(config.auth.header, 'X-API-Key');
  });

  it('respects policyGateWrites=false option', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Test', version: '1.0' },
      servers: [{ url: 'https://api.test.com' }],
      paths: {
        '/items': {
          post: { operationId: 'createItem', summary: 'Create', responses: { 201: { description: 'OK' } } },
        },
      },
    };

    const config = generateFromSpec(spec, { policyGateWrites: false });
    assert.equal(config.tools[0].policy, undefined);
  });

  it('handles Swagger 2.x securityDefinitions', () => {
    const spec = {
      swagger: '2.0',
      info: { title: 'Legacy API', version: '1.0' },
      host: 'api.example.com',
      basePath: '/v1',
      paths: {},
      securityDefinitions: {
        oauth2: {
          type: 'oauth2',
          flows: {
            clientCredentials: {
              tokenUrl: 'https://auth.example.com/token',
              scopes: { 'read:data': 'Read data' },
            },
          },
        },
      },
    };

    const config = generateFromSpec(spec);
    assert.equal(config.auth.type, 'oauth2');
    assert.equal(config.auth.tokenUrl, 'https://auth.example.com/token');
  });

  it('generates operation IDs when missing', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Test', version: '1.0' },
      servers: [{ url: 'https://api.test.com' }],
      paths: {
        '/users': {
          get: { summary: 'List users', responses: { 200: { description: 'OK' } } },
        },
        '/users/{id}': {
          get: { summary: 'Get user', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'OK' } } },
        },
      },
    };

    const config = generateFromSpec(spec);
    assert.ok(config.tools.some((t) => t.name.includes('list')));
    assert.ok(config.tools.some((t) => t.name.includes('get')));
  });

  it('blocks SSRF — loopback server URL throws', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Evil API', version: '1.0' },
      servers: [{ url: 'http://127.0.0.1/internal' }],
      paths: {},
    };
    assert.throws(
      () => generateFromSpec(spec),
      /loopback|127/i,
    );
  });

  it('blocks SSRF — cloud metadata server URL throws', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Evil API', version: '1.0' },
      servers: [{ url: 'http://169.254.169.254/latest/meta-data' }],
      paths: {},
    };
    assert.throws(
      () => generateFromSpec(spec),
      /cloud metadata|169\.254/i,
    );
  });

  it('allows private URLs when allowPrivate:true', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Internal API', version: '1.0' },
      servers: [{ url: 'http://192.168.1.10/api' }],
      paths: {},
    };
    // Should not throw with allowPrivate:true
    const config = generateFromSpec(spec, { allowPrivate: true });
    assert.equal(config.baseUrl, 'http://192.168.1.10/api');
  });

  it('blocks prototype pollution — __proto__ parameter name is dropped', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Test API', version: '1.0' },
      servers: [{ url: 'https://api.example.com' }],
      paths: {
        '/items': {
          get: {
            operationId: 'listItems',
            summary: 'List items',
            parameters: [
              { name: '__proto__', in: 'query', schema: { type: 'string' } },
              { name: 'limit', in: 'query', schema: { type: 'integer' } },
            ],
            responses: { 200: { description: 'OK' } },
          },
        },
      },
    };
    const config = generateFromSpec(spec);
    const tool = config.tools.find((t) => t.name === 'list_items');
    assert.ok(tool, 'list_items tool should exist');
    // __proto__ should be dropped — must not appear as a property
    assert.ok(!Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, '__proto__'),
      '__proto__ key must not appear in properties');
    // legitimate param should still be present
    assert.ok(Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, 'limit'),
      'limit param should survive');
    // properties should have a null prototype (no inherited keys)
    assert.equal(Object.getPrototypeOf(tool.inputSchema.properties), null,
      'properties object must have null prototype');
  });

  it('blocks prototype pollution — constructor body field is dropped', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Test API', version: '1.0' },
      servers: [{ url: 'https://api.example.com' }],
      paths: {
        '/items': {
          post: {
            operationId: 'createItem',
            summary: 'Create item',
            requestBody: {
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      constructor: { type: 'string' },
                      name: { type: 'string' },
                    },
                  },
                },
              },
            },
            responses: { 201: { description: 'Created' } },
          },
        },
      },
    };
    const config = generateFromSpec(spec);
    const tool = config.tools.find((t) => t.name === 'create_item');
    assert.ok(tool, 'create_item tool should exist');
    assert.ok(!Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, 'constructor'),
      'constructor key must not appear in properties');
    assert.ok(Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, 'name'),
      'name field should survive');
  });

  it('strips CRLF from apiKey header name', () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Injection API', version: '1.0' },
      servers: [{ url: 'https://api.example.com' }],
      paths: {},
      components: {
        securitySchemes: {
          apiKey: {
            type: 'apiKey',
            name: 'X-API-Key\r\nInjected-Header: evil',
            in: 'header',
          },
        },
      },
    };
    const config = generateFromSpec(spec);
    assert.ok(config.auth, 'auth should be set');
    assert.equal(config.auth.type, 'header');
    assert.ok(!config.auth.header.includes('\r'), 'CR must be stripped from header name');
    assert.ok(!config.auth.header.includes('\n'), 'LF must be stripped from header name');
    assert.equal(config.auth.header, 'X-API-KeyInjected-Header: evil');
  });
});
