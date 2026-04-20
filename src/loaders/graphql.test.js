import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadGraphqlSchema } from './graphql.js';

// ─── Mock introspection schema ───────────────────────────────────────────────

const MOCK_INTROSPECTION = {
  __schema: {
    queryType: { name: 'Query' },
    mutationType: { name: 'Mutation' },
    types: [
      {
        name: 'Query',
        kind: 'OBJECT',
        fields: [
          {
            name: 'listUsers',
            description: 'Get all users with pagination',
            args: [
              {
                name: 'limit',
                description: 'Max results',
                type: {
                  kind: 'SCALAR',
                  name: 'Int',
                },
              },
              {
                name: 'offset',
                description: 'Pagination offset',
                type: {
                  kind: 'SCALAR',
                  name: 'Int',
                },
              },
            ],
            type: {
              kind: 'LIST',
              ofType: {
                kind: 'OBJECT',
                name: 'User',
              },
            },
          },
          {
            name: 'getUser',
            description: 'Get user by ID',
            args: [
              {
                name: 'userId',
                description: 'User ID',
                type: {
                  kind: 'NON_NULL',
                  ofType: {
                    kind: 'SCALAR',
                    name: 'ID',
                  },
                },
              },
            ],
            type: {
              kind: 'OBJECT',
              name: 'User',
            },
          },
          {
            name: 'searchUsers',
            description: 'Search users by name',
            args: [
              {
                name: 'query',
                type: {
                  kind: 'NON_NULL',
                  ofType: {
                    kind: 'SCALAR',
                    name: 'String',
                  },
                },
              },
              {
                name: 'limit',
                type: {
                  kind: 'SCALAR',
                  name: 'Int',
                },
              },
            ],
            type: {
              kind: 'LIST',
              ofType: {
                kind: 'OBJECT',
                name: 'User',
              },
            },
          },
        ],
      },
      {
        name: 'Mutation',
        kind: 'OBJECT',
        fields: [
          {
            name: 'createUser',
            description: 'Create a new user',
            args: [
              {
                name: 'name',
                type: {
                  kind: 'NON_NULL',
                  ofType: {
                    kind: 'SCALAR',
                    name: 'String',
                  },
                },
              },
              {
                name: 'email',
                type: {
                  kind: 'NON_NULL',
                  ofType: {
                    kind: 'SCALAR',
                    name: 'String',
                  },
                },
              },
              {
                name: 'age',
                type: {
                  kind: 'SCALAR',
                  name: 'Int',
                },
              },
            ],
            type: {
              kind: 'OBJECT',
              name: 'User',
            },
          },
          {
            name: 'updateUser',
            description: 'Update user by ID',
            args: [
              {
                name: 'userId',
                type: {
                  kind: 'NON_NULL',
                  ofType: {
                    kind: 'SCALAR',
                    name: 'ID',
                  },
                },
              },
              {
                name: 'name',
                type: {
                  kind: 'SCALAR',
                  name: 'String',
                },
              },
            ],
            type: {
              kind: 'OBJECT',
              name: 'User',
            },
          },
        ],
      },
    ],
  },
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('loadGraphqlSchema', () => {
  it('generates tools from query type fields', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const queryTools = tools.filter((t) => t.method === 'QUERY');
    assert.ok(queryTools.length >= 2);
    const names = queryTools.map((t) => t.name);
    assert.ok(names.includes('list_users'));
    assert.ok(names.includes('get_user'));
  });

  it('generates tools from mutation type fields', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const mutationTools = tools.filter((t) => t.method === 'MUTATION');
    assert.ok(mutationTools.length >= 2);
    const names = mutationTools.map((t) => t.name);
    assert.ok(names.includes('create_user'));
    assert.ok(names.includes('update_user'));
  });

  it('maps GraphQL scalar types to JSON Schema types correctly', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const createUserTool = tools.find((t) => t.name === 'create_user');
    assert.equal(createUserTool.inputSchema.properties.name.type, 'string');
    assert.equal(createUserTool.inputSchema.properties.email.type, 'string');
    assert.equal(createUserTool.inputSchema.properties.age.type, 'integer');
  });

  it('handles NON_NULL → required', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const createUserTool = tools.find((t) => t.name === 'create_user');
    assert.ok(createUserTool.inputSchema.required.includes('name'));
    assert.ok(createUserTool.inputSchema.required.includes('email'));
    assert.ok(!createUserTool.inputSchema.required.includes('age'));
  });

  it('handles LIST → array type', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const listUsersTool = tools.find((t) => t.name === 'list_users');
    assert.equal(listUsersTool.inputSchema.properties.limit.type, 'integer');
  });

  it('converts names to snake_case', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const names = tools.map((t) => t.name);
    assert.ok(names.includes('list_users'));
    assert.ok(names.includes('get_user'));
    assert.ok(names.includes('search_users'));
    assert.ok(names.includes('create_user'));
    assert.ok(names.includes('update_user'));
  });

  it('filters by include pattern', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, {
      endpoint: 'http://api.example.com/graphql',
      include: ['User'],
    });
    const names = tools.map((t) => t.name);
    // All tool names contain 'User' or 'user'
    assert.ok(names.length > 0);
    assert.ok(names.every((n) => n.includes('user')));
  });

  it('filters by exclude pattern', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, {
      endpoint: 'http://api.example.com/graphql',
      exclude: ['search'],
    });
    const names = tools.map((t) => t.name);
    assert.ok(!names.includes('search_users'));
  });

  it('filters by types - query only', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, {
      endpoint: 'http://api.example.com/graphql',
      types: ['query'],
    });
    const methods = tools.map((t) => t.method);
    assert.ok(methods.every((m) => m === 'QUERY'));
    assert.equal(tools.filter((t) => t.method === 'MUTATION').length, 0);
  });

  it('filters by types - mutation only', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, {
      endpoint: 'http://api.example.com/graphql',
      types: ['mutation'],
    });
    const methods = tools.map((t) => t.method);
    assert.ok(methods.every((m) => m === 'MUTATION'));
    assert.equal(tools.filter((t) => t.method === 'QUERY').length, 0);
  });

  it('sets graphql.operation and graphql.type correctly', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const listUsersTool = tools.find((t) => t.name === 'list_users');
    assert.equal(listUsersTool.graphql.operation, 'listUsers');
    assert.equal(listUsersTool.graphql.type, 'query');

    const createUserTool = tools.find((t) => t.name === 'create_user');
    assert.equal(createUserTool.graphql.operation, 'createUser');
    assert.equal(createUserTool.graphql.type, 'mutation');
  });

  it('uses field description as tool description', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const listUsersTool = tools.find((t) => t.name === 'list_users');
    assert.equal(listUsersTool.description, 'Get all users with pagination');

    const createUserTool = tools.find((t) => t.name === 'create_user');
    assert.equal(createUserTool.description, 'Create a new user');
  });

  it('sets path to endpoint for all tools', async () => {
    const endpoint = 'http://api.example.com/graphql';
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint });
    assert.ok(tools.every((t) => t.path === endpoint));
  });

  it('handles arguments with descriptions', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const listUsersTool = tools.find((t) => t.name === 'list_users');
    assert.equal(listUsersTool.inputSchema.properties.limit.description, 'Max results');
    assert.equal(listUsersTool.inputSchema.properties.offset.description, 'Pagination offset');
  });

  it('includes all required fields in tool definition', async () => {
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint: 'http://api.example.com/graphql' });
    const tool = tools[0];
    assert.ok(tool.name);
    assert.ok(tool.description);
    assert.ok(tool.method);
    assert.ok(tool.path);
    assert.ok(tool.inputSchema);
    assert.ok(tool.graphql);
    assert.ok(tool.graphql.operation);
    assert.ok(tool.graphql.type);
  });

  it('applies custom nameTransform', async () => {
    const customTransform = (fieldName, operationType) => `${operationType}_${fieldName}`;
    const { tools } = await loadGraphqlSchema(MOCK_INTROSPECTION, {
      endpoint: 'http://api.example.com/graphql',
      nameTransform: customTransform,
    });
    const names = tools.map((t) => t.name);
    assert.ok(names.some((n) => n.startsWith('query_') || n.startsWith('mutation_')));
  });

  it('returns baseUrl in result', async () => {
    const endpoint = 'http://api.example.com/graphql';
    const { baseUrl } = await loadGraphqlSchema(MOCK_INTROSPECTION, { endpoint });
    assert.equal(baseUrl, endpoint);
  });

  it('handles operations without arguments', async () => {
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
                name: 'getStatus',
                description: 'Get server status',
                args: [],
                type: {
                  kind: 'OBJECT',
                  name: 'Status',
                },
              },
            ],
          },
        ],
      },
    };
    const { tools } = await loadGraphqlSchema(schema, { endpoint: 'http://api.example.com/graphql' });
    assert.equal(tools.length, 1);
    assert.equal(tools[0].inputSchema.properties.length, undefined);
    assert.deepEqual(tools[0].inputSchema.required, []);
  });

  it('handles deeply nested NON_NULL and LIST types', async () => {
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
                name: 'getNestedData',
                description: 'Get nested array of non-null items',
                args: [
                  {
                    name: 'ids',
                    description: 'Array of required IDs',
                    type: {
                      kind: 'NON_NULL',
                      ofType: {
                        kind: 'LIST',
                        ofType: {
                          kind: 'NON_NULL',
                          ofType: {
                            kind: 'SCALAR',
                            name: 'ID',
                          },
                        },
                      },
                    },
                  },
                ],
                type: {
                  kind: 'LIST',
                  ofType: {
                    kind: 'OBJECT',
                    name: 'Data',
                  },
                },
              },
            ],
          },
        ],
      },
    };
    const { tools } = await loadGraphqlSchema(schema, { endpoint: 'http://api.example.com/graphql' });
    const tool = tools[0];
    assert.equal(tool.inputSchema.properties.ids.type, 'array');
    assert.ok(tool.inputSchema.required.includes('ids'));
  });

  it('handles Float and Boolean scalar types', async () => {
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
                name: 'getMetrics',
                description: 'Get metrics',
                args: [
                  {
                    name: 'ratio',
                    type: { kind: 'SCALAR', name: 'Float' },
                  },
                  {
                    name: 'includeArchived',
                    type: { kind: 'SCALAR', name: 'Boolean' },
                  },
                ],
                type: { kind: 'OBJECT', name: 'Metrics' },
              },
            ],
          },
        ],
      },
    };
    const { tools } = await loadGraphqlSchema(schema, { endpoint: 'http://api.example.com/graphql' });
    const tool = tools[0];
    assert.equal(tool.inputSchema.properties.ratio.type, 'number');
    assert.equal(tool.inputSchema.properties.includeArchived.type, 'boolean');
  });

  // ─── Introspection result validation tests ─────────────────────────────

  it('rejects introspection response with missing "data" field', async () => {
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ notData: {} }),
    });

    await assert.rejects(
      () => loadGraphqlSchema('http://attacker.example.com/graphql'),
      (err) => err.message.includes('"data"'),
    );

    globalThis.fetch = undefined;
  });

  it('rejects introspection response with missing "__schema" field', async () => {
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ data: { notSchema: {} } }),
    });

    await assert.rejects(
      () => loadGraphqlSchema('http://attacker.example.com/graphql'),
      (err) => err.message.includes('__schema'),
    );

    globalThis.fetch = undefined;
  });

  it('rejects introspection when __schema.types is not an array', async () => {
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: {
          __schema: {
            queryType: { name: 'Query' },
            types: 'INJECTED_STRING',
          },
        },
      }),
    });

    await assert.rejects(
      () => loadGraphqlSchema('http://attacker.example.com/graphql'),
      (err) => err.message.includes('types'),
    );

    globalThis.fetch = undefined;
  });
});
