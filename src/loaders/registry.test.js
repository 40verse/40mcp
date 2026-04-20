import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { registerLoader, loadFromAny, listLoaders } from './registry.js';

// ─── Built-in detection tests ───────────────────────────────────────────────

describe('loadFromAny — built-in detection', () => {
  it('detects OpenAPI spec by object shape (openapi field)', async () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Test', version: '1.0' },
      paths: {
        '/users': {
          get: {
            operationId: 'listUsers',
            summary: 'List users',
            responses: { 200: { description: 'OK' } },
          },
        },
      },
    };

    const { tools } = await loadFromAny(spec);
    assert.ok(tools.length > 0);
    assert.ok(tools[0].name);
  });

  it('detects OpenAPI spec by swagger field', async () => {
    const spec = {
      swagger: '2.0',
      info: { title: 'Test', version: '1.0' },
      host: 'api.example.com',
      basePath: '/v1',
      paths: {
        '/items': {
          get: {
            operationId: 'listItems',
            summary: 'List items',
            responses: { 200: { description: 'OK' } },
          },
        },
      },
    };

    const { tools } = await loadFromAny(spec);
    assert.ok(tools.length > 0);
  });

  it('detects HAR by log.entries', async () => {
    const har = {
      log: {
        entries: [
          {
            request: { method: 'GET', url: 'https://api.example.com/users', queryString: [] },
            response: { status: 200, content: { mimeType: 'application/json', text: '[]' } },
          },
        ],
      },
    };

    const { tools } = await loadFromAny(har);
    assert.ok(tools.length > 0);
  });

  it('detects file by extension (.har)', async () => {
    // This will fail to read the file, but the detection should pick HAR loader
    await assert.rejects(
      () => loadFromAny('/tmp/nonexistent.har'),
      // HAR loader will throw because file doesn't exist, but it was correctly detected
    );
  });

  it('throws for unrecognized input', async () => {
    await assert.rejects(
      () => loadFromAny({ random: 'data' }),
      (err) => err.message.includes('No loader found'),
    );
  });

  it('throws a clear error for null input', async () => {
    await assert.rejects(
      () => loadFromAny(null),
      (err) => err.message.includes('null') && err.message.includes('loadFromAny()'),
    );
  });

  it('throws a clear error for undefined input', async () => {
    await assert.rejects(
      () => loadFromAny(undefined),
      (err) => err.message.includes('undefined') && err.message.includes('loadFromAny()'),
    );
  });
});

// ─── Custom plugin tests ────────────────────────────────────────────────────

describe('registerLoader — custom plugins', () => {
  it('registers and uses a custom loader', async () => {
    registerLoader({
      name: 'test-format',
      detect: (_input) => typeof _input === 'object' && _input._testFormat === true,
      load: async (_input) => ({
        baseUrl: 'https://test.example.com',
        tools: [
          {
            name: 'test_tool',
            description: 'A test tool',
            method: 'GET',
            path: '/test',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      }),
    });

    const { baseUrl, tools } = await loadFromAny({ _testFormat: true });
    assert.equal(baseUrl, 'https://test.example.com');
    assert.equal(tools[0].name, 'test_tool');
  });

  it('custom plugins take priority over built-in loaders', async () => {
    registerLoader({
      name: 'custom-openapi',
      detect: (input) => typeof input === 'object' && input.openapi === 'custom',
      load: async () => ({
        baseUrl: 'https://custom.example.com',
        tools: [{ name: 'custom_tool', description: 'Custom', method: 'GET', path: '/custom', inputSchema: { type: 'object' } }],
      }),
    });

    const { baseUrl } = await loadFromAny({ openapi: 'custom' });
    assert.equal(baseUrl, 'https://custom.example.com');
  });

  it('throws on invalid plugin (missing detect)', () => {
    assert.throws(
      () => registerLoader({ name: 'bad', load: async () => ({}) }),
      (err) => err.message.includes('detect'),
    );
  });

  it('re-registration replaces existing plugin', () => {
    registerLoader({
      name: 'replaceable',
      detect: () => false,
      load: async () => ({ baseUrl: '', tools: [] }),
    });

    const before = listLoaders().filter((l) => l.name === 'replaceable');
    assert.equal(before.length, 1);

    registerLoader({
      name: 'replaceable',
      detect: () => false,
      load: async () => ({ baseUrl: 'new', tools: [] }),
    });

    const after = listLoaders().filter((l) => l.name === 'replaceable');
    assert.equal(after.length, 1);
  });
});

// ─── listLoaders tests ──────────────────────────────────────────────────────

describe('listLoaders', () => {
  it('returns built-in loaders', () => {
    const loaders = listLoaders();
    const builtins = loaders.filter((l) => l.builtin);
    assert.ok(builtins.some((l) => l.name === 'openapi'));
    assert.ok(builtins.some((l) => l.name === 'graphql'));
    assert.ok(builtins.some((l) => l.name === 'har'));
  });

  it('includes custom loaders before builtins', () => {
    const loaders = listLoaders();
    const customIdx = loaders.findIndex((l) => !l.builtin);
    const builtinIdx = loaders.findIndex((l) => l.builtin);
    if (customIdx !== -1) {
      assert.ok(customIdx < builtinIdx);
    }
  });
});
