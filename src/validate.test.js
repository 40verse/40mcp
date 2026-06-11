import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateConfig, assertValidConfig } from './validate.js';

describe('validateConfig', () => {
  it('validates a minimal valid config', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [
        { name: 'ping', description: 'Ping', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } },
      ],
    });
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it('rejects non-object config', () => {
    const result = validateConfig(null);
    assert.equal(result.valid, false);
    assert.ok(result.errors[0].includes('must be an object'));
  });

  it('errors on missing baseUrl', () => {
    const result = validateConfig({ tools: [{ name: 't', method: 'GET', path: '/' }] });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('baseUrl')));
  });

  it('allows missing baseUrl when all tools are chains', () => {
    const result = validateConfig({
      tools: [{ name: 'chain_tool', chain: [{ call: 'a', as: 'a' }], inputSchema: { type: 'object' } }],
    });
    assert.equal(result.valid, true);
  });

  it('errors on invalid auth type', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      auth: { type: 'magic' },
      tools: [],
    });
    assert.ok(result.errors.some((e) => e.includes('auth.type')));
  });

  it('errors on header auth without header name', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      auth: { type: 'header' },
      tools: [],
    });
    assert.ok(result.errors.some((e) => e.includes('auth.header')));
  });

  it('errors on oauth2 without tokenUrl', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      auth: { type: 'oauth2' },
      tools: [],
    });
    assert.ok(result.errors.some((e) => e.includes('tokenUrl')));
  });

  it('warns on auth.value without envVar', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer', value: 'secret' },
      tools: [],
    });
    assert.ok(result.warnings.some((w) => w.includes('envVar')));
  });

  it('errors on invalid transport type', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      transport: { type: 'websocket' },
      tools: [],
    });
    assert.ok(result.errors.some((e) => e.includes('transport.type')));
  });

  it('errors on tools not being an array', () => {
    const result = validateConfig({ baseUrl: 'https://api.example.com', tools: 'wrong' });
    assert.ok(result.errors.some((e) => e.includes('must be an array')));
  });

  it('errors on missing tool name', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ method: 'GET', path: '/' }],
    });
    assert.ok(result.errors.some((e) => e.includes('name is required')));
  });

  it('errors on duplicate tool names', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [
        { name: 'dupe', method: 'GET', path: '/a', inputSchema: { type: 'object' } },
        { name: 'dupe', method: 'GET', path: '/b', inputSchema: { type: 'object' } },
      ],
    });
    assert.ok(result.errors.some((e) => e.includes('duplicate tool name')));
  });

  it('errors on missing method for non-chain tool', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'bad', path: '/' }],
    });
    assert.ok(result.errors.some((e) => e.includes('method is required')));
  });

  it('errors on invalid HTTP method', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'bad', method: 'YEET', path: '/' }],
    });
    assert.ok(result.errors.some((e) => e.includes('method "YEET"')));
  });

  it('errors on missing path', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'bad', method: 'GET' }],
    });
    assert.ok(result.errors.some((e) => e.includes('path is required')));
  });

  it('warns on path param not in inputSchema', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'get_user', method: 'GET', path: '/users/:user_id', inputSchema: { type: 'object', properties: {} } }],
    });
    assert.ok(result.warnings.some((w) => w.includes(':user_id')));
  });

  it('validates chain tools', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [
        {
          name: 'my_chain',
          description: 'A chain',
          chain: [
            { call: 'step_a', as: 'a' },
            { call: 'step_b', as: 'b' },
          ],
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    });
    assert.equal(result.valid, true);
  });

  it('errors on chain step missing call or as', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'bad_chain', chain: [{ call: 'a' }] }],
    });
    assert.ok(result.errors.some((e) => e.includes('chain[0].as')));
  });

  it('errors on duplicate chain step names', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'dup_chain', chain: [{ call: 'a', as: 'x' }, { call: 'b', as: 'x' }] }],
    });
    assert.ok(result.errors.some((e) => e.includes('duplicate chain step')));
  });

  it('warns on missing description', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'no_desc', method: 'GET', path: '/', inputSchema: { type: 'object' } }],
    });
    assert.ok(result.warnings.some((w) => w.includes('missing description')));
  });

  it('warns on missing inputSchema', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'no_schema', description: 'Test', method: 'GET', path: '/' }],
    });
    assert.ok(result.warnings.some((w) => w.includes('missing inputSchema')));
  });

  it('errors when required key is absent from properties — prevents API 400', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{
        name: 'bad_schema',
        description: 'Test',
        method: 'GET',
        path: '/',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string' } },
          required: ['name', 'attributes'], // 'attributes' not in properties
        },
      }],
    });
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes('"attributes"') && e.includes('400')));
  });

  it('passes when all required keys exist in properties', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{
        name: 'good_schema',
        description: 'Test',
        method: 'GET',
        path: '/',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string' }, age: { type: 'integer' } },
          required: ['name'],
        },
      }],
    });
    assert.ok(!result.errors.some((e) => e.includes('required')));
  });

  // ── configVersion schema field (issue #47) ────────────────────────────────
  it('accepts configVersion: 1 without error or warning', () => {
    const result = validateConfig({
      configVersion: 1,
      baseUrl: 'https://api.example.com',
      tools: [
        { name: 'ping', description: 'Ping', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } },
      ],
    });
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
    assert.ok(!result.warnings.some((w) => w.includes('configVersion')));
  });

  it('treats omitted configVersion as valid (implied 1)', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'ping', description: 'Ping', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } }],
    });
    assert.equal(result.valid, true);
    assert.ok(!result.errors.some((e) => e.includes('configVersion')));
  });

  it('rejects configVersion other than 1', () => {
    for (const bad of [2, '1', true, 0, 1.5]) {
      const result = validateConfig({
        configVersion: bad,
        baseUrl: 'https://api.example.com',
        tools: [],
      });
      assert.equal(result.valid, false, `configVersion ${JSON.stringify(bad)} should be rejected`);
      assert.ok(result.errors.some((e) => e.includes('configVersion')));
    }
  });

  it('does not overload version (server-version string) as the schema version', () => {
    // `version: "1.0.0"` is the MCP server-version string and must remain valid.
    const result = validateConfig({
      version: '1.0.0',
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'ping', description: 'Ping', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } }],
    });
    assert.equal(result.valid, true);
    assert.ok(!result.errors.some((e) => e.includes('configVersion') || e.includes('version')));
  });

  // ── tools + mcpServers ambiguity warning (issue #47) ──────────────────────
  it('warns when a config has both tools and mcpServers', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'ping', description: 'Ping', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } }],
      mcpServers: { upstream: { command: '40mcp', args: ['serve', 'x.json'] } },
    });
    const ambiguity = result.warnings.find((w) => w.includes('mcpServers') && w.includes('tools'));
    assert.ok(ambiguity, 'expected an ambiguity warning naming both surfaces');
    assert.ok(ambiguity.includes('link'), 'warning should state which command uses mcpServers');
  });

  it('does not warn for a tools-only config', () => {
    const result = validateConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'ping', description: 'Ping', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } }],
    });
    assert.ok(!result.warnings.some((w) => w.includes('mcpServers')));
  });
});

describe('assertValidConfig', () => {
  it('does not throw on valid config', () => {
    assert.doesNotThrow(() => assertValidConfig({
      baseUrl: 'https://api.example.com',
      tools: [{ name: 'ok', description: 'OK', method: 'GET', path: '/', inputSchema: { type: 'object' } }],
    }));
  });

  it('throws BridgeError on invalid config', () => {
    assert.throws(
      () => assertValidConfig({ tools: 'bad' }),
      (err) => err.bridgeCode === 'CONFIG_INVALID',
    );
  });
});
