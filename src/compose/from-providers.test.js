import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createBridgeFromProviders } from './from-providers.js';
import { createProvider, componentsFromProviders, har } from '../providers/index.js';

// ─── Test helpers ───────────────────────────────────────────────────────────

function mockFetch(status, body) {
  return mock.fn(() =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    }),
  );
}

function toolDef(name) {
  return {
    name,
    description: `tool ${name}`,
    method: 'GET',
    path: `/${name}`,
    inputSchema: { type: 'object', properties: {} },
  };
}

function inlineProvider(name, tools, close) {
  return createProvider({
    name,
    components: async () => ({ tools }),
    ...(close ? { close } : {}),
  });
}

// ─── componentsFromProviders ────────────────────────────────────────────────

describe('componentsFromProviders', () => {
  it('gathers tools from multiple providers in order', async () => {
    const { tools } = await componentsFromProviders([
      inlineProvider('a', [toolDef('alpha')]),
      inlineProvider('b', [toolDef('beta'), toolDef('gamma')]),
    ]);
    assert.deepEqual(tools.map((t) => t.name), ['alpha', 'beta', 'gamma']);
  });

  it('fails loudly on duplicate tool names across providers', async () => {
    await assert.rejects(
      () => componentsFromProviders([
        inlineProvider('a', [toolDef('dup')]),
        inlineProvider('b', [toolDef('dup')]),
      ]),
      /Duplicate tool name "dup".*"b".*"a"/s,
    );
  });

  it('rejects providers whose components() returns a malformed shape', async () => {
    await assert.rejects(
      () => componentsFromProviders([
        { name: 'bad', components: async () => 'garbage' },
      ]),
      /did not return \{ tools/,
    );
  });

  it('rejects an empty provider list', async () => {
    await assert.rejects(() => componentsFromProviders([]), /non-empty array/);
  });
});

// ─── createBridgeFromProviders ──────────────────────────────────────────────

describe('createBridgeFromProviders', () => {
  let originalFetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('builds a working bridge from provider tools', async () => {
    globalThis.fetch = mockFetch(200, { ok: true });
    const bridge = await createBridgeFromProviders({
      name: 'from-providers',
      baseUrl: 'http://localhost:9999',
      providers: [inlineProvider('p', [toolDef('ping')])],
    });
    const result = await bridge.dispatch('ping', {});
    assert.equal(result.ok, true);
  });

  it('merges literal config.tools with provider tools, failing on collision', async () => {
    await assert.rejects(
      () => createBridgeFromProviders({
        name: 'collide',
        baseUrl: 'http://localhost:9999',
        tools: [toolDef('ping')],
        providers: [inlineProvider('p', [toolDef('ping')])],
      }),
      /Duplicate tool name "ping"/,
    );
  });

  it('close() drains the bridge then closes every provider', async () => {
    globalThis.fetch = mockFetch(200, { ok: true });
    const closed = [];
    const bridge = await createBridgeFromProviders({
      name: 'lifecycle',
      baseUrl: 'http://localhost:9999',
      providers: [
        inlineProvider('p1', [toolDef('one')], async () => { closed.push('p1'); }),
        inlineProvider('p2', [toolDef('two')], async () => { closed.push('p2'); }),
      ],
    });
    await bridge.close();
    assert.deepEqual(closed, ['p1', 'p2']);
  });
});

// ─── Loader adapters ────────────────────────────────────────────────────────

describe('provider adapters', () => {
  it('har() adapts an in-memory HAR object into Provider components', async () => {
    const harObject = {
      log: {
        entries: [
          {
            request: {
              method: 'GET',
              url: 'https://api.example.com/users',
              headers: [],
              queryString: [],
            },
            response: {
              status: 200,
              headers: [{ name: 'Content-Type', value: 'application/json' }],
              content: { mimeType: 'application/json', text: '[{"id":1}]' },
            },
            time: 50,
          },
        ],
      },
    };
    const provider = har(harObject, { name: 'legacy-api' });
    assert.equal(provider.name, 'legacy-api');
    const { tools } = await provider.components();
    assert.ok(Array.isArray(tools) && tools.length >= 1, 'expected at least one tool from HAR');
    assert.ok(tools[0].name, 'tool must have a name');
  });
});
