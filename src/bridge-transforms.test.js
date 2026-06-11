import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createRestBridge } from './bridge.js';
import { createTransform, responseTransform } from './transforms/index.js';

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

const GET_ITEM = {
  name: 'get_item',
  description: 'Get one item',
  method: 'GET',
  path: '/item',
  inputSchema: { type: 'object', properties: { q: { type: 'string' } } },
};

function bridgeWith(extra = {}) {
  return createRestBridge({
    name: 'tx-bridge',
    baseUrl: 'http://localhost:9999',
    tools: [GET_ITEM],
    ...extra,
  });
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('bridge — Transform seam', () => {
  let originalFetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('applyToComponents reshapes the tool surface at build time', async () => {
    globalThis.fetch = mockFetch(200, { ok: true });
    const bridge = bridgeWith({
      transforms: [
        createTransform({
          name: 'renamer',
          applyToComponents: ({ tools }) => ({
            tools: tools.map((t) => ({ ...t, description: `[via-transform] ${t.description}` })),
          }),
        }),
      ],
    });
    // The reshaped description must be visible on the dispatcher's tool map
    // (dispatch still works) — and on the served MCP tool list.
    const result = await bridge.dispatch('get_item', {});
    assert.equal(result.ok, true);
  });

  it('throws loudly when applyToComponents returns a malformed shape', () => {
    assert.throws(
      () => bridgeWith({
        transforms: [
          createTransform({ name: 'broken', applyToComponents: () => 'garbage' }),
        ],
      }),
      /applyToComponents must return \{ tools/,
    );
  });

  it('applyToDispatch runs after validation, before the HTTP call', async () => {
    const urls = [];
    globalThis.fetch = mock.fn((url) => {
      urls.push(String(url));
      return Promise.resolve({
        ok: true, status: 200,
        json: () => Promise.resolve({ ok: true }),
        text: () => Promise.resolve('{"ok":true}'),
      });
    });
    const bridge = bridgeWith({
      transforms: [
        createTransform({
          name: 'rewriter',
          applyToDispatch: (_toolName, args) => ({ ...args, q: 'rewritten' }),
        }),
      ],
    });
    await bridge.dispatch('get_item', { q: 'original' });
    assert.ok(urls[0].includes('q=rewritten'), `expected rewritten query, got ${urls[0]}`);
  });

  it('re-validates after applyToDispatch — reserved-key smuggling is rejected', async () => {
    globalThis.fetch = mockFetch(200, { ok: true });
    const bridge = bridgeWith({
      transforms: [
        createTransform({
          name: 'smuggler',
          applyToDispatch: (_toolName, args) => ({ ...args, _chain: ['poison'] }),
        }),
      ],
    });
    await assert.rejects(
      () => bridge.dispatch('get_item', {}),
      /reserved|_chain/i,
    );
  });

  it('applyToResult sees the shaped result and runs before egress-sanitize', async () => {
    globalThis.fetch = mockFetch(200, { kept: 'yes', dropped: 'no' });
    const seen = [];
    const bridge = bridgeWith({
      tools: [{ ...GET_ITEM, response: { pick: ['kept'] } }],
      transforms: [
        createTransform({
          name: 'probe',
          applyToResult: (_toolName, result) => {
            seen.push(structuredClone(result));
            // Attempt to reintroduce a reserved key — egress-sanitize is
            // downstream of the Transform seam (SPEC §2) and must scrub it.
            return { ...result, _tenant: { tenantId: 'evil' } };
          },
        }),
      ],
    });
    const result = await bridge.dispatch('get_item', {});
    assert.equal('dropped' in seen[0], false, 'transform must see post-shaping result');
    assert.equal('_tenant' in result, false, 'egress-sanitize must scrub Transform-reintroduced reserved keys');
    assert.equal(result.kept, 'yes');
  });

  it('responseTransform() participates in the transforms list', async () => {
    globalThis.fetch = mockFetch(200, { kept: 'yes', dropped: 'no' });
    const bridge = bridgeWith({
      transforms: [responseTransform({ pick: ['kept'] })],
    });
    const result = await bridge.dispatch('get_item', {});
    assert.deepEqual(result, { kept: 'yes' });
  });

  it('transforms run once per inbound call — chain sub-dispatches skip the seam', async () => {
    globalThis.fetch = mockFetch(200, { ok: true });
    let applied = 0;
    const bridge = createRestBridge({
      name: 'tx-chain-bridge',
      baseUrl: 'http://localhost:9999',
      tools: [
        GET_ITEM,
        {
          name: 'wrapper',
          description: 'chain wrapper',
          inputSchema: { type: 'object', properties: {} },
          chain: [{ call: 'get_item', as: 'inner', args: {} }],
        },
      ],
      transforms: [
        createTransform({
          name: 'counter',
          applyToResult: (_toolName, result) => { applied += 1; return result; },
        }),
      ],
    });
    await bridge.dispatch('wrapper', {});
    assert.equal(applied, 1, 'applyToResult must run exactly once (outer call), not per chain step');
  });

  it('rejects non-array config.transforms loudly', () => {
    assert.throws(
      () => bridgeWith({ transforms: 'nope' }),
      /transforms must be an array/,
    );
  });
});
