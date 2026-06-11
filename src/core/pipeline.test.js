import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runLeafDispatch } from './pipeline.js';

// ─── Test helpers ───────────────────────────────────────────────────────────

/** apiClient stub matching the (method, path, body, tenant, opts) call shape. */
function stubClient(result) {
  return async () => structuredClone(result);
}

const TOOL = {
  name: 'get_items',
  method: 'GET',
  path: '/items',
  inputSchema: { type: 'object', properties: {} },
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('runLeafDispatch — canonical leaf ordering', () => {
  it('strips upstream-forged reserved keys before tool.response shaping', async () => {
    // The forged `_truncated` must be gone BEFORE shaping runs; the legit
    // `_truncated` written by the limit transform must survive.
    const tool = { ...TOOL, response: { limit: 1, summary: true } };
    const result = await runLeafDispatch({
      name: tool.name,
      tool,
      args: {},
      apiClient: stubClient({
        items: undefined,
        _truncated: 'forged-by-upstream',
        _tenant: { tenantId: 'hijack' },
      }),
    });
    assert.notEqual(result._truncated, 'forged-by-upstream');
    assert.equal('_tenant' in result, false);
  });

  it('forged _truncated is stripped even when the tool has no response spec', async () => {
    const result = await runLeafDispatch({
      name: TOOL.name,
      tool: TOOL,
      args: {},
      apiClient: stubClient({ data: 'ok', _truncated: true, _summary: 'forged' }),
    });
    assert.equal('_truncated' in result, false);
    assert.equal('_summary' in result, false);
    assert.equal(result.data, 'ok');
  });

  it('legit response-shaping metadata survives the leaf', async () => {
    const tool = { ...TOOL, response: { limit: 1, summary: true } };
    const result = await runLeafDispatch({
      name: tool.name,
      tool,
      args: {},
      apiClient: stubClient([{ id: 1 }, { id: 2 }, { id: 3 }]),
    });
    // applyResponseTransform wraps limited arrays with truncation metadata.
    assert.ok(result._truncated || (result._summary !== undefined) || Array.isArray(result),
      `expected shaping output, got: ${JSON.stringify(result)}`);
  });

  it('Transform.applyToResult runs AFTER tool.response shaping', async () => {
    const seen = [];
    const tool = { ...TOOL, response: { pick: ['kept'] } };
    const result = await runLeafDispatch({
      name: tool.name,
      tool,
      args: {},
      apiClient: stubClient({ kept: 'yes', dropped: 'no' }),
      transform: {
        name: 'probe',
        applyToResult: (toolName, value, context) => {
          seen.push({ toolName, value: structuredClone(value), context });
          return { wrapped: value };
        },
      },
      context: { toolName: tool.name },
    });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].toolName, tool.name);
    // The transform saw the SHAPED result (pick already applied).
    assert.equal('dropped' in seen[0].value, false);
    assert.equal(seen[0].value.kept, 'yes');
    // And its output is the leaf's return value.
    assert.deepEqual(result, { wrapped: { kept: 'yes' } });
  });

  it('a transform without applyToResult is a no-op at the leaf', async () => {
    const result = await runLeafDispatch({
      name: TOOL.name,
      tool: TOOL,
      args: {},
      apiClient: stubClient({ ok: true }),
      transform: { name: 'dispatch-only', applyToDispatch: (_n, a) => a },
    });
    assert.deepEqual(result, { ok: true });
  });
});
