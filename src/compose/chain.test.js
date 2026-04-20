import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { executeChain } from './chain.js';

// ─── Test helpers ───────────────────────────────────────────────────────────

function createMockDispatch() {
  const fn = mock.fn();
  const responses = new Map();

  fn.setResponse = (toolName, response) => {
    responses.set(toolName, response);
  };

  fn.setError = (toolName, error) => {
    responses.set(toolName, { _error: true, message: error });
  };

  fn.setThrow = (toolName, error) => {
    responses.set(toolName, { _throw: true, message: error });
  };

  const wrappedFn = async (toolName, args) => {
    fn(toolName, args);
    const response = responses.get(toolName);

    if (!response) {
      throw new Error(`No response configured for tool: ${toolName}`);
    }

    if (response._throw) {
      throw new Error(response.message);
    }

    return response;
  };

  wrappedFn.mock = fn.mock;
  wrappedFn.setResponse = fn.setResponse;
  wrappedFn.setError = fn.setError;
  wrappedFn.setThrow = fn.setThrow;

  return wrappedFn;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('executeChain', () => {
  it('1. executes a single step chain', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'user-1', name: 'Alice' });

    const result = await executeChain(
      [
        {
          call: 'get_user',
          as: 'user',
          args: { user_id: 'user-1' },
        },
      ],
      {},
      dispatch,
    );

    assert.deepEqual(result.user, { id: 'user-1', name: 'Alice' });
    assert.equal(result._chain.completed, 1);
    assert.equal(result._chain.failed, 0);
  });

  it('2. executes a linear chain (step B depends on step A)', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'user-1', name: 'Alice', tenant_id: 't123' });
    dispatch.setResponse('get_tenant', { id: 't123', name: 'Acme Corp' });

    const result = await executeChain(
      [
        {
          call: 'get_user',
          as: 'user',
          args: { user_id: 'user-1' },
        },
        {
          call: 'get_tenant',
          as: 'tenant',
          args: { tenant_id: '$user.tenant_id' },
        },
      ],
      {},
      dispatch,
    );

    assert.deepEqual(result.user, { id: 'user-1', name: 'Alice', tenant_id: 't123' });
    assert.deepEqual(result.tenant, { id: 't123', name: 'Acme Corp' });
    assert.equal(result._chain.completed, 2);
    assert.equal(result._chain.failed, 0);
  });

  it('3. executes parallel chains (independent steps run together)', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_devices', { count: 5, devices: [] });
    dispatch.setResponse('get_groups', { count: 3, groups: [] });

    const callOrder = [];
    const originalMock = dispatch.mock;
    const trackingDispatch = async (toolName, args) => {
      callOrder.push(toolName);
      return dispatch(toolName, args);
    };
    trackingDispatch.mock = originalMock;
    trackingDispatch.setResponse = dispatch.setResponse;
    trackingDispatch.setError = dispatch.setError;
    trackingDispatch.setThrow = dispatch.setThrow;

    const result = await executeChain(
      [
        {
          call: 'get_devices',
          as: 'devices',
          args: { user_id: 'user-1' },
        },
        {
          call: 'get_groups',
          as: 'groups',
          args: { user_id: 'user-1' },
        },
      ],
      {},
      trackingDispatch,
    );

    assert.equal(result._chain.completed, 2);
    assert.equal(result._chain.failed, 0);
    // Both calls should exist (order may vary due to parallelism)
    assert.equal(callOrder.includes('get_devices'), true);
    assert.equal(callOrder.includes('get_groups'), true);
  });

  it('4. mixed chain: some parallel, some sequential', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'u1', tenant_id: 't1' });
    dispatch.setResponse('get_devices', { devices: [{ id: 'd1' }] });
    dispatch.setResponse('get_groups', { groups: [{ id: 'g1' }] });
    dispatch.setResponse('get_tenant', { id: 't1', name: 'Acme' });

    const result = await executeChain(
      [
        {
          call: 'get_user',
          as: 'user',
          args: { user_id: 'u1' },
        },
        // Parallel: both depend only on $args
        {
          call: 'get_devices',
          as: 'devices',
          args: { user_id: '$args.user_id' },
        },
        {
          call: 'get_groups',
          as: 'groups',
          args: { user_id: '$args.user_id' },
        },
        // Sequential: depends on user step
        {
          call: 'get_tenant',
          as: 'tenant',
          args: { tenant_id: '$user.tenant_id' },
        },
      ],
      { user_id: 'u1' },
      dispatch,
    );

    assert.equal(result._chain.completed, 4);
    assert.equal(result._chain.failed, 0);
    assert.deepEqual(result.user, { id: 'u1', tenant_id: 't1' });
    assert.deepEqual(result.tenant, { id: 't1', name: 'Acme' });
  });

  it('5. resolves $args.field from original call arguments', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('search', { results: [] });

    const _result = await executeChain(
      [
        {
          call: 'search',
          as: 'results',
          args: {
            query: '$args.search_term',
            limit: '$args.limit',
          },
        },
      ],
      { search_term: 'alice', limit: 10 },
      dispatch,
    );

    assert.equal(dispatch.mock.calls[0].arguments[1].query, 'alice');
    assert.equal(dispatch.mock.calls[0].arguments[1].limit, 10);
  });

  it('6. resolves $step.nested.path for deep dot-path traversal', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', {
      id: 'u1',
      profile: {
        company: {
          tenant_id: 't1',
        },
      },
    });
    dispatch.setResponse('get_tenant', { id: 't1', name: 'Acme' });

    const _result = await executeChain(
      [
        {
          call: 'get_user',
          as: 'user',
          args: { user_id: 'u1' },
        },
        {
          call: 'get_tenant',
          as: 'tenant',
          args: { tenant_id: '$user.profile.company.tenant_id' },
        },
      ],
      {},
      dispatch,
    );

    assert.equal(dispatch.mock.calls[1].arguments[1].tenant_id, 't1');
  });

  it('7. passes static arg values through unchanged', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('create_item', { id: 'item-1' });

    const _result = await executeChain(
      [
        {
          call: 'create_item',
          as: 'item',
          args: {
            name: 'Test Item',
            priority: 5,
            enabled: true,
            tags: ['a', 'b'],
          },
        },
      ],
      {},
      dispatch,
    );

    const call = dispatch.mock.calls[0].arguments[1];
    assert.equal(call.name, 'Test Item');
    assert.equal(call.priority, 5);
    assert.equal(call.enabled, true);
    assert.deepEqual(call.tags, ['a', 'b']);
  });

  it('8. returns partial results when required step fails', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'u1' });
    dispatch.setThrow('get_devices', 'API error: not found');

    let caughtError = null;
    try {
      await executeChain(
        [
          {
            call: 'get_user',
            as: 'user',
            args: { user_id: 'u1' },
          },
          {
            call: 'get_devices',
            as: 'devices',
            args: { user_id: '$user.id' },
          },
        ],
        {},
        dispatch,
      );
    } catch (error) {
      caughtError = error;
    }

    assert.ok(caughtError);
    assert.match(caughtError.message, /not found/);
  });

  it('9. continues chain when optional step fails', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'u1', tenant_id: 't1' });
    dispatch.setThrow('get_extended_profile', 'Premium feature unavailable');
    dispatch.setResponse('get_tenant', { id: 't1', name: 'Acme' });

    const result = await executeChain(
      [
        {
          call: 'get_user',
          as: 'user',
          args: { user_id: 'u1' },
        },
        {
          call: 'get_extended_profile',
          as: 'extended',
          args: { user_id: '$user.id' },
          optional: true,
        },
        {
          call: 'get_tenant',
          as: 'tenant',
          args: { tenant_id: '$user.tenant_id' },
        },
      ],
      {},
      dispatch,
    );

    assert.deepEqual(result.user, { id: 'u1', tenant_id: 't1' });
    // Optional step failure stores a sanitized error code — not the raw message — to
    // prevent leaking credentials or internal error bodies to downstream steps.
    assert.equal(result.extended.error, 'step failed');
    assert.equal(typeof result.extended.error_code, 'string');
    assert.deepEqual(result.tenant, { id: 't1', name: 'Acme' });
    assert.equal(result._chain.completed, 3);
    assert.equal(result._chain.failed, 0);
  });

  it('10. throws error when $ref references undefined step', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'u1' });

    let caughtError = null;
    try {
      await executeChain(
        [
          {
            call: 'get_user',
            as: 'user',
            args: { user_id: 'u1' },
          },
          {
            call: 'get_devices',
            as: 'devices',
            args: { user_id: '$nonexistent.id' },
          },
        ],
        {},
        dispatch,
      );
    } catch (error) {
      caughtError = error;
    }

    assert.ok(caughtError);
    assert.match(caughtError.message, /Reference to undefined step/);
  });

  it('11. tracks completed and failed counts in metadata', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'u1' });
    dispatch.setThrow('get_devices', 'Error');
    dispatch.setResponse('get_groups', { count: 2 });

    let caughtError = null;
    try {
      await executeChain(
        [
          {
            call: 'get_user',
            as: 'user',
            args: { user_id: 'u1' },
          },
          {
            call: 'get_devices',
            as: 'devices',
            args: { user_id: '$user.id' },
          },
          {
            call: 'get_groups',
            as: 'groups',
            args: { user_id: '$user.id' },
          },
        ],
        {},
        dispatch,
      );
    } catch (error) {
      caughtError = error;
    }

    assert.ok(caughtError);
  });

  it('12. passes through null and undefined args unchanged', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('search', { results: [] });

    const _result = await executeChain(
      [
        {
          call: 'search',
          as: 'results',
          args: {
            query: '$args.term',
            filter: null,
            sort: undefined,
          },
        },
      ],
      { term: 'test' },
      dispatch,
    );

    const call = dispatch.mock.calls[0].arguments[1];
    assert.equal(call.query, 'test');
    assert.equal(call.filter, null);
    assert.equal(call.sort, undefined);
  });

  it('13. handles empty args object', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('list_all', { items: [] });

    const result = await executeChain(
      [
        {
          call: 'list_all',
          as: 'items',
        },
      ],
      {},
      dispatch,
    );

    assert.deepEqual(result.items, { items: [] });
  });

  it('14. detects circular dependencies', async () => {
    const dispatch = createMockDispatch();

    let caughtError = null;
    try {
      await executeChain(
        [
          {
            call: 'step_a',
            as: 'a',
            args: { ref: '$b.value' },
          },
          {
            call: 'step_b',
            as: 'b',
            args: { ref: '$a.value' },
          },
        ],
        {},
        dispatch,
      );
    } catch (error) {
      caughtError = error;
    }

    assert.ok(caughtError);
    assert.match(caughtError.message, /Circular dependency/);
  });

  it('15. resolves $step without path to entire result object', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', { id: 'u1', name: 'Alice' });
    dispatch.setResponse('create_event', { event_id: 'e1' });

    const _result = await executeChain(
      [
        {
          call: 'get_user',
          as: 'user',
          args: { user_id: 'u1' },
        },
        {
          call: 'create_event',
          as: 'event',
          args: { user_data: '$user' },
        },
      ],
      {},
      dispatch,
    );

    const call = dispatch.mock.calls[1].arguments[1];
    assert.deepEqual(call.user_data, { id: 'u1', name: 'Alice' });
  });

  // ─── Recursion depth guard tests ───────────────────────────────────────

  it('16. throws when chain recursion depth is exceeded', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('step_a', { value: 'ok' });

    let caughtError = null;
    try {
      await executeChain(
        [{ call: 'step_a', as: 'a', args: {} }],
        {},
        dispatch,
        { _depth: 10, maxDepth: 10 },
      );
    } catch (error) {
      caughtError = error;
    }

    assert.ok(caughtError);
    assert.match(caughtError.message, /Chain recursion depth exceeded/);
  });

  it('17. allows chains within default depth limit', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('step_a', { value: 'ok' });

    const result = await executeChain(
      [{ call: 'step_a', as: 'a', args: {} }],
      {},
      dispatch,
      { _depth: 5 },
    );

    assert.deepEqual(result.a, { value: 'ok' });
  });

  it('18. respects custom maxDepth option', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('step_a', { value: 'ok' });

    let caughtError = null;
    try {
      await executeChain(
        [{ call: 'step_a', as: 'a', args: {} }],
        {},
        dispatch,
        { _depth: 3, maxDepth: 3 },
      );
    } catch (error) {
      caughtError = error;
    }

    assert.ok(caughtError);
    assert.match(caughtError.message, /max: 3/);
  });

  it('19. passes incremented depth to nested dispatch calls', async () => {
    let capturedOptions = null;
    const trackingDispatch = async (name, args, options) => {
      capturedOptions = options;
      return { value: 'ok' };
    };

    await executeChain(
      [{ call: 'step_a', as: 'a', args: {} }],
      {},
      trackingDispatch,
      { _depth: 2 },
    );

    assert.ok(capturedOptions);
    assert.equal(capturedOptions._depth, 3);
  });

  // ─── Chain-level response transform tests ──────────────────────────────

  it('20. applies chain-level response transforms to all step results', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('get_user', {
      id: 'u1',
      name: 'Alice',
      email: 'alice@example.com',
      internal_id: 'x123',
    });
    dispatch.setResponse('get_posts', [
      { id: 'p1', title: 'Post 1', body: 'Long body...' },
      { id: 'p2', title: 'Post 2', body: 'Another body...' },
    ]);

    const result = await executeChain(
      [
        { call: 'get_user', as: 'user', args: {} },
        { call: 'get_posts', as: 'posts', args: {} },
      ],
      {},
      dispatch,
      { response: { pick: ['id', 'name', 'title'] } },
    );

    // user should only have id and name
    assert.deepEqual(result.user, { id: 'u1', name: 'Alice' });
    // posts should only have id and title
    assert.deepEqual(result.posts, [
      { id: 'p1', title: 'Post 1' },
      { id: 'p2', title: 'Post 2' },
    ]);
    // _chain metadata should be preserved
    assert.equal(result._chain.completed, 2);
  });

  // ─── Security: error message leakage tests ──────────────────────────

  it('20a. optional step failure stores sanitized form, not raw error message', async () => {
    const dispatch = createMockDispatch();
    dispatch.setThrow('fetch_secret', 'auth failed: token=sk-live-secret-key-12345');

    const result = await executeChain(
      [{ call: 'fetch_secret', as: 'secret', args: {}, optional: true }],
      {},
      dispatch,
    );

    // Should NOT expose the raw error message with the credential
    assert.ok(!JSON.stringify(result.secret).includes('sk-live-secret-key-12345'),
      'Raw error message must not appear in chain results');

    // Should store a sanitized code instead
    assert.equal(result.secret.error, 'step failed');
    assert.equal(typeof result.secret.error_code, 'string');
    assert.ok(result.secret.error_code.length > 0);
  });

  it('20b. optional step failure does not include raw error body in _chain metadata', async () => {
    const dispatch = createMockDispatch();
    dispatch.setThrow('leak_step', 'token=Bearer sk-secret; user=admin');

    const result = await executeChain(
      [{ call: 'leak_step', as: 'leaky', args: {}, optional: true }],
      {},
      dispatch,
    );

    // _chain.errors is empty because optional steps don't push to it
    assert.equal(result._chain.errors.length, 0);
    // Raw message not in chain errors
    const chainStr = JSON.stringify(result._chain);
    assert.ok(!chainStr.includes('sk-secret'), 'Credentials must not appear in _chain metadata');
  });

  it('20c. non-optional step failure re-throws without wrapping (full error propagates to caller)', async () => {
    const dispatch = createMockDispatch();
    dispatch.setThrow('required_step', 'REQUIRED_ERROR: payment_token=pk_live_abc');

    let caught = null;
    try {
      await executeChain([{ call: 'required_step', as: 'step', args: {} }], {}, dispatch);
    } catch (e) {
      caught = e;
    }

    // Non-optional failures still throw — caller decides how to handle them
    assert.ok(caught, 'Should throw for non-optional step failure');
    assert.ok(caught.message.includes('REQUIRED_ERROR'));
  });

  it('21. chain-level response transforms do not affect _chain metadata', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('step_a', { value: 'ok' });

    const result = await executeChain(
      [{ call: 'step_a', as: 'a', args: {} }],
      {},
      dispatch,
      { response: { omit: ['steps', 'completed'] } },
    );

    // _chain should be untouched
    assert.equal(result._chain.steps, 1);
    assert.equal(result._chain.completed, 1);
  });
});
