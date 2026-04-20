import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createTenantScope, tenantAuthHook } from './scope.js';

// ─── Test helpers ───────────────────────────────────────────────────────────

function createMockDispatch() {
  return mock.fn(async (toolName, args) => {
    return { tool: toolName, args };
  });
}

// ─── createTenantScope tests ────────────────────────────────────────────────

describe('createTenantScope', () => {
  it('throws if dispatch is missing', () => {
    assert.throws(
      () => createTenantScope({ resolveContext: async () => ({}) }),
      (err) => err.message.includes('dispatch'),
    );
  });

  it('throws if resolveContext is missing', () => {
    assert.throws(
      () => createTenantScope({ dispatch: async () => {} }),
      (err) => err.message.includes('resolveContext'),
    );
  });

  it('resolves tenant context and injects _tenant metadata', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'tenant-1',
        auth: { type: 'bearer', value: 'tok_abc' },
        metadata: { region: 'us-east' },
      }),
    });

    await scoped('list_users', { limit: 10 });

    assert.equal(dispatch.mock.calls.length, 1);
    const callArgs = dispatch.mock.calls[0].arguments[1];
    assert.equal(callArgs.limit, 10);
    assert.equal(callArgs._tenant.tenantId, 'tenant-1');
    assert.equal(callArgs._tenant.auth.type, 'bearer');
    assert.equal(callArgs._tenant.auth.value, 'tok_abc');
    assert.equal(callArgs._tenant.metadata.region, 'us-east');
  });

  it('injects _tenant as a non-enumerable property to prevent leakage', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'tenant-1',
        auth: { type: 'bearer', value: 'tok_secret' },
      }),
    });

    await scoped('some_tool', { userId: 42 });

    const callArgs = dispatch.mock.calls[0].arguments[1];

    // _tenant must be accessible (still works for hooks)
    assert.ok(callArgs._tenant, '_tenant must be accessible on the args object');
    assert.equal(callArgs._tenant.tenantId, 'tenant-1');

    // But must NOT appear in JSON.stringify or Object.keys (non-enumerable)
    const serialized = JSON.stringify(callArgs);
    assert.ok(!serialized.includes('_tenant'), '_tenant must not appear in JSON.stringify output');
    assert.ok(!Object.keys(callArgs).includes('_tenant'), '_tenant must not appear in Object.keys()');
  });

  it('uses defaults when resolveContext returns null and allowFallback is true', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => null,
      defaults: {
        tenantId: 'default-tenant',
        auth: { type: 'bearer', value: 'default-tok' },
        allowFallback: true,
      },
    });

    await scoped('ping', {});

    const callArgs = dispatch.mock.calls[0].arguments[1];
    assert.equal(callArgs._tenant.tenantId, 'default-tenant');
    assert.equal(callArgs._tenant.auth.value, 'default-tok');
  });

  it('denies dispatch when resolveContext returns null without allowFallback (CVE: ACL bypass)', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => null,
      defaults: {
        tenantId: 'default-tenant',
        auth: { type: 'bearer', value: 'default-tok' },
        // No allowFallback — must be explicit
      },
    });

    await assert.rejects(
      () => scoped('ping', {}),
      (err) => err.message.includes('allowFallback'),
    );
    assert.equal(dispatch.mock.calls.length, 0);
  });

  it('strips attacker-supplied _tenant from incoming args', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'legit-tenant',
        auth: { type: 'bearer', value: 'legit-tok' },
      }),
    });

    await scoped('ping', {
      _tenant: { tenantId: 'attacker', auth: { type: 'bearer', value: 'evil-tok' } },
      payload: 'data',
    });

    const callArgs = dispatch.mock.calls[0].arguments[1];
    assert.equal(callArgs._tenant.tenantId, 'legit-tenant');
    assert.equal(callArgs._tenant.auth.value, 'legit-tok');
    assert.equal(callArgs.payload, 'data');
  });

  it('throws when no tenant context and no defaults', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({}),
    });

    await assert.rejects(
      () => scoped('ping', {}),
      (err) => err.message.includes('tenantId is required'),
    );
  });

  it('enforces allowlist', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'tenant-1',
        allowlist: ['list_users', 'get_user'],
      }),
    });

    // Allowed tool
    await scoped('list_users', {});
    assert.equal(dispatch.mock.calls.length, 1);

    // Blocked tool
    await assert.rejects(
      () => scoped('delete_user', {}),
      (err) => err.message.includes('not in tenant') && err.message.includes('allowlist'),
    );
  });

  it('REJECTS allowlist passed as a string (substring-bypass guard)', async () => {
    // A tenant context that carries `allowlist: "list_users"` (a raw string,
    // e.g. from a JSON config typo with a single value instead of an array)
    // would previously hit String.prototype.includes — which does SUBSTRING
    // matching, not exact-element matching. Any tool name that is a
    // substring of the allowlist string would have been accepted. The fix
    // requires allowlist to be an array and throws on any other type.
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'tenant-1',
        allowlist: 'list_users', // string, not array
      }),
    });
    await assert.rejects(
      () => scoped('list_users', {}),
      (err) => err.message.includes('allowlist') && err.message.includes('array'),
    );
    assert.equal(dispatch.mock.calls.length, 0);
  });

  it('treats an empty allowlist as deny-all (hardening)', async () => {
    // Previously: `allowlist: []` short-circuited past the inclusion check
    // and permitted every tool (a foot-gun for operators suspending a tenant
    // by clearing the allowlist). Now an empty array means NO tools allowed.
    // Operators who want "no restriction" must OMIT the allowlist field.
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'suspended',
        allowlist: [], // explicit empty array = deny-all
      }),
    });
    await assert.rejects(
      () => scoped('any_tool', {}),
      (err) => err.message.includes('not in tenant') && err.message.includes('allowlist'),
    );
    assert.equal(dispatch.mock.calls.length, 0);
  });

  it('REJECTS blocklist passed as a string', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'tenant-1',
        blocklist: 'admin_delete',
      }),
    });
    await assert.rejects(
      () => scoped('ping', {}),
      (err) => err.message.includes('blocklist') && err.message.includes('array'),
    );
    assert.equal(dispatch.mock.calls.length, 0);
  });

  it('enforces blocklist', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'tenant-1',
        blocklist: ['admin_reset', 'delete_all'],
      }),
    });

    // Allowed tool
    await scoped('list_users', {});
    assert.equal(dispatch.mock.calls.length, 1);

    // Blocked tool
    await assert.rejects(
      () => scoped('admin_reset', {}),
      (err) => err.message.includes('blocked'),
    );
  });

  it('merges defaults metadata with context metadata', async () => {
    const dispatch = createMockDispatch();
    const scoped = createTenantScope({
      dispatch,
      resolveContext: async () => ({
        tenantId: 'tenant-1',
        metadata: { feature_flag: true },
      }),
      defaults: {
        tenantId: 'fallback',
        metadata: { env: 'production' },
      },
    });

    await scoped('ping', {});

    const callArgs = dispatch.mock.calls[0].arguments[1];
    assert.equal(callArgs._tenant.metadata.env, 'production');
    assert.equal(callArgs._tenant.metadata.feature_flag, true);
  });

  it('passes requestMeta to resolveContext', async () => {
    const dispatch = createMockDispatch();
    const resolveContext = mock.fn(async (meta) => ({
      tenantId: meta?.headers?.['x-tenant-id'] || 'unknown',
    }));

    const scoped = createTenantScope({ dispatch, resolveContext });

    await scoped('ping', {}, { headers: { 'x-tenant-id': 'tenant-42' } });

    assert.equal(resolveContext.mock.calls.length, 1);
    const callArgs = dispatch.mock.calls[0].arguments[1];
    assert.equal(callArgs._tenant.tenantId, 'tenant-42');
  });

  it('acceptance: concurrent tenant calls do not bleed state across tenants', async () => {
    const dispatch = mock.fn(async (toolName, args) => {
      // Simulate async work — delay to make overlap likely
      await new Promise((r) => setTimeout(r, 10));
      // Return the tenant context that was injected
      return {
        tool: toolName,
        tenantSeen: args._tenant?.tenantId,
        authSeen: args._tenant?.auth?.value,
      };
    });

    const scoped = createTenantScope({
      dispatch,
      resolveContext: async (meta) => ({
        tenantId: meta.tenantId,
        auth: { type: 'bearer', value: `tok_${meta.tenantId}` },
      }),
    });

    // Fire both tenant requests simultaneously (high overlap)
    const [r1, r2] = await Promise.all([
      scoped('get_data', {}, { tenantId: 'tenant-A' }),
      scoped('get_data', {}, { tenantId: 'tenant-B' }),
    ]);

    // Each result must reflect its own tenant, not the other's
    assert.equal(r1.tenantSeen, 'tenant-A', 'Tenant A call must see tenant-A context');
    assert.equal(r2.tenantSeen, 'tenant-B', 'Tenant B call must see tenant-B context');
    assert.equal(r1.authSeen, 'tok_tenant-A', 'Tenant A call must see its own auth token');
    assert.equal(r2.authSeen, 'tok_tenant-B', 'Tenant B call must see its own auth token');
  });

  it('acceptance: concurrent tenants respect independent allowlists', async () => {
    const dispatch = createMockDispatch();

    const scoped = createTenantScope({
      dispatch,
      resolveContext: async (meta) => ({
        tenantId: meta.tenantId,
        allowlist: meta.allowlist,
      }),
    });

    // Tenant A can only call tool_a; Tenant B can only call tool_b
    const tenantACall = scoped('tool_a', {}, {
      tenantId: 'tenant-A',
      allowlist: ['tool_a'],
    });

    const tenantBCall = scoped('tool_b', {}, {
      tenantId: 'tenant-B',
      allowlist: ['tool_b'],
    });

    // Both should succeed without blocking the other
    const [_r1, _r2] = await Promise.all([tenantACall, tenantBCall]);

    assert.equal(dispatch.mock.calls.length, 2, 'Both calls should dispatch');
    assert.equal(dispatch.mock.calls[0].arguments[0], 'tool_a');
    assert.equal(dispatch.mock.calls[1].arguments[0], 'tool_b');
  });

  it('acceptance: concurrent calls with different metadata do not cross-contaminate', async () => {
    const dispatch = mock.fn(async (toolName, args) => {
      await new Promise((r) => setTimeout(r, 15));
      return {
        tool: toolName,
        regionSeen: args._tenant?.metadata?.region,
        featureSeen: args._tenant?.metadata?.feature,
      };
    });

    const scoped = createTenantScope({
      dispatch,
      resolveContext: async (meta) => ({
        tenantId: meta.tenantId,
        metadata: {
          region: meta.region,
          feature: meta.feature,
        },
      }),
    });

    // Fire three concurrent calls with different metadata
    const [r1, r2, r3] = await Promise.all([
      scoped('check_feature', {}, { tenantId: 'tenant-A', region: 'us-east', feature: 'flagA' }),
      scoped('check_feature', {}, { tenantId: 'tenant-B', region: 'eu-west', feature: 'flagB' }),
      scoped('check_feature', {}, { tenantId: 'tenant-C', region: 'ap-south', feature: 'flagC' }),
    ]);

    assert.equal(r1.regionSeen, 'us-east');
    assert.equal(r1.featureSeen, 'flagA');

    assert.equal(r2.regionSeen, 'eu-west');
    assert.equal(r2.featureSeen, 'flagB');

    assert.equal(r3.regionSeen, 'ap-south');
    assert.equal(r3.featureSeen, 'flagC');
  });
});

// ─── tenantAuthHook tests ───────────────────────────────────────────────────

describe('tenantAuthHook', () => {
  it('injects bearer auth header from req.tenant', async () => {
    const hook = tenantAuthHook();
    const result = await hook({
      method: 'GET',
      url: 'https://api.example.com/users',
      headers: {},
      body: { limit: 10 },
      tenant: {
        tenantId: 'tenant-1',
        auth: { type: 'bearer', value: 'tok_abc' },
      },
    });

    assert.equal(result.headers['Authorization'], 'Bearer tok_abc');
    // Hook no longer returns body/args — just headers.
    assert.equal(result.body, undefined);
  });

  it('injects custom header auth from req.tenant', async () => {
    const hook = tenantAuthHook();
    const result = await hook({
      method: 'GET',
      url: 'https://api.example.com',
      headers: {},
      body: {},
      tenant: {
        tenantId: 'tenant-1',
        auth: { type: 'header', header: 'X-API-Key', value: 'key_123' },
      },
    });

    assert.equal(result.headers['X-API-Key'], 'key_123');
  });

  it('Refuses attacker-controlled body._tenant fallback', async () => {
    const hook = tenantAuthHook();
    // Body contains `_tenant` but `req.tenant` is absent — a malicious
    // client submitting JSON with an `_tenant` field must NOT succeed
    // in injecting auth headers on outbound requests.
    const result = await hook({
      method: 'GET',
      url: 'https://api.example.com',
      headers: {},
      body: {
        _tenant: {
          tenantId: 'attacker',
          auth: { type: 'bearer', value: 'stolen_token' },
        },
      },
    });
    assert.equal(result, null);
  });

  it('returns null when no _tenant auth', async () => {
    const hook = tenantAuthHook();
    const result = await hook({
      method: 'GET',
      url: 'https://api.example.com',
      headers: {},
      body: { limit: 10 },
    });

    assert.equal(result, null);
  });

  it('returns null when body is empty', async () => {
    const hook = tenantAuthHook();
    const result = await hook({
      method: 'GET',
      url: 'https://api.example.com',
      headers: {},
      body: null,
    });

    assert.equal(result, null);
  });
});

// ─── Acceptance tests ───────────────────────────────────────────────────────

describe('acceptance: multi-tenant concurrency isolation', () => {
  it('concurrent tenant calls do not bleed state across tenants', async () => {
    // Track which tenantId each dispatch invocation saw
    const seenTenants = [];

    const baseDispatch = mock.fn(async (_toolName, args) => {
      // Simulate async work so calls overlap
      await new Promise((r) => setTimeout(r, 10));
      const tenantId = args._tenant?.tenantId;
      seenTenants.push(tenantId);
      return { tenantSeen: tenantId };
    });

    const scoped = createTenantScope({
      dispatch: baseDispatch,
      resolveContext: async (meta) => ({
        tenantId: meta.tenantId,
        auth: { type: 'bearer', value: `tok_${meta.tenantId}` },
      }),
    });

    // Fire both simultaneously — they should overlap due to the 10ms delay above
    const [r1, r2] = await Promise.all([
      scoped('get_data', {}, { tenantId: 'tenant-A' }),
      scoped('get_data', {}, { tenantId: 'tenant-B' }),
    ]);

    // Each result must carry its own tenant context, not the other's
    assert.equal(r1.tenantSeen, 'tenant-A', 'tenant-A call must see tenant-A context');
    assert.equal(r2.tenantSeen, 'tenant-B', 'tenant-B call must see tenant-B context');
    assert.equal(baseDispatch.mock.calls.length, 2, 'dispatch called once per tenant');
  });

  it('allowlist isolation: each tenant can only call its permitted tools', async () => {
    const baseDispatch = mock.fn(async (toolName) => ({ tool: toolName }));

    const scoped = createTenantScope({
      dispatch: baseDispatch,
      resolveContext: async (meta) => ({
        tenantId: meta.tenantId,
        auth: { type: 'bearer', value: `tok_${meta.tenantId}` },
        allowlist: meta.allowlist,
      }),
    });

    // tenant-A can only call tool_a; tenant-B can only call tool_b
    const [okA, okB] = await Promise.all([
      scoped('tool_a', {}, { tenantId: 'tenant-A', allowlist: ['tool_a'] }),
      scoped('tool_b', {}, { tenantId: 'tenant-B', allowlist: ['tool_b'] }),
    ]);
    assert.equal(okA.tool, 'tool_a');
    assert.equal(okB.tool, 'tool_b');

    // tenant-A is blocked from tool_b
    await assert.rejects(
      () => scoped('tool_b', {}, { tenantId: 'tenant-A', allowlist: ['tool_a'] }),
      (err) => err.message.includes('not in allowlist') || err.message.includes('not allowed') || err.code != null,
    );
  });
});
