/**
 * Multi-tenant concurrency isolation acceptance test.
 *
 * Tests that simultaneous requests from different tenants do NOT bleed state.
 * Verifies that:
 *   1. Tenant A's auth context never appears in tenant B's request, and vice versa
 *   2. Tool blocklist/allowlist is enforced per-tenant
 *   3. Context object is per-call, not shared across tenants
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRestBridge } from '../src/bridge.js';
import { createTenantScope, tenantAuthHook } from '../src/tenant/scope.js';

describe('Multi-tenant isolation', () => {
  let server;
  let port;
  let baseUrl;
  let bridge;

  before(async () => {
    // Mock API that echoes back the Authorization header and request path
    server = createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');

      const auth = req.headers.authorization || 'none';
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (url.pathname === '/protected') {
        res.writeHead(200);
        return res.end(JSON.stringify({ auth, tenant: 'received', path: url.pathname }));
      }

      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;

    bridge = createRestBridge({
      name: 'tenant-test-api',
      version: '1.0.0',
      baseUrl,
      hooks: {
        beforeRequest: tenantAuthHook(),
      },
      tools: [
        {
          name: 'call_protected',
          description: 'Call protected endpoint',
          method: 'GET',
          path: '/protected',
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'admin_operation',
          description: 'Admin-only operation',
          method: 'GET',
          path: '/protected',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it('concurrent requests from different tenants do not share auth context', async () => {
    const scopedDispatch = createTenantScope({
      dispatch: (toolName, args) => bridge.dispatch(toolName, args),
      resolveContext: async (meta) => {
        // Simulate tenant resolution from request metadata
        if (meta?.tenantId === 'tenant-a') {
          return {
            tenantId: 'tenant-a',
            auth: { type: 'bearer', value: 'token-from-tenant-a' },
          };
        }
        if (meta?.tenantId === 'tenant-b') {
          return {
            tenantId: 'tenant-b',
            auth: { type: 'bearer', value: 'token-from-tenant-b' },
          };
        }
        return null;
      },
    });

    // Fire simultaneous requests from both tenants
    const [resultA, resultB] = await Promise.all([
      scopedDispatch('call_protected', {}, { tenantId: 'tenant-a' }),
      scopedDispatch('call_protected', {}, { tenantId: 'tenant-b' }),
    ]);

    // Parse responses
    const dataA = typeof resultA === 'string' ? JSON.parse(resultA) : resultA;
    const dataB = typeof resultB === 'string' ? JSON.parse(resultB) : resultB;

    // Verify each tenant got their own auth token
    assert.strictEqual(dataA.auth, 'Bearer token-from-tenant-a', 'Tenant A should receive token-a');
    assert.strictEqual(dataB.auth, 'Bearer token-from-tenant-b', 'Tenant B should receive token-b');

    // Verify no cross-contamination
    assert.notStrictEqual(dataA.auth, dataB.auth, 'Tenant A and B should have different auth headers');
  });

  it('blocklist prevents tool access for blocked tenant', async () => {
    const scopedDispatch = createTenantScope({
      dispatch: (toolName, args) => bridge.dispatch(toolName, args),
      resolveContext: async (meta) => {
        if (meta?.tenantId === 'tenant-restricted') {
          return {
            tenantId: 'tenant-restricted',
            auth: { type: 'bearer', value: 'token-restricted' },
            blocklist: ['admin_operation'],
          };
        }
        return null;
      },
    });

    // admin_operation should be blocked for tenant-restricted
    await assert.rejects(
      () => scopedDispatch('admin_operation', {}, { tenantId: 'tenant-restricted' }),
      (err) => {
        assert.ok(err.message.includes('blocked'), `Expected blocklist error, got: ${err.message}`);
        return true;
      },
    );

    // But call_protected should still work
    const result = await scopedDispatch('call_protected', {}, { tenantId: 'tenant-restricted' });
    const data = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(data.auth, 'Unrestricted tool should still work');
  });

  it('allowlist restricts access to listed tools only', async () => {
    const scopedDispatch = createTenantScope({
      dispatch: (toolName, args) => bridge.dispatch(toolName, args),
      resolveContext: async (meta) => {
        if (meta?.tenantId === 'tenant-limited') {
          return {
            tenantId: 'tenant-limited',
            auth: { type: 'bearer', value: 'token-limited' },
            allowlist: ['call_protected'],
          };
        }
        return null;
      },
    });

    // admin_operation is not in the allowlist
    await assert.rejects(
      () => scopedDispatch('admin_operation', {}, { tenantId: 'tenant-limited' }),
      (err) => {
        assert.ok(err.message.includes('allowlist'), `Expected allowlist error, got: ${err.message}`);
        return true;
      },
    );

    // But call_protected is allowed
    const result = await scopedDispatch('call_protected', {}, { tenantId: 'tenant-limited' });
    const data = typeof result === 'string' ? JSON.parse(result) : result;
    assert.strictEqual(data.auth, 'Bearer token-limited', 'Allowlisted tool should work');
  });

  it('tenant metadata is enriched and passed through args', async () => {
    const scopedDispatch = createTenantScope({
      dispatch: (toolName, args) => {
        // Verify that _tenant is attached to args
        assert.ok(args._tenant, '_tenant should be attached to args');
        assert.strictEqual(args._tenant.tenantId, 'tenant-meta', 'tenantId should be passed');
        assert.ok(args._tenant.metadata, 'metadata should be present');
        // Call bridge to complete the dispatch
        return bridge.dispatch(toolName, args);
      },
      resolveContext: async (meta) => {
        if (meta?.tenantId === 'tenant-meta') {
          return {
            tenantId: 'tenant-meta',
            auth: { type: 'bearer', value: 'token-meta' },
            metadata: { region: 'us-west', tier: 'premium' },
          };
        }
        return null;
      },
    });

    const result = await scopedDispatch('call_protected', {}, { tenantId: 'tenant-meta' });
    const data = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(data.auth, 'Request should succeed with metadata enrichment');
  });
});
