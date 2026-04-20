/**
 * Security invariants — tenant ACL / scope surface
 *
 * Tests for createTenantScope (transitive ACL enforcement, non-enumerable
 * envelope keys, allowlist/blocklist, falsy tenantId edge cases) and
 * the _tenant deep-freeze invariant.
 *
 * @module security/invariants/tenant
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { getByPath } from '../../core/object.js';
import { createTenantScope } from '../../tenant/scope.js';

// ─────────────────────────────────────────────────────────────────────────────
// Non-enumerable envelope key exfil + transitive tenant ACL bypass
// getByPath reads non-enumerable reserved keys and tenant allowlist not
// enforced across chain sub-dispatches
// ─────────────────────────────────────────────────────────────────────────────

describe('non-enumerable envelope key guard + transitive tenant ACL', () => {
  it('getByPath returns undefined for non-enumerable _tenant (bearer token exfil)', () => {
    // The comment at chain.js:334 claimed deepResolveArgs walking only
    // enumerable keys was sufficient protection. It was not: resolveArgValue
    // calls getByPath(args, path) where path is attacker-controlled, and
    // direct property access reads non-enumerable own properties. getByPath
    // must honour the non-enumerable contract so $args._tenant.auth.value
    // resolves to undefined regardless of what the arg tree resolves to.
    const args = {};
    Object.defineProperty(args, '_tenant', {
      value: { tenantId: 'victim', auth: { type: 'bearer', value: 'sk-live-SECRET' } },
      enumerable: false,
      writable: true,
      configurable: true,
    });
    assert.equal(getByPath(args, '_tenant'), undefined);
    assert.equal(getByPath(args, '_tenant.auth.value'), undefined);
    assert.equal(getByPath(args, '_tenant.tenantId'), undefined);
  });

  it('getByPath returns undefined for non-enumerable _steering on step result', () => {
    // CMP9: $stepA._steering.authority extraction from a prior chain step.
    const stepResult = {};
    Object.defineProperty(stepResult, '_steering', {
      value: { authority: 'ROOT', write: true },
      enumerable: false,
      writable: true,
      configurable: true,
    });
    assert.equal(getByPath(stepResult, '_steering'), undefined);
    assert.equal(getByPath(stepResult, '_steering.authority'), undefined);
  });

  it('getByPath returns undefined for non-enumerable nested _chain', () => {
    const obj = {};
    Object.defineProperty(obj, '_chain', {
      value: { steps: 1, completed: 1 },
      enumerable: false,
      writable: true,
      configurable: true,
    });
    assert.equal(getByPath(obj, '_chain.steps'), undefined);
  });

  it('getByPath still resolves enumerable properties with reserved-like names', () => {
    // External API responses may return fields named _tenant, _chain, etc.
    // as regular enumerable properties. Only the non-enumerable (internal)
    // variant is blocked.
    const apiResponse = { _tenant: { id: 'public-data' }, _chain: 'external-value' };
    assert.equal(getByPath(apiResponse, '_tenant.id'), 'public-data');
    assert.equal(getByPath(apiResponse, '_chain'), 'external-value');
  });

  it('executeChain enforces tenant allowlist on sub-dispatches', async () => {
    // createTenantScope enforces allowlist only on the outer call.
    // A chain step can call any downstream tool because depthAwareDispatch
    // never re-checks the ACL. The fix adds allowlist enforcement inside
    // depthAwareDispatch using callerTenant from the incoming args.
    const { executeChain } = await import('../../compose/chain.js');

    const rawDispatch = async (name) => {
      if (name === 'admin_delete_everything') return { result: 'ADMIN PAYLOAD' };
      return { ok: true };
    };

    const args = {};
    Object.defineProperty(args, '_tenant', {
      value: { tenantId: 'tenant-limited', allowlist: ['chain_alpha'] },
      enumerable: false,
      writable: true,
      configurable: true,
    });

    await assert.rejects(
      () => executeChain(
        [{ call: 'admin_delete_everything', as: 'r', args: {} }],
        args,
        rawDispatch,
      ),
      /not in tenant.*allowlist|allowlist/i,
    );
  });

  it('executeChain enforces tenant blocklist on sub-dispatches', async () => {
    const { executeChain } = await import('../../compose/chain.js');

    const rawDispatch = async () => ({ ok: true });

    const args = {};
    Object.defineProperty(args, '_tenant', {
      value: { tenantId: 'tenant-limited', blocklist: ['banned_tool'] },
      enumerable: false,
      writable: true,
      configurable: true,
    });

    await assert.rejects(
      () => executeChain(
        [{ call: 'banned_tool', as: 'r', args: {} }],
        args,
        rawDispatch,
      ),
      /blocked for tenant|blocklist/i,
    );
  });

  it('executeChain allows tools in tenant allowlist (positive case)', async () => {
    const { executeChain } = await import('../../compose/chain.js');

    const rawDispatch = async (name) => ({ result: name });

    const args = {};
    Object.defineProperty(args, '_tenant', {
      value: { tenantId: 'tenant-limited', allowlist: ['allowed_tool'] },
      enumerable: false,
      writable: true,
      configurable: true,
    });

    const result = await executeChain(
      [{ call: 'allowed_tool', as: 'r', args: {} }],
      args,
      rawDispatch,
    );
    assert.deepEqual(result.r, { result: 'allowed_tool' });
  });

  it('executeChain with no tenant context passes through without ACL enforcement', async () => {
    // Without a _tenant envelope, chains run without ACL restrictions
    // (the outer dispatch layer handles auth independently).
    const { executeChain } = await import('../../compose/chain.js');

    const rawDispatch = async (name) => ({ result: name });

    const result = await executeChain(
      [{ call: 'any_tool', as: 'r', args: {} }],
      {},
      rawDispatch,
    );
    assert.deepEqual(result.r, { result: 'any_tool' });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// tenantId: 0 falsy-value edge case
// ─────────────────────────────────────────────────────────────────────────────

describe('tenantId falsy-value edge case', () => {
  it('createTenantScope passes through tenantId: 0 without overriding with defaults', async () => {
    const scope = createTenantScope({
      dispatch: async (_name, _args, _meta, _ctx) => ({}),
      resolveContext: async () => ({ tenantId: 0 }),
      defaults: { tenantId: 99, allowFallback: false },
    });
    // tenantId: 0 is falsy but valid — it must NOT be replaced by defaults.tenantId: 99
    let threw = false;
    try {
      await scope('some_tool', {});
    } catch (err) {
      if (err && err.message && err.message.includes('tenantId is required')) {
        threw = true;
      }
    }
    assert.strictEqual(threw, false, 'tenantId: 0 must not trigger AUTH_MISSING');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// _tenant property non-writable + value frozen
// ─────────────────────────────────────────────────────────────────────────────

describe('_tenant envelope frozen and non-writable', () => {
  it('_tenant property is non-writable and its value is frozen', async () => {
    let capturedArgs = null;
    const scopedDispatch = createTenantScope({
      dispatch: async (_n, args) => { capturedArgs = args; return {}; },
      resolveContext: () => ({ tenantId: 'tenant-A', allowlist: null, blocklist: null }),
    });
    await scopedDispatch('tool', {});
    const desc = Object.getOwnPropertyDescriptor(capturedArgs, '_tenant');
    assert.ok(desc, '_tenant descriptor must exist');
    assert.strictEqual(desc.writable, false, 'must be non-writable');
    assert.strictEqual(desc.configurable, false, 'must be non-configurable');
    assert.ok(Object.isFrozen(desc.value), '_tenant value must be frozen');
    // Overwrite attempt must not succeed
    try { capturedArgs._tenant = { tenantId: 'ADMIN' }; } catch { /* strict mode */ }
    assert.strictEqual(capturedArgs._tenant.tenantId, 'tenant-A',
      'tenantId must be unchanged after overwrite attempt');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// deepFreeze covers non-enumerable properties
// ─────────────────────────────────────────────────────────────────────────────

describe('deepFreeze on nested auth objects', () => {
  it('deepFreeze (via createTenantScope) freezes deeply-nested auth object', async () => {
    let capturedArgs = null;
    const scopedDispatch = createTenantScope({
      dispatch: async (_n, args) => { capturedArgs = args; return {}; },
      resolveContext: () => ({
        tenantId: 'tenant-freeze-test',
        auth: { type: 'bearer', value: 'secret-token' },
        metadata: { nested: { inner: 'value' } },
      }),
    });
    await scopedDispatch('tool', {});
    const tenant = capturedArgs._tenant;
    assert.ok(Object.isFrozen(tenant), '_tenant root must be frozen');
    assert.ok(Object.isFrozen(tenant.auth), '_tenant.auth must be deep-frozen');
    assert.ok(Object.isFrozen(tenant.metadata), '_tenant.metadata must be deep-frozen');
    assert.ok(Object.isFrozen(tenant.metadata.nested), '_tenant.metadata.nested must be deep-frozen');
  });
});
