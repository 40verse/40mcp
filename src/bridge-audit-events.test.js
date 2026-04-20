/**
 * Tests verifying audit event code constants and wire-format stability.
 *
 * The bridge emits audit log entries with an `errorCode` field for tenant ACL
 * denials, policy denials, and policy-approval requirements. These tests lock
 * in the wire-format stability guarantee: each audit path emits an entry whose
 * `errorCode` matches the value in AuditEventCode.
 *
 * The tests trigger each audit path by dispatching against a bridge that has
 * the relevant policy / tenant configuration set. Audit lines are captured
 * from stderr.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRestBridge } from './bridge.js';
import { AuditEventCode } from './errors.js';

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Capture all `[40mcp:audit]` stderr writes that happen during `fn`. */
async function captureAudit(fn) {
  const lines = [];
  const origWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (msg, ...rest) => {
    const s = String(msg);
    if (s.includes('[40mcp:audit]')) lines.push(s);
    return origWrite(msg, ...rest);
  };
  try {
    await fn();
  } finally {
    process.stderr.write = origWrite;
  }
  return lines.map((l) => JSON.parse(l.replace('[40mcp:audit] ', '')));
}

// ─── Constants shape guarantees ───────────────────────────────────────────

describe('AuditEventCode constants', () => {
  it('exports the three known audit event codes', () => {
    assert.equal(AuditEventCode.TENANT_ACL_DENY, 'TENANT_ACL_DENY');
    assert.equal(AuditEventCode.POLICY_DENIED, 'POLICY_DENIED');
    assert.equal(AuditEventCode.POLICY_APPROVAL_REQUIRED_IN_CHAIN, 'POLICY_APPROVAL_REQUIRED_IN_CHAIN');
  });

  it('is frozen so downstream code cannot tamper', () => {
    assert.ok(Object.isFrozen(AuditEventCode));
    assert.throws(() => {
      AuditEventCode.NEW_CODE = 'oops';
    });
  });

  it('is also exported from the package root', async () => {
    const mod = await import('./index.js');
    assert.equal(mod.AuditEventCode, AuditEventCode);
    assert.equal(mod.AuditEventCode.TENANT_ACL_DENY, 'TENANT_ACL_DENY');
  });
});

// ─── Audit wire-format stability ──────────────────────────────────────────

describe('bridge audit events — errorCode matches AuditEventCode', () => {
  it('emits TENANT_ACL_DENY when tenant allowlist excludes the tool', async () => {
    const bridge = createRestBridge({
      name: 'audit-tenant-allowlist',
      baseUrl: 'http://localhost:9999',
      tools: [
        { name: 'forbidden_tool', description: 'x', method: 'GET', path: '/x',
          inputSchema: { type: 'object', properties: {} } },
      ],
    });

    // Inject a tenant envelope matching what tenant/scope.js produces.
    const args = {};
    Object.defineProperty(args, '_tenant', {
      value: { tenantId: 'tenant-a', allowlist: ['allowed_only'], blocklist: null },
      enumerable: false,
    });

    const entries = await captureAudit(async () => {
      await assert.rejects(() => bridge.dispatch('forbidden_tool', args));
    });

    const aclEntry = entries.find((e) => e.tool === 'forbidden_tool' && e.status === 'error');
    assert.ok(aclEntry, 'expected an error audit entry for the denied call');
    assert.equal(aclEntry.errorCode, AuditEventCode.TENANT_ACL_DENY);
    assert.equal(aclEntry.errorCode, 'TENANT_ACL_DENY', 'wire string must not drift');
    assert.equal(aclEntry.tenantId, 'tenant-a');
  });

  it('emits TENANT_ACL_DENY when tenant blocklist contains the tool', async () => {
    const bridge = createRestBridge({
      name: 'audit-tenant-blocklist',
      baseUrl: 'http://localhost:9999',
      tools: [
        { name: 'blocked_tool', description: 'x', method: 'GET', path: '/x',
          inputSchema: { type: 'object', properties: {} } },
      ],
    });

    const args = {};
    Object.defineProperty(args, '_tenant', {
      value: { tenantId: 'tenant-b', allowlist: null, blocklist: ['blocked_tool'] },
      enumerable: false,
    });

    const entries = await captureAudit(async () => {
      await assert.rejects(() => bridge.dispatch('blocked_tool', args));
    });

    const entry = entries.find((e) => e.tool === 'blocked_tool' && e.status === 'error');
    assert.ok(entry, 'expected audit entry for blocklist-denied call');
    assert.equal(entry.errorCode, AuditEventCode.TENANT_ACL_DENY);
    assert.equal(entry.errorCode, 'TENANT_ACL_DENY');
  });

  it('emits POLICY_DENIED when tool has policy:"deny"', async () => {
    const bridge = createRestBridge({
      name: 'audit-policy-deny',
      baseUrl: 'http://localhost:9999',
      tools: [
        { name: 'dangerous_tool', description: 'x', method: 'GET', path: '/x',
          inputSchema: { type: 'object', properties: {} },
          policy: 'deny' },
      ],
    });

    const entries = await captureAudit(async () => {
      await assert.rejects(() => bridge.dispatch('dangerous_tool', {}));
    });

    const entry = entries.find((e) => e.tool === 'dangerous_tool' && e.errorCode === AuditEventCode.POLICY_DENIED);
    assert.ok(entry, 'expected audit entry with POLICY_DENIED errorCode');
    assert.equal(entry.errorCode, 'POLICY_DENIED', 'wire string must not drift');
    assert.equal(entry.status, 'error');
  });

  it('emits POLICY_APPROVAL_REQUIRED_IN_CHAIN when a require_approval tool is dispatched via internal chain path', async () => {
    // The bridge rejects `require_approval` only when reached as a chain
    // sub-dispatch. Top-level calls flow through createPolicyGate (or pass
    // through if the caller skipped the gate). Drive the chain path by
    // dispatching an outer chain tool that calls the approval-gated tool.
    const bridge = createRestBridge({
      name: 'audit-policy-approval-chain',
      baseUrl: 'http://localhost:9999',
      tools: [
        {
          name: 'chain_wrapper',
          description: 'outer',
          chain: [{ call: 'approval_tool', as: 'r', args: {} }],
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'approval_tool',
          description: 'x',
          method: 'GET',
          path: '/x',
          inputSchema: { type: 'object', properties: {} },
          policy: 'require_approval',
        },
      ],
    });

    const entries = await captureAudit(async () => {
      await assert.rejects(() => bridge.dispatch('chain_wrapper', {}));
    });

    const entry = entries.find((e) => e.errorCode === AuditEventCode.POLICY_APPROVAL_REQUIRED_IN_CHAIN);
    assert.ok(entry, 'expected audit entry with POLICY_APPROVAL_REQUIRED_IN_CHAIN errorCode');
    assert.equal(entry.errorCode, 'POLICY_APPROVAL_REQUIRED_IN_CHAIN', 'wire string must not drift');
    assert.equal(entry.tool, 'approval_tool');
    assert.equal(entry.status, 'error');
  });
});
