import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { validateSettings } from './settings.js';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const CWD = '/home/project';

function settingsWithPolicy(pathValue) {
  return { frontdoor: { policy: { path: pathValue } } };
}

function settingsWithTenantMap(pathValue) {
  return { frontdoor: { tenantMap: { path: pathValue } } };
}

function settingsWithSteering(pathValue) {
  return { frontdoor: { steering: { path: pathValue } } };
}

// ─────────────────────────────────────────────────────────────────────────────
// frontdoor.policy.path — containment checks
// ─────────────────────────────────────────────────────────────────────────────

describe('validateSettings — frontdoor.*.path containment', () => {
  // Valid in-repo relative paths

  it('accepts a simple relative path for policy', () => {
    const result = validateSettings(settingsWithPolicy('config/policy.json'), { cwd: CWD });
    assert.equal(result.valid, true, `unexpected errors: ${result.errors.join(', ')}`);
  });

  it('accepts a simple relative path for tenantMap', () => {
    const result = validateSettings(settingsWithTenantMap('config/tenants.json'), { cwd: CWD });
    assert.equal(result.valid, true, `unexpected errors: ${result.errors.join(', ')}`);
  });

  it('accepts a simple relative path for steering', () => {
    const result = validateSettings(settingsWithSteering('steering/rules.json'), { cwd: CWD });
    assert.equal(result.valid, true, `unexpected errors: ${result.errors.join(', ')}`);
  });

  it('accepts a bare filename (no directory segment)', () => {
    const result = validateSettings(settingsWithPolicy('policy.json'), { cwd: CWD });
    assert.equal(result.valid, true, `unexpected errors: ${result.errors.join(', ')}`);
  });

  it('accepts a nested relative path', () => {
    const result = validateSettings(settingsWithPolicy('a/b/c/policy.json'), { cwd: CWD });
    assert.equal(result.valid, true, `unexpected errors: ${result.errors.join(', ')}`);
  });

  // null / undefined — should remain valid (feature disabled)

  it('accepts null path (feature disabled)', () => {
    const result = validateSettings(settingsWithPolicy(null), { cwd: CWD });
    assert.equal(result.valid, true, `unexpected errors: ${result.errors.join(', ')}`);
  });

  // Absolute path rejection

  it('rejects an absolute POSIX path for policy', () => {
    const result = validateSettings(settingsWithPolicy('/etc/passwd'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(
      result.errors.some((e) => e.includes('settings.frontdoor.policy.path')),
      `expected policy.path error, got: ${result.errors.join(', ')}`,
    );
  });

  it('rejects an absolute path for tenantMap', () => {
    const result = validateSettings(settingsWithTenantMap('/var/secrets/tenants.json'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('settings.frontdoor.tenantMap.path')));
  });

  it('rejects an absolute path for steering', () => {
    const result = validateSettings(settingsWithSteering('/tmp/steering.json'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('settings.frontdoor.steering.path')));
  });

  // Directory-traversal rejection

  it('rejects a simple ../ traversal for policy', () => {
    const result = validateSettings(settingsWithPolicy('../sibling/policy.json'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('settings.frontdoor.policy.path')));
  });

  it('rejects a deep ../ traversal for policy', () => {
    const result = validateSettings(settingsWithPolicy('../../etc/passwd'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('settings.frontdoor.policy.path')));
  });

  it('rejects a traversal that descends then escapes', () => {
    const result = validateSettings(settingsWithPolicy('sub/../../outside'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('settings.frontdoor.policy.path')));
  });

  it('rejects a traversal for tenantMap', () => {
    const result = validateSettings(settingsWithTenantMap('../secrets.json'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('settings.frontdoor.tenantMap.path')));
  });

  it('rejects a traversal for steering', () => {
    const result = validateSettings(settingsWithSteering('../steering.json'), { cwd: CWD });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('settings.frontdoor.steering.path')));
  });

  // Error message quality

  it('includes the offending path value in the error message', () => {
    const result = validateSettings(settingsWithPolicy('/etc/passwd'), { cwd: CWD });
    assert.ok(
      result.errors.some((e) => e.includes('/etc/passwd')),
      `expected path value in error, got: ${result.errors.join(', ')}`,
    );
  });

  it('reports errors for all three fields independently', () => {
    const result = validateSettings(
      {
        frontdoor: {
          policy: { path: '/etc/policy' },
          tenantMap: { path: '../../tenants.json' },
          steering: { path: '/tmp/steering' },
        },
      },
      { cwd: CWD },
    );
    assert.equal(result.valid, false);
    const fields = ['settings.frontdoor.policy.path', 'settings.frontdoor.tenantMap.path', 'settings.frontdoor.steering.path'];
    for (const field of fields) {
      assert.ok(
        result.errors.some((e) => e.includes(field)),
        `expected error for ${field}, errors: ${result.errors.join(', ')}`,
      );
    }
  });
});
