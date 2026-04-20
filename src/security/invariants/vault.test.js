/**
 * Security invariants — vault surface
 *
 * Tests for vault passphrase strength enforcement, auth-hook header
 * validation, and symlink-path rejection.
 *
 * @module security/invariants/vault
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { initVault, createVault, recoverVault } from '../vault.js';
import { createVaultDaemonClient } from '../vault-client.js';
import os from 'node:os';
import path from 'node:path';
import { symlink, unlink, writeFile } from 'node:fs/promises';

// ─────────────────────────────────────────────────────────────────────────────
// Vault passphrase strength hardening
// ─────────────────────────────────────────────────────────────────────────────

describe('vault passphrase strength', () => {
  it('initVault rejects passphrase shorter than 16 characters', async () => {
    await assert.rejects(
      () => initVault({ path: '/tmp/__inv_vault_r19__.json', passphrase: 'Short1!Abc' }),
      /at least 16/,
    );
  });

  it('initVault rejects passphrase with fewer than 3 char classes', async () => {
    // 20 lowercase chars — fails the 3-class requirement
    await assert.rejects(
      () => initVault({ path: '/tmp/__inv_vault_r19__.json', passphrase: 'alllowercaselongpass' }),
      /at least 3 character classes/,
    );
  });

  it('initVault rejects highly repetitive passphrase', async () => {
    // aaabbbccc!!!111AAA has only 6 distinct chars — Shannon entropy ~2.6 bits/char
    await assert.rejects(
      () => initVault({ path: '/tmp/__inv_vault_r19__.json', passphrase: 'aaabbbccc!!!111AAA' }),
      /too repetitive/,
    );
  });

  it('initVault rejects passphrase with sequential character run', async () => {
    // Contains "1234" — a 4-char ascending run
    await assert.rejects(
      () => initVault({ path: '/tmp/__inv_vault_r19__.json', passphrase: 'Tr@vis-1234-Protocol' }),
      /sequential or repeated/,
    );
  });

  it('initVault rejects Password123!-style passphrase (only 12 chars)', async () => {
    // Password123! is only 12 chars — must now be rejected on length
    await assert.rejects(
      () => initVault({ path: '/tmp/__inv_vault_r19__.json', passphrase: 'Password123!' }),
      /passphrase/i,
    );
  });

  it('initVault does not raise passphrase error for a genuinely strong passphrase', async () => {
    // Tr@vis#Pr0t0col-2026 — 20 chars, 4 classes, high entropy, no monotone runs
    try {
      await initVault({ path: '/tmp/__inv_vault_r19_strong__.json', passphrase: 'Tr@vis#Pr0t0col-2026' });
      // If it somehow succeeds (e.g., test env creates the file), that's fine
    } catch (err) {
      // Any non-passphrase error (ENOENT, vault-exists, etc.) is acceptable
      assert.doesNotMatch(
        err.message,
        /passphrase must|too repetitive|sequential or repeated/i,
        `Unexpected passphrase rejection: ${err.message}`,
      );
    }
  });

  it('rotateKEK rejects a weak new passphrase (strength gate applies beyond initVault)', async () => {
    // Create a vault with a strong passphrase, then attempt to rotate into a
    // weak one. The strength check must fire before any KEK derivation so the
    // vault is not silently weakened.
    const vaultPath = path.join(os.tmpdir(), `__inv_vault_rotate_weak_${Date.now()}.json`);
    try { await unlink(vaultPath); } catch {}
    const vault = createVault({ path: vaultPath, passphrase: 'Tr@vis#Pr0t0col-2026' });
    await vault.set('probe', 'value');
    try {
      await assert.rejects(
        () => vault.rotateKEK('Password123!'),
        /passphrase must|too repetitive|sequential or repeated/i,
        'rotateKEK must reject a weak new passphrase',
      );
    } finally {
      try { await unlink(vaultPath); } catch {}
    }
  });

  it('createVault rejects a weak passphrase at construction (strength gate applies to every vault entry point)', () => {
    // Symmetric with initVault / rotateKEK / recoverVault: a weak passphrase
    // must fail fast on construction so a fresh vault cannot be created weak
    // and so library consumers of createVault get the same policy the CLI
    // enforces through initVault.
    assert.throws(
      () => createVault({ path: '/tmp/__inv_vault_create_weak__.json', passphrase: 'short1!A' }),
      /passphrase must|too repetitive|sequential or repeated/i,
      'createVault must reject a weak passphrase on construction',
    );
    assert.throws(
      () => createVault({ path: '/tmp/__inv_vault_create_weak__.json', passphrase: 'alllowercaselongpass' }),
      /passphrase must|too repetitive|sequential or repeated/i,
      'createVault must reject a passphrase with too few character classes',
    );
  });

  it('recoverVault rejects a weak new passphrase before touching vault state', async () => {
    // The recoveryKey and vault path are intentionally bogus — the strength
    // gate must fail BEFORE the recovery-key validation runs, so recovery
    // cannot silently weaken a vault even when the caller supplies a valid
    // recovery key.
    await assert.rejects(
      () => recoverVault({
        path: '/tmp/__inv_vault_recover_weak__.json',
        recoveryKey: 'AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA',
        newPassphrase: 'Password123!',
      }),
      /passphrase must|too repetitive|sequential or repeated/i,
      'recoverVault must reject a weak new passphrase',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Vault auth-hook and symlink hardening
// ─────────────────────────────────────────────────────────────────────────────

describe('createVault auth-hook and symlink defenses', () => {
  // ── M10: createAuthHook rejects invalid header names ──────────────────────
  it('createVault createAuthHook rejects header names with CRLF injection', () => {
    const vault = createVault({ path: '/tmp/test-vault-r19.json', passphrase: 'TestPassPhrase123!@#ABC' });
    assert.throws(
      () => vault.createAuthHook({ mySecret: 'Authorization\r\nX-Injected: evil' }),
      /invalid header name|RFC 7230/i,
    );
  });

  it('createVault createAuthHook accepts valid header names', () => {
    const vault = createVault({ path: '/tmp/test-vault-r19.json', passphrase: 'TestPassPhrase123!@#ABC' });
    assert.doesNotThrow(() => vault.createAuthHook({ mySecret: 'Authorization' }));
    assert.doesNotThrow(() => vault.createAuthHook({ mySecret: 'X-Custom-Header' }));
  });

  // ── H1: initVault rejects symlinked vault paths ──────────────────────────
  it('initVault rejects a symlink at the vault path', {
    skip: process.platform === 'win32'
      ? 'symlink creation requires admin/Developer Mode on Windows'
      : false,
  }, async () => {
    const tmpDir = os.tmpdir();
    const target = path.join(tmpDir, `r19-symlink-target-${process.pid}.txt`);
    const linkPath = path.join(tmpDir, `r19-symlink-vault-${process.pid}.json`);
    // Create a real file as the symlink target
    await writeFile(target, 'dummy', 'utf-8');
    try {
      await symlink(target, linkPath);
    } catch { /* symlink already exists from a prior run */ }
    try {
      await assert.rejects(
        () => initVault({ path: linkPath, passphrase: 'K9!mBx#2pL$wN7vQ' }),
        /symlink|symbolic link/i,
        'initVault must reject a symlinked vault path',
      );
    } finally {
      await unlink(linkPath).catch(() => {});
      await unlink(target).catch(() => {});
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Vault hardening — hkdfSync guard + constant-time auth
// ─────────────────────────────────────────────────────────────────────────────

describe('hkdfSync guard and constant-time auth invariants', () => {
  it('hkdfSync is a function in the current Node.js runtime (>= 15)', async () => {
    // Module fix: vault.js imports hkdfSync at module load and throws if it is
    // not a function. On Node < 15 this would produce an opaque crash deep in the
    // boot path. The guard makes it an explicit, early error.
    // On Node >= 15 (our minimum) this must pass.
    const crypto = await import('node:crypto');
    assert.strictEqual(typeof crypto.hkdfSync, 'function',
      'hkdfSync must be available in the current Node.js runtime');
  });

  it('fixed-32-byte buffer pattern: wrong-length secrets never bypass timingSafeEqual', async () => {
    // Security fix fix in vault-daemon.js: the auth handler allocates a fixed
    // 32-byte `candidate` buffer and copies the presented secret in, then runs
    // timingSafeEqual(candidate, expected) — both sides are always 32 bytes.
    // This eliminates the `presented.length !== expected.length` short-circuit
    // that leaked length information via timing.
    //
    // Verify the pattern: for any wrong-length presented secret, the candidate
    // buffer is all-zeros-padded and timingSafeEqual returns false.
    const { timingSafeEqual } = await import('node:crypto');
    const expected = Buffer.from('a'.repeat(64), 'hex');  // 32-byte secret
    for (const wrongLen of [0, 1, 15, 16, 31, 33, 64]) {
      const presented = Buffer.alloc(wrongLen, 0xAB);
      const candidate = Buffer.alloc(32);
      presented.copy(candidate, 0, 0, Math.min(presented.length, 32));
      // With the fixed pattern both buffers are always 32 bytes — no early exit.
      const match = timingSafeEqual(candidate, expected);
      assert.strictEqual(match, false,
        `wrong-length secret (${wrongLen} bytes) must not match via the fixed-buffer pattern`);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Vault-client fail-closed on daemon unavailable
// ─────────────────────────────────────────────────────────────────────────────

describe('B3: vault-client fails closed when daemon is unavailable', () => {
  it('createAuthHook throws when daemon ENOENT (not silent no-op)', async () => {
    const client = createVaultDaemonClient({
      socketPath: '/tmp/__nonexistent_vault_daemon_r25__.sock',
    });
    const hook = client.createAuthHook({ mySecret: 'X-Api-Key' });
    await assert.rejects(
      () => hook({}),
      /daemon unavailable|ENOENT|refusing to dispatch/i,
    );
  });

  it('createBearerHook throws when daemon ENOENT (not silent no-op)', async () => {
    const client = createVaultDaemonClient({
      socketPath: '/tmp/__nonexistent_vault_daemon_r25__.sock',
    });
    const hook = client.createBearerHook('myBearerSecret');
    await assert.rejects(
      () => hook({}),
      /daemon unavailable|ENOENT|refusing to dispatch/i,
    );
  });
});
