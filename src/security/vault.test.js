import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, initVault, recoverVault } from './vault.js';
import { unlink, stat } from 'node:fs/promises';

const TEST_VAULT = '/tmp/40mcp-test-sealed-vault.json';
const PASSPHRASE = 'T3st-Passphrase-DoNotUse-In-Production';

describe('sealed vault — envelope encryption', () => {
  after(async () => {
    try { await unlink(TEST_VAULT); } catch {}
  });

  it('writes the vault file with mode 0600 (writeFile signature edge case)', {
    skip: process.platform === 'win32'
      ? 'POSIX mode bits are not represented on NTFS'
      : false,
  }, async () => {
    const VAULT_MODE_TEST = '/tmp/40mcp-test-vault-mode.json';
    try { await unlink(VAULT_MODE_TEST); } catch {}
    try {
      const vault = createVault({ path: VAULT_MODE_TEST, passphrase: PASSPHRASE });
      await vault.set('MODE_CHECK', 'value');
      const st = await stat(VAULT_MODE_TEST);
      // Previously this was 0o644 because {mode:0o600} was passed as the 4th
      // arg to writeFile (ignored). Must be exactly 0o600 so only the owner
      // can read the encrypted vault file.
      assert.equal(st.mode & 0o777, 0o600, `vault file mode must be 0o600, got 0o${(st.mode & 0o777).toString(8)}`);
    } finally {
      try { await unlink(VAULT_MODE_TEST); } catch {}
    }
  });

  it('seals a secret and returns a seal ID', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const sealId = await vault.set('MY_SECRET', 'super-secret-value', { service: 'test' });

    assert.ok(sealId.startsWith('seal://'));
    assert.ok(sealId.includes('my-secret'));
  });

  it('has() checks existence without unsealing', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault.set('EXISTS', 'value');
    assert.equal(await vault.has('EXISTS'), true);
    assert.equal(await vault.has('NOPE'), false);
  });

  it('getSealId() returns seal reference', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const sealId = await vault.set('SEAL_TEST', 'value');
    const retrieved = await vault.getSealId('SEAL_TEST');
    assert.equal(retrieved, sealId);
  });

  it('getFingerprint() returns SHA-256 prefix without unsealing', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault.set('FP_TEST', 'known-value');
    const fp = await vault.getFingerprint('FP_TEST');
    assert.ok(fp);
    assert.equal(fp.length, 8); // First 8 hex chars
  });

  it('list() returns metadata without values', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault.set('LIST_A', 'a', { service: 'github' });
    await vault.set('LIST_B', 'b', { service: 'stripe' });

    const list = await vault.list();
    const names = list.map((e) => e.name);
    assert.ok(names.includes('LIST_A'));
    assert.ok(names.includes('LIST_B'));

    const entryA = list.find((e) => e.name === 'LIST_A');
    assert.ok(entryA.sealId.startsWith('seal://'));
    assert.ok(entryA.fingerprint);
    assert.equal(entryA.metadata.service, 'github');
    // No value field
    assert.equal(entryA.value, undefined);
  });

  it('persists across instances (file-backed envelope encryption)', async () => {
    const vault1 = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault1.set('PERSIST', 'persisted-secret');

    const vault2 = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    assert.equal(await vault2.has('PERSIST'), true);
  });

  it('wrong passphrase fails to unseal (different KEK)', async () => {
    const vault1 = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault1.set('PROTECTED', 'secret');

    const vault2 = createVault({ path: TEST_VAULT, passphrase: 'Wr0ng-Passphrase-MustFail-Check' });
    // HMAC integrity check should fail
    await assert.rejects(
      () => vault2.has('PROTECTED'),
    );
  });

  it('deletes a sealed secret', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault.set('DELETE_ME', 'bye');
    assert.equal(await vault.has('DELETE_ME'), true);
    await vault.delete('DELETE_ME');
    assert.equal(await vault.has('DELETE_ME'), false);
  });

  it('rotate() re-keys a secret with a new DEK and new seal ID', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const originalSealId = await vault.set('ROTATE_ME', 'secret-value');
    const originalFingerprint = await vault.getFingerprint('ROTATE_ME');

    const newSealId = await vault.rotate('ROTATE_ME');
    assert.ok(newSealId, 'rotate() returns a new seal ID');
    assert.notEqual(newSealId, originalSealId, 'seal ID changes after rotation');

    // Value is preserved — verifiable via fingerprint (SHA-256 of value, unchanged)
    const fingerprintAfter = await vault.getFingerprint('ROTATE_ME');
    assert.equal(fingerprintAfter, originalFingerprint, 'fingerprint unchanged (same value)');
  });

  it('rotate() returns null for nonexistent secret', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const result = await vault.rotate('DOES_NOT_EXIST');
    assert.equal(result, null);
  });

  it('rotate() preserves readability — value can still be unsealed after rotation', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE, tokenTTL: 60 });
    await vault.set('ROTATE_READ', 'my-api-key');
    await vault.rotate('ROTATE_READ');

    const token = await vault.issueToken('ROTATE_READ');
    assert.ok(token, 'token can be issued after rotation');
    const verified = await vault.verifyToken(token.token);
    assert.equal(verified.value, 'my-api-key', 'value readable after rotation');
  });

  it('throws without passphrase', () => {
    assert.throws(
      () => createVault({ path: TEST_VAULT }),
      (err) => err.message.includes('passphrase'),
    );
  });
});

describe('sealed vault — JWT credential tokens', () => {
  after(async () => {
    try { await unlink(TEST_VAULT); } catch {}
  });

  it('issues a JWT token for a sealed secret', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE, tokenTTL: 60 });
    await vault.set('API_KEY', 'sk_live_abc123');

    const result = await vault.issueToken('API_KEY');
    assert.ok(result);
    assert.ok(result.token);
    assert.ok(result.token.split('.').length === 3); // JWT format
    assert.ok(result.expiresAt > Date.now());
  });

  it('verify decodes token and returns secret value', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE, tokenTTL: 60 });
    await vault.set('VERIFY_KEY', 'secret-value-123');

    const { token } = await vault.issueToken('VERIFY_KEY');
    const decoded = await vault.verifyToken(token);

    assert.equal(decoded.name, 'VERIFY_KEY');
    assert.equal(decoded.value, 'secret-value-123');
    assert.ok(decoded.sealId.startsWith('seal://'));
  });

  it('JWT includes custom claims', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE, tokenTTL: 60 });
    await vault.set('SCOPED_KEY', 'scoped-secret');

    const { token } = await vault.issueToken('SCOPED_KEY', { scope: 'read', bot_id: 'bot-1' });
    const decoded = await vault.verifyToken(token);

    assert.equal(decoded.claims.scope, 'read');
    assert.equal(decoded.claims.bot_id, 'bot-1');
  });

  it('expired JWT is rejected', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE, tokenTTL: -1 }); // Already expired
    await vault.set('EXPIRE_KEY', 'will-expire');

    const { token } = await vault.issueToken('EXPIRE_KEY');
    await assert.rejects(
      () => vault.verifyToken(token),
      (err) => err.message.includes('expired'),
    );
  });

  it('tampered JWT is rejected', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE, tokenTTL: 60 });
    await vault.set('TAMPER_KEY', 'secret');

    const { token } = await vault.issueToken('TAMPER_KEY');
    const tampered = token.slice(0, -5) + 'XXXXX'; // Corrupt signature

    await assert.rejects(
      () => vault.verifyToken(tampered),
      (err) => err.message.includes('signature') || err.message.includes('Invalid'),
    );
  });

  it('returns null for missing secret', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const result = await vault.issueToken('NONEXISTENT');
    assert.equal(result, null);
  });

  it('refuses claims that try to override reserved JWT fields', async () => {
    // The previous issueToken spread `...claims` AFTER the reserved fields,
    // so a caller passing { exp: 0 } got a token that bypassed the falsy
    // guard in verifyJWT and never expired. The fix strips exp/iat/sub/sid/nbf
    // from caller claims before the spread.
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE, tokenTTL: 60 });
    await vault.set('CLAIMS_KEY', 'secret-value');

    // Attacker tries to set exp: 0 (falsy, previously bypassed expiry check).
    const { token } = await vault.issueToken('CLAIMS_KEY', { exp: 0, sub: 'OTHER_KEY' });
    const decoded = await vault.verifyToken(token);
    // The real exp must be `now + tokenTTL`, not 0 — so verifyToken succeeds.
    assert.equal(decoded.name, 'CLAIMS_KEY'); // sub not overridden
    assert.equal(decoded.claims.exp > Math.floor(Date.now() / 1000), true);
    // And sub was NOT redirected to another key
    assert.notEqual(decoded.claims.sub, 'OTHER_KEY');
  });

  it('rejects tokens with exp=0 or missing exp (falsy exp bypass)', async () => {
    // Verify the verifyJWT guard itself — a hand-forged token with exp=0
    // must be rejected even if it has a valid signature.
    const { signJWT } = await import('./crypto.js');
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault.set('FORGE_KEY', 'value');
    // Reach in to the jwtSecret via the daemon internals helper.
    const { getDaemonInternals } = await import('./vault.js');
    const jwtSecret = await getDaemonInternals(vault)._getJwtSecret();

    const forgedExpZero = signJWT({ sub: 'FORGE_KEY', exp: 0 }, jwtSecret);
    await assert.rejects(
      () => vault.verifyToken(forgedExpZero),
      (err) => err.message.includes('exp'),
    );

    const forgedNoExp = signJWT({ sub: 'FORGE_KEY' }, jwtSecret);
    await assert.rejects(
      () => vault.verifyToken(forgedNoExp),
      (err) => err.message.includes('exp'),
    );

    const forgedForever = signJWT({ sub: 'FORGE_KEY', exp: Number.MAX_SAFE_INTEGER }, jwtSecret);
    await assert.rejects(
      () => vault.verifyToken(forgedForever),
      (err) => err.message.includes('exp') || err.message.includes('lifetime'),
    );
  });
});

describe('sealed vault — JIT auth hooks', () => {
  after(async () => {
    try { await unlink(TEST_VAULT); } catch {}
  });

  it('createAuthHook unseals just-in-time for requests', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    await vault.set('OPENCLAW_KEY', 'sk_test_jit_123');

    const hook = vault.createAuthHook({ OPENCLAW_KEY: 'X-API-Key' });
    const result = await hook({ method: 'GET', url: '/test', headers: {}, body: {} });

    assert.equal(result.headers['X-API-Key'], 'sk_test_jit_123');
  });

  it('createAuthHook returns null when no matching secrets', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const hook = vault.createAuthHook({ MISSING: 'X-Header' });
    const result = await hook({ method: 'GET', url: '/test', headers: {}, body: {} });
    assert.equal(result, null);
  });
});

describe('sealed vault — seal:// reference resolution', () => {
  after(async () => {
    try { await unlink(TEST_VAULT); } catch {}
  });

  it('unsealConfig resolves seal:// references in nested config', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const sealId = await vault.set('DB_PASSWORD', 'p@ssw0rd');

    const config = {
      database: {
        host: 'localhost',
        password: sealId, // seal://db-password-abc123
      },
      api: {
        keys: [sealId],
      },
    };

    const resolved = await vault.unsealConfig(config);
    assert.equal(resolved.database.password, 'p@ssw0rd');
    assert.equal(resolved.database.host, 'localhost'); // Non-sealed values pass through
    assert.equal(resolved.api.keys[0], 'p@ssw0rd');
  });

  it('unsealConfig passes through non-seal values', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });
    const config = { name: 'test', port: 3000, flag: true };
    const resolved = await vault.unsealConfig(config);
    assert.deepEqual(resolved, config);
  });

  // ─── Prototype pollution defense ──────────────────────────────────────

  it('unsealConfig does NOT pollute Object.prototype via __proto__ own property', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });

    // Build an input with a genuine OWN `__proto__` key. A plain literal
    // `{__proto__: …}` is sugar for `Object.setPrototypeOf`, so use
    // defineProperty to land it as an own data property.
    const config = { name: 'test' };
    Object.defineProperty(config, '__proto__', {
      value: { polluted: 'yes-via-proto' },
      enumerable: true,
      configurable: true,
      writable: true,
    });
    // Also try `constructor` and `prototype` for good measure.
    Object.defineProperty(config, 'constructor', {
      value: { polluted: 'yes-via-ctor' },
      enumerable: true,
      configurable: true,
      writable: true,
    });

    const canary = {};
    assert.equal(canary.polluted, undefined, 'baseline: Object.prototype not polluted');

    const resolved = await vault.unsealConfig(config);

    // (a) Object.prototype must NOT be polluted.
    assert.equal(({}).polluted, undefined, 'Object.prototype.polluted must remain undefined');
    assert.equal(canary.polluted, undefined, 'existing object must not inherit polluted');

    // (b) Dangerous keys must be filtered out of the result.
    assert.ok(!Object.prototype.hasOwnProperty.call(resolved, '__proto__'),
      'result must not carry an own __proto__ key');
    assert.ok(!Object.prototype.hasOwnProperty.call(resolved, 'constructor'),
      'result must not carry an own constructor key');

    // (c) Regular keys still flow through.
    assert.equal(resolved.name, 'test');
  });

  it('unsealConfig filters dangerous keys in nested objects', async () => {
    const vault = createVault({ path: TEST_VAULT, passphrase: PASSPHRASE });

    const nested = { inner: 'value' };
    Object.defineProperty(nested, '__proto__', {
      value: { nested_pollute: 'nope' },
      enumerable: true,
      configurable: true,
      writable: true,
    });

    const config = { outer: 'ok', child: nested };
    const resolved = await vault.unsealConfig(config);

    assert.equal(({}).nested_pollute, undefined, 'Object.prototype must remain clean');
    assert.ok(!Object.prototype.hasOwnProperty.call(resolved.child, '__proto__'));
    assert.equal(resolved.child.inner, 'value');
  });
});

describe('sealed vault — initVault and recovery envelope', () => {
  const INIT_VAULT = '/tmp/40mcp-test-init-vault.json';
  const INIT_PASSPHRASE = 'V@ult-Init#Test2026';

  after(async () => {
    try { await unlink(INIT_VAULT); } catch {}
  });

  it('initVault() creates vault with recovery envelope and returns formatted recovery key', async () => {
    const { vault, recoveryKey } = await initVault({ path: INIT_VAULT, passphrase: INIT_PASSPHRASE });
    assert.ok(vault, 'vault instance returned');
    assert.ok(recoveryKey, 'recovery key returned');
    // Recovery key format: 4 groups of 16 hex chars separated by dashes
    const groups = recoveryKey.split('-');
    assert.equal(groups.length, 4, 'recovery key has 4 groups');
    for (const group of groups) {
      assert.equal(group.length, 16, 'each group is 16 hex chars');
      assert.ok(/^[0-9a-f]{16}$/.test(group), 'each group is valid hex');
    }
    // Vault file should have recovery envelopes
    const { readFile } = await import('node:fs/promises');
    const raw = await readFile(INIT_VAULT, 'utf-8');
    const data = JSON.parse(raw);
    assert.equal(data.version, 3, 'vault file is v3');
    assert.ok(data.recoveryEnvelope, 'recoveryEnvelope present');
    assert.ok(data.recoveryKeyEnvelope, 'recoveryKeyEnvelope present');
  });

  it('initVault() throws if vault file already exists', async () => {
    // File was created by previous test
    await assert.rejects(
      () => initVault({ path: INIT_VAULT, passphrase: INIT_PASSPHRASE }),
      (err) => err.message.includes('already exists'),
    );
  });
});

describe('sealed vault — rotateKEK', () => {
  const ROTATE_VAULT = '/tmp/40mcp-test-rotate-kek-vault.json';
  const ROTATE_PASS = 'R0tate&Test#Vault26';
  const NEW_PASS = 'N3wR0tate&Pass#2026';

  after(async () => {
    try { await unlink(ROTATE_VAULT); } catch {}
  });

  it('rotateKEK() — vault is still readable after KEK rotation', async () => {
    const { vault } = await initVault({ path: ROTATE_VAULT, passphrase: ROTATE_PASS });
    await vault.set('SECRET_A', 'value-a');
    await vault.set('SECRET_B', 'value-b');

    await vault.rotateKEK(NEW_PASS);

    // Open a NEW vault instance with the new passphrase
    const vault2 = createVault({ path: ROTATE_VAULT, passphrase: NEW_PASS });
    assert.equal(await vault2.has('SECRET_A'), true, 'SECRET_A still exists');
    assert.equal(await vault2.has('SECRET_B'), true, 'SECRET_B still exists');

    // Issue and verify a token to confirm DEKs are intact
    const token = await vault2.issueToken('SECRET_A');
    assert.ok(token, 'token issued after KEK rotation');
    const verified = await vault2.verifyToken(token.token);
    assert.equal(verified.value, 'value-a', 'value readable after rotation');
  });

  it('rotateKEK() — tokens issued before rotation are invalidated', async () => {
    // Cross-process invariant: a JWT signed under the old KEK must NOT verify
    // after rotation. Without this guarantee a leaked pre-rotation token would
    // retain access through the rotation. The behaviour was correct in the
    // implementation but had no test coverage until now.
    const TOKEN_INVAL_VAULT = '/tmp/40mcp-test-token-inval-vault.json';
    try {
      const { vault } = await initVault({ path: TOKEN_INVAL_VAULT, passphrase: ROTATE_PASS });
      await vault.set('PRE_ROTATE_SECRET', 'plaintext-x');

      const oldToken = await vault.issueToken('PRE_ROTATE_SECRET');
      assert.ok(oldToken?.token, 'token issued before rotation');

      // Sanity: token verifies under the current KEK
      const verifiedBefore = await vault.verifyToken(oldToken.token);
      assert.equal(verifiedBefore.value, 'plaintext-x');

      // Rotate KEK — old jwtSecret is replaced
      await vault.rotateKEK(NEW_PASS);

      // The old token must NOT verify against the new jwtSecret
      await assert.rejects(
        () => vault.verifyToken(oldToken.token),
        (err) => err && /signature|invalid|verify/i.test(err.message || ''),
        'old token must fail verification after KEK rotation',
      );

      // And a freshly issued token under the new KEK still works
      const freshToken = await vault.issueToken('PRE_ROTATE_SECRET');
      const verifiedAfter = await vault.verifyToken(freshToken.token);
      assert.equal(verifiedAfter.value, 'plaintext-x');
    } finally {
      try { await unlink(TOKEN_INVAL_VAULT); } catch {}
    }
  });

  it('rotateKEK() — recovery capability preserved after rotation', async () => {
    // The vault from the previous test now has rotated KEK and a recovery envelope
    // Re-create a fresh vault for this test to be independent
    const ROTATE2_VAULT = '/tmp/40mcp-test-rotate-kek-vault2.json';
    try {
      const { vault, recoveryKey } = await initVault({ path: ROTATE2_VAULT, passphrase: ROTATE_PASS });
      await vault.set('RECOVERY_TEST', 'recovery-value');

      // Rotate the KEK
      await vault.rotateKEK(NEW_PASS);

      // Now recover using the recovery key with yet another passphrase
      const RECOVERY_PASS = 'Rec0very&Vault#2026';
      const recovered = await recoverVault({ path: ROTATE2_VAULT, recoveryKey, newPassphrase: RECOVERY_PASS });
      assert.ok(recovered, 'vault recovered after KEK rotation');
      assert.equal(await recovered.has('RECOVERY_TEST'), true, 'secret accessible after recovery');
    } finally {
      try { await unlink(ROTATE2_VAULT); } catch {}
    }
  });
});

describe('sealed vault — recoverVault', () => {
  const RECOVER_VAULT = '/tmp/40mcp-test-recover-vault.json';
  const ORIG_PASS = '0rig&Vault#Pass2026';
  const NEW_PASS = 'N3wPass&Recover#2026';

  after(async () => {
    try { await unlink(RECOVER_VAULT); } catch {}
  });

  it('recoverVault() — restores access after passphrase loss', async () => {
    const { recoveryKey } = await initVault({ path: RECOVER_VAULT, passphrase: ORIG_PASS });
    const vault1 = createVault({ path: RECOVER_VAULT, passphrase: ORIG_PASS });
    await vault1.set('LOST_SECRET', 'dont-lose-me');

    // Recover with recovery key (simulating forgotten passphrase)
    const recovered = await recoverVault({ path: RECOVER_VAULT, recoveryKey, newPassphrase: NEW_PASS });
    assert.ok(recovered, 'recovered vault instance returned');
    assert.equal(await recovered.has('LOST_SECRET'), true, 'secret still accessible after recovery');
  });

  it('recoverVault() — throws on wrong recovery key', async () => {
    await assert.rejects(
      () => recoverVault({ path: RECOVER_VAULT, recoveryKey: 'AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA', newPassphrase: NEW_PASS }),
      (err) => err.message.toLowerCase().includes('invalid') || err.message.toLowerCase().includes('decrypt'),
    );
  });

  // A recovery key that decodes to a non-32-byte buffer (typo, dropped
  // digit, substituted O↔0) must fail with a specific transcription-error
  // message BEFORE the decrypt attempt. The naive `Buffer.from(..., 'hex')`
  // silently truncates and emits a generic "could not decrypt" that hides
  // the real cause.
  it('recoverVault() — rejects short recovery keys with a transcription-error message', async () => {
    await assert.rejects(
      () => recoverVault({
        path: RECOVER_VAULT,
        // 62 hex chars instead of 64 → decodes to 31 bytes.
        recoveryKey: 'aaaaaaaaaaaaaaaa-aaaaaaaaaaaaaaaa-aaaaaaaaaaaaaaaa-aaaaaaaaaaaaaa',
        newPassphrase: NEW_PASS,
      }),
      (err) => /32 bytes|64 hex characters|transcription/.test(err.message),
    );
  });

  it('recoverVault() — rejects recovery keys with non-hex characters', async () => {
    await assert.rejects(
      () => recoverVault({
        path: RECOVER_VAULT,
        // 'Z' is not a hex digit; Buffer.from(...,'hex') silently truncates at
        // the first bad byte → 0-byte buffer.
        recoveryKey: 'ZZZZZZZZZZZZZZZZ-ZZZZZZZZZZZZZZZZ-ZZZZZZZZZZZZZZZZ-ZZZZZZZZZZZZZZZZ',
        newPassphrase: NEW_PASS,
      }),
      (err) => /32 bytes|64 hex characters/.test(err.message),
    );
  });

  it('recoverVault() — throws on vault without recovery envelope', async () => {
    const NO_ENV_VAULT = '/tmp/40mcp-test-no-env-vault.json';
    try {
      // createVault (not initVault) creates a vault without recovery envelope
      const vault = createVault({ path: NO_ENV_VAULT, passphrase: 'N0Recovery-Vault-Test-Passphrase' });
      await vault.set('X', 'y'); // triggers save, creates file without recovery envelope
      await assert.rejects(
        () => recoverVault({ path: NO_ENV_VAULT, recoveryKey: 'AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA', newPassphrase: 'N3wPass&NoEnv#2026' }),
        (err) => err.message.includes('no recovery envelope'),
      );
    } finally {
      try { await unlink(NO_ENV_VAULT); } catch {}
    }
  });
});

describe('sealed vault — createBearerHook', () => {
  const BEARER_VAULT = '/tmp/40mcp-test-bearer-vault.json';
  const BEARER_PASS = 'B3arer-Test-Passphrase-Strong';

  after(async () => {
    try { await unlink(BEARER_VAULT); } catch {}
  });

  it('createBearerHook() — emits Authorization: Bearer header', async () => {
    const vault = createVault({ path: BEARER_VAULT, passphrase: BEARER_PASS });
    await vault.set('MY_TOKEN', 'sk-live-abc123');

    const hook = vault.createBearerHook('MY_TOKEN');
    const result = await hook({ method: 'GET', url: '/test', headers: {}, body: {} });

    assert.ok(result, 'hook returns a result');
    assert.ok(result.headers, 'result has headers');
    assert.equal(result.headers['Authorization'], 'Bearer sk-live-abc123');
  });

  it('createBearerHook() — returns null when secret not found', async () => {
    const vault = createVault({ path: BEARER_VAULT, passphrase: BEARER_PASS });
    const hook = vault.createBearerHook('NONEXISTENT_TOKEN');
    const result = await hook({ method: 'GET', url: '/test', headers: {}, body: {} });
    assert.equal(result, null);
  });
});
