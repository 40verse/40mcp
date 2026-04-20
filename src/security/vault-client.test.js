import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, unlink, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createVault } from './vault.js';
import { startDaemon } from './vault-daemon.js';
import { createVaultDaemonClient } from './vault-client.js';

const PASSPHRASE = 'Cl1ent-Test-Passphrase-DoNotUse';

describe('vault-client', {
  skip: process.platform === 'win32'
    ? 'Unix-domain-socket IPC; Windows uses named pipes at \\\\.\\pipe\\<name>'
    : false,
}, () => {
  let tmpDir;
  let vaultPath;
  let socketPath;
  let pidPath;
  let configPath;
  let daemon;
  let daemonSecret;

  before(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), '40mcp-client-test-'));
    vaultPath = join(tmpDir, 'vault.json');
    socketPath = join(tmpDir, 'client-daemon.sock');
    pidPath = join(tmpDir, 'client-daemon.pid');
    configPath = join(tmpDir, 'bridge-config.json');

    // Seed vault
    const vault = createVault({ path: vaultPath, passphrase: PASSPHRASE });
    await vault.set('STRIPE_KEY', 'sk_test_123456');
    await vault.set('GITHUB_TOKEN', 'ghp_abcdef');

    // Bridge config referencing STRIPE_KEY
    await writeFile(configPath, JSON.stringify({
      name: 'test-bridge',
      baseUrl: 'https://api.stripe.com',
      auth: { type: 'sealed-bearer', name: 'STRIPE_KEY' },
      tools: [],
    }), 'utf-8');

    daemon = await startDaemon({
      vaultPath,
      passphrase: PASSPHRASE,
      socketPath,
      pidPath,
      tokenTTL: 300,
      allowedConfigPaths: [configPath],
    });
    daemonSecret = daemon.daemonSecret;
  });

  after(async () => {
    if (daemon) await daemon.close();
    for (const f of [vaultPath, socketPath, pidPath, configPath]) {
      try { await unlink(f); } catch {}
    }
  });

  it('createBearerHook() injects Authorization header via daemon', async () => {
    const client = createVaultDaemonClient({ socketPath, configPath, daemonSecret });
    const hook = client.createBearerHook('STRIPE_KEY');

    const result = await hook({});
    assert.ok(result, 'hook should return headers object');
    assert.equal(result.headers['Authorization'], 'Bearer sk_test_123456');
  });

  it('createAuthHook() injects custom header via daemon', async () => {
    // Config that grants access to STRIPE_KEY
    const client = createVaultDaemonClient({ socketPath, configPath, daemonSecret });
    const hook = client.createAuthHook({ STRIPE_KEY: 'X-Stripe-Key' });

    const result = await hook({});
    assert.ok(result);
    assert.equal(result.headers['X-Stripe-Key'], 'sk_test_123456');
  });

  it('createBearerHook() throws for out-of-scope secret (daemon application error)', async () => {
    // GITHUB_TOKEN is NOT in configPath scope — daemon returns an error response,
    // which is a real (non-connection) error and must not be swallowed.
    const client = createVaultDaemonClient({ socketPath, configPath, daemonSecret });
    const hook = client.createBearerHook('GITHUB_TOKEN');

    await assert.rejects(hook({}), /Vault daemon unseal failed/);
  });

  it('falls back to direct vault when daemon unavailable', async () => {
    const noSockPath = join(tmpDir, 'nonexistent.sock');
    const client = createVaultDaemonClient({
      socketPath: noSockPath,
      configPath,
      daemonSecret,
      vaultPath,
      passphrase: PASSPHRASE,
    });

    const hook = client.createBearerHook('STRIPE_KEY');
    const result = await hook({});
    assert.ok(result, 'fallback should provide result');
    assert.equal(result.headers['Authorization'], 'Bearer sk_test_123456');
  });

  it('throws when daemon unavailable and no fallback configured', async () => {
    const noSockPath = join(tmpDir, 'missing.sock');
    const client = createVaultDaemonClient({
      socketPath: noSockPath,
      configPath,
      daemonSecret,
      // no vaultPath or passphrase
    });

    const hook = client.createBearerHook('STRIPE_KEY');
    // ENOENT is caught inside unsealWithFallback; without a fallback vault it throws
    // a configuration error — this must surface rather than be swallowed.
    await assert.rejects(hook({}), /Vault daemon unavailable and no fallback vault configured/);
  });

  it('caches JWT across multiple unseal calls', async () => {
    const client = createVaultDaemonClient({ socketPath, configPath, daemonSecret });
    const hook = client.createBearerHook('STRIPE_KEY');

    // Call twice — second call should reuse cached token
    const r1 = await hook({});
    const r2 = await hook({});
    assert.equal(r1.headers['Authorization'], r2.headers['Authorization']);
  });
});
