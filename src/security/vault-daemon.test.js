import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, unlink, mkdtemp, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createConnection } from 'node:net';
import { createVault } from './vault.js';
import { startDaemon } from './vault-daemon.js';

const PASSPHRASE = 'Da3mon-Test-Passphrase-DoNotUse';

// Helper: send one NDJSON message to the daemon and collect the first response line
function sendMsg(socketPath, msg) {
  return new Promise((resolve, reject) => {
    const sock = createConnection(socketPath);
    let buf = '';
    const timeout = setTimeout(() => {
      sock.destroy();
      reject(new Error('timeout'));
    }, 3000);

    sock.once('connect', () => {
      sock.write(JSON.stringify(msg) + '\n');
    });

    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timeout);
        const line = buf.slice(0, nl).trim();
        sock.destroy();
        try {
          resolve(JSON.parse(line));
        } catch {
          reject(new Error(`Invalid JSON response: ${line}`));
        }
      }
    });

    sock.once('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

describe('vault-daemon', {
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

  let ghostConfigPath;
  let noAuthConfigPath;

  before(async () => {
    // On macOS, tmpdir() returns `/var/folders/...` but /var is a symlink to
    // /private/var. The daemon canonicalizes configPaths via fs.realpath, so
    // we must canonicalize our tmpDir at test setup too — otherwise the
    // allowlist stores /var/... while the auth handler compares /private/var/...
    // and every request is rejected. Linux has no such symlink.
    tmpDir = await realpath(await mkdtemp(join(tmpdir(), '40mcp-daemon-test-')));
    vaultPath = join(tmpDir, 'vault.json');
    socketPath = join(tmpDir, 'daemon.sock');
    pidPath = join(tmpDir, 'daemon.pid');
    configPath = join(tmpDir, 'bridge-config.json');
    ghostConfigPath = join(tmpDir, 'ghost-config.json');
    noAuthConfigPath = join(tmpDir, 'no-auth-config.json');

    // Seed vault with test secret
    const vault = createVault({ path: vaultPath, passphrase: PASSPHRASE });
    await vault.set('MY_API_KEY', 'super-secret-token-value');
    await vault.set('OTHER_SECRET', 'other-value');

    // Write bridge config referencing only MY_API_KEY
    const bridgeConfig = {
      name: 'test-bridge',
      baseUrl: 'https://api.example.com',
      auth: { type: 'sealed-bearer', name: 'MY_API_KEY' },
      tools: [],
    };
    await writeFile(configPath, JSON.stringify(bridgeConfig), 'utf-8');

    // Start daemon with an explicit configPath whitelist.
    // All test configs must be pre-registered; attempts to use unregistered
    // paths are rejected by the daemon (and exercised by a dedicated test).
    daemon = await startDaemon({
      vaultPath,
      passphrase: PASSPHRASE,
      socketPath,
      pidPath,
      tokenTTL: 300,
      allowedConfigPaths: [configPath, ghostConfigPath, noAuthConfigPath],
    });
    daemonSecret = daemon.daemonSecret;
  });

  after(async () => {
    if (daemon) await daemon.close();
    for (const f of [vaultPath, socketPath, pidPath, configPath]) {
      try { await unlink(f); } catch {}
    }
  });

  it('responds to ping with pong', async () => {
    const res = await sendMsg(socketPath, { id: 'p1', type: 'ping' });
    assert.equal(res.type, 'pong');
    assert.equal(res.id, 'p1');
  });

  it('issues a token for valid daemonSecret + configPath', async () => {
    const res = await sendMsg(socketPath, {
      id: 'a1',
      type: 'auth',
      daemonSecret,
      configPath,
    });
    assert.equal(res.type, 'token', `expected token, got: ${JSON.stringify(res)}`);
    assert.ok(typeof res.token === 'string');
    assert.ok(typeof res.expiresAt === 'number');
    assert.ok(res.expiresAt > Date.now());
  });

  it('rejects auth with wrong daemonSecret', async () => {
    const res = await sendMsg(socketPath, {
      id: 'a2',
      type: 'auth',
      daemonSecret: 'deadbeef'.repeat(8), // wrong
      configPath,
    });
    assert.equal(res.type, 'error');
    assert.ok(res.message.includes('Invalid daemon secret'));
  });

  it('unseals a secret with a valid in-scope JWT', async () => {
    // Get token first
    const authRes = await sendMsg(socketPath, {
      id: 'u1-auth',
      type: 'auth',
      daemonSecret,
      configPath,
    });
    assert.equal(authRes.type, 'token');

    // Unseal with the token
    const unsealRes = await sendMsg(socketPath, {
      id: 'u1',
      type: 'unseal',
      token: authRes.token,
      name: 'MY_API_KEY',
    });
    assert.equal(unsealRes.type, 'value');
    assert.equal(unsealRes.value, 'super-secret-token-value');
  });

  it('rejects unseal for a secret not in config scope', async () => {
    // Token is scoped to MY_API_KEY only (from configPath)
    const authRes = await sendMsg(socketPath, {
      id: 'u2-auth',
      type: 'auth',
      daemonSecret,
      configPath,
    });
    assert.equal(authRes.type, 'token');

    // OTHER_SECRET is in vault but not in config — scope elevation blocked
    const unsealRes = await sendMsg(socketPath, {
      id: 'u2',
      type: 'unseal',
      token: authRes.token,
      name: 'OTHER_SECRET',
    });
    assert.equal(unsealRes.type, 'error');
    // Error message is now opaque to prevent oracle-based enumeration.
    // Must NOT echo the secret name or 'not in token scope' internals.
    assert.ok(
      unsealRes.message === 'Secret access denied' || unsealRes.message.includes('access denied'),
      `expected opaque access-denied message, got: ${unsealRes.message}`,
    );
  });

  it('rejects unseal with an invalid JWT', async () => {
    const res = await sendMsg(socketPath, {
      id: 'u3',
      type: 'unseal',
      token: 'not.a.jwt',
      name: 'MY_API_KEY',
    });
    assert.equal(res.type, 'error');
    assert.ok(res.message.includes('Invalid token'));
  });

  it('returns error for unknown secret name (in scope but not in vault)', async () => {
    // Write a config that claims "GHOST_SECRET" — the path is on the daemon's allowlist
    await writeFile(ghostConfigPath, JSON.stringify({
      auth: { type: 'sealed-bearer', name: 'GHOST_SECRET' },
    }), 'utf-8');

    const authRes = await sendMsg(socketPath, {
      id: 'u4-auth',
      type: 'auth',
      daemonSecret,
      configPath: ghostConfigPath,
    });
    assert.equal(authRes.type, 'token');

    const unsealRes = await sendMsg(socketPath, {
      id: 'u4',
      type: 'unseal',
      token: authRes.token,
      name: 'GHOST_SECRET',
    });
    assert.equal(unsealRes.type, 'error');
    assert.ok(unsealRes.message.includes('not found in vault'));

    try { await unlink(ghostConfigPath); } catch {}
  });

  it('issues empty-scope token when configPath has no auth.name', async () => {
    await writeFile(noAuthConfigPath, JSON.stringify({
      name: 'no-auth',
      baseUrl: 'https://api.example.com',
      tools: [],
    }), 'utf-8');

    const authRes = await sendMsg(socketPath, {
      id: 'u5-auth',
      type: 'auth',
      daemonSecret,
      configPath: noAuthConfigPath,
    });
    assert.equal(authRes.type, 'token');

    // Any unseal should fail — scope is empty
    const unsealRes = await sendMsg(socketPath, {
      id: 'u5',
      type: 'unseal',
      token: authRes.token,
      name: 'MY_API_KEY',
    });
    assert.equal(unsealRes.type, 'error');
    // Opaque access-denied — same message as out-of-scope to prevent oracle enumeration
    assert.ok(
      unsealRes.message === 'Secret access denied' || unsealRes.message.includes('access denied'),
      `expected opaque access-denied message, got: ${unsealRes.message}`,
    );

    try { await unlink(noAuthConfigPath); } catch {}
  });

  it('REJECTS wire-supplied configPath outside the allowlist (arbitrary file read defense)', async () => {
    // Attacker with the daemonSecret asks the daemon to read /etc/passwd.
    // Previously the daemon would readFile() any path it had permission for;
    // now the allowlist gate rejects it before touching the filesystem.
    const res = await sendMsg(socketPath, {
      id: 'attack-1',
      type: 'auth',
      daemonSecret,
      configPath: '/etc/passwd',
    });
    assert.equal(res.type, 'error');
    assert.ok(res.message.includes('configPath not allowed'));
  });

  it('responds to unknown message type with error', async () => {
    const res = await sendMsg(socketPath, { id: 'x1', type: 'bogus' });
    assert.equal(res.type, 'error');
    assert.ok(res.message.includes('Unknown message type'));
  });
});
