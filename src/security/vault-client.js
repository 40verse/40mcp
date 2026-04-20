/**
 * Vault daemon client — same hook API as createVault(), but delegates to daemon over IPC.
 *
 * Security: bridges never hold VAULT_PASSPHRASE or the KEK.
 * Instead, they authenticate with daemonSecret, receive a scoped JWT, and call unseal.
 *
 * Fallback: if daemon socket is unavailable (ENOENT / ECONNREFUSED), falls back to
 * direct vault load (Phase 1 path) when vaultPath + passphrase are provided.
 *
 * @module security/vault-client
 */

import { createConnection } from 'node:net';
import { createVault, getDaemonInternals } from './vault.js';
import { defaultSocketPath } from './vault-daemon.js';

/**
 * Create a vault daemon client.
 *
 * @param {object} opts
 * @param {string} [opts.socketPath] - Socket path (default: ~/.40mcp/daemon.sock)
 * @param {string} [opts.configPath] - Bridge config file path (used for scope grounding)
 * @param {string} [opts.daemonSecret] - Hex string from startDaemon()
 * @param {string} [opts.vaultPath] - Fallback vault file path
 * @param {string} [opts.passphrase] - Fallback vault passphrase
 * @returns {object} Vault-compatible hook interface
 */
export function createVaultDaemonClient({
  socketPath = defaultSocketPath(),
  configPath,
  daemonSecret,
  vaultPath,
  passphrase,
} = {}) {
  let _token = null;
  let _tokenExpiresAt = 0;
  let _refreshPromise = null;
  let _fallback = null;
  let _msgId = 0;

  function nextId() {
    return `vdc-${++_msgId}`;
  }

  // Send a single NDJSON message, receive first response line
  function sendMsg(msg) {
    return new Promise((resolve, reject) => {
      const sock = createConnection(socketPath);
      let buf = '';
      const timeout = setTimeout(() => {
        sock.destroy();
        reject(new Error('Vault daemon connection timeout'));
      }, 5000);

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
            reject(new Error('Invalid daemon response'));
          }
        }
      });

      sock.once('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }

  // Return cached JWT (auto-refresh 30s before expiry).
  //
  // Coalesce concurrent refresh attempts so N parallel unseal callers only
  // open ONE socket to the daemon and store one token. Without this, the
  // previous implementation let N calls each open a socket, each send `auth`,
  // each receive their own token, and last-writer-wins on `_token` /
  // `_tokenExpiresAt` — benign for correctness of a single caller but wastes
  // sockets and means an auth failure from ONE racing caller can clobber a
  // healthy cached token. Mirrors the `_refreshPromise` pattern used by
  // `OAuth2TokenManager.getToken` in core/client.js.
  async function getToken() {
    if (_token && Date.now() < _tokenExpiresAt - 30_000) {
      return _token;
    }
    if (_refreshPromise) return _refreshPromise;

    _refreshPromise = (async () => {
      const res = await sendMsg({
        id: nextId(),
        type: 'auth',
        daemonSecret,
        configPath,
      });
      if (res.type === 'error') {
        throw new Error(`Vault daemon auth failed: ${res.message}`);
      }
      _token = res.token;
      _tokenExpiresAt = res.expiresAt;
      return _token;
    })().finally(() => {
      _refreshPromise = null;
    });
    return _refreshPromise;
  }

  // Unseal a secret via daemon
  async function unsealViaDaemon(name) {
    const token = await getToken();
    const res = await sendMsg({
      id: nextId(),
      type: 'unseal',
      token,
      name,
    });

    if (res.type === 'error') {
      throw new Error(`Vault daemon unseal failed: ${res.message}`);
    }

    return res.value;
  }

  // Try daemon, fall back to direct vault on ENOENT/ECONNREFUSED
  async function unsealWithFallback(name) {
    try {
      return await unsealViaDaemon(name);
    } catch (err) {
      if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
        if (!_fallback) {
          if (!vaultPath || !passphrase) {
            throw new Error(
              'Vault daemon unavailable and no fallback vault configured. ' +
              'Provide vaultPath + passphrase for Phase 1 fallback.',
            );
          }
          _fallback = createVault({ path: vaultPath, passphrase });
        }
        return getDaemonInternals(_fallback)._unsealByName(name);
      }
      throw err;
    }
  }

  return {
    /**
     * Create a beforeRequest hook that injects custom header with unsealed value.
     * Compatible with createVault().createAuthHook().
     *
     * @param {Record<string, string>} mapping - { secretName: headerName }
     * @returns {Function} beforeRequest hook
     */
    createAuthHook(mapping) {
      return async (_req) => {
        const headers = {};
        for (const [secretName, headerName] of Object.entries(mapping)) {
          try {
            const value = await unsealWithFallback(secretName);
            if (value) headers[headerName] = value;
          } catch (err) {
            if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
              // B3: fail closed — silently dropping auth headers lets requests
              // proceed unauthenticated, which is a security regression.
              // Throw so the caller sees a hard failure rather than a silent
              // no-op that leaks unprotected requests to the upstream.
              throw new Error(
                `[vault-client] vault daemon unavailable (${err.code}) — ` +
                `secret "${secretName}" not unsealed; refusing to dispatch without auth header "${headerName}"`,
              );
            }
            throw err;
          }
        }
        return Object.keys(headers).length > 0 ? { headers } : null;
      };
    },

    /**
     * Create a beforeRequest hook that injects Authorization: Bearer <value>.
     * Compatible with createVault().createBearerHook().
     *
     * @param {string} name - Secret name in vault
     * @returns {Function} beforeRequest hook
     */
    createBearerHook(name) {
      return async (_req) => {
        try {
          const value = await unsealWithFallback(name);
          if (!value) return null;
          return { headers: { Authorization: `Bearer ${value}` } };
        } catch (err) {
          if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
            // B3: fail closed — silently dropping the Bearer token lets requests
            // proceed unauthenticated, which is a security regression. Throw so
            // the caller sees a hard failure instead of a silent no-op.
            throw new Error(
              `[vault-client] vault daemon unavailable at ${socketPath} (${err.code}) — ` +
              `secret "${name}" not unsealed; refusing to dispatch without Authorization header`,
            );
          }
          throw err;
        }
      };
    },
  };
}
