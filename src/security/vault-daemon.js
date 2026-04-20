/**
 * Vault daemon — single process that holds the KEK and issues short-lived JWTs to bridges.
 *
 * This eliminates the vulnerability where each bridge process held VAULT_PASSPHRASE.
 * Instead: daemon holds KEK, bridges get scoped short-lived JWTs via Unix socket IPC.
 *
 * Protocol: NDJSON over Unix socket (or named pipe on Windows).
 *
 * Message types (client → daemon):
 *   { id, type: 'ping' }
 *   { id, type: 'auth', daemonSecret, configPath }
 *   { id, type: 'unseal', token, name }
 *   { id, type: 'shutdown', daemonSecret }
 *
 * Responses (daemon → client):
 *   { id, type: 'pong' }
 *   { id, type: 'token', token, expiresAt }
 *   { id, type: 'value', value }
 *   { id, type: 'ok' }
 *   { id, type: 'error', message }
 *
 * Security model:
 * - daemonSecret: 32-byte random nonce generated at daemon startup (never persisted)
 * - Scope: daemon reads bridge config from disk to determine allowed secrets
 *   (bridge cannot self-declare its own scope — config-grounded)
 * - JWT: HS256, signed with sha256(kek + 'jwt-signing'), TTL=5min, scope=[...secretNames]
 *
 * @module security/vault-daemon
 */

import { createServer, createConnection } from 'node:net';
import { readFile, unlink, open, mkdir, chmod, realpath } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname, basename, resolve as resolvePath } from 'node:path';
import { createVault, getDaemonInternals } from './vault.js';
import { safeLog } from '../core/events.js';
import { randomBytes, timingSafeEqual, signJWT, verifyJWT, DEFAULT_TOKEN_TTL } from './crypto.js';

/**
 * Default socket path: ~/.40mcp/daemon.sock (Unix) or \\.\pipe\40mcp-daemon (Windows).
 * @returns {string}
 */
export function defaultSocketPath() {
  if (process.platform === 'win32') {
    return '\\\\.\\pipe\\40mcp-daemon';
  }
  return join(homedir(), '.40mcp', 'daemon.sock');
}

/**
 * Default PID file path: ~/.40mcp/daemon.pid.
 * @returns {string}
 */
export function defaultPidPath() {
  return join(homedir(), '.40mcp', 'daemon.pid');
}

/**
 * Collect all secret names referenced in a bridge config.
 * Reads auth.name at root level and from each tool entry.
 * @private
 */
function collectSecretNames(cfg) {
  const names = new Set();
  if (cfg?.auth?.name) names.add(cfg.auth.name);
  if (Array.isArray(cfg?.tools)) {
    for (const tool of cfg.tools) {
      if (tool?.auth?.name) names.add(tool.auth.name);
    }
  }
  return [...names];
}

/**
 * Probe a socket path — returns 'connectable', 'stale', or 'missing'.
 * @private
 */
async function probeSocket(socketPath) {
  return new Promise((resolve) => {
    const probe = createConnection(socketPath);
    probe.once('connect', () => {
      probe.destroy();
      resolve('connectable');
    });
    probe.once('error', (err) => {
      if (err.code === 'ECONNREFUSED') resolve('stale');
      else if (err.code === 'ENOENT') resolve('missing');
      else resolve('stale');
    });
  });
}

/**
 * Start the vault daemon.
 *
 * @param {object} opts
 * @param {string} opts.vaultPath - Path to vault file
 * @param {string} opts.passphrase - Master passphrase
 * @param {string} [opts.socketPath] - Unix socket / named pipe path
 * @param {string} [opts.pidPath] - PID file path
 * @param {number} [opts.tokenTTL=300] - JWT TTL in seconds
 * @param {string[]} [opts.allowedConfigPaths] - Absolute paths of bridge configs the
 *   daemon is willing to parse for scope grounding. Required unless
 *   `trustWireConfigPath:true` is set. Previous security finding: the
 *   previous implementation accepted any `configPath` over the wire and
 *   called `readFile` on it, granting arbitrary-file-read capability to
 *   anything that could authenticate to the socket.
 * @param {boolean} [opts.trustWireConfigPath=false] - Legacy mode — accept
 *   any `configPath` the client sends. Strongly discouraged.
 * @returns {Promise<{ socketPath: string, pidPath: string, daemonSecret: string, close: Function }>}
 */
export async function startDaemon({
  vaultPath,
  passphrase,
  socketPath = defaultSocketPath(),
  pidPath = defaultPidPath(),
  tokenTTL = DEFAULT_TOKEN_TTL,
  allowedConfigPaths,
  trustWireConfigPath = false,
}) {
  // Canonicalize the allowlist once at startup via fs.realpath so symlink
  // targets — not link paths — are what we compare against. Earlier finding:
  // using path.resolve alone left a symlink-redirect window where an
  // attacker who could swap a symlink inside an allowlisted path could
  // redirect the daemon to read an arbitrary target file. realpath resolves
  // through all symlinks at startup, and the auth handler also realpaths
  // the incoming configPath so the comparison is canonical-to-canonical.
  const allowedConfigPathList = Array.isArray(allowedConfigPaths) ? allowedConfigPaths : [];
  const allowedConfigPathSet = new Set();
  for (const p of allowedConfigPathList) {
    const absolute = resolvePath(p);
    try {
      allowedConfigPathSet.add(await realpath(absolute));
    } catch {
      // File may not yet exist at daemon startup — canonicalize the parent
      // directory (which always exists; mkdir happened before this call in
      // every real-world flow) and recompose. Without this step, macOS symlinks
      // in the prefix (`/var` → `/private/var`, `/tmp` → `/private/tmp`) cause
      // the allowlist to store a non-canonical path while the auth handler
      // realpaths the incoming path to the canonical form — every request for
      // a not-yet-existing config was rejected.
      try {
        const parentCanonical = await realpath(dirname(absolute));
        allowedConfigPathSet.add(join(parentCanonical, basename(absolute)));
      } catch {
        allowedConfigPathSet.add(absolute);
      }
    }
  }
  if (!trustWireConfigPath && allowedConfigPathSet.size === 0) {
    process.stderr.write(
      '[vault-daemon] WARNING: no allowedConfigPaths provided — scope-grounding is effectively disabled. ' +
      'Pass an explicit allowlist or set trustWireConfigPath:true to retain the legacy (insecure) behaviour.\n',
    );
  }
  // Generate session-local daemonSecret (never persisted — only in memory + returned to caller)
  const daemonSecretBuf = randomBytes(32);
  const daemonSecret = daemonSecretBuf.toString('hex');

  // Open vault and verify it loads successfully before accepting connections
  const vault = createVault({ path: vaultPath, passphrase, tokenTTL });
  await getDaemonInternals(vault)._getJwtSecret();

  // ─── PID file (O_EXCL — single daemon enforcement) ──────────────────────────
  try { await mkdir(dirname(pidPath), { recursive: true }); } catch {}

  // Defensive pattern: wrap open+write+close in a
  // try/finally so an error during writeFile cannot leak the fd. The pid
  // file is tiny so this almost never trips, but the defensive pattern is
  // cheap.
  async function openAndWritePid() {
    const fd = await open(pidPath, 'wx', 0o600);
    try {
      await fd.writeFile(String(process.pid));
    } finally {
      await fd.close().catch(() => {});
    }
  }

  try {
    await openAndWritePid();
  } catch (err) {
    if (err.code === 'EEXIST') {
      // Check if existing daemon is still alive.
      //
      // Security consideration: after a reboot, the PID recorded in
      // `daemon.pid` may have been recycled onto a completely unrelated
      // process (systemd, bash, anything). `kill(pid, 0)` would then
      // succeed and the daemon would refuse to start with "already
      // running (PID X)" — a DoS. Additionally verify that the existing
      // PID actually belongs to a node/40mcp process by reading
      // `/proc/<pid>/comm` (Linux) or `/proc/<pid>/exe` (symlink
      // target). On non-Linux we still fall back to `kill(pid, 0)` as
      // a best-effort signal check.
      let existingPid;
      try {
        existingPid = parseInt((await readFile(pidPath, 'utf-8')).trim(), 10);
        if (!Number.isFinite(existingPid) || existingPid <= 0) {
          throw Object.assign(new Error('invalid pid'), { code: 'ESRCH' });
        }
        process.kill(existingPid, 0); // signal 0 = existence check, throws ESRCH if dead
        // PID exists, but is it ACTUALLY the daemon? Check /proc on Linux.
        if (process.platform === 'linux') {
          let comm = null;
          try {
            comm = (await readFile(`/proc/${existingPid}/comm`, 'utf-8')).trim();
          } catch { /* /proc read may fail — fall through and trust kill(0) */ }
          if (comm && !/node|40mcp/i.test(comm)) {
            // PID belongs to an unrelated process (PID reuse after reboot).
            // Treat the PID file as stale.
            throw Object.assign(
              new Error(`pid reused by ${comm}`),
              { code: 'ESRCH' },
            );
          }
        }
        throw new Error(`Daemon already running (PID ${existingPid})`);
      } catch (killErr) {
        if (killErr.code === 'ESRCH') {
          // Stale PID — remove and retry once. Earlier finding:
          // if a racing daemon startup takes the slot between our unlink
          // and retry, the retry throws EEXIST again; surface it as
          // "already running" rather than an opaque error.
          await unlink(pidPath);
          try {
            await openAndWritePid();
          } catch (retryErr) {
            if (retryErr.code === 'EEXIST') {
              let racerPid = 'unknown';
              try {
                racerPid = (await readFile(pidPath, 'utf-8')).trim();
              } catch { /* ignore */ }
              throw new Error(`Daemon already running (PID ${racerPid}) — lost race during stale-PID cleanup`);
            }
            throw retryErr;
          }
        } else {
          throw killErr;
        }
      }
    } else {
      throw err;
    }
  }

  // ─── Stale socket cleanup (Unix only) ───────────────────────────────────────
  if (process.platform !== 'win32') {
    const state = await probeSocket(socketPath);
    if (state === 'connectable') {
      try { await unlink(pidPath); } catch {}
      throw new Error(`Socket ${socketPath} is already connectable — daemon may be running`);
    }
    if (state === 'stale') {
      try { await unlink(socketPath); } catch {}
    }
  }

  // ─── Per-connection NDJSON handler ──────────────────────────────────────────
  async function handleMessage(socket, line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      socket.write(JSON.stringify({ type: 'error', message: 'Invalid JSON' }) + '\n');
      return;
    }

    const { id, type } = msg;

    try {
      switch (type) {
        case 'ping': {
          socket.write(JSON.stringify({ id, type: 'pong' }) + '\n');
          break;
        }

        case 'auth': {
          // Validate daemonSecret — constant-time comparison, always 32 bytes.
          // H1: checking `presented.length !== daemonSecretBuf.length` before
          // timingSafeEqual leaks whether the input has the right length via
          // timing (the short-circuit path exits in O(1) vs O(n)). Fix: always
          // copy the input into a fixed 32-byte buffer before comparing so the
          // timingSafeEqual call runs regardless of input length, and length
          // divergence is caught inside the equal comparison not before it.
          const presented = Buffer.from(msg.daemonSecret || '', 'hex');
          {
            const expected = daemonSecretBuf; // always 32 bytes
            const candidate = Buffer.alloc(32);
            presented.copy(candidate, 0, 0, Math.min(presented.length, 32));
            // Security fix: remove the `presented.length !== expected.length`
            // pre-check. Both `candidate` and `expected` are always exactly
            // 32 bytes — the pre-check is redundant and harmful: a 31-byte
            // input exits in O(1) (short-circuit) while a 32-byte input runs
            // timingSafeEqual in O(n), leaking "you got the length right"
            // via timing. Always run timingSafeEqual exclusively.
            if (!timingSafeEqual(candidate, expected)) {
              socket.write(JSON.stringify({ id, type: 'error', message: 'Invalid daemon secret' }) + '\n');
              return;
            }
          }

          // Config-grounded scope: read bridge config from disk — bridge cannot self-declare.
          // Config security finding: only accept configPath values whitelisted at daemon
          // startup. A malicious local process that stole daemonSecret can no longer ask the
          // daemon to read arbitrary files (/etc/shadow, /proc/1/environ, etc.).
          //
          // Earlier fix: the previous implementation accepted the
          // request when EITHER the canonical OR the raw path was in the
          // allowlist, and then read via the RAW path. If an allowlist entry
          // did not exist at daemon startup (common in test/CI or
          // "daemon-before-bridge" startup ordering), the raw path was
          // stored. An attacker who could drop a symlink at that path after
          // startup could then redirect the daemon's `readFile` through the
          // symlink to an arbitrary file. Now: require the canonical path
          // (post-realpath) to be in the allowlist, and always read via the
          // canonical path — never the raw/symlink path.
          let allowedSecrets = [];
          if (msg.configPath) {
            const absRequested = resolvePath(msg.configPath);
            let canonical;
            try {
              canonical = await realpath(absRequested);
            } catch {
              // File missing at auth time — cannot canonicalize. Fall back
              // to the resolved path for whitelist comparison only (this
              // handles the benign "config does not yet exist" case), but
              // we will NOT pass the symlink-prone path to readFile.
              canonical = absRequested;
            }
            const pathAllowed = trustWireConfigPath || allowedConfigPathSet.has(canonical);
            if (!pathAllowed) {
              // Security note: POSIX filenames may contain raw
              // `\n`, so `absRequested` / `canonical` is a log-forgery
              // primitive if a local attacker can plant a file with a
              // newline in its name under any directory on disk. scrub.
              process.stderr.write(
                `[vault-daemon] SECURITY: refused configPath "${safeLog(absRequested, 256)}" (canonical "${safeLog(canonical, 256)}") — not in allowedConfigPaths whitelist\n`,
              );
              socket.write(
                JSON.stringify({ id, type: 'error', message: 'configPath not allowed' }) + '\n',
              );
              return;
            }
            try {
              // TOCTOU fix: eliminate the TOCTOU window between realpath() and
              // readFile(string). Open the file with O_NOFOLLOW so that if an
              // attacker swaps the last path component to a symlink after our
              // realpath() check, the open() call fails (ELOOP on Linux/macOS)
              // rather than following the new symlink. Then read via the fd
              // (not the string path) so the kernel never re-resolves the name.
              // O_NOFOLLOW is POSIX; fall back to 0 on platforms that lack it
              // (Windows) — the whitelist check is still the primary defence.
              const O_RDONLY = fsConstants.O_RDONLY ?? 0;
              const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
              const fd = await open(canonical, O_RDONLY | O_NOFOLLOW);
              try {
                const raw = await fd.readFile({ encoding: 'utf-8' });
                allowedSecrets = collectSecretNames(JSON.parse(raw));
              } finally {
                await fd.close().catch(() => {});
              }
            } catch {
              allowedSecrets = []; // fail-secure: if config unreadable, no secrets
            }
          }

          // Reload vault if file changed on disk
          await vault._reloadIfChanged();

          const jwtSecret = await getDaemonInternals(vault)._getJwtSecret();
          const now = Math.floor(Date.now() / 1000);
          const payload = {
            sub: msg.configPath || 'bridge',
            scope: allowedSecrets,
            iat: now,
            exp: now + tokenTTL,
          };
          const token = signJWT(payload, jwtSecret);
          socket.write(
            JSON.stringify({ id, type: 'token', token, expiresAt: (now + tokenTTL) * 1000 }) + '\n',
          );
          break;
        }

        case 'unseal': {
          // Validate and decode JWT
          const jwtSecret = await getDaemonInternals(vault)._getJwtSecret();
          let payload;
          try {
            payload = verifyJWT(msg.token, jwtSecret);
          } catch (err) {
            socket.write(
              JSON.stringify({ id, type: 'error', message: `Invalid token: ${err.message}` }) + '\n',
            );
            return;
          }

          const name = msg.name;

          // Scope check — only secrets listed in the JWT scope are accessible
          if (!Array.isArray(payload.scope) || !payload.scope.includes(name)) {
            // Security requirement: opaque message — do NOT echo the secret name.
            // The scope-check path previously echoed `name` verbatim, enabling
            // an oracle-based membership enumeration attack: any authenticated
            // socket client could probe secret names one-by-one and distinguish
            // "name exists but out-of-scope" from "name not found" errors.
            // The "not found" path (below) was already fixed.
            // Secret names come from caller input and POSIX names may contain
            // `\n` / control chars. Scrub before interpolating into the
            // plain-text stderr line.
            process.stderr.write(`[vault-daemon] Secret access denied for scope: ${safeLog(name, 128)}\n`);
            socket.write(
              JSON.stringify({ id, type: 'error', message: 'Secret access denied' }) + '\n',
            );
            return;
          }

          // Reload vault if changed
          await vault._reloadIfChanged();

          const value = await getDaemonInternals(vault)._unsealByName(name);
          if (value === null) {
            // Earlier fix: do NOT echo the secret name back to the socket —
            // the caller already knows the name they requested; including it
            // in the error enables vault-membership enumeration by untrusted
            // clients who can observe error messages.
            process.stderr.write(`[vault-daemon] Secret not found: ${safeLog(name, 128)}\n`);
            socket.write(
              JSON.stringify({ id, type: 'error', message: 'Secret not found in vault' }) + '\n',
            );
            return;
          }

          socket.write(JSON.stringify({ id, type: 'value', value }) + '\n');
          break;
        }

        case 'shutdown': {
          // Security fix: same fix as the auth case — always run timingSafeEqual
          // on fixed 32-byte buffers; never short-circuit on length.
          const presented = Buffer.from(msg.daemonSecret || '', 'hex');
          {
            const expected = daemonSecretBuf; // always 32 bytes
            const candidate = Buffer.alloc(32);
            presented.copy(candidate, 0, 0, Math.min(presented.length, 32));
            if (!timingSafeEqual(candidate, expected)) {
              socket.write(JSON.stringify({ id, type: 'error', message: 'Invalid daemon secret' }) + '\n');
              return;
            }
          }
          socket.write(JSON.stringify({ id, type: 'ok' }) + '\n');
          setTimeout(() => server.close(), 0);
          break;
        }

        default:
          socket.write(
            JSON.stringify({ id, type: 'error', message: `Unknown message type: ${type}` }) + '\n',
          );
      }
    } catch (err) {
      // Security requirement: never forward raw err.message over the IPC socket — it
      // can contain filesystem paths, ciphertext fragments, or data from prior
      // operations. Log to stderr for operator visibility; return a generic
      // message to the client.
      // `type` is the raw `msg.type` from the socket line and `err.message`
      // can embed caller-controlled fragments (e.g. JSON-parse echoes).
      // Scrub both before interpolating.
      process.stderr.write(`[vault-daemon] Internal error handling message type="${safeLog(type, 64)}": ${safeLog(err.message, 256)}\n`);
      socket.write(JSON.stringify({ id, type: 'error', message: 'Internal error' }) + '\n');
    }
  }

  // ─── Server ─────────────────────────────────────────────────────────────────
  const MAX_MSG_SIZE = 1024 * 1024; // 1 MB — prevent unbounded buffer DoS
  const server = createServer((socket) => {
    let buf = '';
    // Concurrency safety: serialize message handling per socket.
    // Previously `handleMessage(socket, line)` was called without await
    // inside the `data` handler, so pipelined NDJSON messages on one
    // connection ran concurrently and could interleave vault state
    // (`_reloadIfChanged`, `_unsealByName`, `_getJwtSecret`) — a second
    // `auth` with a different configPath could race and swap the
    // `allowedSecrets` seen by an in-flight `unseal` on the same socket.
    // Fix: chain each line onto a per-socket promise queue so the
    // handlers run strictly in arrival order.
    let msgQueue = Promise.resolve();
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.length > MAX_MSG_SIZE) { socket.destroy(); return; }
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (line) {
          msgQueue = msgQueue.then(
            () => handleMessage(socket, line),
            () => handleMessage(socket, line),
          );
        }
      }
    });
    socket.on('error', (err) => {
      if (err.code !== 'ECONNRESET') {
        process.stderr.write(`vault-daemon socket error: ${safeLog(err.code || err.message, 256)}\n`);
      }
    });
  });

  // Cryptographic requirement: close the socket-permission TOCTOU window.
  // `server.listen` creates the Unix socket with permissions derived from
  // the process umask (typically 0022 → 0755-ish socket perms), and the
  // subsequent `chmod(socketPath, 0o600)` only tightens it afterwards.
  // Any local user who connects in that micro-window reaches the auth
  // handler before the socket is locked down. Force umask 0o077 around
  // `listen` so the initial create-mode itself is 0o600-equivalent; the
  // explicit `chmod` stays as belt-and-braces and in case umask is
  // inherited differently on some platforms.
  const prevUmask = process.platform !== 'win32' ? process.umask(0o077) : null;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
  } finally {
    if (prevUmask !== null) process.umask(prevUmask);
  }

  if (process.platform !== 'win32') {
    try {
      await chmod(socketPath, 0o600);
    } catch (err) {
      process.stderr.write(`[vault-daemon] WARNING: could not chmod socket ${safeLog(socketPath, 256)}: ${safeLog(err.message, 256)}\n`);
    }
  }

  // Cleanup PID file + socket on close
  server.once('close', async () => {
    try { await unlink(pidPath); } catch {}
    if (process.platform !== 'win32') {
      try { await unlink(socketPath); } catch {}
    }
  });

  return {
    socketPath,
    pidPath,
    daemonSecret,
    close: () =>
      new Promise((resolve) => {
        server.close(resolve);
      }),
  };
}
