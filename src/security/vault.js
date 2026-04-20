/**
 * Sealed credential vault — zero-plaintext API key management.
 *
 * Design principles (Railway Seal pattern + envelope encryption):
 * - Secrets NEVER exist in plaintext at rest or in process.env
 * - Each secret is encrypted with its own DEK (Data Encryption Key)
 * - DEKs are wrapped with a KEK (Key Encryption Key) derived from master passphrase
 * - Runtime access is via short-lived JWTs (signed, expiring, scoped)
 * - Configs reference sealed IDs (e.g., "seal://openclaw-api-key"), never raw values
 * - beforeRequest hooks unseal just-in-time, in-memory only, never persisted
 *
 * Crypto: AES-256-GCM (DEK encryption) + HMAC-SHA256 (JWT signing) + PBKDF2 (KEK derivation)
 *
 * @module security/vault
 */

// hkdfSync requires Node.js 15+. This package declares engines >= 18 in
// package.json, so hkdfSync is always available — no runtime guard needed.
import { randomBytes, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

// Guard at module load so operators get a clear error message on old Node
// versions rather than a cryptic "hkdfSync is not a function" crash deep
// in the vault boot path.
if (typeof hkdfSync !== 'function') {
  throw new Error(
    '[40mcp] vault.js requires Node.js 15 or later (hkdfSync is unavailable). ' +
    'Please upgrade your runtime. The minimum supported version is Node 15; ' +
    'for production use, Node 18 LTS or newer is strongly recommended.',
  );
}
import { readFile, rename, mkdir, stat, open, lstat } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { dirname } from 'node:path';
import { DANGEROUS_KEYS } from '../core/object.js';

// Vault files are capped at 16 MB before read. A tampered or stray 2 GB
// vault file would otherwise OOM the process at load time, before any
// integrity check could run. 16 MB is well above any plausible legitimate
// vault (entry count × AES-GCM ciphertext).
const MAX_VAULT_FILE_BYTES = 16 * 1024 * 1024;
import {
  ALGORITHM, SALT_LENGTH, DEFAULT_TOKEN_TTL,
  deriveKEK, generateDEK,
  encryptWithKey, decryptWithKey,
  wrapDEK, unwrapDEK,
  signJWT, verifyJWT,
  generateSealId,
} from './crypto.js';
import { emitEvent } from '../core/events.js';

// ─── Daemon internals isolation ─────────────────────────────────────────────
// WeakMap keeps daemon-only methods out of the public vault surface.
// WeakMap entries are not accessible from the vault object reference — no enumeration,
// reflection, or prototype traversal can reach them.
const daemonInternals = new WeakMap();

export function getDaemonInternals(vault) {
  return daemonInternals.get(vault);
}

// ─── Recovery key helpers ───────────────────────────────────────────────────

// Recovery key: 32 random bytes, hex-encoded in 4 groups of 16 chars.
// Hex is used (not base64url) because base64url contains '-' which is also
// the group separator — making round-trip decode ambiguous.
// Format: "xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx"
function generateRecoveryKey() {
  const key = randomBytes(32);
  const hex = key.toString('hex'); // always 64 chars
  const encoded = hex.match(/.{16}/g).join('-'); // 4 groups of 16
  return { key, encoded };
}

function encryptRecoveryEnvelope(kek, recoveryKey) {
  // Encrypts the KEK itself using the recovery key
  // so that if passphrase is lost, recovery key can re-derive KEK
  return encryptWithKey(kek.toString('hex'), recoveryKey);
}

function decryptRecoveryEnvelope(envelope, recoveryKey) {
  return Buffer.from(decryptWithKey(envelope, recoveryKey).toString('utf-8'), 'hex');
}

// ─── Extended HMAC integrity ────────────────────────────────────────────────
// Compute an integrity HMAC that covers ALL mutable sealed-state fields,
// not just `entries`. Legacy HMAC covered `JSON.stringify(entries)` only,
// leaving `salt`, `recoveryEnvelope`, and `recoveryKeyEnvelope` outside the
// MAC — an attacker with write access could swap a recovery envelope for one
// they hold the key to and re-key the vault on next `recoverVault()`.
//
// The encoding is intentionally positional (field tag + length prefix + value)
// so that adding/removing fields cannot silently pivot the MAC to a different
// shape. Values are serialized with `JSON.stringify` on structured inputs;
// empty strings are emitted for missing fields so every load computes the
// same canonical form regardless of version.
function computeExtendedHmac(kek, { entries, salt, recoveryEnvelope, recoveryKeyEnvelope }) {
  const h = createHmac('sha256', kek);
  const parts = [
    ['entries', entries ? JSON.stringify(entries) : ''],
    ['salt', salt ? Buffer.from(salt).toString('hex') : ''],
    ['recoveryEnvelope', recoveryEnvelope ? JSON.stringify(recoveryEnvelope) : ''],
    ['recoveryKeyEnvelope', recoveryKeyEnvelope ? JSON.stringify(recoveryKeyEnvelope) : ''],
  ];
  for (const [tag, value] of parts) {
    const tagBuf = Buffer.from(tag, 'utf8');
    const valBuf = Buffer.from(value, 'utf8');
    // 1 byte tag length || tag || 4 byte value length BE || value
    const tagLen = Buffer.alloc(1);
    tagLen.writeUInt8(tagBuf.length, 0);
    const valLen = Buffer.alloc(4);
    valLen.writeUInt32BE(valBuf.length, 0);
    h.update(tagLen);
    h.update(tagBuf);
    h.update(valLen);
    h.update(valBuf);
  }
  return h.digest('hex');
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Create a sealed credential vault.
 *
 * @param {object} config
 * @param {string} config.path - Vault file path
 * @param {string} config.passphrase - Master passphrase (KEK source). Use env var.
 * @param {number} [config.tokenTTL=300] - JWT token lifetime in seconds (default: 5 min)
 * @returns {SealedVault}
 */
export function createVault(config) {
  const { path: vaultPath, passphrase, tokenTTL = DEFAULT_TOKEN_TTL } = config;

  if (!passphrase) {
    throw new Error('Vault passphrase is required. Set VAULT_PASSPHRASE env var.');
  }
  // crypto.pbkdf2 accepts both strings and Buffers as the password argument
  // but derives DIFFERENT KEKs from the two forms (a string is UTF-8 encoded,
  // a Buffer is used raw). A caller that seals with Buffer.from('pass') and
  // reopens with the string 'pass' hits a silent HMAC integrity failure that
  // looks like vault tampering. Fail loudly at construction instead.
  if (typeof passphrase !== 'string') {
    throw new Error(
      `Vault passphrase must be a string (got ${typeof passphrase}). ` +
      `Buffers and other types derive a different KEK than strings and would cause a silent unseal lockout.`,
    );
  }
  // Strength gate applies on construction so a weak passphrase is rejected
  // before any vault file is created or opened. Symmetric with initVault /
  // rotateKEK / recoverVault — every path that sets or uses a master
  // passphrase goes through the same check.
  const strengthError = validatePassphraseStrength(passphrase);
  if (strengthError) throw new Error(strengthError);

  let salt = null;
  let kek = null;
  let entries = {};
  let loaded = false;
  let _loadPromise = null;
  // JWT signing key derived from KEK (separate derivation path)
  let jwtSecret = null;

  // v3 recovery envelopes
  let recoveryEnvelope = null;       // kek → encrypted by recovery key (for passphrase loss)
  let recoveryKeyEnvelope = null;    // recovery key → encrypted by kek (for KEK rotation)

  async function _doLoad() {
    try {
      // Refuse to follow symlinks on the vault path to prevent reading
      // sensitive files. `lstat` + O_NOFOLLOW (where available) closes the window.
      const ls = await lstat(vaultPath);
      if (ls.isSymbolicLink()) {
        throw new Error(
          `[vault] refusing to load symlinked vault path "${vaultPath}" — ` +
          `vault files must be real files, not symlinks.`,
        );
      }

      // Enforce a size ceiling so a tampered or stray huge file cannot OOM
      // the process before integrity verification runs.
      if (ls.size > MAX_VAULT_FILE_BYTES) {
        throw new Error(
          `[vault] vault file too large: ${ls.size} bytes > ${MAX_VAULT_FILE_BYTES} limit`,
        );
      }

      // Read with O_NOFOLLOW to defeat a symlink-swap race between the
      // `lstat` check above and the actual open().
      const fh = await open(
        vaultPath,
        fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
      );
      let raw;
      try {
        raw = await fh.readFile('utf-8');
      } finally {
        await fh.close();
      }
      const st = await stat(vaultPath);

      // Check vault file permissions: hard-fail if world- or group-readable.
      // Advisory warning was insufficient — a world-readable vault exposes
      // sealed entries to any local user, which is equivalent to no encryption
      // at rest for threat model T2 (malicious local process).
      //
      // NTFS does not expose POSIX mode bits through node's fs.stat (it reports
      // a synthesized 0o666), so this check is POSIX-only. Windows file ACL
      // enforcement is a separate surface and out of scope for this guard.
      if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
        throw new Error(`[vault] Vault file permissions are too permissive (${(st.mode & 0o777).toString(8)}). Run: chmod 600 "${vaultPath}"`);
      }

      const data = JSON.parse(raw);

      if (data.version !== 2 && data.version !== 3) {
        throw new Error(`Unsupported vault version: ${data.version}. Expected 2 or 3 (sealed vault).`);
      }

      salt = Buffer.from(data.salt, 'hex');
      kek = await deriveKEK(passphrase, salt);
      // Use HKDF (hkdfSync, Node 15+) for JWT secret derivation instead of
      // bare HMAC with a hardcoded string. hkdfSync provides proper domain
      // separation via HKDF info label; KEK confidentiality remains the primary
      // protection. The label "40mcp:vault:jwt-signing:v1" is an intentional
      // domain separator that prevents cross-context key reuse.
      jwtSecret = Buffer.from(hkdfSync('sha256', kek, Buffer.alloc(32), Buffer.from('40mcp:vault:jwt-signing:v1'), 32));
      entries = data.entries || {};

      // v3: load recovery envelopes if present
      recoveryEnvelope = data.recoveryEnvelope || null;
      recoveryKeyEnvelope = data.recoveryKeyEnvelope || null;

      // Verify HMAC integrity — mandatory for v2+ vaults.
      //
      // Legacy HMAC covers ONLY `JSON.stringify(entries)`. An attacker with
      // write access to the vault file could swap `salt`, `recoveryEnvelope`,
      // or `recoveryKeyEnvelope` — none of which the HMAC witnesses — and pass
      // integrity. Swapping a recoveryEnvelope they control lets `recoverVault()`
      // accept their recovery key and re-key the vault with a passphrase they
      // choose, exposing all secrets.
      //
      // Fix: compute an extended HMAC over a canonical, ordered concatenation
      // of ALL sealed-state fields. On read, prefer the extended HMAC and fall
      // back to the legacy field with a loud deprecation warning so existing
      // deployments keep loading; the next `save()` rewrites both fields so
      // the fallback window closes on first mutation.
      if (data.version >= 2) {
        if (!data.hmac && !data.integrityHmac) {
          emitEvent('vault.integrity_fail', { path: vaultPath, reason: 'missing_hmac' });
          throw new Error('Vault integrity check missing — file may be tampered');
        }
        const extended = computeExtendedHmac(kek, {
          entries,
          salt,
          recoveryEnvelope,
          recoveryKeyEnvelope,
        });
        let verified = false;
        if (data.integrityHmac) {
          const a = Buffer.from(extended, 'hex');
          const b = Buffer.from(data.integrityHmac, 'hex');
          if (a.length === b.length && timingSafeEqual(a, b)) verified = true;
        }
        // Gate the legacy entries-only HMAC fallback on `data.version < 3`.
        // A v3 vault has `recoveryEnvelope` + `recoveryKeyEnvelope` fields that
        // the entries-only HMAC does NOT cover; accepting the legacy fallback on
        // a v3 file would let an attacker strip `integrityHmac`, swap in their
        // own `recoveryEnvelope`, and compute a matching legacy HMAC over the
        // unchanged `entries` — passing integrity. The follow-on `recoverVault()`
        // fails AES-GCM auth (DEKs don't unwrap under attacker KEK) so it's a
        // recovery-DoS / file-pinning, but the integrity gate should fail closed
        // at load, not later. v2 vaults (no recovery envelope at all) still accept
        // the legacy fallback for one cycle to keep existing deployments loadable.
        if (!verified && data.hmac && data.version < 3) {
          const legacy = createHmac('sha256', kek)
            .update(JSON.stringify(entries))
            .digest('hex');
          const a = Buffer.from(legacy, 'hex');
          const b = Buffer.from(data.hmac, 'hex');
          if (a.length === b.length && timingSafeEqual(a, b)) {
            verified = true;
            process.stderr.write(
              `[vault] WARNING: loaded v${data.version} vault "${vaultPath}" with legacy entries-only HMAC; ` +
              `next save() will upgrade to extended HMAC covering salt + recovery envelopes.\n`,
            );
          }
        }
        if (!verified) {
          emitEvent('vault.integrity_fail', { path: vaultPath, reason: 'hmac_mismatch' });
          throw new Error('Vault integrity check failed — file may be tampered');
        }
      }
      emitEvent('vault.load', { path: vaultPath, version: data.version, entryCount: Object.keys(entries).length });
    } catch (err) {
      if (err.code === 'ENOENT') {
        process.stderr.write('[40mcp] vault: creating new vault file without recovery envelope — use `40mcp vault init` for a vault with recovery support\n');
        salt = randomBytes(SALT_LENGTH);
        kek = await deriveKEK(passphrase, salt);
        jwtSecret = Buffer.from(hkdfSync('sha256', kek, Buffer.alloc(32), Buffer.from('40mcp:vault:jwt-signing:v1'), 32));
        entries = {};
        recoveryEnvelope = null;
        recoveryKeyEnvelope = null;
        emitEvent('vault.load', { path: vaultPath, version: null, entryCount: 0, created: true });
      } else {
        salt = kek = entries = jwtSecret = null;
        emitEvent('vault.load_fail', { path: vaultPath, error: err.code || 'UNKNOWN' });
        throw err;
      }
    }
    loaded = true;
  }

  async function load() {
    if (loaded) return;
    if (_loadPromise) return _loadPromise;
    _loadPromise = _doLoad().catch(err => { _loadPromise = null; throw err; });
    return _loadPromise;
  }

  // Serialize saves through a Promise chain to prevent last-write-wins data
  // loss when two callers invoke `vault.set` concurrently. Each tmp filename
  // also gets a unique nonce so parallel writes from the same PID can't race
  // on the same tmp path. The chain guarantees that within a single vault
  // instance only one save() is in flight at a time.
  let _saveQueue = Promise.resolve();
  async function save() {
    const run = async () => {
      // Write BOTH legacy and extended HMAC. Legacy (`hmac`) preserves
      // read-compat with older 40mcp versions that only know how to verify
      // entries-only coverage. Extended (`integrityHmac`) is the real integrity
      // field and is required by any 40mcp with this patch loaded. Attackers
      // who strip `integrityHmac` hoping to downgrade will fail because the
      // loader now prefers extended and only falls back to legacy with a loud
      // stderr warning.
      const legacyHmac = createHmac('sha256', kek)
        .update(JSON.stringify(entries))
        .digest('hex');
      const integrityHmac = computeExtendedHmac(kek, {
        entries,
        salt,
        recoveryEnvelope,
        recoveryKeyEnvelope,
      });
      const version = (recoveryEnvelope || recoveryKeyEnvelope) ? 3 : 2;
      const data = {
        version,
        algorithm: `${ALGORITHM}+envelope`,
        salt: salt.toString('hex'),
        entries,
        hmac: legacyHmac,
        integrityHmac,
        updated: new Date().toISOString(),
      };
      if (recoveryEnvelope) data.recoveryEnvelope = recoveryEnvelope;
      if (recoveryKeyEnvelope) data.recoveryKeyEnvelope = recoveryKeyEnvelope;
      // Force `mkdir` mode 0o700 so the vault directory cannot inherit a
      // permissive umask (typically 0755 → world-traversable). Without this,
      // a local attacker who can list the vault dir learns the timing +
      // filenames of save operations even if they can't read the vault payload.
      await mkdir(dirname(vaultPath), { recursive: true, mode: 0o700 });
      const nonce = randomBytes(8).toString('hex');
      const tmp = `${vaultPath}.tmp.${process.pid}.${nonce}`;
      // Options object MUST be the 3rd arg (not 4th). Passing `'utf-8'` in
      // the 3rd slot causes Node to ignore the `{mode}` options object
      // entirely and fall back to umask-derived 0644 — leaving temp vault
      // files group-readable during the save cycle.
      //
      // `flag:'wx'` enforces O_CREAT|O_EXCL, so if the target tmp path already
      // exists (attacker-planted symlink racing the nonce window) the write
      // fails closed instead of following the symlink or overwriting.
      // Durability: `writeFile` + `rename` gives an atomic filename swap but
      // does not `fsync` the tmp descriptor. On filesystems where rename does not
      // imply data durability, a crash between rename and page flush can leave the
      // new filename pointing at a file whose data blocks were never persisted —
      // unacceptable for a vault holding wrapped DEKs. Open via a handle, write
      // through it, fsync, close, then rename. Fsync the parent directory after
      // rename so the entry itself is durable.
      const fd = await open(tmp, 'wx', 0o600);
      try {
        await fd.writeFile(JSON.stringify(data, null, 2), { encoding: 'utf-8' });
        await fd.sync();
      } finally {
        await fd.close();
      }
      await rename(tmp, vaultPath);
      // Fsync the parent directory so the rename itself is durable across
      // crashes. On Windows, directory fsync is not meaningful — skip.
      // On platforms that refuse `open(dir, O_RDONLY)` (rare), swallow the
      // error rather than fail the whole save: the rename already succeeded
      // and durability is still improved over the baseline.
      if (process.platform !== 'win32') {
        try {
          const dirFd = await open(dirname(vaultPath), 'r');
          try {
            await dirFd.sync();
          } finally {
            await dirFd.close();
          }
        } catch {
          // Directory fsync failed — data file is already fsynced and
          // renamed. Worst case the rename is not durable on crash, which
          // is the pre-fix behaviour. Do not fail the save.
        }
      }
    };
    // Chain onto the queue; callers await the queued slot completing.
    _saveQueue = _saveQueue.then(run, run);
    return _saveQueue;
  }

  /**
   * Unseal a secret in-memory (never persisted, never in env).
   * @private
   */
  function unseal(entry) {
    const dek = unwrapDEK(entry.wrappedDEK, kek);
    return decryptWithKey(entry.sealed, dek).toString('utf-8');
  }

  // ─── Daemon-only methods (isolated via WeakMap — not on public surface) ──────
  async function _unsealByName(name) {
    await load();
    const entry = entries[name];
    if (!entry) return null;
    return unseal(entry);
  }

  async function _getJwtSecret() {
    await load();
    return jwtSecret;
  }

  const vault = {
    /**
     * Seal a secret into the vault.
     * Uses envelope encryption: secret encrypted with DEK, DEK encrypted with KEK.
     *
     * @param {string} name - Secret name
     * @param {string} value - Plaintext value (only exists in memory during this call)
     * @param {object} [metadata] - Service name, scopes, etc.
     * @returns {string} Seal ID (e.g., "seal://openclaw-api-key-a1b2c3d4")
     */
    async set(name, value, metadata) {
      await load();
      const dek = generateDEK();
      const sealed = encryptWithKey(value, dek);
      const wrappedDEK = wrapDEK(dek, kek);
      const sealId = generateSealId(name);

      entries[name] = {
        sealId,
        sealed,
        wrappedDEK,
        metadata: metadata || {},
        created: new Date().toISOString(),
        // fingerprint: HMAC(value, kek) — display only, not used for decryption. Prior versions used SHA-256(value) which was vulnerable to offline brute-force for short secrets.
        fingerprint: createHmac('sha256', kek).update(value).digest('hex').slice(0, 8),
      };
      await save();
      return sealId;
    },

    /**
     * Issue a short-lived JWT credential for a sealed secret.
     * The JWT contains only the secret name (sub) — never the plaintext value.
     * Use verifyToken() to redeem the token and unseal on demand.
     *
     * @param {string} name - Secret name
     * @param {object} [claims] - Additional JWT claims (e.g., { scope: 'read', bot_id: '...' })
     * @returns {{ token: string, expiresAt: number } | null}
     */
    async issueToken(name, claims) {
      await load();
      const entry = entries[name];
      if (!entry) return null;

      const now = Math.floor(Date.now() / 1000);
      // Prevent caller from overriding reserved fields (exp, iat, sub, sid)
      // with forever-token values. The previous implementation applied
      // `...claims` AFTER reserved fields, allowing override. Strip reserved
      // fields from caller-supplied claims before the spread.
      const safeClaims = claims && typeof claims === 'object'
        ? Object.fromEntries(
            Object.entries(claims).filter(
              ([k]) => k !== 'exp' && k !== 'iat' && k !== 'sub' && k !== 'sid' && k !== 'nbf',
            ),
          )
        : {};
      const payload = {
        ...safeClaims,
        sub: name,
        sid: entry.sealId,
        iat: now,
        exp: now + tokenTTL,
      };

      const token = signJWT(payload, jwtSecret);
      emitEvent('vault.token_issued', { name, sealId: entry.sealId, expiresAt: (now + tokenTTL) * 1000 });
      return { token, expiresAt: (now + tokenTTL) * 1000 };
    },

    /**
     * Verify a credential token and unseal the secret value on demand.
     * The JWT proves authorization; the server-side vault decrypts just-in-time.
     * The plaintext value is never stored in or recoverable from the JWT itself.
     *
     * @param {string} token - JWT credential token
     * @returns {{ name: string, value: string, sealId: string, claims: object }}
     */
    async verifyToken(token) {
      await load();
      let payload;
      try {
        payload = verifyJWT(token, jwtSecret);
      } catch (err) {
        emitEvent('vault.token_verify_fail', { reason: err?.message || 'invalid_token' });
        throw err;
      }
      const entry = entries[payload.sub];
      if (!entry) {
        // Operator stderr event retains the name for incident-response
        // correlation, but the thrown error is opaque: leaking vault entry
        // names in the error message is a membership-enumeration oracle.
        emitEvent('vault.token_verify_fail', { name: payload.sub, reason: 'entry_not_found' });
        throw new Error('Vault token verification failed');
      }
      const value = unseal(entry);
      emitEvent('vault.unseal', { name: payload.sub, sealId: entry.sealId, via: 'token' });
      return {
        name: payload.sub,
        value,
        sealId: entry.sealId,
        claims: payload,
      };
    },

    /**
     * Get the seal ID for a secret (safe to log/store — contains no sensitive data).
     * @param {string} name
     * @returns {string|null}
     */
    async getSealId(name) {
      await load();
      return entries[name]?.sealId || null;
    },

    /**
     * Get the fingerprint (first 8 hex chars of HMAC-SHA256) for verification without unsealing.
     * Display only, not used for decryption. Old entries from pre-upgrade vaults use SHA-256(value)
     * and are not recomputed until the secret is rotated or re-sealed.
     * @param {string} name
     * @returns {string|null}
     */
    async getFingerprint(name) {
      await load();
      return entries[name]?.fingerprint || null;
    },

    /**
     * Check if a secret exists without unsealing.
     * @param {string} name
     * @returns {boolean}
     */
    async has(name) {
      await load();
      return name in entries;
    },

    /**
     * Rotate a sealed secret — re-encrypt the value with a new DEK and a new seal ID.
     * Any JWTs issued before rotation remain valid (they use the secret name as subject,
     * not the seal ID). Use rotate() to re-key a compromised DEK without changing the value.
     *
     * @param {string} name - Secret name
     * @returns {string} New seal ID, or null if the secret does not exist
     */
    async rotate(name) {
      await load();
      const entry = entries[name];
      if (!entry) return null;

      const plaintext = unseal(entry);
      const newDek = generateDEK();
      const newSealed = encryptWithKey(plaintext, newDek);
      const newWrappedDEK = wrapDEK(newDek, kek);
      const newSealId = generateSealId(name);

      entries[name] = {
        sealId: newSealId,
        sealed: newSealed,
        wrappedDEK: newWrappedDEK,
        metadata: entry.metadata,
        created: entry.created,
        fingerprint: createHmac('sha256', kek).update(plaintext).digest('hex').slice(0, 8),
        rotated: new Date().toISOString(),
      };
      await save();
      return newSealId;
    },

    /**
     * Delete a sealed secret.
     * @param {string} name
     */
    async delete(name) {
      await load();
      delete entries[name];
      await save();
    },

    /**
     * List all sealed secrets (names, seal IDs, fingerprints — no values).
     * @returns {Array<{ name, sealId, fingerprint, metadata, created }>}
     */
    async list() {
      await load();
      return Object.entries(entries).map(([name, entry]) => ({
        name,
        sealId: entry.sealId,
        fingerprint: entry.fingerprint,
        metadata: entry.metadata || {},
        created: entry.created,
      }));
    },

    /**
     * Create a beforeRequest hook that unseals credentials just-in-time.
     * The secret is decrypted in-memory for the request, then discarded.
     * NEVER stored in process.env or persisted.
     *
     * @param {Record<string, string>} mapping - { secretName: headerName }
     * @returns {Function} beforeRequest hook
     */
    createAuthHook(mapping) {
      // Validate header names at hook-creation time so a config like
      // `{ "Authorization\r\nX-Injected: evil": "mySecret" }` is rejected
      // immediately rather than causing header injection at request time.
      // RFC 7230 §3.2 token: visible US-ASCII except delimiters.
      const SAFE_HEADER_PATTERN = /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/;
      for (const [, headerName] of Object.entries(mapping)) {
        if (!SAFE_HEADER_PATTERN.test(headerName)) {
          throw new Error(
            `createAuthHook: invalid header name "${headerName}" — ` +
            `must match RFC 7230 token (no CR/LF, no whitespace, no delimiters)`,
          );
        }
      }
      return async (_req) => {
        await load();
        const headers = {};
        for (const [secretName, headerName] of Object.entries(mapping)) {
          const entry = entries[secretName];
          if (entry) {
            // JIT unseal — value exists only for this request
            headers[headerName] = unseal(entry);
          }
        }
        return Object.keys(headers).length > 0 ? { headers } : null;
      };
    },

    /**
     * Create a beforeRequest hook that injects Authorization: Bearer <value>.
     * The secret is decrypted in-memory for the request, then discarded.
     *
     * @param {string} name - Secret name in vault
     * @returns {Function} beforeRequest hook
     */
    createBearerHook(name) {
      return async (_req) => {
        await load();
        const entry = entries[name];
        if (!entry) return null;
        return { headers: { 'Authorization': `Bearer ${unseal(entry)}` } };
      };
    },

    /**
     * Rotate the KEK — re-wraps all DEKs under a new KEK derived from newPassphrase.
     * If the vault has a recovery envelope, the recovery capability is preserved.
     *
     * @param {string} newPassphrase - New master passphrase
     */
    async rotateKEK(newPassphrase) {
      await load();
      if (!newPassphrase) throw new Error('newPassphrase is required');
      // Strength gate applies to every path that sets a master passphrase,
      // not just initVault — otherwise rotation silently weakens the vault.
      const strengthError = validatePassphraseStrength(newPassphrase);
      if (strengthError) throw new Error(strengthError);

      const newSalt = randomBytes(SALT_LENGTH);
      const newKek = await deriveKEK(newPassphrase, newSalt);
      const newJwtSecret = Buffer.from(hkdfSync('sha256', newKek, Buffer.alloc(32), Buffer.from('40mcp:vault:jwt-signing:v1'), 32));

      // Re-wrap every entry's DEK under the new KEK
      for (const [name, entry] of Object.entries(entries)) {
        const dek = unwrapDEK(entry.wrappedDEK, kek);
        entries[name] = { ...entry, wrappedDEK: wrapDEK(dek, newKek) };
      }

      // Update recovery envelopes if they exist
      if (recoveryKeyEnvelope !== null) {
        // Decrypt recovery key using old KEK
        const recoveryKeyHex = decryptWithKey(recoveryKeyEnvelope, kek).toString('utf-8');
        const recoveryKeyBuf = Buffer.from(recoveryKeyHex, 'hex');
        // Re-encrypt recovery key with new KEK
        recoveryKeyEnvelope = encryptWithKey(recoveryKeyBuf.toString('hex'), newKek);
        // Re-encrypt new KEK with recovery key
        recoveryEnvelope = encryptRecoveryEnvelope(newKek, recoveryKeyBuf);
      }

      // Commit new KEK into closure
      salt = newSalt;
      kek = newKek;
      jwtSecret = newJwtSecret;

      await save();
      emitEvent('vault.kek_rotated', { path: vaultPath, entryCount: Object.keys(entries).length });
    },

    /**
     * Resolve seal:// references in a config object.
     * Replaces "seal://name" values with JIT-unsealed values.
     * Returns a new object — original is not mutated.
     *
     * @param {object} config - Config with seal:// references
     * @returns {object} Config with resolved values (in-memory only)
     */
    async unsealConfig(config) {
      await load();
      return deepResolveSealRefs(config, entries, kek);
    },

    /**
     * Reload the vault file if its mtime has changed since last load.
     * Used by the vault daemon to pick up external changes.
     * @internal
     */
    async _reloadIfChanged() {
      // M4 TOCTOU fix: serialize reloads through _loadPromise so a concurrent
      // load() or _reloadIfChanged() in-flight is coalesced rather than spawning
      // a second _doLoad(). If _loadPromise is already set, return it directly —
      // that means load is already running and will reflect the latest state.
      // Otherwise, set _loadPromise to the reload body and clear it on finish,
      // exactly mirroring the coalescing pattern in load().
      if (_loadPromise) return _loadPromise;

      const self = this;
      _loadPromise = (async () => {
        const { stat } = await import('node:fs/promises');
        try {
          const st = await stat(vaultPath);
          if (!self._lastMtime || st.mtimeMs > self._lastMtime) {
            loaded = false;
            await _doLoad();
            // Re-stat AFTER load so the recorded mtime reflects what we actually
            // loaded, not what we saw at the check stat. Otherwise a concurrent
            // write during `await _doLoad()` is silently swallowed forever because
            // a future reload check sees `st.mtimeMs === self._lastMtime`.
            try {
              const st2 = await stat(vaultPath);
              self._lastMtime = st2.mtimeMs;
            } catch {
              self._lastMtime = st.mtimeMs;
            }
          }
        } catch {
          // If stat fails (e.g. file deleted), do nothing — next unseal will fail naturally
        }
      })().finally(() => { _loadPromise = null; });
      return _loadPromise;
    },
  };

  daemonInternals.set(vault, { _unsealByName, _getJwtSecret });
  return vault;
}

/**
 * Validates vault passphrase strength.
 * Returns an error message string on failure, or null if the passphrase is acceptable.
 *
 * Requirements (hardened: length≥16/3-class + entropy):
 *   - Minimum 16 characters
 *   - At least 3 character classes (lowercase, uppercase, digits, symbols)
 *   - Shannon entropy >= 3.5 bits/char (rejects highly repetitive strings)
 *   - No monotone runs of 4+ identical or sequential characters (e.g. "aaaa", "1234", "dcba")
 */
function validatePassphraseStrength(passphrase) {
  if (passphrase.length < 16) {
    return 'Vault passphrase must be at least 16 characters';
  }

  const charClasses = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];
  const classCount = charClasses.filter((re) => re.test(passphrase)).length;
  if (classCount < 3) {
    return 'Vault passphrase must use at least 3 character classes (lowercase, uppercase, digits, symbols)';
  }

  // Shannon entropy estimate — rejects highly repetitive or low-variety passphrases
  const freq = {};
  for (const ch of passphrase) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = passphrase.length;
  const entropyPerChar = -Object.values(freq).reduce((acc, n) => {
    const p = n / len;
    return acc + p * Math.log2(p);
  }, 0);
  if (entropyPerChar < 3.5) {
    return 'Vault passphrase is too repetitive — use a more varied passphrase';
  }

  // Detect monotone runs of 4+ identical or sequential (ascending/descending) characters
  for (let i = 0; i + 3 < passphrase.length; i++) {
    const c0 = passphrase.charCodeAt(i);
    const c1 = passphrase.charCodeAt(i + 1);
    const c2 = passphrase.charCodeAt(i + 2);
    const c3 = passphrase.charCodeAt(i + 3);
    if (
      (c0 === c1 && c1 === c2 && c2 === c3) ||
      (c1 === c0 + 1 && c2 === c0 + 2 && c3 === c0 + 3) ||
      (c1 === c0 - 1 && c2 === c0 - 2 && c3 === c0 - 3)
    ) {
      return 'Vault passphrase must not contain sequential or repeated character runs (e.g. "aaaa", "1234", "dcba")';
    }
  }

  return null;
}

/**
 * Initialize a NEW vault with a recovery key envelope.
 * Must be called for new vaults — not for opening existing vaults.
 * Throws if the vault file already exists.
 *
 * @param {object} config
 * @param {string} config.path - Vault file path
 * @param {string} config.passphrase - Master passphrase
 * @returns {{ vault: SealedVault, recoveryKey: string }}
 *   recoveryKey is shown ONCE — store it safely
 */
export async function initVault({ path: vaultPath, passphrase }) {
  if (!passphrase) throw new Error('Vault passphrase is required');

  // Passphrase strength gate (hardened: length≥16/3-class + entropy)
  const strengthError = validatePassphraseStrength(passphrase);
  if (strengthError) throw new Error(strengthError);

  // Check for symlinks BEFORE readFile — a vault directory with write access
  // allows an attacker to plant a symlink at vaultPath and redirect reads to any
  // file the process can access (e.g. /etc/shadow). `_doLoad()` already has this
  // guard via lstat+O_NOFOLLOW; replicate here.
  try {
    const lstStat = await lstat(vaultPath);
    if (lstStat.isSymbolicLink()) {
      throw new Error(`Vault path "${vaultPath}" is a symbolic link — refusing to initialise to prevent symlink-redirect attacks`);
    }
    // Symlink check passed; now check if it's an ordinary file (vault exists)
    throw new Error(`Vault already exists at ${vaultPath}. Use createVault() to open it.`);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    // ENOENT means no file at that path — safe to proceed with init
  }

  // Derive KEK
  const salt = randomBytes(SALT_LENGTH);
  const kek = await deriveKEK(passphrase, salt);

  // Generate recovery key
  const { key: recoveryKeyBuf, encoded: recoveryKeyEncoded } = generateRecoveryKey();

  // Encrypt KEK with recovery key (for passphrase loss recovery)
  const recoveryEnvelope = encryptRecoveryEnvelope(kek, recoveryKeyBuf);

  // Encrypt recovery key with KEK (for KEK rotation without user providing recovery key)
  const recoveryKeyEnvelope = encryptWithKey(recoveryKeyBuf.toString('hex'), kek);

  // Write the initial vault file. Emit extended HMAC alongside legacy so the
  // first load after init can verify full coverage (salt + both recovery
  // envelopes) rather than just `entries`.
  const legacyHmacInit = createHmac('sha256', kek).update(JSON.stringify({})).digest('hex');
  const integrityHmacInit = computeExtendedHmac(kek, {
    entries: {},
    salt,
    recoveryEnvelope,
    recoveryKeyEnvelope,
  });

  const data = {
    version: 3,
    algorithm: `${ALGORITHM}+envelope`,
    salt: salt.toString('hex'),
    entries: {},
    hmac: legacyHmacInit,
    integrityHmac: integrityHmacInit,
    recoveryEnvelope,
    recoveryKeyEnvelope,
    updated: new Date().toISOString(),
  };

  // mkdir mode 0o700 + O_CREAT|O_EXCL + fsync before rename — see save()
  // comments above for rationale.
  await mkdir(dirname(vaultPath), { recursive: true, mode: 0o700 });
  const nonceInit = randomBytes(8).toString('hex');
  const tmpInit = `${vaultPath}.tmp.${process.pid}.${nonceInit}`;
  {
    const fd = await open(tmpInit, 'wx', 0o600);
    try {
      await fd.writeFile(JSON.stringify(data, null, 2), { encoding: 'utf-8' });
      await fd.sync();
    } finally {
      await fd.close();
    }
  }
  await rename(tmpInit, vaultPath);
  if (process.platform !== 'win32') {
    try {
      const dirFd = await open(dirname(vaultPath), 'r');
      try { await dirFd.sync(); } finally { await dirFd.close(); }
    } catch { /* see save() for rationale */ }
  }

  const vault = createVault({ path: vaultPath, passphrase });
  return { vault, recoveryKey: recoveryKeyEncoded };
}

/**
 * Recover vault access from a lost passphrase using the recovery key.
 * Re-wraps all DEKs under a new KEK derived from newPassphrase.
 *
 * @param {object} config
 * @param {string} config.path - Vault file path
 * @param {string} config.recoveryKey - Recovery key (from vault init)
 * @param {string} config.newPassphrase - New master passphrase
 * @returns {SealedVault} Vault opened with newPassphrase
 */
export async function recoverVault({ path: vaultPath, recoveryKey, newPassphrase }) {
  if (!recoveryKey) throw new Error('recoveryKey is required');
  if (!newPassphrase) throw new Error('newPassphrase is required');
  // Strength gate applies to every path that sets a master passphrase,
  // not just initVault — otherwise recovery silently weakens the vault.
  const strengthError = validatePassphraseStrength(newPassphrase);
  if (strengthError) throw new Error(strengthError);

  // Apply same symlink-redirect protection used in _doLoad() and initVault()
  // to recoverVault() — recovery reads sensitive KEK material, making it a
  // high-value target for a symlink-redirect attack.
  try {
    const lstStat = await lstat(vaultPath);
    if (lstStat.isSymbolicLink()) {
      throw new Error(`Vault path "${vaultPath}" is a symbolic link — refusing to recover to prevent symlink-redirect attacks`);
    }
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    throw new Error(`Vault not found at "${vaultPath}" — cannot recover a vault that does not exist`);
  }

  const raw = await readFile(vaultPath, 'utf-8');
  const data = JSON.parse(raw);

  if (!data.recoveryEnvelope) {
    throw new Error('This vault has no recovery envelope. It was created without `initVault` — recovery is not possible.');
  }

  // Reconstruct recovery key buffer from encoded string. Buffer.from(..., 'hex')
  // silently stops at the first non-hex character and drops any trailing
  // half-byte. A typo (dropped leading zero, stray space, substituted 'O' for
  // '0') produces a truncated buffer and then a cryptic "Invalid recovery key"
  // error at decrypt time. Reject inputs that don't decode to exactly 32 bytes
  // with a specific message so operators can recover from transcription errors.
  const recoveryKeyBuf = Buffer.from(recoveryKey.replace(/-/g, ''), 'hex');
  if (recoveryKeyBuf.length !== 32) {
    throw new Error(
      'Invalid recovery key: must decode to 32 bytes (64 hex characters, typically 4 groups of 16 separated by dashes). ' +
      'Check for transcription errors: missing digits, substituted characters (O↔0, l↔1), or stripped leading zeros.',
    );
  }

  // Decrypt the old KEK using the recovery key
  let oldKek;
  try {
    oldKek = decryptRecoveryEnvelope(data.recoveryEnvelope, recoveryKeyBuf);
  } catch {
    throw new Error('Invalid recovery key — could not decrypt vault.');
  }

  // Verify HMAC with old KEK — mandatory.
  // Prefer the extended `integrityHmac` which covers salt + recovery envelopes
  // so an attacker cannot swap in their own `recoveryEnvelope` and still pass
  // integrity. Legacy `hmac` fallback stays for one cycle to keep existing
  // deployments loadable.
  if (!data.integrityHmac && !data.hmac) {
    throw new Error('Vault integrity check missing — file may be tampered');
  }
  {
    const dataSalt = Buffer.from(data.salt || '', 'hex');
    const extended = computeExtendedHmac(oldKek, {
      entries: data.entries || {},
      salt: dataSalt,
      recoveryEnvelope: data.recoveryEnvelope || null,
      recoveryKeyEnvelope: data.recoveryKeyEnvelope || null,
    });
    let verified = false;
    if (data.integrityHmac) {
      const a = Buffer.from(extended, 'hex');
      const b = Buffer.from(data.integrityHmac, 'hex');
      if (a.length === b.length && timingSafeEqual(a, b)) verified = true;
    }
    // Legacy fallback refused for v3 files (which always carry
    // recoveryEnvelope — entries-only HMAC cannot authenticate that field).
    // Without the gate, an attacker could strip integrityHmac, swap
    // recoveryEnvelope, recompute the legacy hmac over unchanged entries, and
    // coerce this function into believing the attacker's envelope is authentic.
    // It still fails at the DEK-unwrap stage, but the integrity gate should
    // reject before we ever touch the attacker's ciphertext.
    if (!verified && data.hmac && data.version < 3) {
      const legacy = createHmac('sha256', oldKek).update(JSON.stringify(data.entries || {})).digest('hex');
      const a = Buffer.from(legacy, 'hex');
      const b = Buffer.from(data.hmac, 'hex');
      if (a.length === b.length && timingSafeEqual(a, b)) {
        verified = true;
        process.stderr.write(
          `[vault] WARNING: recoverVault accepted legacy entries-only HMAC on "${vaultPath}"; ` +
          `rewrite will upgrade to extended HMAC.\n`,
        );
      }
    }
    if (!verified) {
      throw new Error('Vault integrity check failed — recovery key may be incorrect or vault is tampered');
    }
  }

  // Derive new KEK
  const newSalt = randomBytes(SALT_LENGTH);
  const newKek = await deriveKEK(newPassphrase, newSalt);

  // Re-wrap all DEKs
  const entries = data.entries || {};
  for (const [name, entry] of Object.entries(entries)) {
    const dek = unwrapDEK(entry.wrappedDEK, oldKek);
    entries[name] = { ...entry, wrappedDEK: wrapDEK(dek, newKek) };
  }

  // Re-encrypt recovery key with new KEK
  const newRecoveryKeyEnvelope = encryptWithKey(recoveryKeyBuf.toString('hex'), newKek);
  // Re-encrypt new KEK with recovery key
  const newRecoveryEnvelope = encryptRecoveryEnvelope(newKek, recoveryKeyBuf);

  const newLegacyHmac = createHmac('sha256', newKek).update(JSON.stringify(entries)).digest('hex');
  const newIntegrityHmac = computeExtendedHmac(newKek, {
    entries,
    salt: newSalt,
    recoveryEnvelope: newRecoveryEnvelope,
    recoveryKeyEnvelope: newRecoveryKeyEnvelope,
  });

  const newData = {
    version: 3,
    algorithm: `${ALGORITHM}+envelope`,
    salt: newSalt.toString('hex'),
    entries,
    hmac: newLegacyHmac,
    integrityHmac: newIntegrityHmac,
    recoveryEnvelope: newRecoveryEnvelope,
    recoveryKeyEnvelope: newRecoveryKeyEnvelope,
    updated: new Date().toISOString(),
  };

  // Match the nonce pattern used by save() and initVault so concurrent
  // recoverVault calls (test parallelism, fast retries) can't race on the
  // same tmp path.
  const nonceRecover = randomBytes(8).toString('hex');
  const tmpRecover = `${vaultPath}.tmp.${process.pid}.${nonceRecover}`;
  // O_CREAT|O_EXCL so a racing symlink at the tmp path fails the write
  // instead of being followed; fsync before rename so a recovered vault is
  // durable across crashes (see save() comments for rationale).
  {
    const fd = await open(tmpRecover, 'wx', 0o600);
    try {
      await fd.writeFile(JSON.stringify(newData, null, 2), { encoding: 'utf-8' });
      await fd.sync();
    } finally {
      await fd.close();
    }
  }
  await rename(tmpRecover, vaultPath);
  if (process.platform !== 'win32') {
    try {
      const dirFd = await open(dirname(vaultPath), 'r');
      try { await dirFd.sync(); } finally { await dirFd.close(); }
    } catch { /* see save() for rationale */ }
  }

  return createVault({ path: vaultPath, passphrase: newPassphrase });
}

/**
 * Deep-resolve seal:// references in an object.
 * @private
 */
// Bound recursion depth and detect cycles in deepResolveSealRefs. The
// previous implementation would stack-overflow on a deeply nested config and
// infinite-loop on a circular object (possible when callers programmatically
// build a config and pass it to vault.unsealConfig). Mirrors the depth+cycle
// pattern used by flattenObject in transforms/response.js.
const MAX_SEAL_RESOLVE_DEPTH = 20;

function deepResolveSealRefs(obj, entries, kek, depth = 0, seen = new WeakSet()) {
  if (typeof obj === 'string' && obj.startsWith('seal://')) {
    // Find entry by sealId
    for (const entry of Object.values(entries)) {
      if (entry.sealId === obj) {
        const dek = unwrapDEK(entry.wrappedDEK, kek);
        return decryptWithKey(entry.sealed, dek).toString('utf-8');
      }
    }
    return obj; // Not found — pass through
  }

  if (depth >= MAX_SEAL_RESOLVE_DEPTH) {
    return obj;
  }
  if (obj && typeof obj === 'object') {
    if (seen.has(obj)) return obj;
    seen.add(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => deepResolveSealRefs(item, entries, kek, depth + 1, seen));
  }

  if (obj && typeof obj === 'object') {
    // Prototype-pollution defense. If an untrusted config reaches here with a
    // `__proto__` / `constructor` / `prototype` OWN property (e.g. via
    // `Object.defineProperty(cfg, '__proto__', …)` — literal `{__proto__: x}`
    // is sugar for `Object.setPrototypeOf` and is already handled by
    // Object.entries ignoring it), then `result['__proto__'] = …` would invoke
    // the setter on the default `{}` prototype and mutate the prototype chain
    // rather than setting a data property. Skip DANGEROUS_KEYS entirely during
    // reconstruction. `DANGEROUS_KEYS` is the same set used by deepGet / deepSet
    // in core/object.js. Enumerate via Object.entries to skip non-enumerable own
    // properties consistent with prior behaviour.
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      if (DANGEROUS_KEYS.has(key)) continue;
      result[key] = deepResolveSealRefs(value, entries, kek, depth + 1, seen);
    }
    return result;
  }

  return obj;
}
