/**
 * Shared crypto primitives for the vault subsystem.
 * INTERNAL — not exported from src/index.js.
 *
 * Used by: vault.js, vault-daemon.js
 *
 * @module security/crypto
 * @internal
 */

import {
  createCipheriv, createDecipheriv, randomBytes,
  pbkdf2, createHash, createHmac, timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2Async = promisify(pbkdf2);

export const ALGORITHM = 'aes-256-gcm';
export const KEK_LENGTH = 32;
export const DEK_LENGTH = 32;
export const IV_LENGTH = 12;
export const SALT_LENGTH = 32;
// Aligned with OWASP 2023 password storage guidance for PBKDF2-HMAC-SHA256.
// Vaults sealed under the previous 100_000-iteration constant remain valid;
// they will be re-derived at the new iteration count the next time
// rotateKEK() is called (which regenerates the salt as well).
export const PBKDF2_ITERATIONS = 600_000;
export const DEFAULT_TOKEN_TTL = 300; // 5 minutes

// ─── KEK derivation ─────────────────────────────────────────────────────────

/**
 * Derive a Key Encryption Key from a passphrase + salt using PBKDF2-SHA256.
 * @param {string} passphrase
 * @param {Buffer} salt
 * @returns {Promise<Buffer>}
 */
export async function deriveKEK(passphrase, salt) {
  return pbkdf2Async(passphrase, salt, PBKDF2_ITERATIONS, KEK_LENGTH, 'sha256');
}

// ─── DEK generation ─────────────────────────────────────────────────────────

/**
 * Generate a new random Data Encryption Key.
 * @returns {Buffer}
 */
export function generateDEK() {
  return randomBytes(DEK_LENGTH);
}

// ─── AES-256-GCM encrypt / decrypt ─────────────────────────────────────────

/**
 * Encrypt plaintext (string or Buffer) with a key.
 * Returns an object with iv, data, tag — all hex-encoded.
 * @param {string|Buffer} plaintext
 * @param {Buffer} key
 * @returns {{ iv: string, data: string, tag: string }}
 */
export function encryptWithKey(plaintext, key) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), data: encrypted.toString('hex'), tag: tag.toString('hex') };
}

/**
 * Decrypt an entry produced by encryptWithKey.
 * @param {{ iv: string, data: string, tag: string }} entry
 * @param {Buffer} key
 * @returns {Buffer}
 */
export function decryptWithKey(entry, key) {
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(entry.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(entry.tag, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(entry.data, 'hex')),
    decipher.final(),
  ]);
}

// ─── DEK wrapping ───────────────────────────────────────────────────────────

/**
 * Wrap (encrypt) a DEK with a KEK.
 * @param {Buffer} dek
 * @param {Buffer} kek
 * @returns {{ iv: string, data: string, tag: string }}
 */
export function wrapDEK(dek, kek) {
  return encryptWithKey(dek.toString('hex'), kek);
}

/**
 * Unwrap (decrypt) a wrapped DEK using a KEK.
 * @param {{ iv: string, data: string, tag: string }} wrappedDEK
 * @param {Buffer} kek
 * @returns {Buffer}
 */
export function unwrapDEK(wrappedDEK, kek) {
  const dekHex = decryptWithKey(wrappedDEK, kek).toString('utf-8');
  return Buffer.from(dekHex, 'hex');
}

// ─── Base64url helpers ───────────────────────────────────────────────────────

/**
 * Encode data to base64url.
 * @param {string|Buffer} data
 * @returns {string}
 */
export function base64url(data) {
  return Buffer.from(data).toString('base64url');
}

/**
 * Decode a base64url string to a Buffer.
 * @param {string} str
 * @returns {Buffer}
 */
export function base64urlDecode(str) {
  return Buffer.from(str, 'base64url');
}

// ─── JWT (minimal, no deps) ─────────────────────────────────────────────────

/**
 * Sign a JWT payload with HMAC-SHA256.
 * @param {object} payload
 * @param {Buffer|string} secret
 * @returns {string} compact JWT
 */
export function signJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify(payload));
  const signature = createHmac('sha256', secret)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${signature}`;
}

/**
 * Verify a JWT signature and expiry, returning the decoded payload.
 * Throws if invalid or expired.
 * @param {string} token
 * @param {Buffer|string} secret
 * @returns {object} decoded payload
 */
export function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const [header, body, signature] = parts;

  // Assert algorithm is exactly HS256 — prevents alg:none and future confusion.
  // C3: also check that alg is a string before comparing, so a non-string value
  // (number, array, object, null) cannot bypass the check through type coercion.
  const parsedHeader = JSON.parse(base64urlDecode(header).toString('utf-8'));
  if (typeof parsedHeader.alg !== 'string' || parsedHeader.alg !== 'HS256') {
    throw new Error(`JWT algorithm must be exactly HS256, got: ${typeof parsedHeader.alg}`);
  }
  const expected = createHmac('sha256', secret)
    .update(`${header}.${body}`)
    .digest('base64url');

  // Constant-time comparison
  const sigBuf = Buffer.from(signature, 'base64url');
  const expBuf = Buffer.from(expected, 'base64url');
  if (sigBuf.length !== expBuf.length) throw new Error('Invalid JWT signature');

  if (!timingSafeEqual(sigBuf, expBuf)) throw new Error('Invalid JWT signature');

  const payload = JSON.parse(base64urlDecode(body).toString('utf-8'));

  // Prevent falsy exp bypass: previous check short-circuited when `payload.exp === 0`,
  // treating a token with exp=0 as if it had no expiry. Also prevent Infinity or
  // MAX_SAFE_INTEGER. Require exp to be present, a finite integer, not in the
  // far future, and strictly in the future relative to Date.now().
  const nowSec = Date.now() / 1000;
  // 2 days covers the longest legitimate vault token TTL with a generous margin
  // while preventing long-lived tokens from remaining valid for extended periods.
  const MAX_TOKEN_SKEW_SEC = 2 * 24 * 60 * 60; // 2 days
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= 0) {
    throw new Error('JWT missing or invalid exp claim');
  }
  if (payload.exp > nowSec + MAX_TOKEN_SKEW_SEC) {
    throw new Error('JWT exp claim exceeds maximum allowed lifetime');
  }
  if (nowSec > payload.exp) {
    throw new Error('JWT expired');
  }
  // Enforce nbf (not-before) claim if present with the same strict shape check as exp.
  // The vault's issueToken strips nbf from caller-supplied claims so daemon-issued
  // tokens never carry it — but verifyJWT is a general-purpose helper. Silently
  // ignoring nbf would be a correctness trap.
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf) || payload.nbf < 0) {
      throw new Error('JWT invalid nbf claim');
    }
    if (nowSec + 30 < payload.nbf) { // 30s clock-skew tolerance
      throw new Error('JWT not yet valid');
    }
  }

  return payload;
}

// ─── Seal ID generation ─────────────────────────────────────────────────────

/**
 * Generate a unique seal ID for a secret name.
 * @param {string} name
 * @returns {string} e.g. "seal://stripe-api-key-a1b2c3d4ef12"
 */
export function generateSealId(name) {
  const hash = createHash('sha256').update(name + randomBytes(8).toString('hex')).digest('hex').slice(0, 12);
  return `seal://${name.toLowerCase().replace(/[^a-z0-9-]/g, '-')}-${hash}`;
}

// Re-export timingSafeEqual for callers that need it (vault-daemon.js)
export { timingSafeEqual, randomBytes, createHash, createHmac };
