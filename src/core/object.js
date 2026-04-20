/**
 * Object path utilities with prototype-pollution guards.
 *
 * Safely traverse and manipulate nested objects by dot-path without
 * descending through __proto__, constructor, or prototype.
 *
 * @module core/object
 */

/** Prototype-poisoning keys blocked in path traversal */
export const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Prototype-safe own-property check.
 *
 * Use this instead of `'key' in obj` (which walks the prototype chain) or
 * `obj.hasOwnProperty(key)` (which can be shadowed on poisoned objects).
 *
 * @param {object} obj - Object to inspect
 * @param {string} key - Property key to check
 * @returns {boolean} True if obj has key as a direct (non-inherited) property
 */
export function hasOwnKey(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/**
 * Get a value from an object by dot-path (e.g., "user.name" → obj.user.name)
 * Prototype-safe: skips traversal through __proto__, constructor, prototype.
 * Envelope-safe: refuses to traverse non-enumerable own properties — reserved
 * envelope keys (_tenant, _steering, _chain, etc.) are intentionally
 * non-enumerable to prevent leakage via user-controlled path traversal.
 * Returns undefined on any missing segment, dangerous key, or non-enumerable
 * own property access.
 *
 * @param {object} obj - Object to traverse
 * @param {string} path - Dot-separated path (e.g., "a.b.c")
 * @returns {any} The value at path, or undefined
 */
export function getByPath(obj, path) {
  if (!obj || typeof obj !== 'object') return undefined;
  const keys = path.split('.');
  let current = obj;
  for (const key of keys) {
    if (DANGEROUS_KEYS.has(key)) return undefined;
    // Honour the non-enumerable contract. Reserved envelope keys (_tenant,
    // _steering, _chain, _depth, _policy, etc.) are attached with
    // enumerable:false specifically so they are invisible to serialisation,
    // logging, and enumeration. Refuse to traverse them here so a malicious
    // chain $ref like "$args._tenant.auth.value" cannot extract the tenant
    // bearer token even though direct property access would succeed.
    if (current !== null && typeof current === 'object') {
      const desc = Object.getOwnPropertyDescriptor(current, key);
      if (desc !== undefined && !desc.enumerable) return undefined;
    }
    current = current?.[key];
    if (current === undefined) return undefined;
  }
  return current;
}

/**
 * Set a value in an object by dot-path, creating intermediate objects as needed.
 * Prototype-safe: refuses to write any DANGEROUS_KEYS segments.
 *
 * @param {object} obj - Object to modify
 * @param {string} path - Dot-separated path (e.g., "a.b.c")
 * @param {any} value - Value to set
 */
export function setByPath(obj, path, value) {
  const keys = path.split('.');
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (DANGEROUS_KEYS.has(key)) return;
    // Use hasOwnProperty instead of `in` — the `in` operator walks the
    // prototype chain, allowing `setByPath(obj, 'valueOf.foo', x)` to traverse
    // into `Object.prototype.valueOf` and mutate it. hasOwnProperty only
    // creates a new intermediate object when the key is absent as an OWN
    // property, preventing prototype-chain traversal during path building.
    if (!Object.prototype.hasOwnProperty.call(current, key)) {
      current[key] = {};
    }
    current = current[key];
  }

  const lastKey = keys[keys.length - 1];
  if (!DANGEROUS_KEYS.has(lastKey)) {
    current[lastKey] = value;
  }
}

/**
 * Delete a value from an object by dot-path.
 * Prototype-safe: refuses to delete any DANGEROUS_KEYS segments.
 * No-op if any intermediate segment is missing.
 *
 * @param {object} obj - Object to modify
 * @param {string} path - Dot-separated path (e.g., "a.b.c")
 */
export function deleteByPath(obj, path) {
  const keys = path.split('.');
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (DANGEROUS_KEYS.has(key)) return;
    // Use hasOwnProperty instead of `in` — the `in` operator walks the
    // prototype chain, allowing `deleteByPath(obj, 'valueOf.foo')` to traverse
    // into Object.prototype.valueOf. Mirror the fix applied to setByPath.
    if (!Object.prototype.hasOwnProperty.call(current, key)) {
      return;
    }
    current = current[key];
  }

  const lastKey = keys[keys.length - 1];
  if (!DANGEROUS_KEYS.has(lastKey)) {
    delete current[lastKey];
  }
}
