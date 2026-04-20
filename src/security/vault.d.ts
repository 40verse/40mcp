/**
 * 40mcp/security — TypeScript declarations for the `./security` subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/security'`.
 * Canonical declarations live in `../index.d.ts`; re-exported here to keep
 * a single source of truth.
 *
 * Note: the subpath resolves to `src/security/vault.js` which exports
 * `createVault`, `initVault`, `recoverVault`, and the internal
 * `getDaemonInternals` accessor. Vault-daemon client helpers live in
 * `vault-client.js` and are intentionally NOT re-exported by this subpath
 * (only the root `.` entry re-exports `createVaultDaemonClient`).
 */

import type { SealedVault } from '../index.js';

export {
  VaultConfig,
  SealedEntry,
  CredentialToken,
  VerifiedToken,
  SealedVault,
  createVault,
  InitVaultResult,
  initVault,
  recoverVault,
} from '../index.js';

/**
 * @internal Daemon-only accessor. Returns the WeakMap-bound daemon internals
 * for a vault instance, or `undefined` when the vault was not created with
 * daemon bindings. Exposed for `vault-client.js` / `vault-daemon.js`; not part
 * of the stable public API.
 */
export function getDaemonInternals(vault: SealedVault): unknown;
