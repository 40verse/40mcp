/**
 * Security invariants — index / legacy entry point
 *
 * ⚠️  Tests have been split into per-trust-surface files under
 *     src/security/invariants/.  This file is retained as a historical
 *     reference and so that any tooling that hard-codes the old path still
 *     resolves without an import error.
 *
 * Surface files (canonical test suite):
 *   src/security/invariants/ssrf.test.js       — SSRF / URL / network safety
 *   src/security/invariants/policy.test.js     — Policy / authority / steering
 *   src/security/invariants/vault.test.js      — Vault passphrase / key safety
 *   src/security/invariants/webhook.test.js    — Webhook timestamp parsing
 *   src/security/invariants/tenant.test.js     — Tenant scope isolation
 *   src/security/invariants/schema.test.js     — OpenAPI / GraphQL schema safety
 *   src/security/invariants/sanitize.test.js   — Input validation / sanitization
 *
 * Run the full suite:
 *   npm run test:invariants
 *
 * @module security/invariants
 * @see {@link ./invariants/ssrf.test.js}
 * @see {@link ./invariants/sanitize.test.js}
 */
