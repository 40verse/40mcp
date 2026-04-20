/**
 * 40mcp/webhook — TypeScript declarations for the `./webhook` subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/webhook'`.
 * Canonical declarations live in `../index.d.ts`; re-exported here to keep
 * a single source of truth.
 *
 * Note: the JS module also exports `parseWebhookTimestamp` (strict-integer
 * timestamp parser) and a test-only shim `_validateSecretForTesting`. The
 * timestamp parser is a useful public helper and declared below. The
 * `_validateSecretForTesting` shim is deliberately NOT declared here — it
 * is reached only by invariant tests via relative `.js` import, and
 * omitting it from the subpath declarations keeps the public TypeScript
 * surface clean.
 */

export {
  WebhookSecret,
  WebhookRoute,
  WebhookListenerConfig,
  WebhookListenerInstance,
  createWebhookListener,
} from '../index.js';

/**
 * Strict-integer timestamp parser. Returns ms since epoch, or null if
 * the value is not a plain-digit integer within the acceptable range.
 */
export function parseWebhookTimestamp(value: string): number | null;
