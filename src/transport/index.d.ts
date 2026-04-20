/**
 * 40mcp/transport — TypeScript declarations for the `./transport` subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/transport'`.
 * Canonical declarations live in `../index.d.ts`; re-exported here to keep
 * a single source of truth.
 */

export {
  SseTransportOptions,
  SseTransportResult,
  createStdioTransport,
  createSseTransport,
  createTransport,
} from '../index.js';
