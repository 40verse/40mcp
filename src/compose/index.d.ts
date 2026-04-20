/**
 * 40mcp/compose — TypeScript declarations for the `./compose` subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/compose'`.
 * Canonical declarations live in `../index.d.ts`; re-exported here to keep
 * a single source of truth.
 */

export {
  ChainOptions,
  ChainResult,
  executeChain,
  MixerServerConfig,
  MixerConfig,
  MixerInstance,
  createMixer,
} from '../index.js';
