import { createStdioTransport } from './stdio.js';
import { createSseTransport } from './sse.js';
import { BridgeError, BridgeErrorCode } from '../errors.js';

export { createStdioTransport, createSseTransport };

/**
 * Create a transport from a config string.
 * @param {'stdio'|'sse'} type
 * @param {object} [options] - SSE options (port, path, messagePath)
 * @returns {Function}
 */
export function createTransport(type, options) {
  const stdioFn = createStdioTransport;
  const sseFn = createSseTransport;

  if (type === 'stdio') {
    return async () => stdioFn();
  }

  if (type === 'sse') {
    return async (server) => sseFn(server, options);
  }

  throw new BridgeError(BridgeErrorCode.CONFIG_INVALID, `Unknown transport type: ${type}. Must be "stdio" or "sse".`);
}
