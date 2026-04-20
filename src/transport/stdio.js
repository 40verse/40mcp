import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

/**
 * Create a stdio transport.
 * @returns {StdioServerTransport}
 */
export function createStdioTransport() {
  return new StdioServerTransport();
}
