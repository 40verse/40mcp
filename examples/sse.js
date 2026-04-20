/**
 * Example: Start an MCP server with SSE transport for remote clients.
 *
 * Instead of stdio (for local CLI tools), SSE lets browser-based
 * and remote MCP clients connect over HTTP.
 *
 * Run:  node examples/sse.js
 * Then: Connect your MCP client to http://127.0.0.1:8080/sse
 */

import { createRestBridge } from '../src/index.js';

await createRestBridge({
  name: 'sse-example',
  version: '1.0.0',
  baseUrl: 'https://petstore3.swagger.io/api/v3',

  // SSE transport instead of stdio
  transport: {
    type: 'sse',
    port: 8080,
    // host: '0.0.0.0',         // Uncomment to expose externally
    // allowedOrigins: ['*'],   // Uncomment for dev CORS
  },

  tools: [
    {
      name: 'list_pets',
      description: 'List pets by status.',
      method: 'GET',
      path: '/pet/findByStatus',
      queryMap: { pet_status: 'status' },
      inputSchema: {
        type: 'object',
        properties: {
          pet_status: { type: 'string', enum: ['available', 'pending', 'sold'] },
        },
        required: ['pet_status'],
      },
    },
  ],
}).start();
