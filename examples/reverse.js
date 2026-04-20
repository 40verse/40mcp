/**
 * Example: Reverse bridge — expose MCP tools as a REST API.
 *
 * Takes tool definitions from a config and creates a REST API.
 * Prints the OpenAPI spec URL at startup.
 *
 * Run:   node examples/reverse.js
 * Then:  curl http://localhost:3000/api/openapi.json
 */

import { createRestBridge } from '../src/index.js';
import { createReverseBridge } from '../src/index.js';

// Create a bridge with some tools
const bridge = createRestBridge({
  name: 'petstore',
  version: '1.0.0',
  baseUrl: 'https://petstore3.swagger.io/api/v3',
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
          pet_status: {
            type: 'string',
            enum: ['available', 'pending', 'sold'],
          },
        },
        required: ['pet_status'],
      },
    },
  ],
});

// Reverse bridge: expose as REST API instead of MCP
const reverse = createReverseBridge({
  name: 'petstore-rest',
  version: '1.0.0',
  tools: [
    {
      name: 'list_pets',
      description: 'List pets by status.',
      inputSchema: {
        type: 'object',
        properties: {
          pet_status: {
            type: 'string',
            enum: ['available', 'pending', 'sold'],
          },
        },
        required: ['pet_status'],
      },
    },
  ],
  dispatch: bridge.dispatch,
  port: 3000,
});

const { url } = await reverse.start();
console.log(`OpenAPI spec at: ${url}/api/openapi.json`);
console.log(`Example: curl -X POST ${url}/api/tools/list_pets -H 'Content-Type: application/json' -d '{"pet_status":"available"}'`);
