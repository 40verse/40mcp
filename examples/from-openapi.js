/**
 * Example: Auto-generate MCP tools from an OpenAPI spec.
 *
 * This fetches the Petstore spec at startup and creates tools for every
 * operation. API keys are read from environment variables (e.g. set in Railway).
 *
 * Run:   API_KEY=xxx node examples/from-openapi.js
 * .mcp.json:
 *   {
 *     "mcpServers": {
 *       "petstore": {
 *         "command": "node",
 *         "args": ["examples/from-openapi.js"],
 *         "env": { "API_KEY": "your-key-here" }
 *       }
 *     }
 *   }
 */

import { createRestBridge, loadOpenApiSpec } from '../src/index.js';

// Load from a remote or local spec — JSON only for now
const { baseUrl, tools } = await loadOpenApiSpec(
  'https://petstore3.swagger.io/api/v3/openapi.json',
  {
    tags: ['pet'],           // Only wrap the "pet" endpoints
    methods: ['get', 'post'], // Skip PUT/DELETE
  },
);

process.stderr.write(`[from-openapi] Loaded ${tools.length} tools from spec\n`);

await createRestBridge({
  name: 'petstore-auto',
  version: '1.0.0',
  baseUrl,
  // API key stored in Railway env var → injected as header at runtime
  auth: {
    type: 'header',
    header: 'api_key',
    envVar: 'API_KEY',
  },
  tools,
}).start();
