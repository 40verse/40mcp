/**
 * Example: Generate MCP tools from a HAR traffic recording.
 *
 * The HAR loader infers tool definitions from observed HTTP traffic —
 * no OpenAPI spec needed. Point it at a Chrome DevTools HAR export.
 *
 * Run:  node examples/from-har.js
 */

import { loadHarFile } from '../src/loaders/har.js';

// Minimal inline HAR for demonstration (normally loaded from file)
const sampleHar = {
  log: {
    entries: [
      {
        request: { method: 'GET', url: 'https://api.example.com/users?limit=10', queryString: [{ name: 'limit', value: '10' }] },
        response: { status: 200, content: { mimeType: 'application/json', text: '[{"id":1,"name":"Alice"}]' } },
      },
      {
        request: { method: 'GET', url: 'https://api.example.com/users?limit=25', queryString: [{ name: 'limit', value: '25' }] },
        response: { status: 200, content: { mimeType: 'application/json', text: '[{"id":1},{"id":2}]' } },
      },
      {
        request: { method: 'GET', url: 'https://api.example.com/users/42', queryString: [] },
        response: { status: 200, content: { mimeType: 'application/json', text: '{"id":42,"name":"Bob"}' } },
      },
      {
        request: { method: 'POST', url: 'https://api.example.com/users', queryString: [], postData: { mimeType: 'application/json', text: '{"name":"Charlie"}' } },
        response: { status: 201, content: { mimeType: 'application/json', text: '{"id":3}' } },
      },
    ],
  },
};

const { tools } = await loadHarFile(sampleHar);

process.stderr.write(`[from-har] Discovered ${tools.length} tools from HAR traffic\n`);
for (const tool of tools) {
  process.stderr.write(`  ${tool.name} (${tool.method} ${tool.path}) — ${tool._confidence} confidence, ${tool._observations} observations\n`);
}

// Uncomment to start the server:
// await createRestBridge({ name: 'har-discovered', baseUrl, tools }).start();
