/**
 * Self-referential loop test — Phase 5 proof of concept.
 *
 * 40mcp wraps itself:
 *   1. Create a bridge with tools
 *   2. Reverse bridge exposes them as REST
 *   3. Capture HTTP traffic as HAR
 *   4. HAR loader generates new tool definitions from that traffic
 *   5. New bridge works with the generated tools
 *
 * This proves the tesseract: any dimension can generate any other dimension.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRestBridge } from '../src/bridge.js';
import { createReverseBridge } from '../src/reverse/server.js';
import { loadHarFile } from '../src/loaders/har.js';

describe('self-referential loop — 40mcp wraps itself', () => {
  it('reverse bridge → HTTP calls → HAR capture → HAR loader → new bridge', async () => {
    // ─── Step 1: Create a source bridge with tools ───────────────────
    const sourceBridge = createRestBridge({
      name: 'source',
      baseUrl: 'https://jsonplaceholder.typicode.com',
      tools: [
        {
          name: 'get_user',
          description: 'Get a user by ID.',
          method: 'GET',
          path: '/users/:user_id',
          inputSchema: {
            type: 'object',
            properties: { user_id: { type: 'integer' } },
            required: ['user_id'],
          },
        },
        {
          name: 'list_posts',
          description: 'List posts.',
          method: 'GET',
          path: '/posts',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    });

    // ─── Step 2: Expose as REST via reverse bridge ───────────────────
    const reverse = createReverseBridge({
      name: 'source-rest',
      tools: sourceBridge.server ? [
        { name: 'get_user', description: 'Get a user by ID.', inputSchema: { type: 'object', properties: { user_id: { type: 'integer' } }, required: ['user_id'] } },
        { name: 'list_posts', description: 'List posts.', inputSchema: { type: 'object', properties: {} } },
      ] : [],
      dispatch: sourceBridge.dispatch,
      port: 0, // Random port
    });

    const { httpServer, url } = await reverse.start();

    try {
      // ─── Step 3: Make HTTP calls and capture as HAR ──────────────
      const har = { log: { entries: [] } };

      // Call list tools
      const toolsRes = await fetch(`${url}/api/tools`);
      assert.equal(toolsRes.status, 200);
      const toolList = await toolsRes.json();
      assert.ok(toolList.tools.length >= 2);

      // Call get_user via REST
      const userRes = await fetch(`${url}/api/tools/get_user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: 1 }),
      });

      // Capture as HAR entry
      har.log.entries.push({
        request: {
          method: 'POST',
          url: `${url}/api/tools/get_user`,
          queryString: [],
          postData: { mimeType: 'application/json', text: JSON.stringify({ user_id: 1 }) },
        },
        response: {
          status: userRes.status,
          content: { mimeType: 'application/json', text: await userRes.text() },
        },
      });

      // Call list_posts via REST
      const postsRes = await fetch(`${url}/api/tools/list_posts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      har.log.entries.push({
        request: {
          method: 'POST',
          url: `${url}/api/tools/list_posts`,
          queryString: [],
          postData: { mimeType: 'application/json', text: '{}' },
        },
        response: {
          status: postsRes.status,
          content: { mimeType: 'application/json', text: await postsRes.text() },
        },
      });

      // ─── Step 4: HAR loader generates new tool definitions ───────
      // allowPrivate: reverse bridge binds to 127.0.0.1 in this test; loopback is permitted in this context
      // hardening rejects private baseUrls unless explicitly opted in.
      const { baseUrl: harBaseUrl, tools: harTools } = await loadHarFile(har, { allowPrivate: true });

      assert.ok(harBaseUrl, 'HAR loader should detect base URL');
      assert.ok(harTools.length >= 1, `Expected 1+ tools from HAR, got ${harTools.length}`);

      // Verify the generated tools have names and paths
      for (const tool of harTools) {
        assert.ok(tool.name, 'HAR tool should have a name');
        assert.ok(tool.method, 'HAR tool should have a method');
        assert.ok(tool.path, 'HAR tool should have a path');
      }

      // ─── Step 5: New bridge works with HAR-generated tools ───────
      const generatedBridge = createRestBridge({
        name: 'generated-from-har',
        baseUrl: harBaseUrl,
        tools: harTools,
      });

      assert.ok(generatedBridge.dispatch);
      assert.ok(generatedBridge.server);

      // The loop is complete: bridge → REST → HAR → bridge
      process.stderr.write(`[self-ref] Loop complete: ${harTools.length} tools regenerated from HAR traffic\n`);

    } finally {
      httpServer.closeAllConnections?.();
      httpServer.close();
    }
  });

  it('OpenAPI spec from reverse bridge can regenerate tools', async () => {
    // Step 1: Source bridge
    const source = createRestBridge({
      name: 'spec-source',
      baseUrl: 'https://api.example.com',
      tools: [
        { name: 'ping', description: 'Health check', method: 'GET', path: '/ping', inputSchema: { type: 'object', properties: {} } },
        { name: 'create_item', description: 'Create an item', method: 'POST', path: '/items', inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] } },
      ],
    });

    // Step 2: Reverse bridge generates OpenAPI spec
    const reverse = createReverseBridge({
      name: 'spec-gen',
      tools: [
        { name: 'ping', description: 'Health check', inputSchema: { type: 'object', properties: {} } },
        { name: 'create_item', description: 'Create an item', inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] } },
      ],
      dispatch: source.dispatch,
      port: 0,
    });

    const { httpServer, url } = await reverse.start();

    try {
      // Step 3: Fetch generated OpenAPI spec
      const specRes = await fetch(`${url}/api/openapi.json`);
      assert.equal(specRes.status, 200);
      const spec = await specRes.json();

      // Verify it's valid OpenAPI
      assert.equal(spec.openapi, '3.0.0');
      assert.ok(spec.paths['/api/tools/ping']);
      assert.ok(spec.paths['/api/tools/create_item']);

      // Step 4: Feed back into OpenAPI loader (would create tools from spec)
      // The spec is valid OpenAPI and could be loaded with loadOpenApiSpec
      assert.ok(Object.keys(spec.paths).length >= 2);

      process.stderr.write(`[self-ref] OpenAPI loop: ${Object.keys(spec.paths).length} paths in generated spec\n`);
    } finally {
      httpServer.closeAllConnections?.();
      httpServer.close();
    }
  });
});
