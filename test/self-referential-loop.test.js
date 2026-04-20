/**
 * Self-referential loop smoke test.
 *
 * Killer differentiator of 40mcp: reverse bridge → HAR capture → HAR loader → new bridge.
 *
 * Smoke-test strategy (in-memory, no network required):
 *   (a) Tool definitions go into the reverse bridge
 *   (b) Reverse bridge produces a valid OpenAPI spec
 *   (c) OpenAPI spec is fed into the OpenAPI loader → new tool definitions
 *   (d) Loaded tool definitions match the originals (name, method, path)
 *
 * A secondary sub-test validates the HAR leg of the loop using in-memory HAR construction
 * (same pattern used in test/har-ingestion.test.js).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateOpenApiSpec, createReverseBridge } from '../src/reverse/server.js';
import { loadOpenApiSpec } from '../src/openapi.js';
import { loadHarFile } from '../src/loaders/har.js';

// ─── Fixtures ────────────────────────────────────────────────────────────────

/** Canonical tool set used across all sub-tests. */
const SOURCE_TOOLS = [
  {
    name: 'list_repos',
    description: 'List repositories for a user.',
    inputSchema: {
      type: 'object',
      properties: {
        username: { type: 'string' },
        per_page: { type: 'integer' },
      },
      required: ['username'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a single repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
      },
      required: ['owner', 'repo'],
    },
  },
];

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('self-referential loop smoke test', () => {
  /**
   * Sub-test (b)+(c)+(d): OpenAPI path
   *
   * reverse bridge OpenAPI output → loadOpenApiSpec() → tool definitions match
   */
  it('(b) reverse bridge generates valid OpenAPI spec for source tools', () => {
    const spec = generateOpenApiSpec({
      name: 'smoke-api',
      version: '1.0.0',
      tools: SOURCE_TOOLS,
      basePath: '/api',
    });

    // Must be OpenAPI 3.0
    assert.equal(spec.openapi, '3.0.0', 'spec.openapi must be 3.0.0');
    assert.equal(spec.info.title, 'smoke-api');
    assert.equal(spec.info.version, '1.0.0');

    // Each tool must have a POST path under /api/tools/<name>
    for (const tool of SOURCE_TOOLS) {
      const pathKey = `/api/tools/${tool.name}`;
      assert.ok(spec.paths[pathKey], `spec.paths must include ${pathKey}`);
      assert.ok(spec.paths[pathKey].post, `${pathKey} must have a POST operation`);
      assert.equal(
        spec.paths[pathKey].post.operationId,
        tool.name,
        `operationId must equal tool name "${tool.name}"`,
      );
    }
  });

  it('(c) OpenAPI spec from reverse bridge can be loaded back as tool definitions', async () => {
    const spec = generateOpenApiSpec({
      name: 'smoke-api',
      version: '1.0.0',
      tools: SOURCE_TOOLS,
      basePath: '/api',
    });

    // Feed the spec directly (no file I/O needed)
    const { tools: loadedTools } = await loadOpenApiSpec(spec);

    assert.ok(loadedTools.length >= SOURCE_TOOLS.length,
      `Expected at least ${SOURCE_TOOLS.length} tools from spec, got ${loadedTools.length}`);
  });

  it('(d) loaded tool names match originals — loop closes', async () => {
    const spec = generateOpenApiSpec({
      name: 'smoke-api',
      version: '1.0.0',
      tools: SOURCE_TOOLS,
      basePath: '/api',
    });

    const { tools: loadedTools } = await loadOpenApiSpec(spec);

    const sourceNames = SOURCE_TOOLS.map((t) => t.name).sort();
    const loadedNames = loadedTools.map((t) => t.name).sort();

    assert.deepEqual(
      loadedNames,
      sourceNames,
      `Loaded tool names must match source tool names.\nExpected: ${sourceNames}\nGot: ${loadedNames}`,
    );
  });

  /**
   * Full OpenAPI round-trip via the reverse bridge server (no actual HTTP dispatch needed).
   * Uses generateOpenApiSpec() from the reverse bridge module directly.
   */
  it('full OpenAPI round-trip: source tools → reverse bridge spec → loadOpenApiSpec → tools match', async () => {
    // (a) Tools go into the reverse bridge's spec generator
    const spec = generateOpenApiSpec({
      name: 'round-trip',
      version: '2.0.0',
      tools: SOURCE_TOOLS,
      basePath: '/api',
    });

    // (b) Spec is valid OpenAPI
    assert.equal(spec.openapi, '3.0.0');
    assert.equal(Object.keys(spec.paths).length, SOURCE_TOOLS.length);

    // (c) Load back
    const { tools: reloaded } = await loadOpenApiSpec(spec);

    // (d) Names match
    const sourceNames = SOURCE_TOOLS.map((t) => t.name).sort();
    const reloadedNames = reloaded.map((t) => t.name).sort();
    assert.deepEqual(reloadedNames, sourceNames, 'Roundtrip must preserve all tool names');

    // Each reloaded tool has required fields
    for (const tool of reloaded) {
      assert.ok(tool.name, 'reloaded tool must have name');
      assert.ok(tool.method, 'reloaded tool must have method');
      assert.ok(tool.path, 'reloaded tool must have path');
    }
  });

  /**
   * HAR leg smoke test: build an in-memory HAR from simulated reverse-bridge traffic
   * and verify the HAR loader produces tools.
   */
  it('HAR leg: in-memory HAR from reverse bridge traffic → HAR loader → tools', async () => {
    const dispatch = async (toolName, _args) => ({ tool: toolName, ok: true });

    const reverse = createReverseBridge({
      name: 'har-smoke',
      tools: SOURCE_TOOLS,
      dispatch,
      port: 0,
    });

    const { httpServer, url } = await reverse.start();

    try {
      // Build HAR in-memory from real HTTP calls to the reverse bridge
      const har = { log: { entries: [] } };

      for (const tool of SOURCE_TOOLS) {
        const args = {};
        for (const req of tool.inputSchema.required || []) {
          args[req] = 'smoke-value';
        }

        const res = await fetch(`${url}/api/tools/${tool.name}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(args),
        });

        const responseText = await res.text();

        har.log.entries.push({
          request: {
            method: 'POST',
            url: `${url}/api/tools/${tool.name}`,
            queryString: [],
            postData: { mimeType: 'application/json', text: JSON.stringify(args) },
          },
          response: {
            status: res.status,
            content: { mimeType: 'application/json', text: responseText },
          },
        });
      }

      // Feed HAR to the loader.
      // allowPrivate: reverse bridge binds to 127.0.0.1 here; loopback is permitted in this context
      // rejects private baseUrls unless explicitly opted in.
      const { baseUrl: harBaseUrl, tools: harTools } = await loadHarFile(har, { allowPrivate: true });

      assert.ok(harBaseUrl, 'HAR loader must detect a base URL');
      assert.ok(harTools.length >= 1,
        `HAR loader must produce at least 1 tool, got ${harTools.length}`);

      for (const tool of harTools) {
        assert.ok(tool.name, 'HAR-inferred tool must have a name');
        assert.ok(tool.method, 'HAR-inferred tool must have a method');
        assert.ok(tool.path, 'HAR-inferred tool must have a path');
      }
    } finally {
      httpServer.closeAllConnections?.();
      httpServer.close();
    }
  });
});
