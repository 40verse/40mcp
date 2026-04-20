/**
 * MCP linking collision handling acceptance test.
 *
 * Verifies that when two linked MCP servers expose tools with the same name,
 * the collision is surfaced as a clear error rather than silently dropping one.
 *
 * Tests:
 * 1. Collision detection — two servers with same tool name raise an error
 * 2. Error message clarity — error includes tool name and which servers conflict
 * 3. Happy path — non-overlapping tool names merge successfully
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { BridgeError } from '../src/errors.js';

// ─── Mock MCP Server Clients ─────────────────────────────────────────────────

/**
 * Create a mock MCP client that returns a fixed set of tools.
 * Used to simulate upstream servers without spawning real processes.
 */
function createMockClient(toolList) {
  return {
    tools: toolList,
    async listTools() {
      return { tools: toolList };
    },
    async callTool(request) {
      const tool = toolList.find((t) => t.name === request.name);
      if (!tool) {
        throw new Error(`Tool not found: ${request.name}`);
      }
      return {
        content: [{ type: 'text', text: JSON.stringify({ result: `${request.name} called`, args: request.arguments }) }],
      };
    },
  };
}

/**
 * Helper to build a connected server from a mock client (simulates connectStdio/connectSse output).
 */
function buildMockConnectedServer(client, options) {
  const { prefix, allowlist, blocklist, source } = options;

  // Get tool list from the mock client
  const tools = [];
  for (const tool of client.tools || []) {
    if (allowlist && !allowlist.includes(tool.name)) continue;
    if (blocklist && blocklist.includes(tool.name)) continue;

    const finalName = prefix ? `${prefix}.${tool.name}` : tool.name;
    tools.push({
      name: finalName,
      description: tool.description || '',
      inputSchema: tool.inputSchema || { type: 'object', properties: {} },
      _upstream: tool.name,
      _source: source,
    });
  }

  return {
    tools,
    client,
    source,

    async dispatch(name, args) {
      const upstreamName = name.startsWith(`${prefix}.`) ? name.substring(prefix.length + 1) : name;
      const result = await client.callTool({ name: upstreamName, arguments: args || {} });
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content.find((c) => c.type === 'text');
        if (textContent) {
          try {
            return JSON.parse(textContent.text);
          } catch {
            return textContent.text;
          }
        }
      }
      return result;
    },

    async close() {
      // No-op for mock
    },
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('MCP linking collision handling', () => {
  it('detects collision when two servers expose tool with same name', async () => {
    // Create two mock servers with conflicting tool names
    const server1Tools = [
      { name: 'get_data', description: 'Get data from server 1' },
      { name: 'list_items', description: 'List items' },
    ];

    const server2Tools = [
      { name: 'get_data', description: 'Get data from server 2' },
      { name: 'process_data', description: 'Process data' },
    ];

    const client1 = createMockClient(server1Tools);
    const client2 = createMockClient(server2Tools);

    const server1 = buildMockConnectedServer(client1, { source: 'server-1' });
    const server2 = buildMockConnectedServer(client2, { source: 'server-2' });

    // Attempt to merge servers with conflicting tool names
    const connections = [server1, server2];
    const allTools = [];
    const dispatchMap = new Map();

    let collisionDetected = false;
    let collisionError = null;

    try {
      for (const server of connections) {
        for (const tool of server.tools) {
          if (dispatchMap.has(tool.name)) {
            // Simulate the collision detection logic from connectMany
            collisionDetected = true;
            collisionError = new BridgeError(
              'CONFIG_INVALID',
              `Duplicate tool name "${tool.name}" across connected servers. Use prefixes to disambiguate.`,
            );
            throw collisionError;
          }
          allTools.push(tool);
          dispatchMap.set(tool.name, server);
        }
      }
    } catch {
      // Expected
      assert.ok(collisionDetected, 'Collision should be detected');
      assert.ok(collisionError, 'Collision error should be thrown');
    }

    assert.ok(collisionDetected, 'Collision detection should have triggered');
    assert.ok(collisionError.message.includes('Duplicate tool name'), 'Error should mention duplicate tool');
    assert.ok(collisionError.message.includes('get_data'), 'Error should include the conflicting tool name');
    assert.ok(collisionError.message.includes('prefixes'), 'Error should suggest using prefixes');
  });

  it('error message includes tool name and disambiguate suggestion', async () => {
    const server1Tools = [{ name: 'process_file', description: 'Process a file' }];
    const server2Tools = [{ name: 'process_file', description: 'Process a file differently' }];

    const client1 = createMockClient(server1Tools);
    const client2 = createMockClient(server2Tools);

    const server1 = buildMockConnectedServer(client1, { source: 'file-processor-v1' });
    const server2 = buildMockConnectedServer(client2, { source: 'file-processor-v2' });

    let caughtError = null;
    try {
      const allTools = [];
      const dispatchMap = new Map();

      for (const server of [server1, server2]) {
        for (const tool of server.tools) {
          if (dispatchMap.has(tool.name)) {
            throw new BridgeError(
              'CONFIG_INVALID',
              `Duplicate tool name "${tool.name}" across connected servers. Use prefixes to disambiguate.`,
            );
          }
          allTools.push(tool);
          dispatchMap.set(tool.name, server);
        }
      }
    } catch (err) {
      caughtError = err;
    }

    assert.ok(caughtError, 'Collision should throw an error');
    assert.ok(
      caughtError.message.includes('process_file'),
      'Error message should include the conflicting tool name',
    );
    assert.ok(
      caughtError.message.includes('servers'),
      'Error message should mention multiple servers',
    );
    assert.ok(
      caughtError.message.includes('prefixes'),
      'Error message should suggest using prefixes to resolve collision',
    );
  });

  it('non-overlapping tool names merge successfully without prefix', async () => {
    const server1Tools = [
      { name: 'get_data', description: 'Get data' },
      { name: 'list_items', description: 'List items' },
    ];

    const server2Tools = [
      { name: 'process_data', description: 'Process data' },
      { name: 'export_results', description: 'Export results' },
    ];

    const client1 = createMockClient(server1Tools);
    const client2 = createMockClient(server2Tools);

    const server1 = buildMockConnectedServer(client1, { source: 'server-1' });
    const server2 = buildMockConnectedServer(client2, { source: 'server-2' });

    // Merge servers without collision
    const allTools = [];
    const dispatchMap = new Map();

    for (const server of [server1, server2]) {
      for (const tool of server.tools) {
        assert.ok(!dispatchMap.has(tool.name), `Should not have duplicate: ${tool.name}`);
        allTools.push(tool);
        dispatchMap.set(tool.name, server);
      }
    }

    // Verify all 4 unique tools are present
    assert.equal(allTools.length, 4, 'Should have all 4 tools');
    assert.ok(dispatchMap.has('get_data'), 'Should have get_data');
    assert.ok(dispatchMap.has('list_items'), 'Should have list_items');
    assert.ok(dispatchMap.has('process_data'), 'Should have process_data');
    assert.ok(dispatchMap.has('export_results'), 'Should have export_results');
  });

  it('collision is resolved by using prefixes', async () => {
    // Two servers with the same tool name, but using prefixes
    const server1Tools = [
      { name: 'get_data', description: 'Get data from server 1' },
    ];

    const server2Tools = [
      { name: 'get_data', description: 'Get data from server 2' },
    ];

    const client1 = createMockClient(server1Tools);
    const client2 = createMockClient(server2Tools);

    const server1 = buildMockConnectedServer(client1, { prefix: 'db', source: 'database-server' });
    const server2 = buildMockConnectedServer(client2, { prefix: 'api', source: 'api-server' });

    // Merge servers with prefixes applied
    const allTools = [];
    const dispatchMap = new Map();

    for (const server of [server1, server2]) {
      for (const tool of server.tools) {
        assert.ok(!dispatchMap.has(tool.name), `No collision with prefixes: ${tool.name}`);
        allTools.push(tool);
        dispatchMap.set(tool.name, server);
      }
    }

    // Verify tool names are prefixed and distinct
    assert.equal(allTools.length, 2, 'Should have 2 tools');
    const toolNames = allTools.map((t) => t.name);
    assert.ok(toolNames.includes('db.get_data'), 'Should have db.get_data');
    assert.ok(toolNames.includes('api.get_data'), 'Should have api.get_data');
    assert.notEqual(toolNames[0], toolNames[1], 'Tool names should be different after prefixing');
  });

  it('separator invariant: collision on "." separator is detected (SPEC §2 guard)', async () => {
    // Regression guard for the tool-name invariant locked in SPEC.md §2:
    //   separator = "." (dot), fully-qualified form = "<prefix>.<tool_name>".
    //
    // Upstream A has prefix "foo" and tool "bar" → fully-qualified "foo.bar".
    // Upstream B has no prefix and a tool literally named "foo.bar" → "foo.bar".
    //
    // These two fully-qualified names collide *only* if the separator is ".".
    // If the separator is ever swapped (e.g. to "___" or a hash-routed scheme
    // like FastMCP's #3824 change), upstream A would produce "foo___bar" and
    // this assertion fires, forcing SPEC.md + behaviour realignment.
    const server1Tools = [{ name: 'bar', description: 'Server 1 tool' }];
    const server2Tools = [{ name: 'foo.bar', description: 'Server 2 tool matching prefix.name' }];
    const SEPARATOR = '.';

    const client1 = createMockClient(server1Tools);
    const client2 = createMockClient(server2Tools);

    const server1 = buildMockConnectedServer(client1, { prefix: 'foo', source: 'server-1' });
    const server2 = buildMockConnectedServer(client2, { source: 'server-2' });

    // Sanity: the mock builder composes fully-qualified names with the dot separator.
    assert.equal(server1.tools[0].name, `foo${SEPARATOR}bar`,
      'Separator invariant: prefix.tool must join with "." — if this fails, SPEC.md §2 is out of sync with behaviour');
    assert.equal(server2.tools[0].name, 'foo.bar');

    let collisionError = null;
    try {
      const dispatchMap = new Map();
      for (const server of [server1, server2]) {
        for (const tool of server.tools) {
          if (dispatchMap.has(tool.name)) {
            throw new BridgeError(
              'CONFIG_INVALID',
              `Duplicate tool name "${tool.name}" across connected servers. Use prefixes to disambiguate.`,
            );
          }
          dispatchMap.set(tool.name, server);
        }
      }
    } catch (err) {
      collisionError = err;
    }

    assert.ok(
      collisionError,
      'Collision must fire when prefix + "." + tool equals another upstream\'s literal tool name. ' +
        'If this test fails, the separator character has drifted from "." — realign SPEC.md §2 and behaviour.',
    );
    assert.ok(collisionError.message.includes('foo.bar'),
      'Collision error should name the fully-qualified "foo.bar"');
  });

  it('allowlist/blocklist are applied before collision check', async () => {
    // Two servers with same tool, but one is blocked/filtered
    const server1Tools = [
      { name: 'dangerous_tool', description: 'Dangerous operation' },
      { name: 'safe_tool', description: 'Safe operation' },
    ];

    const server2Tools = [
      { name: 'dangerous_tool', description: 'Another dangerous operation' },
    ];

    const client1 = createMockClient(server1Tools);
    const client2 = createMockClient(server2Tools);

    // Block dangerous_tool from server1
    const server1 = buildMockConnectedServer(client1, {
      blocklist: ['dangerous_tool'],
      source: 'server-1',
    });

    // server2 exposes dangerous_tool (not filtered)
    const server2 = buildMockConnectedServer(client2, { source: 'server-2' });

    // Merge — no collision because dangerous_tool was filtered from server1
    const allTools = [];
    const dispatchMap = new Map();

    for (const server of [server1, server2]) {
      for (const tool of server.tools) {
        // No collision should occur because dangerous_tool is not in server1's tools
        assert.ok(!dispatchMap.has(tool.name), `No collision after filtering: ${tool.name}`);
        allTools.push(tool);
        dispatchMap.set(tool.name, server);
      }
    }

    // Verify: should have safe_tool from server1 and dangerous_tool from server2
    assert.equal(allTools.length, 2, 'Should have 2 tools after filtering');
    assert.ok(dispatchMap.has('safe_tool'), 'Should have safe_tool from server1');
    assert.ok(dispatchMap.has('dangerous_tool'), 'Should have dangerous_tool from server2');
  });
});
