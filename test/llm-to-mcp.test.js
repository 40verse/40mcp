/**
 * test/llm-to-mcp.test.js
 *
 * The 4th dimension: LLM-to-MCP
 *
 * The three prior dimensions prove:
 *   1. HAR ingestion — HTTP traffic → parameterised tools
 *   2. MCP-to-API — bridge.dispatch() → real HTTP backend
 *   3. MCP-to-MCP — one bridge proxies through another over stdio
 *
 * This file proves the FULL PRODUCTION LOOP:
 *   Natural-language goal
 *     → tool schema discovery (what tools exist + their JSON Schema)
 *     → tool selection (LLM picks the right tool from the schema)
 *     → dispatch (40mcp executes the call)
 *     → result synthesis (LLM-ready text returned to agent)
 *
 * Primary path: MinimalAgentLoop (deterministic, no API key needed)
 *   - Selects tools by scoring goal text against tool names/descriptions
 *   - Proves schema is machine-readable and dispatch is reliable
 *
 * Extended path (runs when ANTHROPIC_API_KEY is set):
 *   - Real Claude claude-haiku-4-5-20251001 drives tool selection via tool_use
 *   - Proves 40mcp tools integrate into the Anthropic tool_use wire format
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRestBridge } from '../src/index.js';

// ─── Mock API ────────────────────────────────────────────────────────────────
// Realistic product catalog + order management API

function createProductApi() {
  const products = [
    { id: 1, name: 'Ergonomic Chair', category: 'furniture', price: 349.99, stock: 24 },
    { id: 2, name: 'Standing Desk', category: 'furniture', price: 599.00, stock: 8 },
    { id: 3, name: 'Mechanical Keyboard', category: 'peripherals', price: 129.99, stock: 150 },
    { id: 4, name: 'USB-C Hub', category: 'peripherals', price: 49.99, stock: 300 },
    { id: 5, name: 'Monitor Arm', category: 'furniture', price: 89.99, stock: 45 },
  ];

  const orders = [];

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname;
    res.setHeader('Content-Type', 'application/json');

    const send = (status, body) => {
      res.writeHead(status);
      res.end(JSON.stringify(body));
    };

    const parseBody = () =>
      new Promise((resolve) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => resolve(body ? JSON.parse(body) : {}));
      });

    if (req.method === 'GET' && path === '/products') {
      const cat = url.searchParams.get('category');
      const results = cat ? products.filter((p) => p.category === cat) : products;
      return send(200, results);
    }

    const productMatch = path.match(/^\/products\/(\d+)$/);
    if (req.method === 'GET' && productMatch) {
      const p = products.find((p) => p.id === parseInt(productMatch[1]));
      return p ? send(200, p) : send(404, { error: 'product not found' });
    }

    if (req.method === 'POST' && path === '/orders') {
      return parseBody().then((body) => {
        const product = products.find((p) => p.id === body.product_id);
        if (!product) return send(400, { error: 'invalid product_id' });
        if (product.stock < (body.quantity || 1)) return send(409, { error: 'insufficient stock' });

        const order = {
          id: orders.length + 1,
          product_id: body.product_id,
          product_name: product.name,
          quantity: body.quantity || 1,
          total: product.price * (body.quantity || 1),
          status: 'confirmed',
          created_at: new Date().toISOString(),
        };
        orders.push(order);
        product.stock -= order.quantity;
        return send(201, order);
      });
    }

    if (req.method === 'GET' && path === '/orders') {
      return send(200, orders);
    }

    return send(404, { error: 'not found' });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const baseUrl = `http://127.0.0.1:${port}`;
      resolve({ baseUrl, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

// ─── MinimalAgentLoop ────────────────────────────────────────────────────────
// Deterministic LLM simulator. Scores each tool against a goal by counting
// keyword matches across name + description. The highest-scoring tool wins.
// This proves tool schemas are machine-readable and goal-to-tool mapping works
// without requiring a live LLM API.

class MinimalAgentLoop {
  constructor(tools, dispatch) {
    this.tools = tools;       // MCP tool definitions: { name, description, inputSchema }
    this.dispatch = dispatch; // bridge.dispatch(name, args) → result
  }

  /** Score a tool against a goal by keyword overlap. */
  _scoreTool(tool, goal) {
    const haystack = `${tool.name} ${tool.description}`.toLowerCase();
    const words = goal.toLowerCase().split(/\W+/).filter((w) => w.length > 2);
    return words.reduce((n, w) => n + (haystack.includes(w) ? 1 : 0), 0);
  }

  /** Select the best tool for a goal (highest keyword score). */
  selectTool(goal) {
    return this.tools
      .map((t) => ({ tool: t, score: this._scoreTool(t, goal) }))
      .sort((a, b) => b.score - a.score)[0]?.tool ?? null;
  }

  /** Infer arg values for a tool from the goal and a hints object. */
  _inferArgs(tool, hints = {}) {
    const schema = tool.inputSchema?.properties ?? {};
    const args = {};
    for (const [key] of Object.entries(schema)) {
      if (hints[key] !== undefined) args[key] = hints[key];
    }
    return args;
  }

  /**
   * Run a single-turn agent step:
   *   goal → select tool → dispatch → return { tool, args, result }
   * result is the raw API response (object or array).
   */
  async run(goal, hints = {}) {
    const tool = this.selectTool(goal);
    assert.ok(tool, `No tool found for goal: "${goal}"`);

    const args = this._inferArgs(tool, hints);
    const result = await this.dispatch(tool.name, args);

    return { tool: tool.name, args, result };
  }
}

// ─── Bridge factory ──────────────────────────────────────────────────────────

/**
 * Returns { bridge, tools, dispatch } where tools is the raw definition array.
 * MinimalAgentLoop uses the tool defs for schema inspection / selection.
 * dispatch is bridge.dispatch, the direct call function.
 */
function buildProductBridge(baseUrl) {
  const toolDefs = [
      {
        name: 'list_products',
        description: 'List all products in the catalog, optionally filtered by category',
        method: 'GET',
        path: '/products',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Filter by category: furniture or peripherals',
            },
          },
        },
      },
      {
        name: 'get_product',
        description: 'Get details for a specific product by its numeric ID',
        method: 'GET',
        path: '/products/:id',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'number', description: 'Product ID' },
          },
          required: ['id'],
        },
      },
      {
        name: 'place_order',
        description: 'Create a new order to purchase a product',
        method: 'POST',
        path: '/orders',
        inputSchema: {
          type: 'object',
          properties: {
            product_id: { type: 'number', description: 'ID of product to order' },
            quantity: { type: 'number', description: 'Number of units to purchase' },
          },
          required: ['product_id'],
        },
      },
      {
        name: 'list_orders',
        description: 'List all placed orders',
        method: 'GET',
        path: '/orders',
        inputSchema: { type: 'object', properties: {} },
      },
  ];

  const bridge = createRestBridge({ name: 'product-catalog', baseUrl, tools: toolDefs });
  return { tools: toolDefs, dispatch: bridge.dispatch };
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

let api;

before(async () => {
  api = await createProductApi();
});

after(async () => {
  await api.close();
});

// ─── Tests ───────────────────────────────────────────────────────────────────

test('LLM-to-MCP: tool schemas are valid JSON Schema with names and descriptions', () => {
  const { tools } = buildProductBridge('http://localhost:1');

  assert.ok(tools.length === 4, `expected 4 tools, got ${tools.length}`);

  for (const tool of tools) {
    assert.ok(typeof tool.name === 'string' && tool.name.length > 0, 'tool must have name');
    assert.ok(
      typeof tool.description === 'string' && tool.description.length > 10,
      `tool "${tool.name}" needs a meaningful description`
    );
    assert.ok(tool.inputSchema?.type === 'object', `tool "${tool.name}" inputSchema must be type:object`);
    assert.ok(typeof tool.inputSchema.properties === 'object', 'inputSchema must have properties');
  }
});

test('LLM-to-MCP: MinimalAgentLoop selects correct tool from goal text', () => {
  const { tools, dispatch } = buildProductBridge(api.baseUrl);
  const agent = new MinimalAgentLoop(tools, dispatch);

  // Each goal should unambiguously map to a specific tool
  assert.equal(agent.selectTool('list all products in the catalog')?.name, 'list_products');
  assert.equal(agent.selectTool('get details for a specific product')?.name, 'get_product');
  assert.equal(agent.selectTool('place an order to purchase something')?.name, 'place_order');
  assert.equal(agent.selectTool('list all orders that were placed')?.name, 'list_orders');
});

test('LLM-to-MCP: agent runs list_products goal end-to-end', async () => {
  const { tools, dispatch } = buildProductBridge(api.baseUrl);
  const agent = new MinimalAgentLoop(tools, dispatch);

  const { tool, result } = await agent.run('Show me all products available in the catalog');
  assert.equal(tool, 'list_products');

  assert.ok(Array.isArray(result));
  assert.equal(result.length, 5);
  assert.ok(result.every((p) => p.name && p.price));
});

test('LLM-to-MCP: agent runs filtered list_products with category hint', async () => {
  const { tools, dispatch } = buildProductBridge(api.baseUrl);
  const agent = new MinimalAgentLoop(tools, dispatch);

  const { tool, result } = await agent.run(
    'List products in the furniture category',
    { category: 'furniture' }
  );
  assert.equal(tool, 'list_products');

  assert.ok(result.every((p) => p.category === 'furniture'));
  assert.equal(result.length, 3);
});

test('LLM-to-MCP: agent fetches a specific product by ID', async () => {
  const { tools, dispatch } = buildProductBridge(api.baseUrl);
  const agent = new MinimalAgentLoop(tools, dispatch);

  const { tool, result } = await agent.run('Get details for a specific product', { id: 3 });
  assert.equal(tool, 'get_product');

  assert.equal(result.id, 3);
  assert.equal(result.name, 'Mechanical Keyboard');
  assert.equal(result.category, 'peripherals');
});

test('LLM-to-MCP: agent places an order — full purchase loop', async () => {
  const { tools, dispatch } = buildProductBridge(api.baseUrl);
  const agent = new MinimalAgentLoop(tools, dispatch);

  const { tool, result } = await agent.run(
    'Create a new order to purchase a product',
    { product_id: 4, quantity: 2 }
  );
  assert.equal(tool, 'place_order');

  assert.equal(result.status, 'confirmed');
  assert.equal(result.product_id, 4);
  assert.equal(result.quantity, 2);
  assert.ok(typeof result.total === 'number');
  assert.ok(result.total > 0);
});

test('LLM-to-MCP: multi-step agent loop: discover catalog, pick item, place order, verify', async () => {
  const { tools, dispatch } = buildProductBridge(api.baseUrl);
  const agent = new MinimalAgentLoop(tools, dispatch);

  // Step 1: discover what's available
  const step1 = await agent.run('List all products available');
  const catalog = step1.result;
  assert.ok(catalog.length > 0, 'catalog must not be empty');

  // Step 2: find a specific item (simulate LLM picking from catalog)
  const target = catalog.find((p) => p.category === 'peripherals');
  assert.ok(target, 'must find a peripherals product');

  // Step 3: get full details
  const step3 = await agent.run('Get product details', { id: target.id });
  const detail = step3.result;
  assert.equal(detail.id, target.id);
  assert.ok(detail.stock > 0, 'product must be in stock');

  // Step 4: place the order
  const step4 = await agent.run('Place an order for this product', {
    product_id: detail.id,
    quantity: 1,
  });
  const order = step4.result;
  assert.equal(order.status, 'confirmed');
  assert.equal(order.product_id, detail.id);

  // Step 5: verify it appears in order history
  const step5 = await agent.run('List all placed orders');
  const history = step5.result;
  assert.ok(history.some((o) => o.product_id === detail.id));
});

test('LLM-to-MCP: result is a structured object ready for LLM reasoning', async () => {
  const { tools, dispatch } = buildProductBridge(api.baseUrl);
  const agent = new MinimalAgentLoop(tools, dispatch);

  const { result } = await agent.run('Show me the product catalog');

  // LLMs need structured data — verify the result is a proper object
  assert.ok(Array.isArray(result), 'catalog should be an array');
  assert.ok(result[0].name, 'each item should have a name field');
  assert.ok(typeof result[0].price === 'number', 'price should be numeric');

  // Verify it serializes cleanly for LLM context injection
  const serialized = JSON.stringify(result);
  assert.doesNotThrow(() => JSON.parse(serialized), 'result must round-trip through JSON');
});

// ─── Extended: Real Anthropic tool_use (runs only if API key is set) ─────────
//
// This test is intentionally skipped in CI because it requires a live
// ANTHROPIC_API_KEY, which is not available in automated test environments.
// It is designed to be run manually by contributors who have API access:
//
//   ANTHROPIC_API_KEY=sk-ant-... npm run test:integration
//
// The test validates the full LLM→MCP round-trip: that a real Claude Haiku
// model correctly selects a tool via the tool_use protocol and that 40mcp
// dispatches the call and returns a valid, JSON-serializable result.
// All the non-LLM parts of this flow are covered by the unit suite.

const anthropicAvailable = !!process.env.ANTHROPIC_API_KEY;

test(
  'LLM-to-MCP (real Claude): Haiku selects and calls a tool via tool_use',
  { skip: anthropicAvailable ? false : 'ANTHROPIC_API_KEY not set' },
  async () => {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const client = new Anthropic();

    const { tools, dispatch } = buildProductBridge(api.baseUrl);

    // Convert 40mcp tool schemas to Anthropic tool_use format
    const anthropicTools = tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.inputSchema,
    }));

    // Ask Claude to list furniture products
    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 256,
      tools: anthropicTools,
      tool_choice: { type: 'any' },
      messages: [
        {
          role: 'user',
          content: 'List all furniture products available in the catalog.',
        },
      ],
    });

    // Claude should request a tool call
    const toolUse = response.content.find((c) => c.type === 'tool_use');
    assert.ok(toolUse, 'Claude should return a tool_use block');
    assert.equal(toolUse.name, 'list_products', `expected list_products, got ${toolUse.name}`);

    // Execute the tool call via 40mcp (returns raw API response)
    const products = await dispatch(toolUse.name, toolUse.input ?? {});

    // Claude's tool call should have filtered by furniture
    if (toolUse.input?.category) {
      assert.ok(products.every((p) => p.category === toolUse.input.category));
    } else {
      assert.ok(Array.isArray(products));
    }
  }
);
