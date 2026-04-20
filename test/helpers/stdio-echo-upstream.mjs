#!/usr/bin/env node
/**
 * Test-only MCP upstream for the webhook → linked-upstream composition test.
 *
 * Exposes two deterministic tools over stdio so the test can assert that
 * a webhook POST routed through `createWebhookListener` + `connectStdio`
 * actually reaches an upstream MCP server and returns a verifiable result.
 *
 *   echo_text(text: string) → { echoed: text, pid, now }
 *   sum_numbers(a: number, b: number) → { sum: a + b }
 *
 * This file is NOT shipped with the package — it lives under `test/helpers/`
 * and is loaded only by the integration test that spawns it.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const server = new Server(
  { name: 'stdio-echo-upstream', version: '0.0.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'echo_text',
      description: 'Echo the input text, plus metadata for verification.',
      inputSchema: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text'],
      },
    },
    {
      name: 'sum_numbers',
      description: 'Return the sum of two numbers.',
      inputSchema: {
        type: 'object',
        properties: {
          a: { type: 'number' },
          b: { type: 'number' },
        },
        required: ['a', 'b'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const name = req.params?.name;
  const args = req.params?.arguments ?? {};
  if (name === 'echo_text') {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          echoed: String(args.text ?? ''),
          source: 'stdio-echo-upstream',
        }),
      }],
    };
  }
  if (name === 'sum_numbers') {
    const a = Number(args.a);
    const b = Number(args.b);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ sum: a + b }),
      }],
    };
  }
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: `unknown tool: ${name}` }) }],
    isError: true,
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);

// Exit cleanly when the parent closes stdin. StdioServerTransport fires onclose
// on EOF, but the SDK doesn't call process.exit itself — without this hook the
// helper lingers in the event loop and blocks `connectStdio`'s .close() from
// completing its test tear-down.
transport.onclose = () => {
  process.exit(0);
};
process.stdin.on('end', () => process.exit(0));
process.stdin.on('close', () => process.exit(0));
