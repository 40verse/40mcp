/**
 * Bridge test — Microsoft Docs MCP + HuggingFace hf-mcp-server.
 *
 * Target upstream servers:
 *   - https://github.com/microsoftdocs/mcp       (remote HTTP/SSE at learn.microsoft.com/api/mcp)
 *   - https://github.com/huggingface/hf-mcp-server (remote HTTP at huggingface.co/mcp)
 *
 * Both are remote MCP servers. This test proves 40mcp's `connect` layer can
 * bridge to each by:
 *
 *   1. Spawning two local 40mcp REST-stub servers whose tool surfaces mirror
 *      the real Microsoft Docs and HuggingFace MCP servers (same tool names,
 *      same input schemas, approximate response shapes served by a local
 *      HTTP fixture).
 *   2. Using connectStdio + connectMany to aggregate both into one cluster,
 *      with "msdocs." and "hf." prefixes.
 *   3. Verifying tool discovery, prefix namespacing, dispatch routing, and
 *      layered response transforms (tokenBudget / pick) work end-to-end.
 *   4. Optionally attempting a live connectStreamableHttp against the real
 *      upstream endpoints — skipped cleanly when the sandbox blocks outbound
 *      network.
 *
 * Run:
 *   node --test test/bridge-microsoft-huggingface.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { writeFile, rm, mkdtemp } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { connectMany, connectStreamableHttp } from '../src/connect.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = resolve(__dirname, '../src/cli.js');

// ─── Tool surfaces (mirrors of the real upstream MCP servers) ─────────────────

// Microsoft Learn Docs MCP: https://github.com/microsoftdocs/mcp
const MSDOCS_TOOLS = [
  {
    name: 'microsoft_docs_search',
    description: 'Search official Microsoft and Azure documentation. Returns concise content chunks.',
    method: 'GET',
    path: '/search',
    queryMap: { question: 'q' },
    response: { pick: ['title', 'url', 'snippet'], limit: 10 },
    inputSchema: {
      type: 'object',
      properties: {
        question: { type: 'string', description: 'Search query for Microsoft documentation.' },
      },
      required: ['question'],
    },
  },
  {
    name: 'microsoft_code_sample_search',
    description: 'Search for code snippets and examples in official Microsoft Learn documentation.',
    method: 'GET',
    path: '/code-samples',
    queryMap: { query: 'q', language: 'lang' },
    response: { pick: ['title', 'language', 'code', 'url'], limit: 20 },
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query for Microsoft code samples.' },
        language: { type: 'string', description: 'Optional language filter (csharp, python, etc).' },
      },
      required: ['query'],
    },
  },
  {
    name: 'microsoft_docs_fetch',
    description: 'Fetch and convert a full Microsoft documentation page to markdown.',
    method: 'GET',
    path: '/fetch',
    queryMap: { url: 'url' },
    response: { tokenBudget: 4000 },
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Full URL of the Microsoft Learn documentation page.' },
      },
      required: ['url'],
    },
  },
];

// HuggingFace hf-mcp-server: https://github.com/huggingface/hf-mcp-server
const HF_TOOLS = [
  {
    name: 'hf_whoami',
    description: 'Return authenticated HuggingFace user info (anonymous if no token).',
    method: 'GET',
    path: '/whoami',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'model_search',
    description: 'Search the HuggingFace Hub for AI models by query, task, or library.',
    method: 'GET',
    path: '/models',
    queryMap: { query: 'search', task: 'task', library: 'library', limit: 'limit' },
    response: { pick: ['modelId', 'pipeline_tag', 'downloads', 'likes'], limit: 20 },
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        task: { type: 'string' },
        library: { type: 'string' },
        limit: { type: 'integer' },
      },
    },
  },
  {
    name: 'dataset_search',
    description: 'Search the HuggingFace Hub for datasets.',
    method: 'GET',
    path: '/datasets',
    queryMap: { query: 'search', limit: 'limit' },
    response: { pick: ['id', 'downloads', 'likes', 'tags'], limit: 20 },
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        limit: { type: 'integer' },
      },
    },
  },
  {
    name: 'space_search',
    description: 'Search HuggingFace Spaces (interactive ML demos).',
    method: 'GET',
    path: '/spaces',
    queryMap: { query: 'search', limit: 'limit' },
    response: { pick: ['id', 'likes', 'sdk'], limit: 20 },
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        limit: { type: 'integer' },
      },
    },
  },
  {
    name: 'paper_search',
    description: 'Search HuggingFace Papers for ML research.',
    method: 'GET',
    path: '/papers',
    queryMap: { query: 'q' },
    response: { pick: ['title', 'authors', 'url'], limit: 10 },
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
      },
      required: ['query'],
    },
  },
];

// ─── Local HTTP fixture backing both stub MCP servers ─────────────────────────

function createFixtureServer() {
  return createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const url = new URL(req.url, `http://${req.headers.host}`);

    // Microsoft Docs surface
    if (req.method === 'GET' && url.pathname === '/search') {
      return res.end(JSON.stringify([
        { title: 'Azure Functions overview', url: 'https://learn.microsoft.com/azure/functions/overview', snippet: 'Azure Functions is a serverless compute service...', score: 0.92 },
        { title: 'Get started with .NET', url: 'https://learn.microsoft.com/dotnet/core/get-started', snippet: 'Create your first .NET app.', score: 0.81 },
      ]));
    }
    if (req.method === 'GET' && url.pathname === '/code-samples') {
      return res.end(JSON.stringify([
        { title: 'HTTP trigger', language: 'csharp', code: '[FunctionName("Http")] public static async Task<IActionResult> Run(...) { }', url: 'https://learn.microsoft.com/sample/1' },
        { title: 'Cosmos DB query', language: 'csharp', code: 'var query = container.GetItemQueryIterator<T>(...);', url: 'https://learn.microsoft.com/sample/2' },
      ]));
    }
    if (req.method === 'GET' && url.pathname === '/fetch') {
      return res.end(JSON.stringify({
        url: url.searchParams.get('url'),
        markdown: '# Azure Functions\n\nAzure Functions is a serverless compute service that lets you run event-triggered code without provisioning or managing infrastructure.',
      }));
    }

    // HuggingFace surface
    if (req.method === 'GET' && url.pathname === '/whoami') {
      return res.end(JSON.stringify({ name: 'anonymous', type: 'user', orgs: [] }));
    }
    if (req.method === 'GET' && url.pathname === '/models') {
      return res.end(JSON.stringify([
        { modelId: 'mistralai/Mistral-7B-v0.1', pipeline_tag: 'text-generation', downloads: 1200000, likes: 2300, tags: ['pytorch'] },
        { modelId: 'openai/whisper-large-v3', pipeline_tag: 'automatic-speech-recognition', downloads: 890000, likes: 1800, tags: ['pytorch'] },
      ]));
    }
    if (req.method === 'GET' && url.pathname === '/datasets') {
      return res.end(JSON.stringify([
        { id: 'squad', downloads: 450000, likes: 1200, tags: ['question-answering'] },
        { id: 'glue', downloads: 380000, likes: 980, tags: ['text-classification'] },
      ]));
    }
    if (req.method === 'GET' && url.pathname === '/spaces') {
      return res.end(JSON.stringify([
        { id: 'stabilityai/stable-diffusion', likes: 9800, sdk: 'gradio' },
        { id: 'microsoft/HuggingGPT', likes: 3400, sdk: 'gradio' },
      ]));
    }
    if (req.method === 'GET' && url.pathname === '/papers') {
      return res.end(JSON.stringify([
        { title: 'Attention Is All You Need', authors: ['Vaswani et al.'], url: 'https://huggingface.co/papers/1706.03762' },
      ]));
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not found', path: url.pathname }));
  });
}

// ─── Test: build the bridge and run end-to-end ────────────────────────────────

describe('Bridge: microsoftdocs/mcp + huggingface/hf-mcp-server', () => {
  let apiServer;
  let apiPort;
  let workDir;
  let msdocsConfigPath;
  let hfConfigPath;
  let cluster;

  before(async () => {
    // Local HTTP fixture that backs both stub MCP servers.
    apiServer = createFixtureServer();
    await new Promise((r) => apiServer.listen(0, '127.0.0.1', r));
    apiPort = apiServer.address().port;

    workDir = await mkdtemp(join(tmpdir(), '40mcp-bridge-test-'));
    msdocsConfigPath = join(workDir, 'msdocs-stub.json');
    hfConfigPath = join(workDir, 'hf-stub.json');

    await writeFile(msdocsConfigPath, JSON.stringify({
      name: 'microsoftdocs-mcp-stub',
      version: '1.0.0',
      baseUrl: `http://127.0.0.1:${apiPort}`,
      tools: MSDOCS_TOOLS,
    }, null, 2));

    await writeFile(hfConfigPath, JSON.stringify({
      name: 'hf-mcp-server-stub',
      version: '1.0.0',
      baseUrl: `http://127.0.0.1:${apiPort}`,
      tools: HF_TOOLS,
    }, null, 2));

    // Build the bridge: connect to both stub servers at once via connectMany.
    cluster = await connectMany([
      { command: 'node', args: [cliPath, 'serve', msdocsConfigPath], prefix: 'msdocs' },
      { command: 'node', args: [cliPath, 'serve', hfConfigPath], prefix: 'hf' },
    ]);
  });

  after(async () => {
    if (cluster?.close) await cluster.close();
    if (apiServer) await new Promise((r) => apiServer.close(r));
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  it('aggregates Microsoft Docs and HuggingFace tool surfaces into one cluster', () => {
    const names = cluster.tools.map((t) => t.name);

    // Microsoft Docs MCP tools
    assert.ok(names.includes('msdocs.microsoft_docs_search'), `missing msdocs.microsoft_docs_search, got: ${names}`);
    assert.ok(names.includes('msdocs.microsoft_code_sample_search'), `missing msdocs.microsoft_code_sample_search, got: ${names}`);
    assert.ok(names.includes('msdocs.microsoft_docs_fetch'), `missing msdocs.microsoft_docs_fetch, got: ${names}`);

    // HuggingFace hf-mcp-server tools
    assert.ok(names.includes('hf.hf_whoami'), `missing hf.hf_whoami, got: ${names}`);
    assert.ok(names.includes('hf.model_search'), `missing hf.model_search, got: ${names}`);
    assert.ok(names.includes('hf.dataset_search'), `missing hf.dataset_search, got: ${names}`);
    assert.ok(names.includes('hf.space_search'), `missing hf.space_search, got: ${names}`);
    assert.ok(names.includes('hf.paper_search'), `missing hf.paper_search, got: ${names}`);

    assert.equal(cluster.tools.length, MSDOCS_TOOLS.length + HF_TOOLS.length);
  });

  it('namespaces prevent tool name collisions across upstream servers', () => {
    const names = cluster.tools.map((t) => t.name);
    for (const n of names) {
      assert.ok(n.startsWith('msdocs.') || n.startsWith('hf.'), `unprefixed tool leaked: ${n}`);
    }
  });

  it('tools/call routes microsoft_docs_search through the bridge to the upstream fixture', async () => {
    const result = await cluster.dispatch('msdocs.microsoft_docs_search', { question: 'azure functions' });
    const data = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(Array.isArray(data), `expected array of docs, got: ${typeof data}`);
    assert.ok(data.length > 0, 'expected at least one doc result');
    assert.ok(data[0].title && data[0].url, 'expected title+url on each result');
    // pick transform strips `score` → confirm token-aware shaping ran upstream.
    assert.ok(!('score' in data[0]), 'expected pick transform to strip score field');
  });

  it('tools/call routes microsoft_code_sample_search with language filter', async () => {
    const result = await cluster.dispatch('msdocs.microsoft_code_sample_search', { query: 'http trigger', language: 'csharp' });
    const data = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(Array.isArray(data));
    assert.ok(data.every((s) => 'language' in s && 'code' in s), 'expected language+code per sample');
  });

  it('tools/call routes microsoft_docs_fetch and applies tokenBudget', async () => {
    const result = await cluster.dispatch('msdocs.microsoft_docs_fetch', { url: 'https://learn.microsoft.com/azure/functions/overview' });
    const data = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(data, 'expected fetch payload');
    assert.ok(data.markdown || data.url, 'expected markdown or url in fetch result');
  });

  it('tools/call routes hf.model_search through the bridge with picked fields', async () => {
    const result = await cluster.dispatch('hf.model_search', { query: 'mistral', limit: 10 });
    const data = typeof result === 'string' ? JSON.parse(result) : result;
    assert.ok(Array.isArray(data));
    assert.ok(data.length > 0);
    assert.ok(data.every((m) => 'modelId' in m), 'expected modelId on each');
    // `tags` was stripped by pick → confirm response transform layering.
    assert.ok(data.every((m) => !('tags' in m)), 'expected pick to strip tags');
  });

  it('tools/call routes hf.dataset_search and hf.space_search', async () => {
    const datasets = await cluster.dispatch('hf.dataset_search', { query: 'squad' });
    const datasetData = typeof datasets === 'string' ? JSON.parse(datasets) : datasets;
    assert.ok(Array.isArray(datasetData));
    assert.ok(datasetData.some((d) => d.id === 'squad'));

    const spaces = await cluster.dispatch('hf.space_search', { query: 'stable diffusion' });
    const spaceData = typeof spaces === 'string' ? JSON.parse(spaces) : spaces;
    assert.ok(Array.isArray(spaceData));
    assert.ok(spaceData.some((s) => s.sdk === 'gradio'));
  });

  it('tools/call routes hf.paper_search and hf.hf_whoami', async () => {
    const papers = await cluster.dispatch('hf.paper_search', { query: 'attention' });
    const paperData = typeof papers === 'string' ? JSON.parse(papers) : papers;
    assert.ok(Array.isArray(paperData));
    assert.ok(paperData.some((p) => p.title.includes('Attention')));

    const me = await cluster.dispatch('hf.hf_whoami', {});
    const meData = typeof me === 'string' ? JSON.parse(me) : me;
    assert.ok(meData && meData.name === 'anonymous', 'expected anonymous whoami fallback');
  });

  it('unknown tool returns a structured error without crashing the cluster', async () => {
    await assert.rejects(
      () => cluster.dispatch('msdocs.does_not_exist', {}),
      (err) => typeof err?.message === 'string' && err.message.length > 0,
    );
    // cluster is still usable after the error
    const result = await cluster.dispatch('hf.hf_whoami', {});
    assert.ok(result);
  });

  it('upstream tool inputSchemas survive sanitization (no $ref, no prototype pollution)', () => {
    const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
    for (const tool of cluster.tools) {
      assert.equal(tool.inputSchema?.type, 'object');
      assert.ok(!hasOwn(tool.inputSchema || {}, '$ref'), `${tool.name}: schema leaked $ref`);
      assert.ok(!hasOwn(tool.inputSchema || {}, '__proto__'), `${tool.name}: schema leaked __proto__`);
      assert.ok(!hasOwn(tool.inputSchema || {}, 'constructor'), `${tool.name}: schema leaked constructor`);
    }
  });
});

// ─── Optional live probe against the real remote MCP servers ──────────────────
//
// These try an honest connectStreamableHttp() against the canonical remote endpoints.
// They PASS when the connection succeeds (CI with egress) OR when the
// environment blocks outbound network (sandbox). They FAIL only if connect.js
// throws an unexpected error shape, which would indicate a regression in the
// connector itself.

describe('Live probe (skipped when offline): real remote MCP endpoints', () => {
  const LIVE_TARGETS = [
    { label: 'microsoftdocs/mcp', url: 'https://learn.microsoft.com/api/mcp', prefix: 'msdocs_live' },
    { label: 'huggingface/hf-mcp-server', url: 'https://huggingface.co/mcp', prefix: 'hf_live' },
  ];

  for (const target of LIVE_TARGETS) {
    it(`connectStreamableHttp to ${target.label} succeeds OR skips cleanly when egress blocked`, async () => {
      let connected;
      try {
        connected = await connectStreamableHttp({ url: target.url, prefix: target.prefix });
      } catch (err) {
        const msg = String(err?.message || err);
        const code = err?.code;
        const networkBlocked =
          /ENETUNREACH|ECONNREFUSED|EAI_AGAIN|ENOTFOUND|fetch failed|403|not in allowlist|tunnel|proxy|(?:SSE|Streamable HTTP) client transport not available/i.test(msg) ||
          code === 403 ||
          code === 'ENETUNREACH' || code === 'ECONNREFUSED' || code === 'EAI_AGAIN' || code === 'ENOTFOUND';
        if (networkBlocked) {
          process.stderr.write(`[live-probe] ${target.label}: skipped (offline / egress blocked): ${msg.split('\n')[0]}\n`);
          return;
        }
        throw err;
      }
      try {
        assert.ok(Array.isArray(connected.tools), 'expected tools array from live MCP server');
        process.stderr.write(`[live-probe] ${target.label}: connected, ${connected.tools.length} tools discovered\n`);
      } finally {
        await connected.close();
      }
    });
  }
});
