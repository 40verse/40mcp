/**
 * Frontdoor policy / tenant scope.
 *
 * Spawns a `40mcp link --sse ...` frontdoor with each of `--policy` and
 * `--tenant-map` and verifies that the linked surface is shaped
 * accordingly. Also exercises the AsyncLocalStorage principal threading
 * that lands `principal` + `sessionId` on `frontdoor.tool_call`, and the
 * loud-failure path for the removed `--steering` flag.
 *
 * Tool calls are made over the published SSE endpoint using the MCP SDK's
 * SSE client, so the full transport → ALS → policy → tenant → dispatch
 * chain is covered end-to-end.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function waitForPort(port, { timeoutMs = 10_000 } = {}) {
  const start = Date.now();
  return new Promise((resolveWait, reject) => {
    const tick = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/health`);
        if (res.ok) return resolveWait();
      } catch { /* still starting */ }
      if (Date.now() - start > timeoutMs) {
        return reject(new Error(`frontdoor /health never came up on ${port}`));
      }
      setTimeout(tick, 100);
    };
    tick();
  });
}

async function pickFreePort() {
  return await new Promise((done, fail) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => done(port));
    });
    srv.on('error', fail);
  });
}

async function connectClient(port, token) {
  const transport = new SSEClientTransport(new URL(`http://127.0.0.1:${port}/sse`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
    // The EventSource used by the server-send path also needs to carry the
    // bearer token or the stream 401s on the initial GET.
    eventSourceInit: {
      fetch: (url, init) => fetch(url, {
        ...init,
        headers: { ...(init?.headers || {}), Authorization: `Bearer ${token}` },
      }),
    },
  });
  const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
  await client.connect(transport);
  return { client, transport };
}

function killProc(proc) {
  return new Promise((done) => {
    if (!proc || proc.exitCode !== null) return done();
    proc.kill('SIGTERM');
    proc.once('exit', done);
    setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* ignore */ } done(); }, 3000).unref();
  });
}

// Shared upstream — an HTTP API + a .mcp.json pointing at a stdio 40mcp
// child that bridges it. Three tools: ping, echo, delete_all (deliberately
// named so policy denies can be demonstrated).
let apiServer;
let apiPort;
let upstreamCfg;
let frontdoorCfg;
const cliPath = resolve(__dirname, '../src/cli.js');

before(async () => {
  apiServer = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/ping') { res.end(JSON.stringify({ pong: true })); return; }
    if (req.url === '/echo') { res.end(JSON.stringify({ echo: true })); return; }
    if (req.url === '/delete_all') { res.end(JSON.stringify({ deleted: 42 })); return; }
    res.writeHead(404); res.end('{}');
  });
  await new Promise((done) => apiServer.listen(0, '127.0.0.1', done));
  apiPort = apiServer.address().port;

  upstreamCfg = resolve(__dirname, '_frontdoor-pst-upstream.json');
  await writeFile(upstreamCfg, JSON.stringify({
    name: 'upstream',
    baseUrl: `http://127.0.0.1:${apiPort}`,
    tools: [
      { name: 'ping', description: 'ping', method: 'GET', path: '/ping',
        inputSchema: { type: 'object', properties: {} } },
      { name: 'echo', description: 'echo', method: 'GET', path: '/echo',
        inputSchema: { type: 'object', properties: {} } },
      { name: 'delete_all', description: 'delete everything', method: 'GET', path: '/delete_all',
        inputSchema: { type: 'object', properties: {} } },
    ],
  }));

  frontdoorCfg = resolve(__dirname, '_frontdoor-pst-servers.mcp.json');
  await writeFile(frontdoorCfg, JSON.stringify({
    mcpServers: {
      upstream: { command: 'node', args: [cliPath, 'serve', upstreamCfg] },
    },
  }));
});

after(async () => {
  await new Promise((done) => apiServer.close(done));
  await rm(upstreamCfg, { force: true });
  await rm(frontdoorCfg, { force: true });
});

// ─── Policy ──────────────────────────────────────────────────────────────

describe('frontdoor --policy', () => {
  it('denies a tool whose policy is "deny" and allows the rest', async () => {
    const port = await pickFreePort();
    const policyFile = resolve(__dirname, '_frontdoor-policy.json');
    await writeFile(policyFile, JSON.stringify({
      toolPolicies: { 'upstream.delete_all': 'deny' },
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--require-bearer', 'policy-tok',
      '--policy', policyFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    let client; let transport;
    try {
      await waitForPort(port);
      ({ client, transport } = await connectClient(port, 'policy-tok'));

      // Allowed tool.
      const ok = await client.callTool({ name: 'upstream.ping', arguments: {} });
      assert.ok(ok.content, 'ping should succeed');

      // Denied tool.
      await assert.rejects(
        () => client.callTool({ name: 'upstream.delete_all', arguments: {} }),
        (err) => /deny|policy/i.test(err.message),
      );

      // Policy audit event fires for the denied call.
      await new Promise((done) => setTimeout(done, 100));
      assert.ok(/\[40mcp:event\].*frontdoor\.policy|policy_denied/.test(stderr),
        `expected policy audit in stderr, got:\n${stderr.slice(-800)}`);
    } finally {
      try { await transport?.close(); } catch { /* ignore */ }
      try { await client?.close(); } catch { /* ignore */ }
      await killProc(proc);
      await rm(policyFile, { force: true });
    }
  });

  it('require_approval is treated as deny when no approval handler is configured', async () => {
    const port = await pickFreePort();
    const policyFile = resolve(__dirname, '_frontdoor-policy-approval.json');
    await writeFile(policyFile, JSON.stringify({
      toolPolicies: { 'upstream.echo': 'require_approval' },
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--require-bearer', 'approv-tok',
      '--policy', policyFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    let client; let transport;
    try {
      await waitForPort(port);
      ({ client, transport } = await connectClient(port, 'approv-tok'));

      await assert.rejects(
        () => client.callTool({ name: 'upstream.echo', arguments: {} }),
        (err) => /deny|policy/i.test(err.message),
      );

      await new Promise((done) => setTimeout(done, 100));
      assert.ok(/no_approval_handler/.test(stderr),
        `expected no_approval_handler event, got:\n${stderr.slice(-800)}`);
    } finally {
      try { await transport?.close(); } catch { /* ignore */ }
      try { await client?.close(); } catch { /* ignore */ }
      await killProc(proc);
      await rm(policyFile, { force: true });
    }
  });
});

// ─── Steering (removed) ──────────────────────────────────────────────────

describe('frontdoor --steering (removed feature)', () => {
  it('exits with a removal error instead of silently ignoring the flag', async () => {
    const port = await pickFreePort();
    const steeringFile = resolve(__dirname, '_frontdoor-steering.json');
    await writeFile(steeringFile, JSON.stringify({
      'upstream.ping': { prehook: 'X' },
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--require-bearer', 'steer-tok',
      '--steering', steeringFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    proc.stdout.on('data', () => {});
    let stderr = '';
    proc.stderr.on('data', (d) => { stderr += d; });

    try {
      const exitCode = await new Promise((done) => proc.once('exit', done));
      assert.equal(exitCode, 1, `expected exit 1, got ${exitCode}; stderr:\n${stderr.slice(-800)}`);
      assert.ok(
        /--steering is no longer supported/.test(stderr),
        `expected removal message, got:\n${stderr.slice(-800)}`,
      );
    } finally {
      await killProc(proc);
      await rm(steeringFile, { force: true });
    }
  });
});

// ─── Tenant scope ────────────────────────────────────────────────────────

describe('frontdoor --tenant-map', () => {
  it('enforces per-principal allowlist', async () => {
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-tenant-bearer.json');
    const tenantFile = resolve(__dirname, '_frontdoor-tenant-map.json');
    await writeFile(bearerFile, JSON.stringify({
      alice: 'tok-alice',
      bob: 'tok-bob',
    }));
    await writeFile(tenantFile, JSON.stringify({
      alice: { tenantId: 'alice-tenant', allowlist: ['upstream.ping'] },
      bob:   { tenantId: 'bob-tenant',   allowlist: ['upstream.echo'] },
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
      '--tenant-map', tenantFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', () => {});

    let aClient; let aTransport; let bClient; let bTransport;
    try {
      await waitForPort(port);

      // Alice: ping allowed, echo denied.
      ({ client: aClient, transport: aTransport } = await connectClient(port, 'tok-alice'));
      const alicePing = await aClient.callTool({ name: 'upstream.ping', arguments: {} });
      assert.ok(alicePing.content, 'alice.ping should succeed');
      await assert.rejects(
        () => aClient.callTool({ name: 'upstream.echo', arguments: {} }),
        (err) => /not (available|in) .* allowlist|Access denied|not authorized/i.test(err.message),
      );

      // Bob: echo allowed, ping denied.
      ({ client: bClient, transport: bTransport } = await connectClient(port, 'tok-bob'));
      const bobEcho = await bClient.callTool({ name: 'upstream.echo', arguments: {} });
      assert.ok(bobEcho.content, 'bob.echo should succeed');
      await assert.rejects(
        () => bClient.callTool({ name: 'upstream.ping', arguments: {} }),
        (err) => /not (available|in) .* allowlist|Access denied|not authorized/i.test(err.message),
      );
    } finally {
      try { await aTransport?.close(); } catch { /* ignore */ }
      try { await aClient?.close(); } catch { /* ignore */ }
      try { await bTransport?.close(); } catch { /* ignore */ }
      try { await bClient?.close(); } catch { /* ignore */ }
      await killProc(proc);
      await rm(bearerFile, { force: true });
      await rm(tenantFile, { force: true });
    }
  });

  it('--tenant-map without multi-token auth fails fast', async () => {
    const port = await pickFreePort();
    const tenantFile = resolve(__dirname, '_frontdoor-tenant-alone.json');
    await writeFile(tenantFile, JSON.stringify({
      alice: { tenantId: 't1' },
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--require-bearer', 'single-tok',
      '--tenant-map', tenantFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    try {
      const code = await new Promise((done) => proc.once('exit', done));
      assert.notEqual(code, 0, 'expected non-zero exit');
      assert.ok(/multi-token/i.test(stderr), `expected multi-token guard error, got:\n${stderr.slice(-600)}`);
    } finally {
      if (proc.exitCode === null) proc.kill('SIGKILL');
      await rm(tenantFile, { force: true });
    }
  });
});

// ─── Principal threading into frontdoor.tool_call ────────────────────────

describe('frontdoor.tool_call principal + sessionId attribution', () => {
  it('tags tool_call events with the session principal', async () => {
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-principal-bearer.json');
    await writeFile(bearerFile, JSON.stringify({ alice: 'tok-prin-alice' }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    let client; let transport;
    try {
      await waitForPort(port);
      ({ client, transport } = await connectClient(port, 'tok-prin-alice'));
      const r = await client.callTool({ name: 'upstream.ping', arguments: {} });
      assert.ok(r.content);

      await new Promise((done) => setTimeout(done, 150));
      assert.ok(
        /frontdoor\.tool_call.*"tool":"upstream\.ping".*"principal":"alice"/.test(stderr),
        `expected frontdoor.tool_call tagged with principal=alice, got:\n${stderr.slice(-800)}`,
      );
      // sessionId is also present and non-null.
      assert.ok(/frontdoor\.tool_call.*"sessionId":"[^"]+"/.test(stderr),
        `expected sessionId on tool_call, got:\n${stderr.slice(-800)}`);
    } finally {
      try { await transport?.close(); } catch { /* ignore */ }
      try { await client?.close(); } catch { /* ignore */ }
      await killProc(proc);
      await rm(bearerFile, { force: true });
    }
  });
});
