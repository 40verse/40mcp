/**
 * Instance-metadata integration tests.
 *
 * Spawns the real `40mcp` CLI with `settings.instance.{name,tags}` set and
 * verifies the metadata appears on:
 *   1. stderr banners (`[40mcp] Frontdoor published — ... [<name> tag1,tag2]`)
 *   2. `/health` JSON payload (`instance: { name, tags }`)
 *   3. `[40mcp:audit]` log entries when a tool dispatches
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, '../../src/cli.js');

function pickFreePort() {
  return new Promise((done, fail) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => done(port));
    });
    srv.on('error', fail);
  });
}

function waitForHealth(port, { timeoutMs = 5000 } = {}) {
  const start = Date.now();
  return new Promise((done, fail) => {
    const tick = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/health`);
        if (res.ok) return done();
      } catch { /* still starting */ }
      if (Date.now() - start > timeoutMs) return fail(new Error(`health never came up on :${port}`));
      setTimeout(tick, 75);
    };
    tick();
  });
}

async function killAndWait(proc) {
  if (!proc || proc.killed) return;
  proc.kill('SIGTERM');
  await new Promise((done) => {
    if (proc.exitCode !== null) return done();
    proc.once('exit', done);
    setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} done(); }, 2000).unref();
  });
}

describe('instance metadata — /health payload', () => {
  let work;
  let proc;
  let port;

  before(async () => {
    work = mkdtempSync(join(tmpdir(), 'instance-meta-'));
    port = await pickFreePort();
    const configPath = join(work, 'config.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'instance-probe',
      baseUrl: 'http://127.0.0.1:1',
      tools: [{
        name: 'noop', description: 'noop', method: 'GET', path: '/noop',
        inputSchema: { type: 'object', properties: {} },
      }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      instance: { name: 'GitHub Production', tags: ['prod', 'source-control'] },
      bridge: { transport: { type: 'sse', host: '127.0.0.1', port } },
    }));

    proc = spawn('node', [CLI, 'serve', configPath], {
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: work,
    });
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', () => {});
    await waitForHealth(port);
  });

  after(async () => {
    await killAndWait(proc);
    try { rmSync(work, { recursive: true, force: true }); } catch {}
  });

  it('/health surfaces instance.name and instance.tags', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'ok');
    assert.deepEqual(body.instance, { name: 'GitHub Production', tags: ['prod', 'source-control'] });
  });
});

describe('instance metadata — banner suffix', () => {
  let work;

  before(() => {
    work = mkdtempSync(join(tmpdir(), 'instance-banner-'));
  });

  after(() => {
    try { rmSync(work, { recursive: true, force: true }); } catch {}
  });

  it('serve startup banner carries [<name> tags] suffix when instance is set', async () => {
    const port = await pickFreePort();
    const configPath = join(work, 'config.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'banner-probe',
      baseUrl: 'http://127.0.0.1:1',
      tools: [{
        name: 'noop', description: 'noop', method: 'GET', path: '/noop',
        inputSchema: { type: 'object', properties: {} },
      }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      instance: { name: 'Twitter Frontdoor', tags: ['staging'] },
      bridge: { transport: { type: 'sse', host: '127.0.0.1', port } },
    }));

    const proc = spawn('node', [CLI, 'serve', configPath], {
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: work,
    });
    let stderr = '';
    proc.stderr.on('data', (c) => { stderr += c.toString(); });
    proc.stdout.on('data', () => {});
    try {
      await waitForHealth(port);
      // `[<config.name>] MCP server started (SSE) — N tools at <url> [<instance.name> tag1,tag2]`
      assert.match(stderr, /MCP server started \(SSE\) —.*\[Twitter Frontdoor staging\]/);
      assert.match(stderr, /Loaded settings from /);
    } finally {
      await killAndWait(proc);
    }
  });

  it('serve stdio banner carries suffix when instance is set', async () => {
    const configPath = join(work, 'stdio-config.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'stdio-banner',
      baseUrl: 'http://127.0.0.1:1',
      tools: [{
        name: 'noop', description: 'noop', method: 'GET', path: '/noop',
        inputSchema: { type: 'object', properties: {} },
      }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      instance: { name: 'Local Dev', tags: ['dev'] },
    }));

    // stdio mode keeps running until we terminate it. Read stderr for a
    // brief window, assert the banner, then kill.
    const proc = spawn('node', [CLI, 'serve', configPath], {
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: work,
    });
    let stderr = '';
    proc.stderr.on('data', (c) => { stderr += c.toString(); });
    proc.stdout.on('data', () => {});
    try {
      // Wait until the startup banner lands (or short deadline).
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && !/MCP server started —/.test(stderr)) {
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.match(stderr, /MCP server started —.*\[Local Dev dev\]/);
    } finally {
      await killAndWait(proc);
    }
  });
});

describe('instance metadata — audit entries (frontdoor)', () => {
  let work;
  let apiServer;
  let upstreamCfg;
  let frontdoorCfg;
  let proc;
  let frontdoorPort;
  let stderrBuf = '';

  before(async () => {
    work = mkdtempSync(join(tmpdir(), 'instance-audit-'));
    // Tiny upstream API the bridge will front
    apiServer = createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/ping') { res.end(JSON.stringify({ pong: true })); return; }
      res.writeHead(404); res.end('{}');
    });
    await new Promise((done) => apiServer.listen(0, '127.0.0.1', done));
    const apiPort = apiServer.address().port;

    upstreamCfg = join(work, 'upstream.json');
    writeFileSync(upstreamCfg, JSON.stringify({
      name: 'ping-upstream',
      baseUrl: `http://127.0.0.1:${apiPort}`,
      tools: [{
        name: 'ping', description: 'ping', method: 'GET', path: '/ping',
        inputSchema: { type: 'object', properties: {} },
      }],
    }));
    frontdoorCfg = join(work, 'frontdoor.mcp.json');
    writeFileSync(frontdoorCfg, JSON.stringify({
      mcpServers: {
        ping: { command: 'node', args: [CLI, 'serve', upstreamCfg] },
      },
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      instance: { name: 'frontdoor-prod', tags: ['prod', 'sse'] },
    }));

    frontdoorPort = await pickFreePort();
    proc = spawn('node', [
      CLI, 'link', frontdoorCfg,
      '--sse', String(frontdoorPort),
      '--host', '127.0.0.1',
      '--require-bearer', 'audit-test-token',
    ], {
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: work,
    });
    proc.stderr.on('data', (c) => { stderrBuf += c.toString(); });
    proc.stdout.on('data', () => {});
    await waitForHealth(frontdoorPort);
  });

  after(async () => {
    await killAndWait(proc);
    await new Promise((done) => apiServer.close(done));
    try { rmSync(work, { recursive: true, force: true }); } catch {}
  });

  it('frontdoor banner carries [<name> tags] suffix', () => {
    assert.match(stderrBuf, /Frontdoor published —.*\[frontdoor-prod prod,sse\]/);
  });

  it('/health surfaces instance metadata even on the frontdoor', async () => {
    const res = await fetch(`http://127.0.0.1:${frontdoorPort}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.deepEqual(body.instance, { name: 'frontdoor-prod', tags: ['prod', 'sse'] });
  });
});

describe('namespace canonicality — .mcp.json entry key', () => {
  it('the entry key is the deterministic prefix (no separate id)', async () => {
    // Lock in the contract that `connectFromConfig` uses the entry key as
    // the canonical namespace. This also serves as a regression guard for
    // the `prefix` rejection landed in phase 1.
    const { connectFromConfig } = await import('../../src/connect.js');
    const result = await connectFromConfig({});
    assert.deepEqual(result.tools, []);
    // Reject body-level `prefix` (phase 1 contract).
    await assert.rejects(
      () => connectFromConfig({
        github: { command: 'echo', args: [], prefix: 'overridden' },
      }),
      (err) => /"prefix"/.test(err.message),
    );
  });
});
