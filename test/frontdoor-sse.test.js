/**
 * Published frontdoor MCP.
 *
 * Spawns `40mcp link .mcp.json --sse <port> --require-bearer-env FRONTDOOR_TOKEN`
 * against a stdio upstream and verifies the inbound bearer gate holds.
 *
 * The upstream is a disposable REST-bridge config served via `40mcp serve`,
 * spawned as a child process by `link` (stdio). The published frontdoor is
 * bound to 127.0.0.1 on a random port.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

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

describe('frontdoor: link --sse --require-bearer-env', () => {
  let apiServer;
  let upstreamCfg;
  let frontdoorCfg;
  let frontdoorProc;
  let frontdoorPort;

  before(async () => {
    // Upstream REST API the stdio bridge will front.
    apiServer = createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/ping') {
        res.end(JSON.stringify({ pong: true }));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });
    await new Promise((done) => apiServer.listen(0, '127.0.0.1', done));
    const apiPort = apiServer.address().port;

    // 40mcp REST-bridge config — acts as the private upstream MCP server.
    upstreamCfg = resolve(__dirname, '_frontdoor-upstream.json');
    await writeFile(upstreamCfg, JSON.stringify({
      name: 'ping-upstream',
      baseUrl: `http://127.0.0.1:${apiPort}`,
      tools: [
        {
          name: 'ping',
          description: 'Ping the upstream API.',
          method: 'GET',
          path: '/ping',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    }));

    const cliPath = resolve(__dirname, '../src/cli.js');
    // .mcp.json that points `link` at the upstream as a stdio child process.
    frontdoorCfg = resolve(__dirname, '_frontdoor-servers.mcp.json');
    await writeFile(frontdoorCfg, JSON.stringify({
      mcpServers: {
        ping: {
          command: 'node',
          args: [cliPath, 'serve', upstreamCfg],
        },
      },
    }));

    frontdoorPort = await pickFreePort();
    frontdoorProc = spawn('node', [
      cliPath,
      'link', frontdoorCfg,
      '--sse', String(frontdoorPort),
      '--host', '127.0.0.1',
      '--require-bearer-env', 'TEST_FRONTDOOR_TOKEN',
    ], {
      env: { ...process.env, TEST_FRONTDOOR_TOKEN: 'frontdoor-secret' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    // Surface child output on test failure — silent by default.
    frontdoorProc.stdout.on('data', () => {});
    frontdoorProc.stderr.on('data', () => {});

    await waitForPort(frontdoorPort);
  });

  after(async () => {
    if (frontdoorProc && !frontdoorProc.killed) {
      frontdoorProc.kill('SIGTERM');
      await new Promise((done) => {
        if (frontdoorProc.exitCode !== null) return done();
        frontdoorProc.once('exit', done);
        setTimeout(() => { try { frontdoorProc.kill('SIGKILL'); } catch { /* ignore */ } done(); }, 3000).unref();
      });
    }
    await new Promise((done) => apiServer.close(done));
    await rm(upstreamCfg, { force: true });
    await rm(frontdoorCfg, { force: true });
  });

  it('/health is reachable without auth', async () => {
    const res = await fetch(`http://127.0.0.1:${frontdoorPort}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'ok');
  });

  it('GET /sse without bearer returns 401', async () => {
    const res = await fetch(`http://127.0.0.1:${frontdoorPort}/sse`);
    await res.text().catch(() => {});
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('www-authenticate'), 'Bearer');
  });

  it('GET /sse with wrong bearer returns 401', async () => {
    const res = await fetch(`http://127.0.0.1:${frontdoorPort}/sse`, {
      headers: { Authorization: 'Bearer wrong-token' },
    });
    await res.text().catch(() => {});
    assert.equal(res.status, 401);
  });

  it('POST /message without bearer returns 401', async () => {
    const res = await fetch(`http://127.0.0.1:${frontdoorPort}/message?sessionId=x`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    await res.text().catch(() => {});
    assert.equal(res.status, 401);
  });

  it('GET /sse with correct bearer is accepted (no 401)', async () => {
    const controller = new AbortController();
    const res = await fetch(`http://127.0.0.1:${frontdoorPort}/sse?sessionId=ok1`, {
      headers: { Authorization: 'Bearer frontdoor-secret' },
      signal: controller.signal,
    });
    try {
      assert.notEqual(res.status, 401);
    } finally {
      controller.abort();
      try { await res.body?.cancel(); } catch { /* ignore */ }
    }
  });
});

// ─── Tool filter + /health detail + audit events ──────────────────────────────

describe('frontdoor: --allow-tool / --deny-tool / --health-detail', () => {
  let apiServer;
  let apiPort;
  let upstreamCfg;
  let frontdoorCfg;

  before(async () => {
    apiServer = createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/ping') { res.end(JSON.stringify({ pong: true })); return; }
      if (req.url === '/echo') { res.end(JSON.stringify({ echo: true })); return; }
      res.writeHead(404); res.end('{}');
    });
    await new Promise((done) => apiServer.listen(0, '127.0.0.1', done));
    apiPort = apiServer.address().port;

    upstreamCfg = resolve(__dirname, '_frontdoor-filter-upstream.json');
    await writeFile(upstreamCfg, JSON.stringify({
      name: 'multi-upstream',
      baseUrl: `http://127.0.0.1:${apiPort}`,
      tools: [
        { name: 'ping', description: 'ping', method: 'GET', path: '/ping',
          inputSchema: { type: 'object', properties: {} } },
        { name: 'echo', description: 'echo', method: 'GET', path: '/echo',
          inputSchema: { type: 'object', properties: {} } },
      ],
    }));

    const cliPath = resolve(__dirname, '../src/cli.js');
    frontdoorCfg = resolve(__dirname, '_frontdoor-filter-servers.mcp.json');
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

  function runLinkInspect(extraArgs) {
    const cliPath = resolve(__dirname, '../src/cli.js');
    return new Promise((done, fail) => {
      const proc = spawn('node', [
        cliPath, 'link', frontdoorCfg, '--inspect', ...extraArgs,
      ], { stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (b) => { stdout += b.toString(); });
      proc.stderr.on('data', (b) => { stderr += b.toString(); });
      proc.on('exit', (code) => {
        if (code !== 0) return fail(new Error(`link --inspect exited ${code}: ${stderr}`));
        try { done({ stdout: JSON.parse(stdout), stderr }); }
        catch (e) { fail(e); }
      });
      proc.on('error', fail);
    });
  }

  it('--allow-tool filters the inspected tool list', async () => {
    const { stdout } = await runLinkInspect(['--allow-tool', 'upstream.ping']);
    const names = stdout.tools.map((t) => t.name);
    assert.deepEqual(names, ['upstream.ping']);
  });

  it('--deny-tool removes matching tools from the inspected list', async () => {
    const { stdout } = await runLinkInspect(['--deny-tool', 'upstream.echo']);
    const names = stdout.tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['upstream.ping']);
  });

  it('--deny-tool wins when both flags match the same tool', async () => {
    const { stdout } = await runLinkInspect([
      '--allow-tool', 'upstream.*',
      '--deny-tool', 'upstream.echo',
    ]);
    const names = stdout.tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['upstream.ping']);
  });

  it('glob patterns match against the prefixed tool name', async () => {
    const { stdout } = await runLinkInspect(['--allow-tool', 'upstream.p*']);
    const names = stdout.tools.map((t) => t.name);
    assert.deepEqual(names, ['upstream.ping']);
  });

  it('--health-detail surfaces per-upstream status on /health', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--require-bearer-env', 'TEST_HEALTH_TOKEN',
      '--health-detail',
    ], {
      env: { ...process.env, TEST_HEALTH_TOKEN: 'tok' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', () => {});

    try {
      await waitForPort(port);
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      const body = await res.json();
      assert.equal(res.status, 200);
      assert.equal(body.status, 'ok');
      assert.ok(Array.isArray(body.upstreams), 'expected upstreams[]');
      assert.equal(body.upstreams.length, 1);
      assert.equal(body.upstreams[0].status, 'ok');
      assert.ok(body.upstreams[0].source.includes('stdio:'), 'source should be the stdio: entry');
    } finally {
      proc.kill('SIGTERM');
      await new Promise((done) => {
        if (proc.exitCode !== null) return done();
        proc.once('exit', done);
        setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* ignore */ } done(); }, 3000).unref();
      });
    }
  });

  it('--bearer-file accepts multiple tokens and tags sse.auth_ok with principal', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-bearer-file.json');
    await writeFile(bearerFile, JSON.stringify({
      alice: 'token-alice-abcdef',
      bob: 'token-bob-ghijkl',
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    try {
      await waitForPort(port);

      // Alice's token is accepted.
      const aliceCtl = new AbortController();
      const aliceRes = await fetch(`http://127.0.0.1:${port}/sse?sessionId=alice-s`, {
        headers: { Authorization: 'Bearer token-alice-abcdef' },
        signal: aliceCtl.signal,
      });
      try { assert.notEqual(aliceRes.status, 401, 'alice token must not 401'); }
      finally { aliceCtl.abort(); try { await aliceRes.body?.cancel(); } catch { /* ignore */ } }

      // Bob's token is accepted.
      const bobCtl = new AbortController();
      const bobRes = await fetch(`http://127.0.0.1:${port}/sse?sessionId=bob-s`, {
        headers: { Authorization: 'Bearer token-bob-ghijkl' },
        signal: bobCtl.signal,
      });
      try { assert.notEqual(bobRes.status, 401, 'bob token must not 401'); }
      finally { bobCtl.abort(); try { await bobRes.body?.cancel(); } catch { /* ignore */ } }

      // Any other token is rejected.
      const bad = await fetch(`http://127.0.0.1:${port}/sse`, {
        headers: { Authorization: 'Bearer not-a-real-token' },
      });
      await bad.text().catch(() => {});
      assert.equal(bad.status, 401);

      await new Promise((done) => setTimeout(done, 100));
      // Both principals should have produced an sse.auth_ok line.
      assert.ok(/sse\.auth_ok.*"principal":"alice"/.test(stderr),
        `expected sse.auth_ok for alice, got:\n${stderr}`);
      assert.ok(/sse\.auth_ok.*"principal":"bob"/.test(stderr),
        `expected sse.auth_ok for bob, got:\n${stderr}`);
      assert.ok(/sse\.auth_failed/.test(stderr), 'expected one sse.auth_failed');
    } finally {
      proc.kill('SIGTERM');
      await new Promise((done) => {
        if (proc.exitCode !== null) return done();
        proc.once('exit', done);
        setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* ignore */ } done(); }, 3000).unref();
      });
      await rm(bearerFile, { force: true });
    }
  });

  it('--bearer-file rejects an empty JSON object', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-bearer-empty.json');
    await writeFile(bearerFile, '{}');

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    try {
      const code = await new Promise((done) => proc.once('exit', done));
      assert.notEqual(code, 0, 'expected non-zero exit');
      assert.ok(/empty/i.test(stderr), `expected "empty" in stderr, got:\n${stderr}`);
    } finally {
      if (proc.exitCode === null) proc.kill('SIGKILL');
      await rm(bearerFile, { force: true });
    }
  });

  it('--bearer-file rejects duplicate tokens across principals', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-bearer-dup.json');
    await writeFile(bearerFile, JSON.stringify({
      alice: 'same-token',
      bob: 'same-token',
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    try {
      const code = await new Promise((done) => proc.once('exit', done));
      assert.notEqual(code, 0, 'expected non-zero exit on duplicate tokens');
      assert.ok(/share the same token/i.test(stderr),
        `expected duplicate-token error in stderr, got:\n${stderr}`);
    } finally {
      if (proc.exitCode === null) proc.kill('SIGKILL');
      await rm(bearerFile, { force: true });
    }
  });

  it('--max-sessions-per-principal caps concurrent sessions per token', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-bearer-cap.json');
    await writeFile(bearerFile, JSON.stringify({
      alice: 'cap-token-alice',
      bob: 'cap-token-bob',
    }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
      '--max-sessions-per-principal', '1',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    const ctls = [];
    try {
      await waitForPort(port);

      // First alice session — accepted.
      const c1 = new AbortController(); ctls.push(c1);
      const r1 = await fetch(`http://127.0.0.1:${port}/sse?sessionId=alice-cap-1`, {
        headers: { Authorization: 'Bearer cap-token-alice' },
        signal: c1.signal,
      });
      assert.notEqual(r1.status, 429);

      // Second alice session — over the cap, 429.
      const c2 = new AbortController(); ctls.push(c2);
      const r2 = await fetch(`http://127.0.0.1:${port}/sse?sessionId=alice-cap-2`, {
        headers: { Authorization: 'Bearer cap-token-alice' },
        signal: c2.signal,
      });
      try {
        await r2.text().catch(() => {});
        assert.equal(r2.status, 429, 'second alice session should hit per-principal cap');
      } finally {
        try { await r2.body?.cancel(); } catch { /* ignore */ }
      }

      // Bob is independent — accepted.
      const c3 = new AbortController(); ctls.push(c3);
      const r3 = await fetch(`http://127.0.0.1:${port}/sse?sessionId=bob-cap-1`, {
        headers: { Authorization: 'Bearer cap-token-bob' },
        signal: c3.signal,
      });
      assert.notEqual(r3.status, 429, 'bob should not be capped by alice');

      await new Promise((done) => setTimeout(done, 100));
      // Stderr should show one rate_limit_hit tagged with principal=alice.
      assert.ok(/sse\.rate_limit_hit.*"reason":"per_principal_cap".*"principal":"alice"/.test(stderr),
        `expected per_principal_cap event for alice, got:\n${stderr}`);
    } finally {
      for (const c of ctls) c.abort();
      proc.kill('SIGTERM');
      await new Promise((done) => {
        if (proc.exitCode !== null) return done();
        proc.once('exit', done);
        setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* ignore */ } done(); }, 3000).unref();
      });
      await rm(bearerFile, { force: true });
    }
  });

  it('--max-sessions-per-principal rejects non-positive integers', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-bearer-badcap.json');
    await writeFile(bearerFile, JSON.stringify({ alice: 'tok' }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
      '--max-sessions-per-principal', '0',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    try {
      const code = await new Promise((done) => proc.once('exit', done));
      assert.notEqual(code, 0, 'expected non-zero exit on invalid cap');
      assert.ok(/positive integer/i.test(stderr), `expected validation error, got:\n${stderr}`);
    } finally {
      if (proc.exitCode === null) proc.kill('SIGKILL');
      await rm(bearerFile, { force: true });
    }
  });

  it('--bearer-file conflicts with --require-bearer-env and fails fast', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const bearerFile = resolve(__dirname, '_frontdoor-bearer-conflict.json');
    await writeFile(bearerFile, JSON.stringify({ alice: 'tok' }));

    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--bearer-file', bearerFile,
      '--require-bearer-env', 'UNUSED_ENV',
    ], {
      env: { ...process.env, UNUSED_ENV: 'x' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    try {
      const code = await new Promise((done) => proc.once('exit', done));
      assert.notEqual(code, 0, 'expected non-zero exit when both auth sources set');
      assert.ok(/Only one of/i.test(stderr), `expected conflict error, got:\n${stderr}`);
    } finally {
      if (proc.exitCode === null) proc.kill('SIGKILL');
      await rm(bearerFile, { force: true });
    }
  });

  it('sse.auth_ok / sse.auth_failed events appear on stderr', async () => {
    const cliPath = resolve(__dirname, '../src/cli.js');
    const port = await pickFreePort();
    const proc = spawn('node', [
      cliPath, 'link', frontdoorCfg,
      '--sse', String(port),
      '--host', '127.0.0.1',
      '--require-bearer-env', 'TEST_AUDIT_TOKEN',
    ], {
      env: { ...process.env, TEST_AUDIT_TOKEN: 'audit-tok' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (b) => { stderr += b.toString(); });

    try {
      await waitForPort(port);

      // One failed and one accepted GET /sse — both should produce events.
      await fetch(`http://127.0.0.1:${port}/sse`).then((r) => r.text().catch(() => {}));

      const controller = new AbortController();
      const ok = await fetch(`http://127.0.0.1:${port}/sse?sessionId=auditok`, {
        headers: { Authorization: 'Bearer audit-tok' },
        signal: controller.signal,
      });
      try {
        assert.notEqual(ok.status, 401);
      } finally {
        controller.abort();
        try { await ok.body?.cancel(); } catch { /* ignore */ }
      }

      // Give stderr a tick to flush.
      await new Promise((done) => setTimeout(done, 100));
      assert.ok(/\[40mcp:event\].*sse\.auth_failed/.test(stderr), `expected sse.auth_failed in stderr, got:\n${stderr}`);
      assert.ok(/\[40mcp:event\].*sse\.auth_ok/.test(stderr), `expected sse.auth_ok in stderr, got:\n${stderr}`);
    } finally {
      proc.kill('SIGTERM');
      await new Promise((done) => {
        if (proc.exitCode !== null) return done();
        proc.once('exit', done);
        setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* ignore */ } done(); }, 3000).unref();
      });
    }
  });
});
