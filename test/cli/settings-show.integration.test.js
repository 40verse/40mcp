/**
 * Integration tests for `40mcp settings show` and `40mcp doctor` drift.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, '../../src/cli.js');

function runCli(args, { env = {}, cwd } = {}) {
  return new Promise((done) => {
    const proc = spawn('node', [CLI, ...args], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd,
    });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (c) => { stdout += c.toString(); });
    proc.stderr.on('data', (c) => { stderr += c.toString(); });
    proc.on('exit', (code) => done({ code, stdout, stderr }));
  });
}

describe('settings show — text output', () => {
  let work;

  before(() => { work = mkdtempSync(join(tmpdir(), 'settings-show-')); });
  after(() => { try { rmSync(work, { recursive: true, force: true }); } catch {} });

  it('prints default tree with no settings file', async () => {
    const res = await runCli(['settings', 'show'], { cwd: work, env: { MAX_SSE_CONNECTIONS: '' } });
    assert.equal(res.code, 0);
    assert.match(res.stdout, /\[bridge\]/);
    assert.match(res.stdout, /\[frontdoor\]/);
    assert.match(res.stdout, /\[instance\]/);
    assert.match(res.stdout, /bridge\.transport\.type\s+=\s+"stdio"\s+← default/);
    assert.match(res.stderr, /No 40mcp\.settings\.json found/);
  });

  it('annotates settings.json-sourced leaves', async () => {
    const path = join(work, '40mcp.settings.json');
    writeFileSync(path, JSON.stringify({
      instance: { name: 'Demo' },
      bridge: { transport: { type: 'sse', port: 9999 } },
    }));
    const res = await runCli(['settings', 'show'], { cwd: work, env: { MAX_SSE_CONNECTIONS: '' } });
    assert.equal(res.code, 0);
    assert.match(res.stdout, new RegExp(`bridge\\.transport\\.port\\s+=\\s+9999\\s+← settings\\.json:${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.match(res.stdout, /instance\.name\s+=\s+"Demo"/);
  });

  it('env overlay wins over settings.json', async () => {
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      frontdoor: { limits: { sse: { maxConnections: 200 } } },
    }));
    const res = await runCli(['settings', 'show'], { cwd: work, env: { MAX_SSE_CONNECTIONS: '500' } });
    assert.match(res.stdout, /frontdoor\.limits\.sse\.maxConnections\s+=\s+500\s+← env:MAX_SSE_CONNECTIONS/);
  });

  it('--json emits machine-readable rows', async () => {
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      instance: { name: 'Demo' },
    }));
    const res = await runCli(['settings', 'show', '--json'], { cwd: work, env: { MAX_SSE_CONNECTIONS: '' } });
    assert.equal(res.code, 0);
    const parsed = JSON.parse(res.stdout);
    assert.ok(Array.isArray(parsed.rows));
    assert.ok(parsed.source.endsWith('40mcp.settings.json'));
    const name = parsed.rows.find((r) => r.path === 'instance.name');
    assert.equal(name.value, 'Demo');
  });

  it('--show alternate invocation works too', async () => {
    const res = await runCli(['settings', '--show'], { cwd: work, env: { MAX_SSE_CONNECTIONS: '' } });
    assert.equal(res.code, 0);
    assert.match(res.stdout, /\[bridge\]/);
  });

  it('redacts secret env values', async () => {
    const res = await runCli(['settings', 'show', '--json'], {
      cwd: work,
      env: { VAULT_DAEMON_SECRET: 'hunter2', MAX_SSE_CONNECTIONS: '' },
    });
    const parsed = JSON.parse(res.stdout);
    const secret = parsed.rows.find((r) => r.path === 'bridge.vault.daemonSecret');
    assert.equal(secret.value, '<set>');
    assert.equal(secret.source, 'env:VAULT_DAEMON_SECRET');
  });
});

describe('doctor — settings drift warnings', () => {
  let work;

  before(() => { work = mkdtempSync(join(tmpdir(), 'doctor-drift-')); });
  after(() => { try { rmSync(work, { recursive: true, force: true }); } catch {} });

  it('warns when SSE frontdoor on non-loopback host has no auth', async () => {
    const configPath = join(work, 'config.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'x', baseUrl: 'http://127.0.0.1:1',
      tools: [{ name: 'noop', description: 'n', method: 'GET', path: '/n', inputSchema: { type: 'object', properties: {} } }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      frontdoor: { transport: { type: 'sse', host: '0.0.0.0', port: 8080 } },
    }));
    const res = await runCli(['doctor', configPath], { cwd: work, env: { MAX_SSE_CONNECTIONS: '' } });
    assert.match(res.stderr, /will refuse to publish at runtime/);
  });

  it('warns when env shadows a settings knob', async () => {
    const configPath = join(work, 'config2.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'x', baseUrl: 'http://127.0.0.1:1',
      tools: [{ name: 'noop', description: 'n', method: 'GET', path: '/n', inputSchema: { type: 'object', properties: {} } }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      frontdoor: { limits: { sse: { maxConnections: 200 } } },
    }));
    const res = await runCli(['doctor', configPath], { cwd: work, env: { MAX_SSE_CONNECTIONS: '500' } });
    assert.match(res.stderr, /MAX_SSE_CONNECTIONS=500 in env will override/);
  });

  it('warns when tenantMap set without bearerFile', async () => {
    const configPath = join(work, 'config3.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'x', baseUrl: 'http://127.0.0.1:1',
      tools: [{ name: 'noop', description: 'n', method: 'GET', path: '/n', inputSchema: { type: 'object', properties: {} } }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      frontdoor: {
        transport: { type: 'sse', host: '127.0.0.1', port: 8080 },
        tenantMap: { path: './tenants.json' },
      },
    }));
    const res = await runCli(['doctor', configPath], { cwd: work });
    assert.match(res.stderr, /tenantMap\.path is set but frontdoor\.auth\.bearerFile is not/);
  });

  it('warns when vault daemon requested without secret', async () => {
    const configPath = join(work, 'config4.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'x', baseUrl: 'http://127.0.0.1:1',
      tools: [{ name: 'noop', description: 'n', method: 'GET', path: '/n', inputSchema: { type: 'object', properties: {} } }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      bridge: { vault: { daemon: true } },
    }));
    const res = await runCli(['doctor', configPath], {
      cwd: work,
      env: { VAULT_DAEMON_SECRET: '' },
    });
    assert.match(res.stderr, /vault\.daemon=true but VAULT_DAEMON_SECRET env var is unset/);
  });

  it('warns when bridge SSE binds a non-loopback host (no inbound auth)', async () => {
    const configPath = join(work, 'config-bridge-sse.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'x', baseUrl: 'http://127.0.0.1:1',
      tools: [{ name: 'noop', description: 'n', method: 'GET', path: '/n', inputSchema: { type: 'object', properties: {} } }],
    }));
    writeFileSync(join(work, '40mcp.settings.json'), JSON.stringify({
      bridge: { transport: { type: 'sse', host: '0.0.0.0', port: 9090 } },
    }));
    const res = await runCli(['doctor', configPath], { cwd: work });
    assert.match(res.stderr, /bridge\.transport binds 0\.0\.0\.0:9090 \(non-loopback\)/);
    assert.match(res.stderr, /no inbound auth/);
  });

  it('warns when reverse bridge binds non-loopback without auth.envVar', async () => {
    const configPath = join(work, 'config-reverse.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'x', baseUrl: 'http://127.0.0.1:1',
      tools: [{ name: 'noop', description: 'n', method: 'GET', path: '/n', inputSchema: { type: 'object', properties: {} } }],
      reverse: { host: '0.0.0.0', port: 8080 },
    }));
    const res = await runCli(['doctor', configPath], { cwd: work });
    assert.match(res.stderr, /reverse bridge binds 0\.0\.0\.0:8080/);
    assert.match(res.stderr, /reverse\.auth\.envVar is unset/);
  });

  it('warns when vault.path resolves outside the default allowlist', async () => {
    const configPath = join(work, 'config-vault.json');
    writeFileSync(configPath, JSON.stringify({
      name: 'x', baseUrl: 'http://127.0.0.1:1',
      tools: [{ name: 'noop', description: 'n', method: 'GET', path: '/n', inputSchema: { type: 'object', properties: {} } }],
      vault: { path: '/etc/40mcp/vault.json' },
    }));
    const res = await runCli(['doctor', configPath], { cwd: work });
    assert.match(res.stderr, /vault\.path .* outside the default allowlist/);
    assert.match(res.stderr, /not group-readable/);
  });
});
