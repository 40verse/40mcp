#!/usr/bin/env node
/**
 * 40mcp three-tier trust topology simulator.
 *
 *   Client / Instance 3 ──[CLIENT_TOKEN]──▶ Instance 1 ──[PROXY_TOKEN + policy gate]──▶ Instance 2 ──▶ vault-sealed upstream
 *                                           (gateway)                                   (backend)        (DEEP_SECRET)
 *
 * Trust model (application layer, not network):
 *   - Instance 2 has DEEP_SECRET (sealed env var). Its dispatch uses the
 *     secret to authenticate to the real upstream API. Instance 1 never
 *     sees DEEP_SECRET.
 *   - Instance 2 requires PROXY_TOKEN on every inbound call and runs a
 *     policy gate that denies destructive tools regardless of caller.
 *   - Instance 1 holds only PROXY_TOKEN. It accepts CLIENT_TOKEN from
 *     external clients and forwards tool calls to Instance 2.
 *   - Instance 3 is an external HTTP client. It knows CLIENT_TOKEN only.
 *
 * Probes (each verifies a distinct layer of the gating):
 *   L1  Instance 3 → Instance 2 direct, no token         → 401 (auth)
 *   L2  Instance 3 → Instance 2 direct, wrong token      → 401 (auth)
 *   L3  Instance 3 → Instance 2 direct, stolen PROXY_TOKEN + non-destructive tool → passes auth (compromise confirmed)
 *   L4  Instance 3 → Instance 2 direct, stolen PROXY_TOKEN + destructive tool     → 401 via policy gate (defense-in-depth)
 *   L5  Instance 3 → Instance 1 (happy path)             → 200, result proxied
 *   L6  Instance 3 → Instance 1 → destructive tool       → blocked by Instance 2's policy gate
 *   L7  Credential isolation: Instance 1's response never contains DEEP_SECRET
 *   L8  Compromise blast radius: list what Instance 1 can reach vs what Instance 2 owns
 */

import { performance } from 'node:perf_hooks';
import { writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer as createRawHttpServer, request as httpRequest } from 'node:http';

import { createReverseBridge } from '../../src/reverse/server.js';
import { createPolicyGate } from '../../src/security/policy.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(__dirname, 'results');
const LOOPBACK = '127.0.0.1';

const CLIENT_TOKEN = 'client-public-token';   // known to Instance 3 AND Instance 1
const PROXY_TOKEN  = 'gateway-to-backend';    // known to Instance 1 ONLY
const DEEP_SECRET  = 'sk-vault-sealed-0xDEADBEEF';  // known to Instance 2 ONLY

function post({ port, path, token, body = '{}' }) {
  return new Promise((resolveFn, reject) => {
    const buf = Buffer.from(body);
    const headers = { 'Content-Type': 'application/json', 'Content-Length': buf.length };
    if (token != null) headers['x-token'] = token;
    const req = httpRequest({ host: LOOPBACK, port, path, method: 'POST', headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolveFn({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf-8') }));
    });
    req.on('error', reject);
    req.write(buf);
    req.end();
  });
}

// ─── Topology ──────────────────────────────────────────────────────────

async function startUpstream() {
  const audit = [];
  const srv = createRawHttpServer((req, res) => {
    const auth = req.headers.authorization || '';
    audit.push({ url: req.url, auth });
    res.setHeader('Content-Type', 'application/json');
    // Upstream demands the DEEP_SECRET. If it's missing, 401.
    if (!auth.includes(DEEP_SECRET)) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: 'upstream requires sealed credential' }));
      return;
    }
    if (req.url === '/customers') {
      res.end(JSON.stringify({ items: [{ id: 1, name: 'alice' }, { id: 2, name: 'bob' }] }));
      return;
    }
    if (req.url === '/delete-all') {
      res.end(JSON.stringify({ deleted: 'everything' }));
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not found' }));
  });
  srv.listen(0, LOOPBACK);
  await new Promise((r) => srv.once('listening', r));
  return { srv, port: srv.address().port, audit };
}

async function startInstance2({ upstreamPort }) {
  // Instance 2's dispatch USES DEEP_SECRET to call the upstream. It is
  // the ONLY entity in the topology that has the secret — it lives in
  // this closure and is never returned to callers.
  process.env.__INST2_TOKEN__ = PROXY_TOKEN;
  const sawSecret = { count: 0 };   // observability — any caller side-channel read would bump this
  const rawDispatch = async (name /*, args */) => {
    sawSecret.count += 1;   // every dispatch uses the secret internally
    const path = name === 'list_customers' ? '/customers' : '/delete-all';
    const r = await fetch(`http://${LOOPBACK}:${upstreamPort}${path}`, {
      headers: { authorization: `Bearer ${DEEP_SECRET}` },
    });
    if (!r.ok) throw new Error(`upstream ${r.status}`);
    return r.json();
  };
  // Policy gate: destructive tools marked deny. This is the
  // application-layer defense that holds even when a caller somehow
  // authenticates (e.g., stolen PROXY_TOKEN).
  const gatedDispatch = createPolicyGate({
    dispatch: rawDispatch,
    tools: [
      { name: 'list_customers', policy: 'allow' },
      { name: 'delete_all',     policy: 'deny'  },
    ],
  });
  const handle = createReverseBridge({
    name: 'inst-2',
    tools: [
      { name: 'list_customers', inputSchema: { type: 'object' } },
      { name: 'delete_all',     inputSchema: { type: 'object' } },
    ],
    dispatch: gatedDispatch,
    port: 0,
    host: LOOPBACK,
    auth: { envVar: '__INST2_TOKEN__', header: 'x-token' },
  });
  const { httpServer } = await handle.start();
  return {
    httpServer,
    port: httpServer.address().port,
    sawSecret,
    close: () => new Promise((r) => {
      httpServer.closeAllConnections?.();
      httpServer.close(() => { delete process.env.__INST2_TOKEN__; r(); });
    }),
  };
}

async function startInstance1({ inst2Port }) {
  process.env.__INST1_TOKEN__ = CLIENT_TOKEN;
  // Instance 1's dispatch forwards to Instance 2 using PROXY_TOKEN.
  // It NEVER sees DEEP_SECRET — it has no access to Instance 2's vault.
  const dispatch = async (name, args) => {
    const res = await post({
      port: inst2Port,
      path: `/api/tools/${name}`,
      token: PROXY_TOKEN,
      body: JSON.stringify({ args }),
    });
    if (res.status === 401) throw new Error(`backend rejected: 401`);
    if (res.status === 400) throw new Error(`backend 400: ${res.body.slice(0, 120)}`);
    if (res.status >= 500) throw new Error(`backend 5xx: ${res.status}`);
    return JSON.parse(res.body).result;
  };
  const handle = createReverseBridge({
    name: 'inst-1',
    tools: [
      { name: 'list_customers', inputSchema: { type: 'object' } },
      { name: 'delete_all',     inputSchema: { type: 'object' } },
    ],
    dispatch,
    port: 0,
    host: LOOPBACK,
    auth: { envVar: '__INST1_TOKEN__', header: 'x-token' },
  });
  const { httpServer } = await handle.start();
  return {
    httpServer,
    port: httpServer.address().port,
    close: () => new Promise((r) => {
      httpServer.closeAllConnections?.();
      httpServer.close(() => { delete process.env.__INST1_TOKEN__; r(); });
    }),
  };
}

// ─── Probes ────────────────────────────────────────────────────────────

async function run() {
  const up = await startUpstream();
  const inst2 = await startInstance2({ upstreamPort: up.port });
  const inst1 = await startInstance1({ inst2Port: inst2.port });

  console.log('');
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  40mcp three-tier trust topology — application-layer gating');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  upstream on :${up.port}  (requires Bearer DEEP_SECRET)`);
  console.log(`  Instance 2 on :${inst2.port}  (auth PROXY_TOKEN, policy gate)`);
  console.log(`  Instance 1 on :${inst1.port}  (auth CLIENT_TOKEN, proxies to Instance 2)`);
  console.log('');

  const probes = [];
  async function probe(label, expected, fn) {
    const t0 = performance.now();
    let outcome, detail;
    try {
      const got = await fn();
      outcome = got.verdict === expected ? 'PASS' : 'FAIL';
      detail = got.detail;
    } catch (err) {
      outcome = 'ERROR';
      detail = err.message;
    }
    const dt = Math.round(performance.now() - t0);
    const icon = outcome === 'PASS' ? '✓' : outcome === 'FAIL' ? '✗' : '!';
    console.log(`  ${icon} ${label.padEnd(48)} ${outcome}  ${dt}ms`);
    if (detail) console.log(`      ${detail}`);
    probes.push({ label, expected, outcome, detail, ms: dt });
  }

  // L1  Instance 3 → Instance 2 direct, no token
  await probe('L1  direct no-token       → 401', 'refused', async () => {
    const r = await post({ port: inst2.port, path: '/api/tools/list_customers', token: null });
    return { verdict: r.status === 401 ? 'refused' : `unexpected-${r.status}`, detail: `status=${r.status}` };
  });

  // L2  Instance 3 → Instance 2 direct, wrong token (CLIENT_TOKEN)
  await probe('L2  direct with CLIENT_TOKEN → 401', 'refused', async () => {
    const r = await post({ port: inst2.port, path: '/api/tools/list_customers', token: CLIENT_TOKEN });
    return { verdict: r.status === 401 ? 'refused' : `unexpected-${r.status}`, detail: `status=${r.status}` };
  });

  // L3  Instance 3 → Instance 2 direct, stolen PROXY_TOKEN, non-destructive
  //     This simulates "network controls bypassed + token leaked". Auth
  //     passes (that's the definition of token leak). The policy gate
  //     becomes the last line of defense.
  await probe('L3  direct stolen PROXY_TOKEN read tool → passes auth', 'allowed', async () => {
    const r = await post({ port: inst2.port, path: '/api/tools/list_customers', token: PROXY_TOKEN });
    return { verdict: r.status === 200 ? 'allowed' : `unexpected-${r.status}`, detail: `status=${r.status} body=${r.body.slice(0, 80)}` };
  });

  // L4  Instance 3 → Instance 2 direct, stolen PROXY_TOKEN, destructive tool
  //     The policy gate must DENY even though auth passed.
  await probe('L4  direct stolen PROXY_TOKEN destructive → policy denied', 'blocked', async () => {
    const r = await post({ port: inst2.port, path: '/api/tools/delete_all', token: PROXY_TOKEN });
    const blocked = r.status >= 400 || r.body.includes('blocked by policy');
    return { verdict: blocked ? 'blocked' : `leaked-${r.status}`, detail: `status=${r.status} body=${r.body.slice(0, 100)}` };
  });

  // L5  Happy path: Instance 3 → Instance 1 → Instance 2
  await probe('L5  via gateway with CLIENT_TOKEN  → 200', 'allowed', async () => {
    const r = await post({ port: inst1.port, path: '/api/tools/list_customers', token: CLIENT_TOKEN });
    return { verdict: r.status === 200 ? 'allowed' : `unexpected-${r.status}`, detail: `status=${r.status} body=${r.body.slice(0, 80)}` };
  });

  // L6  Instance 3 → Instance 1 → destructive tool: Instance 2's policy denies
  await probe('L6  via gateway destructive        → backend policy denies', 'blocked', async () => {
    const r = await post({ port: inst1.port, path: '/api/tools/delete_all', token: CLIENT_TOKEN });
    const blocked = r.status >= 400 || r.body.includes('blocked by policy');
    return { verdict: blocked ? 'blocked' : `leaked-${r.status}`, detail: `status=${r.status} body=${r.body.slice(0, 100)}` };
  });

  // L7  Credential isolation: Instance 1's proxied response never contains DEEP_SECRET
  await probe('L7  DEEP_SECRET not in gateway response', 'isolated', async () => {
    const r = await post({ port: inst1.port, path: '/api/tools/list_customers', token: CLIENT_TOKEN });
    const leaks = r.body.includes('DEEPBEEF') || r.body.includes('sk-vault') || r.body.includes(DEEP_SECRET);
    return { verdict: leaks ? 'leaked' : 'isolated', detail: `body=${r.body.slice(0, 120)}` };
  });

  // L8  Instance 1 compromise blast radius: what Instance 1 can reach vs what Instance 2 owns
  //     This is a DOCUMENTATION probe — it reports the attacker's capability set.
  //     An attacker who fully compromises Instance 1 gets PROXY_TOKEN + the
  //     registered tool list, and inherits whatever policy Instance 2 permits.
  //     They DO NOT get DEEP_SECRET (lives in Instance 2's closure).
  await probe('L8  compromise scope report', 'documented', async () => {
    const report = {
      inst1_owns: ['PROXY_TOKEN', 'tool list(list_customers, delete_all)'],
      inst1_cannot_reach: ['DEEP_SECRET', 'upstream /delete-all (policy-denied)'],
      attacker_capability: 'equal to Instance 1 minus the policy-denied tools',
      defense_in_depth: 'L4+L6 prove: even with full Instance 1 compromise, deny-policy tools remain unreachable',
    };
    return { verdict: 'documented', detail: JSON.stringify(report) };
  });

  await inst1.close();
  await inst2.close();
  up.srv.close();

  const pass = probes.filter((p) => p.outcome === 'PASS').length;
  const fail = probes.filter((p) => p.outcome === 'FAIL').length;
  const err  = probes.filter((p) => p.outcome === 'ERROR').length;
  console.log('');
  console.log(`  ── ${pass} PASS · ${fail} FAIL · ${err} ERROR`);
  console.log('══════════════════════════════════════════════════════════════');

  await mkdir(OUT_DIR, { recursive: true });
  const summary = { run_at: new Date().toISOString(), probes, totals: { pass, fail, err } };
  await writeFile(resolve(OUT_DIR, 'three-tier-latest.json'), JSON.stringify(summary, null, 2));
  await writeFile(resolve(OUT_DIR, 'three-tier-latest.md'), renderMd(summary));
  console.log(`  results/three-tier-latest.{json,md}`);
}

function renderMd(s) {
  const lines = [
    '# 40mcp three-tier trust topology',
    '',
    `- **Run at:** ${s.run_at}`,
    `- **Totals:** ${s.totals.pass} PASS · ${s.totals.fail} FAIL · ${s.totals.err} ERROR`,
    '',
    '## Topology',
    '',
    '```',
    'Client / Instance 3 ──[CLIENT_TOKEN]──▶ Instance 1 ──[PROXY_TOKEN]──▶ Instance 2 ──▶ upstream',
    '                                        (gateway)                    (backend + vault)',
    '```',
    '',
    '## Probes',
    '',
    '| ID | Label | Expected | Outcome | Detail |',
    '|----|-------|----------|---------|--------|',
  ];
  for (const p of s.probes) {
    const icon = p.outcome === 'PASS' ? '✓' : p.outcome === 'FAIL' ? '✗' : '!';
    const detail = (p.detail || '').replace(/\|/g, '\\|').slice(0, 160);
    lines.push(`| ${p.label.split(' ')[0]} | ${p.label.slice(4)} | ${p.expected} | ${icon} ${p.outcome} | \`${detail}\` |`);
  }
  return lines.join('\n');
}

run().catch((err) => { console.error('three-tier-sim crashed:', err); process.exit(1); });
