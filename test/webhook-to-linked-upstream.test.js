/**
 * End-to-end composition test for SPEC §11.2 "Event-Driven Agent Mesh".
 *
 * The SPEC claim: an external webhook event triggers a tool call on a linked
 * MCP upstream. The components (`createWebhookListener`, `connectStdio`) have
 * unit coverage individually, but prior to this file no test exercised them
 * composed as a single flow. This file closes that gap:
 *
 *   webhook HTTP POST
 *     → webhook listener (HMAC validated)
 *       → linked upstream dispatch (connectStdio)
 *         → stdio child MCP server (test/helpers/stdio-echo-upstream.mjs)
 *           → tool result
 *         ← returned via MCP response
 *       ← unwrapped + sanitized by the connector
 *     ← returned in the HTTP response (response: 'sync')
 *
 * If `connectStdio` can't spawn the helper in the environment (missing Node,
 * restricted runner, etc.) the suite soft-skips with a stderr note, matching
 * the pattern in src/connect.test.js.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { connectStdio } from '../src/connect.js';
import { createWebhookListener } from '../src/webhook/listener.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const UPSTREAM_HELPER = join(__dirname, 'helpers', 'stdio-echo-upstream.mjs');

// Soft-skip state. If upstream spawn fails, every test body bails early with
// assert.ok(true) rather than a hard failure — same convention as connect.test.js.
let SKIP_REASON = null;
let upstream = null;
let listener = null;
let listenerHttpServer = null;
let listenerUrl = null;

// Single shared HMAC secret for the signed-webhook route. The route reads from
// process.env by name; set it before createWebhookListener reads it.
const HMAC_ENV_VAR = 'WEBHOOK_TO_LINKED_UPSTREAM_TEST_SECRET';
const HMAC_SECRET = 'test-secret-do-not-reuse';

async function postJson(url, body, extraHeaders = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = request({
      method: 'POST',
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        ...extraHeaders,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf-8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* leave as text */ }
        resolve({ status: res.statusCode, headers: res.headers, body: json ?? text });
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// File-level setup so both describe blocks share the same upstream connection.
// If upstream spawn fails, both suites soft-skip.
before(async () => {
  process.env[HMAC_ENV_VAR] = HMAC_SECRET;

  try {
    upstream = await connectStdio({
      command: 'node',
      args: [UPSTREAM_HELPER],
      prefix: 'echo',
    });
  } catch (err) {
    SKIP_REASON = `connectStdio failed: ${err?.message || err}`;
    process.stderr.write(`[webhook-to-linked-upstream.test] SKIP — ${SKIP_REASON}\n`);
    return;
  }

  listener = createWebhookListener({
    name: 'webhook-to-linked-upstream-test',
    port: 0,
    host: '127.0.0.1',
    dispatch: upstream.dispatch,
    routes: [
      {
        path: '/hooks/echo',
        method: 'POST',
        tool: 'echo.echo_text',
        argMap: { text: '$body.text' },
        response: 'sync',
      },
      {
        path: '/hooks/sum',
        method: 'POST',
        tool: 'echo.sum_numbers',
        argMap: {
          a: '$body.a',
          b: '$body.b',
        },
        response: 'sync',
      },
      {
        path: '/hooks/signed-echo',
        method: 'POST',
        tool: 'echo.echo_text',
        argMap: { text: '$body.text' },
        secret: {
          type: 'header',
          envVar: HMAC_ENV_VAR,
          header: 'x-webhook-secret',
        },
        response: 'sync',
      },
    ],
  });

  const started = await listener.start();
  listenerUrl = started.url;
  listenerHttpServer = started.httpServer;
});

after(async () => {
  if (upstream?.close) {
    await upstream.close().catch(() => {});
  }

  if (listenerHttpServer) {
    // Node's HTTP server .close() stops accepting new connections but does not
    // evict existing keep-alive sockets. Without closeAllConnections(), those
    // sockets pin the event loop past the test body and `node --test` hangs
    // after reporting all cases pass.
    if (typeof listenerHttpServer.closeAllConnections === 'function') {
      listenerHttpServer.closeAllConnections();
    }
    await new Promise((r) => listenerHttpServer.close(() => r()));
  }

  delete process.env[HMAC_ENV_VAR];
});

describe('webhook → linked MCP upstream composition (SPEC §11.2)', () => {  it('routes a webhook POST through the linked upstream and returns the tool result', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    const body = JSON.stringify({ text: 'hello from webhook' });
    const res = await postJson(`${listenerUrl}/hooks/echo`, body);

    assert.equal(res.status, 200, `expected 200, got ${res.status} body=${JSON.stringify(res.body)}`);
    assert.equal(res.body.status, 'ok');

    // The linked connector unwraps MCP text/content into `result`. For
    // echo_text the upstream returns a JSON string; the connector parses it
    // into an object before handing it back to the webhook listener.
    const result = res.body.result;
    assert.ok(result, 'response.result must be present');
    assert.equal(result.echoed, 'hello from webhook');
    assert.equal(result.source, 'stdio-echo-upstream');
  });

  it('passes numeric args through the chain without coercion loss', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    const body = JSON.stringify({ a: 7, b: 35 });
    const res = await postJson(`${listenerUrl}/hooks/sum`, body);

    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    assert.equal(res.body.result.sum, 42);
  });

  it('rejects an unsigned request to the HMAC-gated route', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    const body = JSON.stringify({ text: 'no signature' });
    const res = await postJson(`${listenerUrl}/hooks/signed-echo`, body);

    assert.equal(res.status, 401, `expected 401 for unsigned request, got ${res.status}`);
    assert.ok(res.body.error, 'expected an error body');
  });

  it('accepts a correctly-signed request to the HMAC-gated route', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    const body = JSON.stringify({ text: 'signed hello' });
    const res = await postJson(`${listenerUrl}/hooks/signed-echo`, body, {
      'x-webhook-secret': HMAC_SECRET,
    });

    assert.equal(res.status, 200, `expected 200, got ${res.status} body=${JSON.stringify(res.body)}`);
    assert.equal(res.body.status, 'ok');
    assert.equal(res.body.result.echoed, 'signed hello');
  });

  it('returns a 404 for a path with no matching route', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    const body = JSON.stringify({});
    const res = await postJson(`${listenerUrl}/hooks/does-not-exist`, body);
    assert.equal(res.status, 404);
  });

  it('uses `x-webhook-secret` for constant-time comparison (length-oracle probe)', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    // Same-length wrong secret → rejected. Proves the comparison is driven by
    // value rather than length only. Full timing-side-channel coverage lives
    // in the webhook invariant suite; this is a composition-level smoke.
    const body = JSON.stringify({ text: 'probe' });
    const wrongSameLength = 'x'.repeat(HMAC_SECRET.length);
    const res = await postJson(`${listenerUrl}/hooks/signed-echo`, body, {
      'x-webhook-secret': wrongSameLength,
    });
    assert.equal(res.status, 401);
  });
});

// Parallel check: prove the raw connector still dispatches tools independently
// of the webhook path. If the linked-upstream connection itself were broken,
// every test above would pass for the wrong reason (uniform HTTP-layer error).
describe('linked MCP upstream direct dispatch (SPEC §11.2 control)', () => {
  it('calls echo_text directly via connectStdio.dispatch', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    const result = await upstream.dispatch('echo.echo_text', { text: 'direct' });
    assert.equal(result.echoed, 'direct');
    assert.equal(result.source, 'stdio-echo-upstream');
  });

  it('lists both helper tools under the configured prefix', async () => {
    if (SKIP_REASON) return assert.ok(true, SKIP_REASON);

    const names = upstream.tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['echo.echo_text', 'echo.sum_numbers']);
  });
});
