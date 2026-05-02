import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createWebhookListener, parseWebhookTimestamp } from './listener.js';

// ─── parseWebhookTimestamp regression tests (CVE: replay window bypass) ─────

describe('parseWebhookTimestamp (strict-integer parsing)', () => {
  it('accepts plain unix seconds (10 digits) and converts to ms', () => {
    assert.equal(parseWebhookTimestamp('1700000000'), 1_700_000_000_000);
  });

  it('accepts plain unix milliseconds (13 digits)', () => {
    assert.equal(parseWebhookTimestamp('1700000000000'), 1_700_000_000_000);
  });

  it('REJECTS scientific notation that previously bypassed the replay window', () => {
    // The previous heuristic Number("1e10") = 1e10 was treated as ms (length != 10)
    // and yielded a far-future timestamp inside the replay window.
    assert.equal(parseWebhookTimestamp('1e10'), null);
    assert.equal(parseWebhookTimestamp('1.7e12'), null);
    assert.equal(parseWebhookTimestamp('Infinity'), null);
  });

  it('REJECTS decimals, signs, hex and other Number()-coercible forms', () => {
    assert.equal(parseWebhookTimestamp('1700000000.5'), null);
    assert.equal(parseWebhookTimestamp('-1700000000'), null);
    assert.equal(parseWebhookTimestamp('+1700000000'), null);
    assert.equal(parseWebhookTimestamp('0x1'), null);
    assert.equal(parseWebhookTimestamp(' 1700000000'), null);
    assert.equal(parseWebhookTimestamp('1700000000 '), null);
  });

  it('REJECTS oversized digit strings (overflow attempts)', () => {
    assert.equal(parseWebhookTimestamp('99999999999999'), null); // 14 digits
    assert.equal(parseWebhookTimestamp('1'.repeat(20)), null);
  });

  it('REJECTS non-string input', () => {
    assert.equal(parseWebhookTimestamp(1700000000), null);
    assert.equal(parseWebhookTimestamp(null), null);
    assert.equal(parseWebhookTimestamp(undefined), null);
  });
});

// ─── Test helpers ───────────────────────────────────────────────────────────

function createMockDispatch() {
  const responses = new Map();
  const fn = mock.fn(async (toolName, _args) => {
    const response = responses.get(toolName);
    if (!response) return { ok: true };
    if (response._throw) throw new Error(response.message);
    return response;
  });
  fn.setResponse = (name, resp) => responses.set(name, resp);
  fn.setThrow = (name, msg) => responses.set(name, { _throw: true, message: msg });
  return fn;
}

async function sendRequest(url, path, options = {}) {
  const { method = 'POST', body, headers = {} } = options;
  const init = { method, headers: { 'Content-Type': 'application/json', ...headers } };
  if (body) init.body = JSON.stringify(body);
  return fetch(`${url}${path}`, init);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('createWebhookListener', () => {
  it('throws if dispatch is missing', () => {
    assert.throws(
      () => createWebhookListener({ routes: [{ path: '/hook', tool: 'test' }] }),
      (err) => err.message.includes('dispatch'),
    );
  });

  it('throws if routes is empty', () => {
    assert.throws(
      () => createWebhookListener({ dispatch: async () => {}, routes: [] }),
      (err) => err.message.includes('at least one route'),
    );
  });

  it('throws on invalid route path', () => {
    assert.throws(
      () => createWebhookListener({
        dispatch: async () => {},
        routes: [{ path: '../etc/passwd', tool: 'test' }],
      }),
      (err) => err.message.includes('Invalid webhook route path'),
    );
  });

  it('throws if route is missing tool name', () => {
    assert.throws(
      () => createWebhookListener({
        dispatch: async () => {},
        routes: [{ path: '/hook' }],
      }),
      (err) => err.message.includes('requires a tool name'),
    );
  });

  // ─── A01: non-loopback host without secret is a hard error ───────────────

  it('throws when a route has no secret and host is 0.0.0.0', () => {
    assert.throws(
      () => createWebhookListener({
        dispatch: async () => {},
        host: '0.0.0.0',
        routes: [{ path: '/hook', tool: 'test' }],
      }),
      (err) => err.message.includes('no secret') || err.message.includes('Set route.secret'),
    );
  });

  it('throws when a route has no secret and host is a non-loopback IP', () => {
    assert.throws(
      () => createWebhookListener({
        dispatch: async () => {},
        host: '10.0.0.1',
        routes: [{ path: '/hook', tool: 'test' }],
      }),
      (err) => err.message.includes('Set route.secret'),
    );
  });

  it('does NOT throw when a route has no secret and host is 127.0.0.1 (loopback)', () => {
    const stderrLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => { stderrLines.push(String(msg)); return origWrite(msg, ...rest); };
    try {
      assert.doesNotThrow(
        () => createWebhookListener({
          dispatch: async () => {},
          host: '127.0.0.1',
          routes: [{ path: '/hook', tool: 'test' }],
        }),
      );
      // A warning must be emitted for the unauthenticated loopback route
      assert.ok(
        stderrLines.some((l) => l.includes('WARNING') && l.includes('no secret')),
        'Expected a WARNING stderr line about the missing secret',
      );
    } finally {
      process.stderr.write = origWrite;
    }
  });

  it('does NOT throw when a route has no secret and host is localhost (loopback)', () => {
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => origWrite(msg, ...rest);
    try {
      assert.doesNotThrow(
        () => createWebhookListener({
          dispatch: async () => {},
          host: 'localhost',
          routes: [{ path: '/hook', tool: 'test' }],
        }),
      );
    } finally {
      process.stderr.write = origWrite;
    }
  });

  it('does NOT throw when a route HAS a secret and host is 0.0.0.0', () => {
    assert.doesNotThrow(
      () => createWebhookListener({
        dispatch: async () => {},
        host: '0.0.0.0',
        routes: [{
          path: '/hook',
          tool: 'test',
          secret: { type: 'header', envVar: '__TEST_WEBHOOK_SECRET' },
        }],
      }),
    );
  });
});

describe('webhook HTTP server', () => {
  it('health endpoint returns ok (no structural details by default)', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{ path: '/hook', tool: 'my_tool' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await fetch(`${url}/health`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.status, 'ok');
      // Structural fields (name, routes) are gated behind exposeHealthDetails:true
      // to prevent deployment fingerprinting.
      assert.equal(body.routes, undefined);
      assert.equal(body.name, undefined);
    } finally {
      httpServer.close();
    }
  });

  it('health endpoint exposes details when exposeHealthDetails is true', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      exposeHealthDetails: true,
      routes: [{ path: '/hook', tool: 'my_tool' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await fetch(`${url}/health`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.status, 'ok');
      assert.equal(body.routes, 1);
    } finally {
      httpServer.close();
    }
  });

  it('routes endpoint is disabled by default (information disclosure prevention)', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [
        { path: '/hooks/github', tool: 'process_github', method: 'POST' },
        { path: '/hooks/stripe', tool: 'process_stripe' },
      ],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await fetch(`${url}/routes`);
      assert.equal(res.status, 404, 'routes endpoint should return 404 when exposeRoutes is not set');
    } finally {
      httpServer.close();
    }
  });

  it('routes endpoint lists registered routes when exposeRoutes is true', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      exposeRoutes: true,
      routes: [
        { path: '/hooks/github', tool: 'process_github', method: 'POST' },
        { path: '/hooks/stripe', tool: 'process_stripe' },
      ],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await fetch(`${url}/routes`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.routes.length, 2);
      assert.equal(body.routes[0].tool, 'process_github');
    } finally {
      httpServer.close();
    }
  });

  it('dispatches tool on matching webhook (async mode)', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{ path: '/hooks/test', tool: 'my_tool' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await sendRequest(url, '/hooks/test', {
        body: { event: 'push', repo: 'test' },
      });

      assert.equal(res.status, 202);
      const body = await res.json();
      assert.equal(body.status, 'accepted');

      // Give async dispatch time to complete
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(dispatch.mock.calls.length, 1);
      assert.equal(dispatch.mock.calls[0].arguments[0], 'my_tool');
    } finally {
      httpServer.close();
    }
  });

  it('dispatches tool on matching webhook (sync mode)', async () => {
    const dispatch = createMockDispatch();
    dispatch.setResponse('my_tool', { processed: true });

    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{ path: '/hooks/test', tool: 'my_tool', response: 'sync' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await sendRequest(url, '/hooks/test', {
        body: { data: 'test' },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.status, 'ok');
      assert.deepEqual(body.result, { processed: true });
    } finally {
      httpServer.close();
    }
  });

  it('returns 404 for unmatched paths', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{ path: '/hooks/test', tool: 'my_tool' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await sendRequest(url, '/hooks/unknown');
      assert.equal(res.status, 404);
    } finally {
      httpServer.close();
    }
  });

  it('extracts args from body using argMap', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{
        path: '/hooks/test',
        tool: 'my_tool',
        response: 'sync',
        argMap: {
          repo_name: '$body.repository.name',
          event: '$body.action',
          static_value: 'fixed',
        },
      }],
    });
    const { httpServer, url } = await listener.start();

    try {
      await sendRequest(url, '/hooks/test', {
        body: { repository: { name: 'my-repo' }, action: 'opened' },
      });

      const callArgs = dispatch.mock.calls[0].arguments[1];
      assert.equal(callArgs.repo_name, 'my-repo');
      assert.equal(callArgs.event, 'opened');
      assert.equal(callArgs.static_value, 'fixed');
    } finally {
      httpServer.close();
    }
  });

  it('extracts args from headers using argMap', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{
        path: '/hooks/test',
        tool: 'my_tool',
        response: 'sync',
        argMap: {
          event_type: '$header.x-github-event',
        },
      }],
    });
    const { httpServer, url } = await listener.start();

    try {
      await sendRequest(url, '/hooks/test', {
        body: {},
        headers: { 'X-GitHub-Event': 'push' },
      });

      const callArgs = dispatch.mock.calls[0].arguments[1];
      assert.equal(callArgs.event_type, 'push');
    } finally {
      httpServer.close();
    }
  });

  it('filters events based on filter criteria', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{
        path: '/hooks/test',
        tool: 'my_tool',
        filter: { '$body.action': ['opened', 'closed'] },
      }],
    });
    const { httpServer, url } = await listener.start();

    try {
      // This should be filtered out
      const res1 = await sendRequest(url, '/hooks/test', {
        body: { action: 'edited' },
      });
      assert.equal(res1.status, 200);
      const body1 = await res1.json();
      assert.equal(body1.status, 'filtered');

      // This should pass through
      const res2 = await sendRequest(url, '/hooks/test', {
        body: { action: 'opened' },
      });
      assert.equal(res2.status, 202);

      await new Promise((r) => setTimeout(r, 50));
      assert.equal(dispatch.mock.calls.length, 1);
    } finally {
      httpServer.close();
    }
  });

  it('validates header secret', async () => {
    const dispatch = createMockDispatch();
    process.env.__TEST_WEBHOOK_SECRET = 'my-secret-123';

    try {
      const listener = createWebhookListener({
        dispatch,
        port: 0,
        routes: [{
          path: '/hooks/test',
          tool: 'my_tool',
          secret: {
            type: 'header',
            header: 'X-Webhook-Secret',
            envVar: '__TEST_WEBHOOK_SECRET',
          },
        }],
      });
      const { httpServer, url } = await listener.start();

      try {
        // Missing secret → 401
        const res1 = await sendRequest(url, '/hooks/test', { body: {} });
        assert.equal(res1.status, 401);

        // Wrong secret → 401
        const res2 = await sendRequest(url, '/hooks/test', {
          body: {},
          headers: { 'X-Webhook-Secret': 'wrong' },
        });
        assert.equal(res2.status, 401);

        // Correct secret → 202
        const res3 = await sendRequest(url, '/hooks/test', {
          body: {},
          headers: { 'X-Webhook-Secret': 'my-secret-123' },
        });
        assert.equal(res3.status, 202);
      } finally {
        httpServer.close();
      }
    } finally {
      delete process.env.__TEST_WEBHOOK_SECRET;
    }
  });

  it('returns 500 on sync dispatch failure', async () => {
    const dispatch = createMockDispatch();
    dispatch.setThrow('my_tool', 'Something broke');

    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{ path: '/hooks/test', tool: 'my_tool', response: 'sync' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await sendRequest(url, '/hooks/test', { body: {} });
      assert.equal(res.status, 500);
      const body = await res.json();
      assert.equal(body.error, 'Tool dispatch failed');
    } finally {
      httpServer.close();
    }
  });

  it('handles CORS preflight without wildcard origin (server-to-server endpoint)', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{ path: '/hooks/test', tool: 'my_tool' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      const res = await fetch(`${url}/hooks/test`, { method: 'OPTIONS' });
      assert.equal(res.status, 204);
      // Webhook endpoints are server-to-server; no wildcard CORS origin is set
      assert.equal(res.headers.get('Access-Control-Allow-Origin'), null,
        'webhook listener should not set wildcard CORS origin');
    } finally {
      httpServer.close();
    }
  });

  it('rejects oversized request bodies', async () => {
    const dispatch = createMockDispatch();
    const listener = createWebhookListener({
      dispatch,
      port: 0,
      routes: [{ path: '/hooks/test', tool: 'my_tool' }],
    });
    const { httpServer, url } = await listener.start();

    try {
      // Send a body larger than 1MB
      const largeBody = 'x'.repeat(1_100_000);
      try {
        const res = await fetch(`${url}/hooks/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: largeBody,
        });
        // If we get a response, it should be an error status
        assert.ok(res.status >= 400);
      } catch {
        // Connection reset is expected — the server destroyed the request
        assert.ok(true, 'Connection was destroyed as expected for oversized body');
      }
      // Dispatch should NOT have been called
      assert.equal(dispatch.mock.calls.length, 0);
    } finally {
      httpServer.close();
    }
  });

  // ─── Async error rate limiter tests ──────────────────────────────────

  // ─── 202 recon-reduction: tool field is omitted on no-secret routes ─────

  it('202 response omits tool name on loopback routes without a secret', async () => {
    const dispatch = createMockDispatch();
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => origWrite(msg, ...rest); // suppress warning noise in test output

    try {
      const listener = createWebhookListener({
        dispatch,
        port: 0,
        host: '127.0.0.1',
        routes: [{ path: '/hooks/test', tool: 'my_tool' }],
      });
      const { httpServer, url } = await listener.start();

      try {
        const res = await sendRequest(url, '/hooks/test', { body: { event: 'push' } });
        assert.equal(res.status, 202);
        const body = await res.json();
        assert.equal(body.status, 'accepted');
        assert.equal(body.tool, undefined, '202 must not echo tool name on no-secret routes (recon reduction)');
      } finally {
        httpServer.close();
      }
    } finally {
      process.stderr.write = origWrite;
    }
  });

  it('202 response includes tool name on routes with a secret', async () => {
    const dispatch = createMockDispatch();
    process.env.__TEST_WEBHOOK_SECRET202 = 'secret-for-202-test';

    try {
      const listener = createWebhookListener({
        dispatch,
        port: 0,
        routes: [{
          path: '/hooks/test',
          tool: 'my_tool',
          secret: { type: 'header', header: 'x-webhook-secret', envVar: '__TEST_WEBHOOK_SECRET202' },
        }],
      });
      const { httpServer, url } = await listener.start();

      try {
        const res = await sendRequest(url, '/hooks/test', {
          body: {},
          headers: { 'x-webhook-secret': 'secret-for-202-test' },
        });
        assert.equal(res.status, 202);
        const body = await res.json();
        assert.equal(body.status, 'accepted');
        assert.equal(body.tool, 'my_tool', '202 must include tool name when route has a secret');
      } finally {
        httpServer.close();
      }
    } finally {
      delete process.env.__TEST_WEBHOOK_SECRET202;
    }
  });

  it('suppresses repeated async dispatch errors after rate limit is reached', async () => {
    let dispatchCallCount = 0;
    const failDispatch = async () => {
      dispatchCallCount++;
      throw new Error('downstream failure');
    };

    const stderrLines = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (msg, ...rest) => { stderrLines.push(String(msg)); return origWrite(msg, ...rest); };

    try {
      const listener = createWebhookListener({
        dispatch: failDispatch,
        port: 0,
        maxErrorsPerWindow: 3,
        errorLogWindowMs: 60_000,
        routes: [{ path: '/hooks/test', tool: 'my_tool' }],
      });
      const { httpServer, url } = await listener.start();

      try {
        // Send 6 requests — all will fail
        for (let i = 0; i < 6; i++) {
          await sendRequest(url, '/hooks/test', { body: { x: i } });
          // Small delay to allow async catch to run
          await new Promise((r) => setTimeout(r, 10));
        }

        // Dispatch called 6 times
        assert.equal(dispatchCallCount, 6);

        const errorLines = stderrLines.filter((l) => l.includes('Webhook dispatch error'));
        const suppressLines = stderrLines.filter((l) => l.includes('suppressed') || l.includes('rate limit'));

        // Only first 3 errors should be logged
        assert.ok(errorLines.length <= 3, `Expected at most 3 error lines, got ${errorLines.length}`);
        // A suppression notice must appear
        assert.ok(suppressLines.length > 0, 'Expected a suppression warning to be emitted');
      } finally {
        httpServer.close();
      }
    } finally {
      process.stderr.write = origWrite;
    }
  });
});
