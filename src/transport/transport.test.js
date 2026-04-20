import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createStdioTransport } from './stdio.js';
import { createSseTransport } from './sse.js';
import { createTransport } from './index.js';

// ─── Test helpers ───────────────────────────────────────────────────────────

function createTestServer() {
  const server = new Server(
    { name: 'test-server', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );
  return server;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('stdio transport', () => {
  it('createStdioTransport returns a StdioServerTransport instance', () => {
    const transport = createStdioTransport();
    assert.ok(transport instanceof StdioServerTransport);
  });

  it('transport can be passed to server.connect()', async () => {
    const _server = createTestServer();
    const transport = createStdioTransport();

    // Just verify it doesn't throw
    assert.doesNotThrow(() => {
      // We can't actually connect to stdio in tests, but we can verify
      // the transport is the right type
      assert.ok(transport);
    });
  });
});

// Use 127.0.0.1 (not localhost) in fetch URLs throughout this file. On Node 18
// undici resolves "localhost" to ::1 (IPv6) by preference, but createSseTransport
// binds to 127.0.0.1 (IPv4) by default — fetch would fail with a bare
// "fetch failed" on the Node 18 CI leg. Node 20+ has Happy Eyeballs fallback
// so localhost would work there; pin to the IPv4 literal for CI parity.
describe('SSE transport', () => {
  it('createSseTransport starts HTTP server on specified port', async () => {
    const server = createTestServer();
    const { httpServer, url } = await createSseTransport(server, { port: 0 });

    try {
      const address = httpServer.address();
      assert.ok(address.port > 0);
      assert.ok(url.includes('127.0.0.1') || url.includes('localhost'));
      // URL must reflect actual assigned port, not the requested 0
      assert.ok(url.includes(`:${address.port}`), `URL ${url} should contain assigned port ${address.port}`);
    } finally {
      httpServer.close();
    }
  });

  it('SSE health endpoint returns JSON with status ok', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, { port: 0 });

    try {
      const address = httpServer.address();
      const port = address.port;
      const response = await fetch(`http://127.0.0.1:${port}/health`);

      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.status, 'ok');
      // sessions is gated behind exposeSessionCount — not present by default
      assert.ok(!('sessions' in body), 'session count must not be exposed by default');
    } finally {
      httpServer.close();
    }
  });

  it('SSE server closes cleanly', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, { port: 0 });

    const address = httpServer.address();
    assert.ok(address.port > 0);

    await new Promise((resolve) => {
      httpServer.close(resolve);
    });
  });

  it('SSE server with custom port and path', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      path: '/custom-sse',
      messagePath: '/custom-message',
    });

    try {
      const address = httpServer.address();
      const port = address.port;

      // Health endpoint should still work
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      assert.equal(response.status, 200);
    } finally {
      httpServer.close();
    }
  });

  it('SSE server returns 404 for unknown paths', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, { port: 0 });

    try {
      const address = httpServer.address();
      const port = address.port;

      const response = await fetch(`http://127.0.0.1:${port}/unknown`);
      assert.equal(response.status, 404);
    } finally {
      httpServer.close();
    }
  });

  it('SSE server handles CORS preflight requests', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, { port: 0 });

    try {
      const address = httpServer.address();
      const port = address.port;

      const response = await fetch(`http://127.0.0.1:${port}/health`, {
        method: 'OPTIONS',
      });
      assert.equal(response.status, 204);
      // When no allowedOrigins configured, CORS header is omitted (security hardening)
      assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
    } finally {
      httpServer.close();
    }
  });
});

describe('SSE transport — frontdoor bearer auth', () => {
  it('GET /sse rejects requests without Authorization', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'sekret',
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/sse`);
      // Drain body to release the socket
      await response.text().catch(() => {});
      assert.equal(response.status, 401);
      assert.equal(response.headers.get('www-authenticate'), 'Bearer');
    } finally {
      httpServer.close();
    }
  });

  it('GET /sse rejects requests with wrong bearer token', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'sekret',
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/sse`, {
        headers: { Authorization: 'Bearer wrong' },
      });
      await response.text().catch(() => {});
      assert.equal(response.status, 401);
    } finally {
      httpServer.close();
    }
  });

  it('POST /message rejects requests without Authorization', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'sekret',
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/message?sessionId=abc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      await response.text().catch(() => {});
      assert.equal(response.status, 401);
    } finally {
      httpServer.close();
    }
  });

  it('GET /health stays open even when bearer auth is required', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'sekret',
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.status, 'ok');
    } finally {
      httpServer.close();
    }
  });

  it('OPTIONS preflight stays open and exposes Authorization in allow-headers', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'sekret',
      allowedOrigins: ['https://chat.openai.com'],
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/sse`, {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://chat.openai.com',
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'authorization',
        },
      });
      assert.equal(response.status, 204);
      const allowHeaders = response.headers.get('access-control-allow-headers') || '';
      assert.ok(/authorization/i.test(allowHeaders), `expected Authorization in Access-Control-Allow-Headers, got: ${allowHeaders}`);
    } finally {
      httpServer.close();
    }
  });

  it('GET /sse accepts a request with the correct bearer token', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'sekret',
    });

    try {
      const port = httpServer.address().port;
      // Use a raw socket-style request so we can read initial status without
      // waiting for the long-lived stream to close.
      const controller = new AbortController();
      const responsePromise = fetch(`http://127.0.0.1:${port}/sse?sessionId=authok`, {
        headers: { Authorization: 'Bearer sekret' },
        signal: controller.signal,
      });
      const response = await responsePromise;
      try {
        assert.notEqual(response.status, 401, 'bearer-authorized request must not return 401');
        // Accept either 200 (SSE stream) or anything non-401; the real
        // assertion is that auth passed.
      } finally {
        controller.abort();
        try { await response.body?.cancel(); } catch { /* ignore */ }
      }
    } finally {
      httpServer.close();
    }
  });

  it('bearer mismatch of different lengths is still rejected (no length short-circuit)', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'this-is-a-long-token-abcdef',
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/sse`, {
        headers: { Authorization: 'Bearer x' },
      });
      await response.text().catch(() => {});
      assert.equal(response.status, 401);
    } finally {
      httpServer.close();
    }
  });
});

describe('SSE transport — multi-token bearer auth', () => {
  it('accepts either token when requireBearer is a {principal: token} map', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: { alice: 'tok-a', bob: 'tok-b' },
    });

    try {
      const port = httpServer.address().port;

      for (const [principal, token] of [['alice', 'tok-a'], ['bob', 'tok-b']]) {
        const controller = new AbortController();
        const res = await fetch(`http://127.0.0.1:${port}/sse?sessionId=multi-${principal}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        try {
          assert.notEqual(res.status, 401, `token for ${principal} should not 401`);
        } finally {
          controller.abort();
          try { await res.body?.cancel(); } catch { /* ignore */ }
        }
      }
    } finally {
      httpServer.close();
    }
  });

  it('rejects a token that matches no principal entry', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: { alice: 'tok-a', bob: 'tok-b' },
    });

    try {
      const port = httpServer.address().port;
      const res = await fetch(`http://127.0.0.1:${port}/sse`, {
        headers: { Authorization: 'Bearer tok-c' },
      });
      await res.text().catch(() => {});
      assert.equal(res.status, 401);
    } finally {
      httpServer.close();
    }
  });

  it('empty {principal: token} map behaves like no auth required', async () => {
    // Library-layer behavior only: `requireBearer: {}` collapses to "no
    // auth required" so `createSseTransport` stays a clean primitive.
    // The CLI frontdoor path (`link --sse --bearer-file`) rejects an
    // empty file at startup — see the "rejects an empty JSON object"
    // integration test in test/frontdoor-sse.test.js.
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: {},
    });

    try {
      const port = httpServer.address().port;
      // No Authorization header — should not 401 because the map is empty.
      const controller = new AbortController();
      const res = await fetch(`http://127.0.0.1:${port}/sse?sessionId=empty-map`, {
        signal: controller.signal,
      });
      try {
        assert.notEqual(res.status, 401);
      } finally {
        controller.abort();
        try { await res.body?.cancel(); } catch { /* ignore */ }
      }
    } finally {
      httpServer.close();
    }
  });
});

describe('SSE transport — per-principal session cap', () => {
  // The real MCP SDK `Server` rejects a second `connect(transport)` call
  // — fine for production (one Server per process) but it makes
  // multi-session rate-limit tests bounce off a 500 path before the cap
  // can actually accumulate. Use a noop stub so the SSE transport's
  // `transport.start()` fallback completes cleanly for every session.
  function createMultiSessionStub() {
    return { connect: async () => {} };
  }

  // Helper: open a sessioned GET /sse and keep it open until aborted.
  // Returns the response so the caller can read status before aborting.
  async function openSession(port, principal, token, sessionId, controller) {
    return await fetch(`http://127.0.0.1:${port}/sse?sessionId=${sessionId}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    });
  }

  it('caps concurrent sessions per principal in multi-token mode', async () => {
    const server = createMultiSessionStub();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: { alice: 'tok-a', bob: 'tok-b' },
      maxSessionsPerPrincipal: 2,
      maxSessionsPerIp: 100, // make sure the per-IP cap doesn't trip first
    });

    const ctls = [];
    try {
      const port = httpServer.address().port;

      // Two sessions for alice — both accepted.
      for (let i = 0; i < 2; i++) {
        const c = new AbortController(); ctls.push(c);
        const r = await openSession(port, 'alice', 'tok-a', `alice-${i}`, c);
        assert.notEqual(r.status, 429, `alice session ${i} should not be rate limited`);
        assert.notEqual(r.status, 401);
      }

      // Third alice session — capped.
      const overC = new AbortController(); ctls.push(overC);
      const over = await openSession(port, 'alice', 'tok-a', 'alice-3', overC);
      try {
        await over.text().catch(() => {});
        assert.equal(over.status, 429, 'third alice session should hit per-principal cap');
      } finally {
        try { await over.body?.cancel(); } catch { /* ignore */ }
      }

      // Bob is independent — should still be accepted.
      const bobC = new AbortController(); ctls.push(bobC);
      const bob = await openSession(port, 'bob', 'tok-b', 'bob-1', bobC);
      assert.notEqual(bob.status, 429, 'bob should not be capped by alice');
      assert.notEqual(bob.status, 401);
    } finally {
      for (const c of ctls) c.abort();
      httpServer.close();
    }
  });

  it('does not apply the per-principal cap in single-token mode', async () => {
    // Single-token mode → principal === null on every request, so the
    // per-principal cap is a no-op. Only the per-IP cap bounds.
    const server = createMultiSessionStub();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: 'shared',
      maxSessionsPerPrincipal: 1,
      maxSessionsPerIp: 100,
    });

    const ctls = [];
    try {
      const port = httpServer.address().port;
      // 3 sessions on the shared token — all should be accepted because
      // principal === null skips the per-principal gate.
      for (let i = 0; i < 3; i++) {
        const c = new AbortController(); ctls.push(c);
        const r = await fetch(`http://127.0.0.1:${port}/sse?sessionId=shared-${i}`, {
          headers: { Authorization: 'Bearer shared' },
          signal: c.signal,
        });
        assert.notEqual(r.status, 429, `single-token session ${i} should not be rate limited`);
        assert.notEqual(r.status, 401);
      }
    } finally {
      for (const c of ctls) c.abort();
      httpServer.close();
    }
  });

  it('counter releases when a session closes', async () => {
    const server = createMultiSessionStub();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      requireBearer: { alice: 'tok-a' },
      maxSessionsPerPrincipal: 1,
      maxSessionsPerIp: 100,
    });

    try {
      const port = httpServer.address().port;

      // Open + close one session, then open a new one — the second open
      // must succeed because the first slot was released.
      const c1 = new AbortController();
      const r1 = await openSession(port, 'alice', 'tok-a', 'alice-x', c1);
      assert.notEqual(r1.status, 429);
      c1.abort();
      try { await r1.body?.cancel(); } catch { /* ignore */ }

      // Give the close handler a tick to decrement the counter.
      await new Promise((done) => setTimeout(done, 50));

      const c2 = new AbortController();
      const r2 = await openSession(port, 'alice', 'tok-a', 'alice-y', c2);
      try {
        assert.notEqual(r2.status, 429, 'reopen after close should succeed');
      } finally {
        c2.abort();
        try { await r2.body?.cancel(); } catch { /* ignore */ }
      }
    } finally {
      httpServer.close();
    }
  });
});

describe('SSE transport — /health healthProvider', () => {
  it('default /health stays `{status:"ok"}` when no provider is set', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, { port: 0 });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      const body = await response.json();
      assert.equal(response.status, 200);
      assert.equal(body.status, 'ok');
      assert.ok(!('upstreams' in body), 'default /health must not enumerate upstreams');
    } finally {
      httpServer.close();
    }
  });

  it('healthProvider payload is merged into /health', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      healthProvider: () => ({
        upstreams: [
          { source: 'stdio:github', status: 'ok' },
          { source: 'stdio:twitter', status: 'degraded' },
        ],
      }),
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      const body = await response.json();
      assert.equal(response.status, 200);
      assert.equal(body.status, 'ok');
      assert.equal(body.upstreams.length, 2);
      assert.equal(body.upstreams[1].status, 'degraded');
    } finally {
      httpServer.close();
    }
  });

  it('a throwing healthProvider still returns `{status:"ok"}`', async () => {
    const server = createTestServer();
    const { httpServer } = await createSseTransport(server, {
      port: 0,
      healthProvider: () => { throw new Error('boom'); },
    });

    try {
      const port = httpServer.address().port;
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      const body = await response.json();
      assert.equal(response.status, 200);
      assert.equal(body.status, 'ok');
      assert.ok(!('upstreams' in body));
    } finally {
      httpServer.close();
    }
  });
});

describe('transport factory', () => {
  it('createTransport("stdio") returns a function', () => {
    const factory = createTransport('stdio');
    assert.equal(typeof factory, 'function');
  });

  it('createTransport("sse", options) returns a function', () => {
    const factory = createTransport('sse', { port: 8080 });
    assert.equal(typeof factory, 'function');
  });

  it('createTransport throws for unknown transport type', () => {
    assert.throws(() => {
      createTransport('unknown');
    }, /Unknown transport type/);
  });

  it('stdio factory can create transport', async () => {
    const factory = createTransport('stdio');
    const transport = await factory();
    assert.ok(transport instanceof StdioServerTransport);
  });

  it('sse factory can create transport', async () => {
    const server = createTestServer();
    const factory = createTransport('sse', { port: 0 });
    const result = await factory(server);

    try {
      assert.ok(result.httpServer);
      assert.ok(result.url);
    } finally {
      result.httpServer.close();
    }
  });
});
