/**
 * Production failure mock library.
 *
 * Each factory spins up a real HTTP server that exhibits a specific failure
 * behavior observed (or theorized) in production API integrations. Mocks are
 * the "ground truth" in the autoresearch loop: the bridge must navigate them
 * correctly to prove a seam is safe.
 *
 * Usage:
 *   const { server, port } = await schemaDriftApi();
 *   // ... run scenario ...
 *   server.close();
 *
 * Seam map:
 *   Seam 1 — Spec  → Tool Definitions   (translation fidelity)
 *   Seam 2 — Args  → HTTP Request       (parameter mapping)
 *   Seam 3 — HTTP Response → MCP Result (response transform)
 *   Auth   — Vault → Runtime Secret     (credential lifecycle)
 *   Compose — N APIs → Unified Surface  (mixer/chain)
 */

import { createServer } from 'node:http';

// ─── Internal helper ──────────────────────────────────────────────────────────

function startServer(handler) {
  return new Promise((resolve, reject) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port });
    });
    server.on('error', reject);
  });
}

// ─── Scenario 1: Schema Drift (Seam 3) ───────────────────────────────────────
//
// The spec declares fields as required strings. The live API returns null for
// them — a common result of data migrations, backend refactors, or spec rot.
//
// Production trigger: API evolves without spec update; null rows from DB.
// Question: Does the bridge crash on null values, or pass them through cleanly?

export async function schemaDriftApi() {
  return startServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    const userMatch = req.url.match(/^\/users\/(\d+)$/);
    if (req.method === 'GET' && userMatch) {
      // Required fields declared in spec as string — returned as null in reality
      res.writeHead(200);
      return res.end(JSON.stringify({
        id: parseInt(userMatch[1]),
        name: null,
        email: null,
        role: null,
      }));
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not found' }));
  });
}

// ─── Scenario 2: Array Serialization (Seam 2) ────────────────────────────────
//
// This API is strict: arrays must arrive as comma-separated values
// (?tags=a,b,c). It rejects repeated-param style (?tags=a&tags=b&tags=c)
// with a 400 and a diagnostic message.
//
// The bridge's qs() in core/path.js currently uses URLSearchParams.append()
// which produces repeated params. This mock exposes that behavior.
//
// Production trigger: Any API using OpenAPI style:simple or style:form,explode:false.
// Question: Does the bridge serialize arrays as comma-sep or repeated params?

export async function arrayFormatApi() {
  let lastReceivedQuery = null;

  const { server, port } = await startServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'GET' && req.url.startsWith('/items')) {
      const url = new URL(req.url, 'http://localhost');
      const tagsRepeated = url.searchParams.getAll('tags');
      const tagsComma = url.searchParams.get('tags');

      lastReceivedQuery = req.url;

      // Strict: only comma-sep accepted
      if (tagsRepeated.length > 1) {
        res.writeHead(400);
        return res.end(JSON.stringify({
          error: 'Invalid array format',
          hint: 'Use comma-separated: ?tags=a,b,c',
          received: tagsRepeated,
          rawQuery: url.search,
        }));
      }

      const tags = tagsComma ? tagsComma.split(',').filter(Boolean) : [];
      res.writeHead(200);
      return res.end(JSON.stringify({ items: tags.map(t => ({ tag: t.trim() })) }));
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not found' }));
  });

  // Expose lastReceivedQuery for diagnostic assertions in tests
  return { server, port, getLastQuery: () => lastReceivedQuery };
}

// ─── Scenario 3: Error as 200 (Seam 3) ───────────────────────────────────────
//
// The API always returns HTTP 200. Success vs failure is signalled by a
// {success: boolean} envelope in the body. This is common in legacy PHP APIs,
// some payment processors, and SOAP-over-HTTP bridges.
//
// Production trigger: Any API that uses application-level error codes over HTTP 200.
// Question: Does the bridge throw (treating 200 as success) or pass the body
//           through so the LLM can see success: false?

export async function errorAs200Api() {
  return startServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'GET' && req.url.startsWith('/orders/')) {
      // HTTP 200, but the operation failed at the application level
      res.writeHead(200);
      return res.end(JSON.stringify({
        success: false,
        error: 'Order not found',
        code: 'ORDER_404',
        requestId: 'req_abc123',
      }));
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not found' }));
  });
}

// ─── Scenario 4: Token Expiry (Auth seam) ─────────────────────────────────────
//
// The API accepts a bearer token for the first N calls, then returns 401 with a
// WWW-Authenticate header indicating the token expired. The bridge has no
// OAuth2 refresh configured — it uses a static token.
//
// Production trigger: Short-lived API keys, token rotation, vault out of sync
//                     with the live credential.
// Question: Does the bridge surface a clean 401 error, or crash/hang?

export async function tokenExpiryApi({ expiresAfter = 2 } = {}) {
  let callCount = 0;
  const VALID_TOKEN = 'Bearer valid-token-xyz';

  return startServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    const auth = req.headers['authorization'];

    if (auth !== VALID_TOKEN) {
      res.writeHead(401);
      res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
      return res.end(JSON.stringify({ error: 'Unauthorized', code: 'AUTH_REQUIRED' }));
    }

    callCount++;

    if (callCount > expiresAfter) {
      res.setHeader('WWW-Authenticate',
        'Bearer error="invalid_token", error_description="Access token expired"');
      res.writeHead(401);
      return res.end(JSON.stringify({
        error: 'token_expired',
        message: 'Access token has expired. Re-authenticate to continue.',
      }));
    }

    res.writeHead(200);
    res.end(JSON.stringify({ data: 'protected resource', callNumber: callCount }));
  });
}

// ─── Scenario 6: Large Response (Seam 3) ──────────────────────────────────────
//
// The endpoint returns an unbounded list — 1000 items with rich per-item data.
// No pagination. Total payload is ~200KB.
//
// Production trigger: Any "list all" endpoint without cursor/page params.
// Question: Does tokenBudget truncation work cleanly? Is the truncated result
//           still parseable, and does it carry metadata about what was cut?

export async function largeResponseApi() {
  const records = Array.from({ length: 1000 }, (_, i) => ({
    id: i + 1,
    title: `Record ${i + 1}`,
    description: `Detailed description for record ${i + 1}. `.repeat(8),
    metadata: {
      created: '2025-01-01T00:00:00Z',
      updated: '2025-06-01T12:00:00Z',
      tags: ['alpha', 'beta', 'gamma'],
      owner: `user_${(i % 20) + 1}`,
    },
    metrics: { views: i * 13, score: (i % 5) * 0.2 },
  }));

  return startServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'GET' && req.url === '/records') {
      res.writeHead(200);
      return res.end(JSON.stringify(records));
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not found' }));
  });
}
