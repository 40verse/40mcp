/**
 * reverse-mixed-auth — reverse bridge exposes only allowed tools under
 * mixed auth states.
 *
 * Threat: an operator stands up a reverse bridge with auth required.
 * An attacker probes the bridge with three states:
 *   (a) no auth header → must 401
 *   (b) valid auth header + allowed tool → 200
 *   (c) valid auth header + BLOCKED tool name → 404 (tool unknown, not 200)
 *
 * Defense: reverse bridge `auth.envVar` gate runs unconditionally on
 * every request; tool name lookup is exact-match against the
 * registered tool map; unknown names return 404 not 200.
 */

import { createReverseBridge } from '../../../reverse/server.js';
import { request as httpRequest } from 'node:http';

function post({ port, path, token, body = '{"args":{}}' }) {
  return new Promise((resolveFn, reject) => {
    const buf = Buffer.from(body);
    const headers = { 'Content-Type': 'application/json', 'Content-Length': buf.length };
    if (token != null) headers['x-token'] = token;
    const req = httpRequest({ host: '127.0.0.1', port, path, method: 'POST', headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolveFn({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.write(buf);
    req.end();
  });
}

export default {
  id: 'reverse-mixed-auth',
  boundary: 'reverse-bridge',
  story:
    'Attacker probes reverse bridge with no auth, valid auth + allowed tool, ' +
    'valid auth + unknown tool name. Must produce 401 / 200 / 404 respectively ' +
    '(no oracle and no silent fall-through).',

  async run() {
    process.env.__TRUSTMATRIX_RM_TOKEN__ = 'valid-token-for-reverse-mixed-auth';
    const handle = createReverseBridge({
      name: 'tm-rm',
      tools: [
        { name: 'allowed_tool', inputSchema: { type: 'object' } },
      ],
      dispatch: async () => ({ ok: true }),
      port: 0,
      host: '127.0.0.1',
      auth: { envVar: '__TRUSTMATRIX_RM_TOKEN__', header: 'x-token' },
    });
    const { httpServer } = await handle.start();
    const port = httpServer.address().port;
    try {
      // (a) no auth header
      const r1 = await post({ port, path: '/api/tools/allowed_tool', token: null });
      // (b) valid auth + allowed tool
      const r2 = await post({ port, path: '/api/tools/allowed_tool', token: 'valid-token-for-reverse-mixed-auth' });
      // (c) valid auth + unknown tool name
      const r3 = await post({ port, path: '/api/tools/secret_admin_tool', token: 'valid-token-for-reverse-mixed-auth' });
      const findings = [];
      if (r1.status !== 401) findings.push(`no-auth → ${r1.status} (expected 401)`);
      if (r2.status !== 200) findings.push(`auth+allowed → ${r2.status} (expected 200)`);
      if (r3.status !== 404) findings.push(`auth+unknown → ${r3.status} (expected 404)`);
      if (findings.length === 0) {
        return { verdict: 'pass', detail: '401/200/404 sequence verified' };
      }
      return { verdict: 'fail', detail: findings.join('; ') };
    } finally {
      await new Promise((r) => { httpServer.closeAllConnections?.(); httpServer.close(() => r()); });
      delete process.env.__TRUSTMATRIX_RM_TOKEN__;
    }
  },
};
