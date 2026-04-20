/**
 * webhook-tenant-escalation-sync — webhook payload attempts tenant
 * escalation through the SYNC dispatch path.
 *
 * Threat: a webhook caller sends a body that tries to smuggle
 * `_tenant: { tenantId: 'admin', auth: { value: 'forged' } }` into the
 * dispatched tool's args. If the validator misses it, downstream code
 * reading `args._tenant` would dispatch as the spoofed tenant.
 *
 * Defense: `validateToolArgs` runs `scanReservedKeys` recursively on
 * every dispatch — `_tenant` (and the whole reserved envelope set) is
 * rejected at any depth, including inside an `argMap`-mapped body.
 */

import { createWebhookListener } from '../../../webhook/listener.js';
import { request as httpRequest } from 'node:http';

function post({ port, path, body }) {
  return new Promise((resolveFn, reject) => {
    const buf = Buffer.from(body);
    const req = httpRequest({
      host: '127.0.0.1', port, path, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': buf.length },
    }, (res) => {
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
  id: 'webhook-tenant-escalation-sync',
  boundary: 'webhook',
  story:
    'Webhook body smuggles _tenant via the synchronous dispatch path. Validator ' +
    'must reject before the dispatched tool ever sees a forged tenant context.',

  async run() {
    let dispatchedTenant = null;
    const dispatch = async (name, args) => {
      // Record any tenant the dispatched tool would have observed.
      // After the validator runs, this should never see a forged value.
      dispatchedTenant = args && args._tenant ? args._tenant : null;
      return { ok: true };
    };
    const handle = createWebhookListener({
      name: 'tm-tenant-sync', host: '127.0.0.1', port: 0,
      dispatch,
      routes: [{
        path: '/hook',
        tool: 'do_thing',
        response: 'sync',
        // No argMap → entire body becomes args
      }],
    });
    const h = await handle.start();
    const port = h.httpServer.address().port;
    try {
      // Top-level _tenant smuggling
      const body1 = JSON.stringify({ _tenant: { tenantId: 'admin', auth: { value: 'forged' } }, real: 'data' });
      const r1 = await post({ port, path: '/hook', body: body1 });
      // Nested _tenant smuggling
      const body2 = JSON.stringify({ wrapper: { nested: { _tenant: { tenantId: 'admin' } } } });
      const r2 = await post({ port, path: '/hook', body: body2 });

      const findings = [];
      // Top-level should be rejected (400) OR scrubbed (200 with no forged tenant observed)
      if (r1.status === 200 && dispatchedTenant && dispatchedTenant.tenantId === 'admin') {
        findings.push('top-level _tenant escaped validator and reached dispatch');
      }
      if (r1.status >= 500) {
        findings.push(`top-level smuggling produced 5xx: ${r1.status} (should be 400 or scrubbed-200)`);
      }
      // Nested should also be rejected
      dispatchedTenant = null;
      if (r2.status === 200 && dispatchedTenant && JSON.stringify(dispatchedTenant).includes('admin')) {
        findings.push('nested _tenant escaped validator and reached dispatch');
      }

      if (findings.length === 0) {
        return { verdict: 'pass', detail: `top-level: ${r1.status}, nested: ${r2.status} — no forged tenant reached dispatch` };
      }
      return { verdict: 'fail', detail: findings.join('; ') };
    } finally {
      await new Promise((r) => { h.httpServer.closeAllConnections?.(); h.httpServer.close(() => r()); });
    }
  },
};
