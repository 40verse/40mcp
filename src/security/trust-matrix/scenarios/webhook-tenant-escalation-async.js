/**
 * webhook-tenant-escalation-async — webhook payload attempts tenant
 * escalation through the ASYNC (fire-and-forget) dispatch path.
 *
 * Threat: same as the sync variant. The
 * async path returns 202 immediately and dispatches in the background.
 * The validator must still reject the smuggled `_tenant` before the
 * background dispatch ever runs.
 *
 * Defense: same `validateToolArgs` recursive `scanReservedKeys` runs
 * regardless of sync vs async response mode.
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export default {
  id: 'webhook-tenant-escalation-async',
  boundary: 'webhook',
  story:
    'Webhook async (fire-and-forget) dispatch path receives a smuggled _tenant. ' +
    'The validator must reject before the background dispatch runs — no forged ' +
    'tenant should ever reach the tool.',

  async run() {
    let dispatchedTenant = null;
    const dispatch = async (name, args) => {
      dispatchedTenant = args && args._tenant ? args._tenant : null;
      return { ok: true };
    };
    const handle = createWebhookListener({
      name: 'tm-tenant-async', host: '127.0.0.1', port: 0,
      dispatch,
      routes: [{ path: '/hook', tool: 'do_thing' /* default async response */ }],
    });
    const h = await handle.start();
    const port = h.httpServer.address().port;
    try {
      const body = JSON.stringify({ _tenant: { tenantId: 'admin', auth: { value: 'forged' } }, real: 'data' });
      const res = await post({ port, path: '/hook', body });
      // Async returns 202 'accepted' immediately. Wait briefly for the background dispatch.
      await sleep(150);
      const findings = [];
      if (res.status !== 202 && res.status !== 400) {
        findings.push(`async response status ${res.status} (expected 202 accepted or 400 rejected)`);
      }
      if (dispatchedTenant && dispatchedTenant.tenantId === 'admin') {
        findings.push('forged _tenant reached background dispatch');
      }
      if (findings.length === 0) {
        return { verdict: 'pass', detail: `async response: ${res.status}; no forged tenant reached dispatch` };
      }
      return { verdict: 'fail', detail: findings.join('; ') };
    } finally {
      await new Promise((r) => { h.httpServer.closeAllConnections?.(); h.httpServer.close(() => r()); });
    }
  },
};
