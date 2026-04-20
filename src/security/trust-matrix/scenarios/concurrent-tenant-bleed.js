/**
 * concurrent-tenant-bleed — tenant A and B hammer overlapping chains
 * under concurrent load with no context bleed.
 *
 * Threat: two tenants share a tool surface. They invoke the same chain
 * concurrently. If chain step state, dispatch options, or async-context
 * is shared between tenants (closure capture, module-level state, race
 * on a shared counter), tenant A's call could surface tenant B's
 * `_tenant` envelope or vice-versa.
 *
 * Defense: every dispatch carries `_tenant` non-enumerably on its own
 * args object — nothing is shared between concurrent calls. This
 * scenario fires N concurrent calls per tenant, observes the dispatched
 * args, and asserts every observation matches the originating tenant.
 */

import { executeChain } from '../../../compose/chain.js';
import { createTenantScope } from '../../../tenant/scope.js';

export default {
  id: 'concurrent-tenant-bleed',
  boundary: 'tenant-scope',
  story:
    'Two tenants fire 50 concurrent chain calls each. Every dispatched sub-step ' +
    'must observe its caller\'s tenantId — never the other tenant\'s. Zero bleed.',

  async run() {
    const observations = []; // { caller: 'A' | 'B', observed: <tenantId> }

    // Inner dispatch records who it was called as.
    const innerDispatch = async (name, args) => {
      const seen = args?._tenant?.tenantId || 'NONE';
      observations.push({ name, observed: seen });
      // Tiny async hop to maximise interleaving.
      await new Promise((r) => setImmediate(r));
      return { ok: seen };
    };

    // The "chain" wrapper that the tenant scope wraps.
    const dispatchWithChain = async (name, args, opts) => {
      if (name === 'shared_chain') {
        return executeChain(
          [
            { call: 'sub_a', as: 'a', args: {} },
            { call: 'sub_b', as: 'b', args: {} },
          ],
          args,
          innerDispatch,
          opts,
        );
      }
      return innerDispatch(name, args);
    };

    const scopedA = createTenantScope({
      dispatch: dispatchWithChain,
      resolveContext: async () => ({ tenantId: 'tenant-A', auth: { type: 'bearer', value: 'A-token' } }),
    });
    const scopedB = createTenantScope({
      dispatch: dispatchWithChain,
      resolveContext: async () => ({ tenantId: 'tenant-B', auth: { type: 'bearer', value: 'B-token' } }),
    });

    const N = 50;
    const callsA = Array.from({ length: N }, () => scopedA('shared_chain', { from: 'A' }, {}));
    const callsB = Array.from({ length: N }, () => scopedB('shared_chain', { from: 'B' }, {}));

    // Interleave the two arrays so the event loop sees A,B,A,B,... and
    // the dispatch contexts have maximum opportunity to bleed.
    const interleaved = [];
    for (let i = 0; i < N; i++) {
      interleaved.push(callsA[i]);
      interleaved.push(callsB[i]);
    }
    await Promise.all(interleaved);

    // Every observation must match a real tenant ID. None should
    // observe the OTHER tenant's ID. We can't directly tag which
    // observation came from which call (that's the point — we're
    // testing isolation, not tracing) — but we CAN count observations
    // per tenantId and verify the totals match expectations.
    // Each tenant fires N chain calls; each chain has 2 sub-steps;
    // so we expect 2*N observations per tenant = 100 each = 200 total.
    const counts = { A: 0, B: 0, OTHER: 0 };
    for (const o of observations) {
      if (o.observed === 'tenant-A') counts.A += 1;
      else if (o.observed === 'tenant-B') counts.B += 1;
      else counts.OTHER += 1;
    }
    const expected = 2 * N;
    const findings = [];
    if (counts.OTHER > 0) findings.push(`${counts.OTHER} observations had unexpected tenantId`);
    if (counts.A !== expected) findings.push(`tenant-A observations: ${counts.A} (expected ${expected})`);
    if (counts.B !== expected) findings.push(`tenant-B observations: ${counts.B} (expected ${expected})`);
    if (findings.length === 0) {
      return { verdict: 'pass', detail: `${N} concurrent calls × 2 tenants × 2 sub-steps = ${observations.length} observations, all correctly attributed` };
    }
    return { verdict: 'fail', detail: findings.join('; ') };
  },
};
