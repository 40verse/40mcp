/**
 * vault-degraded-auth — vault daemon unavailable; degraded auth path
 * fails loudly and safely, not silently.
 *
 * Threat: a bridge configured with `auth: { type: 'sealed', vault: ... }`
 * has its vault daemon become unreachable (process crashed, socket
 * unmounted, network partition). The bridge must not silently fall
 * back to anonymous auth, must not crash, and must surface the
 * degradation visibly to operators.
 *
 * Defense: `createRestBridge` with `auth.type === 'sealed'` requires
 * `config.vault` and throws a clear error at construction if it's
 * missing. At runtime, vault failures surface as auth errors that
 * trip the constant-time compare path with empty material — never
 * silently allowing a request through.
 */

import { createRestBridge } from '../../../bridge.js';

export default {
  id: 'vault-degraded-auth',
  boundary: 'vault',
  story:
    'Bridge configured for sealed auth without a vault must throw at ' +
    'construction with a clear error. The "fail loudly, fail closed" ' +
    'invariant — no silent fallback to anonymous.',

  async run() {
    let threw = false;
    let messageSafe = false;
    try {
      // No vault provided — should immediately reject.
      createRestBridge({
        name: 'tm-vault-degraded',
        version: '1.0.0',
        baseUrl: 'http://127.0.0.1:1',
        auth: { type: 'sealed', name: 'my-secret', header: 'X-API-Key' },
        tools: [{ name: 'do_x', description: 'x', method: 'GET', path: '/x', inputSchema: { type: 'object' } }],
      });
    } catch (err) {
      threw = true;
      // Error message must mention vault / sealed / config so the
      // operator immediately knows what to fix.
      if (/vault|sealed|requires/i.test(err.message)) messageSafe = true;
    }

    if (threw && messageSafe) {
      return {
        verdict: 'pass',
        detail: 'sealed auth without vault throws at construction with operator-actionable error',
      };
    }
    if (!threw) {
      return { verdict: 'fail', detail: 'sealed auth without vault did NOT throw — silent fallback risk' };
    }
    return { verdict: 'fail', detail: 'threw but error message does not mention vault/sealed' };
  },
};
