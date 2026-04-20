import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { frontdoorContext, currentPrincipal, currentSessionId } from './context.js';

describe('transport/context — frontdoor AsyncLocalStorage', () => {
  it('returns null outside an active request', () => {
    assert.equal(currentPrincipal(), null);
    assert.equal(currentSessionId(), null);
  });

  it('propagates principal and sessionId inside .run()', () => {
    let observedPrincipal;
    let observedSession;
    frontdoorContext.run({ principal: 'alice', sessionId: 's1' }, () => {
      observedPrincipal = currentPrincipal();
      observedSession = currentSessionId();
    });
    assert.equal(observedPrincipal, 'alice');
    assert.equal(observedSession, 's1');
    // And cleanly clears after the run.
    assert.equal(currentPrincipal(), null);
  });

  it('survives async boundaries inside the run block', async () => {
    const seen = await frontdoorContext.run(
      { principal: 'bob', sessionId: 's2' },
      async () => {
        await new Promise((r) => setImmediate(r));
        await Promise.resolve();
        return { p: currentPrincipal(), s: currentSessionId() };
      },
    );
    assert.equal(seen.p, 'bob');
    assert.equal(seen.s, 's2');
  });

  it('null principal is returned as null (not undefined)', () => {
    let seen;
    frontdoorContext.run({ principal: null, sessionId: 's3' }, () => {
      seen = currentPrincipal();
    });
    assert.equal(seen, null);
  });

  it('concurrent runs do not bleed between each other', async () => {
    const [a, b] = await Promise.all([
      frontdoorContext.run({ principal: 'alice', sessionId: 'sa' }, async () => {
        await new Promise((r) => setImmediate(r));
        return currentPrincipal();
      }),
      frontdoorContext.run({ principal: 'bob', sessionId: 'sb' }, async () => {
        await new Promise((r) => setImmediate(r));
        return currentPrincipal();
      }),
    ]);
    assert.equal(a, 'alice');
    assert.equal(b, 'bob');
  });
});
