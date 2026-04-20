/**
 * Chain error code contract — `ChainError` + `BridgeErrorCode.CHAIN_*` must
 * actually emit on the documented failure paths. Prior to this test suite
 * the five CHAIN_* codes and the `ChainError` class were exported by
 * `src/errors.js` but never thrown in shipping code — `src/compose/chain.js`
 * used plain `Error` everywhere, so `TROUBLESHOOTING.md`'s guidance to catch
 * `err.bridgeCode === 'CHAIN_STEP_FAILED'` silently never fired. This suite
 * locks the public error surface against that regression.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { executeChain } from '../../src/compose/chain.js';
import { BridgeErrorCode, ChainError, BridgeError } from '../../src/errors.js';

describe('chain error code contract (public — user-facing catch paths)', () => {
  it('CHAIN_REF_UNDEFINED fires on reference to missing step', async () => {
    const steps = [
      { call: 'step_b', as: 'b', args: { id: '$missing.id' } },
    ];
    await assert.rejects(
      executeChain(steps, {}, async () => ({ id: 1 })),
      (err) => {
        assert.ok(err instanceof ChainError, 'expected ChainError');
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_REF_UNDEFINED);
        assert.match(err.message, /Reference to undefined step/);
        return true;
      },
    );
  });

  it('CHAIN_CIRCULAR_DEPENDENCY fires on circular step refs', async () => {
    const steps = [
      { call: 'a', as: 'a', args: { x: '$b.x' } },
      { call: 'b', as: 'b', args: { x: '$a.x' } },
    ];
    await assert.rejects(
      executeChain(steps, {}, async () => ({ x: 1 })),
      (err) => {
        assert.ok(err instanceof ChainError);
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_CIRCULAR_DEPENDENCY);
        return true;
      },
    );
  });

  it('CHAIN_CIRCULAR_DEPENDENCY fires on invocation cycle across chain-tools', async () => {
    const steps = [{ call: 'outer', as: 'r' }];
    await assert.rejects(
      executeChain(steps, {}, async () => ({}), {
        _currentChainName: 'outer',
        _chainStack: ['outer'],
      }),
      (err) => {
        assert.ok(err instanceof ChainError);
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_CIRCULAR_DEPENDENCY);
        assert.match(err.message, /invocation cycle/);
        return true;
      },
    );
  });

  it('CHAIN_DEPTH_EXCEEDED fires when recursion depth is reached', async () => {
    const steps = [{ call: 't', as: 'r' }];
    await assert.rejects(
      executeChain(steps, {}, async () => ({}), { _depth: 10 }),
      (err) => {
        assert.ok(err instanceof ChainError);
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_DEPTH_EXCEEDED);
        return true;
      },
    );
  });

  it('CHAIN_STEP_FAILED fires on duplicate `as` name', async () => {
    const steps = [
      { call: 'x', as: 'r' },
      { call: 'y', as: 'r' },
    ];
    await assert.rejects(
      executeChain(steps, {}, async () => ({})),
      (err) => {
        assert.ok(err instanceof ChainError);
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_STEP_FAILED);
        assert.match(err.message, /Duplicate step name/);
        return true;
      },
    );
  });

  it('CHAIN_STEP_FAILED fires on reserved `as` name (_chain)', async () => {
    const steps = [{ call: 't', as: '_chain' }];
    await assert.rejects(
      executeChain(steps, {}, async () => ({})),
      (err) => {
        assert.ok(err instanceof ChainError);
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_STEP_FAILED);
        return true;
      },
    );
  });

  it('CHAIN_STEP_FAILED fires on reserved `as` name (args)', async () => {
    const steps = [{ call: 't', as: 'args' }];
    await assert.rejects(
      executeChain(steps, {}, async () => ({})),
      (err) => {
        assert.ok(err instanceof ChainError);
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_STEP_FAILED);
        return true;
      },
    );
  });

  it('CHAIN_STEP_FAILED fires on missing `as` field', async () => {
    const steps = [{ call: 't' }];
    await assert.rejects(
      executeChain(steps, {}, async () => ({})),
      (err) => {
        assert.ok(err instanceof ChainError);
        assert.equal(err.bridgeCode, BridgeErrorCode.CHAIN_STEP_FAILED);
        return true;
      },
    );
  });

  it('AUTH_MISSING (not a chain code) fires when chain sub-dispatch violates tenant allowlist', async () => {
    const steps = [{ call: 'forbidden_tool', as: 'r' }];
    const args = {};
    // Inject a tenant envelope the way bridge+tenant scope would
    Object.defineProperty(args, '_tenant', {
      value: {
        tenantId: 'tenant-b',
        allowlist: ['allowed_tool'],
        blocklist: null,
      },
      enumerable: false,
    });
    await assert.rejects(
      executeChain(steps, args, async () => ({})),
      (err) => {
        assert.ok(err instanceof BridgeError, 'tenant violation should use BridgeError, not ChainError');
        assert.equal(err.bridgeCode, BridgeErrorCode.AUTH_MISSING);
        assert.match(err.message, /allowlist/);
        return true;
      },
    );
  });
});
