import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createTransform, composeTransforms } from './index.js';

describe('createTransform — validation', () => {
  it('throws on empty object (missing name)', () => {
    assert.throws(() => createTransform({}), /name/);
  });

  it('throws when only a name is provided (no apply methods)', () => {
    assert.throws(
      () => createTransform({ name: 'x' }),
      /at least one/,
    );
  });

  it('throws on invalid name (contains space / punctuation)', () => {
    assert.throws(
      () => createTransform({ name: 'bad name!', applyToResult: () => {} }),
      /tool-prefix regex/,
    );
  });

  it('throws on empty-string name', () => {
    assert.throws(
      () => createTransform({ name: '', applyToResult: () => {} }),
      /non-empty string/,
    );
  });

  it('throws when name exceeds the 64-char length bound', () => {
    const longName = 'a'.repeat(65);
    assert.throws(
      () => createTransform({ name: longName, applyToResult: () => {} }),
      /tool-prefix regex/,
    );
  });

  it('throws when spec is null or undefined', () => {
    assert.throws(() => createTransform(null), /object spec/);
    assert.throws(() => createTransform(undefined), /object spec/);
  });

  it('throws when an apply-method is not a function', () => {
    assert.throws(
      () => createTransform({ name: 'x', applyToResult: 'not-a-function' }),
      /applyToResult/,
    );
    assert.throws(
      () => createTransform({ name: 'x', applyToDispatch: 42 }),
      /applyToDispatch/,
    );
    assert.throws(
      () => createTransform({ name: 'x', applyToComponents: {} }),
      /applyToComponents/,
    );
  });

  it('accepts the full allowed charset [a-zA-Z0-9_-]', () => {
    assert.doesNotThrow(() =>
      createTransform({
        name: 'Abc_123-XYZ',
        applyToResult: () => {},
      }),
    );
  });
});

describe('createTransform — happy path', () => {
  it('constructs with only applyToComponents; other methods are absent', () => {
    const t = createTransform({
      name: 'components-only',
      applyToComponents: (c) => c,
    });
    assert.equal(t.name, 'components-only');
    assert.equal(typeof t.applyToComponents, 'function');
    assert.equal('applyToDispatch' in t, false);
    assert.equal('applyToResult' in t, false);
  });

  it('constructs with only applyToDispatch; other methods are absent', () => {
    const t = createTransform({
      name: 'dispatch-only',
      applyToDispatch: (_tool, args) => args,
    });
    assert.equal(t.name, 'dispatch-only');
    assert.equal(typeof t.applyToDispatch, 'function');
    assert.equal('applyToComponents' in t, false);
    assert.equal('applyToResult' in t, false);
  });

  it('constructs with only applyToResult; other methods are absent', () => {
    const t = createTransform({
      name: 'result-only',
      applyToResult: (_tool, result) => result,
    });
    assert.equal(t.name, 'result-only');
    assert.equal(typeof t.applyToResult, 'function');
    assert.equal('applyToComponents' in t, false);
    assert.equal('applyToDispatch' in t, false);
  });

  it('constructs with all three methods when provided', () => {
    const t = createTransform({
      name: 'full',
      applyToComponents: (c) => c,
      applyToDispatch: (_n, a) => a,
      applyToResult: (_n, r) => r,
    });
    assert.equal(typeof t.applyToComponents, 'function');
    assert.equal(typeof t.applyToDispatch, 'function');
    assert.equal(typeof t.applyToResult, 'function');
  });

  it('returned transform is frozen (cannot mutate name)', () => {
    const t = createTransform({
      name: 'frozen',
      applyToResult: () => {},
    });
    assert.ok(Object.isFrozen(t));
    assert.throws(() => {
      t.name = 'other';
    }, TypeError);
  });

  it('apply-methods are invoked with the expected arguments and return values', () => {
    const t = createTransform({
      name: 'echo',
      applyToDispatch: (toolName, args, context) => ({ ...args, _seen: { toolName, ctx: context?.tag } }),
      applyToResult: (toolName, result) => ({ ...result, _from: toolName }),
    });
    assert.deepEqual(
      t.applyToDispatch('foo', { a: 1 }, { tag: 'T' }),
      { a: 1, _seen: { toolName: 'foo', ctx: 'T' } },
    );
    assert.deepEqual(
      t.applyToResult('bar', { ok: true }, {}),
      { ok: true, _from: 'bar' },
    );
  });
});

describe('composeTransforms', () => {
  it('returns a no-op composite when called with zero args', () => {
    const c = composeTransforms();
    assert.equal(typeof c.applyToComponents, 'function');
    assert.equal(typeof c.applyToDispatch, 'function');
    assert.equal(typeof c.applyToResult, 'function');

    const components = { tools: [{ name: 'a' }] };
    assert.strictEqual(c.applyToComponents(components), components);

    const args = { x: 1 };
    assert.strictEqual(c.applyToDispatch('tool', args, {}), args);

    const result = { ok: true };
    assert.strictEqual(c.applyToResult('tool', result, {}), result);
  });

  it('with a single transform behaves like the original', () => {
    const inner = createTransform({
      name: 'inner',
      applyToResult: (_tool, r) => ({ ...r, marked: true }),
    });
    const c = composeTransforms(inner);

    // Only surfaces methods the constituent implements.
    assert.equal(typeof c.applyToResult, 'function');
    assert.equal('applyToComponents' in c, false);
    assert.equal('applyToDispatch' in c, false);

    assert.deepEqual(
      c.applyToResult('t', { ok: true }, {}),
      { ok: true, marked: true },
    );
  });

  it('threads applyToResult through multiple transforms in order', () => {
    const a = createTransform({
      name: 'a',
      applyToResult: (_tool, r) => ({ ...r, steps: [...(r.steps ?? []), 'a'] }),
    });
    const b = createTransform({
      name: 'b',
      applyToResult: (_tool, r) => ({ ...r, steps: [...(r.steps ?? []), 'b'] }),
    });
    const c = composeTransforms(a, b);

    const out = c.applyToResult('tool', { steps: [] }, {});
    assert.deepEqual(out.steps, ['a', 'b']);
  });

  it('threads applyToDispatch through multiple transforms in order', () => {
    const a = createTransform({
      name: 'a',
      applyToDispatch: (_tool, args) => ({ ...args, trail: [...(args.trail ?? []), 'a'] }),
    });
    const b = createTransform({
      name: 'b',
      applyToDispatch: (_tool, args) => ({ ...args, trail: [...(args.trail ?? []), 'b'] }),
    });
    const c = composeTransforms(a, b);

    const out = c.applyToDispatch('tool', { trail: [] }, {});
    assert.deepEqual(out.trail, ['a', 'b']);
  });

  it('surfaces dispatch and result methods independently when different transforms implement each', () => {
    const dispatcher = createTransform({
      name: 'dispatcher',
      applyToDispatch: (_tool, args) => ({ ...args, dispatched: true }),
    });
    const resulter = createTransform({
      name: 'resulter',
      applyToResult: (_tool, r) => ({ ...r, resulted: true }),
    });
    const c = composeTransforms(dispatcher, resulter);

    assert.equal(typeof c.applyToDispatch, 'function');
    assert.equal(typeof c.applyToResult, 'function');
    // No constituent implements applyToComponents — composite omits it.
    assert.equal('applyToComponents' in c, false);

    assert.deepEqual(
      c.applyToDispatch('t', { a: 1 }, {}),
      { a: 1, dispatched: true },
    );
    assert.deepEqual(
      c.applyToResult('t', { ok: true }, {}),
      { ok: true, resulted: true },
    );
  });

  it('skips transforms that do not implement a given method', () => {
    const onlyDispatch = createTransform({
      name: 'd',
      applyToDispatch: (_tool, args) => ({ ...args, d: true }),
    });
    const onlyResult = createTransform({
      name: 'r',
      applyToResult: (_tool, r) => ({ ...r, r: true }),
    });
    const alsoResult = createTransform({
      name: 'r2',
      applyToResult: (_tool, r) => ({ ...r, r2: true }),
    });
    const c = composeTransforms(onlyDispatch, onlyResult, alsoResult);

    // applyToDispatch only runs onlyDispatch.
    assert.deepEqual(
      c.applyToDispatch('t', {}, {}),
      { d: true },
    );
    // applyToResult threads onlyResult then alsoResult.
    assert.deepEqual(
      c.applyToResult('t', {}, {}),
      { r: true, r2: true },
    );
  });

  it('threads applyToComponents through multiple transforms in order', () => {
    const a = createTransform({
      name: 'a',
      applyToComponents: (c) => ({ ...c, tools: [...c.tools, { name: 'a-tool' }] }),
    });
    const b = createTransform({
      name: 'b',
      applyToComponents: (c) => ({ ...c, tools: [...c.tools, { name: 'b-tool' }] }),
    });
    const composite = composeTransforms(a, b);

    const out = composite.applyToComponents({ tools: [] });
    assert.deepEqual(out.tools.map((t) => t.name), ['a-tool', 'b-tool']);
  });

  it('composite is frozen', () => {
    const t = createTransform({ name: 't', applyToResult: () => {} });
    const c = composeTransforms(t);
    assert.ok(Object.isFrozen(c));
  });

  it('passes toolName and context through to each constituent', () => {
    const seen = [];
    const a = createTransform({
      name: 'a',
      applyToResult: (toolName, r, context) => {
        seen.push(['a', toolName, context?.tag]);
        return r;
      },
    });
    const b = createTransform({
      name: 'b',
      applyToResult: (toolName, r, context) => {
        seen.push(['b', toolName, context?.tag]);
        return r;
      },
    });
    const c = composeTransforms(a, b);
    c.applyToResult('the-tool', { ok: true }, { tag: 'T' });
    assert.deepEqual(seen, [
      ['a', 'the-tool', 'T'],
      ['b', 'the-tool', 'T'],
    ]);
  });
});
