import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createProvider, openapi } from './index.js';

describe('createProvider — validation', () => {
  it('throws on empty object (missing name and components)', () => {
    assert.throws(() => createProvider({}), /name/);
  });

  it('throws when name is present but components is missing', () => {
    assert.throws(() => createProvider({ name: 'x' }), /components/);
  });

  it('throws when components is not a function', () => {
    assert.throws(
      () => createProvider({ name: 'x', components: { tools: [] } }),
      /components/,
    );
  });

  it('throws on invalid name (contains space / punctuation)', () => {
    assert.throws(
      () => createProvider({ name: 'bad name!', components: async () => ({ tools: [] }) }),
      /tool-prefix regex/,
    );
  });

  it('throws on empty-string name', () => {
    assert.throws(
      () => createProvider({ name: '', components: async () => ({ tools: [] }) }),
      /non-empty string/,
    );
  });

  it('throws when name exceeds the 64-char length bound', () => {
    const longName = 'a'.repeat(65);
    assert.throws(
      () => createProvider({ name: longName, components: async () => ({ tools: [] }) }),
      /tool-prefix regex/,
    );
  });

  it('throws when spec is null or undefined', () => {
    assert.throws(() => createProvider(null), /object spec/);
    assert.throws(() => createProvider(undefined), /object spec/);
  });

  it('throws when close is provided but is not a function', () => {
    assert.throws(
      () => createProvider({
        name: 'x',
        components: async () => ({ tools: [] }),
        close: 'not-a-function',
      }),
      /close/,
    );
  });

  it('accepts the full allowed charset [a-zA-Z0-9_-]', () => {
    assert.doesNotThrow(() =>
      createProvider({
        name: 'Abc_123-XYZ',
        components: async () => ({ tools: [] }),
      }),
    );
  });
});

describe('createProvider — happy path', () => {
  it('returns an object with expected shape', async () => {
    const p = createProvider({
      name: 'test',
      components: async () => ({ tools: [{ name: 'foo' }] }),
    });
    assert.equal(typeof p, 'object');
    assert.equal(p.name, 'test');
    assert.equal(typeof p.components, 'function');
  });

  it('components() returns the expected payload', async () => {
    const p = createProvider({
      name: 'test',
      components: async () => ({ tools: [{ name: 'foo' }] }),
    });
    const result = await p.components();
    assert.deepEqual(result, { tools: [{ name: 'foo' }] });
  });

  it('returned provider is frozen (cannot mutate name/components)', () => {
    const p = createProvider({
      name: 'test',
      components: async () => ({ tools: [] }),
    });
    assert.ok(Object.isFrozen(p));
    // Strict-mode assignment to a frozen property throws.
    assert.throws(() => {
      p.name = 'other';
    }, TypeError);
  });

  it('supports resources and prompts in the components payload', async () => {
    const p = createProvider({
      name: 'rich',
      components: async () => ({
        tools: [{ name: 'foo' }],
        resources: [{ uri: 'mem://r1' }],
        prompts: [{ name: 'greet' }],
      }),
    });
    const result = await p.components();
    assert.equal(result.tools.length, 1);
    assert.equal(result.resources.length, 1);
    assert.equal(result.prompts.length, 1);
  });
});

describe('createProvider — close optionality', () => {
  it('works without a close function (property is absent)', () => {
    const p = createProvider({
      name: 'noclose',
      components: async () => ({ tools: [] }),
    });
    assert.equal('close' in p, false);
  });

  it('works with a close function and exposes it on the provider', async () => {
    let closed = 0;
    const p = createProvider({
      name: 'withclose',
      components: async () => ({ tools: [] }),
      close: async () => { closed += 1; },
    });
    assert.equal(typeof p.close, 'function');
    await p.close();
    assert.equal(closed, 1);
  });
});

describe('providers module exports', () => {
  it('re-exports openapi', () => {
    assert.equal(typeof openapi, 'function');
  });
});
