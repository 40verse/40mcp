import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { applyResponseTransform } from './response.js';

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: pick — keeps only listed fields
// ─────────────────────────────────────────────────────────────────────────────

describe('applyResponseTransform', () => {
  it('pick — keeps only listed fields from single object', () => {
    const data = { id: 1, name: 'Alice', email: 'alice@example.com', password: 'secret' };
    const result = applyResponseTransform(data, { pick: ['id', 'name'] });

    assert.deepEqual(result, { id: 1, name: 'Alice' });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 2: pick — works on arrays of objects
  // ───────────────────────────────────────────────────────────────────────────

  it('pick — works on arrays of objects', () => {
    const data = [
      { id: 1, name: 'Alice', secret: 'x' },
      { id: 2, name: 'Bob', secret: 'y' },
    ];
    const result = applyResponseTransform(data, { pick: ['id', 'name'] });

    assert.deepEqual(result, [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' },
    ]);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 3: pick — supports dot-notation paths
  // ───────────────────────────────────────────────────────────────────────────

  it('pick — supports dot-notation paths', () => {
    const data = {
      id: 1,
      user: { name: 'Alice', email: 'alice@example.com' },
      metadata: { created: '2024-01-01' },
    };
    const result = applyResponseTransform(data, { pick: ['id', 'user.name', 'metadata.created'] });

    assert.deepEqual(result, {
      id: 1,
      user: { name: 'Alice' },
      metadata: { created: '2024-01-01' },
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 4: omit — removes listed fields
  // ───────────────────────────────────────────────────────────────────────────

  it('omit — removes listed fields from single object', () => {
    const data = { id: 1, name: 'Alice', email: 'alice@example.com', password: 'secret' };
    const result = applyResponseTransform(data, { omit: ['password', 'email'] });

    assert.deepEqual(result, { id: 1, name: 'Alice' });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 5: limit — truncates arrays
  // ───────────────────────────────────────────────────────────────────────────

  it('limit — truncates arrays to N items', () => {
    const data = [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' },
      { id: 3, name: 'Charlie' },
      { id: 4, name: 'David' },
    ];
    const result = applyResponseTransform(data, { limit: 2 });

    assert.deepEqual(result, [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' },
    ]);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 6: limit + summary — adds _summary metadata
  // ───────────────────────────────────────────────────────────────────────────

  it('limit + summary — adds _summary metadata when array truncated', () => {
    const data = Array.from({ length: 100 }, (_, i) => ({ id: i + 1, name: `User${i + 1}` }));
    const result = applyResponseTransform(data, { limit: 10, summary: true });

    assert.equal(result._summary, 'Showing 10 of 100 items');
    assert.equal(result.items.length, 10);
    assert.deepEqual(result.items[0], { id: 1, name: 'User1' });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 7: summary with custom template string
  // ───────────────────────────────────────────────────────────────────────────

  it('summary — supports custom template string', () => {
    const data = Array.from({ length: 50 }, (_, i) => ({ id: i + 1 }));
    const result = applyResponseTransform(data, {
      limit: 5,
      summary: 'Only {shown} results available; database has {total}',
    });

    assert.equal(result._summary, 'Only 5 results available; database has 50');
    assert.equal(result.items.length, 5);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 8: flatten — converts nested to dot-notation
  // ───────────────────────────────────────────────────────────────────────────

  it('flatten — converts nested objects to dot-notation keys', () => {
    const data = {
      id: 1,
      user: { name: 'Alice', email: 'alice@example.com' },
      metadata: { created: '2024-01-01', updated: '2024-01-02' },
    };
    const result = applyResponseTransform(data, { flatten: true });

    assert.deepEqual(result, {
      id: 1,
      'user.name': 'Alice',
      'user.email': 'alice@example.com',
      'metadata.created': '2024-01-01',
      'metadata.updated': '2024-01-02',
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 9: tokenBudget — truncates large responses
  // ───────────────────────────────────────────────────────────────────────────

  it('tokenBudget — truncates large array responses when over budget', () => {
    // Create data that will exceed a small budget
    const data = Array.from({ length: 50 }, (_, i) => ({
      id: i + 1,
      description: 'This is a very long description that takes up a lot of space in the token budget',
    }));

    const result = applyResponseTransform(data, { tokenBudget: 100 });

    assert.equal(result._truncated, true);
    assert(result.items.length < 50, 'array should be reduced');
    assert(result.items.length > 0, 'should have at least some items');
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 10: template — formats items as strings
  // ───────────────────────────────────────────────────────────────────────────

  it('template — formats items as strings', () => {
    const data = [
      { name: 'Alice', email: 'alice@example.com', role: 'admin' },
      { name: 'Bob', email: 'bob@example.com', role: 'user' },
    ];
    const result = applyResponseTransform(data, { template: '{name} ({email}) - {role}' });

    assert.deepEqual(result, [
      'Alice (alice@example.com) - admin',
      'Bob (bob@example.com) - user',
    ]);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 11: passthrough — returns data unchanged when no transform
  // ───────────────────────────────────────────────────────────────────────────

  it('passthrough — returns data unchanged when no transform applied', () => {
    const data = { id: 1, name: 'Alice', secret: 'password' };

    const result1 = applyResponseTransform(data, {});
    assert.deepEqual(result1, data);

    const result2 = applyResponseTransform(data);
    assert.deepEqual(result2, data);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Test 12: null/undefined data — returns as-is
  // ───────────────────────────────────────────────────────────────────────────

  it('null/undefined data — returns as-is', () => {
    const result1 = applyResponseTransform(null, { pick: ['id'] });
    assert.equal(result1, null);

    const result2 = applyResponseTransform(undefined, { omit: ['password'] });
    assert.equal(result2, undefined);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Additional tests: edge cases and combinations
  // ───────────────────────────────────────────────────────────────────────────

  it('pick + omit — applies both in sequence', () => {
    const data = { id: 1, name: 'Alice', email: 'alice@example.com', password: 'secret', role: 'admin' };
    const result = applyResponseTransform(data, { pick: ['id', 'name', 'email', 'role'], omit: ['email'] });

    assert.deepEqual(result, { id: 1, name: 'Alice', role: 'admin' });
  });

  it('flatten on array — flattens each item', () => {
    const data = [
      { id: 1, user: { name: 'Alice', email: 'alice@example.com' } },
      { id: 2, user: { name: 'Bob', email: 'bob@example.com' } },
    ];
    const result = applyResponseTransform(data, { flatten: true });

    assert.deepEqual(result, [
      { id: 1, 'user.name': 'Alice', 'user.email': 'alice@example.com' },
      { id: 2, 'user.name': 'Bob', 'user.email': 'bob@example.com' },
    ]);
  });

  it('template with missing fields — preserves placeholders', () => {
    const data = { name: 'Alice', email: 'alice@example.com' };
    const result = applyResponseTransform(data, { template: '{name} {role}' });

    assert.equal(result, 'Alice {role}');
  });

  it('limit without summary — no _summary added', () => {
    const data = Array.from({ length: 10 }, (_, i) => ({ id: i + 1 }));
    const result = applyResponseTransform(data, { limit: 5 });

    assert(Array.isArray(result), 'should return array directly');
    assert.equal(result.length, 5);
    assert(!result._summary, 'should not add _summary');
  });

  it('tokenBudget on small data — no truncation', () => {
    const data = { id: 1, name: 'Alice' };
    const result = applyResponseTransform(data, { tokenBudget: 10000 });

    // Should not add _truncated marker since it fits in budget
    assert.deepEqual(result, { id: 1, name: 'Alice' });
  });

  it('complex combination: pick + limit + template + summary', () => {
    const data = Array.from({ length: 20 }, (_, i) => ({
      id: i + 1,
      name: `User${i + 1}`,
      email: `user${i + 1}@example.com`,
      password: 'secret',
      role: 'user',
    }));

    const result = applyResponseTransform(data, {
      pick: ['id', 'name', 'email', 'role'],
      limit: 5,
      template: '{id}: {name} ({email}) [{role}]',
      summary: 'Showing {shown}/{total} users',
    });

    assert.equal(result._summary, 'Showing 5/20 users');
    assert.equal(result.items.length, 5);
    assert.equal(result.items[0], '1: User1 (user1@example.com) [user]');
  });

  it('omit on nested paths — removes nested fields', () => {
    const data = {
      id: 1,
      user: { name: 'Alice', email: 'alice@example.com' },
      metadata: { secret: 'hidden' },
    };
    const result = applyResponseTransform(data, { omit: ['user.email', 'metadata'] });

    assert.deepEqual(result, {
      id: 1,
      user: { name: 'Alice' },
    });
  });

  it('empty array — returns empty array', () => {
    const data = [];
    const result = applyResponseTransform(data, { pick: ['id', 'name'], limit: 10 });

    assert.deepEqual(result, []);
  });

  it('non-object scalar values — pass through unchanged', () => {
    assert.equal(applyResponseTransform(42, { pick: ['id'] }), 42);
    assert.equal(applyResponseTransform('string', { omit: ['password'] }), 'string');
    assert.equal(applyResponseTransform(true, { limit: 5 }), true);
  });
});
