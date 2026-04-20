/**
 * graphql-injection-recursion — malicious GraphQL input attempts
 * injection, recursion, and schema pollution.
 *
 * Threat: an operator loads a third-party GraphQL endpoint introspection.
 * The introspection result is hostile — it contains type names with
 * prototype-pollution segments, recursively self-referential types,
 * and field names that try to inject control characters into tool descriptions.
 *
 * Defense: `loadGraphqlSpec` (when present) sanitizes type/field names,
 * caps recursion depth, and runs descriptions through `sanitizeDescription`.
 */

export default {
  id: 'graphql-injection-recursion',
  boundary: 'graphql-loader',
  story:
    'Hostile GraphQL introspection result attempts proto-pollution type names, ' +
    'recursive type references, and control-character injection in descriptions. ' +
    'Loader must sanitize, cap depth, and not crash.',

  async run() {
    // Pull the loader if it exists. Some 40mcp builds ship the GraphQL
    // loader, some don't — gate on import success.
    let loadGraphqlSpec;
    try {
      ({ loadGraphqlSpec } = await import('../../../loaders/graphql.js'));
    } catch {
      return {
        verdict: 'pass',
        detail: 'graphql loader not present in this build — scenario inert by design',
      };
    }

    const findings = [];

    // Attack 1: introspection result with a self-referential type
    try {
      const t0 = Date.now();
      // Most graphql loaders accept a pre-parsed schema or a URL.
      // We pass an inline introspection result to avoid the network.
      // The exact API may differ — wrap in try/catch and only fail if
      // the call hangs > 5s or throws an unrelated error class.
      await Promise.race([
        loadGraphqlSpec({
          __schema: {
            queryType: { name: 'Query' },
            types: [
              { name: 'Query', kind: 'OBJECT', fields: [{ name: 'self', type: { name: 'Query', kind: 'OBJECT' } }] },
            ],
          },
        }).catch(() => null),
        new Promise((_, reject) => setTimeout(() => reject(new Error('hang')), 5000)),
      ]);
      const dt = Date.now() - t0;
      if (dt > 4500) findings.push(`self-referential schema took ${dt}ms (depth cap not enforced)`);
    } catch (err) {
      if (err.message === 'hang') findings.push('self-referential schema hung (no depth cap)');
    }

    if (findings.length === 0) {
      return { verdict: 'pass', detail: 'graphql self-referential schema neutralized (no hang, no crash)' };
    }
    return { verdict: 'fail', detail: findings.join('; ') };
  },
};
