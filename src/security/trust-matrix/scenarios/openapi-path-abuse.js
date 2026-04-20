/**
 * openapi-path-abuse — malicious OpenAPI input attempts path traversal,
 * recursion, and parameter pollution across the full conversion chain.
 *
 * Threat: an operator loads a third-party OpenAPI spec (marketplace,
 * vendor, plugin distribution). The spec is hostile — it contains
 * path-traversal `$ref` chains, prototype-poisoned operationIds,
 * cloud-metadata `servers[].url`, and parameter names that try to
 * shadow `Object.prototype` keys.
 *
 * Defense: `loadOpenApiSpec` enforces SSRF guard on extracted server
 * URL, file size cap before read, $ref depth cap, prototype-pollution
 * key blocking in `resolveRefPath`, and snake-case sanitization of
 * tool names.
 */

import { loadOpenApiSpec } from '../../../openapi.js';

export default {
  id: 'openapi-path-abuse',
  boundary: 'openapi-loader',
  story:
    'Hostile OpenAPI spec attempts SSRF via servers[].url, path traversal ' +
    'via $ref to ../../etc, prototype pollution via constructor parameter ' +
    'name, and infinite $ref recursion. Every attack must be neutralized.',

  async run() {
    const findings = [];

    // Attack 1: server URL pointing at cloud metadata
    try {
      await loadOpenApiSpec({
        openapi: '3.0.0',
        info: { title: 't', version: '1' },
        servers: [{ url: 'http://169.254.169.254/latest/meta-data/' }],
        paths: { '/x': { get: { operationId: 'fetchMeta', responses: { 200: { description: 'ok' } } } } },
      });
      findings.push('cloud-metadata server URL accepted');
    } catch (err) {
      if (!/metadata|169\.254|ssrf|safe/i.test(err.message)) {
        findings.push(`SSRF refusal threw with unexpected message: ${err.message.slice(0, 80)}`);
      }
    }

    // Attack 2: $ref into prototype chain (resolveRefPath proto guard)
    try {
      const spec = {
        openapi: '3.0.0',
        info: { title: 't', version: '1' },
        servers: [{ url: 'https://api.example.com' }],
        paths: {
          '/x': {
            get: {
              operationId: 'doX',
              parameters: [{ $ref: '#/constructor/prototype/polluted' }],
              responses: { 200: { description: 'ok' } },
            },
          },
        },
      };
      const { tools } = await loadOpenApiSpec(spec);
      // Should NOT crash, should NOT have a polluted property on
      // the resulting tool's inputSchema.
      const polluted = tools.some((t) => t.inputSchema && Object.prototype.hasOwnProperty.call(t.inputSchema, 'polluted'));
      if (polluted) findings.push('$ref via constructor.prototype produced polluted tool');
    } catch (err) {
      findings.push(`$ref proto-chain threw unexpectedly: ${err.message.slice(0, 80)}`);
    }

    // Attack 3: parameter named __proto__
    try {
      const { tools } = await loadOpenApiSpec({
        openapi: '3.0.0',
        info: { title: 't', version: '1' },
        servers: [{ url: 'https://api.example.com' }],
        paths: {
          '/x': {
            get: {
              operationId: 'paramProto',
              parameters: [{ name: '__proto__', in: 'query', schema: { type: 'string' } }],
              responses: { 200: { description: 'ok' } },
            },
          },
        },
      });
      // Tool MUST NOT carry __proto__ as a query field that shadows the chain.
      const tool = tools[0];
      const props = tool?.inputSchema?.properties || {};
      if (Object.prototype.hasOwnProperty.call(props, '__proto__')) {
        findings.push('__proto__ parameter survived into inputSchema.properties');
      }
    } catch (err) {
      findings.push(`__proto__ param threw unexpectedly: ${err.message.slice(0, 80)}`);
    }

    // Attack 4: deeply nested self-referential $ref (depth cap test)
    try {
      const spec = {
        openapi: '3.0.0',
        info: { title: 't', version: '1' },
        servers: [{ url: 'https://api.example.com' }],
        components: {
          schemas: {
            Loop: { $ref: '#/components/schemas/Loop' },
          },
        },
        paths: {
          '/x': {
            get: {
              operationId: 'circular',
              parameters: [{ name: 'q', in: 'query', schema: { $ref: '#/components/schemas/Loop' } }],
              responses: { 200: { description: 'ok' } },
            },
          },
        },
      };
      // Should complete without infinite loop.
      const t0 = Date.now();
      await loadOpenApiSpec(spec);
      const dt = Date.now() - t0;
      if (dt > 1000) findings.push(`circular $ref took ${dt}ms (depth cap not enforced quickly)`);
    } catch (err) {
      // A throw is acceptable — the cap surfaces as either silent skip or controlled error
      if (!/ref|depth|circular|recursion/i.test(err.message)) {
        findings.push(`circular $ref threw with unexpected message: ${err.message.slice(0, 80)}`);
      }
    }

    if (findings.length === 0) {
      return { verdict: 'pass', detail: '4 OpenAPI attack shapes neutralized (SSRF, proto-ref, proto-param, circular-ref)' };
    }
    return { verdict: 'fail', detail: findings.join('; ') };
  },
};
