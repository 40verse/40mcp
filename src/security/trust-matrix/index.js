/**
 * Adversarial composition test matrix — the "trust matrix".
 *
 * Each scenario is a named, self-contained adversarial story that
 * exercises 40mcp components in composition (not isolation). The trust matrix
 * proves that the units, when wired together, withstand a specific attacker profile.
 *
 * Scenario shape:
 *   {
 *     id: 'kebab-case-id',
 *     boundary: 'short trust-boundary label',
 *     story: '1-sentence threat story',
 *     async run() => { verdict: 'pass'|'fail'|'error', detail: '...' }
 *   }
 *
 * Adding a scenario:
 *   1. Create scenarios/<id>.js exporting `default { id, boundary, story, run }`
 *   2. Import it here and push into SCENARIOS
 *   3. The runner picks it up automatically
 */

import linkedUpstreamShadow from './scenarios/linked-upstream-shadow.js';
import reverseMixedAuth from './scenarios/reverse-mixed-auth.js';
import webhookTenantEscalationAsync from './scenarios/webhook-tenant-escalation-async.js';
import webhookTenantEscalationSync from './scenarios/webhook-tenant-escalation-sync.js';
import concurrentTenantBleed from './scenarios/concurrent-tenant-bleed.js';
import vaultDegradedAuth from './scenarios/vault-degraded-auth.js';
import openapiPathAbuse from './scenarios/openapi-path-abuse.js';
import harInjectionChain from './scenarios/har-injection-chain.js';
import ssrfIpv4Probes from './scenarios/ssrf-ipv4-probes.js';
import ssrfIpv6Probes from './scenarios/ssrf-ipv6-probes.js';
import graphqlInjectionRecursion from './scenarios/graphql-injection-recursion.js';

/** Ordered list of scenarios. */
export const SCENARIOS = [
  linkedUpstreamShadow,
  reverseMixedAuth,
  webhookTenantEscalationAsync,
  webhookTenantEscalationSync,
  concurrentTenantBleed,
  vaultDegradedAuth,
  graphqlInjectionRecursion,
  openapiPathAbuse,
  harInjectionChain,
  ssrfIpv4Probes,
  ssrfIpv6Probes,
];

/**
 * Run every registered scenario sequentially. Returns a structured
 * report; callers (CI, scripts/trust-matrix.mjs) format it for output.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.verbose=false] - print each scenario verdict to stderr
 * @returns {Promise<{run_at, totals, scenarios}>}
 */
export async function runTrustMatrix({ verbose = false } = {}) {
  const results = [];
  for (const scenario of SCENARIOS) {
    const t0 = Date.now();
    let verdict = 'error';
    let detail = '';
    try {
      const out = await scenario.run();
      verdict = out?.verdict || 'error';
      detail = out?.detail || '';
    } catch (err) {
      verdict = 'error';
      detail = err?.message || String(err);
    }
    const ms = Date.now() - t0;
    const result = {
      id: scenario.id,
      boundary: scenario.boundary,
      story: scenario.story,
      verdict,
      detail,
      ms,
    };
    results.push(result);
    if (verbose) {
      const icon = verdict === 'pass' ? '✓' : verdict === 'fail' ? '✗' : '!';
      process.stderr.write(`  ${icon} ${scenario.id.padEnd(38)} ${verdict.toUpperCase()}  ${ms}ms\n`);
      if (verdict !== 'pass' && detail) process.stderr.write(`      ${detail}\n`);
    }
  }
  const pass = results.filter((r) => r.verdict === 'pass').length;
  const fail = results.filter((r) => r.verdict === 'fail').length;
  const err = results.filter((r) => r.verdict === 'error').length;
  return {
    run_at: new Date().toISOString(),
    totals: { pass, fail, error: err, total: results.length },
    scenarios: results,
  };
}
