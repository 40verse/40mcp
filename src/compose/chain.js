/**
 * Compound tool chains: combine multiple API calls into a single MCP tool.
 *
 * Supports:
 * - $args.field: reference to original call arguments
 * - $stepName.field.nested: reference to prior step results (dot-path traversal)
 * - Automatic parallelism: steps with no cross-dependencies run together
 * - Optional steps: errors don't fail the chain if optional: true
 * - Comprehensive error tracking: partial results + chain metadata
 * - Recursion depth guard: prevents infinite chain nesting
 * - Chain-level response transforms: apply transforms to final merged result
 */

import { applyResponseTransform } from '../transforms/response.js';
import { DANGEROUS_KEYS, getByPath } from '../core/object.js';
import { BridgeError, ChainError, BridgeErrorCode } from '../errors.js';

/** Maximum chain nesting depth to prevent infinite recursion */
const MAX_CHAIN_DEPTH = 10;
/**
 * Maximum number of steps that may run concurrently within a single wave.
 * Previously `Promise.all(wave)` fired every step in parallel, so an
 * attacker-controlled chain config with 500 parallel steps would issue 500
 * concurrent outbound HTTP requests — bypassing any upstream rate limit and
 * exhausting file descriptors.
 */
const DEFAULT_WAVE_CONCURRENCY = 20;

/**
 * Extract a safe, short error code from an error — no raw message body.
 * Used to sanitize optional step failures before storing in shared chain state,
 * preventing API tokens, credentials, or internal error bodies from leaking
 * to subsequent chain steps and the final response.
 * @private
 */
function safeErrorCode(error) {
  if (error && typeof error.code === 'string' && /^[A-Z0-9_]{1,32}$/.test(error.code)) {
    return error.code;
  }
  if (error instanceof TypeError) return 'TYPE_ERROR';
  if (error instanceof RangeError) return 'RANGE_ERROR';
  if (error instanceof SyntaxError) return 'SYNTAX_ERROR';
  return 'STEP_FAILED';
}

/**
 * Resolve a single argument value: handle $ref or pass static value
 * @private
 */
function resolveArgValue(value, args, results) {
  if (typeof value !== 'string' || !value.startsWith('$')) {
    return value;
  }

  const ref = value.substring(1); // Remove leading $
  if (ref.startsWith('args.')) {
    const path = ref.substring(5); // Remove 'args.'
    return getByPath(args, path);
  }

  // Format: $stepName.path or $stepName
  const dotIndex = ref.indexOf('.');
  const stepName = dotIndex === -1 ? ref : ref.substring(0, dotIndex);
  const path = dotIndex === -1 ? '' : ref.substring(dotIndex + 1);

  if (!Object.hasOwn(results, stepName)) {
    throw new ChainError(
      BridgeErrorCode.CHAIN_REF_UNDEFINED,
      `Reference to undefined step: ${stepName}`,
      { step: stepName },
    );
  }

  if (path === '') {
    return results[stepName];
  }

  return getByPath(results[stepName], path);
}

/** Maximum recursion depth for chain arg tree walks. */
const MAX_ARG_TREE_DEPTH = 20;

/**
 * Recursively resolve $ref strings inside a nested arg tree.
 *
 * Previously `resolveStepArgs` iterated only top-level entries, so
 * `{body: {parent: "$stepA.id"}}` passed through the literal string
 * `"$stepA.id"` to the upstream call — silently corrupting requests. The same
 * shallow walk meant `buildExecutionWaves` missed dependencies nested inside
 * arrays or object literals, so step B could end up in the same wave as its
 * nominal prerequisite step A.
 *
 * This walker handles plain objects, arrays, and scalar $ref strings. Depth is
 * capped to block pathological config-time recursion. Prototype guarding via
 * `Object.hasOwn` ensures inherited keys are skipped.
 * @private
 */
function deepResolveArgs(node, args, results, depth = 0) {
  if (depth >= MAX_ARG_TREE_DEPTH) return node;
  if (typeof node === 'string') return resolveArgValue(node, args, results);
  if (node === null || typeof node !== 'object') return node;
  if (Array.isArray(node)) {
    const out = new Array(node.length);
    for (let i = 0; i < node.length; i += 1) {
      out[i] = deepResolveArgs(node[i], args, results, depth + 1);
    }
    return out;
  }
  // Plain object — preserve prototype-less behaviour to avoid ever
  // reintroducing an inherited `constructor`/`__proto__` own key from
  // the input.
  const out = Object.create(null);
  for (const key of Object.keys(node)) {
    if (!Object.prototype.hasOwnProperty.call(node, key)) continue;
    if (DANGEROUS_KEYS.has(key)) continue;
    out[key] = deepResolveArgs(node[key], args, results, depth + 1);
  }
  return out;
}

/**
 * Resolve all argument values in a step's args object (recursive).
 * @private
 */
function resolveStepArgs(stepArgs, args, results) {
  const top = deepResolveArgs(stepArgs || {}, args, results);
  // Always return a plain object at the top level (downstream code does
  // `Object.entries(args)` / spread on the root). Previously `{ ...top }` restored a default prototype, which
  // would expose inherited keys to any caller using `for...in`. Keep
  // the null-prototype hardening by copying into `Object.create(null)`.
  if (top && typeof top === 'object' && !Array.isArray(top)) {
    return Object.assign(Object.create(null), top);
  }
  return top;
}

/**
 * Recursively collect every $stepName dependency reference inside a nested
 * arg tree. Complements `deepResolveArgs` for wave planning.
 * @private
 */
function collectDependencies(node, deps, argsSeen, depth = 0) {
  if (depth >= MAX_ARG_TREE_DEPTH) return;
  if (typeof node === 'string' && node.startsWith('$')) {
    const ref = node.substring(1);
    if (ref.startsWith('args.')) {
      argsSeen.add(true);
      return;
    }
    const dotIndex = ref.indexOf('.');
    const stepName = dotIndex === -1 ? ref : ref.substring(0, dotIndex);
    deps.add(stepName);
    return;
  }
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) collectDependencies(item, deps, argsSeen, depth + 1);
    return;
  }
  for (const key of Object.keys(node)) {
    if (!Object.prototype.hasOwnProperty.call(node, key)) continue;
    collectDependencies(node[key], deps, argsSeen, depth + 1);
  }
}

/**
 * Build a dependency graph to identify parallel execution opportunities
 * @private
 * @returns Array of arrays, where each inner array is a wave of parallel steps
 */
function buildExecutionWaves(steps) {
  const stepsByName = new Map();
  const stepIndex = new Map();

  steps.forEach((step, idx) => {
    if (stepsByName.has(step.as)) {
      throw new ChainError(
        BridgeErrorCode.CHAIN_STEP_FAILED,
        `Duplicate step name "${step.as}" — each step must have a unique "as" name`,
        { step: step.as },
      );
    }
    stepsByName.set(step.as, step);
    stepIndex.set(step.as, idx);
  });

  const dependencies = new Map();
  const hasArgsDependency = new Set();

  // Compute dependencies for each step —
  // walk the FULL arg tree, not just top-level values. Previously a
  // nested ref like `{body: {parent: "$stepA.id"}}` was invisible
  // to the planner, placing step B in the same wave as step A and
  // causing a non-deterministic "reference to undefined step" race
  // or silent literal-string passthrough to the upstream API.
  for (const step of steps) {
    const rawDeps = new Set();
    const argsDepSeen = new Set();
    collectDependencies(step.args || {}, rawDeps, argsDepSeen);
    if (argsDepSeen.size > 0) hasArgsDependency.add(step.as);

    // Only retain dependencies that resolve to a step in this chain;
    // other names are treated as undefined-step errors at run time.
    const deps = new Set();
    for (const name of rawDeps) {
      if (stepsByName.has(name)) deps.add(name);
    }
    dependencies.set(step.as, deps);
  }

  // Build execution waves (topological sort)
  const waves = [];
  const executed = new Set();

  while (executed.size < steps.length) {
    const wave = [];

    for (const step of steps) {
      if (executed.has(step.as)) continue;

      const deps = dependencies.get(step.as);
      const depsReady = Array.from(deps).every((d) => executed.has(d));

      if (depsReady) {
        wave.push(step);
      }
    }

    if (wave.length === 0) {
      throw new ChainError(
        BridgeErrorCode.CHAIN_CIRCULAR_DEPENDENCY,
        'Circular dependency detected in chain',
      );
    }

    waves.push(wave);
    wave.forEach((s) => executed.add(s.as));
  }

  return waves;
}

/**
 * Execute a compound tool chain.
 *
 * @param {Array<object>} steps - Chain step definitions
 * @param {object} args - Initial tool arguments from the MCP call
 * @param {Function} dispatch - async function(toolName, args) → result
 * @returns {Promise<object>} Merged results keyed by step `as` names + metadata
 *
 * Step schema:
 * {
 *   call: 'tool_name',          // Tool to dispatch
 *   as: 'result_key',           // Key in results
 *   args: { ... },              // Arguments; supports $ref
 *   optional: false             // If true, errors don't fail chain
 * }
 *
 * $ref resolution:
 * - $args.field → from args
 * - $stepName.field.nested → from prior step result
 * - static values → pass through
 *
 * @param {object} [options] - Chain execution options
 * @param {number} [options.maxDepth] - Override max recursion depth (default: 10)
 * @param {object} [options.response] - Response transform to apply to final result
 * @param {number} [options._depth] - Internal: current recursion depth (do not set manually)
 */
export async function executeChain(steps, args, dispatch, options = {}) {
  const depth = options._depth || 0;

  // Input size guard: reject oversized initial args before any work begins.
  // An attacker-controlled chain call with a 50 MB args blob would cause every
  // deepResolveArgs walk and JSON.stringify audit call to thrash memory. Cap at
  // 10 MB; circular-reference failures are let through to downstream error handling.
  const MAX_ARGS_JSON_BYTES = 10 * 1024 * 1024; // 10 MB
  try {
    const approxSize = Buffer.byteLength(JSON.stringify(args ?? {}), 'utf8');
    if (approxSize > MAX_ARGS_JSON_BYTES) {
      throw new ChainError(
        BridgeErrorCode.CHAIN_STEP_FAILED,
        `[chain] Initial args exceed maximum size (${approxSize} bytes > ${MAX_ARGS_JSON_BYTES})`,
        { approxSize, max: MAX_ARGS_JSON_BYTES },
      );
    }
  } catch (e) {
    if (e.message.includes('exceed')) throw e;
    // JSON.stringify failed (circular ref etc.) — let downstream handle
  }

  // Clamp the requested maxDepth to the compiled hard ceiling. A caller could
  // pass `{ maxDepth: 9999 }` to inflate the ceiling and the spread would
  // propagate the inflated value through every recursive level. Math.min ensures
  // no caller — internal or otherwise — can drive recursion beyond MAX_CHAIN_DEPTH.
  const requestedDepth = typeof options.maxDepth === 'number' && options.maxDepth > 0
    ? options.maxDepth
    : MAX_CHAIN_DEPTH;
  const maxDepth = Math.min(requestedDepth, MAX_CHAIN_DEPTH);

  if (depth >= maxDepth) {
    throw new ChainError(
      BridgeErrorCode.CHAIN_DEPTH_EXCEEDED,
      `Chain recursion depth exceeded (max: ${maxDepth}). Possible infinite chain loop.`,
      { maxDepth, depth },
    );
  }

  // Validate step `as` names to prevent prototype pollution of the results object
  for (const step of steps) {
    if (!step.as || typeof step.as !== 'string') {
      throw new ChainError(
        BridgeErrorCode.CHAIN_STEP_FAILED,
        `Chain step missing required "as" field`,
      );
    }
    if (DANGEROUS_KEYS.has(step.as)) {
      throw new ChainError(
        BridgeErrorCode.CHAIN_STEP_FAILED,
        `Chain step "as" name "${step.as}" is reserved and cannot be used`,
        { step: step.as },
      );
    }
    if (step.as === '_chain') {
      throw new ChainError(
        BridgeErrorCode.CHAIN_STEP_FAILED,
        `Chain step "as" name "_chain" is reserved for chain metadata`,
      );
    }
    // Reserve `args` as a step name. Without this, a step `as: "args"` collides
    // with the `$args.foo` discriminator in `resolveArgValue` — every `$args.foo`
    // is parsed as "caller args", never as "the step named args", producing silent
    // data corruption that operators find impossible to debug.
    if (step.as === 'args') {
      throw new ChainError(
        BridgeErrorCode.CHAIN_STEP_FAILED,
        `Chain step "as" name "args" is reserved (collides with $args.* references)`,
      );
    }
  }

  // Track the stack of chain-tool names actively on the call chain and refuse
  // re-entry with a clear error BEFORE any step runs. This catches invocation-level
  // cycles across chain-tools where chain-tool X's step calls chain-tool Y whose
  // step calls X.
  const incomingStack = Array.isArray(options._chainStack) ? options._chainStack : [];
  const chainStack = options._currentChainName
    ? incomingStack.concat(options._currentChainName)
    : incomingStack.slice();

  // Wrap dispatch to track depth for nested chains. Preserve the caller's
  // `_tenant` context as a non-enumerable property on each sub-dispatch's args.
  // This is attached by `tenant/scope.js` scopedDispatch. `deepResolveArgs` +
  // `Object.create(null)` + `Object.keys(node)` silently drop it because
  // Object.keys skips non-enumerable keys. Without propagation, every chain
  // sub-dispatch runs with `args._tenant === undefined`. The fix preserves
  // `_tenant` as non-enumerable so `path.js:dispatchToolCall` finds it via
  // direct property read, and the auth flow correctly injects the caller's
  // tenant credentials. The non-enumerable descriptor keeps the key invisible
  // to `Object.keys`/`Object.entries`/`JSON.stringify`. Chain step $ref
  // resolution intentionally ignores `_tenant` because `deepResolveArgs` walks
  // only enumerable own keys — a malicious chain config cannot extract
  // `$args._tenant` and leak the auth material into an outbound body.
  const callerTenant = args && typeof args === 'object' ? args._tenant : undefined;
  const depthAwareDispatch = async (name, callArgs) => {
    if (chainStack.includes(name)) {
      throw new ChainError(
        BridgeErrorCode.CHAIN_CIRCULAR_DEPENDENCY,
        `Chain invocation cycle detected: ${[...chainStack, name].join(' → ')}`,
        { stack: [...chainStack, name] },
      );
    }
    // Enforce tenant allowlist/blocklist
    // transitively on EVERY sub-dispatch. The outer `scopedDispatch`
    // (tenant/scope.js) checks ACL at the entry point only — chain sub-steps
    // invoke the raw inner `dispatch` directly, bypassing that check. An
    // attacker who adds a chain tool to a restricted tenant's allowlist can
    // then reach any downstream tool the chain declares. Re-run the check
    // here using the caller's tenant envelope so the invariant holds
    // regardless of what `dispatch` implementation is used.
    if (callerTenant && typeof callerTenant === 'object') {
      if (Array.isArray(callerTenant.allowlist) && !callerTenant.allowlist.includes(name)) {
        throw new BridgeError(
          BridgeErrorCode.AUTH_MISSING,
          `Tool "${name}" is not in tenant "${callerTenant.tenantId || '?'}" allowlist`,
          { tenantId: callerTenant.tenantId, toolName: name },
        );
      }
      if (Array.isArray(callerTenant.blocklist) && callerTenant.blocklist.includes(name)) {
        throw new BridgeError(
          BridgeErrorCode.AUTH_MISSING,
          `Tool "${name}" is blocked for tenant "${callerTenant.tenantId || '?'}"`,
          { tenantId: callerTenant.tenantId, toolName: name },
        );
      }
    }
    // Re-attach tenant context onto the sub-dispatch args. Use
    // defineProperty with enumerable:false so downstream iteration
    // continues to skip it (matching scopedDispatch's pattern).
    if (callerTenant !== undefined && callArgs && typeof callArgs === 'object') {
      Object.defineProperty(callArgs, '_tenant', {
        value: callerTenant, // callerTenant is already frozen by scope.js
        enumerable: false,
        writable: false,
        configurable: false,
      });
    }
    return dispatch(name, callArgs, {
      ...options,
      _depth: depth + 1,
      _chainStack: chainStack,
      _currentChainName: name,
    });
  };
  const results = {};
  const stepResults = {
    _chain: {
      steps: steps.length,
      completed: 0,
      failed: 0,
      errors: [],
    },
  };

  const waves = buildExecutionWaves(steps);
  const waveConcurrency = Math.max(
    1,
    Math.min(
      typeof options.maxWaveConcurrency === 'number' &&
      Number.isFinite(options.maxWaveConcurrency) &&
      options.maxWaveConcurrency > 0
        ? options.maxWaveConcurrency
        : DEFAULT_WAVE_CONCURRENCY,
      DEFAULT_WAVE_CONCURRENCY,
    ),
  );

  async function runStep(step) {
    try {
      const resolvedArgs = resolveStepArgs(step.args || {}, args, results);
      const result = await depthAwareDispatch(step.call, resolvedArgs);
      results[step.as] = result;
      stepResults[step.as] = result;
      stepResults._chain.completed += 1;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      if (step.optional) {
        // Log only the sanitized error code by default. The previous version
        // emitted the raw upstream error message, which for validation-error
        // responses commonly echoes the user's request body — a cross-tenant log
        // leak when stderr is collected into a shared aggregator. Operators who
        // need the full forensic detail can opt in via FOURDMCP_CHAIN_DEBUG=1.
        const code = safeErrorCode(error);
        if (process.env.FOURDMCP_CHAIN_DEBUG === '1') {
          process.stderr.write(`[40mcp] chain step "${step.as}" failed (optional, code=${code}): ${message}\n`);
        } else {
          process.stderr.write(`[40mcp] chain step "${step.as}" failed (optional, code=${code})\n`);
        }
        // Store failure indicator under non-reserved keys. `_error` and
        // `_error_code` are reserved, so using them caused two bugs: (1) a
        // subsequent step passing `$failedStep` (whole object) as an arg would be
        // rejected with "reserved key" — confusing failure. (2) stripInternalEnvelopes
        // strips them from results before egress, hiding step-failure indicators
        // from callers. Plain `error` / `error_code` are not reserved; they survive
        // egress and are safe to propagate through $ref expansion.
        const sanitized = { error: 'step failed', error_code: code };
        results[step.as] = sanitized;
        stepResults[step.as] = sanitized;
        stepResults._chain.completed += 1;
      } else {
        // Defensively sanitize the error code stored in `_chain.errors[]`.
        // Today the non-optional branch immediately re-throws so stepResults
        // is never returned — but the `message` field on this array is a
        // latent leak surface for any future "partial success" refactor. Store
        // the safe code only; the raw error still re-throws below and is
        // handled by bridge.js / mixer.js where NODE_ENV gating applies.
        const safeCode = safeErrorCode(error);
        stepResults._chain.failed += 1;
        stepResults._chain.errors.push({
          step: step.as,
          error_code: safeCode,
        });
        throw error;
      }
    }
  }

  for (const wave of waves) {
    // Batch the wave into chunks of waveConcurrency so an adversarial chain
    // config cannot fire an unbounded number of outbound requests in a single
    // microtask.
    for (let i = 0; i < wave.length; i += waveConcurrency) {
      const batch = wave.slice(i, i + waveConcurrency);
      await Promise.all(batch.map(runStep));
    }
  }

  // Apply chain-level response transforms if configured
  if (options.response) {
    const dataKeys = Object.keys(stepResults).filter((k) => k !== '_chain');
    for (const key of dataKeys) {
      stepResults[key] = applyResponseTransform(stepResults[key], options.response);
    }
  }

  return stepResults;
}
