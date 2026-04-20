/**
 * Transform interface shell.
 *
 * A Transform is anything that rewrites the component surface at build-time,
 * the dispatch args at call-time, or the result payload at call-time. The
 * interface is pure duck typing — there is no class hierarchy. Any object
 * with the shape below satisfies the contract:
 *
 *   {
 *     name: string,                                         // stable identity
 *     applyToComponents?(components) => components,         // build-time
 *     applyToDispatch?(toolName, args, context) => args,    // call-time pre-dispatch
 *     applyToResult?(toolName, result, context) => result,  // call-time pre-egress
 *   }
 *
 * `name` is required so audit logs and diagnostics can attribute a decision
 * back to the Transform that made it. All three methods are optional; most
 * existing transforms implement only one. The interface is deliberately
 * duck-typed on `name` plus at least one of the three methods.
 *
 * ### What this module ships
 *
 * - `createTransform({ name, applyToComponents?, applyToDispatch?, applyToResult? })`
 *   — validating factory that returns a frozen Transform-conformant object.
 * - `composeTransforms(...transforms)` — helper that takes an array of
 *   Transforms and returns a composite Transform. Each method on the composite
 *   threads its input through every constituent Transform that implements
 *   that method, in order. Missing methods on individual constituents are
 *   no-ops in the composite.
 *
 * ### What this module does NOT ship
 *
 * - Bridge integration. The canonical pipeline order (SPEC §2 "Pipeline
 *   order") documents where `applyToDispatch` and `applyToResult`
 *   will run once Transform is wired into `src/bridge.js`. That wiring lands
 *   in a future PR.
 * - Any refactor of `src/transforms/response.js` (`applyResponseTransform`).
 *   That module remains the stable 1.0 surface. Wrapping it as a
 *   Transform-conformant object is deferred.
 *
 * @module transforms
 */

/**
 * Tool-name / prefix character charset and length, pinned in SPEC.md §2
 * ("Tool-name invariant"): `^[a-zA-Z0-9_-]{1,64}$`. Transform names share
 * the same identifier universe as Provider names and tool prefixes so that
 * audit logs and diagnostics can reference them by a single, consistent
 * charset. The same regex is used by `createProvider`.
 */
const TRANSFORM_NAME_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * The three optional method names. Kept as a single source of truth so
 * `createTransform` validation and `composeTransforms` iteration stay in
 * lockstep.
 */
const APPLY_METHODS = Object.freeze([
  'applyToComponents',
  'applyToDispatch',
  'applyToResult',
]);

/**
 * Construct a Transform-conformant object.
 *
 * Validates:
 *   - `name` is a non-empty string matching the prefix regex from SPEC §2.
 *   - At least one of `applyToComponents`, `applyToDispatch`, `applyToResult`
 *     is provided.
 *   - Every provided apply-method is a function.
 *
 * Returns a frozen object so callers cannot accidentally mutate `name` or
 * swap an apply-method after registration. Missing methods are left absent
 * on the returned object (rather than set to `undefined`) so callers can
 * duck-check with `'applyToResult' in transform`.
 *
 * @param {object} spec
 * @param {string} spec.name - Stable Transform identity (matches `^[a-zA-Z0-9_-]{1,64}$`).
 * @param {(components: object) => object} [spec.applyToComponents]
 *   Build-time: reshape `{ tools, resources?, prompts? }` before publish.
 * @param {(toolName: string, args: object, context: object) => object} [spec.applyToDispatch]
 *   Call-time: reshape the request args before dispatch.
 * @param {(toolName: string, result: any, context: object) => any} [spec.applyToResult]
 *   Call-time: reshape the result payload before egress-sanitize.
 * @returns {Readonly<object>} frozen Transform-conformant object.
 */
export function createTransform(spec) {
  if (spec == null || typeof spec !== 'object') {
    throw new TypeError(
      'createTransform({ name, applyToComponents?, applyToDispatch?, applyToResult? }) requires an object spec.',
    );
  }

  const { name } = spec;

  if (typeof name !== 'string' || name.length === 0) {
    throw new TypeError(
      'createTransform: `name` must be a non-empty string.',
    );
  }
  if (!TRANSFORM_NAME_REGEX.test(name)) {
    throw new TypeError(
      `createTransform: \`name\` "${name}" does not match the tool-prefix regex ` +
      `${TRANSFORM_NAME_REGEX} pinned in SPEC.md §2 (Tool-name invariant). ` +
      'Transform names share the tool-prefix namespace; allowed charset is ' +
      '[a-zA-Z0-9_-], 1-64 chars.',
    );
  }

  const transform = { name };
  let methodCount = 0;
  for (const methodName of APPLY_METHODS) {
    const fn = spec[methodName];
    if (fn === undefined) continue;
    if (typeof fn !== 'function') {
      throw new TypeError(
        `createTransform: \`${methodName}\`, if provided, must be a function.`,
      );
    }
    transform[methodName] = fn;
    methodCount += 1;
  }

  if (methodCount === 0) {
    throw new TypeError(
      'createTransform: must provide at least one of ' +
      '`applyToComponents`, `applyToDispatch`, or `applyToResult`. ' +
      'A Transform with zero apply-methods has no seam to attach to.',
    );
  }

  return Object.freeze(transform);
}

/**
 * Compose N Transforms into a single Transform.
 *
 * For each of the three apply-methods, the composite calls every
 * constituent Transform that implements that method in the given order,
 * threading output -> input. A constituent that doesn't implement a given
 * method is a no-op for that method.
 *
 * The composite only surfaces a method if at least one constituent
 * implements it. That keeps the duck-typed check `'applyToResult' in
 * composite` meaningful: callers can still tell whether any result-shaping
 * happens across the whole pipeline.
 *
 * Edge cases:
 *   - `composeTransforms()` with zero args returns a Transform with all
 *     three apply-methods present, each an identity pass-through. This
 *     lets callers use it as a sentinel "no-op" Transform.
 *   - `composeTransforms(single)` surfaces exactly the methods `single`
 *     implements, each calling through to `single`.
 *
 * @param {...object} transforms - Zero or more Transform-conformant objects.
 * @returns {Readonly<object>} frozen composite Transform.
 */
export function composeTransforms(...transforms) {
  // Zero-arg case: return a universal identity Transform so callers can
  // use it as a no-op sentinel in pipelines that always want to invoke
  // all three seams.
  if (transforms.length === 0) {
    return Object.freeze({
      name: 'compose:empty',
      applyToComponents: (components) => components,
      applyToDispatch: (_toolName, args, _context) => args,
      applyToResult: (_toolName, result, _context) => result,
    });
  }

  const composite = { name: 'compose(' + transforms.map((t) => t?.name ?? '?').join(',') + ')' };

  if (transforms.some((t) => typeof t?.applyToComponents === 'function')) {
    composite.applyToComponents = (components) => {
      let current = components;
      for (const t of transforms) {
        if (typeof t?.applyToComponents === 'function') {
          current = t.applyToComponents(current);
        }
      }
      return current;
    };
  }

  if (transforms.some((t) => typeof t?.applyToDispatch === 'function')) {
    composite.applyToDispatch = (toolName, args, context) => {
      let current = args;
      for (const t of transforms) {
        if (typeof t?.applyToDispatch === 'function') {
          current = t.applyToDispatch(toolName, current, context);
        }
      }
      return current;
    };
  }

  if (transforms.some((t) => typeof t?.applyToResult === 'function')) {
    composite.applyToResult = (toolName, result, context) => {
      let current = result;
      for (const t of transforms) {
        if (typeof t?.applyToResult === 'function') {
          current = t.applyToResult(toolName, current, context);
        }
      }
      return current;
    };
  }

  return Object.freeze(composite);
}
