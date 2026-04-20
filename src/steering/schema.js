/**
 * Agent Steering schema — constants for forced-inference write classification.
 *
 * Defines memory_type enum, importance/confidence ranges, and decay policies.
 * Used by tools that opt into steering.write: true to enforce classification at write time.
 *
 * @module steering/schema
 */

/**
 * Valid memory types for steered writes.
 * Each type determines a decay policy applied at write time.
 * @type {string[]}
 */
export const MEMORY_TYPES = Object.freeze([
  'correction',
  'decision',
  'observation',
  'inference',
  'fact',
  'hypothesis',
  'assumption',
  'reference',
]);

/**
 * Confidence score range.
 * Used by tools to signal how certain they are about a write.
 * @type {{ min: number, max: number }}
 */
export const CONFIDENCE_RANGE = Object.freeze({ min: 0, max: 1 });

/**
 * Importance score range.
 * Used by tools to signal priority for retention/replaying.
 * @type {{ min: number, max: number }}
 */
export const IMPORTANCE_RANGE = Object.freeze({ min: 0, max: 1 });

/**
 * Decay policies keyed by memory_type.
 * Each policy specifies: class (permanent|archive|decay), halfLifeDays, minConfidenceToRetain.
 *
 * - permanent: never decays, always retained
 * - archive: moved to cold storage after halfLifeDays, fully retained
 * - decay: confidence-weighted expiry after halfLifeDays
 *
 * @type {Object<string, { class: string, halfLifeDays: number | null, minConfidenceToRetain: number }>}
 */
export const DECAY_POLICIES = Object.freeze({
  correction: {
    class: 'permanent',
    halfLifeDays: null,
    minConfidenceToRetain: 0,
  },
  decision: {
    class: 'permanent',
    halfLifeDays: null,
    minConfidenceToRetain: 0,
  },
  observation: {
    class: 'archive',
    halfLifeDays: 365,
    minConfidenceToRetain: 0.5,
  },
  fact: {
    class: 'archive',
    halfLifeDays: 365,
    minConfidenceToRetain: 0.5,
  },
  reference: {
    class: 'archive',
    halfLifeDays: 365,
    minConfidenceToRetain: 0.3,
  },
  inference: {
    class: 'decay',
    halfLifeDays: 30,
    minConfidenceToRetain: 0.7,
  },
  hypothesis: {
    class: 'decay',
    halfLifeDays: 14,
    minConfidenceToRetain: 0.6,
  },
  assumption: {
    class: 'decay',
    halfLifeDays: 60,
    minConfidenceToRetain: 0.5,
  },
});

/**
 * JSON Schema fragment for steering write fields.
 * Merged into tool.inputSchema.properties for tools with steering.write: true.
 *
 * @type {Object}
 */
export const STEERING_WRITE_REQUIRED_FIELDS = Object.freeze({
  memory_type: {
    type: 'string',
    enum: MEMORY_TYPES,
    description: 'Classification of this write: correction, decision, observation, inference, fact, hypothesis, assumption, or reference',
  },
  confidence: {
    type: 'number',
    minimum: CONFIDENCE_RANGE.min,
    maximum: CONFIDENCE_RANGE.max,
    description: 'Confidence score (0..1) — how certain this write is',
  },
  importance: {
    type: 'number',
    minimum: IMPORTANCE_RANGE.min,
    maximum: IMPORTANCE_RANGE.max,
    description: 'Importance score (0..1) — priority for retention/replaying',
  },
});
