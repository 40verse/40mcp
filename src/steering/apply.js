/**
 * Agent Steering application — merge steering fields into tool schemas at setup time.
 *
 * Functions:
 * - applySteering: enriches tool inputSchema with required steering fields
 * - classifyWrite: derives decay policy from validated args
 * - deriveDecayPolicy: lookup helper
 *
 * @module steering/apply
 */

import {
  MEMORY_TYPES,
  STEERING_WRITE_REQUIRED_FIELDS,
  DECAY_POLICIES,
  CONFIDENCE_RANGE,
  IMPORTANCE_RANGE,
} from './schema.js';

/**
 * Apply steering to a tool: if tool.steering.write === true, inject required fields into inputSchema.
 * Pure function — does not mutate the input tool.
 *
 * @param {object} tool - Tool definition
 * @returns {object} New tool with enriched inputSchema (if steering.write), or original tool
 */
export function applySteering(tool) {
  if (!tool.steering || tool.steering.write !== true) {
    return tool;
  }

  // Merge steering fields into inputSchema
  const schema = tool.inputSchema || { type: 'object', properties: {}, required: [] };
  const existingProps = schema.properties || {};
  const existingRequired = schema.required || [];

  // Steering fields MUST take precedence over existing properties. An operator
  // or compromised upstream config could shadow the steering fields with
  // definitions that lacked the required `enum`/range constraints — effectively
  // removing type safety. Steering schema is authoritative.
  const mergedProps = {
    ...existingProps,
    ...STEERING_WRITE_REQUIRED_FIELDS,
  };

  // Add steering field names to required (preserve existing required, avoid duplicates)
  const steeringFields = ['memory_type', 'confidence', 'importance'];
  const mergedRequired = [
    ...new Set([...steeringFields, ...existingRequired]),
  ];

  const newSchema = {
    ...schema,
    properties: mergedProps,
    required: mergedRequired,
  };

  return {
    ...tool,
    inputSchema: newSchema,
  };
}

/**
 * Derive the decay policy for a given memory_type.
 * Throws if memory_type is invalid.
 *
 * @param {string} memory_type - Must be in MEMORY_TYPES enum
 * @returns {object} Decay policy object from DECAY_POLICIES
 * @throws {Error} if memory_type is unknown
 */
export function deriveDecayPolicy(memory_type) {
  if (!MEMORY_TYPES.includes(memory_type)) {
    throw new Error(
      `Unknown memory_type "${memory_type}". Must be one of: ${MEMORY_TYPES.join(', ')}`,
    );
  }
  return DECAY_POLICIES[memory_type];
}

/**
 * Classify a validated write call — extract steering metadata and derive decay policy.
 * Assumes args has already been validated and memory_type/confidence/importance are present.
 *
 * @param {object} args - Tool arguments (must include memory_type, confidence, importance)
 * @returns {object} Classification: { memory_type, confidence, importance, decay_policy }
 * @throws {Error} if memory_type is unknown
 */
export function classifyWrite(args) {
  const { memory_type, confidence, importance } = args;

  // Defensive: validator should have caught this, but verify at runtime
  if (!memory_type) {
    throw new Error('memory_type is required for steered writes');
  }

  // Previously neither `confidence` nor `importance` was range-checked here
  // even though the schema declares `CONFIDENCE_RANGE = {0,1}` and
  // `IMPORTANCE_RANGE = {0,1}`. A caller
  // passing `confidence: -999` or `importance: "not a number"` would
  // flow straight into the audit log with the bogus value, and any
  // downstream consumer relying on the documented range contract would
  // misbehave. Validate explicitly and throw a typed error.
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) ||
      confidence < CONFIDENCE_RANGE.min || confidence > CONFIDENCE_RANGE.max) {
    throw new Error(
      `confidence must be a number in [${CONFIDENCE_RANGE.min}, ${CONFIDENCE_RANGE.max}]`,
    );
  }
  if (typeof importance !== 'number' || !Number.isFinite(importance) ||
      importance < IMPORTANCE_RANGE.min || importance > IMPORTANCE_RANGE.max) {
    throw new Error(
      `importance must be a number in [${IMPORTANCE_RANGE.min}, ${IMPORTANCE_RANGE.max}]`,
    );
  }

  const decay_policy = deriveDecayPolicy(memory_type);

  return {
    memory_type,
    confidence,
    importance,
    decay_policy,
  };
}
