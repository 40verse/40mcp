/**
 * Agent Steering — forced-inference write classification.
 *
 * Barrel export for schema and apply modules.
 * @module steering
 */

export {
  MEMORY_TYPES,
  CONFIDENCE_RANGE,
  IMPORTANCE_RANGE,
  DECAY_POLICIES,
  STEERING_WRITE_REQUIRED_FIELDS,
} from './schema.js';

export {
  applySteering,
  classifyWrite,
  deriveDecayPolicy,
} from './apply.js';

export {
  runPrehook,
  runPosthook,
  attachSteeringEnvelope,
} from './hooks.js';

export {
  Authority,
  AUTHORITIES,
  resolveAuthority,
  checkAuthority,
} from './authority.js';

export {
  AgenticMemory,
  createAgenticMemory,
  RELEASE_OUTCOMES,
} from './memory.js';
