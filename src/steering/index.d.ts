/**
 * 40mcp/steering — TypeScript declarations for the steering subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/steering'`.
 * See SPEC.md §2 ("Steering module") and §5 (schema/hook surface may change pre-1.0).
 */

// ─── Schema constants ───────────────────────────────────────────────────────

export type MemoryType =
  | 'correction'
  | 'decision'
  | 'observation'
  | 'inference'
  | 'fact'
  | 'hypothesis'
  | 'assumption'
  | 'reference';

export declare const MEMORY_TYPES: readonly MemoryType[];

export interface NumericRange {
  readonly min: number;
  readonly max: number;
}

export declare const CONFIDENCE_RANGE: NumericRange;
export declare const IMPORTANCE_RANGE: NumericRange;

export interface DecayPolicy {
  /** 'permanent' | 'archive' | 'decay' */
  readonly class: 'permanent' | 'archive' | 'decay';
  readonly halfLifeDays: number | null;
  readonly minConfidenceToRetain: number;
}

export declare const DECAY_POLICIES: Readonly<Record<MemoryType, DecayPolicy>>;

export interface SteeringFieldSchema {
  type: 'string' | 'number';
  enum?: readonly string[];
  minimum?: number;
  maximum?: number;
  description: string;
}

export declare const STEERING_WRITE_REQUIRED_FIELDS: Readonly<{
  memory_type: SteeringFieldSchema;
  confidence: SteeringFieldSchema;
  importance: SteeringFieldSchema;
}>;

// ─── Apply ──────────────────────────────────────────────────────────────────

export interface SteeringToolConfig {
  write?: boolean;
  authority?: string | AuthoritySpec | Authority;
  prehook?: string | { instructions?: string; [key: string]: unknown };
  posthook?: string | { instructions?: string; conditional?: boolean; [key: string]: unknown };
}

export interface SteerableTool {
  name?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, unknown>;
    required?: string[];
    [key: string]: unknown;
  };
  steering?: SteeringToolConfig;
  [key: string]: unknown;
}

/** Inject steering fields into a tool's inputSchema when steering.write === true. Pure. */
export function applySteering<T extends SteerableTool>(tool: T): T;

/** Lookup helper — throws on unknown memory_type. */
export function deriveDecayPolicy(memory_type: MemoryType | string): DecayPolicy;

export interface Classification {
  memory_type: MemoryType;
  confidence: number;
  importance: number;
  decay_policy: DecayPolicy;
}

/** Normalize + validate a steered write. Throws on invalid memory_type / out-of-range values. */
export function classifyWrite(args: {
  memory_type: MemoryType | string;
  confidence: number;
  importance: number;
  [key: string]: unknown;
}): Classification;

// ─── Hooks ──────────────────────────────────────────────────────────────────

export interface PrehookResult {
  args: Record<string, unknown>;
  classification: Classification | null;
  instructions: string | null;
  authority: Authority | null;
}

export interface PosthookResult<T = unknown> {
  result: T;
  instructions: string | null;
}

export function runPrehook(
  tool: SteerableTool,
  args: Record<string, unknown>,
): PrehookResult;

export function runPosthook<T>(
  tool: SteerableTool,
  result: T,
  ctx?: { classification?: Classification | null },
): PosthookResult<T>;

/** Attach a steering envelope (instructions, classification) onto a tool result. */
export function attachSteeringEnvelope<T>(
  result: T,
  envelope: { instructions?: string | null; classification?: Classification | null; [key: string]: unknown },
): T;

// ─── Authority ──────────────────────────────────────────────────────────────

export interface AuthoritySpec {
  id?: string;
  allowed_memory_types?: readonly (MemoryType | string)[];
  max_confidence?: number;
  max_importance?: number;
  allowed_scopes?: readonly string[] | null;
}

export interface Authority {
  readonly id: string;
  readonly allowed_memory_types: readonly MemoryType[];
  readonly max_confidence: number;
  readonly max_importance: number;
  readonly allowed_scopes: readonly string[] | null;
}

/** Build a frozen Authority from a plain spec. Factory function — call without `new`. Validates shape; throws on invalid input. */
export function Authority(spec: AuthoritySpec): Authority;

/** Built-in authority presets. Resolve by name or as literal objects. */
export declare const AUTHORITIES: Readonly<{
  READONLY: Authority;
  OBSERVER: Authority;
  RESEARCHER: Authority;
  DECIDER: Authority;
  ROOT: Authority;
}>;

export type AuthorityRef = keyof typeof AUTHORITIES | Authority | AuthoritySpec;

/** Resolve a preset name, Authority, or spec into a canonical Authority. Throws on unknown names. */
export function resolveAuthority(ref: AuthorityRef): Authority;

export interface AuthorityCheckResult {
  allowed: boolean;
  reason: string | null;
}

/** Check a classified write against an Authority. Pure — does not throw. */
export function checkAuthority(
  authority: Authority,
  classified: {
    memory_type: MemoryType | string;
    confidence: number;
    importance: number;
    coordination_scope?: string;
  },
): AuthorityCheckResult;

// ─── Memory ─────────────────────────────────────────────────────────────────

export type ReleaseOutcome = 'persisted' | 'discarded' | 'escalated';

export declare const RELEASE_OUTCOMES: readonly ReleaseOutcome[];

export type AgenticDispatchFn = (
  toolName: string,
  args: Record<string, unknown>,
) => Promise<unknown>;

export interface AgenticMemoryOptions {
  dispatch: AgenticDispatchFn;
  /** Authority preset name, spec, or Authority. Defaults to READONLY (deny-all). */
  authority?: AuthorityRef;
  /** Defaults: 'memory_write'. */
  writeTool?: string;
  /** Defaults: 'mem_release'. */
  releaseTool?: string;
  /** Defaults: 'memory_read'. */
  readTool?: string;
}

export interface AgenticMemoryWriteArgs {
  content: string;
  memory_type: MemoryType | string;
  confidence: number;
  importance: number;
  agent_id?: string;
  coordination_scope?: string;
  [key: string]: unknown;
}

export interface AgenticMemoryReleaseArgs {
  handle_id: string;
  outcome: ReleaseOutcome;
  note?: string;
}

export declare class AgenticMemory {
  constructor(opts: AgenticMemoryOptions);
  readonly dispatch: AgenticDispatchFn;
  readonly authority: Authority;
  readonly writeTool: string;
  readonly releaseTool: string;
  readonly readTool: string;
  write(args: AgenticMemoryWriteArgs): Promise<unknown>;
  release(args: AgenticMemoryReleaseArgs): Promise<unknown>;
  read(args?: Record<string, unknown>): Promise<unknown>;
}

export function createAgenticMemory(opts: AgenticMemoryOptions): AgenticMemory;
