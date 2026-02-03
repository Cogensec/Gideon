import { z } from 'zod';
import { StructuredToolInterface } from '@langchain/core/tools';

// ============================================================================
// Skill Interface Definitions
// ============================================================================

/**
 * Command context passed to skill command handlers
 */
export interface SkillCommandContext {
  /** Current working directory */
  cwd: string;
  /** Environment variables */
  env: Record<string, string | undefined>;
  /** Active skill sessions */
  sessions: Map<string, SkillSession>;
  /** Abort signal for cancellation */
  signal?: AbortSignal;
}

/**
 * Result returned from skill command execution
 */
export interface SkillCommandResult {
  /** Whether the command succeeded */
  success: boolean;
  /** Output message to display */
  output: string;
  /** Structured data (optional) */
  data?: unknown;
  /** Error message if failed */
  error?: string;
}

/**
 * A command provided by a skill
 */
export interface SkillCommand {
  /** Command name (e.g., 'recon', 'scan') */
  name: string;
  /** Short description */
  description: string;
  /** Usage example */
  usage: string;
  /** Detailed help text */
  help?: string;
  /** Command aliases */
  aliases?: string[];
  /** Execute the command */
  execute: (args: string[], ctx: SkillCommandContext) => Promise<SkillCommandResult>;
}

/**
 * Skill session for stateful operations
 */
export interface SkillSession {
  /** Session ID */
  id: string;
  /** Skill that owns this session */
  skillId: string;
  /** Session start time */
  startedAt: Date;
  /** Session state data */
  state: Record<string, unknown>;
}

/**
 * Skill capability flags
 */
export interface SkillCapabilities {
  /** Skill provides LangChain tools */
  providesTools: boolean;
  /** Skill requires GPU acceleration */
  requiresGpu: boolean;
  /** Skill supports CPU fallback */
  supportsCpuFallback: boolean;
  /** Skill maintains session state */
  stateful: boolean;
  /** Skill requires external service */
  requiresExternalService: boolean;
}

/**
 * Skill configuration schema
 */
export interface SkillConfig {
  /** Whether skill is enabled */
  enabled: boolean;
  /** Skill-specific settings */
  settings: Record<string, unknown>;
}

/**
 * Skill metadata
 */
export interface SkillMetadata {
  /** Unique skill identifier */
  id: string;
  /** Display name */
  name: string;
  /** Description of what the skill does */
  description: string;
  /** Semantic version */
  version: string;
  /** Skill author */
  author?: string;
  /** Skill category */
  category: SkillCategory;
  /** Capability flags */
  capabilities: SkillCapabilities;
  /** Required environment variables */
  requiredEnvVars?: string[];
  /** Optional environment variables */
  optionalEnvVars?: string[];
}

/**
 * Skill categories for organization
 */
export type SkillCategory =
  | 'security-research'
  | 'threat-detection'
  | 'data-analytics'
  | 'code-analysis'
  | 'voice'
  | 'governance'
  | 'integration'
  | 'utility';

/**
 * Main Skill interface - all skills must implement this
 */
export interface Skill {
  /** Skill metadata */
  metadata: SkillMetadata;

  /** Commands provided by this skill */
  commands: SkillCommand[];

  /** LangChain tools provided by this skill (optional) */
  tools?: StructuredToolInterface[];

  /**
   * Initialize the skill
   * Called when skill is loaded/enabled
   */
  initialize?: (config?: SkillConfig) => Promise<void>;

  /**
   * Shutdown the skill
   * Called when skill is unloaded/disabled
   */
  shutdown?: () => Promise<void>;

  /**
   * Check if skill is available (dependencies met)
   */
  isAvailable: () => Promise<boolean>;

  /**
   * Get skill health status
   */
  getStatus?: () => Promise<SkillStatus>;
}

/**
 * Skill health status
 */
export interface SkillStatus {
  /** Whether skill is operational */
  healthy: boolean;
  /** Status message */
  message: string;
  /** Last check timestamp */
  checkedAt: Date;
  /** Service-specific details */
  details?: Record<string, unknown>;
}

// ============================================================================
// Skill Registry Types
// ============================================================================

/**
 * Registered skill entry
 */
export interface RegisteredSkill {
  skill: Skill;
  enabled: boolean;
  loadedAt: Date;
  config?: SkillConfig;
}

/**
 * Skill load result
 */
export interface SkillLoadResult {
  success: boolean;
  skillId: string;
  error?: string;
}

// ============================================================================
// Zod Schemas for Validation
// ============================================================================

export const SkillCategorySchema = z.enum([
  'security-research',
  'threat-detection',
  'data-analytics',
  'code-analysis',
  'voice',
  'governance',
  'integration',
  'utility',
]);

export const SkillCapabilitiesSchema = z.object({
  providesTools: z.boolean(),
  requiresGpu: z.boolean(),
  supportsCpuFallback: z.boolean(),
  stateful: z.boolean(),
  requiresExternalService: z.boolean(),
});

export const SkillMetadataSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string(),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  author: z.string().optional(),
  category: SkillCategorySchema,
  capabilities: SkillCapabilitiesSchema,
  requiredEnvVars: z.array(z.string()).optional(),
  optionalEnvVars: z.array(z.string()).optional(),
});

export const SkillConfigSchema = z.object({
  enabled: z.boolean(),
  settings: z.record(z.unknown()),
});
