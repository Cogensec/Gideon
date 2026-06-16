import { readFileSync, existsSync } from 'fs';
import { parse } from 'yaml';
import { z } from 'zod';

const SourceConfigSchema = z.object({
  enabled: z.boolean(),
  base_url: z.string().optional(),
  rate_limit: z.number().optional(),
  cache_ttl: z.number().optional(),
});

const GovernanceConfigSchema = z.object({
  enabled: z.boolean().default(true),
  registry: z.object({
    auto_activate_trusted: z.boolean().default(false),
    trusted_sources: z.array(z.string()).default([]),
    max_agents_per_owner: z.number().default(10),
    stale_threshold_minutes: z.number().default(30),
  }).optional(),
  policies: z.object({
    default_action: z.enum(['allow', 'deny', 'audit']).default('allow'),
    realtime_evaluation: z.boolean().default(true),
    log_all_evaluations: z.boolean().default(false),
  }).optional(),
  monitoring: z.object({
    behavioral_profiling: z.boolean().default(true),
    anomaly_sensitivity: z.number().min(0).max(1).default(0.7),
    activity_buffer_size: z.number().default(1000),
    auto_quarantine_critical: z.boolean().default(true),
  }).optional(),
  access_control: z.object({
    default_expiry_hours: z.number().default(0),
    require_justification: z.boolean().default(true),
    auto_cleanup_expired: z.boolean().default(true),
  }).optional(),
  audit: z.object({
    hash_chain_enabled: z.boolean().default(true),
    retention_days: z.number().default(30),
    max_log_size: z.number().default(10485760),
    auto_compliance_report: z.boolean().default(false),
  }).optional(),
}).optional();

const MemoryConfigSchema = z.object({
  enabled: z.boolean().default(true),
  inject: z.boolean().default(true),
  max_facts: z.number().default(500),
  // Which scopes are eligible for injection during a defensive turn.
  scopes: z.array(z.enum(['defensive', 'redteam', 'shared'])).default(['defensive', 'shared']),
}).optional();

const LearningConfigSchema = z.object({
  enabled: z.boolean().default(true),
  review_after_turn: z.boolean().default(true),
  max_learned_skills: z.number().default(50),
  min_confidence: z.number().min(0).max(1).default(0.6),
}).optional();

const CompressionConfigSchema = z.object({
  enabled: z.boolean().default(true),
  threshold_tokens: z.number().default(12000),
  tail_tokens: z.number().default(4000),
  head_items: z.number().default(3),
  min_savings_ratio: z.number().min(0).max(1).default(0.1),
}).optional();

const InsightsConfigSchema = z.object({
  enabled: z.boolean().default(true),
  redact_findings: z.boolean().default(true),
}).optional();

const GideonConfigSchema = z.object({
  sources: z.record(z.string(), SourceConfigSchema),
  output: z.object({
    formats: z.array(z.enum(['markdown', 'json', 'stix'])),
    directory: z.string(),
    include_stix: z.boolean(),
    redaction: z.object({
      enabled: z.boolean(),
      patterns: z.array(z.string()),
    }),
  }),
  agent: z.object({
    max_iterations: z.number(),
    confidence_threshold: z.number(),
    min_corroboration_sources: z.number(),
    enable_verification: z.boolean(),
  }),
  safety: z.object({
    defensive_mode: z.boolean(),
    block_offensive: z.boolean(),
    require_explicit_auth: z.boolean(),
  }),
  governance: GovernanceConfigSchema,
  memory: MemoryConfigSchema,
  learning: LearningConfigSchema,
  compression: CompressionConfigSchema,
  insights: InsightsConfigSchema,
});

export type GideonConfig = z.infer<typeof GideonConfigSchema>;
export type SourceConfig = z.infer<typeof SourceConfigSchema>;
export type GovernanceConfig = z.infer<typeof GovernanceConfigSchema>;
export type MemoryConfig = NonNullable<z.infer<typeof MemoryConfigSchema>>;
export type LearningConfig = NonNullable<z.infer<typeof LearningConfigSchema>>;
export type CompressionConfig = NonNullable<z.infer<typeof CompressionConfigSchema>>;
export type InsightsConfig = NonNullable<z.infer<typeof InsightsConfigSchema>>;

// Defaults applied when a section is omitted from gideon.config.yaml.
const MEMORY_DEFAULTS: MemoryConfig = { enabled: true, inject: true, max_facts: 500, scopes: ['defensive', 'shared'] };
const LEARNING_DEFAULTS: LearningConfig = { enabled: true, review_after_turn: true, max_learned_skills: 50, min_confidence: 0.6 };
const COMPRESSION_DEFAULTS: CompressionConfig = { enabled: true, threshold_tokens: 12000, tail_tokens: 4000, head_items: 3, min_savings_ratio: 0.1 };
const INSIGHTS_DEFAULTS: InsightsConfig = { enabled: true, redact_findings: true };

/** Load a config section, falling back to defaults if config is unavailable. */
function loadSection<T>(pick: (c: GideonConfig) => T | undefined, fallback: T): T {
  try {
    return pick(loadConfig()) ?? fallback;
  } catch {
    return fallback;
  }
}

export function getMemoryConfig(): MemoryConfig {
  return loadSection((c) => c.memory, MEMORY_DEFAULTS);
}

export function getLearningConfig(): LearningConfig {
  return loadSection((c) => c.learning, LEARNING_DEFAULTS);
}

export function getCompressionConfig(): CompressionConfig {
  return loadSection((c) => c.compression, COMPRESSION_DEFAULTS);
}

export function getInsightsConfig(): InsightsConfig {
  return loadSection((c) => c.insights, INSIGHTS_DEFAULTS);
}

let cachedConfig: GideonConfig | null = null;

/**
 * Load and parse the Gideon configuration file
 */
export function loadConfig(): GideonConfig {
  if (cachedConfig) return cachedConfig;

  const configPath = process.env.GIDEON_CONFIG || './gideon.config.yaml';

  if (!existsSync(configPath)) {
    throw new Error(`Configuration file not found: ${configPath}`);
  }

  const configFile = readFileSync(configPath, 'utf-8');
  const parsed = parse(configFile);

  cachedConfig = GideonConfigSchema.parse(parsed);
  return cachedConfig;
}

/**
 * Get configuration for a specific source
 */
export function getSourceConfig(sourceName: string): SourceConfig | undefined {
  try {
    const config = loadConfig();
    return config.sources[sourceName];
  } catch {
    // Config not available, return undefined
    return undefined;
  }
}

/**
 * Reset cached configuration (useful for testing)
 */
export function resetConfig(): void {
  cachedConfig = null;
}
