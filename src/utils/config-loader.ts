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

const GideonConfigSchema = z.object({
  sources: z.record(SourceConfigSchema),
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
});

export type GideonConfig = z.infer<typeof GideonConfigSchema>;
export type SourceConfig = z.infer<typeof SourceConfigSchema>;
export type GovernanceConfig = z.infer<typeof GovernanceConfigSchema>;

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
