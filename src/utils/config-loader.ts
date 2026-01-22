import { readFileSync, existsSync } from 'fs';
import { parse } from 'yaml';
import { z } from 'zod';

const SourceConfigSchema = z.object({
  enabled: z.boolean(),
  base_url: z.string().optional(),
  rate_limit: z.number().optional(),
  cache_ttl: z.number().optional(),
});

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
});

export type GideonConfig = z.infer<typeof GideonConfigSchema>;
export type SourceConfig = z.infer<typeof SourceConfigSchema>;

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
