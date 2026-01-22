# Gideon Transformation Plan
## File-by-File Change Specification

---

## Phase 1: Project Renaming & Core Configuration

### 1.1 Package & Project Metadata

#### **package.json** [EDIT]
Changes:
- `name`: "dexter-ts" → "gideon"
- `description`: "Dexter - AI agent for deep financial research." → "Gideon - Autonomous cybersecurity operations assistant."
- `bin`: "dexter-ts" → "gideon"
- Add new dependencies:
  - `yaml`: "^2.3.4" (config file parsing)
  - `node-cache`: "^5.1.2" (in-memory caching)
  - `bottleneck`: "^2.19.5" (rate limiting)
- Dev dependencies:
  - Keep existing test framework (Bun test)

#### **env.example** [CREATE]
New file for environment template:
```env
# LLM Provider API Keys
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_API_KEY=
XAI_API_KEY=
OLLAMA_BASE_URL=http://127.0.0.1:11434

# Security Data Sources
NVD_API_KEY=
CISA_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

# Optional: Web search
TAVILY_API_KEY=

# Application Settings
GIDEON_OUTPUT_DIR=./outputs
GIDEON_LOG_LEVEL=info
```

#### **gideon.config.yaml** [CREATE]
Configuration file for sources and behavior:
```yaml
# Gideon Configuration

sources:
  nvd:
    enabled: true
    base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    rate_limit: 5  # requests per second
    cache_ttl: 900  # 15 minutes

  cisa_kev:
    enabled: true
    base_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cache_ttl: 3600  # 1 hour

  virustotal:
    enabled: true
    base_url: "https://www.virustotal.com/api/v3"
    rate_limit: 4  # requests per minute (free tier)
    cache_ttl: 300  # 5 minutes

  abuseipdb:
    enabled: true
    base_url: "https://api.abuseipdb.com/api/v2"
    rate_limit: 1000  # requests per day
    cache_ttl: 600  # 10 minutes

output:
  formats:
    - markdown
    - json
  directory: ./outputs
  include_stix: false

  redaction:
    enabled: true
    patterns:
      - "(?i)(api[_-]?key|token|password|secret)\\s*[:=]\\s*['\"]?([^'\"\\s]{8,})"
      - "(?i)(bearer\\s+[a-zA-Z0-9\\-_]+\\.?[a-zA-Z0-9\\-_]*\\.?[a-zA-Z0-9\\-_]*)"

agent:
  max_iterations: 10
  confidence_threshold: 0.6
  min_corroboration_sources: 2
  enable_verification: true

safety:
  defensive_mode: true
  block_offensive: true
  require_explicit_auth: false  # Change to true for production
```

---

## Phase 2: Core Infrastructure Changes

### 2.1 Directory Structure Changes

#### **Create new directories:**
```
src/
  tools/
    security/          [NEW] - Security connectors
    search/            [KEEP] - Web search (Tavily)
  commands/            [NEW] - CLI command handlers
  verification/        [NEW] - Verification & confidence scoring
  output/              [NEW] - Output generators (MD, JSON, STIX)
  utils/
    cache.ts           [NEW] - Caching utilities
    rate-limiter.ts    [NEW] - Rate limiting
    config-loader.ts   [NEW] - YAML config loading
    redactor.ts        [NEW] - Sensitive data redaction

.gideon/               [NEW] - Application data directory
  scratchpad/          [NEW] - Agent work logs
  cache/               [NEW] - Response cache files
```

#### **Delete finance-specific directories:**
```
src/tools/finance/     [DELETE] - All financial data connectors
```

---

### 2.2 Configuration System

#### **src/utils/config-loader.ts** [CREATE]
Loads and validates `gideon.config.yaml`:
```typescript
import { readFileSync } from 'fs';
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

let cachedConfig: GideonConfig | null = null;

export function loadConfig(): GideonConfig {
  if (cachedConfig) return cachedConfig;

  const configPath = process.env.GIDEON_CONFIG || './gideon.config.yaml';
  const configFile = readFileSync(configPath, 'utf-8');
  const parsed = parse(configFile);

  cachedConfig = GideonConfigSchema.parse(parsed);
  return cachedConfig;
}

export function getSourceConfig(sourceName: string) {
  const config = loadConfig();
  return config.sources[sourceName];
}
```

#### **src/utils/cache.ts** [CREATE]
In-memory caching with TTL:
```typescript
import NodeCache from 'node-cache';
import { createHash } from 'crypto';

const cache = new NodeCache({
  stdTTL: 900, // Default 15 minutes
  checkperiod: 120, // Check for expired keys every 2 minutes
  useClones: false,
});

export function getCached<T>(key: string): T | undefined {
  return cache.get<T>(key);
}

export function setCached<T>(key: string, value: T, ttl?: number): void {
  cache.set(key, value, ttl || 900);
}

export function generateCacheKey(prefix: string, params: Record<string, any>): string {
  const hash = createHash('md5')
    .update(JSON.stringify(params))
    .digest('hex')
    .slice(0, 12);
  return `${prefix}:${hash}`;
}

export function clearCache(): void {
  cache.flushAll();
}
```

#### **src/utils/rate-limiter.ts** [CREATE]
Rate limiting for external APIs:
```typescript
import Bottleneck from 'bottleneck';
import { getSourceConfig } from './config-loader.js';

const limiters = new Map<string, Bottleneck>();

export function getRateLimiter(sourceName: string): Bottleneck {
  if (limiters.has(sourceName)) {
    return limiters.get(sourceName)!;
  }

  const config = getSourceConfig(sourceName);
  const rateLimit = config?.rate_limit || 5;

  // Default: requests per second
  const limiter = new Bottleneck({
    minTime: 1000 / rateLimit, // ms between requests
    maxConcurrent: 1,
  });

  limiters.set(sourceName, limiter);
  return limiter;
}

export async function rateLimitedFetch<T>(
  sourceName: string,
  fetchFn: () => Promise<T>
): Promise<T> {
  const limiter = getRateLimiter(sourceName);
  return limiter.schedule(fetchFn);
}
```

#### **src/utils/redactor.ts** [CREATE]
Sensitive data redaction:
```typescript
import { loadConfig } from './config-loader.js';

export function redactSensitiveData(text: string): string {
  const config = loadConfig();

  if (!config.output.redaction.enabled) {
    return text;
  }

  let redacted = text;

  for (const pattern of config.output.redaction.patterns) {
    const regex = new RegExp(pattern, 'g');
    redacted = redacted.replace(regex, (match, p1) => {
      return `${p1}=***REDACTED***`;
    });
  }

  return redacted;
}
```

---

## Phase 3: Security Tools & Connectors

### 3.1 Connector Interface

#### **src/tools/security/types.ts** [CREATE]
Standard interfaces for all security connectors:
```typescript
import { z } from 'zod';

export const SecurityQuerySchema = z.object({
  type: z.enum(['cve', 'advisory', 'ioc', 'news', 'breach']),
  query: z.string(),
  timeframe: z.object({
    start: z.string().optional(),
    end: z.string().optional(),
  }).optional(),
  filters: z.record(z.any()).optional(),
});

export type SecurityQuery = z.infer<typeof SecurityQuerySchema>;

export interface NormalizedData {
  id: string;
  source: string;
  type: string;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: number;
  summary: string;
  details: Record<string, any>;
  timestamp: string;
  url?: string;
}

export interface SecurityConnector {
  name: string;
  description: string;
  fetch(query: SecurityQuery): Promise<any>;
  normalize(rawData: any): NormalizedData[];
  rank(results: NormalizedData[]): NormalizedData[];
}

export interface ConnectorResult {
  connector: string;
  data: NormalizedData[];
  error?: string;
  cached: boolean;
}
```

### 3.2 CVE Connector (Reference Implementation)

#### **src/tools/security/cve-connector.ts** [CREATE]
NVD CVE + CISA KEV integration:
```typescript
import { SecurityConnector, SecurityQuery, NormalizedData } from './types.js';
import { rateLimitedFetch } from '../../utils/rate-limiter.js';
import { getCached, setCached, generateCacheKey } from '../../utils/cache.js';
import { getSourceConfig } from '../../utils/config-loader.js';

export const CVEConnector: SecurityConnector = {
  name: 'cve_connector',
  description: 'Searches CVE database (NVD) and CISA KEV catalog',

  async fetch(query: SecurityQuery): Promise<any> {
    const cacheKey = generateCacheKey('cve', query);
    const cached = getCached(cacheKey);
    if (cached) return cached;

    const results = await rateLimitedFetch('nvd', async () => {
      const config = getSourceConfig('nvd');
      const apiKey = process.env.NVD_API_KEY || '';

      const params = new URLSearchParams({
        keywordSearch: query.query,
        resultsPerPage: '20',
      });

      const response = await fetch(`${config.base_url}?${params}`, {
        headers: apiKey ? { 'apiKey': apiKey } : {},
      });

      if (!response.ok) {
        throw new Error(`NVD API error: ${response.statusText}`);
      }

      return response.json();
    });

    const ttl = getSourceConfig('nvd')?.cache_ttl;
    setCached(cacheKey, results, ttl);

    return results;
  },

  normalize(rawData: any): NormalizedData[] {
    const vulnerabilities = rawData.vulnerabilities || [];

    return vulnerabilities.map((vuln: any) => {
      const cve = vuln.cve;
      const cveId = cve.id;

      // Extract CVSS score and severity
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
      const cvssScore = metrics?.cvssData?.baseScore || 0;
      const severity = metrics?.cvssData?.baseSeverity || 'UNKNOWN';

      // Map CVSS severity to our standard
      const severityMap: Record<string, NormalizedData['severity']> = {
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW',
      };

      return {
        id: cveId,
        source: 'nvd',
        type: 'cve',
        severity: severityMap[severity] || 'INFORMATIONAL',
        confidence: 1.0, // NVD is authoritative
        summary: cve.descriptions?.[0]?.value || '',
        details: {
          cvssScore,
          vectorString: metrics?.cvssData?.vectorString,
          publishedDate: cve.published,
          lastModified: cve.lastModified,
          references: cve.references?.slice(0, 5).map((ref: any) => ref.url) || [],
          affectedProducts: cve.configurations?.nodes?.map((node: any) =>
            node.cpeMatch?.map((cpe: any) => cpe.criteria).join(', ')
          ).filter(Boolean) || [],
        },
        timestamp: cve.published,
        url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      };
    });
  },

  rank(results: NormalizedData[]): NormalizedData[] {
    // Sort by severity (CRITICAL first) then by CVSS score (if available)
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4 };

    return results.sort((a, b) => {
      const severityDiff = (severityOrder[a.severity || 'INFORMATIONAL'] || 4) -
                           (severityOrder[b.severity || 'INFORMATIONAL'] || 4);
      if (severityDiff !== 0) return severityDiff;

      const scoreA = a.details?.cvssScore || 0;
      const scoreB = b.details?.cvssScore || 0;
      return scoreB - scoreA;
    });
  },
};
```

### 3.3 IOC Connector

#### **src/tools/security/ioc-connector.ts** [CREATE]
VirusTotal + AbuseIPDB integration:
```typescript
import { SecurityConnector, SecurityQuery, NormalizedData } from './types.js';
import { rateLimitedFetch } from '../../utils/rate-limiter.js';
import { getCached, setCached, generateCacheKey } from '../../utils/cache.js';
import { getSourceConfig } from '../../utils/config-loader.js';

function detectIOCType(value: string): 'ip' | 'domain' | 'url' | 'hash' | 'unknown' {
  // IP address
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return 'ip';

  // Hash (MD5, SHA1, SHA256)
  if (/^[a-fA-F0-9]{32}$/.test(value)) return 'hash'; // MD5
  if (/^[a-fA-F0-9]{40}$/.test(value)) return 'hash'; // SHA1
  if (/^[a-fA-F0-9]{64}$/.test(value)) return 'hash'; // SHA256

  // URL
  if (value.startsWith('http://') || value.startsWith('https://')) return 'url';

  // Domain
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(value)) return 'domain';

  return 'unknown';
}

export const IOCConnector: SecurityConnector = {
  name: 'ioc_connector',
  description: 'Analyzes indicators of compromise (IP, domain, URL, hash) using VirusTotal and AbuseIPDB',

  async fetch(query: SecurityQuery): Promise<any> {
    const iocValue = query.query.trim();
    const iocType = detectIOCType(iocValue);

    if (iocType === 'unknown') {
      throw new Error(`Unable to determine IOC type for: ${iocValue}`);
    }

    const cacheKey = generateCacheKey('ioc', { value: iocValue, type: iocType });
    const cached = getCached(cacheKey);
    if (cached) return cached;

    const results: any = {
      ioc: iocValue,
      type: iocType,
      sources: {},
    };

    // Fetch from VirusTotal
    if (process.env.VIRUSTOTAL_API_KEY) {
      try {
        const vtData = await fetchVirusTotal(iocValue, iocType);
        results.sources.virustotal = vtData;
      } catch (err) {
        results.sources.virustotal = { error: String(err) };
      }
    }

    // Fetch from AbuseIPDB (only for IPs)
    if (iocType === 'ip' && process.env.ABUSEIPDB_API_KEY) {
      try {
        const abuseData = await fetchAbuseIPDB(iocValue);
        results.sources.abuseipdb = abuseData;
      } catch (err) {
        results.sources.abuseipdb = { error: String(err) };
      }
    }

    const ttl = getSourceConfig('virustotal')?.cache_ttl;
    setCached(cacheKey, results, ttl);

    return results;
  },

  normalize(rawData: any): NormalizedData[] {
    const normalized: NormalizedData[] = [];
    const iocValue = rawData.ioc;
    const iocType = rawData.type;

    // Normalize VirusTotal data
    if (rawData.sources.virustotal && !rawData.sources.virustotal.error) {
      const vt = rawData.sources.virustotal;
      const malicious = vt.data?.attributes?.last_analysis_stats?.malicious || 0;
      const total = Object.values(vt.data?.attributes?.last_analysis_stats || {})
        .reduce((sum: number, val: any) => sum + (Number(val) || 0), 0);

      const reputation = total > 0 ? (total - malicious) / total : 0;
      const severity: NormalizedData['severity'] =
        malicious > 10 ? 'CRITICAL' :
        malicious > 5 ? 'HIGH' :
        malicious > 2 ? 'MEDIUM' :
        malicious > 0 ? 'LOW' : 'INFORMATIONAL';

      normalized.push({
        id: `vt-${iocValue}`,
        source: 'virustotal',
        type: 'ioc',
        severity,
        confidence: 0.9,
        summary: `VirusTotal: ${malicious}/${total} vendors flagged as malicious`,
        details: {
          ioc: iocValue,
          iocType,
          maliciousCount: malicious,
          totalVendors: total,
          reputation,
          categories: vt.data?.attributes?.categories || {},
        },
        timestamp: new Date().toISOString(),
        url: `https://www.virustotal.com/gui/${iocType}/${iocValue}`,
      });
    }

    // Normalize AbuseIPDB data
    if (rawData.sources.abuseipdb && !rawData.sources.abuseipdb.error) {
      const abuse = rawData.sources.abuseipdb;
      const abuseScore = abuse.data?.abuseConfidenceScore || 0;

      const severity: NormalizedData['severity'] =
        abuseScore > 75 ? 'HIGH' :
        abuseScore > 50 ? 'MEDIUM' :
        abuseScore > 25 ? 'LOW' : 'INFORMATIONAL';

      normalized.push({
        id: `abuse-${iocValue}`,
        source: 'abuseipdb',
        type: 'ioc',
        severity,
        confidence: 0.85,
        summary: `AbuseIPDB: ${abuseScore}% abuse confidence score`,
        details: {
          ioc: iocValue,
          abuseScore,
          totalReports: abuse.data?.totalReports || 0,
          country: abuse.data?.countryCode || 'Unknown',
          isp: abuse.data?.isp || 'Unknown',
        },
        timestamp: new Date().toISOString(),
        url: `https://www.abuseipdb.com/check/${iocValue}`,
      });
    }

    return normalized;
  },

  rank(results: NormalizedData[]): NormalizedData[] {
    return results.sort((a, b) => b.confidence - a.confidence);
  },
};

async function fetchVirusTotal(ioc: string, type: string): Promise<any> {
  return rateLimitedFetch('virustotal', async () => {
    const config = getSourceConfig('virustotal');
    const apiKey = process.env.VIRUSTOTAL_API_KEY!;

    const endpoint = type === 'hash' ? `files/${ioc}` :
                     type === 'domain' ? `domains/${ioc}` :
                     type === 'url' ? `urls/${Buffer.from(ioc).toString('base64url')}` :
                     type === 'ip' ? `ip_addresses/${ioc}` : '';

    const response = await fetch(`${config.base_url}/${endpoint}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (!response.ok && response.status !== 404) {
      throw new Error(`VirusTotal API error: ${response.statusText}`);
    }

    return response.json();
  });
}

async function fetchAbuseIPDB(ip: string): Promise<any> {
  return rateLimitedFetch('abuseipdb', async () => {
    const config = getSourceConfig('abuseipdb');
    const apiKey = process.env.ABUSEIPDB_API_KEY!;

    const params = new URLSearchParams({
      ipAddress: ip,
      maxAgeInDays: '90',
      verbose: 'true',
    });

    const response = await fetch(`${config.base_url}/check?${params}`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.statusText}`);
    }

    return response.json();
  });
}
```

### 3.4 Security Search Meta-Tool

#### **src/tools/security/security-search.ts** [CREATE]
Similar to financial_search, routes queries to appropriate connectors:
```typescript
import { DynamicStructuredTool, StructuredToolInterface } from '@langchain/core/tools';
import { AIMessage } from '@langchain/core/messages';
import { z } from 'zod';
import { callLlm } from '../../model/llm.js';
import { CVEConnector } from './cve-connector.js';
import { IOCConnector } from './ioc-connector.js';
import { getCurrentDate } from '../../agent/prompts.js';

const SECURITY_CONNECTORS = [
  CVEConnector,
  IOCConnector,
  // Add more connectors as they're implemented
];

const SecuritySearchInputSchema = z.object({
  query: z.string().describe('Natural language security query'),
});

function buildSecurityRouterPrompt(): string {
  return `You are a security data routing assistant.
Current date: ${getCurrentDate()}

Given a user's query about cybersecurity, call the appropriate security connector(s).

## Available Connectors

1. **cve_connector**: CVE database search (NVD, CISA KEV)
   - Use for: vulnerability searches, CVE lookups, exploit information
   - Example: "latest critical CVEs", "CVE-2024-1234", "log4j vulnerabilities"

2. **ioc_connector**: Indicator of Compromise analysis
   - Use for: IP addresses, domains, URLs, file hashes
   - Example: "8.8.8.8", "malicious-domain.com", "SHA256:abc123..."

## Guidelines

- For CVE queries: Extract CVE IDs, keywords, severity levels, date ranges
- For IOC queries: Identify the indicator type (IP, domain, URL, hash)
- For broad queries: May need multiple connectors
- Always include relevant context from the query

Call the appropriate connector(s) now.`;
}

export function createSecuritySearch(model: string): DynamicStructuredTool {
  return new DynamicStructuredTool({
    name: 'security_search',
    description: `Intelligent search for security data. Routes queries to CVE databases, IOC reputation services, and security advisories. Use for vulnerability searches, threat intelligence, and indicator analysis.`,
    schema: SecuritySearchInputSchema,

    func: async (input: { query: string }): Promise<string> => {
      // Use LLM to route query to appropriate connector(s)
      const routerPrompt = `${buildSecurityRouterPrompt()}\n\nQuery: ${input.query}`;

      // Create temporary tools from connectors
      const connectorTools: StructuredToolInterface[] = SECURITY_CONNECTORS.map(connector => {
        return new DynamicStructuredTool({
          name: connector.name,
          description: connector.description,
          schema: z.object({
            query: z.string(),
          }),
          func: async (args: { query: string }) => {
            const rawData = await connector.fetch({
              type: 'cve', // Will be overridden by specific logic
              query: args.query,
            });
            const normalized = connector.normalize(rawData);
            const ranked = connector.rank(normalized);
            return JSON.stringify(ranked, null, 2);
          },
        });
      });

      // Call LLM with connector tools
      const response = await callLlm(routerPrompt, {
        model,
        systemPrompt: 'You are a security data router. Call the appropriate connector tools.',
        tools: connectorTools,
      }) as AIMessage;

      // Execute tool calls if any
      if (response.tool_calls && response.tool_calls.length > 0) {
        const results: string[] = [];

        for (const toolCall of response.tool_calls) {
          const connector = SECURITY_CONNECTORS.find(c => c.name === toolCall.name);
          if (!connector) continue;

          const args = toolCall.args as { query: string };
          const rawData = await connector.fetch({
            type: 'cve', // Simplified for MVP
            query: args.query,
          });
          const normalized = connector.normalize(rawData);
          const ranked = connector.rank(normalized);

          results.push(JSON.stringify(ranked, null, 2));
        }

        return results.join('\n\n---\n\n');
      }

      // Fallback if no tool calls
      return JSON.stringify({ error: 'No connector selected by router' });
    },
  });
}
```

#### **src/tools/security/index.ts** [CREATE]
Export all security connectors:
```typescript
export { CVEConnector } from './cve-connector.js';
export { IOCConnector } from './ioc-connector.js';
export { createSecuritySearch } from './security-search.js';
export * from './types.js';
```

---

## Phase 4: Agent & Prompt Updates

### 4.1 Agent Prompts

#### **src/agent/prompts.ts** [EDIT]
Replace financial prompts with security-focused versions:

**Changes:**
1. Rename `DEFAULT_SYSTEM_PROMPT`: "Dexter" → "Gideon"
2. Update domain: "financial research" → "cybersecurity operations"
3. Update tool references: "financial_search" → "security_search"
4. Add verification instructions
5. Add confidence scoring guidance

```typescript
export const DEFAULT_SYSTEM_PROMPT = `You are Gideon, a cybersecurity operations assistant.

Current date: ${getCurrentDate()}

Your output is displayed on a command line interface. Keep responses short and concise.

## Behavior

- Prioritize accuracy and verification over speed
- Use professional, objective security analyst tone
- Cross-reference multiple sources when possible
- Clearly distinguish facts from assumptions
- Include confidence levels in assessments

## Response Format

- Keep responses brief and actionable
- For vulnerability data, include: CVE ID, severity, CVSS score, affected products, mitigations
- For IOCs, include: reputation scores, detection counts, recommended actions
- Use Unicode box-drawing tables for comparative data
- Do not use markdown formatting (no **bold**, *italics*, headers)`;

export function buildSystemPrompt(): string {
  return `You are Gideon, a CLI assistant with access to security research and threat intelligence tools.

Current date: ${getCurrentDate()}

Your output is displayed on a command line interface. Keep responses short and concise.

## Available Tools

- security_search: Search CVE databases, analyze IOCs, fetch security advisories
- web_search: Search the web for threat intelligence, security news, and context

## Behavior

- DEFENSIVE ONLY: Never provide exploitation techniques, intrusion methods, or offensive capabilities
- Prioritize accuracy over speed - verify findings across multiple sources
- Include confidence scores and clearly label assumptions
- For critical findings, explain "what would change my assessment"
- Cross-reference data from multiple sources when possible
- Focus on detection, mitigation, and defensive strategies

## Verification Steps

1. Cross-source corroboration: Check if multiple sources confirm findings
2. Confidence scoring: Rate confidence (0.0-1.0) based on source reliability
3. Assumption tracking: Clearly label inferred vs. confirmed information
4. Alternative explanations: Consider other interpretations of data

## Response Format

- Lead with key finding and confidence level
- For CVEs: ID, severity, CVSS, affected products, exploitability, mitigations
- For IOCs: type, reputation scores, detection counts, recommended actions
- For advisories: vendor, severity, affected products, patches available
- Use tables for comparative data (sized for terminal ~80-120 chars)
- No markdown formatting (no **bold**, *italics*, headers)`;
}
```

### 4.2 Agent Core Updates

#### **src/agent/agent.ts** [EDIT]
**Changes:**
1. Replace `createFinancialSearch` with `createSecuritySearch` in tools
2. Update system prompt calls
3. Add verification step before final answer
4. Add confidence scoring to scratchpad

**Key modifications:**
```typescript
// Line 47-51: Update tool initialization
static create(config: AgentConfig = {}): Agent {
  const model = config.model ?? 'gpt-5.2';
  const tools: StructuredToolInterface[] = [
    createSecuritySearch(model),  // Changed from createFinancialSearch
    ...(process.env.TAVILY_API_KEY ? [tavilySearch] : []),
  ];
  const systemPrompt = buildSystemPrompt();
  return new Agent(config, tools, systemPrompt);
}
```

### 4.3 Scratchpad Updates

#### **src/agent/scratchpad.ts** [EDIT]
**Changes:**
1. Change directory: `.dexter/scratchpad` → `.gideon/scratchpad`
2. Add confidence field to entries
3. Add verification status

```typescript
// Line 43: Update scratchpad directory
private readonly scratchpadDir = '.gideon/scratchpad';

// Add confidence to ScratchpadEntry interface (line 24)
export interface ScratchpadEntry {
  type: 'init' | 'tool_result' | 'thinking' | 'verification';
  timestamp: string;
  confidence?: number;  // NEW
  verified?: boolean;   // NEW
  // ... rest of fields
}
```

---

## Phase 5: Command System

### 5.1 Command Types

#### **src/commands/types.ts** [CREATE]
```typescript
export interface CommandContext {
  model: string;
  modelProvider: string;
  maxIterations: number;
  signal?: AbortSignal;
}

export interface CommandResult {
  success: boolean;
  output: string;
  artifacts?: {
    markdown?: string;
    json?: any;
    stix?: any;
  };
  error?: string;
}

export type CommandHandler = (
  args: string[],
  context: CommandContext
) => Promise<CommandResult>;
```

### 5.2 Command Implementations

#### **src/commands/brief.ts** [CREATE]
Daily security briefing:
```typescript
import { Agent } from '../agent/agent.js';
import { CommandContext, CommandResult } from './types.js';
import { generateMarkdownReport, generateJSONReport } from '../output/index.js';

export async function briefCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const agent = Agent.create(context);

  const query = `Generate a daily security briefing including:
1. Critical CVEs published in the last 24 hours
2. Major security advisories from vendors (Microsoft, Apple, Google, etc.)
3. Notable security incidents or breaches
4. Emerging threat campaigns or attack trends

Focus on actionable intelligence for defenders.`;

  let fullAnswer = '';
  const toolCalls: any[] = [];

  for await (const event of agent.run(query)) {
    if (event.type === 'answer_chunk') {
      fullAnswer += event.text;
    } else if (event.type === 'done') {
      toolCalls.push(...event.toolCalls);
    }
  }

  // Generate artifacts
  const markdown = await generateMarkdownReport({
    title: 'Daily Security Briefing',
    content: fullAnswer,
    toolCalls,
    timestamp: new Date().toISOString(),
  });

  const json = await generateJSONReport({
    type: 'briefing',
    content: fullAnswer,
    toolCalls,
    timestamp: new Date().toISOString(),
  });

  return {
    success: true,
    output: fullAnswer,
    artifacts: { markdown, json },
  };
}
```

#### **src/commands/cve.ts** [CREATE]
CVE search and analysis:
```typescript
import { Agent } from '../agent/agent.js';
import { CommandContext, CommandResult } from './types.js';

export async function cveCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  if (args.length === 0) {
    return {
      success: false,
      output: '',
      error: 'Usage: gideon cve <search query>',
    };
  }

  const agent = Agent.create(context);
  const query = `Search for CVEs matching: ${args.join(' ')}

For each CVE found, include:
- CVE ID and description
- CVSS score and severity
- Affected products/versions
- Exploitability status (is it in CISA KEV?)
- Available mitigations or patches
- References for more information`;

  let fullAnswer = '';

  for await (const event of agent.run(query)) {
    if (event.type === 'answer_chunk') {
      fullAnswer += event.text;
    }
  }

  return {
    success: true,
    output: fullAnswer,
  };
}
```

#### **src/commands/ioc.ts** [CREATE]
IOC analysis:
```typescript
import { Agent } from '../agent/agent.js';
import { CommandContext, CommandResult } from './types.js';

export async function iocCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  if (args.length === 0) {
    return {
      success: false,
      output: '',
      error: 'Usage: gideon ioc <ip|domain|url|hash>',
    };
  }

  const ioc = args[0];
  const agent = Agent.create(context);

  const query = `Analyze this indicator of compromise: ${ioc}

Provide:
1. IOC type (IP, domain, URL, hash)
2. Reputation scores from multiple sources
3. Malicious/suspicious detections
4. Geolocation (if IP)
5. Associated threats or campaigns
6. Recommended actions (block, monitor, investigate)
7. Confidence level in the assessment`;

  let fullAnswer = '';

  for await (const event of agent.run(query)) {
    if (event.type === 'answer_chunk') {
      fullAnswer += event.text;
    }
  }

  return {
    success: true,
    output: fullAnswer,
  };
}
```

#### **src/commands/policy.ts** [CREATE]
Hardening checklist generator:
```typescript
import { CommandContext, CommandResult } from './types.js';

const HARDENING_TEMPLATES: Record<string, string[]> = {
  aws: [
    'Enable MFA for all IAM users and root account',
    'Implement least-privilege IAM policies',
    'Enable CloudTrail logging in all regions',
    'Enable GuardDuty for threat detection',
    'Encrypt EBS volumes and S3 buckets at rest',
    'Enable VPC Flow Logs',
    'Use Security Groups with least-privilege rules',
    'Enable AWS Config for compliance monitoring',
    'Implement SCPs (Service Control Policies) at organization level',
    'Regular review of IAM access keys and rotation',
  ],
  azure: [
    'Enable MFA for all users',
    'Implement Azure AD Conditional Access policies',
    'Enable Microsoft Defender for Cloud',
    'Use Azure Policy for compliance enforcement',
    'Enable diagnostic logging for all resources',
    'Encrypt data at rest with customer-managed keys',
    'Implement Network Security Groups (NSGs) with least privilege',
    'Enable Azure Sentinel for SIEM',
    'Regular access reviews in Azure AD',
    'Implement Privileged Identity Management (PIM)',
  ],
  gcp: [
    'Enable 2FA/MFA for all accounts',
    'Implement least-privilege IAM roles',
    'Enable VPC Flow Logs',
    'Use Cloud Security Command Center',
    'Enable Cloud Audit Logs',
    'Encrypt data at rest and in transit',
    'Implement firewall rules with least privilege',
    'Use Organization Policy constraints',
    'Enable Binary Authorization for container security',
    'Regular review of service account keys',
  ],
  k8s: [
    'Enable RBAC and use least-privilege roles',
    'Implement Pod Security Standards/Policies',
    'Enable network policies for pod-to-pod traffic',
    'Use secrets management (external secrets, sealed secrets)',
    'Enable audit logging',
    'Scan container images for vulnerabilities',
    'Implement resource quotas and limits',
    'Use admission controllers (OPA/Gatekeeper)',
    'Enable encryption at rest for etcd',
    'Regular updates of Kubernetes and node OS',
  ],
};

export async function policyCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  if (args.length === 0) {
    return {
      success: false,
      output: `Usage: gideon policy <stack>

Available stacks: ${Object.keys(HARDENING_TEMPLATES).join(', ')}`,
      error: 'No stack specified',
    };
  }

  const stack = args[0].toLowerCase();
  const checklist = HARDENING_TEMPLATES[stack];

  if (!checklist) {
    return {
      success: false,
      output: `Unknown stack: ${stack}

Available stacks: ${Object.keys(HARDENING_TEMPLATES).join(', ')}`,
      error: `Unknown stack: ${stack}`,
    };
  }

  const output = `Hardening Checklist: ${stack.toUpperCase()}

${checklist.map((item, i) => `${i + 1}. ${item}`).join('\n')}

Note: This is a baseline checklist. Tailor to your specific environment and threat model.`;

  return {
    success: true,
    output,
  };
}
```

#### **src/commands/index.ts** [CREATE]
```typescript
export { briefCommand } from './brief.js';
export { cveCommand } from './cve.js';
export { iocCommand } from './ioc.js';
export { policyCommand } from './policy.js';
export * from './types.js';
```

### 5.3 CLI Integration

#### **src/cli.tsx** [EDIT]
**Changes:**
1. Update intro message (Dexter → Gideon)
2. Add command parsing
3. Integrate command handlers

**Add after line 73:**
```typescript
// Handle commands
if (query.startsWith('gideon ')) {
  const parts = query.slice(7).trim().split(' ');
  const command = parts[0];
  const args = parts.slice(1);

  const commandContext: CommandContext = {
    model,
    modelProvider: provider,
    maxIterations: 10,
  };

  let result: CommandResult | null = null;

  switch (command) {
    case 'brief':
      result = await briefCommand(args, commandContext);
      break;
    case 'cve':
      result = await cveCommand(args, commandContext);
      break;
    case 'ioc':
      result = await iocCommand(args, commandContext);
      break;
    case 'policy':
      result = await policyCommand(args, commandContext);
      break;
    default:
      setError(`Unknown command: ${command}`);
      return;
  }

  if (result) {
    if (!result.success) {
      setError(result.error || 'Command failed');
      return;
    }

    // Save message and response
    await saveMessage(query);
    await updateAgentResponse(result.output);

    // Save artifacts if present
    if (result.artifacts) {
      await saveArtifacts(result.artifacts);
    }
  }

  return;
}
```

---

## Phase 6: Output System

### 6.1 Output Generators

#### **src/output/markdown-generator.ts** [CREATE]
```typescript
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { loadConfig } from '../utils/config-loader.js';
import { redactSensitiveData } from '../utils/redactor.js';

export interface MarkdownReportInput {
  title: string;
  content: string;
  toolCalls?: any[];
  timestamp: string;
  metadata?: Record<string, any>;
}

export async function generateMarkdownReport(input: MarkdownReportInput): Promise<string> {
  const config = loadConfig();
  const outputDir = config.output.directory;

  // Create timestamped directory
  const dirName = new Date(input.timestamp).toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const reportDir = join(outputDir, dirName);

  if (!existsSync(reportDir)) {
    mkdirSync(reportDir, { recursive: true });
  }

  // Build markdown
  let markdown = `# ${input.title}\n\n`;
  markdown += `**Generated:** ${new Date(input.timestamp).toLocaleString()}\n\n`;
  markdown += `---\n\n`;
  markdown += `## Analysis\n\n`;
  markdown += `${input.content}\n\n`;

  if (input.toolCalls && input.toolCalls.length > 0) {
    markdown += `---\n\n## Data Sources\n\n`;
    input.toolCalls.forEach((call, i) => {
      markdown += `${i + 1}. **${call.tool}**\n`;
      markdown += `   - Args: ${JSON.stringify(call.args)}\n`;
    });
    markdown += `\n`;
  }

  if (input.metadata) {
    markdown += `---\n\n## Metadata\n\n`;
    markdown += `\`\`\`json\n${JSON.stringify(input.metadata, null, 2)}\n\`\`\`\n`;
  }

  // Redact sensitive data
  const redacted = redactSensitiveData(markdown);

  // Write to file
  const filepath = join(reportDir, 'report.md');
  writeFileSync(filepath, redacted);

  return redacted;
}
```

#### **src/output/json-generator.ts** [CREATE]
```typescript
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { loadConfig } from '../utils/config-loader.js';

export interface JSONReportInput {
  type: string;
  content: string;
  toolCalls?: any[];
  timestamp: string;
  metadata?: Record<string, any>;
}

export async function generateJSONReport(input: JSONReportInput): Promise<any> {
  const config = loadConfig();
  const outputDir = config.output.directory;

  const dirName = new Date(input.timestamp).toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const reportDir = join(outputDir, dirName);

  if (!existsSync(reportDir)) {
    mkdirSync(reportDir, { recursive: true });
  }

  const jsonData = {
    type: input.type,
    timestamp: input.timestamp,
    content: input.content,
    toolCalls: input.toolCalls || [],
    metadata: input.metadata || {},
  };

  const filepath = join(reportDir, 'data.json');
  writeFileSync(filepath, JSON.stringify(jsonData, null, 2));

  return jsonData;
}
```

#### **src/output/index.ts** [CREATE]
```typescript
export { generateMarkdownReport } from './markdown-generator.js';
export { generateJSONReport } from './json-generator.js';
```

---

## Phase 7: Testing

### 7.1 Test Structure

#### **tests/connectors/cve-connector.test.ts** [CREATE]
```typescript
import { describe, test, expect } from 'bun:test';
import { CVEConnector } from '../../src/tools/security/cve-connector.js';

describe('CVEConnector', () => {
  test('normalizes NVD data correctly', () => {
    const mockData = {
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2024-1234',
            descriptions: [{ value: 'Test vulnerability description' }],
            published: '2024-01-15T10:00:00.000Z',
            lastModified: '2024-01-16T12:00:00.000Z',
            metrics: {
              cvssMetricV31: [
                {
                  cvssData: {
                    baseScore: 9.8,
                    baseSeverity: 'CRITICAL',
                    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                  },
                },
              ],
            },
            references: [
              { url: 'https://example.com/advisory' },
            ],
          },
        },
      ],
    };

    const normalized = CVEConnector.normalize(mockData);

    expect(normalized).toHaveLength(1);
    expect(normalized[0].id).toBe('CVE-2024-1234');
    expect(normalized[0].severity).toBe('CRITICAL');
    expect(normalized[0].details.cvssScore).toBe(9.8);
  });

  test('ranks vulnerabilities by severity and CVSS', () => {
    const data = [
      { id: '1', severity: 'MEDIUM' as const, confidence: 1, summary: '', details: { cvssScore: 5.5 }, source: 'nvd', type: 'cve', timestamp: '' },
      { id: '2', severity: 'CRITICAL' as const, confidence: 1, summary: '', details: { cvssScore: 9.8 }, source: 'nvd', type: 'cve', timestamp: '' },
      { id: '3', severity: 'HIGH' as const, confidence: 1, summary: '', details: { cvssScore: 8.1 }, source: 'nvd', type: 'cve', timestamp: '' },
    ];

    const ranked = CVEConnector.rank(data);

    expect(ranked[0].id).toBe('2'); // CRITICAL first
    expect(ranked[1].id).toBe('3'); // HIGH second
    expect(ranked[2].id).toBe('1'); // MEDIUM last
  });
});
```

#### **tests/utils/cache.test.ts** [CREATE]
```typescript
import { describe, test, expect, beforeEach } from 'bun:test';
import { getCached, setCached, clearCache, generateCacheKey } from '../../src/utils/cache.js';

describe('Cache utilities', () => {
  beforeEach(() => {
    clearCache();
  });

  test('stores and retrieves cached values', () => {
    setCached('test-key', { data: 'test-value' });
    const cached = getCached('test-key');

    expect(cached).toEqual({ data: 'test-value' });
  });

  test('returns undefined for non-existent keys', () => {
    const cached = getCached('non-existent');
    expect(cached).toBeUndefined();
  });

  test('generates consistent cache keys', () => {
    const key1 = generateCacheKey('prefix', { a: 1, b: 2 });
    const key2 = generateCacheKey('prefix', { a: 1, b: 2 });

    expect(key1).toBe(key2);
  });
});
```

---

## Phase 8: Documentation

### 8.1 README Update

#### **README.md** [REWRITE]
Complete rewrite for security focus - see separate section below.

### 8.2 Additional Docs

#### **CONTRIBUTING.md** [CREATE]
Contribution guidelines:
- Code style
- Testing requirements
- PR process
- Safety requirements

#### **SAFETY.md** [CREATE]
Safety and ethical guidelines:
- Defensive-only policy
- Prohibited capabilities
- Reporting vulnerabilities
- Responsible disclosure

---

## Summary: Files to Change

### DELETE (9 files)
```
src/tools/finance/api.ts
src/tools/finance/constants.ts
src/tools/finance/crypto.ts
src/tools/finance/estimates.ts
src/tools/finance/filings.ts
src/tools/finance/financial-search.ts
src/tools/finance/fundamentals.ts
src/tools/finance/insider_trades.ts
src/tools/finance/metrics.ts
src/tools/finance/news.ts
src/tools/finance/prices.ts
src/tools/finance/segments.ts
src/tools/finance/index.ts
```

### EDIT (7 files)
```
package.json              - Rename, update deps
README.md                 - Complete rewrite
src/agent/agent.ts        - Update tools
src/agent/prompts.ts      - Security prompts
src/agent/scratchpad.ts   - Change directory
src/cli.tsx               - Add command routing
src/tools/index.ts        - Update exports
```

### CREATE (30+ files)
```
# Config
env.example
gideon.config.yaml

# Core utils
src/utils/config-loader.ts
src/utils/cache.ts
src/utils/rate-limiter.ts
src/utils/redactor.ts

# Security tools
src/tools/security/types.ts
src/tools/security/cve-connector.ts
src/tools/security/ioc-connector.ts
src/tools/security/security-search.ts
src/tools/security/index.ts

# Commands
src/commands/types.ts
src/commands/brief.ts
src/commands/cve.ts
src/commands/ioc.ts
src/commands/policy.ts
src/commands/index.ts

# Output
src/output/markdown-generator.ts
src/output/json-generator.ts
src/output/index.ts

# Tests
tests/connectors/cve-connector.test.ts
tests/connectors/ioc-connector.test.ts
tests/utils/cache.test.ts
tests/utils/rate-limiter.test.ts
tests/agent/agent.test.ts

# Docs
ARCHITECTURE.md
TRANSFORMATION_PLAN.md
CONTRIBUTING.md
SAFETY.md
```

---

## Implementation Order (Recommended)

1. **Phase 1**: Project metadata (package.json, env.example, config.yaml)
2. **Phase 2**: Core utils (config-loader, cache, rate-limiter, redactor)
3. **Phase 3**: Security connectors (types, CVE connector, IOC connector, security-search)
4. **Phase 4**: Agent updates (prompts, agent.ts, scratchpad)
5. **Phase 5**: Commands (types, all command handlers, CLI integration)
6. **Phase 6**: Output system (markdown, JSON generators)
7. **Phase 7**: Tests (connector tests, util tests, agent tests)
8. **Phase 8**: Documentation (README, CONTRIBUTING, SAFETY)
9. **Phase 9**: Cleanup (delete finance directory, final testing)
10. **Phase 10**: Commit and push

---

## Safety Checkpoints

Before each phase, verify:
- [ ] No offensive capabilities introduced
- [ ] All external calls rate-limited
- [ ] Sensitive data redaction in place
- [ ] Clear labeling of assumptions
- [ ] Defensive-only language in prompts and docs

---

## Testing Plan

### Unit Tests
- [x] Cache utilities
- [x] Rate limiter
- [x] CVE connector normalization
- [x] IOC connector normalization
- [ ] Redactor patterns

### Integration Tests
- [ ] End-to-end command execution (brief, cve, ioc, policy)
- [ ] Agent loop with security tools
- [ ] Multi-source corroboration
- [ ] Output generation (MD + JSON)

### Manual Tests
- [ ] Interactive mode
- [ ] Each command with real APIs
- [ ] Error handling (bad API keys, rate limits, network errors)
- [ ] Cache and rate limiting behavior

---

This plan provides a complete roadmap for transforming Dexter into Gideon while preserving the core agent architecture and adding security-specific capabilities, safety guardrails, and structured outputs.
