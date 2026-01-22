# Gideon Development Roadmap
## Implementation Plan

---

## Phase 1: Project Configuration

### 1.1 Package & Project Metadata

#### **package.json** [CONFIGURED]
- `name`: "gideon"
- `description`: "Gideon - Autonomous cybersecurity operations assistant."
- `bin`: "gideon"
- Dependencies:
  - `yaml`: "^2.3.4" (config file parsing)
  - `node-cache`: "^5.1.2" (in-memory caching)
  - `bottleneck`: "^2.19.5" (rate limiting)

#### **env.example** [CREATE]
Environment template:
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

## Phase 2: Core Infrastructure

### 2.1 Directory Structure

```
src/
  tools/
    security/          - Security connectors
    search/            - Web search (Tavily)
  commands/            - CLI command handlers
  verification/        - Verification & confidence scoring
  output/              - Output generators (MD, JSON, STIX)
  utils/
    cache.ts           - Caching utilities
    rate-limiter.ts    - Rate limiting
    config-loader.ts   - YAML config loading
    redactor.ts        - Sensitive data redaction

.gideon/               - Application data directory
  scratchpad/          - Agent work logs
  cache/               - Response cache files
```

### 2.2 Configuration System

#### **src/utils/config-loader.ts** [CREATE]
Loads and validates `gideon.config.yaml`

#### **src/utils/cache.ts** [CREATE]
In-memory caching with TTL using node-cache

#### **src/utils/rate-limiter.ts** [CREATE]
Rate limiting for external APIs using Bottleneck

#### **src/utils/redactor.ts** [CREATE]
Sensitive data redaction for output sanitization

---

## Phase 3: Security Tools & Connectors

### 3.1 Connector Interface

#### **src/tools/security/types.ts** [CREATE]
Standard interfaces for all security connectors:
```typescript
interface SecurityConnector {
  name: string;
  description: string;
  fetch(query: SecurityQuery): Promise<any>;
  normalize(rawData: any): NormalizedData[];
  rank(results: NormalizedData[]): NormalizedData[];
}
```

### 3.2 Connectors to Implement

#### **src/tools/security/cve-connector.ts** [CREATE]
NVD CVE + CISA KEV integration

#### **src/tools/security/ioc-connector.ts** [CREATE]
VirusTotal + AbuseIPDB integration

#### **src/tools/security/security-search.ts** [CREATE]
Meta-tool that routes queries to appropriate connectors

#### **src/tools/security/index.ts** [CREATE]
Export all security connectors

---

## Phase 4: Agent & Prompt Updates

### 4.1 Agent Prompts

#### **src/agent/prompts.ts** [UPDATE]
Security-focused system prompts with:
- Verification instructions
- Confidence scoring guidance
- Defensive-only guardrails

### 4.2 Agent Core

#### **src/agent/agent.ts** [UPDATE]
- Use `createSecuritySearch` in tools
- Add verification step before final answer
- Add confidence scoring to scratchpad

### 4.3 Scratchpad

#### **src/agent/scratchpad.ts** [UPDATE]
- Directory: `.gideon/scratchpad`
- Add confidence field to entries
- Add verification status

---

## Phase 5: Command System

### 5.1 Command Types

#### **src/commands/types.ts** [CREATE]
```typescript
interface CommandContext {
  model: string;
  modelProvider: string;
  maxIterations: number;
  signal?: AbortSignal;
}

interface CommandResult {
  success: boolean;
  output: string;
  artifacts?: {
    markdown?: string;
    json?: any;
    stix?: any;
  };
  error?: string;
}
```

### 5.2 Command Implementations

#### **src/commands/brief.ts** [CREATE]
Daily security briefing

#### **src/commands/cve.ts** [CREATE]
CVE search and analysis

#### **src/commands/ioc.ts** [CREATE]
IOC analysis

#### **src/commands/policy.ts** [CREATE]
Hardening checklist generator

#### **src/commands/index.ts** [CREATE]
Export all commands

### 5.3 CLI Integration

#### **src/cli.tsx** [UPDATE]
Add command parsing and routing

---

## Phase 6: Output System

### 6.1 Output Generators

#### **src/output/markdown-generator.ts** [CREATE]
Generate markdown reports with redaction

#### **src/output/json-generator.ts** [CREATE]
Generate structured JSON output

#### **src/output/index.ts** [CREATE]
Export all generators

---

## Phase 7: Testing

### 7.1 Test Structure

#### **tests/connectors/cve-connector.test.ts** [CREATE]
Test CVE normalization and ranking

#### **tests/connectors/ioc-connector.test.ts** [CREATE]
Test IOC detection and normalization

#### **tests/utils/cache.test.ts** [CREATE]
Test caching utilities

#### **tests/utils/rate-limiter.test.ts** [CREATE]
Test rate limiting

#### **tests/agent/agent.test.ts** [CREATE]
Test agent loop with mock connectors

---

## Phase 8: Documentation

### 8.1 Documentation Files

#### **README.md** [UPDATE]
Complete documentation for security focus

#### **CONTRIBUTING.md** [CREATE]
- Code style
- Testing requirements
- PR process
- Safety requirements

#### **SAFETY.md** [CREATE]
- Defensive-only policy
- Prohibited capabilities
- Reporting vulnerabilities
- Responsible disclosure

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
- [ ] Cache utilities
- [ ] Rate limiter
- [ ] CVE connector normalization
- [ ] IOC connector normalization
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

This plan provides a complete roadmap for building Gideon with security-specific capabilities, safety guardrails, and structured outputs.
