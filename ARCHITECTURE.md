# Gideon Architecture

## 1. System Overview

Gideon is an autonomous cybersecurity operations assistant built with TypeScript/Bun that:
- Produces daily security briefings (CVEs, advisories, breaches)
- Analyzes indicators of compromise (IOCs)
- Searches vulnerability databases
- Generates hardening recommendations
- Creates structured incident reports
- **DUAL MODE**: Operates as a defensive analyst by default. When explicitly authorized, unlocks **Red Team Mode** for autonomous sandboxed exploitation, C2 interaction, and post-exploitation mapping.

## 2. Core Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     CLI Entry Point                           │
│                    (src/index.tsx)                            │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│               Gideon CLI Interface                            │
│                    (src/cli.tsx)                              │
│                                                               │
│  Commands:                                                    │
│  - gideon brief              → Daily security briefing        │
│  - gideon cve <query>        → CVE search & analysis          │
│  - gideon ioc <value>        → IOC reputation check           │
│  - gideon policy <stack>     → Hardening checklist            │
│  - gideon report <file.md>   → Incident report generator      │
│  - /model                    → Model selection                │
│  - Interactive mode (default)→ Natural language queries       │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│              Security Agent Core Loop                         │
│                  (src/agent/agent.ts)                         │
│                                                               │
│  Features:                                                    │
│  1. Cross-source corroboration verification                   │
│  2. Confidence scoring                                        │
│  3. "What would change my mind" reasoning                     │
│  4. Assumption tracking                                       │
│  5. Defensive-only guardrails                                 │
│  6. Structured output generation (MD + JSON)                  │
└─────────┬──────────────────────────────┬─────────────────────┘
          │                              │
┌─────────▼──────────┐        ┌─────────▼──────────────────────┐
│   Scratchpad       │        │   Security Tools Layer         │
│ (scratchpad.ts)    │        │   (src/tools/ & src/skills/)   │
│                    │        │                                │
│ - Query tracking   │        │ ┌──────────────────────────┐   │
│ - Tool results     │        │ │  security_search         │   │
│ - Confidence scores│        │ │  (meta-tool with LLM     │   │
│ - Verification logs│        │ │   routing)               │   │
│ - Output artifacts │        │ └────────┬─────────────────┘   │
│   (MD + JSON)      │        │          │                     │
└────────────────────┘        ├──────────▼─────────────────────┤
                              │   Action Engine & Sandbox      │
                              │   (src/engine/action-engine.ts)│
                              │   - Docker Sandboxing          │
                              │   - Tool Adapters (Nmap, msf)  │
                              └──────────┬─────────────────────┘
                              │ ┌────────▼─────────────────┐   │
                              │ │  Security Connectors     │   │
                              │ │  - cve-connector         │   │
                              │ │  - ioc-connector         │   │
                              │ │  - news-connector        │   │
                              │ └──────────────────────────┘   │
                              │                                │
                              │ ┌──────────────────────────┐   │
                              │ │  C2 Manager (Red Team)   │   │
                              │ │  (Sliver, Mythic bridge) │   │
                              │ └──────────────────────────┘   │
                              │                                │
                              │ ┌──────────────────────────┐   │
                              │ │  tavily_search           │   │
                              │ │  (general web search)    │   │
                              │ └──────────────────────────┘   │
                              └────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              Configuration & Cache Layer                     │
│              (src/utils/config.ts, cache.ts)                 │
│                                                              │
│  - YAML/JSON config for sources, thresholds, output prefs    │
│  - Rate limiting (per-source)                                │
│  - Response caching (15min TTL)                              │
│  - API key management                                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    LLM Integration Layer                     │
│                    (src/model/llm.ts)                        │
│                                                              │
│  Multi-provider support via LangChain:                       │
│  - OpenAI (gpt-5.2, gpt-4.1-mini)                           │
│  - Anthropic (claude-3-5-sonnet, haiku)                     │
│  - Google (gemini-2.0-flash)                                │
│  - Ollama (local models)                                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   Output Generator                           │
│              (src/utils/output-generator.ts)                 │
│                                                              │
│  Generates:                                                  │
│  - outputs/<timestamp>/report.md    (human-readable)         │
│  - outputs/<timestamp>/data.json    (structured data)        │
│  - outputs/<timestamp>/stix.json    (optional STIX format)   │
└─────────────────────────────────────────────────────────────┘
```

## 3. Key Design Patterns

1. **Context Compaction**: During agent iteration, full tool results are summarized by LLM to save tokens. Final answer generation uses full context.

2. **Scratchpad Pattern**: All agent work (thinking + tool results) logged to append-only JSONL file in `.gideon/scratchpad/` for debugging and context management.

3. **Meta-Tool Pattern**: `security_search` uses LLM routing to select and call appropriate sub-tools based on natural language query.

4. **Streaming UI**: Events (thinking, tool_start, tool_end, answer_chunk) streamed to UI in real-time for transparency.

## 4. Module Boundaries

### 4.1 Security Connectors (`src/tools/security/`)
Each connector implements a standardized interface:
```typescript
interface SecurityConnector {
  name: string;
  fetch(query: SecurityQuery): Promise<SecurityData>;
  normalize(rawData: any): NormalizedData;
  rank(results: NormalizedData[]): RankedData[];
}
```

**Connectors:**
- `cve-connector.ts`: NVD CVE API + CISA KEV catalog
- `advisory-connector.ts`: Vendor security bulletins
- `ioc-connector.ts`: VirusTotal, AbuseIPDB, URLScan
- `news-connector.ts`: Security news aggregation
- `breach-connector.ts`: Public breach data

### 4.2 Command Handlers (`src/commands/`)
Map CLI commands to agent workflows:
- `brief-command.ts`: Daily briefing orchestration
- `cve-command.ts`: CVE search & impact analysis
- `ioc-command.ts`: IOC reputation lookup
- `policy-command.ts`: Hardening checklist generation
- `report-command.ts`: Incident report assembly

### 4.3 Verification Engine (`src/verification/`)
- `corroboration.ts`: Cross-source validation
- `confidence.ts`: Confidence scoring
- `assumptions.ts`: Assumption tracking

### 4.4 Output System (`src/output/`)
- `markdown-generator.ts`: Report formatting
- `json-generator.ts`: Structured data export
- `stix-generator.ts`: STIX 2.1 format (optional)

### 4.5 Action Engine & Sandbox (`src/engine/`)
- `action-engine.ts`: Orchestrates tool execution
- `sandbox.ts`: Docker-based process wrapping and resource limits
- `tool-adapters.ts`: Wrappers for nmap, sqlmap, nuclei

### 4.6 C2 Framework Integration (`src/c2/`)
- `c2-manager.ts`: Core C2 tracking and tool exposures
- `adapters/sliver-adapter.ts`: Sliver RPC mappings

## 5. Safety & Guardrails (Dual-Mode)

### Defensive Mode (Default)

1. **Read-Only by Default**: All tools default to read-only mode. No system modification capabilities.
2. **No Offensive Capabilities**: Exploitation requests blocked, tools unavailable.

### Red Team Mode (Authorized)

1. **Scope Enforcement**: Every execution via `ActionEngine` or `C2Manager` is validated against the active `EngagementScope`. Out of scope attempts are hard-blocked.
2. **Container Isolation**: Offensive tool operations must execute inside `gideon-toolbox` docker containers to protect the host OS.
3. **Audit Trail**: Every execution (success or failure) is logged with cryptographically referenced audit records indicating risk level and target.

### Universal Safety (Active in Both Modes)

1. **Jailbreak Defenses**: NeMo guardrails block prompt injections and adversarial hijacking attempts at all times.
2. **Data Handling**:
   - No plaintext storage of credentials (except explicitly requested harvest dumps)
   - Redaction of sensitive data in external API queries
   - Clear labeling of assumptions vs. facts

3. **Rate Limiting & Caching**: Prevent abuse of external OSINT APIs.

### Implementation
- Pre-execution validation in agent loop
- Tool-level safety checks
- Output sanitization (redact API keys, tokens)
- Audit logging of all operations

## 6. Deployment & Usage

### Installation
```bash
git clone https://github.com/cogensec/gideon.git
cd gideon
bun install
cp env.example .env
# Edit .env with API keys
bun start
```

### Configuration
`gideon.config.yaml`:
```yaml
sources:
  nvd:
    enabled: true
    api_key: ${NVD_API_KEY}
    rate_limit: 5req/sec
  virustotal:
    enabled: true
    api_key: ${VT_API_KEY}
    rate_limit: 4req/min

output:
  format: [markdown, json]
  directory: ./outputs
  redact_patterns:
    - "(?i)(api[_-]?key|token|password)\\s*[:=]\\s*['\"]?([^'\"\\s]+)"

thresholds:
  confidence_minimum: 0.6
  corroboration_sources: 2
```

### Example Usage
```bash
# Daily briefing
gideon brief

# CVE search
gideon cve "log4j vulnerabilities 2024"

# IOC analysis
gideon ioc 8.8.8.8

# Hardening checklist
gideon policy aws

# Incident report
gideon report incident-notes.md

# Interactive mode
gideon
> What are the latest critical CVEs for Microsoft Exchange?
```

## 7. Testing Strategy

### Unit Tests
- Connector interfaces and normalization
- Confidence scoring logic
- Output generators (MD, JSON, STIX)
- Rate limiting and caching

### Integration Tests
- End-to-end command execution
- Agent loop with mock connectors
- Multi-source corroboration

### Safety Tests
- Guardrail enforcement
- Offensive capability prevention
- Data redaction validation
