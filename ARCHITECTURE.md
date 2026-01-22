# Gideon Architecture

## 1. Current State: Dexter (Financial Research Agent)

### System Overview
Dexter is an autonomous financial research agent built with TypeScript/Bun that:
- Takes natural language queries about stocks, companies, and markets
- Uses an agentic loop with task planning and self-reflection
- Executes financial data API calls and web searches
- Streams real-time results through a terminal UI (Ink/React)

### Core Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     CLI Entry Point                           │
│                    (src/index.tsx)                            │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│                   Ink CLI Interface                           │
│                    (src/cli.tsx)                              │
│  - User input handling                                        │
│  - Model selection (/model command)                           │
│  - History navigation                                         │
│  - Real-time UI rendering                                     │
└────────────────────┬─────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────────┐
│                   Agent Core Loop                             │
│                  (src/agent/agent.ts)                         │
│                                                               │
│  1. Receive user query                                        │
│  2. Build prompt with system instructions                     │
│  3. Call LLM with tools available                             │
│  4. Execute tool calls (if any)                               │
│  5. Summarize results (context compaction)                    │
│  6. Iterate until ready for final answer                      │
│  7. Generate final answer with full context                   │
│                                                               │
│  Safety: Max iterations = 10, AbortSignal support             │
└─────────┬──────────────────────────────┬─────────────────────┘
          │                              │
┌─────────▼──────────┐        ┌─────────▼──────────────────────┐
│   Scratchpad       │        │      Tools Layer               │
│ (scratchpad.ts)    │        │   (src/tools/)                 │
│                    │        │                                │
│ - Append-only JSONL│        │ ┌──────────────────────────┐   │
│ - Query tracking   │        │ │  financial_search        │   │
│ - Tool results     │        │ │  (meta-tool with LLM     │   │
│ - Thinking logs    │        │ │   routing)               │   │
│ - Context building │        │ └────────┬─────────────────┘   │
└────────────────────┘        │          │                     │
                              │ ┌────────▼─────────────────┐   │
                              │ │  Finance Sub-Tools       │   │
                              │ │  - prices                │   │
                              │ │  - fundamentals          │   │
                              │ │  - filings               │   │
                              │ │  - metrics               │   │
                              │ │  - estimates             │   │
                              │ │  - news                  │   │
                              │ │  - crypto                │   │
                              │ │  - insider trades        │   │
                              │ └──────────────────────────┘   │
                              │                                │
                              │ ┌──────────────────────────┐   │
                              │ │  tavily_search           │   │
                              │ │  (web search)            │   │
                              │ └──────────────────────────┘   │
                              └────────────────────────────────┘

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
```

### Key Design Patterns

1. **Context Compaction**: During agent iteration, full tool results are summarized by LLM to save tokens. Final answer generation uses full context.

2. **Scratchpad Pattern**: All agent work (thinking + tool results) logged to append-only JSONL file for debugging and context management.

3. **Meta-Tool Pattern**: `financial_search` uses LLM routing to select and call appropriate sub-tools based on natural language query.

4. **Streaming UI**: Events (thinking, tool_start, tool_end, answer_chunk) streamed to UI in real-time for transparency.

---

## 2. Target State: Gideon (Cybersecurity Operations Assistant)

### System Overview
Gideon is an autonomous cybersecurity operations assistant that:
- Produces daily security briefings (CVEs, advisories, breaches)
- Analyzes indicators of compromise (IOCs)
- Searches vulnerability databases
- Generates hardening recommendations
- Creates structured incident reports
- **DEFENSIVE ONLY**: No exploit creation, intrusion tools, or offensive capabilities

### Transformed Architecture

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
│  Enhanced with:                                               │
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
│ (scratchpad.ts)    │        │   (src/tools/security/)        │
│                    │        │                                │
│ - Query tracking   │        │ ┌──────────────────────────┐   │
│ - Tool results     │        │ │  security_search         │   │
│ - Confidence scores│        │ │  (meta-tool with LLM     │   │
│ - Verification logs│        │ │   routing)               │   │
│ - Output artifacts │        │ └────────┬─────────────────┘   │
│   (MD + JSON)      │        │          │                     │
└────────────────────┘        │ ┌────────▼─────────────────┐   │
                              │ │  Security Connectors     │   │
                              │ │  - cve-connector         │   │
                              │ │    (NVD, CISA KEV)       │   │
                              │ │  - advisory-connector    │   │
                              │ │    (vendor advisories)   │   │
                              │ │  - ioc-connector         │   │
                              │ │    (VirusTotal, AbuseIPDB)│  │
                              │ │  - news-connector        │   │
                              │ │    (security news feeds) │   │
                              │ │  - breach-connector      │   │
                              │ │    (HaveIBeenPwned, etc) │   │
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
│                   Output Generator                           │
│              (src/utils/output-generator.ts)                 │
│                                                              │
│  Generates:                                                  │
│  - outputs/<timestamp>/report.md    (human-readable)         │
│  - outputs/<timestamp>/data.json    (structured data)        │
│  - outputs/<timestamp>/stix.json    (optional STIX format)   │
└─────────────────────────────────────────────────────────────┘
```

### New Module Boundaries

#### 1. **Security Connectors** (`src/tools/security/`)
Each connector implements a standardized interface:
```typescript
interface SecurityConnector {
  name: string;
  fetch(query: SecurityQuery): Promise<SecurityData>;
  normalize(rawData: any): NormalizedData;
  rank(results: NormalizedData[]): RankedData[];
}
```

**Connectors to implement:**
- `cve-connector.ts`: NVD CVE API + CISA KEV catalog
- `advisory-connector.ts`: Vendor security bulletins
- `ioc-connector.ts`: VirusTotal, AbuseIPDB, URLScan
- `news-connector.ts`: Security news aggregation
- `breach-connector.ts`: Public breach data

#### 2. **Command Handlers** (`src/commands/`)
Map CLI commands to agent workflows:
- `brief-command.ts`: Daily briefing orchestration
- `cve-command.ts`: CVE search & impact analysis
- `ioc-command.ts`: IOC reputation lookup
- `policy-command.ts`: Hardening checklist generation
- `report-command.ts`: Incident report assembly

#### 3. **Verification Engine** (`src/verification/`)
- `corroboration.ts`: Cross-source validation
- `confidence.ts`: Confidence scoring
- `assumptions.ts`: Assumption tracking

#### 4. **Output System** (`src/output/`)
- `markdown-generator.ts`: Report formatting
- `json-generator.ts`: Structured data export
- `stix-generator.ts`: STIX 2.1 format (optional)

---

## 3. Safety & Guardrails

### Non-Negotiable Rules (Enforced in Code)

1. **Read-Only by Default**: All tools default to read-only mode. No system modification capabilities.

2. **No Offensive Capabilities**:
   - No exploit code generation
   - No intrusion instructions
   - No malware creation
   - No credential theft tools
   - No evasion techniques

3. **Explicit Authorization Required**: Any potentially destructive operations require explicit user confirmation and are logged.

4. **Data Handling**:
   - No plaintext storage of credentials
   - Redaction of sensitive data in logs
   - Clear labeling of assumptions vs. facts

5. **Rate Limiting & Caching**: Prevent abuse of external APIs.

### Implementation
- Pre-execution validation in agent loop
- Tool-level safety checks
- Output sanitization (redact API keys, tokens)
- Audit logging of all operations

---

## 4. Key Architectural Changes

### From Finance to Security Domain

| Component | Current (Finance) | New (Security) |
|-----------|-------------------|----------------|
| **Tools** | financial_search, tavily_search | security_search, tavily_search |
| **Sub-tools** | prices, fundamentals, filings, etc. | cve, advisory, ioc, news, breach |
| **Data Sources** | Financial Datasets API, market data | NVD, CISA, VirusTotal, vendor APIs |
| **Output** | Streaming text answer | MD report + JSON + optional STIX |
| **Prompts** | Financial analysis tone | Security analyst tone, verification focus |
| **Scratchpad** | .dexter/scratchpad/ | .gideon/scratchpad/ |
| **Config** | Environment variables only | YAML config + env vars |
| **Safety** | Basic (max iterations) | Enhanced (guardrails, verification, confidence) |

### Preserved Components
- Agent loop structure (iterations, tool execution, final answer)
- Scratchpad pattern for work tracking
- Multi-provider LLM support
- Streaming UI with real-time updates
- Context compaction strategy
- CLI interface framework (Ink)

---

## 5. Testing Strategy

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

---

## 6. Deployment & Usage

### Installation
```bash
git clone https://github.com/Requie/gideon.git
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

---

## Next Steps
1. ✅ Architecture design complete
2. Create file-by-file transformation plan
3. Implement core refactoring
4. Build first connector (CVE)
5. Add command system
6. Implement verification engine
7. Create output generators
8. Add tests
9. Update documentation
