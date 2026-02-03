# Gideon Agent System

Gideon is an autonomous cybersecurity operations assistant powered by large language models and NVIDIA AI acceleration technologies.

## Overview

Gideon operates as an intelligent agent that can:
- Analyze security threats and vulnerabilities
- Process indicators of compromise (IOCs)
- Generate security briefings and hardening recommendations
- Correlate events and detect attack patterns
- Provide voice-based security consultations

## Agent Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GIDEON AGENT                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   LLM Core  │  │  Tool Layer │  │   NVIDIA Acceleration   │ │
│  │             │  │             │  │                         │ │
│  │ • OpenAI    │  │ • CVE       │  │ • NIM (Local LLM)       │ │
│  │ • Anthropic │  │ • IOC       │  │ • PersonaPlex (Voice)   │ │
│  │ • Google    │  │ • Policy    │  │ • Guardrails (Safety)   │ │
│  │ • NVIDIA NIM│  │ • Search    │  │ • Morpheus (Detection)  │ │
│  │ • Ollama    │  │             │  │ • RAPIDS (Processing)   │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Agent Loop (`src/agent/agent.ts`)

The agent implements a ReAct-style loop:

1. **Receive Query** - User submits a security question
2. **Guardrails Check** - NeMo Guardrails validates input safety
3. **Tool Selection** - LLM decides which tools to invoke
4. **Tool Execution** - Execute security tools (CVE lookup, IOC analysis, etc.)
5. **Context Compaction** - Summarize results for efficient context usage
6. **Final Answer** - Generate comprehensive response
7. **Output Check** - Validate response safety before delivery

### 2. Security Tools (`src/tools/`)

| Tool | Purpose | Data Sources |
|------|---------|--------------|
| `security_search` | Meta-tool for security queries | Routes to appropriate connector |
| `cve_connector` | Vulnerability research | NVD, CISA KEV |
| `ioc_connector` | Indicator analysis | VirusTotal, AbuseIPDB |
| `tavily_search` | Web research | Tavily API |

### 3. Commands (`src/commands/`)

| Command | Description |
|---------|-------------|
| `gideon brief` | Daily security briefing |
| `gideon cve <query>` | CVE research |
| `gideon ioc <indicator>` | IOC analysis |
| `gideon policy <stack>` | Hardening recommendations |
| `gideon voice` | Voice interaction mode |
| `gideon analyze` | Morpheus threat detection |
| `gideon rapids` | GPU-accelerated data processing |

## NVIDIA AI Integration

Gideon leverages five NVIDIA AI technologies for enhanced capabilities:

### NVIDIA NIM (Local LLM Inference)

**Purpose:** Self-hosted, GPU-accelerated LLM inference

**Benefits:**
- Air-gapped/on-premises deployment
- 2.6x faster than CPU inference
- Data never leaves your infrastructure

**Configuration:**
```bash
NIM_BASE_URL=http://localhost:8000/v1
NIM_API_KEY=your-key
```

**Usage:**
```bash
# Select NIM from model menu
gideon
> /model
> Select: NVIDIA NIM
```

### NVIDIA PersonaPlex (Voice AI)

**Purpose:** Full-duplex speech-to-speech conversations

**Benefits:**
- Natural voice interaction with 170ms latency
- Simultaneous listening and speaking
- 16 voice options (natural/varied, male/female)
- Custom security analyst persona

**Configuration:**
```bash
PERSONAPLEX_URL=http://localhost:8998
PERSONAPLEX_VOICE=NATM1
PERSONAPLEX_CPU_OFFLOAD=true
```

**Usage:**
```bash
gideon voice                    # Start voice mode
gideon voice --voice NATF1      # Use specific voice
gideon voice --list-voices      # List available voices
```

### NVIDIA NeMo Guardrails (AI Safety)

**Purpose:** ML-based safety rails for LLM interactions

**Features:**
- **Jailbreak Detection** - Blocks bypass attempts (trained on 17K jailbreaks)
- **Topic Control** - Keeps queries within defensive security scope
- **Content Safety** - Filters harmful content from responses

**Configuration:**
```bash
NEMO_GUARDRAILS_URL=http://localhost:7331
NEMO_GUARDRAILS_ENABLED=true
```

**How it works:**
```
User Query → Jailbreak Check → Topic Check → Agent → Content Safety → Response
```

### NVIDIA Morpheus (Threat Detection)

**Purpose:** GPU-accelerated cybersecurity AI pipelines

**Pipelines:**
| Pipeline | Capability | Performance |
|----------|------------|-------------|
| Digital Fingerprinting | User behavior anomaly detection | Real-time |
| DGA Detection | Malware domain identification | 208K logs/sec |
| Phishing Detection | NLP email analysis | 99%+ accuracy |
| Ransomware Detection | Behavioral pattern detection | Real-time |

**Configuration:**
```bash
MORPHEUS_URL=http://localhost:8080
MORPHEUS_ENABLED=true
```

**Usage:**
```bash
gideon analyze --logs cloudtrail.json --type dfp
gideon analyze --domains suspicious.txt --type dga
gideon analyze --email phishing.eml --type phishing
gideon analyze --events appshield.json --type ransomware
```

### NVIDIA RAPIDS (Accelerated Data Processing)

**Purpose:** GPU-accelerated data science for security analytics

**Libraries:**
| Library | Purpose | Speedup |
|---------|---------|---------|
| cuDF | GPU DataFrames | 5-150x |
| cuML | Machine Learning | 10-50x |
| cuGraph | Graph Analytics | 100x+ |

**Operations:**
- **Batch IOC Analysis** - Process thousands of indicators in parallel
- **Event Correlation** - Build attack graphs from security events
- **Threat Clustering** - Group similar incidents
- **Network Graph Analysis** - Detect lateral movement
- **Anomaly Detection** - ML-based outlier detection

**Configuration:**
```bash
RAPIDS_URL=http://localhost:8090
RAPIDS_ENABLED=true
```

**Usage:**
```bash
gideon rapids --status                     # Check server status
gideon rapids --batch-ioc indicators.csv   # Batch IOC analysis
gideon rapids --correlate events.json      # Event correlation
gideon rapids --cluster threats.json       # Threat clustering
gideon rapids --graph flows.json           # Network analysis
gideon rapids --anomaly data.json          # Anomaly detection
```

## Safety & Guardrails

Gideon is designed exclusively for **defensive security**. Multiple layers ensure safe operation:

### 1. Pattern-Based Blocking
Hardcoded patterns block offensive requests:
- Exploitation techniques
- Malware creation
- Attack tools
- Social engineering

### 2. NeMo Guardrails (ML-Based)
ML models trained on real attack patterns:
- 17K known jailbreak attempts
- Content safety classification
- Topic boundary enforcement

### 3. Defensive-Only Prompts
System prompts reinforce defensive focus:
- No exploitation guidance
- No attack code generation
- Focus on detection and mitigation

## Scratchpad System

Gideon uses a scratchpad pattern for context management:

```
.gideon/scratchpad/
├── query_abc123.jsonl    # Tool calls and results
├── query_def456.jsonl    # Full audit trail
└── ...
```

Each query gets its own JSONL file tracking:
- Initial query
- Tool invocations
- Raw results
- LLM summaries
- Thinking steps

## Configuration

### Environment Variables

```bash
# LLM Providers
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_API_KEY=

# NVIDIA Stack
NIM_BASE_URL=http://localhost:8000/v1
PERSONAPLEX_URL=http://localhost:8998
NEMO_GUARDRAILS_URL=http://localhost:7331
MORPHEUS_URL=http://localhost:8080
RAPIDS_URL=http://localhost:8090

# Security Sources
NVD_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

### Configuration File (`gideon.config.yaml`)

See the configuration file for detailed settings including:
- Data source configuration
- Agent parameters
- Safety settings
- NVIDIA integration settings

## Development

### Adding New Tools

1. Create tool in `src/tools/security/`
2. Implement the connector interface
3. Register in `src/tools/index.ts`
4. Add to agent's tool list

### Adding New Commands

1. Create command in `src/commands/`
2. Export from `src/commands/index.ts`
3. Add CLI routing in `src/cli.tsx`

## Performance Benchmarks

| Operation | CPU | GPU (NVIDIA) | Speedup |
|-----------|-----|--------------|---------|
| LLM Inference | Baseline | NIM | 2.6x |
| IOC Batch (100K) | ~30 min | RAPIDS | 60x |
| Event Correlation | ~10 min | RAPIDS | 100x |
| Log Processing | ~1K/sec | Morpheus | 208x |
| Voice Latency | N/A | PersonaPlex | 170ms |

## License

Gideon is open source. See LICENSE for details.

NVIDIA components have their own licenses:
- NIM: NVIDIA AI Enterprise
- PersonaPlex: NVIDIA Open Model License
- NeMo Guardrails: Apache 2.0
- Morpheus: Apache 2.0
- RAPIDS: Apache 2.0
