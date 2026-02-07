# GIDEON 🛡️

Gideon is an autonomous cybersecurity operations assistant that performs security research using task planning, self-reflection, and real-time threat intelligence data. Built for defensive security operations - detection, mitigation, and protection.

<img src="https://img.shields.io/badge/Security-Defensive%20Only-green" alt="Defensive Security"/><img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License"/>

## Overview

Gideon takes complex security questions and turns them into clear, step-by-step research plans. It executes those tasks using live threat intelligence, checks its own work, and refines results until it has a confident, data-backed answer.

**Key Capabilities:**
- **CVE Research**: Search and analyze vulnerabilities from NVD and CISA KEV catalog.
- **IOC Analysis**: Reputation checking for IPs, domains, URLs, and file hashes.
- **Neural Semantic Search**: Deep web research powered by **Exa AI** for technical write-ups and obscure research.
- **Multi-Model Support**: Unified access to 400+ models via **OpenRouter** integration.
- **Daily Briefings**: Automated security intelligence summaries and notable incident tracking.
- **Policy Generation**: Security hardening checklists for AWS, Azure, GCP, K8s, and Okta.
- **Advanced Skills**: Specialized modules for Threat Detection, Data Analytics, and Voice AI.
- **Safety & Verification**: Cross-source validation and defensive-only safety blocks.

---

## Installation

### Prerequisites

- [Bun](https://bun.com) runtime (v1.3.6 or higher)
- API keys for LLM providers (OpenAI, Anthropic, Google, OpenRouter, or local Ollama)
- Optional: API keys for security data sources (NVD, VirusTotal, AbuseIPDB, Exa AI)

#### Installing Bun

**macOS/Linux:**
```bash
curl -fsSL https://bun.com/install | bash
```

**Windows:**
```bash
powershell -c "irm bun.sh/install.ps1|iex"
```

### Setup

1. Clone the repository:
```bash
git clone https://github.com/cogensec/gideon.git
cd gideon
```

2. Install dependencies:
```bash
bun install
```

3. Set up environment variables:
```bash
cp env.example .env
# Edit .env with your API keys
```

---

## Configuration

Gideon is highly configurable via environment variables and `gideon.config.yaml`.

### LLM & Model Configuration
| Variable | Description |
|----------|-------------|
| `OPENROUTER_API_KEY` | Access to 400+ models from OpenAI, Claude, etc. |
| `OPENAI_API_KEY` | Direct OpenAI API access. |
| `ANTHROPIC_API_KEY` | Direct Anthropic Claude access. |
| `GOOGLE_API_KEY` | Direct Google Gemini access. |
| `OLLAMA_BASE_URL` | Local LLM endpoint (default: `http://127.0.0.1:11434`). |

### Security Data & Search
| Variable | Description |
|----------|-------------|
| `EXA_API_KEY` | Neural semantic search for deep technical research. |
| `TAVILY_API_KEY` | General web search for security intelligence. |
| `NVD_API_KEY` | NIST Vulnerability Database (CVE) access. |
| `VIRUSTOTAL_API_KEY` | Indicator of Compromise (IOC) reputation. |
| `ABUSEIPDB_API_KEY` | IP reputation and malicious actor tracking. |

### NVIDIA AI Integration (Advanced)
Gideon integrates with NVIDIA's AI stack for high-performance operations:
- **NIM**: GPU-accelerated local LLM inference.
- **PersonaPlex**: Hands-free voice AI for security operations.
- **Morpheus**: AI-powered threat detection pipelines (DFP, DGA, Anti-phishing).
- **RAPIDS**: Accelerated data science for batch IOC analysis.
- **NeMo Guardrails**: Enterprise-grade AI safety and topic control.

---

## Advanced Skills System

Gideon features a modular "Skills" system that extends its core capabilities.

### 🛡️ Security Research
Advanced bug bounty hunting and penetration testing assistance.
- **Commands**: `start [mode]`, `scope [program]`, `recon [target]`, `hunt [vuln-class]`.
- **Modes**: `bounty`, `pentest`, `research`, `ctf`.

### 🎙️ Voice AI
Hands-free security operations using NVIDIA PersonaPlex.
- **Commands**: `speak [text]`, `voice-set [voice-id]`, `voice-list`, `voice-enable`, `voice-status`.

### 🔍 Threat Detection
Real-time analysis using NVIDIA Morpheus pipelines.
- **Capabilities**: Phishing detection, DGA analysis, Ransomware pattern matching.

### 🛡️ Governance & Safety
Multi-layer protection using NVIDIA NeMo Guardrails.
- **Features**: Jailbreak detection, topic steering, self-correction, and audit logging.

### 🔐 OpenClaw Sentinel
Comprehensive security sidecar for OpenClaw agent deployments.
- **Commands**: `openclaw-init`, `openclaw-status`, `openclaw-audit`, `openclaw-scan-skill <name>`, `openclaw-scan-injection <content>`, `openclaw-report`.
- **Security Modules**: Gateway Sentinel, Skill Scanner, Prompt Injection Defense, Hardening Auditor, Credential Guard, Memory Monitor.
- **CVE Coverage**: CVE-2026-25253, CVE-2026-24763, CVE-2026-25157, CVE-2026-22708, ClawHavoc campaign.

---

## Usage

### Interactive Mode
Launch the Gideon shell for natural language queries:
```bash
bun start
```

### Specialized Operations
- **Security Briefing**: `> gideon brief`
- **CVE Lookup**: `> gideon cve CVE-2024-1234`
- **IOC Reputation**: `> gideon ioc 8.8.8.8`
- **Hardening Policy**: `> gideon policy aws`
- **Skill Management**: `> skills` (Show enabled skills and commands)

---

## Architecture

Gideon uses a modular agent-based architecture designed for extensibility:

```mermaid
graph TD
    UI[Gideon CLI / Interactive] --> Core[Agent Core Loop]
    Core --> Planning[Task Planning & Reasoning]
    Core --> Tools[Tools & Skills Layer]
    
    subgraph "Tools Layer"
        Search[Web & Neural Search - Exa/Tavily]
        SecRepo[Security Repos - NVD/CISA]
        ThreatIntel[IOC Analysis - VT/AbuseIPDB]
    end
    
    subgraph "NVIDIA AI Stack"
        NIM[NIM - Local Models]
        Morpheus[Morpheus - Threat Pipelines]
        Plex[PersonaPlex - Voice AI]
        NeMo[NeMo - Safety Guardrails]
    end
    
    Tools --> Search
    Tools --> SecRepo
    Tools --> ThreatIntel
    Tools --> NIM
    Tools --> Morpheus
    Tools --> Plex
    Tools --> NeMo
```

---

## Safety & Ethics

Gideon is designed **exclusively for defensive security operations**. It includes built-in safety mechanisms to prevent misuse:
1. **Query Filtering**: Rejects requests for exploitation techniques or offensive tools.
2. **Defensive Prompting**: Always prioritizes mitigation, patching, and protection.
3. **Data Redaction**: Automatically redacts sensitive information from logs and outputs.
4. **Safety Guardrails**: Leverages NeMo Guardrails for enterprise-grade topic control.

---

## License
MIT License. Created by **Cogensec** for defenders, by defenders.
Gideon: Your autonomous cybersecurity operations assistant.
