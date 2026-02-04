# GIDEON🛡️

Gideon is an autonomous cybersecurity operations assistant that performs security research using task planning, self-reflection, and real-time threat intelligence data. Built for defensive security operations - detection, mitigation, and protection.

<img src="https://img.shields.io/badge/Security-Defensive%20Only-green" alt="Defensive Security"/>
<img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License"/>

## Overview

Gideon takes complex security questions and turns them into clear, step-by-step research plans. It executes those tasks using live threat intelligence, checks its own work, and refines results until it has a confident, data-backed answer.

**Key Capabilities:**
- **CVE Research**: Search and analyze vulnerabilities from NVD and CISA KEV catalog
- **IOC Analysis**: Reputation checking for IPs, domains, URLs, and file hashes
- **Daily Briefings**: Automated security intelligence summaries
- **Policy Generation**: Security hardening checklists for AWS, Azure, GCP, K8s, Okta
- **Intelligent Routing**: Automatically selects appropriate data sources
- **Self-Validation**: Checks findings across multiple sources and provides confidence scores
- **Structured Outputs**: Generates Markdown reports and JSON data files

**Safety Features:**
- Defensive mode only - no exploitation techniques or offensive capabilities
- Built-in safety blocks for malicious query patterns
- Cross-source verification and confidence scoring
- Rate limiting and caching to prevent API abuse

---

## Installation

### Prerequisites

- [Bun](https://bun.com) runtime (v1.0 or higher)
- API keys for LLM providers (OpenAI, Anthropic, Google, or local Ollama)
- Optional: API keys for security data sources (NVD, VirusTotal, AbuseIPDB)

#### Installing Bun

**macOS/Linux:**
```bash
curl -fsSL https://bun.com/install | bash
```

**Windows:**
```bash
powershell -c "irm bun.sh/install.ps1|iex"
```

Verify installation:
```bash
bun --version
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

Required keys in `.env`:
```env
# LLM Provider (at least one required)
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key
GOOGLE_API_KEY=your-google-key
OLLAMA_BASE_URL=http://127.0.0.1:11434

# Security Data Sources (optional but recommended)
NVD_API_KEY=your-nvd-key                    # Get at: https://nvd.nist.gov/developers/request-an-api-key
VIRUSTOTAL_API_KEY=your-virustotal-key      # Get at: https://www.virustotal.com/
ABUSEIPDB_API_KEY=your-abuseipdb-key        # Get at: https://www.abuseipdb.com/

# Web Search (optional)
TAVILY_API_KEY=your-tavily-key
```

4. Configure Gideon (optional):
Edit `gideon.config.yaml` to customize:
- Data source settings
- Rate limits
- Output formats
- Safety constraints

---

## Usage

### Interactive Mode

Run Gideon in interactive mode for natural language queries:

```bash
bun start
```

Example queries:
- "What are the latest critical CVEs for Microsoft Exchange?"
- "Analyze the IP address 8.8.8.8"
- "Show me log4j vulnerabilities from 2024"
- "Is malicious-domain.com safe?"

### Command Mode

Gideon provides specialized commands for common security operations:

#### Daily Security Briefing

```bash
bun start
> gideon brief
```

Generates a comprehensive daily briefing including:
- Critical CVEs from the last 24 hours
- Major vendor security advisories
- Notable security incidents
- Emerging threat trends

Outputs saved to: `./outputs/<timestamp>/`

#### CVE Search

```bash
> gideon cve <search query>
```

Examples:
```bash
> gideon cve CVE-2024-1234
> gideon cve log4j vulnerabilities 2024
> gideon cve latest critical windows
```

Provides:
- CVE details and description
- CVSS score and severity
- Affected products/versions
- Exploitation status
- Mitigations and patches

#### IOC Analysis

```bash
> gideon ioc <indicator>
```

Supported indicators:
- IP addresses: `gideon ioc 8.8.8.8`
- Domains: `gideon ioc suspicious-domain.com`
- URLs: `gideon ioc https://malicious-site.com`
- Hashes: `gideon ioc <md5|sha1|sha256>`

Provides:
- Reputation scores from VirusTotal and AbuseIPDB
- Malicious detection counts
- Geolocation and ISP info (for IPs)
- Recommended defensive actions
- Confidence assessment

#### Security Policy Generation

```bash
> gideon policy <stack>
```

Available stacks:
- `aws` - Amazon Web Services
- `azure` - Microsoft Azure
- `gcp` - Google Cloud Platform
- `k8s` - Kubernetes
- `okta` - Okta Identity Platform

Example:
```bash
> gideon policy aws
```

Generates a security hardening checklist with 15+ actionable items.

### Development Mode

Run with auto-reload for development:
```bash
bun dev
```

---

## Architecture

Gideon uses a modular agent-based architecture:

```
┌─────────────────────────────────────┐
│         Gideon CLI                   │
│  (Interactive + Command Mode)        │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│        Agent Core Loop               │
│  • Task planning                     │
│  • Tool execution                    │
│  • Self-validation                   │
│  • Confidence scoring                │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│      Security Tools Layer            │
│  ┌─────────────────────────────┐    │
│  │   security_search           │    │
│  │   (Intelligent router)      │    │
│  └──────────┬──────────────────┘    │
│             │                        │
│  ┌──────────▼──────────────────┐    │
│  │ Security Connectors         │    │
│  │ • CVE (NVD, CISA KEV)       │    │
│  │ • IOC (VT, AbuseIPDB)       │    │
│  │ • News feeds                │    │
│  └─────────────────────────────┘    │
└──────────────────────────────────────┘
```

**Key Features:**
- **Context Compaction**: Summarizes tool results to manage token usage
- **Scratchpad Pattern**: Logs all agent work for debugging
- **Rate Limiting**: Prevents API abuse
- **Caching**: 15-minute cache for API responses
- **Verification Engine**: Cross-source validation and confidence scoring

---

## Safety & Ethics

### Defensive Mode Only

Gideon is designed exclusively for defensive security operations:

✅ **Supported:**
- Vulnerability research and analysis
- Indicator of compromise reputation checking
- Security hardening recommendations
- Threat intelligence gathering
- Incident response support

❌ **Not Supported:**
- Exploitation techniques or proof-of-concept exploits
- Intrusion tools or methodologies
- Malware creation or analysis
- Credential theft or brute-forcing
- Detection evasion techniques

### Safety Mechanisms

1. **Query Filtering**: Blocks requests for offensive capabilities
2. **Output Sanitization**: Redacts sensitive data (API keys, tokens)
3. **Confidence Labeling**: Distinguishes facts from assumptions
4. **Rate Limiting**: Prevents abuse of external APIs
5. **Audit Logging**: Tracks all operations in scratchpad

---

## Configuration

Edit `gideon.config.yaml` to customize behavior:

```yaml
sources:
  nvd:
    enabled: true
    rate_limit: 5  # requests per second
    cache_ttl: 900  # 15 minutes

output:
  formats:
    - markdown
    - json
  directory: ./outputs
  redaction:
    enabled: true

agent:
  max_iterations: 10
  confidence_threshold: 0.6
  min_corroboration_sources: 2

safety:
  defensive_mode: true
  block_offensive: true
```

---

## Output Formats

Gideon generates structured outputs for all briefing and analysis commands:

### Markdown Reports
`./outputs/<timestamp>/report.md`

Human-readable reports with:
- Analysis summary
- Data sources used
- Metadata

### JSON Data
`./outputs/<timestamp>/data.json`

Machine-readable data with:
- Full content
- Tool call details
- Timestamps
- Metadata

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Push** to the branch (`git push origin feature/amazing-feature`)
4. **Open** a Pull Request

**Important:**
- Keep PRs small and focused
- Add tests for new features
- Maintain defensive-only focus
- Update documentation

---

## License

This project is licensed under the MIT License.

---

## Acknowledgments

- Built with [LangChain](https://www.langchain.com/)
- Powered by multiple LLM providers (OpenAI, Anthropic, Google, Ollama, Grok)
- Security data from NVD, CISA, VirusTotal, AbuseIPDB

---

## Support

- **Issues**: [GitHub Issues](https://github.com/cogensec/gideon/issues)
- **Documentation**: See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design
- **Transformation Plan**: See [TRANSFORMATION_PLAN.md](TRANSFORMATION_PLAN.md)

---

**Gideon**: Your autonomous cybersecurity operations assistant. Built for defenders, by defenders.
