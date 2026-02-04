---
title: Configuration Reference
description: A complete guide to configuring Gideon using gideon.config.yaml.
---

Gideon is configured using a central `gideon.config.yaml` file. This file controls everything from threat intelligence sources to safety guardrails and output formats.

## Sources Configuration

Each security intelligence source can be enabled or disabled and tuned for performance.

```yaml
sources:
  nvd:
    enabled: true
    base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    rate_limit: 5     # requests per second
    cache_ttl: 900    # 15 minutes
  virustotal:
    enabled: true
    rate_limit: 4     # requests per minute (free tier)
```

## Agent Governance

Configure how Gideon monitors and controls its own behavior.

```yaml
governance:
  enabled: true
  monitoring:
    behavioral_profiling: true
    anomaly_sensitivity: 0.7
  access_control:
    require_justification: true
```

## Safety & Redaction

Gideon is designed with a **Defensive-Only** posture. These settings ensure it never generates or processes offensive content.

```yaml
safety:
  defensive_mode: true      # Strictly blocks offensive capabilities
  block_offensive: true     # Prevents generation of exploit code
  require_explicit_auth: false
```

### Sensitive Data Redaction
Gideon automatically scrubs sensitive data (API keys, passwords, tokens) from its outputs using regex patterns.

```yaml
redaction:
  enabled: true
  patterns:
    - "(?i)(api[_-]?key|token|password|secret)\\s*[:=]\\s*['\"]?([^'\"\\s]{8,})"
```

## AI Guardrails (NVIDIA NeMo)

Gideon uses [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) to enforce topical boundaries.

```yaml
guardrails:
  enabled: true
  input_rails:
    jailbreak_detection: true # Blocks prompt injection/jailbreaking
    topic_control: true       # Ensures conversation stays on security
  allowed_topics:
    - cybersecurity
    - vulnerability analysis
    - incident response
  blocked_topics:
    - offensive security
    - malware development
```
