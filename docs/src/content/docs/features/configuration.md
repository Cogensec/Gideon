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

## OpenClaw Sentinel

Configure the sidecar security platform for OpenClaw AI agents. All settings live under the `openclaw:` key.

```yaml
openclaw:
  enabled: true
  gateway:
    gateway_url: "ws://127.0.0.1:18789"  # OpenClaw WebSocket endpoint
    bind_mode: localhost                   # Expected bind mode
    openclaw_home: "~/.openclaw"           # OpenClaw data directory
  sentinel:
    enabled: true
    behavioral_profiling: true             # Build per-session behavior baselines
    detect_cve_2026_25253: true            # CVE-2026-25253 kill chain tracking
    anomaly_sensitivity: 0.7               # Behavioral anomaly threshold
    kill_chain_threshold: 2                # Stages before critical alert
  skill_scanner:
    enabled: true
    block_critical: true                   # Auto-block critical-risk skills
    check_typosquatting: true              # Detect name impersonation
    check_obfuscation: true                # Detect encoded payloads
    publisher_min_age_days: 30             # Minimum account age
  injection_defense:
    enabled: true
    confidence_threshold: 0.7              # Detection confidence cutoff
    use_nemo_guardrails: true              # Use NeMo jailbreak model
    sanitize_content: true                 # Auto-strip injection payloads
  hardening_auditor:
    enabled: true
    detect_drift: true                     # Alert on config changes between audits
    min_token_length: 32                   # Minimum auth token strength
  credential_guard:
    enabled: true
    redact_outbound: true                  # Auto-redact secrets in outbound data
    exfiltration_detection: true           # Detect credential-read-then-network patterns
    bulk_read_threshold: 5                 # Memory files read before alerting
```

For a full walkthrough of each workstream, see the [OpenClaw Sentinel feature page](/docs/features/openclaw-sentinel).
