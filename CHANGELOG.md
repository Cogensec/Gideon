# Changelog

All notable changes to the Gideon project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - 2026-02-11

### Added

- **OpenClaw Sentinel Sidecar Security Platform** — Complete security layer for OpenClaw AI agents (`src/openclaw/`)
  - **Gateway Sentinel** (`gateway-sentinel.ts`) — Real-time WebSocket traffic analysis with CVE-2026-25253 kill chain tracking, behavioral profiling, and 9 parallel detection checks per message
  - **ClawHub Skill Scanner** (`skill-scanner.ts`) — Supply chain defense scanning for AMOS payloads, reverse shells, credential harvesting, code obfuscation, typosquatting, permission overreach, and publisher reputation
  - **Prompt Injection Defense** (`prompt-injection-defense.ts`) — 7-layer pattern detection (CSS-hidden, Unicode obfuscation, role overrides, tool invocation, memory poisoning, exfiltration instructions, delimiter escapes) plus NeMo Guardrails integration
  - **Hardening Auditor** (`hardening-auditor.ts`) — Configuration assessment across 8 categories (authentication, network, sandboxing, file permissions, credential storage, tool restrictions, runtime, skills) with A-F grading and drift detection
  - **Credential Guard** (`credential-guard.ts`) — File access monitoring, exfiltration pattern detection (credential-read-then-network chains), outbound content scanning with automatic redaction
  - **Memory Integrity Monitor** (`memory-integrity.ts`) — Memory poisoning detection with 11 indicator patterns, contradiction detection, and SHA-256 baseline hashing
  - **Policy Rules** (`policy-rules.ts`) — 12 OpenClaw-specific governance rules covering all CVEs and attack patterns
  - **Orchestrator** (`index.ts`) — Sidecar lifecycle management, multi-layer message routing, comprehensive report generation
  - **Type System** (`types.ts`) — Zod schemas for all OpenClaw-specific data types, CVE constants, MITRE technique mappings, known malicious campaign data

- **OpenClaw Sentinel Skill** (`src/skills/openclaw-sentinel/index.ts`) — 8 commands for managing the security sidecar
  - `openclaw-init` / `oc-init` — Initialize sidecar, register policies, run first audit
  - `openclaw-audit` / `oc-audit` — Run hardening assessment with A-F grade
  - `openclaw-scan-skill` / `oc-scan-skill` — Scan a ClawHub skill for threats
  - `openclaw-scan-injection` / `oc-scan-injection` — Check content for prompt injection
  - `openclaw-scan-memory` / `oc-scan-memory` — Scan memory files for poisoning
  - `openclaw-audit-creds` / `oc-audit-creds` — Audit credential storage security
  - `openclaw-status` / `oc-status` — Show health status of all modules
  - `openclaw-report` / `oc-report` — Generate comprehensive security report

- **OpenClaw Configuration** — New `openclaw:` section in `gideon.config.yaml` with settings for all 5 workstreams (gateway, sentinel, skill_scanner, injection_defense, hardening_auditor, credential_guard)

- **Feature Documentation** — `docs/src/content/docs/features/openclaw-sentinel.md` with full architecture diagram, workstream details, policy rules table, and getting started guide

### Changed

- **Skills Registry** (`src/skills/index.ts`) — Added `openclawSentinelSkill` to built-in skills array and re-exports
- **README.md** — Added OpenClaw Sentinel section, Agent Governance in key capabilities, OpenClaw skill in skills section, expanded architecture diagram with Governance and Sidecar layers, additional safety items
- **Features Overview** (`docs/src/content/docs/features/index.md`) — Reorganized into Core Security, Platform Security, and AI sections; added OpenClaw Sentinel link
- **Skills Overview** (`docs/src/content/docs/skills/index.md`) — Added OpenClaw Sentinel to built-in skills table and detailed guides
- **Configuration Reference** (`docs/src/content/docs/features/configuration.md`) — Added full OpenClaw Sentinel configuration section with all settings documented
- **Introduction** (`docs/src/content/docs/introduction.md`) — Added OpenClaw Sentinel and Agent Governance to key capabilities
- **Quick Start** (`docs/src/content/docs/getting-started/quickstart.md`) — Added optional OpenClaw security setup section
- **Core Concepts** (`docs/src/content/docs/architecture/core-concepts.md`) — Added Governance Layer and OpenClaw Sidecar Layer documentation
- **Advanced Capabilities** (`docs/src/content/docs/features/advanced-capabilities.md`) — Added OpenClaw Sentinel commands table to CLI reference
- **Project Roadmap** (`docs/src/content/docs/community/roadmap.md`) — Updated to v1.1 with all OpenClaw Sentinel and Governance items marked complete
- **Docs Sidebar** (`docs/astro.config.mjs`) — Added OpenClaw Sentinel to Features section, Features Overview and Skills Overview pages

### Security

- Defends against **CVE-2026-25253** (CVSS 8.8) — One-click RCE via token exfiltration, cross-site WebSocket hijacking, approval bypass, and sandbox escape
- Defends against **CVE-2026-24763** — Command injection through unsanitized gateway input
- Defends against **CVE-2026-25157** — Second command injection vector
- Defends against **CVE-2026-22708** — Invisible prompt injection via CSS-hidden web page instructions
- Defends against **ClawHavoc campaign** — 341+ malicious ClawHub skills distributing Atomic macOS Stealer (AMOS) via 14 compromised publisher accounts

## [1.0.0] - 2026-01-15

### Added

- Autonomous task planning and self-reflection agent loop (ReAct pattern)
- CVE Research connector (NVD + CISA KEV catalog)
- IOC Analysis connector (VirusTotal + AbuseIPDB)
- Neural semantic search via Exa AI
- Multi-model LLM support via OpenRouter (400+ models)
- Daily security briefing generation
- Security hardening policy generation (AWS, Azure, GCP, K8s, Okta)
- Modular skills system with registry
- Security Research skill (bug bounty, pentest, research, CTF modes)
- Threat Detection skill (NVIDIA Morpheus pipelines — DFP, DGA, Phishing, Ransomware)
- Data Analytics skill (NVIDIA RAPIDS — cuDF, cuGraph, cuML)
- Voice AI skill (NVIDIA PersonaPlex)
- Governance skill (audit logging, access control)
- NVIDIA NIM integration for local GPU-accelerated inference
- NVIDIA NeMo Guardrails integration (jailbreak detection, topic control, content safety)
- Agent governance system (agent registry, policy engine, agent monitor, access control, audit logger)
- Sensitive data redaction with configurable regex patterns
- Colang-based security rails definitions
- Astro Starlight documentation site
- Defensive-only safety mandate enforced at all layers
