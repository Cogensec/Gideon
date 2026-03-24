# Changelog

All notable changes to Gideon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-03-23

### Fixed
- **Strict Type Safety Enforcement**: Resolved ~80 TypeScript compilation errors to achieve successful compilation via `tsc --noEmit`.
- **Barrel File Re-exports (`src/gideon/index.ts`)**: 
  - Updated re-exports from `prompts.ts`, `recon.ts`, and `reports.ts`.
  - Replaced non-existent exports (e.g., `buildReportPrompt`, `formatHackerOneReport`) with actual implementations (like `buildStatusPrompt`, `generateEngagementReport`).
- **Zod v4 API Compatibility**: 
  - Updated `z.record(z.any())` schemas to `z.record(z.string(), z.any())` ensuring compliance with v4 schema definitions.
  - Removed explicit empty object assignments `.default({})` for properties with required fields to fix parameter overload mismatch errors across `governance/types.ts`, `openclaw/types.ts`, `skills/types.ts`, `tools/security/types.ts`, and `utils/config-loader.ts`.
- **Skills Layer Refactoring**: Fixed staleness by aligning references with current underlying internal APIs.
  - *Code Scanning*: Migrated logic to `scanPath` from deprecated `scanDirectory`, updating internal result field mappings.
  - *Data Analytics*: Updated deprecated `runBatchIOCAnalysis` calls to `batchAnalyzeIOCs`, alongside modern `RapidsResult` fields.
  - *Governance*: Standardized proxy entity property access (e.g., `createdAt` -> `registeredAt`, `lastActiveAt` -> `lastSeenAt`) and properly invoked `AuditLogger.listPolicySets`.
  - *Security Research*: Realigned missing toolkit functions (`getToolsByCategory`) and updated missing enumeration fallback hooks.
  - *Threat Detection*: Updated commands to modern Morpheus GPU pipeline wrappers (`analyzeWithDFP`, `detectDGA`, `detectPhishing`, `detectRansomware`).
  - *Voice*: Remapped `speakText` invocation footprint to match the `textToSpeech` generalized parameterized options dictionary format.
- **Null-Safety & Casting Validations**:
  - `gideon.ts`: Re-aligned parameter properties for accurately calculating `CVSSInput`.
  - `rapids.ts`: Eliminated compilation type-casting violations across operations by using safe intermediaries (`as unknown as Type`).
  - `agent-registry.ts`: Corrected potential truthy syntax leaks utilizing strict conditional object spreading.
  - `credential-guard.ts` & `personaplex.ts`: Installed exact strict `null` and `undefined` bounding criteria for WebSocket connections and active session handling properties.
  - `scanner.ts`: Deduped recursive object properties initialized within native code configurations.

## [1.1.0] - 2026-02-07

### Added
- **OpenClaw Sentinel** — Comprehensive security sidecar for OpenClaw agent deployments
  - Gateway Sentinel for real-time WebSocket traffic analysis and behavioral profiling
  - ClawHub Skill Scanner for supply chain defense against malicious skills
  - Prompt Injection Defense with NeMo Guardrails integration
  - Hardening Auditor with A-F grading and configuration drift detection
  - Credential Guard for exfiltration pattern detection and outbound data redaction
  - Memory Integrity Monitor for poisoning detection
  - 12 pre-built OpenClaw-specific policy rules
  - Commands: `openclaw-init`, `openclaw-status`, `openclaw-audit`, `openclaw-scan-skill`, `openclaw-scan-injection`, `openclaw-scan-memory`, `openclaw-audit-creds`, `openclaw-report`
  - CVE coverage: CVE-2026-25253, CVE-2026-24763, CVE-2026-25157, CVE-2026-22708
  - ClawHavoc campaign detection (800+ malicious skills, Atomic macOS Stealer)

- **OpenRouter Integration** — Unified access to 400+ LLM models
  - Browse and select from all available OpenRouter models
  - Automatic model list caching
  - Fallback support for direct provider APIs and local Ollama

- **Exa AI Neural Search** — Deep semantic search for technical security research
  - Powers advanced web research for CVE analysis and threat intelligence
  - Complements Tavily for comprehensive search coverage

### Enhanced
- **Documentation Site** — Expanded GideoDocs with OpenClaw integration guides
- **Skills System** — Added OpenClaw Sentinel to built-in skills registry
- **Quick Start Guide** — Added OpenClaw initialization instructions

## [1.0.0] - 2026-01-15

### Added
- **Core Agent Loop** — Task planning, self-reflection, and iterative reasoning
- **CVE Research** — NVD and CISA KEV integration for vulnerability analysis
- **IOC Analysis** — VirusTotal and AbuseIPDB for indicator reputation checking
- **Security Briefings** — Automated daily intelligence summaries
- **Policy Generation** — Hardening checklists for AWS, Azure, GCP, K8s, Okta
- **NVIDIA AI Stack Integration**
  - NIM for GPU-accelerated local LLM inference
  - Morpheus for AI-powered threat detection (DFP, DGA, Phishing, Ransomware)
  - PersonaPlex for hands-free Voice AI operations
  - RAPIDS for accelerated batch IOC processing
  - NeMo Guardrails for enterprise AI safety
- **Agent Governance** — Policy engine, behavioral profiling, hash-chain audit logging
- **Multi-Model Support** — OpenAI, Anthropic, Google, OpenRouter, Ollama
- **Safety Mechanisms** — Defensive-only mode, sensitive data redaction

[Unreleased]: https://github.com/cogensec/gideon/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/cogensec/gideon/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cogensec/gideon/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cogensec/gideon/releases/tag/v1.0.0
