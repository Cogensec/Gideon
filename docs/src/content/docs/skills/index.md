---
title: Skills System
description: Understanding and extending Gideon's modular capabilities.
---

# Modular Skills System 🛠️

Gideon features a powerful "Skills" system that allows for rapid extension of its core capabilities. Every major feature in Gideon—from Voice AI to Threat Detection—is implemented as a skill.

## What is a Skill?

A skill is a self-contained module that provides:
- **Commands**: Specific CLI triggers (e.g., `gideon brief`).
- **Tools**: Wrappers for LLM use via LangChain.
- **Lifecycle Hooks**: Initialization and availability checks.

## Built-in Skills

| Skill | Description | Requirements |
|-------|-------------|--------------|
| **Security Research** | Workflows for bug bounty and pentest assistance. | None |
| **Threat Detection** | Morpheus-powered analysis of network traffic and logs. | NVIDIA GPU |
| **Data Analytics** | RAPIDS-powered batch processing of IOCs. | NVIDIA GPU |
| **Voice AI** | Hands-free operation using PersonaPlex. | NVIDIA GPU |
| **Governance** | Audit logging and access control logic. | None |
| **OpenClaw Sentinel** | Sidecar security for OpenClaw AI agents. 8 commands covering gateway monitoring, skill scanning, prompt injection defense, hardening audits, credential protection, and memory integrity. | OpenClaw instance |

## Skill Structure

Skills are located in `src/skills/`. A typical skill directory looks like this:

```bash
src/skills/my-skill/
├── index.ts      # Main registration and metadata
├── tools.ts      # Tool definitions (LangChain)
├── commands.ts   # CLI command handlers
└── types.ts      # Skill-specific type definitions
```

---

## Adding a New Skill

Adding a skill is a three-step process:

### 1. Define Metadata
Define what the skill provides and its hardware requirements.

### 2. Register Commands & Tools
Map your logic to the Gideon CLI and the Agent Core loop.

### 3. Register in the Registry
Export your skill from `src/skills/index.ts`.

> [!TIP]
> Always implement a CPU fallback for skills that primarily use GPU acceleration (like NVIDIA NIM integrations) to ensure Gideon remains portable.

---

## Detailed Skill Guides

- [Security Research](/docs/skills/security-research)
- [Threat Detection (Morpheus)](/docs/skills/threat-detection)
- [Voice AI (PersonaPlex)](/docs/skills/voice-ai)
- [OpenClaw Sentinel](/docs/features/openclaw-sentinel)
