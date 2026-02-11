---
title: Quick Start
description: Get Gideon running in 5 minutes.
---

# Quick Start 🚀

Get Gideon up and running on your local machine to start performing automated security research.

## Prerequisites

- [Bun](https://bun.com) v1.3.6 or higher.
- API keys for at least one LLM provider (OpenRouter recommended).
- Optional: API keys for search/security data (Exa, VirusTotal, etc.).

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/cogensec/gideon.git
cd gideon
```

### 2. Install Dependencies

```bash
bun install
```

### 3. Setup Environment Variables

Copy the example environment file and add your API keys.

```bash
cp env.example .env
```

Edit the `.env` file:
```bash
# Recommended for multi-model access
OPENROUTER_API_KEY=your_key_here

# Required for deep research
EXA_API_KEY=your_key_here
```

## Running Gideon

### Interactive Mode
Launch the Gideon shell for natural language queries:

```bash
bun start
```

### Specialized Commands
You can also run specific security tasks directly from the CLI:

- **Security Briefing**: `bun start brief`
- **CVE Lookup**: `bun start cve CVE-2024-1234`
- **IOC Reputation**: `bun start ioc 8.8.8.8`

### OpenClaw Security (Optional)
If you run [OpenClaw](https://github.com/openclaw/openclaw) AI agents, initialize the security sidecar:

```bash
> openclaw-init
```

This registers all 12 security policies, creates a governed agent entry, and runs the initial hardening audit. Use `openclaw-status` to check module health at any time.

---

## What's Next?

Learn more about Gideon's [Core Architecture](/docs/architecture/core-concepts), explore the [Modular Skill System](/docs/skills), or set up the [OpenClaw Sentinel](/docs/features/openclaw-sentinel) for AI agent security.
