---
title: Introduction
description: What is Gideon?
---

# Gideon 🛡️

Gideon is an **autonomous cybersecurity operations assistant** that performs security research using task planning, self-reflection, and real-time threat intelligence data. Built for defensive security operations - detection, mitigation, and protection.

## Why Gideon?

In a world of rapidly evolving threats, security teams are often overwhelmed by the sheer volume of CVEs, IOCs, and security news. Gideon acts as a force multiplier by:

- **Automating Research**: Turns complex security questions into structured, data-backed answers.
- **Dual Mode Precision**: Runs defensive diagnostics by default, and sandboxed [Red Team Mode](docs/features/red-team) autonomous exploitation when explicitly authorized.
- **Leveraging GPU Acceleration**: Seamlessly integrates with the NVIDIA AI stack for high-performance operations.

## Key Capabilities

- **CVE Research**: Analyze vulnerabilities from NVD and CISA KEV.
- **IOC Analysis**: Reputation checking for IPs, domains, and files.
- **Neural Search**: Deep web research powered by Exa AI.
- **Multi-Model**: Access to 400+ models via OpenRouter.
- **Daily Briefings**: Stay updated with automated security summaries.
- **Policy Generation**: Hardening checklists for the major cloud providers.

---

## The Gideon Philosophy

> [!IMPORTANT]
> **Dual Mode Principle**. Gideon operates securely as a defensive analyst by default. Operating in **Red Team Mode** requires explicit engagement scopes, locking offensive tools (nmap, sqli) to isolated Docker sandboxes and preventing lateral runaway.

Gideon follows a set of core principles:
1. **Transparency**: All reasoning is logged in a scratchpad for auditability.
2. **Corroboration**: Data is validated across multiple sources before being presented as fact.
3. **Safety First**: Red Team Mode includes scope-enforced execution and Docker-based Action Engine guardrails to prevent unapproved maneuvers.

---

## Next Steps

Ready to get started? Head over to the [Quick Start](/docs/getting-started/quickstart) guide to launch your first Gideon session.
