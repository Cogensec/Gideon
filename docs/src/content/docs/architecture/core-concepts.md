---
title: Core Concepts
description: The fundamental building blocks of Gideon.
---

# Core Concepts 🏗️

Gideon is built on a modular, agent-based architecture designed for extensibility, safety, and transparency.

## 1. System Overview

At its heart, Gideon is a defensive security operations assistant. It doesn't just search for information; it reasons about security problems.

- **Objective-Oriented**: Gideon takes high-level goals (e.g., "Analyze the impact of CVE-2024-1234 on our stack") and breaks them into tasks.
- **Defensive Focus**: Every component is designed to prioritize mitigation and protection over exploitation.
- **Multi-Layered Security**: Combines pattern-based checks, LLM reasoning, and enterprise-grade guardrails (NVIDIA NeMo).

## 2. The Module System

Gideon's functionality is divided into four main layers:

### CLI & UI Layer
The entry point for all interactions. Built with **React (Ink)** for a rich, interactive terminal experience.

### Agent Core Loop
The reasoning engine. Implements the **ReAct (Reason + Act)** pattern, allowing Gideon to think, call tools, and reflect on the results.

### Security Tools Layer
Standardized connectors to external data sources:
- **CVE Connector**: NVD, CISA KEV catalog.
- **IOC Connector**: VirusTotal, AbuseIPDB, URLScan.
- **Web Search**: Exa AI (Neural Search), Tavily.

### NVIDIA AI Stack
Optional GPU-accelerated integrations for high-performance operations:
- **NIM**: Local LLM inference.
- **Morpheus**: Threat detection pipelines.
- **PersonaPlex**: Voice AI.
- **NeMo Guardrails**: Topic control and safety.

---

## 3. Data Flow & Transparency

Gideon maintains a **Scratchpad**—an append-only log of every thought and tool result. This ensures:
- **Auditability**: You can see exactly why Gideon reached a conclusion.
- **Self-Correction**: Gideon can review previous steps and correct assumptions if new data contradicts them.
- **Context Management**: Large tool results are summarized to maintain relevant context without overwhelming the LLM.
