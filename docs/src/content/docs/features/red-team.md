---
title: Red Team Mode
description: Autonomous Red Teaming, Post-Exploitation, and Engagement Scoping
---

Gideon features a powerful **Dual-Mode Security Architecture**. While it operates as a defensive analyst by default, it can be transitioned into **Red Team Mode** for explicitly authorized penetration tests and security engagements.

## Engaging Red Team Mode

To activate Red Team mode and unlock offensive capabilities, use the `/redteam` command. 

```bash
> /redteam
```

> [!CAUTION]
> Gideon will execute live offensive tools (Nmap, Nuclei, SQLMap, Metasploit) and generate payloads when in Red Team mode. Do not enable this mode when connected to unauthorized networks.

## Action Engine & Sandbox

Because of the unpredictable nature of executing generative-AI-guided shell commands, Gideon routes all offensive operations through its **Action Engine**. 
The Action Engine wraps these commands inside an isolated Docker container (`gideon-toolbox`), ensuring that your host operating system is completely insulated from side-effects or rogue exploit executions.

## Unified C2 Integration

Gideon integrates directly with C2 frameworks like **Sliver** and **Mythic**. Upon compromising a host, the agent uses the `c2_sessions` and `c2_shell` tools to autonomously enumerate the host, retrieve process lists, and plan lateral movement without requiring manual operator proxies.

## Skills

### Post-Exploitation
The `post-exploitation` skill tracks domain mappings via a graph database (Neo4j) extending our attack surface graph to internal domains.
- **Situational Awareness**: Tracking compromised hosts and loaded credentials (`skills post-exploitation sitrep`)
- **Credential Harvesting**: Generating harvesting plans (`skills post-exploitation harvest`)
- **Lateral Movement**: An algorithmic planner evaluating movement techniques (WinRM, WMI, SSH, Pass-the-Hash) against discovered credentials.

### Weaponization
The `weaponization` skill provides real-time payload compilation and evasion handling.
- **Payload Generation**: Leveraging `msfvenom` for generation and automated encoding.
- **Obfuscation**: Planners mapping out obfuscation steps for C#, PowerShell, Python, and C loaders.
- **EDR Evasion**: A library of implementations for Direct Syscalls, Process Hollowing, and AMSI Patching.

## Safety Controls

Even in Red Team Mode, Gideon operates under strict controls:
1. **Engagement Scopes**: Every execution validates the target against subnet ranges, IP whitelists, and wildcard scopes.
2. **Jailbreak Detection**: NeMo Guardrails continue tracking for adversarial prompt injections that try to manipulate the agent against its operator.
3. **Audit Trails**: cryptographically referenced audit logs ensure the entire engagement is documented for read-out reporting.
