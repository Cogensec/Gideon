# AGENTS.md

Gideon is a cybersecurity operations assistant built with TypeScript, Bun, React (Ink), and LangChain. It integrates NVIDIA AI technologies for GPU acceleration. Gideon operates in two modes: **Defensive Mode** (default) for threat intelligence, analysis, and hardening, and **Red Team Mode** for authorized offensive security engagements.

## Commands

```bash
# Install dependencies
bun install

# Run in development mode
bun run dev

# Run production
bun run start

# Type checking
bun run typecheck

# Run tests
bun test

# Run tests in watch mode
bun test:watch
```

## Testing

- Run `bun test` before committing
- Run `bun run typecheck` to verify TypeScript types
- All tests must pass before merging

## Project Structure

```
src/
├── agent/          # Agent loop implementation (ReAct pattern)
├── c2/             # C2 framework integration (Sliver, Mythic)
├── commands/       # CLI commands (brief, cve, ioc, policy, skills)
├── components/     # Ink React components for terminal UI
├── connectors/     # External API connectors (NVD, VirusTotal, AbuseIPDB)
├── engine/         # Action engine for tool orchestration & sandboxed execution
├── guardrails/     # NeMo Guardrails config (config.yml, security-rails.co)
├── model/          # LLM provider setup (OpenAI, Anthropic, Google, Ollama, NIM)
├── skills/         # Modular skill system (see Skills Architecture)
├── tools/          # LangChain tools for security operations
└── utils/          # Utilities (nim.ts, personaplex.ts, morpheus.ts, rapids.ts)
```

## Skills Architecture

Gideon uses a modular skills system. Each skill is self-contained with commands, tools, and lifecycle hooks.

```
src/skills/
├── index.ts              # Skill registry and initialization
├── types.ts              # Skill interface definitions
├── registry.ts           # Skill management
├── security-research/    # Bug bounty, pentest, security research
├── threat-detection/     # Morpheus-powered threat detection
├── data-analytics/       # RAPIDS-powered data processing
├── code-scanning/        # Static analysis, vulnerability scanning
├── voice/                # PersonaPlex speech-to-speech
├── governance/           # Access control, audit logging
├── post-exploitation/    # [RED TEAM] Domain mapping, lateral movement, privesc
└── weaponization/        # [RED TEAM] Payload generation, obfuscation, evasion
```

### Adding a New Skill

```typescript
// src/skills/my-skill/index.ts
import { Skill, SkillCommand } from '../types.js';

const commands: SkillCommand[] = [
  {
    name: 'my-command',
    description: 'What it does',
    usage: 'my-command <arg>',
    execute: async (args, ctx) => {
      return { success: true, output: 'Result' };
    },
  },
];

export const mySkill: Skill = {
  metadata: {
    id: 'my-skill',
    name: 'My Skill',
    description: 'What this skill does',
    version: '1.0.0',
    category: 'utility',
    capabilities: {
      providesTools: false,
      requiresGpu: false,
      supportsCpuFallback: true,
      stateful: false,
      requiresExternalService: false,
    },
  },
  commands,
  async isAvailable() { return true; },
};

// Register in src/skills/index.ts
```

### Built-in Skills

| Skill | Category | Description |
|-------|----------|-------------|
| security-research | security-research | Bug bounty, pentest workflows |
| threat-detection | threat-detection | Morpheus threat detection |
| data-analytics | data-analytics | RAPIDS data processing |
| code-scanning | code-analysis | Static vulnerability scanning |
| voice | voice | PersonaPlex speech AI |
| governance | governance | Access control, audit logs |
| post-exploitation | security-research | [RED TEAM] Domain mapping, lateral movement, privesc |
| weaponization | security-research | [RED TEAM] Payload generation, obfuscation, evasion |

## Code Style

- TypeScript strict mode enabled
- ESNext modules with Bun runtime
- React JSX for terminal UI (Ink)
- Zod for runtime validation
- Async/await over raw promises

```typescript
// Preferred: explicit types, async/await
export async function analyzeIOC(indicator: string): Promise<IOCResult> {
  const response = await fetch(url);
  const data = await response.json();
  return IOCResultSchema.parse(data);
}

// Avoid: implicit any, .then() chains
```

## Git Workflow

- Use descriptive commit messages
- PR titles: `Add feature`, `Fix bug`, `Update component`
- Run `bun test && bun run typecheck` before committing

## NVIDIA Integrations

When modifying NVIDIA utilities:

| Component | File | Service Port |
|-----------|------|--------------|
| NIM (LLM) | `src/utils/nim.ts` | 8000 |
| PersonaPlex (Voice) | `src/utils/personaplex.ts` | 8998 |
| NeMo Guardrails | `src/utils/nemo-guardrails.ts` | 7331 |
| Morpheus (Detection) | `src/utils/morpheus.ts` | 8080 |
| RAPIDS (Processing) | `src/utils/rapids.ts` | 8090 |

All NVIDIA integrations support CPU offload mode for systems without GPUs.

## Environment Variables

Required API keys go in `.env` (see `env.example`):
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` - LLM providers
- `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` - Security data
- `NIM_BASE_URL`, `PERSONAPLEX_URL`, `MORPHEUS_URL`, `RAPIDS_URL` - NVIDIA services

## Boundaries

**Never modify:**
- `.env` files (contain secrets)
- `node_modules/`
- User credentials or API keys
- Production configuration without explicit request

**Security focus — Dual Mode Architecture:**

Gideon operates in two modes:

**Defensive Mode (default):**
- Focus on detection, analysis, and remediation
- NeMo Guardrails block offensive topics
- No exploitation or payload capabilities loaded

**Red Team Mode (authorized engagements only):**
- Activated via `/redteam` with explicit engagement authorization
- All operations are scope-validated and audit-logged
- Human-in-the-loop approval for exploitation and post-exploitation
- Auto-deactivates after engagement window expires
- Guardrails remain active for jailbreak/prompt injection defense

**When adding security tools:**
1. Create connector in `src/connectors/` or `src/tools/security/`
2. Add rate limiting via Bottleneck
3. Implement caching with node-cache
4. Register in `src/tools/index.ts`
5. For offensive tools: add to `src/engine/tool-adapters.ts` and gate behind Red Team mode

## Adding New Commands

```typescript
// src/commands/example.ts
import { Command } from './types';

export const exampleCommand: Command = {
  name: 'example',
  description: 'Example command',
  execute: async (args) => {
    // Implementation
  },
};

// Export from src/commands/index.ts
export { exampleCommand } from './example';
```

## Configuration

Main config: `gideon.config.yaml`
- `sources`: External API endpoints and rate limits
- `agent`: Loop parameters (max_iterations, confidence_threshold)
- `safety`: Defensive mode settings
- `redteam`: Red Team mode configuration (tools, sandbox, audit)
- `guardrails`: NeMo Guardrails settings
- `morpheus`: Threat detection pipelines
- `rapids`: Accelerated analytics settings

## Red Team Architecture

```
src/agent/redteam-mode.ts    # Mode manager, engagement authorization, scope enforcement
src/engine/                   # Action Engine for tool orchestration
├── action-engine.ts          # Core execution orchestrator
├── sandbox.ts                # Docker-based sandboxed execution
└── tool-adapters.ts          # nmap, nuclei, sqlmap, metasploit adapters
src/c2/                       # C2 framework integration
├── c2-manager.ts             # Unified C2 management layer
└── adapters/sliver-adapter.ts # Sliver gRPC client
src/skills/post-exploitation/ # Domain mapping, credential ops, lateral movement
src/skills/weaponization/     # Payload generation, encoding, obfuscation, EDR evasion
```

**Key design principles:**
- Every offensive action is scope-validated before execution
- All tool executions run inside Docker sandboxes
- Approval gates for exploitation and post-exploitation phases
- Full audit trail for engagement reporting
- Red Team skills are dynamically registered/unregistered with mode changes
