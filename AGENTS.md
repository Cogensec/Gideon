# AGENTS.md

Gideon is a cybersecurity operations assistant built with TypeScript, Bun, React (Ink), and LangChain. It integrates NVIDIA AI technologies for GPU acceleration.

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
├── commands/       # CLI commands (brief, cve, ioc, policy, voice, analyze, rapids)
├── components/     # Ink React components for terminal UI
├── connectors/     # External API connectors (NVD, VirusTotal, AbuseIPDB)
├── guardrails/     # NeMo Guardrails config (config.yml, security-rails.co)
├── model/          # LLM provider setup (OpenAI, Anthropic, Google, Ollama, NIM)
├── tools/          # LangChain tools for security operations
└── utils/          # Utilities (nim.ts, personaplex.ts, nemo-guardrails.ts, morpheus.ts, rapids.ts)
```

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

**Security focus:**
- Gideon is DEFENSIVE ONLY - never generate offensive security code
- Never provide exploitation techniques, attack tools, or malware
- Focus on detection, analysis, and remediation
- Block requests for hacking tutorials or social engineering

**When adding security tools:**
1. Create connector in `src/connectors/` or `src/tools/security/`
2. Add rate limiting via Bottleneck
3. Implement caching with node-cache
4. Register in `src/tools/index.ts`

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
- `guardrails`: NeMo Guardrails settings
- `morpheus`: Threat detection pipelines
- `rapids`: Accelerated analytics settings
