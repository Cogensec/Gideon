import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';
import { callLlm, getFastModel } from '../model/llm.js';
import { estimateTokens } from '../agent/context-compressor.js';
import { redactSecrets } from '../memory/redaction.js';
import { getInsightsConfig } from '../utils/config-loader.js';

// ============================================================================
// InsightsAnalyzer — after-action analytics over the scratchpad JSONL logs
// (Hermes insights engine analog). Pure reader: no LLM needed for the stats;
// an optional fast-model `narrate()` produces prose.
// ============================================================================

const SCRATCHPAD_DIR = join('.gideon', 'scratchpad');

export interface SessionInsights {
  sessions: number; // scratchpad files
  queries: number;
  toolCalls: number;
  toolBreakdown: Record<string, number>;
  errors: number;
  approxTokens: number;
  findings: string[];
  learnedSkills: number;
  firstAt?: string;
  lastAt?: string;
}

interface ScratchpadEntry {
  type: 'init' | 'tool_result' | 'thinking';
  timestamp?: string;
  content?: string;
  toolName?: string;
  result?: unknown;
  llmSummary?: string;
}

export class InsightsAnalyzer {
  constructor(
    private readonly scratchpadDir: string = SCRATCHPAD_DIR,
    private readonly learnedDir: string = join('.gideon', 'skills-learned')
  ) {}

  /**
   * Aggregate insights across all scratchpad files (optionally since an ISO date).
   */
  collect(sinceIso?: string): SessionInsights {
    const insights: SessionInsights = {
      sessions: 0,
      queries: 0,
      toolCalls: 0,
      toolBreakdown: {},
      errors: 0,
      approxTokens: 0,
      findings: [],
      learnedSkills: this.countLearnedSkills(),
    };

    if (!existsSync(this.scratchpadDir)) return insights;

    const since = sinceIso ? Date.parse(sinceIso) : 0;
    const files = readdirSync(this.scratchpadDir).filter((f) => f.endsWith('.jsonl'));

    for (const file of files) {
      const path = join(this.scratchpadDir, file);
      if (since) {
        try {
          if (statSync(path).mtimeMs < since) continue;
        } catch {
          /* ignore */
        }
      }

      let entries: ScratchpadEntry[];
      try {
        entries = readFileSync(path, 'utf-8')
          .split('\n')
          .filter((l) => l.trim())
          .map((l) => JSON.parse(l) as ScratchpadEntry);
      } catch {
        continue;
      }
      if (entries.length === 0) continue;

      insights.sessions++;

      for (const e of entries) {
        if (e.timestamp) {
          if (!insights.firstAt || e.timestamp < insights.firstAt) insights.firstAt = e.timestamp;
          if (!insights.lastAt || e.timestamp > insights.lastAt) insights.lastAt = e.timestamp;
        }

        if (e.type === 'init' && e.content) {
          insights.queries++;
        } else if (e.type === 'tool_result' && e.toolName) {
          insights.toolCalls++;
          insights.toolBreakdown[e.toolName] = (insights.toolBreakdown[e.toolName] ?? 0) + 1;
          const resultStr = typeof e.result === 'string' ? e.result : JSON.stringify(e.result ?? '');
          if (resultStr.startsWith('Error:') || (e.llmSummary ?? '').includes('[FAILED]')) {
            insights.errors++;
          }
          insights.approxTokens += estimateTokens(resultStr);
          if (e.llmSummary && !e.llmSummary.includes('[FAILED]')) {
            insights.findings.push(e.llmSummary.trim());
          }
        }
      }
    }

    // Keep the most informative, de-duplicated findings.
    insights.findings = Array.from(new Set(insights.findings)).slice(0, 25);
    return insights;
  }

  /**
   * Optional fast-model after-action prose. Findings are redacted first.
   */
  async narrate(insights: SessionInsights, model: string, modelProvider: string): Promise<string> {
    const findings = redactSecrets(insights.findings.slice(0, 15).join('\n'));
    const prompt = `Write a brief after-action summary (4-6 sentences, plain text) of this security session.
Sessions: ${insights.sessions}, queries: ${insights.queries}, tool calls: ${insights.toolCalls}, errors: ${insights.errors}.
Key findings:
${findings}`;

    try {
      const out = await callLlm(prompt, {
        model: getFastModel(modelProvider, model),
        systemPrompt: 'You are a security analyst writing a concise after-action report. No markdown.',
      });
      return String(out).trim();
    } catch {
      return '';
    }
  }

  private countLearnedSkills(): number {
    try {
      if (!existsSync(this.learnedDir)) return 0;
      return readdirSync(this.learnedDir).filter((f) => f.endsWith('.md')).length;
    } catch {
      return 0;
    }
  }
}

/**
 * Render insights as a plain-text Unicode-table report (Gideon house style).
 */
export function formatInsightsReport(insights: SessionInsights): string {
  const cfg = getInsightsConfig();
  const lines: string[] = [];

  lines.push('╔══════════════════════════════════════════════════════════════╗');
  lines.push('║  Gideon Engagement Insights (After-Action)                     ║');
  lines.push('╚══════════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push(`Sessions analyzed : ${insights.sessions}`);
  lines.push(`Queries           : ${insights.queries}`);
  lines.push(`Tool calls        : ${insights.toolCalls}`);
  lines.push(`Errors            : ${insights.errors}`);
  lines.push(`Approx tokens      : ${insights.approxTokens.toLocaleString()}`);
  lines.push(`Learned playbooks  : ${insights.learnedSkills}`);
  if (insights.firstAt) lines.push(`First activity     : ${insights.firstAt}`);
  if (insights.lastAt) lines.push(`Last activity      : ${insights.lastAt}`);
  lines.push('');

  const tools = Object.entries(insights.toolBreakdown).sort((a, b) => b[1] - a[1]);
  if (tools.length > 0) {
    lines.push('Tool usage');
    lines.push('──────────────────────────────────────');
    const max = Math.max(...tools.map(([, n]) => n));
    for (const [name, n] of tools) {
      const bar = '█'.repeat(Math.max(1, Math.round((n / max) * 20)));
      lines.push(`${name.padEnd(20)} ${String(n).padStart(4)}  ${bar}`);
    }
    lines.push('');
  }

  if (insights.findings.length > 0) {
    lines.push('Key findings');
    lines.push('──────────────────────────────────────');
    for (const f of insights.findings.slice(0, 12)) {
      lines.push(`• ${cfg.redact_findings ? redactSecrets(f) : f}`);
    }
  }

  return lines.join('\n');
}
