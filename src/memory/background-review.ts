import { existsSync, readFileSync } from 'fs';
import { callLlm, getFastModel } from '../model/llm.js';
import { localTopicCheck } from '../utils/nemo-guardrails.js';
import { getRedTeamManager } from '../agent/redteam-mode.js';
import { buildCombinedReviewPrompt, ReviewOutputSchema, ReviewOutput } from '../agent/review-prompts.js';
import { getLearningConfig } from '../utils/config-loader.js';
import { MemoryStore } from './memory-store.js';
import { MemoryManager } from './memory-manager.js';
import { LearnedSkillStore } from '../skills/learned/learned-skill-store.js';
import { buildFactId, MemoryFact, MemoryScope } from './types.js';

// ============================================================================
// runBackgroundReview — the post-turn learning loop.
//
// Runs once per turn on a fast model, over the turn transcript. Distils durable
// memory facts and reusable defensive playbooks, then persists them under full
// integrity/redaction/scope gating. Never blocks the user-facing turn.
// ============================================================================

export interface ReviewInput {
  scratchpadPath: string;
  finalAnswer: string;
  model: string;
  modelProvider: string;
  mode: MemoryScope; // 'defensive' | 'redteam'
  engagementId?: string;
  baseDir?: string;
  signal?: AbortSignal;
}

export interface ReviewSummary {
  memoryAdded: number;
  skillsCreated: number;
  skillsPatched: number;
  oneLiner: string;
}

interface ScratchpadEntry {
  type: 'init' | 'tool_result' | 'thinking';
  content?: string;
  toolName?: string;
  llmSummary?: string;
}

/** Build a compact transcript from the scratchpad + final answer. */
function buildTranscript(scratchpadPath: string, finalAnswer: string): string {
  const lines: string[] = [];
  if (existsSync(scratchpadPath)) {
    const entries = readFileSync(scratchpadPath, 'utf-8')
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as ScratchpadEntry);
    for (const e of entries) {
      if (e.type === 'init' && e.content) lines.push(`User asked: ${e.content}`);
      else if (e.type === 'thinking' && e.content) lines.push(`Agent thought: ${e.content}`);
      else if (e.type === 'tool_result' && e.llmSummary) lines.push(`Tool result: ${e.llmSummary}`);
    }
  }
  lines.push(`Final answer: ${finalAnswer}`);
  // Keep the transcript bounded for the fast model.
  return lines.join('\n').slice(0, 8000);
}

/**
 * Fire-and-forget the background learning loop, resolving the operating mode +
 * engagement from the current red-team manager. Used by non-interactive command
 * callers (brief/cve/ioc/voice) so memory and playbooks grow there too. Never
 * throws; learning is best-effort.
 */
export function fireBackgroundReview(opts: {
  scratchpadPath?: string;
  finalAnswer: string;
  model: string;
  modelProvider: string;
  signal?: AbortSignal;
}): void {
  if (!opts.scratchpadPath || !opts.finalAnswer) return;
  const manager = getRedTeamManager();
  const engagement = manager.getActiveEngagement();
  void runBackgroundReview({
    scratchpadPath: opts.scratchpadPath,
    finalAnswer: opts.finalAnswer,
    model: opts.model,
    modelProvider: opts.modelProvider,
    mode: manager.isRedTeamMode() ? 'redteam' : 'defensive',
    engagementId: engagement?.id,
    signal: opts.signal,
  }).catch(() => {
    /* best-effort */
  });
}

export async function runBackgroundReview(input: ReviewInput): Promise<ReviewSummary | null> {
  const cfg = getLearningConfig();
  if (!cfg.enabled || !cfg.review_after_turn) return null;

  const transcript = buildTranscript(input.scratchpadPath, input.finalAnswer);

  const store = new MemoryStore(input.baseDir);
  const memory = new MemoryManager(store, input.model, input.modelProvider);
  const skills = new LearnedSkillStore(input.baseDir);

  let review: ReviewOutput;
  try {
    review = (await callLlm(buildCombinedReviewPrompt(transcript, skills.getNotes().map((n) => n.title)), {
      model: getFastModel(input.modelProvider, input.model),
      systemPrompt: 'You are a precise reviewer that returns only structured JSON.',
      outputSchema: ReviewOutputSchema,
      signal: input.signal,
    })) as ReviewOutput;
  } catch {
    return null;
  }

  const isDefensive = input.mode === 'defensive';

  // --- Memory facts ---
  const facts: MemoryFact[] = [];
  for (const f of review.memoryFacts) {
    if (f.confidence < cfg.min_confidence) continue;
    // Defensive turns must not learn offensive content.
    if (isDefensive && !localTopicCheck(f.text)) continue;

    // Red-team turns keep all learned facts in the 'redteam' scope (never
    // shared/defensive); defensive turns write durable 'shared' facts.
    const scope: MemoryScope = input.mode === 'redteam' ? 'redteam' : 'shared';

    facts.push({
      id: buildFactId(f.category, f.text),
      category: f.category,
      scope,
      text: f.text,
      confidence: f.confidence,
      source: 'agent_review',
      createdAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      engagementId: input.mode === 'redteam' ? input.engagementId : undefined,
    });
  }

  // memory.sync enforces the configured max_facts cap after writing.
  const memoryAdded = await memory.sync(facts, review.profilePatch);

  // --- Learned skills ---
  let skillsCreated = 0;
  let skillsPatched = 0;
  const skillMode: MemoryScope = input.mode === 'redteam' ? 'redteam' : 'shared';
  for (const note of review.skillNotes) {
    if ((note.confidence ?? 0.6) < cfg.min_confidence) continue;
    // Defensive mode: drop offensive playbooks.
    if (isDefensive) {
      const blob = [note.title, note.trigger, ...note.steps].join(' ');
      if (!localTopicCheck(blob)) continue;
    }
    const res = await skills.upsert(note, skillMode, cfg.max_learned_skills);
    if (res.action === 'created') skillsCreated++;
    else if (res.action === 'patched') skillsPatched++;
  }

  if (memoryAdded === 0 && skillsCreated === 0 && skillsPatched === 0) {
    return { memoryAdded, skillsCreated, skillsPatched, oneLiner: '' };
  }

  const parts: string[] = [];
  if (memoryAdded > 0) parts.push(`Memory updated (+${memoryAdded})`);
  if (skillsCreated > 0) parts.push(`Playbook${skillsCreated > 1 ? 's' : ''} learned (+${skillsCreated})`);
  if (skillsPatched > 0) parts.push(`Playbook${skillsPatched > 1 ? 's' : ''} patched (${skillsPatched})`);

  return { memoryAdded, skillsCreated, skillsPatched, oneLiner: parts.join(' · ') };
}
