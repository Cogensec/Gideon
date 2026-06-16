import { MemoryStore } from './memory-store.js';
import { MemoryManager } from './memory-manager.js';
import { getRedTeamManager } from '../agent/redteam-mode.js';
import { buildFactId, MemoryCategory, MemoryFact, MemoryScope } from './types.js';

// ============================================================================
// /remember — explicit, operator-provided durable memory.
//
// This is the deterministic, lowest-poisoning-surface path into memory: the
// operator states a fact directly. Still redacted + integrity-scanned by the
// store. Facts captured this way are tagged source:'user'.
// ============================================================================

/**
 * Naive category inference from the phrasing of an operator note. Defaults to
 * operator_preference. Kept simple and deterministic (no LLM).
 */
function inferCategory(text: string): MemoryCategory {
  const t = text.toLowerCase();
  if (/\b(owns?|asset|domain|cidr|subnet|ip range|in[- ]scope)\b/.test(t)) return 'org_asset';
  if (/\b(safe|allowlist|whitelist|benign|known[- ]good|ignore)\b/.test(t)) return 'known_safe_indicator';
  if (/\b(prefer|format|verbosity|tone|report|style)\b/.test(t)) return 'operator_preference';
  if (/\b(triage|dismiss|accepted|false positive|won't fix|wontfix)\b/.test(t)) return 'triage_decision';
  return 'operator_preference';
}

export interface RememberResult {
  ok: boolean;
  message: string;
}

/**
 * Persist an operator-provided fact. Used by the CLI `/remember` command.
 */
export async function rememberFact(
  text: string,
  opts: { model?: string; modelProvider?: string; baseDir?: string } = {}
): Promise<RememberResult> {
  const trimmed = text.trim();
  if (!trimmed) {
    return { ok: false, message: 'Usage: /remember <fact about you or your environment>' };
  }

  const redTeam = getRedTeamManager();
  const engagement = redTeam.getActiveEngagement();
  // Operator notes default to 'shared' so they help in every mode, unless an
  // engagement is active (then the note is engagement-scoped).
  const scope: MemoryScope = engagement ? 'redteam' : 'shared';
  const category = inferCategory(trimmed);

  const fact: MemoryFact = {
    id: buildFactId(category, trimmed),
    category: engagement ? 'engagement_context' : category,
    scope,
    text: trimmed,
    confidence: 1.0, // operator-stated
    source: 'user',
    createdAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    engagementId: engagement?.id,
  };

  const store = new MemoryStore(opts.baseDir);
  const mgr = new MemoryManager(store, opts.model ?? 'gpt-5.2', opts.modelProvider ?? 'openai');
  const added = await mgr.sync([fact]);

  if (added > 0) {
    return { ok: true, message: `Remembered (${fact.category}, ${scope}): ${trimmed}` };
  }
  // sync returns 0 for duplicate or rejected — re-run addFact to get the reason.
  const res = await store.addFact(fact);
  return { ok: false, message: res.reason === 'duplicate' ? 'Already remembered.' : `Not stored: ${res.reason}` };
}
