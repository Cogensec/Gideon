import { callLlm, getFastModel } from '../model/llm.js';
import { redactSecrets } from '../memory/redaction.js';
import { getCompressionConfig } from '../utils/config-loader.js';

// ============================================================================
// ContextCompressor — keep long multi-step / multi-hour engagements inside the
// model context window.
//
// Operates over Gideon's existing compaction unit: the array of per-tool LLM
// summaries that feed buildIterationPrompt. Protects a head (earliest items)
// and a token-budgeted tail, summarizing only the middle. Anti-thrashing skips
// compression when recent passes barely helped.
// ============================================================================

/** Cheap heuristic — no tiktoken dependency in the project. */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export interface CompressionState {
  /** Savings ratios (0..1) of the most recent passes, newest last. */
  lastSavings: number[];
}

export function newCompressionState(): CompressionState {
  return { lastSavings: [] };
}

export interface CompressorOptions {
  thresholdTokens: number;
  tailTokens: number;
  headItems: number;
  minSavingsRatio: number;
}

const COMPRESSION_SYSTEM_PROMPT =
  'You compress intermediate research notes. Preserve concrete findings, identifiers (CVE ids, ' +
  'IPs, hostnames, hashes), and decisions. Be terse. Do NOT answer the user; only summarize.';

export class ContextCompressor {
  private readonly opts: CompressorOptions;

  constructor(
    private readonly model: string,
    private readonly modelProvider: string,
    opts?: Partial<CompressorOptions>
  ) {
    const cfg = getCompressionConfig();
    this.opts = {
      thresholdTokens: opts?.thresholdTokens ?? cfg.threshold_tokens,
      tailTokens: opts?.tailTokens ?? cfg.tail_tokens,
      headItems: opts?.headItems ?? cfg.head_items,
      minSavingsRatio: opts?.minSavingsRatio ?? cfg.min_savings_ratio,
    };
  }

  /**
   * True when the prompt exceeds the threshold AND the last two passes each
   * saved at least minSavingsRatio (anti-thrashing).
   */
  shouldCompress(promptTokens: number, state: CompressionState): boolean {
    if (promptTokens <= this.opts.thresholdTokens) return false;
    const recent = state.lastSavings.slice(-2);
    if (recent.length === 2 && recent.every((s) => s < this.opts.minSavingsRatio)) {
      return false;
    }
    return true;
  }

  /**
   * Compress the summaries array. Returns the (possibly) shorter array and the
   * fraction of tokens saved. Mutates `state.lastSavings`.
   */
  async compress(
    summaries: string[],
    state: CompressionState,
    signal?: AbortSignal
  ): Promise<{ summaries: string[]; savedRatio: number }> {
    const before = estimateTokens(summaries.join('\n'));
    const { headItems, tailTokens } = this.opts;

    if (summaries.length <= headItems + 1) {
      state.lastSavings.push(0);
      return { summaries, savedRatio: 0 };
    }

    const head = summaries.slice(0, headItems);

    // Build the tail by walking backwards until the token budget is exhausted.
    const tail: string[] = [];
    let tailTokenCount = 0;
    for (let i = summaries.length - 1; i >= headItems; i--) {
      const t = estimateTokens(summaries[i]);
      if (tailTokenCount + t > tailTokens && tail.length > 0) break;
      tail.unshift(summaries[i]);
      tailTokenCount += t;
    }

    const middleCount = summaries.length - head.length - tail.length;
    if (middleCount <= 0) {
      state.lastSavings.push(0);
      return { summaries, savedRatio: 0 };
    }

    const middle = summaries.slice(headItems, headItems + middleCount);
    const middleSummary = await this.summarizeMiddle(middle, signal);

    const compressed = [...head, middleSummary, ...tail];
    const after = estimateTokens(compressed.join('\n'));
    const savedRatio = before > 0 ? Math.max(0, 1 - after / before) : 0;

    state.lastSavings.push(savedRatio);
    // If compression didn't actually help, keep the original.
    if (savedRatio <= 0) return { summaries, savedRatio: 0 };
    return { summaries: compressed, savedRatio };
  }

  private async summarizeMiddle(middle: string[], signal?: AbortSignal): Promise<string> {
    const text = redactSecrets(middle.join('\n'));
    const prompt = `Summarize these intermediate research notes into a compact "Historical Findings" block.
Keep concrete identifiers and decisions; drop redundancy.

Notes:
${text}`;

    try {
      const summary = await callLlm(prompt, {
        model: getFastModel(this.modelProvider, this.model),
        systemPrompt: COMPRESSION_SYSTEM_PROMPT,
        signal,
      });
      return `[compressed history] ${String(summary).trim()}`;
    } catch {
      return this.staticFallback(middle);
    }
  }

  /** Deterministic fallback when the summarizer is unavailable. */
  private staticFallback(middle: string[]): string {
    const head = middle.slice(0, 3).map((s) => `- ${s}`).join('\n');
    return `[compressed history] ${middle.length} earlier steps omitted. First few:\n${redactSecrets(head)}`;
  }
}
