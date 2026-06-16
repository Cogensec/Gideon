import { CommandContext, CommandResult } from './types.js';
import { InsightsAnalyzer, formatInsightsReport } from '../insights/insights.js';
import { getInsightsConfig } from '../utils/config-loader.js';

// ============================================================================
// /insights — engagement after-action analytics from the scratchpad logs.
//
// Usage:
//   /insights              full report
//   /insights --since 7d   only sessions in the last 7 days (d/h supported)
//   /insights --narrate    append a fast-model after-action prose summary
// ============================================================================

function parseSince(arg?: string): string | undefined {
  if (!arg) return undefined;
  const m = arg.match(/^(\d+)([dh])$/i);
  if (!m) return undefined;
  const n = parseInt(m[1], 10);
  const ms = m[2].toLowerCase() === 'd' ? n * 86400000 : n * 3600000;
  return new Date(Date.now() - ms).toISOString();
}

export async function insightsCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  if (!getInsightsConfig().enabled) {
    return { success: false, output: '', error: 'Insights are disabled in gideon.config.yaml.' };
  }

  const sinceIdx = args.indexOf('--since');
  const sinceIso = sinceIdx >= 0 ? parseSince(args[sinceIdx + 1]) : undefined;
  const narrate = args.includes('--narrate');

  try {
    const analyzer = new InsightsAnalyzer();
    const insights = analyzer.collect(sinceIso);

    if (insights.sessions === 0) {
      return { success: true, output: 'No engagement activity recorded yet.' };
    }

    let output = formatInsightsReport(insights);

    if (narrate) {
      const prose = await analyzer.narrate(insights, context.model, context.modelProvider);
      if (prose) output += `\n\nAfter-action summary\n──────────────────────────────────────\n${prose}`;
    }

    return { success: true, output, artifacts: { json: insights } };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to generate insights: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}
