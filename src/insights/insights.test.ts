import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { InsightsAnalyzer, formatInsightsReport } from './insights.js';

function writeSession(dir: string, name: string, entries: object[]): void {
  writeFileSync(join(dir, name), entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
}

describe('InsightsAnalyzer', () => {
  let root: string;
  let scratchpadDir: string;
  let learnedDir: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'gideon-insights-'));
    scratchpadDir = join(root, 'scratchpad');
    learnedDir = join(root, 'skills-learned');
    mkdirSync(scratchpadDir, { recursive: true });
    mkdirSync(learnedDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  test('aggregates queries, tool breakdown, errors and tokens', () => {
    writeSession(scratchpadDir, 'a.jsonl', [
      { type: 'init', content: 'triage CVE-2026-1', timestamp: '2026-06-16T10:00:00Z' },
      { type: 'tool_result', toolName: 'security_search', result: '{"ok":true}', llmSummary: 'found CVE details', timestamp: '2026-06-16T10:00:01Z' },
      { type: 'tool_result', toolName: 'security_search', result: 'Error: rate limited', llmSummary: '[FAILED]: rate limited', timestamp: '2026-06-16T10:00:02Z' },
    ]);
    writeSession(scratchpadDir, 'b.jsonl', [
      { type: 'init', content: 'check 8.8.8.8', timestamp: '2026-06-16T11:00:00Z' },
      { type: 'tool_result', toolName: 'tavily_search', result: '{"reputation":"clean"}', llmSummary: '8.8.8.8 is benign', timestamp: '2026-06-16T11:00:01Z' },
    ]);
    writeFileSync(join(learnedDir, 'abc123.md'), '<!--gideon-skill {} -->\n# x');

    const analyzer = new InsightsAnalyzer(scratchpadDir, learnedDir);
    const insights = analyzer.collect();

    expect(insights.sessions).toBe(2);
    expect(insights.queries).toBe(2);
    expect(insights.toolCalls).toBe(3);
    expect(insights.toolBreakdown.security_search).toBe(2);
    expect(insights.toolBreakdown.tavily_search).toBe(1);
    expect(insights.errors).toBe(1);
    expect(insights.approxTokens).toBeGreaterThan(0);
    expect(insights.learnedSkills).toBe(1);
    expect(insights.findings).toContain('8.8.8.8 is benign');
    // [FAILED] summaries are excluded from findings.
    expect(insights.findings.some((f) => f.includes('[FAILED]'))).toBe(false);
  });

  test('--since filtering returns empty for an empty dir', () => {
    const analyzer = new InsightsAnalyzer(scratchpadDir, learnedDir);
    expect(analyzer.collect().sessions).toBe(0);
  });

  test('formatInsightsReport renders a plain-text report', () => {
    writeSession(scratchpadDir, 'a.jsonl', [
      { type: 'init', content: 'q', timestamp: '2026-06-16T10:00:00Z' },
      { type: 'tool_result', toolName: 'security_search', result: '{}', llmSummary: 'did a thing', timestamp: '2026-06-16T10:00:01Z' },
    ]);
    const insights = new InsightsAnalyzer(scratchpadDir, learnedDir).collect();
    const report = formatInsightsReport(insights);
    expect(report).toContain('Engagement Insights');
    expect(report).toContain('security_search');
    expect(report).not.toContain('**'); // no markdown
  });
});
