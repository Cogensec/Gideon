import { test, expect, describe } from 'bun:test';
import {
  buildMemoryReviewPrompt,
  buildSkillReviewPrompt,
  buildCombinedReviewPrompt,
  ReviewOutputSchema,
} from './review-prompts.js';

describe('review prompts', () => {
  const transcript = 'User asked: triage CVE-2026-1234\nFinal answer: severity high';

  test('memory prompt encodes the non-capture contract (no transient values)', () => {
    const p = buildMemoryReviewPrompt(transcript);
    expect(p).toContain('Do NOT record');
    expect(p).toContain('transient');
    expect(p).toContain("phrased as an instruction");
    expect(p).toContain(transcript);
  });

  test('skill prompt forbids offensive playbooks and lists loaded skills', () => {
    const p = buildSkillReviewPrompt(transcript, ['subdomain-triage']);
    expect(p).toContain('DEFENSIVE');
    expect(p).toContain('never record offensive');
    expect(p).toContain('subdomain-triage');
  });

  test('combined prompt covers both memory and skills', () => {
    const p = buildCombinedReviewPrompt(transcript, []);
    expect(p).toContain('MEMORY');
    expect(p).toContain('SKILLS');
    expect(p).toContain('(none)');
  });

  test('output schema accepts a well-formed review and rejects a bad one', () => {
    const ok = ReviewOutputSchema.safeParse({
      memoryFacts: [{ category: 'operator_preference', text: 'prefers tables', confidence: 0.9 }],
      skillNotes: [],
    });
    expect(ok.success).toBe(true);

    const bad = ReviewOutputSchema.safeParse({
      memoryFacts: [{ category: 'not_a_category', text: 'x', confidence: 2 }],
      skillNotes: [],
    });
    expect(bad.success).toBe(false);
  });
});
