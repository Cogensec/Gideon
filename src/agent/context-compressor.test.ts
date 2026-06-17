import { test, expect, describe } from 'bun:test';
import { ContextCompressor, estimateTokens, newCompressionState } from './context-compressor.js';

describe('ContextCompressor.shouldCompress', () => {
  const c = new ContextCompressor('gpt-5.2', 'openai', {
    thresholdTokens: 100,
    tailTokens: 40,
    headItems: 2,
    minSavingsRatio: 0.1,
  });

  test('false below threshold', () => {
    expect(c.shouldCompress(50, newCompressionState())).toBe(false);
  });

  test('true above threshold with no history', () => {
    expect(c.shouldCompress(200, newCompressionState())).toBe(true);
  });

  test('anti-thrashing: skips after two low-savings passes', () => {
    const state = { lastSavings: [0.02, 0.03] };
    expect(c.shouldCompress(200, state)).toBe(false);
  });

  test('resumes when a recent pass saved enough', () => {
    const state = { lastSavings: [0.02, 0.5] };
    expect(c.shouldCompress(200, state)).toBe(true);
  });
});

describe('ContextCompressor.compress', () => {
  test('preserves head and tail, replaces the middle', async () => {
    // Force the static fallback by using a model that will fail the LLM call;
    // compress catches the error and falls back deterministically.
    const c = new ContextCompressor('definitely-not-a-real-model:x', 'nope', {
      thresholdTokens: 1,
      tailTokens: 30,
      headItems: 2,
      minSavingsRatio: 0.1,
    });

    const mids = Array.from({ length: 10 }, (_, i) => `MID-${i} lots of intermediate detail `.repeat(5));
    const summaries = ['HEAD-0 first finding', 'HEAD-1 second finding', ...mids, 'TAIL-5 recent finding'];

    const state = newCompressionState();
    const { summaries: out, savedRatio } = await c.compress(summaries, state, undefined);

    // Head preserved verbatim.
    expect(out[0]).toBe('HEAD-0 first finding');
    expect(out[1]).toBe('HEAD-1 second finding');
    // Tail preserved verbatim.
    expect(out[out.length - 1]).toBe('TAIL-5 recent finding');
    // Middle replaced by a single compressed entry.
    expect(out.some((s) => s.startsWith('[compressed history]'))).toBe(true);
    expect(out.length).toBeLessThan(summaries.length);
    expect(savedRatio).toBeGreaterThan(0);
  });

  test('no-op when too few items to compress', async () => {
    const c = new ContextCompressor('x', 'y', { thresholdTokens: 1, tailTokens: 10, headItems: 3, minSavingsRatio: 0.1 });
    const summaries = ['a', 'b'];
    const { summaries: out, savedRatio } = await c.compress(summaries, newCompressionState());
    expect(out).toEqual(summaries);
    expect(savedRatio).toBe(0);
  });
});

describe('estimateTokens', () => {
  test('roughly chars/4', () => {
    expect(estimateTokens('abcd')).toBe(1);
    expect(estimateTokens('a'.repeat(40))).toBe(10);
  });
});
