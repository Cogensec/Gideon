import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { MemoryStore } from './memory-store.js';
import { MemoryManager } from './memory-manager.js';
import { buildFactId, MemoryCategory, MemoryFact, MemoryScope } from './types.js';

function fact(category: MemoryCategory, text: string, scope: MemoryScope, engagementId?: string): MemoryFact {
  return {
    id: buildFactId(category, text),
    category,
    scope,
    text,
    confidence: 0.9,
    source: 'agent_review',
    createdAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    engagementId,
  };
}

describe('MemoryManager.prefetch', () => {
  let dir: string;
  let store: MemoryStore;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'gideon-mm-'));
    store = new MemoryStore(dir);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('returns an empty string when no memory exists', async () => {
    const mgr = new MemoryManager(store, 'gpt-5.2', 'openai');
    expect(await mgr.prefetch('any query', ['defensive', 'shared'])).toBe('');
  });

  test('formats a fenced lower-trust block (no LLM call under threshold)', async () => {
    await store.addFact(fact('org_asset', 'Owns 10.0.0.0/8', 'shared'));
    await store.upsertProfile({ reportFormat: 'Unicode tables, no markdown' });

    const mgr = new MemoryManager(store, 'gpt-5.2', 'openai');
    const block = await mgr.prefetch('what is in scope?', ['defensive', 'shared']);

    expect(block).toContain('<memory-context>');
    expect(block).toContain('NOT new user input');
    expect(block).toContain('Owns 10.0.0.0/8');
    expect(block).toContain('Unicode tables, no markdown');
    expect(block).toContain('</memory-context>');
  });

  test('defensive recall never includes red-team facts', async () => {
    await store.addFact(fact('org_asset', 'shared asset note', 'shared'));
    await store.addFact(fact('engagement_context', 'compromised host h1', 'redteam', 'eng-1'));

    const mgr = new MemoryManager(store, 'gpt-5.2', 'openai');
    const block = await mgr.prefetch('status?', ['defensive', 'shared']);

    expect(block).toContain('shared asset note');
    expect(block).not.toContain('compromised host h1');
  });
});
