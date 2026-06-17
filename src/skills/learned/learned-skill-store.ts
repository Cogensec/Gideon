import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import { MemoryIntegrityMonitor } from '../../openclaw/memory-integrity.js';
import { OpenClawSidecarConfigSchema } from '../../openclaw/types.js';
import { redactSecrets } from '../../memory/redaction.js';
import type { MemoryScope } from '../../memory/types.js';

// ============================================================================
// LearnedSkillStore — durable, auto-grown defensive playbooks.
//
// Gideon's built-in skills are hand-coded TS. Learned skills are instead stored
// as markdown with a JSON frontmatter line under .gideon/skills-learned/ and
// injected into the system prompt as a compact "Learned Playbooks" section.
// This mirrors a class-level skill-file approach without generating code.
// ============================================================================

const SKILLS_DIR = join('.gideon', 'skills-learned');

export interface SkillNote {
  id: string;
  title: string;
  /** When this playbook applies. */
  trigger: string;
  /** Ordered steps. */
  steps: string[];
  /** Optional correction captured from operator feedback. */
  correction?: string;
  mode: MemoryScope;
  confidence: number;
  usageCount: number;
  createdAt: string;
  updatedAt: string;
}

export type UpsertAction = 'created' | 'patched' | 'skipped';

interface SkillFrontmatter {
  id: string;
  title: string;
  mode: MemoryScope;
  confidence: number;
  usageCount: number;
  createdAt: string;
  updatedAt: string;
}

function normalizeTitle(title: string): string {
  return title.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function buildNoteId(title: string): string {
  return createHash('md5').update(normalizeTitle(title)).digest('hex').slice(0, 12);
}

export class LearnedSkillStore {
  private readonly dir: string;
  private readonly integrity: MemoryIntegrityMonitor;
  private notes: Map<string, SkillNote> = new Map();
  private loaded = false;

  constructor(baseDir: string = process.cwd()) {
    this.dir = join(baseDir, SKILLS_DIR);
    this.integrity = new MemoryIntegrityMonitor(
      OpenClawSidecarConfigSchema.parse({ gateway: { openclawHome: '~/.openclaw' } })
    );
  }

  async load(): Promise<void> {
    this.loadSync();
  }

  /** Synchronous load — all underlying fs ops are synchronous anyway. */
  private loadSync(): void {
    if (this.loaded) return;
    if (existsSync(this.dir)) {
      for (const file of readdirSync(this.dir)) {
        if (!file.endsWith('.md')) continue;
        try {
          const note = this.parseFile(readFileSync(join(this.dir, file), 'utf-8'));
          if (note) this.notes.set(note.id, note);
        } catch {
          /* skip malformed */
        }
      }
    }
    this.loaded = true;
  }

  /**
   * Create or patch a learned playbook. Integrity-scans and redacts content;
   * rejects notes that look like poisoning. Returns the action taken.
   */
  async upsert(
    input: { title: string; trigger: string; steps: string[]; correction?: string; confidence?: number },
    mode: MemoryScope,
    maxNotes = 50
  ): Promise<{ action: UpsertAction; reason?: string }> {
    await this.load();

    const title = redactSecrets(input.title).trim();
    const trigger = redactSecrets(input.trigger).trim();
    const steps = input.steps.map((s) => redactSecrets(s).trim()).filter(Boolean);
    const correction = input.correction ? redactSecrets(input.correction).trim() : undefined;

    if (!title || steps.length === 0) {
      return { action: 'skipped', reason: 'missing title or steps' };
    }

    // Poisoning scan over the full note text.
    const blob = [title, trigger, ...steps, correction ?? ''].join('\n');
    const suspicious = this.integrity.scanMemoryEntry(blob, 'learned-skill');
    if (suspicious && (suspicious.severity === 'critical' || suspicious.severity === 'high')) {
      return { action: 'skipped', reason: `integrity: ${suspicious.reason}` };
    }

    const id = buildNoteId(title);
    const now = new Date().toISOString();
    const existing = this.notes.get(id);

    if (existing) {
      // Patch: merge steps, refresh correction, bump usage/confidence.
      const mergedSteps = Array.from(new Set([...existing.steps, ...steps]));
      const patched: SkillNote = {
        ...existing,
        trigger: trigger || existing.trigger,
        steps: mergedSteps,
        correction: correction ?? existing.correction,
        confidence: Math.max(existing.confidence, input.confidence ?? existing.confidence),
        usageCount: existing.usageCount + 1,
        updatedAt: now,
      };
      this.notes.set(id, patched);
      this.writeFile(patched);
      return { action: 'patched' };
    }

    const note: SkillNote = {
      id,
      title,
      trigger,
      steps,
      correction,
      mode,
      confidence: input.confidence ?? 0.6,
      usageCount: 1,
      createdAt: now,
      updatedAt: now,
    };
    this.notes.set(id, note);
    this.writeFile(note);
    await this.prune(maxNotes);
    return { action: 'created' };
  }

  /**
   * Compact "Learned Playbooks" block for injection into the system prompt.
   * Includes notes for the given mode plus 'shared' notes.
   */
  format(mode: MemoryScope, maxNotes = 10): string {
    this.loadSync();
    const eligible = Array.from(this.notes.values())
      .filter((n) => n.mode === mode || n.mode === 'shared')
      .sort((a, b) => b.confidence - a.confidence || b.usageCount - a.usageCount)
      .slice(0, maxNotes);

    if (eligible.length === 0) return '';

    const lines = ['## Learned Playbooks', '(Distilled from prior engagements. Apply when the trigger matches.)', ''];
    for (const n of eligible) {
      lines.push(`### ${n.title}`);
      lines.push(`Trigger: ${n.trigger}`);
      n.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      if (n.correction) lines.push(`Note: ${n.correction}`);
      lines.push('');
    }
    return lines.join('\n').trimEnd();
  }

  getNotes(): SkillNote[] {
    return Array.from(this.notes.values());
  }

  private async prune(maxNotes: number): Promise<void> {
    if (this.notes.size <= maxNotes) return;
    const sorted = Array.from(this.notes.values()).sort(
      (a, b) => b.confidence - a.confidence || b.usageCount - a.usageCount
    );
    for (const note of sorted.slice(maxNotes)) {
      this.notes.delete(note.id);
      const path = join(this.dir, `${note.id}.md`);
      try {
        if (existsSync(path)) unlinkSync(path);
      } catch {
        /* ignore */
      }
    }
  }

  private writeFile(note: SkillNote): void {
    if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true });
    const frontmatter: SkillFrontmatter = {
      id: note.id,
      title: note.title,
      mode: note.mode,
      confidence: note.confidence,
      usageCount: note.usageCount,
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
    };
    const body = [
      `<!--gideon-skill ${JSON.stringify(frontmatter)} -->`,
      `# ${note.title}`,
      '',
      `**Trigger:** ${note.trigger}`,
      '',
      '## Steps',
      ...note.steps.map((s, i) => `${i + 1}. ${s}`),
      ...(note.correction ? ['', `**Correction:** ${note.correction}`] : []),
      '',
    ].join('\n');
    writeFileSync(join(this.dir, `${note.id}.md`), body);
  }

  private parseFile(content: string): SkillNote | null {
    const match = content.match(/<!--gideon-skill (.+?) -->/s);
    if (!match) return null;
    const fm = JSON.parse(match[1]) as SkillFrontmatter;

    const triggerMatch = content.match(/\*\*Trigger:\*\* (.+)/);
    const correctionMatch = content.match(/\*\*Correction:\*\* (.+)/);
    const steps = Array.from(content.matchAll(/^\d+\.\s+(.+)$/gm)).map((m) => m[1].trim());

    return {
      id: fm.id,
      title: fm.title,
      trigger: triggerMatch ? triggerMatch[1].trim() : '',
      steps,
      correction: correctionMatch ? correctionMatch[1].trim() : undefined,
      mode: fm.mode,
      confidence: fm.confidence,
      usageCount: fm.usageCount,
      createdAt: fm.createdAt,
      updatedAt: fm.updatedAt,
    };
  }
}
