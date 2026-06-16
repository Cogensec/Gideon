import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'fs';
import { join } from 'path';
import { MemoryIntegrityMonitor } from '../openclaw/memory-integrity.js';
import { OpenClawSidecarConfigSchema } from '../openclaw/types.js';
import { redactSecrets } from './redaction.js';
import {
  MemoryFact,
  MemoryFactSchema,
  MemoryScope,
  OperatorProfile,
  AddFactResult,
  emptyProfile,
} from './types.js';

// ============================================================================
// MemoryStore — durable operator/org profile + scope-tagged facts
//
// Storage layout under .gideon/memory/:
//   profile.json  — single OperatorProfile object
//   facts.jsonl   — append-only durable facts (mirrors Scratchpad's resilient
//                   JSONL pattern)
//
// Every write runs redaction first, then the OpenClaw MemoryIntegrityMonitor
// poisoning scan. critical/high hits are rejected outright.
// ============================================================================

const MEMORY_DIR = join('.gideon', 'memory');
const PROFILE_FILE = 'profile.json';
const FACTS_FILE = 'facts.jsonl';

export class MemoryStore {
  private readonly dir: string;
  private readonly profilePath: string;
  private readonly factsPath: string;
  private readonly integrity: MemoryIntegrityMonitor;

  private profile: OperatorProfile = emptyProfile();
  private facts: MemoryFact[] = [];
  private loaded = false;

  constructor(baseDir: string = process.cwd()) {
    this.dir = join(baseDir, MEMORY_DIR);
    this.profilePath = join(this.dir, PROFILE_FILE);
    this.factsPath = join(this.dir, FACTS_FILE);
    // Construct the poisoning monitor — scanMemoryEntry only depends on the
    // module-level indicator patterns, not the config. We supply an explicit
    // gateway input so nested defaults (openclawHome) are populated.
    this.integrity = new MemoryIntegrityMonitor(
      OpenClawSidecarConfigSchema.parse({ gateway: { openclawHome: '~/.openclaw' } })
    );
  }

  /**
   * Load profile + facts from disk. Safe to call repeatedly.
   */
  async load(): Promise<void> {
    if (this.loaded) return;

    if (existsSync(this.profilePath)) {
      try {
        this.profile = JSON.parse(readFileSync(this.profilePath, 'utf-8')) as OperatorProfile;
      } catch {
        this.profile = emptyProfile();
      }
    }

    if (existsSync(this.factsPath)) {
      try {
        this.facts = readFileSync(this.factsPath, 'utf-8')
          .split('\n')
          .filter((l) => l.trim())
          .map((l) => JSON.parse(l) as MemoryFact)
          .filter((f) => MemoryFactSchema.safeParse(f).success);
      } catch {
        this.facts = [];
      }
    }

    this.loaded = true;
  }

  getProfile(): OperatorProfile {
    return { ...this.profile };
  }

  /**
   * Merge a patch into the operator profile and persist.
   */
  async upsertProfile(patch: Partial<OperatorProfile>): Promise<void> {
    await this.load();

    const redact = (s?: string) => (s === undefined ? undefined : redactSecrets(s));
    const mergeList = (existing: string[], incoming?: string[]): string[] => {
      if (!incoming || incoming.length === 0) return existing;
      const set = new Set(existing);
      for (const item of incoming) {
        const clean = redactSecrets(item).trim();
        if (clean) set.add(clean);
      }
      return Array.from(set);
    };

    this.profile = {
      reportFormat: redact(patch.reportFormat) ?? this.profile.reportFormat,
      verbosity: redact(patch.verbosity) ?? this.profile.verbosity,
      preferences: mergeList(this.profile.preferences, patch.preferences),
      orgContext: mergeList(this.profile.orgContext, patch.orgContext),
      updatedAt: new Date().toISOString(),
    };

    this.ensureDir();
    writeFileSync(this.profilePath, JSON.stringify(this.profile, null, 2));
  }

  /**
   * Add a fact. Redacts, runs the poisoning scan, dedups by id.
   * Returns { added:false, reason } on rejection.
   */
  async addFact(fact: MemoryFact): Promise<AddFactResult> {
    await this.load();

    // 1. Redact secrets before anything is stored.
    const cleanText = redactSecrets(fact.text);

    // 2. Poisoning scan — reject instructions disguised as facts.
    const suspicious = this.integrity.scanMemoryEntry(cleanText, `memory:${fact.source}`);
    if (suspicious && (suspicious.severity === 'critical' || suspicious.severity === 'high')) {
      return { added: false, reason: `rejected by integrity monitor: ${suspicious.reason}` };
    }

    const stored: MemoryFact = {
      ...fact,
      text: cleanText,
      // A medium-severity hit downgrades confidence rather than blocking.
      confidence: suspicious ? Math.min(fact.confidence, 0.4) : fact.confidence,
      lastSeenAt: new Date().toISOString(),
    };

    // 3. Dedup by id — refresh lastSeenAt on an existing fact instead.
    const existing = this.facts.find((f) => f.id === stored.id);
    if (existing) {
      existing.lastSeenAt = stored.lastSeenAt;
      existing.confidence = Math.max(existing.confidence, stored.confidence);
      this.rewriteFacts();
      return { added: false, reason: 'duplicate', fact: existing };
    }

    const parsed = MemoryFactSchema.safeParse(stored);
    if (!parsed.success) {
      return { added: false, reason: `invalid fact: ${parsed.error.message}` };
    }

    this.facts.push(stored);
    this.ensureDir();
    appendFileSync(this.factsPath, JSON.stringify(stored) + '\n');
    return { added: true, fact: stored };
  }

  /**
   * Return facts visible in the given scope(s).
   */
  getFacts(scopes: MemoryScope[]): MemoryFact[] {
    const allow = new Set(scopes);
    return this.facts.filter((f) => allow.has(f.scope));
  }

  /**
   * Drop lowest-confidence / oldest facts beyond maxFacts to prevent bloat.
   */
  async prune(maxFacts = 500): Promise<void> {
    await this.load();
    if (this.facts.length <= maxFacts) return;

    this.facts.sort((a, b) => {
      if (b.confidence !== a.confidence) return b.confidence - a.confidence;
      return b.lastSeenAt.localeCompare(a.lastSeenAt);
    });
    this.facts = this.facts.slice(0, maxFacts);
    this.rewriteFacts();
  }

  /**
   * Remove all facts for a given engagement (called when a red-team engagement
   * is deactivated so engagement context is not carried forward).
   */
  async pruneEngagement(engagementId: string): Promise<number> {
    await this.load();
    const before = this.facts.length;
    this.facts = this.facts.filter((f) => f.engagementId !== engagementId);
    if (this.facts.length !== before) this.rewriteFacts();
    return before - this.facts.length;
  }

  private ensureDir(): void {
    if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true });
  }

  private rewriteFacts(): void {
    this.ensureDir();
    writeFileSync(this.factsPath, this.facts.map((f) => JSON.stringify(f)).join('\n') + '\n');
  }
}
