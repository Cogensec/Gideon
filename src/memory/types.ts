import { z } from 'zod';

// ============================================================================
// Persistent Memory Types
//
// Gideon's cross-session memory. Inspired by the Hermes agent's memory_manager
// (who the operator is) layered on top of Gideon's defensive/red-team modes.
//
// Security note: every fact persisted here is LLM-distilled (source
// 'agent_review') or operator-provided (source 'user') and MUST pass through
// the OpenClaw MemoryIntegrityMonitor + secret redaction before being written.
// ============================================================================

/**
 * Operating-mode scope for a memory record. Determines which turns a record is
 * eligible to be recalled into. 'shared' facts are visible in every mode;
 * 'redteam'/'engagement_context' facts NEVER leak into a defensive turn.
 */
export type MemoryScope = 'defensive' | 'redteam' | 'shared';

export const MemoryScopeSchema = z.enum(['defensive', 'redteam', 'shared']);

/**
 * What kind of durable knowledge a fact captures.
 */
export type MemoryCategory =
  | 'operator_preference' // report format, verbosity, tone
  | 'org_asset' // owned domains/IPs/CIDRs, crown jewels
  | 'triage_decision' // prior accept/dismiss calls on findings
  | 'known_safe_indicator' // allowlisted IPs/domains/hashes
  | 'engagement_context'; // red-team-only, scoped to an engagement id

export const MemoryCategorySchema = z.enum([
  'operator_preference',
  'org_asset',
  'triage_decision',
  'known_safe_indicator',
  'engagement_context',
]);

/**
 * A single durable fact about the operator or their environment.
 */
export interface MemoryFact {
  /** Stable id = md5(category + normalized text).slice(0, 12) — used for dedup. */
  id: string;
  category: MemoryCategory;
  scope: MemoryScope;
  /** The durable fact, already redacted of secrets. */
  text: string;
  /** 0..1 — how confident we are this is a durable, correct fact. */
  confidence: number;
  /** Facts are never copied verbatim from tool output. */
  source: 'user' | 'agent_review';
  createdAt: string;
  lastSeenAt: string;
  /** Set only when scope === 'redteam' / 'engagement_context'. */
  engagementId?: string;
}

export const MemoryFactSchema = z.object({
  id: z.string().min(1),
  category: MemoryCategorySchema,
  scope: MemoryScopeSchema,
  text: z.string().min(1),
  confidence: z.number().min(0).max(1),
  source: z.enum(['user', 'agent_review']),
  createdAt: z.string(),
  lastSeenAt: z.string(),
  engagementId: z.string().optional(),
});

/**
 * The operator/organization profile — a single durable object.
 */
export interface OperatorProfile {
  /** e.g. "Unicode tables, no markdown". */
  reportFormat?: string;
  /** e.g. "terse" | "detailed". */
  verbosity?: string;
  /** Free-form durable preferences. */
  preferences: string[];
  /** Durable organizational context (owned assets, environment notes). */
  orgContext: string[];
  updatedAt: string;
}

export const OperatorProfileSchema = z.object({
  reportFormat: z.string().optional(),
  verbosity: z.string().optional(),
  preferences: z.array(z.string()).default([]),
  orgContext: z.array(z.string()).default([]),
  updatedAt: z.string(),
});

/**
 * Result of attempting to persist a fact.
 */
export interface AddFactResult {
  added: boolean;
  /** Populated when added === false (dedup, integrity rejection, low confidence). */
  reason?: string;
  /** The stored fact (existing one when deduped). */
  fact?: MemoryFact;
}

/**
 * Build the deterministic dedup id for a fact.
 */
export function buildFactId(category: MemoryCategory, text: string): string {
  // Local import avoids pulling node:crypto types into the public surface.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createHash } = require('crypto') as typeof import('crypto');
  const normalized = `${category}:${text.trim().toLowerCase().replace(/\s+/g, ' ')}`;
  return createHash('md5').update(normalized).digest('hex').slice(0, 12);
}

/**
 * Create an empty profile.
 */
export function emptyProfile(): OperatorProfile {
  return { preferences: [], orgContext: [], updatedAt: new Date().toISOString() };
}
