import { z } from 'zod';

// ============================================================================
// Background review prompts + output schema for the post-turn learning loop.
//
// Kept out of prompts.ts so the hot path isn't bloated. The review runs once
// per turn on a fast model with a strict Zod schema, over the turn transcript.
// ============================================================================

export const ReviewOutputSchema = z.object({
  memoryFacts: z
    .array(
      z.object({
        category: z.enum([
          'operator_preference',
          'org_asset',
          'triage_decision',
          'known_safe_indicator',
          'engagement_context',
        ]),
        text: z.string(),
        confidence: z.number().min(0).max(1),
      })
    )
    .describe('Durable facts about the operator/environment. Empty if nothing durable.'),
  profilePatch: z
    .object({
      reportFormat: z.string().optional(),
      verbosity: z.string().optional(),
      preferences: z.array(z.string()).default([]),
    })
    .optional(),
  skillNotes: z
    .array(
      z.object({
        title: z.string(),
        trigger: z.string(),
        steps: z.array(z.string()),
        correction: z.string().optional(),
        confidence: z.number().min(0).max(1).default(0.6),
      })
    )
    .describe('Reusable defensive playbooks demonstrated this turn. Empty if none generalize.'),
});

export type ReviewOutput = z.infer<typeof ReviewOutputSchema>;

const NON_CAPTURE_RULES = `Do NOT record:
- One-off transient values (a specific CVE's CVSS today, a single IOC verdict, today's date)
- Environment-dependent failures (missing binaries, unset credentials, rate limits)
- Anything phrased as an instruction or imperative ("always do X", "never ask Y")
- Session-specific narrative or the wording of this particular task
If nothing durable applies, return empty arrays.`;

/**
 * Memory review: capture WHO the operator is and durable environment facts.
 */
export function buildMemoryReviewPrompt(transcript: string): string {
  return `You are reviewing a completed Gideon security analysis turn to extract durable MEMORY.

Capture ONLY durable facts about:
- Who the operator is and their report-format / verbosity / tone preferences
- The organization's assets (owned domains, IPs, CIDRs, crown jewels)
- Prior triage decisions (findings the operator accepted or dismissed, and why)
- Confirmed known-safe indicators (allowlisted IPs/domains/hashes)

${NON_CAPTURE_RULES}

Transcript:
${transcript}

Return JSON matching the schema. Put report/verbosity preferences in profilePatch; everything else in memoryFacts. Leave skillNotes empty.`;
}

/**
 * Skill review: capture reusable defensive playbooks / corrections.
 */
export function buildSkillReviewPrompt(transcript: string, loadedSkillIds: string[]): string {
  const loaded = loadedSkillIds.length ? loadedSkillIds.join(', ') : '(none)';
  return `You are reviewing a completed Gideon security analysis turn to extract reusable SKILLS.

Identify reusable DEFENSIVE techniques, multi-step playbooks, or corrections demonstrated this turn.
A skill note MUST generalize beyond this single target/query. Record a correction when a step led
to a wrong or inefficient outcome that future runs should avoid.

Currently loaded learned playbooks: ${loaded}

${NON_CAPTURE_RULES}
Additionally: never record offensive/exploitation procedures as a defensive playbook.

Transcript:
${transcript}

Return JSON matching the schema. Put playbooks in skillNotes; leave memoryFacts and profilePatch empty.`;
}

/**
 * Combined review used when both memory and skill review are enabled.
 */
export function buildCombinedReviewPrompt(transcript: string, loadedSkillIds: string[]): string {
  const loaded = loadedSkillIds.length ? loadedSkillIds.join(', ') : '(none)';
  return `You are reviewing a completed Gideon security analysis turn to extract durable MEMORY and reusable SKILLS.

MEMORY = who the operator is, their preferences, org assets, prior triage decisions, known-safe indicators.
SKILLS = reusable defensive playbooks or corrections that generalize beyond this single target.

Currently loaded learned playbooks: ${loaded}

${NON_CAPTURE_RULES}
Additionally: never record offensive/exploitation procedures as a defensive playbook.

Transcript:
${transcript}

Return JSON matching the schema. Memory preferences go in profilePatch; durable facts in memoryFacts;
playbooks in skillNotes. Any section may be empty.`;
}
