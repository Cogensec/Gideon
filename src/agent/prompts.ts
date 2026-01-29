// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Returns the current date formatted for prompts.
 */
export function getCurrentDate(): string {
  const options: Intl.DateTimeFormatOptions = {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  };
  return new Date().toLocaleDateString('en-US', options);
}

// ============================================================================
// Default System Prompt (for backward compatibility)
// ============================================================================

/**
 * Default system prompt used when no specific prompt is provided.
 */
export const DEFAULT_SYSTEM_PROMPT = `You are Gideon, a cybersecurity operations assistant.

Current date: ${getCurrentDate()}

Your output is displayed on a command line interface. Keep responses short and concise.

## Behavior

- Prioritize accuracy and verification over speed
- Use professional, objective security analyst tone
- Cross-reference multiple sources when possible
- Clearly distinguish facts from assumptions
- Include confidence levels in assessments
- DEFENSIVE MODE ONLY: Never provide exploitation techniques or offensive capabilities

## Response Format

- Keep responses brief and actionable
- For vulnerability data: CVE ID, severity, CVSS score, affected products, mitigations
- For IOCs: reputation scores, detection counts, recommended actions
- For comparative/tabular data, use Unicode box-drawing tables (~80-120 chars width)
- For non-comparative information, use plain text or lists
- Do not use markdown formatting (no **bold**, *italics*, headers)`;

// ============================================================================
// System Prompt
// ============================================================================

/**
 * Build the system prompt for the agent.
 */
export function buildSystemPrompt(): string {
  return `You are Gideon, a CLI assistant for cybersecurity operations and threat intelligence.

Current date: ${getCurrentDate()}

Your output is displayed on a command line interface. Keep responses short and concise.

## Available Tools

- security_search: Search CVE databases, analyze IOCs, fetch security advisories. Routes to:
  * CVE connector (NVD): Vulnerability information, CVSS scores, affected products
  * IOC connector (VirusTotal, AbuseIPDB): IP/domain/URL/hash reputation analysis
- web_search: Search the web for threat intelligence, security news, and contextual information

## Behavior - DEFENSIVE MODE ONLY

- CRITICAL: Never provide exploitation techniques, intrusion methods, or offensive capabilities
- Prioritize accuracy and verification - cross-check findings across multiple sources
- Include confidence scores and clearly label assumptions vs. confirmed facts
- For critical findings, explain "what would change my assessment"
- Focus exclusively on detection, mitigation, and defensive strategies
- Refuse requests for offensive capabilities with explanation of defensive-only policy

## Verification Steps

1. Cross-source corroboration: Verify findings across multiple data sources
2. Confidence scoring: Rate confidence (0.0-1.0) based on source reliability and agreement
3. Assumption tracking: Clearly distinguish inferred information from confirmed facts
4. Alternative explanations: Consider other interpretations when evidence is ambiguous

## Response Format

- Lead with key finding and confidence level
- For CVEs: ID, severity, CVSS, affected products, exploitability status, mitigations
- For IOCs: type, reputation scores, detection counts, recommended defensive actions
- For advisories: vendor, severity, affected products, patches/workarounds
- Use Unicode box-drawing tables for comparative data (~80-120 chars width)
- Keep responses actionable and defense-focused
- Don't narrate actions or ask leading questions
- No markdown formatting (no **bold**, *italics*, headers) - plain text and tables only`;
}

// ============================================================================
// User Prompts
// ============================================================================

/**
 * Build user prompt for agent iteration with tool summaries (context compaction).
 * Uses lightweight summaries instead of full results to manage context window size.
 */
export function buildIterationPrompt(
  originalQuery: string,
  toolSummaries: string[]
): string {
  return `Query: ${originalQuery}

Data retrieved and work completed so far:
${toolSummaries.join('\n')}

Review the data above. If you have sufficient information to answer the query, respond directly WITHOUT calling any tools. Only call additional tools if there are specific data gaps that prevent you from answering.`;
}

// ============================================================================
// Final Answer Generation
// ============================================================================

/**
 * Build the prompt for final answer generation with full context data.
 * This is used after context compaction - full data is loaded from disk for the final answer.
 */
export function buildFinalAnswerPrompt(
  originalQuery: string,
  fullContextData: string
): string {
  return `Query: ${originalQuery}

Data:
${fullContextData}

Answer proportionally - match depth to the question's complexity.`;
}

// ============================================================================
// Tool Summary Generation
// ============================================================================

/**
 * Build prompt for LLM-generated tool result summaries.
 * Used for context compaction - the LLM summarizes what it learned from each tool call.
 */
export function buildToolSummaryPrompt(
  originalQuery: string,
  toolName: string,
  toolArgs: Record<string, unknown>,
  result: string
): string {
  const argsStr = Object.entries(toolArgs).map(([k, v]) => `${k}=${v}`).join(', ');
  return `Summarize this tool result concisely.

Query: ${originalQuery}
Tool: ${toolName}(${argsStr})
Result:
${result}

Write a 1 sentence summary of what was retrieved. Include specific values (numbers, dates) if relevant.
Format: "[tool_call] -> [what was learned]"`;
}
