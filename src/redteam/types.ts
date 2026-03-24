/**
 * Gideon Red Team Engine - Type Definitions
 *
 * Comprehensive type system for enterprise red teaming capabilities.
 * Aligned with MITRE ATLAS, OWASP LLM Top 10 (2025), and NIST AI RMF.
 */

import { z } from 'zod';

// ============================================================================
// MITRE ATLAS Technique Identifiers
// ============================================================================

export type AtlasTactic =
    | 'reconnaissance'
    | 'resource-development'
    | 'initial-access'
    | 'ml-attack-staging'
    | 'persistence'
    | 'defense-evasion'
    | 'credential-access'
    | 'discovery'
    | 'lateral-movement'
    | 'exfiltration'
    | 'impact';

export type AtlasTechnique =
    | 'AML.T0051'   // LLM Prompt Injection
    | 'AML.T0054'   // LLM Jailbreak
    | 'AML.T0053'   // Command Injection via LLM
    | 'AML.T0046'   // System Prompt Theft
    | 'AML.T0020'   // Poisoning Training Data
    | 'AML.T0042'   // Input Manipulation
    | 'AML.T0043'   // Model Evasion
    | 'AML.T0044'   // Full Model Access
    | 'AML.T0048'   // Exfiltration via AI API
    | 'AML.T0049'   // Supply Chain Compromise
    | 'AML.T0050'   // Denial of AI Service
    | 'AML.T0052'   // Indirect Prompt Injection
    | 'AML.T0055'   // Excessive Agency Exploitation
    | 'AML.T0056'   // Agent Hijacking
    | 'AML.T0057';  // Memory Poisoning

// ============================================================================
// OWASP LLM Top 10 (2025)
// ============================================================================

export type OwaspLlmRisk =
    | 'LLM01:2025'  // Prompt Injection
    | 'LLM02:2025'  // Sensitive Information Disclosure
    | 'LLM03:2025'  // Supply Chain Vulnerabilities
    | 'LLM04:2025'  // Data and Model Poisoning
    | 'LLM05:2025'  // Improper Output Handling
    | 'LLM06:2025'  // Excessive Agency
    | 'LLM07:2025'  // System Prompt Leakage
    | 'LLM08:2025'  // Vector and Embedding Weaknesses
    | 'LLM09:2025'  // Misinformation
    | 'LLM10:2025'; // Unbounded Consumption

// ============================================================================
// Core Enums
// ============================================================================

export type AttackSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AttackStatus = 'passed' | 'failed' | 'error' | 'skipped' | 'running' | 'pending';
export type CampaignStatus = 'created' | 'running' | 'completed' | 'failed' | 'cancelled';
export type AttackDepth = 'quick' | 'standard' | 'deep' | 'exhaustive';

export type AttackSuite =
    | 'prompt-injection'
    | 'credential-extraction'
    | 'guardrail-bypass'
    | 'agent-hijacking'
    | 'excessive-agency'
    | 'supply-chain'
    | 'data-exfiltration'
    | 'system-prompt-leakage'
    | 'resource-exhaustion';

export type ReportFormat = 'markdown' | 'json' | 'sarif';

// ============================================================================
// Attack Technique Definition
// ============================================================================

export interface AttackTechnique {
    /** Unique technique identifier */
    id: string;
    /** Human-readable name */
    name: string;
    /** Detailed description */
    description: string;
    /** Attack suite this belongs to */
    suite: AttackSuite;
    /** MITRE ATLAS technique mapping */
    atlasTechnique: AtlasTechnique;
    /** MITRE ATLAS tactic mapping */
    atlasTactic: AtlasTactic;
    /** OWASP LLM Top 10 risk mappings */
    owaspMapping: OwaspLlmRisk[];
    /** Severity if attack succeeds */
    severity: AttackSeverity;
    /** Which Gideon defense module this tests */
    defenseModule: string;
    /** Attack depth levels available */
    supportedDepths: AttackDepth[];
    /** Tags for filtering */
    tags: string[];
}

// ============================================================================
// Attack Payload & Execution
// ============================================================================

export interface AttackPayload {
    /** Unique payload identifier */
    id: string;
    /** Technique this payload implements */
    techniqueId: string;
    /** The actual payload content */
    content: string;
    /** Description of what this payload tests */
    description: string;
    /** Expected behavior if defense holds */
    expectedDefenseBehavior: string;
    /** Encoding or transformation applied */
    encoding?: string;
    /** Metadata for multi-turn attacks */
    turnIndex?: number;
    /** Total turns in a multi-turn chain */
    totalTurns?: number;
}

export interface AttackResult {
    /** Unique result identifier */
    id: string;
    /** Campaign this result belongs to */
    campaignId: string;
    /** Attack technique used */
    technique: AttackTechnique;
    /** Payload that was sent */
    payload: AttackPayload;
    /** Whether the defense held */
    status: AttackStatus;
    /** Severity of the finding (if attack succeeded) */
    severity: AttackSeverity;
    /** Which defense module was tested */
    defenseModule: string;
    /** Did the defense successfully block? */
    defenseHeld: boolean;
    /** Confidence in the result (0-1) */
    confidence: number;
    /** Evidence from the attack */
    evidence: AttackEvidence;
    /** Remediation recommendations */
    remediation: string;
    /** Compliance framework mappings */
    complianceMapping: ComplianceMapping;
    /** Timestamp of execution */
    executedAt: string;
    /** Duration in milliseconds */
    durationMs: number;
}

export interface AttackEvidence {
    /** The request/payload sent */
    request: string;
    /** The response received */
    response: string;
    /** Whether the response indicates a successful attack */
    attackSucceeded: boolean;
    /** Defense alerts triggered */
    alertsTriggered: string[];
    /** Detailed analysis of why the attack succeeded/failed */
    analysis: string;
    /** Screenshots or artifacts (paths) */
    artifacts?: string[];
}

export interface ComplianceMapping {
    nistAiRmf?: string[];
    soc2?: string[];
    iso27001?: string[];
    owaspLlm: OwaspLlmRisk[];
    mitreAtlas: AtlasTechnique[];
}

// ============================================================================
// Campaign Management
// ============================================================================

export interface CampaignScope {
    /** Target endpoint URL or identifier */
    target: string;
    /** Target type */
    targetType: 'agent' | 'llm-endpoint' | 'api' | 'openclaw-instance';
    /** Attack suites to run */
    suites: AttackSuite[];
    /** Attack depth */
    depth: AttackDepth;
    /** Maximum concurrent attacks */
    maxConcurrency: number;
    /** Timeout per attack in milliseconds */
    attackTimeoutMs: number;
    /** Whether to stop on first critical finding */
    stopOnCritical: boolean;
    /** Rate limiting (attacks per minute) */
    rateLimit: number;
}

export interface CampaignAuthorization {
    /** Who authorized this campaign */
    authorizedBy: string;
    /** Authorization timestamp */
    authorizedAt: string;
    /** Scope limitations */
    scopeRestrictions?: string[];
    /** Expiry of authorization */
    expiresAt?: string;
    /** Whether this is a dry-run only */
    dryRunOnly: boolean;
}

export interface Campaign {
    /** Unique campaign identifier */
    id: string;
    /** Campaign name */
    name: string;
    /** Description */
    description: string;
    /** Campaign scope */
    scope: CampaignScope;
    /** Authorization details */
    authorization: CampaignAuthorization;
    /** Current status */
    status: CampaignStatus;
    /** Attack results */
    results: AttackResult[];
    /** Start time */
    startedAt?: string;
    /** End time */
    completedAt?: string;
    /** Campaign-level metrics */
    metrics: CampaignMetrics;
    /** Created timestamp */
    createdAt: string;
}

export interface CampaignMetrics {
    /** Total techniques to run */
    totalTechniques: number;
    /** Completed techniques */
    completedTechniques: number;
    /** Passed (defense held) */
    passed: number;
    /** Failed (attack succeeded) */
    failed: number;
    /** Errors */
    errors: number;
    /** Skipped */
    skipped: number;
    /** Overall risk score (0-100) */
    riskScore: number;
    /** OWASP coverage percentage */
    owaspCoverage: number;
    /** ATLAS coverage percentage */
    atlasCoverage: number;
    /** Duration in milliseconds */
    durationMs: number;
}

// ============================================================================
// Scoring
// ============================================================================

export interface ScoringResult {
    /** Overall risk score (0-100, higher = more risk) */
    overallRiskScore: number;
    /** Risk level */
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
    /** Grade (A-F) */
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    /** Breakdown by OWASP LLM risk */
    owaspBreakdown: Record<OwaspLlmRisk, {
        tested: boolean;
        passed: number;
        failed: number;
        riskScore: number;
    }>;
    /** Breakdown by ATLAS tactic */
    atlasBreakdown: Record<AtlasTactic, {
        tested: boolean;
        techniquesCovered: number;
        passed: number;
        failed: number;
    }>;
    /** Breakdown by defense module */
    defenseBreakdown: Record<string, {
        tested: boolean;
        attacksBlocked: number;
        attacksByPassed: number;
        effectiveness: number;
    }>;
    /** Top findings (sorted by severity) */
    topFindings: AttackResult[];
}

// ============================================================================
// Report
// ============================================================================

export interface RedTeamReport {
    /** Report identifier */
    id: string;
    /** Campaign this report is for */
    campaignId: string;
    /** Report title */
    title: string;
    /** Executive summary */
    executiveSummary: string;
    /** Scoring results */
    scoring: ScoringResult;
    /** Campaign details */
    campaign: Campaign;
    /** Detailed findings */
    findings: AttackResult[];
    /** Compliance coverage */
    compliance: {
        owaspLlm: { covered: OwaspLlmRisk[]; notCovered: OwaspLlmRisk[] };
        mitreAtlas: { covered: AtlasTechnique[]; notCovered: AtlasTechnique[] };
    };
    /** Remediation roadmap */
    remediationPriority: Array<{
        rank: number;
        finding: string;
        severity: AttackSeverity;
        remediation: string;
        effort: 'low' | 'medium' | 'high';
    }>;
    /** Generated at */
    generatedAt: string;
    /** Report format */
    format: ReportFormat;
}

// ============================================================================
// Attack Module Interface
// ============================================================================

export interface AttackModule {
    /** Suite identifier */
    suite: AttackSuite;
    /** Display name */
    name: string;
    /** Description */
    description: string;
    /** Available techniques in this module */
    techniques: AttackTechnique[];
    /** Generate payloads for a given depth */
    generatePayloads(depth: AttackDepth): AttackPayload[];
    /** Execute a single attack and evaluate results */
    executeAttack(
        payload: AttackPayload,
        target: string,
        options: AttackExecutionOptions,
    ): Promise<AttackResult>;
}

export interface AttackExecutionOptions {
    /** Campaign ID for tracking */
    campaignId: string;
    /** Timeout in milliseconds */
    timeoutMs: number;
    /** Whether this is a dry-run */
    dryRun: boolean;
    /** LLM model to use for evaluation */
    model?: string;
    /** Additional context for the attack */
    context?: Record<string, unknown>;
}

// ============================================================================
// Configuration
// ============================================================================

export interface RedTeamConfig {
    /** Enable red teaming capabilities */
    enabled: boolean;
    /** Require explicit authorization for each campaign */
    requireAuthorization: boolean;
    /** Default attack depth */
    defaultDepth: AttackDepth;
    /** Maximum concurrent attacks */
    maxConcurrency: number;
    /** Default timeout per attack (ms) */
    defaultTimeoutMs: number;
    /** Rate limit (attacks per minute) */
    rateLimit: number;
    /** Stop campaign on critical finding */
    stopOnCritical: boolean;
    /** Output directory for reports */
    outputDirectory: string;
    /** Default report format */
    reportFormat: ReportFormat;
    /** Validate defenses after attacks (run against OpenClaw/Guardrails) */
    validateDefenses: boolean;
    /** Log all operations to governance audit trail */
    auditLogging: boolean;
}

// ============================================================================
// Zod Schemas for Validation
// ============================================================================

export const AttackSuiteSchema = z.enum([
    'prompt-injection',
    'credential-extraction',
    'guardrail-bypass',
    'agent-hijacking',
    'excessive-agency',
    'supply-chain',
    'data-exfiltration',
    'system-prompt-leakage',
    'resource-exhaustion',
]);

export const AttackDepthSchema = z.enum(['quick', 'standard', 'deep', 'exhaustive']);
export const ReportFormatSchema = z.enum(['markdown', 'json', 'sarif']);

export const CampaignScopeSchema = z.object({
    target: z.string().min(1),
    targetType: z.enum(['agent', 'llm-endpoint', 'api', 'openclaw-instance']),
    suites: z.array(AttackSuiteSchema).min(1),
    depth: AttackDepthSchema,
    maxConcurrency: z.number().int().min(1).max(10).default(3),
    attackTimeoutMs: z.number().int().min(1000).max(120000).default(30000),
    stopOnCritical: z.boolean().default(false),
    rateLimit: z.number().int().min(1).max(60).default(10),
});

export const RedTeamConfigSchema = z.object({
    enabled: z.boolean().default(false),
    requireAuthorization: z.boolean().default(true),
    defaultDepth: AttackDepthSchema.default('standard'),
    maxConcurrency: z.number().int().min(1).max(10).default(3),
    defaultTimeoutMs: z.number().int().min(1000).max(120000).default(30000),
    rateLimit: z.number().int().min(1).max(60).default(10),
    stopOnCritical: z.boolean().default(false),
    outputDirectory: z.string().default('./outputs/redteam'),
    reportFormat: ReportFormatSchema.default('markdown'),
    validateDefenses: z.boolean().default(true),
    auditLogging: z.boolean().default(true),
});
