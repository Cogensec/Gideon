/**
 * Gideon Red Team Engine - Main Entry Point
 *
 * Orchestrates the full red teaming pipeline:
 * campaign creation → attack execution → scoring → reporting
 */

export { CampaignManager } from './campaign-manager.js';
export { AttackRunner, type ProgressEvent, type DryRunPlan } from './attack-runner.js';
export { ScoringEngine } from './scoring-engine.js';
export { ReportGenerator } from './report-generator.js';

// Attack Modules
export { PromptInjectionModule } from './attacks/prompt-injection.js';
export { CredentialExtractionModule } from './attacks/credential-extraction.js';
export { GuardrailBypassModule } from './attacks/guardrail-bypass.js';
export { AgentHijackingModule } from './attacks/agent-hijacking.js';
export { ExcessiveAgencyModule } from './attacks/excessive-agency.js';
export { SupplyChainModule } from './attacks/supply-chain.js';
export { DataExfiltrationModule } from './attacks/data-exfiltration.js';
export { SystemPromptLeakageModule } from './attacks/system-prompt-leakage.js';
export { ResourceExhaustionModule } from './attacks/resource-exhaustion.js';

// Types
export type {
    Campaign,
    CampaignScope,
    CampaignAuthorization,
    CampaignMetrics,
    AttackModule as AttackModuleType,
    AttackTechnique,
    AttackPayload,
    AttackResult,
    AttackEvidence,
    AttackSuite,
    AttackDepth,
    AttackSeverity,
    ScoringResult,
    RedTeamReport,
    RedTeamConfig,
    ComplianceMapping,
    OwaspLlmRisk,
    AtlasTechnique,
    AtlasTactic,
    ReportFormat,
} from './types.js';

import { CampaignManager } from './campaign-manager.js';
import { AttackRunner } from './attack-runner.js';
import { ScoringEngine } from './scoring-engine.js';
import { ReportGenerator } from './report-generator.js';
import { PromptInjectionModule } from './attacks/prompt-injection.js';
import { CredentialExtractionModule } from './attacks/credential-extraction.js';
import { GuardrailBypassModule } from './attacks/guardrail-bypass.js';
import { AgentHijackingModule } from './attacks/agent-hijacking.js';
import { ExcessiveAgencyModule } from './attacks/excessive-agency.js';
import { SupplyChainModule } from './attacks/supply-chain.js';
import { DataExfiltrationModule } from './attacks/data-exfiltration.js';
import { SystemPromptLeakageModule } from './attacks/system-prompt-leakage.js';
import { ResourceExhaustionModule } from './attacks/resource-exhaustion.js';
import { RedTeamConfig } from './types.js';

// ============================================================================
// All Attack Modules
// ============================================================================

const ALL_ATTACK_MODULES = [
    PromptInjectionModule,
    CredentialExtractionModule,
    GuardrailBypassModule,
    AgentHijackingModule,
    ExcessiveAgencyModule,
    SupplyChainModule,
    DataExfiltrationModule,
    SystemPromptLeakageModule,
    ResourceExhaustionModule,
];

// ============================================================================
// Factory Function
// ============================================================================

/**
 * Create a fully initialized Red Team Engine with all modules registered.
 */
export function createRedTeamEngine(config?: Partial<RedTeamConfig>): {
    campaignManager: CampaignManager;
    attackRunner: AttackRunner;
    scoringEngine: ScoringEngine;
    reportGenerator: ReportGenerator;
} {
    const campaignManager = new CampaignManager(config);
    const scoringEngine = new ScoringEngine();
    const attackRunner = new AttackRunner(campaignManager, scoringEngine);
    const reportGenerator = new ReportGenerator(scoringEngine);

    // Register all attack modules
    for (const module of ALL_ATTACK_MODULES) {
        attackRunner.registerModule(module);
    }

    return {
        campaignManager,
        attackRunner,
        scoringEngine,
        reportGenerator,
    };
}

/**
 * Get a summary of all available attack modules
 */
export function getAvailableModules(): Array<{
    suite: string;
    name: string;
    description: string;
    techniqueCount: number;
}> {
    return ALL_ATTACK_MODULES.map(m => ({
        suite: m.suite,
        name: m.name,
        description: m.description,
        techniqueCount: m.techniques.length,
    }));
}

/**
 * Get total technique count across all modules
 */
export function getTotalTechniqueCount(): number {
    return ALL_ATTACK_MODULES.reduce((sum, m) => sum + m.techniques.length, 0);
}
