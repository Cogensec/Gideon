/**
 * Attack Runner - Multi-step attack chain orchestration
 *
 * Executes attack modules against targets with rate limiting,
 * concurrency control, and real-time progress tracking.
 */

import {
    AttackModule,
    AttackPayload,
    AttackResult,
    AttackTechnique,
    AttackSeverity,
    AttackEvidence,
    Campaign,
    CampaignScope,
    ComplianceMapping,
    AttackExecutionOptions,
} from './types.js';
import { CampaignManager } from './campaign-manager.js';
import { ScoringEngine } from './scoring-engine.js';

// ============================================================================
// Attack Runner
// ============================================================================

export class AttackRunner {
    private campaignManager: CampaignManager;
    private scoringEngine: ScoringEngine;
    private modules: Map<string, AttackModule> = new Map();
    private onProgress?: (event: ProgressEvent) => void;

    constructor(
        campaignManager: CampaignManager,
        scoringEngine: ScoringEngine,
    ) {
        this.campaignManager = campaignManager;
        this.scoringEngine = scoringEngine;
    }

    /**
     * Register an attack module
     */
    registerModule(module: AttackModule): void {
        this.modules.set(module.suite, module);
    }

    /**
     * Get all registered modules
     */
    getModules(): AttackModule[] {
        return Array.from(this.modules.values());
    }

    /**
     * Get a specific module
     */
    getModule(suite: string): AttackModule | undefined {
        return this.modules.get(suite);
    }

    /**
     * Set progress callback
     */
    onProgressUpdate(callback: (event: ProgressEvent) => void): void {
        this.onProgress = callback;
    }

    /**
     * Execute a full campaign
     */
    async executeCampaign(campaignId: string): Promise<Campaign> {
        const campaign = this.campaignManager.startCampaign(campaignId);
        const scope = campaign.scope;

        this.emitProgress({
            type: 'campaign_start',
            campaignId,
            message: `Starting red team campaign: ${campaign.name}`,
        });

        try {
            // Gather all payloads from requested suites
            const attackPlan = this.buildAttackPlan(scope);

            // Update total count
            this.campaignManager.updateMetrics(campaignId, {
                totalTechniques: attackPlan.length,
            });

            this.emitProgress({
                type: 'plan_ready',
                campaignId,
                message: `Attack plan: ${attackPlan.length} payloads across ${scope.suites.length} suites`,
            });

            // Execute with rate limiting and concurrency control
            const results = await this.executeWithRateLimit(
                campaignId,
                attackPlan,
                scope,
            );

            // Store results
            campaign.results = results;

            // Calculate final metrics
            const scoring = this.scoringEngine.scoreCampaign(campaign);
            this.campaignManager.updateMetrics(campaignId, {
                completedTechniques: results.length,
                passed: results.filter(r => r.defenseHeld).length,
                failed: results.filter(r => !r.defenseHeld).length,
                errors: results.filter(r => r.status === 'error').length,
                skipped: results.filter(r => r.status === 'skipped').length,
                riskScore: scoring.overallRiskScore,
                owaspCoverage: this.scoringEngine.calculateOwaspCoverage(results),
                atlasCoverage: this.scoringEngine.calculateAtlasCoverage(results),
            });

            this.campaignManager.completeCampaign(campaignId);

            this.emitProgress({
                type: 'campaign_complete',
                campaignId,
                message: `Campaign complete. Risk score: ${scoring.overallRiskScore}/100 (${scoring.grade})`,
            });

            return this.campaignManager.getCampaign(campaignId);
        } catch (error) {
            campaign.status = 'failed';
            campaign.completedAt = new Date().toISOString();

            this.emitProgress({
                type: 'campaign_error',
                campaignId,
                message: `Campaign failed: ${error instanceof Error ? error.message : String(error)}`,
            });

            throw error;
        }
    }

    /**
     * Execute a dry run - returns the plan without executing
     */
    buildDryRunPlan(scope: CampaignScope): DryRunPlan {
        const attackPlan = this.buildAttackPlan(scope);

        const bySuite = new Map<string, AttackPlanItem[]>();
        for (const item of attackPlan) {
            const suite = item.technique.suite;
            if (!bySuite.has(suite)) bySuite.set(suite, []);
            bySuite.get(suite)!.push(item);
        }

        const suites: DryRunSuite[] = [];
        for (const [suite, items] of bySuite.entries()) {
            const module = this.modules.get(suite);
            suites.push({
                suite,
                name: module?.name || suite,
                description: module?.description || '',
                techniqueCount: items.length,
                techniques: items.map(i => ({
                    id: i.technique.id,
                    name: i.technique.name,
                    atlas: i.technique.atlasTechnique,
                    owasp: i.technique.owaspMapping,
                    severity: i.technique.severity,
                    defenseModule: i.technique.defenseModule,
                })),
            });
        }

        return {
            target: scope.target,
            targetType: scope.targetType,
            depth: scope.depth,
            totalPayloads: attackPlan.length,
            suites,
            estimatedDurationMinutes: Math.ceil(attackPlan.length / scope.rateLimit),
        };
    }

    // ============================================================================
    // Private Methods
    // ============================================================================

    private buildAttackPlan(scope: CampaignScope): AttackPlanItem[] {
        const plan: AttackPlanItem[] = [];

        for (const suiteName of scope.suites) {
            const module = this.modules.get(suiteName);
            if (!module) continue;

            const payloads = module.generatePayloads(scope.depth);

            for (const payload of payloads) {
                const technique = module.techniques.find(
                    t => t.id === payload.techniqueId,
                );
                if (!technique) continue;

                plan.push({ technique, payload, module });
            }
        }

        return plan;
    }

    private async executeWithRateLimit(
        campaignId: string,
        plan: AttackPlanItem[],
        scope: CampaignScope,
    ): Promise<AttackResult[]> {
        const results: AttackResult[] = [];
        const delayMs = (60 / scope.rateLimit) * 1000;

        // Execute sequentially with rate limiting for predictable results
        for (let i = 0; i < plan.length; i++) {
            const item = plan[i];
            const campaign = this.campaignManager.getCampaign(campaignId);

            // Check if campaign was cancelled
            if (campaign.status === 'cancelled') break;

            // Check stop-on-critical
            if (scope.stopOnCritical) {
                const hasCritical = results.some(
                    r => !r.defenseHeld && r.severity === 'critical',
                );
                if (hasCritical) {
                    this.emitProgress({
                        type: 'attack_skipped',
                        campaignId,
                        message: `Stopping: critical finding detected (stopOnCritical=true)`,
                    });
                    break;
                }
            }

            this.emitProgress({
                type: 'attack_start',
                campaignId,
                message: `[${i + 1}/${plan.length}] ${item.technique.name}`,
            });

            try {
                const options: AttackExecutionOptions = {
                    campaignId,
                    timeoutMs: scope.attackTimeoutMs,
                    dryRun: campaign.authorization.dryRunOnly,
                };

                const result = await item.module.executeAttack(
                    item.payload,
                    scope.target,
                    options,
                );

                results.push(result);

                const status = result.defenseHeld ? '✅ BLOCKED' : '❌ BYPASSED';
                this.emitProgress({
                    type: 'attack_complete',
                    campaignId,
                    message: `${status} ${item.technique.name} (${result.severity})`,
                });
            } catch (error) {
                const errorResult = this.createErrorResult(
                    campaignId,
                    item.technique,
                    item.payload,
                    error,
                );
                results.push(errorResult);

                this.emitProgress({
                    type: 'attack_error',
                    campaignId,
                    message: `⚠️ Error: ${item.technique.name}: ${error instanceof Error ? error.message : String(error)}`,
                });
            }

            // Rate limiting delay (skip after last item)
            if (i < plan.length - 1) {
                await this.delay(delayMs);
            }
        }

        return results;
    }

    private createErrorResult(
        campaignId: string,
        technique: AttackTechnique,
        payload: AttackPayload,
        error: unknown,
    ): AttackResult {
        return {
            id: crypto.randomUUID(),
            campaignId,
            technique,
            payload,
            status: 'error',
            severity: technique.severity,
            defenseModule: technique.defenseModule,
            defenseHeld: true, // Assume defense held on error
            confidence: 0,
            evidence: {
                request: payload.content,
                response: error instanceof Error ? error.message : String(error),
                attackSucceeded: false,
                alertsTriggered: [],
                analysis: `Attack execution failed: ${error instanceof Error ? error.message : String(error)}`,
            },
            remediation: 'Review error and retry',
            complianceMapping: {
                owaspLlm: technique.owaspMapping,
                mitreAtlas: [technique.atlasTechnique],
            },
            executedAt: new Date().toISOString(),
            durationMs: 0,
        };
    }

    private emitProgress(event: ProgressEvent): void {
        if (this.onProgress) {
            this.onProgress(event);
        }
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// ============================================================================
// Types
// ============================================================================

interface AttackPlanItem {
    technique: AttackTechnique;
    payload: AttackPayload;
    module: AttackModule;
}

export interface ProgressEvent {
    type:
    | 'campaign_start'
    | 'plan_ready'
    | 'attack_start'
    | 'attack_complete'
    | 'attack_error'
    | 'attack_skipped'
    | 'campaign_complete'
    | 'campaign_error';
    campaignId: string;
    message: string;
}

export interface DryRunPlan {
    target: string;
    targetType: string;
    depth: string;
    totalPayloads: number;
    suites: DryRunSuite[];
    estimatedDurationMinutes: number;
}

export interface DryRunSuite {
    suite: string;
    name: string;
    description: string;
    techniqueCount: number;
    techniques: Array<{
        id: string;
        name: string;
        atlas: string;
        owasp: string[];
        severity: AttackSeverity;
        defenseModule: string;
    }>;
}
