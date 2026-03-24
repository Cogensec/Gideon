/**
 * Campaign Manager - Orchestrates red team campaigns
 *
 * Handles campaign creation, authorization, scoping, and lifecycle management.
 * Integrates with governance audit logging for enterprise compliance.
 */

import {
    Campaign,
    CampaignScope,
    CampaignAuthorization,
    CampaignStatus,
    CampaignMetrics,
    AttackSuite,
    AttackDepth,
    RedTeamConfig,
    CampaignScopeSchema,
} from './types.js';

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_REDTEAM_CONFIG: RedTeamConfig = {
    enabled: true,
    requireAuthorization: true,
    defaultDepth: 'standard',
    maxConcurrency: 3,
    defaultTimeoutMs: 30000,
    rateLimit: 10,
    stopOnCritical: false,
    outputDirectory: './outputs/redteam',
    reportFormat: 'markdown',
    validateDefenses: true,
    auditLogging: true,
};

const ALL_SUITES: AttackSuite[] = [
    'prompt-injection',
    'credential-extraction',
    'guardrail-bypass',
    'agent-hijacking',
    'excessive-agency',
    'supply-chain',
    'data-exfiltration',
    'system-prompt-leakage',
    'resource-exhaustion',
];

// ============================================================================
// Campaign Manager
// ============================================================================

export class CampaignManager {
    private campaigns: Map<string, Campaign> = new Map();
    private config: RedTeamConfig;

    constructor(config?: Partial<RedTeamConfig>) {
        this.config = { ...DEFAULT_REDTEAM_CONFIG, ...config };
    }

    /**
     * Create a new red team campaign
     */
    createCampaign(params: {
        name: string;
        description?: string;
        target: string;
        targetType?: CampaignScope['targetType'];
        suites?: AttackSuite[] | 'full' | 'owasp-llm';
        depth?: AttackDepth;
        authorizedBy?: string;
        dryRun?: boolean;
        stopOnCritical?: boolean;
    }): Campaign {
        // Resolve suite selection
        let suites: AttackSuite[];
        if (!params.suites || params.suites === 'full') {
            suites = [...ALL_SUITES];
        } else if (params.suites === 'owasp-llm') {
            suites = [
                'prompt-injection',
                'credential-extraction',
                'guardrail-bypass',
                'excessive-agency',
                'supply-chain',
                'data-exfiltration',
                'system-prompt-leakage',
                'resource-exhaustion',
            ];
        } else {
            suites = params.suites;
        }

        const scope: CampaignScope = {
            target: params.target,
            targetType: params.targetType || 'agent',
            suites,
            depth: params.depth || this.config.defaultDepth,
            maxConcurrency: this.config.maxConcurrency,
            attackTimeoutMs: this.config.defaultTimeoutMs,
            stopOnCritical: params.stopOnCritical ?? this.config.stopOnCritical,
            rateLimit: this.config.rateLimit,
        };

        // Validate scope
        const validation = CampaignScopeSchema.safeParse(scope);
        if (!validation.success) {
            throw new Error(`Invalid campaign scope: ${validation.error.message}`);
        }

        const authorization: CampaignAuthorization = {
            authorizedBy: params.authorizedBy || 'system',
            authorizedAt: new Date().toISOString(),
            dryRunOnly: params.dryRun ?? false,
        };

        const campaign: Campaign = {
            id: crypto.randomUUID(),
            name: params.name,
            description: params.description || `Red team campaign against ${params.target}`,
            scope,
            authorization,
            status: 'created',
            results: [],
            metrics: this.createEmptyMetrics(),
            createdAt: new Date().toISOString(),
        };

        this.campaigns.set(campaign.id, campaign);
        return campaign;
    }

    /**
     * Start a campaign
     */
    startCampaign(campaignId: string): Campaign {
        const campaign = this.getCampaign(campaignId);
        if (campaign.status !== 'created') {
            throw new Error(`Campaign ${campaignId} is already ${campaign.status}`);
        }

        campaign.status = 'running';
        campaign.startedAt = new Date().toISOString();
        return campaign;
    }

    /**
     * Complete a campaign
     */
    completeCampaign(campaignId: string): Campaign {
        const campaign = this.getCampaign(campaignId);
        campaign.status = 'completed';
        campaign.completedAt = new Date().toISOString();

        if (campaign.startedAt) {
            campaign.metrics.durationMs =
                new Date(campaign.completedAt).getTime() - new Date(campaign.startedAt).getTime();
        }

        return campaign;
    }

    /**
     * Cancel a campaign
     */
    cancelCampaign(campaignId: string): Campaign {
        const campaign = this.getCampaign(campaignId);
        campaign.status = 'cancelled';
        campaign.completedAt = new Date().toISOString();
        return campaign;
    }

    /**
     * Update campaign metrics
     */
    updateMetrics(campaignId: string, updates: Partial<CampaignMetrics>): void {
        const campaign = this.getCampaign(campaignId);
        Object.assign(campaign.metrics, updates);
    }

    /**
     * Get a campaign by ID
     */
    getCampaign(campaignId: string): Campaign {
        const campaign = this.campaigns.get(campaignId);
        if (!campaign) {
            throw new Error(`Campaign ${campaignId} not found`);
        }
        return campaign;
    }

    /**
     * List all campaigns
     */
    listCampaigns(filters?: {
        status?: CampaignStatus;
        since?: Date;
    }): Campaign[] {
        let campaigns = Array.from(this.campaigns.values());

        if (filters?.status) {
            campaigns = campaigns.filter(c => c.status === filters.status);
        }
        if (filters?.since) {
            campaigns = campaigns.filter(
                c => new Date(c.createdAt) >= filters.since!,
            );
        }

        return campaigns.sort(
            (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
        );
    }

    /**
     * Get campaign summary for display
     */
    getCampaignSummary(campaignId: string): string {
        const campaign = this.getCampaign(campaignId);
        const m = campaign.metrics;

        const lines = [
            `# Campaign: ${campaign.name}`,
            ``,
            `**Status:** ${campaign.status}`,
            `**Target:** ${campaign.scope.target} (${campaign.scope.targetType})`,
            `**Depth:** ${campaign.scope.depth}`,
            `**Suites:** ${campaign.scope.suites.join(', ')}`,
            `**Authorization:** ${campaign.authorization.authorizedBy} at ${campaign.authorization.authorizedAt}`,
            `${campaign.authorization.dryRunOnly ? '⚠️ **DRY RUN ONLY**' : ''}`,
            ``,
            `## Progress`,
            `- Total: ${m.totalTechniques}`,
            `- Completed: ${m.completedTechniques}`,
            `- ✅ Passed (defense held): ${m.passed}`,
            `- ❌ Failed (attack succeeded): ${m.failed}`,
            `- ⚠️ Errors: ${m.errors}`,
            `- ⏭ Skipped: ${m.skipped}`,
            ``,
            `## Risk Score: ${m.riskScore}/100`,
            `- OWASP Coverage: ${m.owaspCoverage}%`,
            `- ATLAS Coverage: ${m.atlasCoverage}%`,
        ];

        return lines.join('\n');
    }

    /**
     * Get config
     */
    getConfig(): RedTeamConfig {
        return { ...this.config };
    }

    // ============================================================================
    // Private Helpers
    // ============================================================================

    private createEmptyMetrics(): CampaignMetrics {
        return {
            totalTechniques: 0,
            completedTechniques: 0,
            passed: 0,
            failed: 0,
            errors: 0,
            skipped: 0,
            riskScore: 0,
            owaspCoverage: 0,
            atlasCoverage: 0,
            durationMs: 0,
        };
    }
}
