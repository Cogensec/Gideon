/**
 * Red Team Report Generator
 *
 * Generates enterprise-grade reports from campaign results.
 * Supports Markdown, JSON, and SARIF formats with compliance mapping.
 */

import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import {
    RedTeamReport,
    Campaign,
    ScoringResult,
    AttackResult,
    AttackSeverity,
    ReportFormat,
} from './types.js';
import { ScoringEngine } from './scoring-engine.js';

// ============================================================================
// Report Generator
// ============================================================================

export class ReportGenerator {
    private scoringEngine: ScoringEngine;

    constructor(scoringEngine: ScoringEngine) {
        this.scoringEngine = scoringEngine;
    }

    /**
     * Generate a full report from campaign results
     */
    generateReport(campaign: Campaign, format: ReportFormat = 'markdown'): RedTeamReport {
        const scoring = this.scoringEngine.scoreCampaign(campaign);

        const report: RedTeamReport = {
            id: crypto.randomUUID(),
            campaignId: campaign.id,
            title: `Red Team Assessment: ${campaign.name}`,
            executiveSummary: this.generateExecutiveSummary(campaign, scoring),
            scoring,
            campaign,
            findings: campaign.results.filter(r => r.status === 'failed'),
            compliance: this.generateComplianceSection(campaign),
            remediationPriority: this.generateRemediationPriority(campaign.results),
            generatedAt: new Date().toISOString(),
            format,
        };

        return report;
    }

    /**
     * Save report to filesystem
     */
    saveReport(report: RedTeamReport, outputDir: string): string {
        if (!existsSync(outputDir)) {
            mkdirSync(outputDir, { recursive: true });
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const baseName = `redteam-${timestamp}`;

        let outputPath: string;

        switch (report.format) {
            case 'json':
                outputPath = join(outputDir, `${baseName}.json`);
                writeFileSync(outputPath, JSON.stringify(report, null, 2));
                break;

            case 'sarif':
                outputPath = join(outputDir, `${baseName}.sarif.json`);
                writeFileSync(outputPath, JSON.stringify(this.toSarif(report), null, 2));
                break;

            case 'markdown':
            default:
                outputPath = join(outputDir, `${baseName}.md`);
                writeFileSync(outputPath, this.toMarkdown(report));
                break;
        }

        return outputPath;
    }

    /**
     * Generate Markdown report
     */
    toMarkdown(report: RedTeamReport): string {
        const s = report.scoring;
        const c = report.campaign;
        const lines: string[] = [];

        // Header
        lines.push(`# 🔴 ${report.title}`);
        lines.push('');
        lines.push(`**Generated:** ${new Date(report.generatedAt).toLocaleString()}`);
        lines.push(`**Campaign ID:** \`${c.id}\``);
        lines.push(`**Target:** ${c.scope.target} (${c.scope.targetType})`);
        lines.push(`**Depth:** ${c.scope.depth}`);
        lines.push(`**Authorization:** ${c.authorization.authorizedBy}`);
        lines.push('');

        // Executive Summary
        lines.push('## Executive Summary');
        lines.push('');
        lines.push(report.executiveSummary);
        lines.push('');

        // Risk Score Dashboard
        lines.push('## Risk Assessment');
        lines.push('');
        lines.push(`| Metric | Value |`);
        lines.push(`|--------|-------|`);
        lines.push(`| **Overall Risk Score** | **${s.overallRiskScore}/100** |`);
        lines.push(`| **Risk Level** | ${this.riskBadge(s.riskLevel)} |`);
        lines.push(`| **Grade** | **${s.grade}** |`);
        lines.push(`| Techniques Tested | ${c.metrics.completedTechniques} |`);
        lines.push(`| Defenses Held | ✅ ${c.metrics.passed} |`);
        lines.push(`| Defenses Bypassed | ❌ ${c.metrics.failed} |`);
        lines.push(`| Errors | ⚠️ ${c.metrics.errors} |`);
        lines.push(`| Duration | ${this.formatDuration(c.metrics.durationMs)} |`);
        lines.push('');

        // OWASP LLM Top 10 Coverage
        lines.push('## OWASP LLM Top 10 (2025) Coverage');
        lines.push('');
        lines.push('| # | Risk | Tested | Passed | Failed | Risk |');
        lines.push('|---|------|--------|--------|--------|------|');
        const owaspNames: Record<string, string> = {
            'LLM01:2025': 'Prompt Injection', 'LLM02:2025': 'Sensitive Info Disclosure',
            'LLM03:2025': 'Supply Chain', 'LLM04:2025': 'Data/Model Poisoning',
            'LLM05:2025': 'Improper Output Handling', 'LLM06:2025': 'Excessive Agency',
            'LLM07:2025': 'System Prompt Leakage', 'LLM08:2025': 'Vector/Embedding Weakness',
            'LLM09:2025': 'Misinformation', 'LLM10:2025': 'Unbounded Consumption',
        };
        for (const [risk, data] of Object.entries(s.owaspBreakdown)) {
            const name = owaspNames[risk] || risk;
            const testedIcon = data.tested ? '✅' : '⬜';
            const riskScore = data.riskScore > 0 ? `🔴 ${data.riskScore}` : data.tested ? '🟢 0' : '—';
            lines.push(`| ${risk} | ${name} | ${testedIcon} | ${data.passed} | ${data.failed} | ${riskScore} |`);
        }
        lines.push('');

        // MITRE ATLAS Coverage
        lines.push('## MITRE ATLAS Tactic Coverage');
        lines.push('');
        lines.push('| Tactic | Tested | Techniques | Passed | Failed |');
        lines.push('|--------|--------|------------|--------|--------|');
        for (const [tactic, data] of Object.entries(s.atlasBreakdown)) {
            const icon = data.tested ? '✅' : '⬜';
            lines.push(`| ${tactic} | ${icon} | ${data.techniquesCovered} | ${data.passed} | ${data.failed} |`);
        }
        lines.push('');

        // Defense Module Effectiveness
        lines.push('## Defense Module Effectiveness');
        lines.push('');
        lines.push('| Module | Attacks Blocked | Attacks Bypassed | Effectiveness |');
        lines.push('|--------|----------------|------------------|---------------|');
        for (const [mod, data] of Object.entries(s.defenseBreakdown)) {
            const bar = this.effectivenessBar(data.effectiveness);
            lines.push(`| ${mod} | ${data.attacksBlocked} | ${data.attacksByPassed} | ${bar} ${data.effectiveness}% |`);
        }
        lines.push('');

        // Top Findings
        if (s.topFindings.length > 0) {
            lines.push('## 🚨 Critical Findings');
            lines.push('');
            for (let i = 0; i < s.topFindings.length; i++) {
                const f = s.topFindings[i];
                lines.push(`### ${i + 1}. ${f.technique.name}`);
                lines.push('');
                lines.push(`- **Severity:** ${this.severityBadge(f.severity)}`);
                lines.push(`- **OWASP:** ${f.complianceMapping.owaspLlm.join(', ')}`);
                lines.push(`- **ATLAS:** ${f.complianceMapping.mitreAtlas.join(', ')}`);
                lines.push(`- **Defense Module:** ${f.defenseModule}`);
                lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
                lines.push('');
                lines.push(`**Analysis:** ${f.evidence.analysis}`);
                lines.push('');
                lines.push(`**Remediation:** ${f.remediation}`);
                lines.push('');
                lines.push('<details>');
                lines.push('<summary>Evidence</summary>');
                lines.push('');
                lines.push('**Request:**');
                lines.push('```');
                lines.push(f.evidence.request.substring(0, 500));
                lines.push('```');
                lines.push('');
                lines.push('**Response:**');
                lines.push('```');
                lines.push(f.evidence.response.substring(0, 500));
                lines.push('```');
                lines.push('</details>');
                lines.push('');
            }
        }

        // Remediation Priority
        if (report.remediationPriority.length > 0) {
            lines.push('## Remediation Roadmap');
            lines.push('');
            lines.push('| Priority | Finding | Severity | Effort | Remediation |');
            lines.push('|----------|---------|----------|--------|-------------|');
            for (const r of report.remediationPriority) {
                lines.push(`| ${r.rank} | ${r.finding} | ${this.severityBadge(r.severity)} | ${r.effort} | ${r.remediation.substring(0, 100)} |`);
            }
            lines.push('');
        }

        // Compliance Section
        lines.push('## Compliance Evidence');
        lines.push('');
        lines.push(`**OWASP LLM Top 10 Coverage:** ${c.metrics.owaspCoverage}%`);
        lines.push(`**MITRE ATLAS Coverage:** ${c.metrics.atlasCoverage}%`);
        lines.push('');

        // Footer
        lines.push('---');
        lines.push(`*Report generated by Gideon Red Team Engine v1.0.0*`);

        return lines.join('\n');
    }

    /**
     * Generate SARIF format for tool integration
     */
    toSarif(report: RedTeamReport): Record<string, unknown> {
        return {
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            version: '2.1.0',
            runs: [{
                tool: {
                    driver: {
                        name: 'Gideon Red Team Engine',
                        version: '1.0.0',
                        informationUri: 'https://github.com/cogensec/gideon',
                        rules: report.findings.map(f => ({
                            id: f.technique.id,
                            name: f.technique.name,
                            shortDescription: { text: f.technique.description },
                            defaultConfiguration: { level: this.severityToSarif(f.severity) },
                            properties: {
                                'owasp-llm': f.complianceMapping.owaspLlm,
                                'mitre-atlas': f.complianceMapping.mitreAtlas,
                            },
                        })),
                    },
                },
                results: report.findings.map(f => ({
                    ruleId: f.technique.id,
                    message: { text: f.evidence.analysis },
                    level: this.severityToSarif(f.severity),
                    locations: [{ physicalLocation: { artifactLocation: { uri: report.campaign.scope.target } } }],
                    properties: {
                        defenseModule: f.defenseModule,
                        confidence: f.confidence,
                        remediation: f.remediation,
                    },
                })),
            }],
        };
    }

    // ============================================================================
    // Private Helpers
    // ============================================================================

    private generateExecutiveSummary(campaign: Campaign, scoring: ScoringResult): string {
        const m = campaign.metrics;
        const failed = scoring.topFindings;

        let summary = `This red team assessment tested ${m.totalTechniques} attack techniques across ${campaign.scope.suites.length} attack suites against the target \`${campaign.scope.target}\`. `;

        if (m.failed === 0) {
            summary += `**All defenses held.** No attack techniques successfully bypassed the defensive controls. `;
            summary += `The overall risk score is **${scoring.overallRiskScore}/100 (Grade: ${scoring.grade})**.`;
        } else {
            summary += `**${m.failed} attack(s) bypassed defenses**, with ${failed.filter(f => f.severity === 'critical').length} critical findings. `;
            summary += `The overall risk score is **${scoring.overallRiskScore}/100 (Grade: ${scoring.grade})**. `;
            summary += `Immediate remediation is recommended for critical findings.`;
        }

        return summary;
    }

    private generateComplianceSection(campaign: Campaign): RedTeamReport['compliance'] {
        const testedOwasp = new Set(campaign.results.flatMap(r => r.complianceMapping.owaspLlm));
        const testedAtlas = new Set(campaign.results.map(r => r.technique.atlasTechnique));
        const allOwasp = ['LLM01:2025', 'LLM02:2025', 'LLM03:2025', 'LLM04:2025', 'LLM05:2025', 'LLM06:2025', 'LLM07:2025', 'LLM08:2025', 'LLM09:2025', 'LLM10:2025'] as const;
        const allAtlas = ['AML.T0051', 'AML.T0054', 'AML.T0053', 'AML.T0046', 'AML.T0020', 'AML.T0042', 'AML.T0043', 'AML.T0044', 'AML.T0048', 'AML.T0049', 'AML.T0050', 'AML.T0052', 'AML.T0055', 'AML.T0056', 'AML.T0057'] as const;

        return {
            owaspLlm: {
                covered: [...testedOwasp] as any[],
                notCovered: allOwasp.filter(r => !testedOwasp.has(r)) as any[],
            },
            mitreAtlas: {
                covered: [...testedAtlas] as any[],
                notCovered: allAtlas.filter(t => !testedAtlas.has(t)) as any[],
            },
        };
    }

    private generateRemediationPriority(results: AttackResult[]): RedTeamReport['remediationPriority'] {
        const severityOrder: Record<AttackSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

        return results
            .filter(r => !r.defenseHeld)
            .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
            .map((r, i) => ({
                rank: i + 1,
                finding: r.technique.name,
                severity: r.severity,
                remediation: r.remediation,
                effort: r.severity === 'critical' ? 'high' as const : r.severity === 'high' ? 'medium' as const : 'low' as const,
            }));
    }

    private riskBadge(level: string): string {
        const badges: Record<string, string> = {
            critical: '🔴 CRITICAL', high: '🟠 HIGH', medium: '🟡 MEDIUM',
            low: '🟢 LOW', none: '⚪ NONE',
        };
        return badges[level] || level;
    }

    private severityBadge(severity: AttackSeverity): string {
        const badges: Record<AttackSeverity, string> = {
            critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium',
            low: '🟢 Low', info: 'ℹ️ Info',
        };
        return badges[severity];
    }

    private effectivenessBar(pct: number): string {
        const filled = Math.round(pct / 10);
        return '█'.repeat(filled) + '░'.repeat(10 - filled);
    }

    private formatDuration(ms: number): string {
        if (ms < 1000) return `${ms}ms`;
        if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
        return `${(ms / 60000).toFixed(1)}m`;
    }

    private severityToSarif(severity: AttackSeverity): string {
        const map: Record<AttackSeverity, string> = {
            critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'none',
        };
        return map[severity];
    }
}
