/**
 * Red Team Command Handler
 *
 * CLI interface for Gideon's red teaming capabilities.
 * Manages attack campaigns against AI systems with enterprise reporting.
 *
 * Usage:
 *   redteam <target>                              - Run full assessment
 *   redteam <target> --suite owasp-llm            - OWASP LLM Top 10 suite
 *   redteam <target> --attack prompt-injection     - Specific attack suite
 *   redteam <target> --technique AML.T0051         - Specific ATLAS technique
 *   redteam <target> --depth deep                  - Assessment depth
 *   redteam <target> --dry-run                     - Plan without executing
 *   redteam <target> --report compliance           - Full compliance report
 *   redteam <target> --validate-defenses           - Validate defensive modules
 */
import { join } from 'path';
import { CommandContext, CommandResult } from './types.js';
import {
    createRedTeamEngine,
    getAvailableModules,
    getTotalTechniqueCount,
} from '../redteam/index.js';
import type { AttackSuite, AttackDepth, ReportFormat } from '../redteam/types.js';

// ============================================================================
// Command Handler
// ============================================================================

export async function handleRedTeamCommand(
    args: string[],
    context: CommandContext,
): Promise<CommandResult> {
    const { target, options, error } = parseArgs(args);

    if (error) {
        return { success: false, output: error, error };
    }

    if (options.help || !target) {
        return showHelp();
    }

    // Initialize engine
    const engine = createRedTeamEngine({
        outputDirectory: options.output || join(process.cwd(), 'outputs', 'redteam'),
        reportFormat: (options.format || 'markdown') as ReportFormat,
        defaultDepth: (options.depth || 'standard') as AttackDepth,
    });

    // Determine suites to run
    let suites: AttackSuite[] | 'full' | 'owasp-llm';
    if (options.suite === 'full') {
        suites = 'full';
    } else if (options.suite === 'owasp-llm') {
        suites = 'owasp-llm';
    } else if (options.attack) {
        suites = [options.attack as AttackSuite];
    } else {
        suites = 'full';
    }

    try {
        // Create campaign
        const campaign = engine.campaignManager.createCampaign({
            name: `Red Team Assessment - ${new Date().toISOString().slice(0, 10)}`,
            target,
            suites,
            depth: (options.depth || 'standard') as AttackDepth,
            dryRun: options.dryRun || false,
            authorizedBy: 'gideon-cli',
            stopOnCritical: options.stopOnCritical || false,
        });

        // Dry run mode
        if (options.dryRun) {
            const plan = engine.attackRunner.buildDryRunPlan(campaign.scope);
            return {
                success: true,
                output: formatDryRunOutput(plan),
                artifacts: { json: plan },
            };
        }

        // Execute campaign with progress output
        let progressOutput = '';
        engine.attackRunner.onProgressUpdate((event) => {
            progressOutput += `${event.message}\n`;
            // Log progress in real-time
            console.log(`  ${event.message}`);
        });

        console.log(`\n🔴 Starting Red Team Campaign: ${campaign.name}`);
        console.log(`   Target: ${target}`);
        console.log(`   Depth: ${options.depth || 'standard'}`);
        console.log(`   Suites: ${campaign.scope.suites.join(', ')}`);
        console.log('');

        const completedCampaign = await engine.attackRunner.executeCampaign(campaign.id);

        // Generate report
        const report = engine.reportGenerator.generateReport(
            completedCampaign,
            (options.format || 'markdown') as ReportFormat,
        );

        // Save report
        const outputDir = options.output || join(process.cwd(), 'outputs', 'redteam');
        const reportPath = engine.reportGenerator.saveReport(report, outputDir);

        // Generate CLI summary
        const summary = formatCampaignSummary(completedCampaign, report, reportPath);

        return {
            success: true,
            output: summary,
            artifacts: {
                json: report,
                markdown: engine.reportGenerator.toMarkdown(report),
            },
        };
    } catch (err) {
        return {
            success: false,
            output: `Red team campaign failed: ${err}`,
            error: String(err),
        };
    }
}

// ============================================================================
// Argument Parsing
// ============================================================================

function parseArgs(args: string[]): {
    target: string | null;
    options: Record<string, any>;
    error?: string;
} {
    const options: Record<string, any> = {};
    let target: string | null = null;

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            const nextArg = args[i + 1];

            switch (key) {
                case 'suite':
                    if (!nextArg || !['full', 'owasp-llm'].includes(nextArg)) {
                        return { target: null, options, error: 'Invalid suite. Use: full, owasp-llm' };
                    }
                    options.suite = nextArg;
                    i++;
                    break;

                case 'attack':
                    const validAttacks = [
                        'prompt-injection', 'credential-extraction', 'guardrail-bypass',
                        'agent-hijacking', 'excessive-agency', 'supply-chain',
                        'data-exfiltration', 'system-prompt-leakage', 'resource-exhaustion',
                    ];
                    if (!nextArg || !validAttacks.includes(nextArg)) {
                        return { target: null, options, error: `Invalid attack. Use: ${validAttacks.join(', ')}` };
                    }
                    options.attack = nextArg;
                    i++;
                    break;

                case 'technique':
                    options.technique = nextArg;
                    i++;
                    break;

                case 'depth':
                    if (!nextArg || !['quick', 'standard', 'deep', 'exhaustive'].includes(nextArg)) {
                        return { target: null, options, error: 'Invalid depth. Use: quick, standard, deep, exhaustive' };
                    }
                    options.depth = nextArg;
                    i++;
                    break;

                case 'output':
                    options.output = nextArg;
                    i++;
                    break;

                case 'format':
                    if (!nextArg || !['markdown', 'json', 'sarif'].includes(nextArg)) {
                        return { target: null, options, error: 'Invalid format. Use: markdown, json, sarif' };
                    }
                    options.format = nextArg;
                    i++;
                    break;

                case 'dry-run':
                    options.dryRun = true;
                    break;

                case 'validate-defenses':
                    options.validateDefenses = true;
                    break;

                case 'stop-on-critical':
                    options.stopOnCritical = true;
                    break;

                case 'help':
                    options.help = true;
                    break;

                default:
                    break;
            }
        } else if (!target) {
            target = arg;
        }
    }

    return { target, options };
}

// ============================================================================
// Output Formatting
// ============================================================================

function formatDryRunOutput(plan: any): string {
    let output = `\n${'═'.repeat(70)}\n`;
    output += `  🔴 RED TEAM DRY RUN - Attack Plan\n`;
    output += `${'═'.repeat(70)}\n\n`;

    output += `Target:     ${plan.target} (${plan.targetType})\n`;
    output += `Depth:      ${plan.depth}\n`;
    output += `Payloads:   ${plan.totalPayloads}\n`;
    output += `Est. Time:  ~${plan.estimatedDurationMinutes} minutes\n\n`;

    for (const suite of plan.suites) {
        output += `${'─'.repeat(60)}\n`;
        output += `📋 ${suite.name} (${suite.techniqueCount} techniques)\n`;
        output += `   ${suite.description.substring(0, 80)}...\n\n`;

        for (const tech of suite.techniques) {
            const severityIcon = ({ critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' } as Record<string, string>)[tech.severity] || '⚪';
            output += `   ${severityIcon} ${tech.name}\n`;
            output += `      ATLAS: ${tech.atlas} | OWASP: ${tech.owasp.join(', ')}\n`;
            output += `      Tests: ${tech.defenseModule}\n\n`;
        }
    }

    output += `${'═'.repeat(70)}\n`;
    output += `Run without --dry-run to execute this campaign.\n`;

    return output;
}

function formatCampaignSummary(campaign: any, report: any, reportPath: string): string {
    const m = campaign.metrics;
    const s = report.scoring;

    let output = `\n${'═'.repeat(70)}\n`;
    output += `  🔴 RED TEAM ASSESSMENT COMPLETE\n`;
    output += `${'═'.repeat(70)}\n\n`;

    // Risk score with visual bar
    const riskBar = '█'.repeat(Math.round(s.overallRiskScore / 10)) + '░'.repeat(10 - Math.round(s.overallRiskScore / 10));
    output += `  Risk Score: ${riskBar} ${s.overallRiskScore}/100 (Grade: ${s.grade})\n`;
    output += `  Risk Level: ${s.riskLevel.toUpperCase()}\n\n`;

    // Summary stats
    output += `  Techniques Tested:  ${m.completedTechniques}\n`;
    output += `  ✅ Defenses Held:   ${m.passed}\n`;
    output += `  ❌ Defenses Bypassed: ${m.failed}\n`;
    output += `  ⚠️  Errors:          ${m.errors}\n`;
    output += `  Duration:           ${m.durationMs < 60000 ? `${(m.durationMs / 1000).toFixed(1)}s` : `${(m.durationMs / 60000).toFixed(1)}m`}\n\n`;

    // Coverage
    output += `  OWASP LLM Coverage: ${m.owaspCoverage}%\n`;
    output += `  MITRE ATLAS Coverage: ${m.atlasCoverage}%\n\n`;

    // Top findings
    if (s.topFindings.length > 0) {
        output += `${'─'.repeat(60)}\n`;
        output += `  🚨 CRITICAL FINDINGS\n\n`;

        for (let i = 0; i < Math.min(s.topFindings.length, 5); i++) {
            const f = s.topFindings[i];
            const icon = ({ critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' } as Record<string, string>)[f.severity] || '⚪';
            output += `  ${i + 1}. ${icon} ${f.technique.name}\n`;
            output += `     ${f.evidence.analysis.substring(0, 80)}\n\n`;
        }
    }

    // Report location
    output += `${'─'.repeat(60)}\n`;
    output += `  📄 Full report: ${reportPath}\n`;
    output += `${'═'.repeat(70)}\n`;

    return output;
}

// ============================================================================
// Help
// ============================================================================

function showHelp(): CommandResult {
    const modules = getAvailableModules();
    const totalTechniques = getTotalTechniqueCount();

    const output = `
# 🔴 Gideon Red Team Engine

Enterprise-grade AI red teaming with MITRE ATLAS & OWASP LLM Top 10 coverage.

**${modules.length} Attack Suites | ${totalTechniques} Techniques**

## Usage

\`\`\`
redteam <target-url> [options]
\`\`\`

## Options

| Option | Description |
|--------|-------------|
| \`--suite <name>\` | Attack suite: full, owasp-llm |
| \`--attack <name>\` | Specific attack module |
| \`--depth <level>\` | Depth: quick, standard, deep, exhaustive |
| \`--format <fmt>\` | Report: markdown, json, sarif |
| \`--output <dir>\` | Output directory |
| \`--dry-run\` | Show plan without executing |
| \`--stop-on-critical\` | Stop on first critical finding |
| \`--validate-defenses\` | Test against Gideon's defensive modules |
| \`--help\` | Show this help message |

## Attack Modules

${modules.map(m => `| \`${m.suite}\` | ${m.name} (${m.techniqueCount} techniques) |`).join('\n')}

## Examples

\`\`\`bash
# Full assessment
redteam http://localhost:3000/api/chat

# OWASP LLM Top 10 assessment
redteam http://localhost:3000/api/chat --suite owasp-llm

# Quick prompt injection test
redteam http://localhost:3000/api/chat --attack prompt-injection --depth quick

# Dry run (plan only)
redteam http://localhost:3000/api/chat --suite full --dry-run

# Deep assessment with SARIF output
redteam https://agent.example.com/api --depth deep --format sarif
\`\`\`

## Compliance Mapping

- **MITRE ATLAS**: Adversarial ML Threat Matrix technique coverage
- **OWASP LLM Top 10 (2025)**: Full risk coverage
- **NIST AI RMF**: Risk management framework alignment
- **SARIF**: GitHub Code Scanning compatible output
`;

    return { success: true, output };
}
