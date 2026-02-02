import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { ScanResult, SecurityReport, Vulnerability, Severity } from './types';

/**
 * Security Report Generator
 *
 * Generates comprehensive security reports in multiple formats:
 * - Markdown: Human-readable detailed report
 * - JSON: Machine-readable structured data
 * - SARIF: Static Analysis Results Interchange Format (GitHub compatible)
 */
export class ReportGenerator {
  private result: ScanResult;
  private outputDir: string;

  constructor(result: ScanResult, outputDir?: string) {
    this.result = result;
    this.outputDir = outputDir || join(process.cwd(), 'outputs', this.getTimestamp());
  }

  private getTimestamp(): string {
    return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  }

  /**
   * Generate all report formats
   */
  async generateAll(): Promise<{ markdown: string; json: string; sarif?: string }> {
    // Ensure output directory exists
    if (!existsSync(this.outputDir)) {
      mkdirSync(this.outputDir, { recursive: true });
    }

    const markdown = this.generateMarkdown();
    const json = this.generateJSON();
    const sarif = this.generateSARIF();

    // Write files
    writeFileSync(join(this.outputDir, 'security-report.md'), markdown);
    writeFileSync(join(this.outputDir, 'security-report.json'), json);
    writeFileSync(join(this.outputDir, 'security-report.sarif'), sarif);

    return {
      markdown: join(this.outputDir, 'security-report.md'),
      json: join(this.outputDir, 'security-report.json'),
      sarif: join(this.outputDir, 'security-report.sarif'),
    };
  }

  /**
   * Generate detailed Markdown report
   */
  generateMarkdown(): string {
    const { stats, vulnerabilities, summary } = this.result;
    const severityEmoji: Record<Severity, string> = {
      critical: '[CRITICAL]',
      high: '[HIGH]',
      medium: '[MEDIUM]',
      low: '[LOW]',
      informational: '[INFO]',
    };

    let md = `# Gideon Security Scan Report

**Generated:** ${new Date(this.result.timestamp).toLocaleString()}
**Target:** ${this.result.config.targetPath}
**Scan ID:** ${this.result.id}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Overall Risk Score** | ${summary.riskScore}/100 (${summary.riskLevel.toUpperCase()}) |
| **Files Scanned** | ${stats.filesScanned.toLocaleString()} |
| **Lines Analyzed** | ${stats.linesScanned.toLocaleString()} |
| **Scan Duration** | ${(stats.duration / 1000).toFixed(2)}s |
| **Total Vulnerabilities** | ${stats.vulnerabilitiesFound} |

### Severity Breakdown

| Severity | Count |
|----------|-------|
| ${severityEmoji.critical} Critical | ${stats.bySeverity.critical} |
| ${severityEmoji.high} High | ${stats.bySeverity.high} |
| ${severityEmoji.medium} Medium | ${stats.bySeverity.medium} |
| ${severityEmoji.low} Low | ${stats.bySeverity.low} |
| ${severityEmoji.informational} Info | ${stats.bySeverity.informational} |

`;

    // Top Issues
    if (summary.topIssues.length > 0) {
      md += `### Top Security Issues\n\n`;
      for (const issue of summary.topIssues) {
        md += `- ${issue}\n`;
      }
      md += '\n';
    }

    // Recommendations
    if (summary.recommendations.length > 0) {
      md += `### Immediate Recommendations\n\n`;
      for (const rec of summary.recommendations) {
        md += `- ${rec}\n`;
      }
      md += '\n';
    }

    // Compliance Gaps
    if (summary.complianceGaps && summary.complianceGaps.length > 0) {
      md += `### Potential Compliance Gaps\n\n`;
      for (const gap of summary.complianceGaps) {
        md += `- ${gap}\n`;
      }
      md += '\n';
    }

    md += `---

## Detailed Findings

`;

    // Group by severity
    const grouped = this.groupBySeverity(vulnerabilities);

    for (const severity of ['critical', 'high', 'medium', 'low', 'informational'] as Severity[]) {
      const vulns = grouped[severity];
      if (!vulns || vulns.length === 0) continue;

      md += `### ${severityEmoji[severity]} ${severity.charAt(0).toUpperCase() + severity.slice(1)} Severity (${vulns.length})\n\n`;

      for (let i = 0; i < vulns.length; i++) {
        const v = vulns[i];
        md += this.formatVulnerability(v, i + 1);
      }
    }

    // Remediation Plan
    md += `---

## Remediation Plan

| Priority | Issue | Effort | Action |
|----------|-------|--------|--------|
`;

    let priority = 1;
    for (const v of vulnerabilities.filter((v) => v.severity === 'critical' || v.severity === 'high')) {
      const effort = v.fix?.breakingChange ? 'High' : 'Medium';
      md += `| ${priority++} | ${v.name} | ${effort} | ${v.recommendation.slice(0, 50)}... |\n`;
      if (priority > 10) break;
    }

    // Appendix
    md += `
---

## Appendix

### Scan Configuration

\`\`\`json
${JSON.stringify(this.result.config, null, 2)}
\`\`\`

### References

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Secure Coding Guidelines](https://www.nist.gov/programs-projects/secure-software-development-framework-ssdf)

---

*Report generated by Gideon Security Scanner*
`;

    return md;
  }

  /**
   * Format a single vulnerability for markdown
   */
  private formatVulnerability(v: Vulnerability, index: number): string {
    let md = `#### ${index}. ${v.name}

**File:** \`${v.location.file}:${v.location.startLine}\`
**Confidence:** ${v.confidence}
**CWE:** ${v.cwe.join(', ') || 'N/A'}
**OWASP:** ${v.owasp.join(', ') || 'N/A'}

**Description:**
${v.description}

**Impact:**
${v.impact}

**Vulnerable Code:**
\`\`\`
${v.location.snippet}
\`\`\`

`;

    if (v.location.context && v.location.context.length > 0) {
      md += `**Context:**
\`\`\`
${v.location.context.join('\n')}
\`\`\`

`;
    }

    md += `**Recommendation:**
${v.recommendation}

`;

    if (v.fix) {
      md += `**Suggested Fix:**

*${v.fix.description}*

Before:
\`\`\`
${v.fix.originalCode}
\`\`\`

After:
\`\`\`
${v.fix.fixedCode}
\`\`\`

${v.fix.explanation}

${v.fix.breakingChange ? '⚠️ **Warning:** This fix may introduce breaking changes.' : ''}

`;
    }

    if (v.references.length > 0) {
      md += `**References:**\n`;
      for (const ref of v.references) {
        md += `- ${ref}\n`;
      }
      md += '\n';
    }

    md += `---\n\n`;
    return md;
  }

  /**
   * Group vulnerabilities by severity
   */
  private groupBySeverity(vulns: Vulnerability[]): Record<Severity, Vulnerability[]> {
    const grouped: Record<Severity, Vulnerability[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      informational: [],
    };

    for (const v of vulns) {
      grouped[v.severity].push(v);
    }

    return grouped;
  }

  /**
   * Generate JSON report
   */
  generateJSON(): string {
    const report: SecurityReport = {
      metadata: {
        generatedAt: new Date().toISOString(),
        scanId: this.result.id,
        targetPath: this.result.config.targetPath,
        gideonVersion: '1.0.0',
      },
      executiveSummary: {
        overallRisk: this.result.summary.riskLevel,
        criticalFindings: this.result.stats.bySeverity.critical,
        highFindings: this.result.stats.bySeverity.high,
        mediumFindings: this.result.stats.bySeverity.medium,
        lowFindings: this.result.stats.bySeverity.low,
        topVulnerabilities: this.result.summary.topIssues,
        immediateActions: this.result.summary.recommendations,
      },
      findings: this.result.vulnerabilities.map((v) => ({
        id: v.id,
        title: v.name,
        severity: v.severity,
        category: v.category,
        location: `${v.location.file}:${v.location.startLine}`,
        description: v.description,
        impact: v.impact,
        recommendation: v.recommendation,
        cweReference: v.cwe.join(', '),
        owaspReference: v.owasp.join(', '),
        codeSnippet: v.location.snippet,
        proposedFix: v.fix?.fixedCode,
      })),
      technicalDetails: {
        filesAnalyzed: [], // Would need to track this
        languagesDetected: [], // Would need to track this
        scanDuration: `${(this.result.stats.duration / 1000).toFixed(2)}s`,
        patternsChecked: 0, // Would need to track this
      },
      remediationPlan: this.generateRemediationPlan(),
    };

    return JSON.stringify(report, null, 2);
  }

  /**
   * Generate prioritized remediation plan
   */
  private generateRemediationPlan(): SecurityReport['remediationPlan'] {
    const plan: SecurityReport['remediationPlan'] = [];
    const seen = new Set<string>();

    let priority = 1;
    for (const v of this.result.vulnerabilities) {
      // Deduplicate by pattern
      if (seen.has(v.patternId)) continue;
      seen.add(v.patternId);

      const effort = v.severity === 'critical' || v.fix?.breakingChange ? 'high' :
                     v.severity === 'high' ? 'medium' : 'low';

      plan.push({
        priority: priority++,
        issue: v.name,
        effort: effort as 'low' | 'medium' | 'high',
        recommendation: v.recommendation,
      });

      if (priority > 20) break;
    }

    return plan;
  }

  /**
   * Generate SARIF format (GitHub compatible)
   */
  generateSARIF(): string {
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Gideon Security Scanner',
              version: '1.0.0',
              informationUri: 'https://github.com/gideon-security/gideon',
              rules: this.getSARIFRules(),
            },
          },
          results: this.result.vulnerabilities.map((v) => ({
            ruleId: v.patternId,
            level: this.getSARIFLevel(v.severity),
            message: {
              text: `${v.name}: ${v.description}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: v.location.file,
                  },
                  region: {
                    startLine: v.location.startLine,
                    endLine: v.location.endLine,
                    snippet: {
                      text: v.location.snippet,
                    },
                  },
                },
              },
            ],
            fixes: v.fix ? [
              {
                description: {
                  text: v.fix.description,
                },
                artifactChanges: [
                  {
                    artifactLocation: {
                      uri: v.location.file,
                    },
                    replacements: [
                      {
                        deletedRegion: {
                          startLine: v.location.startLine,
                          endLine: v.location.endLine,
                        },
                        insertedContent: {
                          text: v.fix.fixedCode,
                        },
                      },
                    ],
                  },
                ],
              },
            ] : undefined,
          })),
        },
      ],
    };

    return JSON.stringify(sarif, null, 2);
  }

  /**
   * Get SARIF rules from findings
   */
  private getSARIFRules(): any[] {
    const rules = new Map<string, any>();

    for (const v of this.result.vulnerabilities) {
      if (rules.has(v.patternId)) continue;

      rules.set(v.patternId, {
        id: v.patternId,
        name: v.name,
        shortDescription: {
          text: v.name,
        },
        fullDescription: {
          text: v.description,
        },
        helpUri: v.references[0] || '',
        properties: {
          category: v.category,
          cwe: v.cwe,
          owasp: v.owasp,
        },
      });
    }

    return Array.from(rules.values());
  }

  /**
   * Convert severity to SARIF level
   */
  private getSARIFLevel(severity: Severity): string {
    const mapping: Record<Severity, string> = {
      critical: 'error',
      high: 'error',
      medium: 'warning',
      low: 'note',
      informational: 'note',
    };
    return mapping[severity];
  }

  /**
   * Generate a concise summary for CLI output
   */
  generateCLISummary(): string {
    const { stats, summary } = this.result;
    const severityColors: Record<Severity, string> = {
      critical: '\x1b[31m', // Red
      high: '\x1b[33m',     // Yellow
      medium: '\x1b[36m',   // Cyan
      low: '\x1b[32m',      // Green
      informational: '\x1b[37m', // White
    };
    const reset = '\x1b[0m';

    let output = `
╔══════════════════════════════════════════════════════════════════╗
║                 GIDEON SECURITY SCAN RESULTS                     ║
╠══════════════════════════════════════════════════════════════════╣
║ Target: ${this.result.config.targetPath.slice(0, 50).padEnd(55)}║
║ Risk Score: ${summary.riskScore}/100 (${summary.riskLevel.toUpperCase()})${' '.repeat(45 - summary.riskLevel.length)}║
╠══════════════════════════════════════════════════════════════════╣
║ Files Scanned: ${stats.filesScanned.toString().padEnd(10)} Lines Analyzed: ${stats.linesScanned.toString().padEnd(15)}║
║ Duration: ${(stats.duration / 1000).toFixed(2)}s${' '.repeat(52 - (stats.duration / 1000).toFixed(2).length)}║
╠══════════════════════════════════════════════════════════════════╣
║ FINDINGS:                                                        ║
║   Critical: ${stats.bySeverity.critical.toString().padEnd(5)} High: ${stats.bySeverity.high.toString().padEnd(5)} Medium: ${stats.bySeverity.medium.toString().padEnd(5)} Low: ${stats.bySeverity.low.toString().padEnd(5)}        ║
╚══════════════════════════════════════════════════════════════════╝
`;

    // Top findings
    if (this.result.vulnerabilities.length > 0) {
      output += '\nTop Findings:\n';
      const topFindings = this.result.vulnerabilities.slice(0, 5);
      for (const v of topFindings) {
        const color = severityColors[v.severity];
        output += `  ${color}[${v.severity.toUpperCase()}]${reset} ${v.name}\n`;
        output += `          ${v.location.file}:${v.location.startLine}\n`;
      }
    }

    if (summary.recommendations.length > 0) {
      output += '\nRecommendations:\n';
      for (const rec of summary.recommendations.slice(0, 3)) {
        output += `  - ${rec}\n`;
      }
    }

    return output;
  }
}

/**
 * Quick report generation helper
 */
export async function generateReport(
  result: ScanResult,
  outputDir?: string
): Promise<{ markdown: string; json: string; sarif?: string }> {
  const generator = new ReportGenerator(result, outputDir);
  return generator.generateAll();
}
