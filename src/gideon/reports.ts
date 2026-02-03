import { v4 as uuidv4 } from 'uuid';
import {
  Finding,
  SeverityLevel,
  VulnerabilityClass,
  AttackChain,
  GideonSession,
  ReconSummary,
} from './types';

// ============================================================================
// Finding Report Templates
// ============================================================================

/**
 * Generate a finding report template
 */
export function generateFindingTemplate(severity: SeverityLevel): string {
  return `## [${severity.toUpperCase()}] Title of Vulnerability

**Program:** [Program Name]
**Asset:** [Affected URL/Endpoint]
**Vulnerability Type:** [CWE-XXX: Name]
**CVSS Score:** [X.X] (Vector String)

### Summary
[2-3 sentence description of the vulnerability and its impact]

### Technical Details
[Detailed explanation of the vulnerability mechanism]

### Steps to Reproduce
1. Navigate to [URL]
2. [Step 2]
3. [Step 3]
4. Observe [vulnerability behavior]

### Proof of Concept

**Request:**
\`\`\`http
[HTTP request here]
\`\`\`

**Response:**
\`\`\`http
[HTTP response excerpt showing vulnerability]
\`\`\`

### Impact
[Business impact assessment - what can an attacker do?]

### Remediation
[Specific fix recommendations with code examples if applicable]

### References
- [CWE Reference]
- [OWASP Reference]
- [Relevant documentation/articles]
`;
}

/**
 * Format a finding as markdown
 */
export function formatFindingMarkdown(finding: Finding): string {
  let md = `## [${finding.severity.toUpperCase()}] ${finding.title}\n\n`;

  md += `**ID:** ${finding.id}\n`;
  md += `**Asset:** ${finding.asset}\n`;
  if (finding.endpoint) md += `**Endpoint:** ${finding.endpoint}\n`;
  if (finding.parameter) md += `**Parameter:** ${finding.parameter}\n`;
  md += `**Vulnerability Type:** ${finding.cwe.join(', ')}: ${finding.vulnerabilityClass}\n`;

  if (finding.cvss) {
    md += `**CVSS Score:** ${finding.cvss.score} (${finding.cvss.vector})\n`;
  }

  md += `\n### Summary\n${finding.summary}\n`;
  md += `\n### Technical Details\n${finding.technicalDetails}\n`;

  md += `\n### Steps to Reproduce\n`;
  finding.stepsToReproduce.forEach((step, i) => {
    md += `${i + 1}. ${step}\n`;
  });

  md += `\n### Proof of Concept\n`;
  md += `**Type:** ${finding.proofOfConcept.type}\n`;
  md += `\`\`\`\n${finding.proofOfConcept.content}\n\`\`\`\n`;

  md += `\n### Impact\n${finding.impact}\n`;
  md += `\n### Remediation\n${finding.remediation}\n`;

  if (finding.references.length > 0) {
    md += `\n### References\n`;
    finding.references.forEach(ref => {
      md += `- ${ref}\n`;
    });
  }

  if (finding.evidence.length > 0) {
    md += `\n### Evidence\n`;
    finding.evidence.forEach((e, i) => {
      md += `\n**Evidence ${i + 1}** (${e.type}) - ${e.timestamp}\n`;
      if (e.filename) md += `File: ${e.filename}\n`;
      md += `\`\`\`\n${e.content.slice(0, 500)}${e.content.length > 500 ? '...' : ''}\n\`\`\`\n`;
    });
  }

  return md;
}

/**
 * Create a new finding object
 */
export function createFinding(params: {
  title: string;
  severity: SeverityLevel;
  vulnerabilityClass: VulnerabilityClass;
  asset: string;
  summary: string;
  technicalDetails: string;
  stepsToReproduce: string[];
  proofOfConcept: { type: 'curl' | 'code' | 'burp' | 'screenshot' | 'video'; content: string };
  impact: string;
  remediation: string;
  cwe?: string[];
  owasp?: string[];
  endpoint?: string;
  parameter?: string;
  cvss?: { score: number; vector: string };
  references?: string[];
}): Finding {
  return {
    id: uuidv4(),
    title: params.title,
    severity: params.severity,
    vulnerabilityClass: params.vulnerabilityClass,
    cwe: params.cwe || getCWEForVulnClass(params.vulnerabilityClass),
    owasp: params.owasp || [],
    asset: params.asset,
    endpoint: params.endpoint,
    parameter: params.parameter,
    summary: params.summary,
    technicalDetails: params.technicalDetails,
    stepsToReproduce: params.stepsToReproduce,
    proofOfConcept: params.proofOfConcept,
    impact: params.impact,
    cvss: params.cvss,
    remediation: params.remediation,
    references: params.references || [],
    evidence: [],
    discoveredAt: new Date().toISOString(),
    status: 'discovered',
  };
}

/**
 * Get CWE IDs for vulnerability class
 */
function getCWEForVulnClass(vulnClass: VulnerabilityClass): string[] {
  const cweMap: Record<VulnerabilityClass, string[]> = {
    sqli: ['CWE-89'],
    nosqli: ['CWE-943'],
    cmdi: ['CWE-78'],
    ldapi: ['CWE-90'],
    xpathi: ['CWE-643'],
    ssti: ['CWE-1336'],
    graphql_injection: ['CWE-89', 'CWE-943'],
    auth_bypass: ['CWE-287'],
    session_fixation: ['CWE-384'],
    session_hijacking: ['CWE-384'],
    jwt_vuln: ['CWE-347'],
    oauth_misconfig: ['CWE-287'],
    password_reset: ['CWE-640'],
    mfa_bypass: ['CWE-287'],
    idor: ['CWE-639'],
    privilege_escalation: ['CWE-269'],
    path_traversal: ['CWE-22'],
    lfi: ['CWE-98'],
    rfi: ['CWE-98'],
    xss_reflected: ['CWE-79'],
    xss_stored: ['CWE-79'],
    xss_dom: ['CWE-79'],
    csrf: ['CWE-352'],
    clickjacking: ['CWE-1021'],
    postmessage: ['CWE-345'],
    websocket: ['CWE-1385'],
    cors: ['CWE-942'],
    race_condition: ['CWE-362'],
    price_manipulation: ['CWE-472'],
    workflow_bypass: ['CWE-841'],
    rate_limit_bypass: ['CWE-770'],
    mass_assignment: ['CWE-915'],
    api_auth: ['CWE-287'],
    graphql_dos: ['CWE-400'],
    api_versioning: ['CWE-288'],
    undocumented_endpoint: ['CWE-912'],
    ssrf: ['CWE-918'],
    cloud_misconfig: ['CWE-16'],
    k8s_misconfig: ['CWE-16'],
    container_escape: ['CWE-1008'],
    prototype_pollution: ['CWE-1321'],
    deserialization: ['CWE-502'],
    cache_poisoning: ['CWE-444'],
    request_smuggling: ['CWE-444'],
    subdomain_takeover: ['CWE-284'],
  };

  return cweMap[vulnClass] || [];
}

// ============================================================================
// Recon Summary Report
// ============================================================================

/**
 * Generate reconnaissance summary template
 */
export function generateReconSummaryTemplate(target: string): string {
  return `## Reconnaissance Summary: ${target}

### Scope Confirmed
- **Domains:** [list in-scope domains]
- **IPs:** [IP ranges if applicable]
- **Exclusions:** [out-of-scope items]

### Attack Surface Discovery

| Asset | Technology | Status | Interesting Findings |
|-------|------------|--------|---------------------|
| [subdomain] | [tech stack] | [alive/dead] | [notes] |

### Subdomains Found
\`\`\`
[list of discovered subdomains]
\`\`\`

### Open Ports & Services
| IP/Host | Port | Service | Version |
|---------|------|---------|---------|
| [host] | [port] | [service] | [version] |

### Technologies Detected
| Technology | Category | Confidence |
|------------|----------|------------|
| [tech] | [category] | [high/medium/low] |

### Interesting Findings
- [Finding 1]
- [Finding 2]

### Priority Targets
1. **[Target]** - [Reason for priority]
2. **[Target]** - [Reason for priority]

### Next Steps
- [ ] [Recommended testing action 1]
- [ ] [Recommended testing action 2]
`;
}

/**
 * Format recon summary as markdown
 */
export function formatReconSummaryMarkdown(summary: ReconSummary): string {
  let md = `## Reconnaissance Summary: ${summary.target}\n`;
  md += `**Generated:** ${summary.timestamp}\n\n`;

  // Subdomains
  md += `### Subdomains (${summary.subdomains.length} found)\n\n`;
  md += `| Subdomain | Status | Technologies | Notes |\n`;
  md += `|-----------|--------|--------------|-------|\n`;

  for (const sub of summary.subdomains.slice(0, 20)) {
    const status = sub.isAlive ? `${sub.httpStatus || 'alive'}` : 'dead';
    const techs = sub.technologies?.slice(0, 3).join(', ') || '-';
    md += `| ${sub.subdomain} | ${status} | ${techs} | ${sub.notes || '-'} |\n`;
  }

  if (summary.subdomains.length > 20) {
    md += `\n*...and ${summary.subdomains.length - 20} more subdomains*\n`;
  }

  // Technologies
  if (summary.technologies.length > 0) {
    md += `\n### Technologies Detected\n\n`;
    md += `| Technology | Category | Confidence |\n`;
    md += `|------------|----------|------------|\n`;

    for (const tech of summary.technologies) {
      md += `| ${tech.name} ${tech.version || ''} | ${tech.category} | ${tech.confidence}% |\n`;
    }
  }

  // Ports
  if (summary.ports.length > 0) {
    md += `\n### Open Ports\n\n`;
    md += `| Host | Port | Service | Version |\n`;
    md += `|------|------|---------|----------|\n`;

    for (const port of summary.ports) {
      md += `| ${port.ip} | ${port.port}/${port.protocol} | ${port.service || '-'} | ${port.version || '-'} |\n`;
    }
  }

  // Interesting findings
  if (summary.interestingFindings.length > 0) {
    md += `\n### Interesting Findings\n\n`;
    for (const finding of summary.interestingFindings) {
      md += `- ${finding}\n`;
    }
  }

  // Priority targets
  if (summary.priorityTargets.length > 0) {
    md += `\n### Priority Targets\n\n`;
    for (let i = 0; i < summary.priorityTargets.length; i++) {
      const target = summary.priorityTargets[i];
      md += `${i + 1}. **${target.asset}** - ${target.reason}\n`;
      md += `   - Suggested tests: ${target.suggestedTests.join(', ')}\n`;
    }
  }

  // Next steps
  if (summary.nextSteps.length > 0) {
    md += `\n### Next Steps\n\n`;
    for (const step of summary.nextSteps) {
      md += `- [ ] ${step}\n`;
    }
  }

  return md;
}

// ============================================================================
// Attack Chain Analysis
// ============================================================================

/**
 * Format attack chain as markdown
 */
export function formatAttackChainMarkdown(chain: AttackChain, findings: Finding[]): string {
  let md = `## Attack Chain: ${chain.name}\n\n`;
  md += `**Combined Severity:** ${chain.combinedSeverity.toUpperCase()}\n\n`;
  md += `### Description\n${chain.description}\n\n`;

  md += `### Attack Steps\n\n`;
  for (const step of chain.steps) {
    const finding = findings.find(f => f.id === step.findingId);
    md += `**Step ${step.order}:** ${step.description}\n`;
    if (finding) {
      md += `- Finding: [${finding.severity.toUpperCase()}] ${finding.title}\n`;
      md += `- Asset: ${finding.asset}\n`;
    }
    if (step.prerequisite) {
      md += `- Prerequisite: ${step.prerequisite}\n`;
    }
    md += '\n';
  }

  md += `### Combined Impact\n${chain.combinedImpact}\n\n`;

  md += `### Attack Narrative\n${chain.attackNarrative}\n`;

  return md;
}

// ============================================================================
// Session Reports
// ============================================================================

/**
 * Generate full engagement report
 */
export function generateEngagementReport(session: GideonSession): string {
  let md = `# Security Engagement Report\n\n`;
  md += `**Session ID:** ${session.id}\n`;
  md += `**Mode:** ${session.mode}\n`;
  md += `**Status:** ${session.status}\n`;
  md += `**Started:** ${session.startedAt}\n\n`;

  // Scope
  if (session.scope) {
    md += `## Scope\n\n`;
    md += `**Program:** ${session.scope.programName}\n`;
    md += `**Platform:** ${session.scope.platform || 'Private'}\n`;
    md += `**Safe Harbor:** ${session.scope.safeHarbor ? 'Yes' : 'No'}\n\n`;

    md += `### In-Scope Assets\n`;
    md += `- Domains: ${session.scope.inScope.domains.join(', ') || 'None'}\n`;
    md += `- Wildcards: ${session.scope.inScope.wildcards.join(', ') || 'None'}\n`;
    md += `- APIs: ${session.scope.inScope.apis.join(', ') || 'None'}\n\n`;
  }

  // Executive Summary
  md += `## Executive Summary\n\n`;
  const criticalCount = session.findings.filter(f => f.severity === 'critical').length;
  const highCount = session.findings.filter(f => f.severity === 'high').length;
  const mediumCount = session.findings.filter(f => f.severity === 'medium').length;
  const lowCount = session.findings.filter(f => f.severity === 'low').length;

  md += `| Severity | Count |\n`;
  md += `|----------|-------|\n`;
  md += `| Critical | ${criticalCount} |\n`;
  md += `| High | ${highCount} |\n`;
  md += `| Medium | ${mediumCount} |\n`;
  md += `| Low | ${lowCount} |\n`;
  md += `| **Total** | **${session.findings.length}** |\n\n`;

  // Findings
  if (session.findings.length > 0) {
    md += `## Detailed Findings\n\n`;

    // Critical first
    for (const severity of ['critical', 'high', 'medium', 'low', 'informational'] as SeverityLevel[]) {
      const severityFindings = session.findings.filter(f => f.severity === severity);
      if (severityFindings.length > 0) {
        md += `### ${severity.charAt(0).toUpperCase() + severity.slice(1)} Severity\n\n`;
        for (const finding of severityFindings) {
          md += formatFindingMarkdown(finding);
          md += '\n---\n\n';
        }
      }
    }
  }

  // Attack Chains
  if (session.attackChains.length > 0) {
    md += `## Attack Chains\n\n`;
    for (const chain of session.attackChains) {
      md += formatAttackChainMarkdown(chain, session.findings);
      md += '\n---\n\n';
    }
  }

  // Recon Summary
  if (session.reconSummary) {
    md += `## Reconnaissance Summary\n\n`;
    md += formatReconSummaryMarkdown(session.reconSummary);
  }

  // Activity Log
  md += `## Activity Log\n\n`;
  md += `| Timestamp | Phase | Action | Details |\n`;
  md += `|-----------|-------|--------|----------|\n`;
  for (const activity of session.activityLog.slice(-50)) {
    md += `| ${activity.timestamp} | ${activity.phase} | ${activity.action} | ${activity.details.slice(0, 50)} |\n`;
  }

  // Notes
  if (session.notes.length > 0) {
    md += `\n## Notes\n\n`;
    for (const note of session.notes) {
      md += `- ${note}\n`;
    }
  }

  return md;
}

/**
 * Generate JSON report for platform submission
 */
export function generateJSONReport(session: GideonSession): object {
  return {
    engagement: {
      id: session.id,
      mode: session.mode,
      status: session.status,
      started: session.startedAt,
      scope: session.scope?.programName,
    },
    summary: {
      totalFindings: session.findings.length,
      bySeverity: {
        critical: session.findings.filter(f => f.severity === 'critical').length,
        high: session.findings.filter(f => f.severity === 'high').length,
        medium: session.findings.filter(f => f.severity === 'medium').length,
        low: session.findings.filter(f => f.severity === 'low').length,
        informational: session.findings.filter(f => f.severity === 'informational').length,
      },
      attackChains: session.attackChains.length,
    },
    findings: session.findings.map(f => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      vulnerabilityClass: f.vulnerabilityClass,
      cwe: f.cwe,
      asset: f.asset,
      endpoint: f.endpoint,
      parameter: f.parameter,
      cvss: f.cvss,
      status: f.status,
      discoveredAt: f.discoveredAt,
    })),
    attackChains: session.attackChains,
  };
}
