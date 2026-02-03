/**
 * Security Research Skill
 *
 * Provides AI-assisted bug bounty hunting, penetration testing,
 * and security research capabilities.
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';

// Import existing gideon functionality
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
  GideonSession,
  GideonMode,
  GideonModeSchema,
  ScopeDefinition,
  SeverityLevel,
  VulnerabilityClass,
  VulnerabilityClassSchema,
  ToolCategory,
  TOOL_CATEGORIES,
} from '../../gideon/index.js';

// Session state (keyed by context session ID)
const sessions = new Map<string, GideonSession>();
let currentSessionId: string | null = null;

// ============================================================================
// Command Implementations
// ============================================================================

async function handleStart(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const modeArg = args[0]?.toLowerCase();

  if (!modeArg) {
    return {
      success: false,
      output: '',
      error: 'Usage: start <mode>\nModes: bounty, pentest, research, ctf',
    };
  }

  const parseResult = GideonModeSchema.safeParse(modeArg);
  if (!parseResult.success) {
    return {
      success: false,
      output: '',
      error: `Invalid mode: ${modeArg}\nValid modes: bounty, pentest, research, ctf`,
    };
  }

  const mode = parseResult.data;
  const session = createSession(mode);
  sessions.set(session.id, session);
  currentSessionId = session.id;

  const modeDescriptions: Record<GideonMode, string> = {
    bounty: 'Bug Bounty Hunting - Focus on finding vulnerabilities with bounty value',
    pentest: 'Penetration Testing - Authorized security assessment',
    research: 'Security Research - Read-only analysis and learning',
    ctf: 'Capture The Flag - Competition-focused challenges',
  };

  return {
    success: true,
    output: `# Security Research Session Started

**Mode:** ${mode}
**Session ID:** ${session.id}
**Description:** ${modeDescriptions[mode]}

## Next Steps
1. Define scope with \`scope <program>\`
2. Run reconnaissance with \`recon <target>\`
3. Hunt vulnerabilities with \`hunt <class>\`

Use \`status\` to check session state.`,
    data: { sessionId: session.id, mode },
  };
}

async function handleScope(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  if (!currentSessionId) {
    return {
      success: false,
      output: '',
      error: 'No active session. Start one with: start <mode>',
    };
  }

  const programName = args[0];
  if (!programName) {
    return {
      success: false,
      output: '',
      error: 'Usage: scope <program-name>\nExample: scope hackerone-example',
    };
  }

  const session = sessions.get(currentSessionId);
  if (!session) {
    return {
      success: false,
      output: '',
      error: 'Session not found',
    };
  }

  // Create basic scope (in practice, this would be loaded from a file or API)
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
      vulnerabilityTypes: ['DoS', 'Social Engineering'],
    },
    rules: {
      allowAutomatedScanning: false,
      requiresVPN: false,
      reportingMethod: 'platform',
      duplicatePolicy: 'first-reporter',
    },
    bountyTable: {},
  };

  setScope(session, scope);
  updateSessionStatus(session, 'recon');

  return {
    success: true,
    output: `# Scope Defined

**Program:** ${programName}
**Status:** Ready for reconnaissance

## Configure Scope
Add targets to scope by providing a scope file or defining them interactively.

**Tip:** Use \`check <target>\` to verify if a target is in scope.`,
    data: { scope },
  };
}

async function handleRecon(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const target = args[0];
  const reconType = args[1] || 'passive';

  if (!target) {
    return {
      success: false,
      output: '',
      error: 'Usage: recon <target> [type]\nTypes: passive, active, subdomain',
    };
  }

  let commands: string[];
  let title: string;

  switch (reconType) {
    case 'passive':
      commands = generatePassiveReconCommands(target);
      title = 'Passive Reconnaissance';
      break;
    case 'active':
      commands = generateActiveReconCommands(target);
      title = 'Active Reconnaissance';
      break;
    case 'subdomain':
      commands = generateSubdomainEnumCommands(target);
      title = 'Subdomain Enumeration';
      break;
    default:
      return {
        success: false,
        output: '',
        error: `Unknown recon type: ${reconType}\nValid types: passive, active, subdomain`,
      };
  }

  return {
    success: true,
    output: `# ${title} - ${target}

## Commands to Execute

\`\`\`bash
${commands.join('\n')}
\`\`\`

## AI Guidance

${buildReconPrompt(target, reconType as 'passive' | 'active' | 'subdomain')}`,
    data: { target, reconType, commands },
  };
}

async function handleHunt(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const vulnClass = args[0];

  if (!vulnClass) {
    const classes = VulnerabilityClassSchema.options.join(', ');
    return {
      success: false,
      output: '',
      error: `Usage: hunt <vulnerability-class>\n\nAvailable classes:\n${classes}`,
    };
  }

  const parseResult = VulnerabilityClassSchema.safeParse(vulnClass);
  if (!parseResult.success) {
    const classes = VulnerabilityClassSchema.options.join(', ');
    return {
      success: false,
      output: '',
      error: `Unknown vulnerability class: ${vulnClass}\n\nAvailable:\n${classes}`,
    };
  }

  const prompt = buildHuntPrompt(parseResult.data);

  return {
    success: true,
    output: `# Hunting: ${vulnClass}

${prompt}`,
    data: { vulnerabilityClass: vulnClass },
  };
}

async function handleTools(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const category = args[0];

  if (!category) {
    const tools = getAllTools();
    const categories = TOOL_CATEGORIES.join(', ');

    return {
      success: true,
      output: `# Security Tools

## Categories
${categories}

## All Tools
${tools.map(t => `- **${t.name}**: ${t.description}`).join('\n')}

Use \`tools <category>\` for category-specific tools.`,
      data: { tools },
    };
  }

  if (!TOOL_CATEGORIES.includes(category as ToolCategory)) {
    return {
      success: false,
      output: '',
      error: `Unknown category: ${category}\nValid: ${TOOL_CATEGORIES.join(', ')}`,
    };
  }

  const tools = getToolsForCategory(category as ToolCategory);

  return {
    success: true,
    output: `# ${category} Tools

${tools.map(t => `## ${t.name}
${t.description}
\`\`\`bash
${t.installCommand}
\`\`\`
`).join('\n')}`,
    data: { category, tools },
  };
}

async function handleCheck(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const target = args[0];

  if (!target) {
    return {
      success: false,
      output: '',
      error: 'Usage: check <target>',
    };
  }

  if (!currentSessionId) {
    return {
      success: false,
      output: '',
      error: 'No active session. Start one with: start <mode>',
    };
  }

  const session = sessions.get(currentSessionId);
  if (!session?.scope) {
    return {
      success: false,
      output: '',
      error: 'No scope defined. Use: scope <program>',
    };
  }

  const result = isInScope(target, session.scope);

  return {
    success: true,
    output: `# Scope Check: ${target}

**In Scope:** ${result.inScope ? '✓ Yes' : '✗ No'}
**Reason:** ${result.reason}`,
    data: result,
  };
}

async function handleSeverity(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  // Interactive CVSS calculator guidance
  return {
    success: true,
    output: `# CVSS 3.1 Severity Calculator

## Attack Vector (AV)
- **N** (Network): Remotely exploitable
- **A** (Adjacent): Adjacent network
- **L** (Local): Local access required
- **P** (Physical): Physical access required

## Attack Complexity (AC)
- **L** (Low): No special conditions
- **H** (High): Special conditions required

## Privileges Required (PR)
- **N** (None): No authentication
- **L** (Low): Basic user privileges
- **H** (High): Admin privileges

## User Interaction (UI)
- **N** (None): No user interaction
- **R** (Required): User must take action

## Impact (C/I/A)
- **H** (High): Total compromise
- **L** (Low): Limited impact
- **N** (None): No impact

Provide the finding details and I'll calculate the CVSS score.`,
  };
}

async function handleReport(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const format = args[0] || 'markdown';

  if (!currentSessionId) {
    return {
      success: false,
      output: '',
      error: 'No active session. Start one with: start <mode>',
    };
  }

  const session = sessions.get(currentSessionId);
  if (!session) {
    return {
      success: false,
      output: '',
      error: 'Session not found',
    };
  }

  const stats = getSessionStats(session);

  let report: string;
  switch (format) {
    case 'hackerone':
      report = session.findings.length > 0
        ? formatHackerOneReport(session.findings[0])
        : 'No findings to report.';
      break;
    case 'bugcrowd':
      report = session.findings.length > 0
        ? formatBugcrowdReport(session.findings[0])
        : 'No findings to report.';
      break;
    default:
      report = generateEngagementReport(session);
  }

  return {
    success: true,
    output: report,
    data: { format, stats },
  };
}

async function handleChain(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  if (!currentSessionId) {
    return {
      success: false,
      output: '',
      error: 'No active session. Start one with: start <mode>',
    };
  }

  const session = sessions.get(currentSessionId);
  if (!session) {
    return {
      success: false,
      output: '',
      error: 'Session not found',
    };
  }

  if (session.findings.length < 2) {
    return {
      success: true,
      output: `# Attack Chain Analysis

You need at least 2 findings to analyze potential attack chains.

**Current findings:** ${session.findings.length}

Continue hunting and add more findings to enable chain analysis.`,
    };
  }

  const prompt = buildChainPrompt(session.findings);

  return {
    success: true,
    output: `# Attack Chain Analysis

${prompt}`,
    data: { findingCount: session.findings.length },
  };
}

async function handleStatus(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  if (!currentSessionId) {
    return {
      success: true,
      output: `# Security Research Status

**No active session.**

Start a new session with: \`start <mode>\`
Modes: bounty, pentest, research, ctf`,
    };
  }

  const session = sessions.get(currentSessionId);
  if (!session) {
    return {
      success: false,
      output: '',
      error: 'Session not found',
    };
  }

  const stats = getSessionStats(session);

  return {
    success: true,
    output: `# Security Research Status

**Session ID:** ${session.id}
**Mode:** ${session.mode}
**Status:** ${session.status}
**Duration:** ${stats.duration}
**Program:** ${session.scope?.programName || 'Not defined'}

## Findings Summary
- **Total:** ${stats.totalFindings}
- **Critical:** ${stats.bySeverity.critical}
- **High:** ${stats.bySeverity.high}
- **Medium:** ${stats.bySeverity.medium}
- **Low:** ${stats.bySeverity.low}
- **Info:** ${stats.bySeverity.informational}

## Attack Chains
- **Chained findings:** ${stats.chainedFindings}`,
    data: { session, stats },
  };
}

async function handleHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Security Research Skill

AI-assisted bug bounty hunting, penetration testing, and security research.

## Commands

| Command | Description |
|---------|-------------|
| \`start <mode>\` | Start session (bounty/pentest/research/ctf) |
| \`scope <program>\` | Define engagement scope |
| \`recon <target>\` | Run reconnaissance |
| \`hunt <class>\` | Hunt specific vulnerability class |
| \`chain\` | Analyze attack chains |
| \`report [format]\` | Generate report (markdown/hackerone/bugcrowd) |
| \`tools [category]\` | Get tool recommendations |
| \`check <target>\` | Verify target is in scope |
| \`severity\` | CVSS severity calculator |
| \`status\` | Show session status |

## Workflow
1. Start a session: \`start bounty\`
2. Define scope: \`scope hackerone-program\`
3. Reconnaissance: \`recon example.com\`
4. Hunt vulnerabilities: \`hunt xss\`
5. Generate report: \`report hackerone\``,
  };
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'start',
    description: 'Start a new security research session',
    usage: 'start <mode>',
    help: 'Modes: bounty, pentest, research, ctf',
    execute: handleStart,
  },
  {
    name: 'scope',
    description: 'Define engagement scope',
    usage: 'scope <program-name>',
    execute: handleScope,
  },
  {
    name: 'recon',
    description: 'Run reconnaissance on a target',
    usage: 'recon <target> [type]',
    help: 'Types: passive, active, subdomain',
    execute: handleRecon,
  },
  {
    name: 'hunt',
    description: 'Hunt for a specific vulnerability class',
    usage: 'hunt <vulnerability-class>',
    execute: handleHunt,
  },
  {
    name: 'chain',
    description: 'Analyze potential attack chains',
    usage: 'chain',
    execute: handleChain,
  },
  {
    name: 'report',
    description: 'Generate a finding report',
    usage: 'report [format]',
    help: 'Formats: markdown, hackerone, bugcrowd',
    execute: handleReport,
  },
  {
    name: 'tools',
    description: 'Get security tool recommendations',
    usage: 'tools [category]',
    execute: handleTools,
  },
  {
    name: 'check',
    description: 'Check if a target is in scope',
    usage: 'check <target>',
    execute: handleCheck,
  },
  {
    name: 'severity',
    description: 'Calculate CVSS severity score',
    usage: 'severity',
    execute: handleSeverity,
  },
  {
    name: 'status',
    description: 'Show current session status',
    usage: 'status',
    aliases: ['info'],
    execute: handleStatus,
  },
  {
    name: 'research-help',
    description: 'Show security research help',
    usage: 'research-help',
    aliases: ['sr-help'],
    execute: handleHelp,
  },
];

export const securityResearchSkill: Skill = {
  metadata: {
    id: 'security-research',
    name: 'Security Research',
    description: 'AI-assisted bug bounty hunting, penetration testing, and security research',
    version: '1.0.0',
    author: 'Gideon',
    category: 'security-research',
    capabilities: {
      providesTools: false,
      requiresGpu: false,
      supportsCpuFallback: true,
      stateful: true,
      requiresExternalService: false,
    },
  },

  commands,

  async isAvailable(): Promise<boolean> {
    // Always available - no external dependencies
    return true;
  },

  async getStatus(): Promise<SkillStatus> {
    const activeSessions = sessions.size;
    return {
      healthy: true,
      message: `${activeSessions} active session(s)`,
      checkedAt: new Date(),
      details: {
        activeSessions,
        currentSessionId,
      },
    };
  },

  async initialize(): Promise<void> {
    // No initialization needed
  },

  async shutdown(): Promise<void> {
    sessions.clear();
    currentSessionId = null;
  },
};
