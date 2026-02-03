/**
 * Governance Skill
 *
 * Agent security governance, access control, and audit logging.
 * Ensures safe and compliant AI agent operations.
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';

import {
  getAgentRegistry,
  getPolicyEngine,
  getAuditLogger,
  getAccessControl,
} from '../../governance/index.js';

// ============================================================================
// Command Implementations
// ============================================================================

async function handleAgents(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'list':
      return handleAgentsList();
    case 'status':
      return handleAgentsStatus(args[1]);
    case 'register':
      return handleAgentsRegister(args.slice(1));
    default:
      return {
        success: true,
        output: `# Agent Management

## Subcommands
- \`agents list\` - List registered agents
- \`agents status <id>\` - Get agent status
- \`agents register <name>\` - Register new agent`,
      };
  }
}

async function handleAgentsList(): Promise<SkillCommandResult> {
  try {
    const registry = getAgentRegistry();
    const agents = registry.listAgents();

    if (agents.length === 0) {
      return {
        success: true,
        output: '# Registered Agents\n\nNo agents registered.',
      };
    }

    const lines = ['# Registered Agents\n'];
    for (const agent of agents) {
      lines.push(`## ${agent.name}`);
      lines.push(`- **ID:** ${agent.id}`);
      lines.push(`- **Status:** ${agent.status}`);
      lines.push(`- **Capabilities:** ${agent.capabilities.join(', ')}`);
      lines.push('');
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: { agents },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to list agents: ${error}`,
    };
  }
}

async function handleAgentsStatus(agentId: string): Promise<SkillCommandResult> {
  if (!agentId) {
    return {
      success: false,
      output: '',
      error: 'Usage: agents status <agent-id>',
    };
  }

  try {
    const registry = getAgentRegistry();
    const agent = registry.getAgent(agentId);

    if (!agent) {
      return {
        success: false,
        output: '',
        error: `Agent not found: ${agentId}`,
      };
    }

    return {
      success: true,
      output: `# Agent: ${agent.name}

**ID:** ${agent.id}
**Status:** ${agent.status}
**Created:** ${agent.createdAt}
**Last Active:** ${agent.lastActiveAt || 'Never'}

## Capabilities
${agent.capabilities.map(c => `- ${c}`).join('\n')}

## Permissions
${agent.permissions.map(p => `- ${p}`).join('\n')}`,
      data: { agent },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to get agent status: ${error}`,
    };
  }
}

async function handleAgentsRegister(args: string[]): Promise<SkillCommandResult> {
  const name = args[0];

  if (!name) {
    return {
      success: false,
      output: '',
      error: 'Usage: agents register <name>',
    };
  }

  try {
    const registry = getAgentRegistry();
    const agent = registry.registerAgent({
      name,
      capabilities: ['query', 'analyze'],
      permissions: ['read'],
    });

    return {
      success: true,
      output: `# Agent Registered

**Name:** ${agent.name}
**ID:** ${agent.id}
**Status:** ${agent.status}`,
      data: { agent },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to register agent: ${error}`,
    };
  }
}

async function handlePolicy(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'list':
      return handlePolicyList();
    case 'check':
      return handlePolicyCheck(args.slice(1));
    default:
      return {
        success: true,
        output: `# Policy Management

## Subcommands
- \`policy list\` - List active policies
- \`policy check <action> <resource>\` - Check if action is allowed`,
      };
  }
}

async function handlePolicyList(): Promise<SkillCommandResult> {
  try {
    const engine = getPolicyEngine();
    const policies = engine.listPolicies();

    const lines = ['# Active Policies\n'];
    for (const policy of policies) {
      lines.push(`## ${policy.name}`);
      lines.push(`- **Effect:** ${policy.effect}`);
      lines.push(`- **Actions:** ${policy.actions.join(', ')}`);
      lines.push(`- **Resources:** ${policy.resources.join(', ')}`);
      lines.push('');
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: { policies },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to list policies: ${error}`,
    };
  }
}

async function handlePolicyCheck(args: string[]): Promise<SkillCommandResult> {
  const action = args[0];
  const resource = args[1];

  if (!action || !resource) {
    return {
      success: false,
      output: '',
      error: 'Usage: policy check <action> <resource>',
    };
  }

  try {
    const engine = getPolicyEngine();
    const result = engine.evaluate({ action, resource });

    return {
      success: true,
      output: `# Policy Check

**Action:** ${action}
**Resource:** ${resource}
**Result:** ${result.allowed ? '✓ Allowed' : '✗ Denied'}
**Reason:** ${result.reason || 'N/A'}`,
      data: result,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Policy check failed: ${error}`,
    };
  }
}

async function handleAudit(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'recent':
      return handleAuditRecent(parseInt(args[1]) || 10);
    case 'search':
      return handleAuditSearch(args.slice(1));
    default:
      return {
        success: true,
        output: `# Audit Log

## Subcommands
- \`audit recent [count]\` - Show recent audit entries
- \`audit search <query>\` - Search audit logs`,
      };
  }
}

async function handleAuditRecent(count: number): Promise<SkillCommandResult> {
  try {
    const logger = getAuditLogger();
    const entries = logger.getRecent(count);

    if (entries.length === 0) {
      return {
        success: true,
        output: '# Recent Audit Entries\n\nNo entries found.',
      };
    }

    const lines = ['# Recent Audit Entries\n'];
    for (const entry of entries) {
      lines.push(`## ${entry.timestamp}`);
      lines.push(`- **Action:** ${entry.action}`);
      lines.push(`- **Agent:** ${entry.agentId}`);
      lines.push(`- **Resource:** ${entry.resource}`);
      lines.push(`- **Result:** ${entry.result}`);
      lines.push('');
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: { entries },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to get audit entries: ${error}`,
    };
  }
}

async function handleAuditSearch(args: string[]): Promise<SkillCommandResult> {
  const query = args.join(' ');

  if (!query) {
    return {
      success: false,
      output: '',
      error: 'Usage: audit search <query>',
    };
  }

  try {
    const logger = getAuditLogger();
    const entries = logger.search(query);

    return {
      success: true,
      output: `# Audit Search: "${query}"

Found ${entries.length} entries.

${entries.map(e => `- ${e.timestamp}: ${e.action} on ${e.resource}`).join('\n')}`,
      data: { query, entries },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Audit search failed: ${error}`,
    };
  }
}

async function handleGovernanceHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Governance Skill

Agent security governance, access control, and audit logging.

## Commands

### Agent Management
| Command | Description |
|---------|-------------|
| \`agents list\` | List registered agents |
| \`agents status <id>\` | Get agent status |
| \`agents register <name>\` | Register new agent |

### Policy Management
| Command | Description |
|---------|-------------|
| \`policy list\` | List active policies |
| \`policy check <action> <resource>\` | Check if action allowed |

### Audit Logging
| Command | Description |
|---------|-------------|
| \`audit recent [count]\` | Show recent entries |
| \`audit search <query>\` | Search audit logs |

## Features
- Role-based access control (RBAC)
- Policy-based authorization
- Comprehensive audit logging
- Agent registration and monitoring`,
  };
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'agents',
    description: 'Manage registered agents',
    usage: 'agents <subcommand>',
    execute: handleAgents,
  },
  {
    name: 'policy',
    description: 'Manage security policies',
    usage: 'policy <subcommand>',
    execute: handlePolicy,
  },
  {
    name: 'audit',
    description: 'View audit logs',
    usage: 'audit <subcommand>',
    execute: handleAudit,
  },
  {
    name: 'governance-help',
    description: 'Show governance help',
    usage: 'governance-help',
    execute: handleGovernanceHelp,
  },
];

export const governanceSkill: Skill = {
  metadata: {
    id: 'governance',
    name: 'Governance',
    description: 'Agent security governance, access control, and audit logging',
    version: '1.0.0',
    author: 'Gideon',
    category: 'governance',
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
    return true; // Always available
  },

  async getStatus(): Promise<SkillStatus> {
    try {
      const registry = getAgentRegistry();
      const agentCount = registry.listAgents().length;

      return {
        healthy: true,
        message: `${agentCount} agents registered`,
        checkedAt: new Date(),
        details: { agentCount },
      };
    } catch {
      return {
        healthy: true,
        message: 'Governance ready',
        checkedAt: new Date(),
      };
    }
  },
};
