import { CommandContext, CommandResult } from './types';
import {
  getGideonGovernance,
  getAgentRegistry,
  getPolicyEngine,
  getAccessControl,
  getAuditLogger,
  AgentType,
  PolicySeverity,
} from '../governance';

/**
 * Agent Governance Command Handler
 *
 * Provides CLI interface for agent security governance operations.
 *
 * Usage:
 *   governance status                     - Show governance dashboard
 *   governance agents                     - List all registered agents
 *   governance agents register <name>     - Register a new agent
 *   governance agents activate <id>       - Activate a pending agent
 *   governance agents suspend <id>        - Suspend an agent
 *   governance agents quarantine <id>     - Quarantine an agent
 *   governance policies                   - List all policies
 *   governance policies show <id>         - Show policy details
 *   governance audit                      - Show recent audit events
 *   governance audit report               - Generate compliance report
 *   governance health                     - Show agent health statuses
 */
export async function handleGovernanceCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const subcommand = args[0] || 'status';

  switch (subcommand) {
    case 'status':
      return showDashboard();

    case 'agents':
      return handleAgentsCommand(args.slice(1));

    case 'policies':
      return handlePoliciesCommand(args.slice(1));

    case 'permissions':
      return handlePermissionsCommand(args.slice(1));

    case 'audit':
      return handleAuditCommand(args.slice(1));

    case 'health':
      return showAgentHealth();

    case 'help':
    default:
      return showHelp();
  }
}

async function showDashboard(): Promise<CommandResult> {
  const governance = getGideonGovernance();
  const stats = governance.getStats();

  const output = `
# Gideon Agent Security Governance Dashboard

## Overview
| Metric | Value |
|--------|-------|
| Total Agents | ${stats.totalAgents} |
| Active Agents | ${stats.activeAgents} |
| Suspended Agents | ${stats.suspendedAgents} |
| Quarantined Agents | ${stats.quarantinedAgents} |
| Active Policies | ${stats.activePolicies} |
| Compliance Score | ${stats.complianceScore}% |

## Last 24 Hours
| Metric | Value |
|--------|-------|
| Agent Activities | ${stats.activitiesLast24h} |
| Policy Violations | ${stats.violationsLast24h} |
| Anomalies Detected | ${stats.anomaliesLast24h} |

## Quick Actions
- \`governance agents\` - List all agents
- \`governance policies\` - View security policies
- \`governance audit\` - View audit logs
- \`governance health\` - Check agent health
`;

  return {
    success: true,
    output,
    artifacts: { json: stats },
  };
}

async function handleAgentsCommand(args: string[]): Promise<CommandResult> {
  const action = args[0] || 'list';
  const registry = getAgentRegistry();
  const governance = getGideonGovernance();

  switch (action) {
    case 'list': {
      const agents = registry.listAgents();

      if (agents.length === 0) {
        return {
          success: true,
          output: 'No agents registered. Use `governance agents register <name>` to add one.',
        };
      }

      const statusEmoji: Record<string, string> = {
        active: '[ACTIVE]',
        suspended: '[SUSPENDED]',
        quarantined: '[QUARANTINE]',
        revoked: '[REVOKED]',
        pending: '[PENDING]',
      };

      let output = '# Registered Agents\n\n';
      output += '| Status | Name | Type | Owner | ID |\n';
      output += '|--------|------|------|-------|----|\n';

      for (const agent of agents) {
        output += `| ${statusEmoji[agent.status] || agent.status} | ${agent.name} | ${agent.type} | ${agent.owner} | ${agent.id.slice(0, 8)}... |\n`;
      }

      return { success: true, output, artifacts: { json: agents } };
    }

    case 'register': {
      const name = args[1];
      if (!name) {
        return {
          success: false,
          output: 'Usage: governance agents register <name> [--type <type>] [--owner <owner>]',
          error: 'Missing agent name',
        };
      }

      // Parse optional args
      let type: AgentType = 'generic';
      let owner = 'admin';
      const capabilities: string[] = [];

      for (let i = 2; i < args.length; i++) {
        if (args[i] === '--type' && args[i + 1]) {
          type = args[i + 1] as AgentType;
          i++;
        } else if (args[i] === '--owner' && args[i + 1]) {
          owner = args[i + 1];
          i++;
        } else if (args[i] === '--capability' && args[i + 1]) {
          capabilities.push(args[i + 1]);
          i++;
        }
      }

      try {
        const agent = governance.registerAgent({
          name,
          type,
          owner,
          capabilities: capabilities.length > 0 ? capabilities : ['basic'],
          description: `Agent registered via CLI`,
        });

        return {
          success: true,
          output: `Agent registered successfully!\n\nID: ${agent.id}\nName: ${agent.name}\nType: ${agent.type}\nStatus: ${agent.status}\n\nUse \`governance agents activate ${agent.id}\` to activate.`,
          artifacts: { json: agent },
        };
      } catch (error) {
        return {
          success: false,
          output: `Failed to register agent: ${error}`,
          error: String(error),
        };
      }
    }

    case 'activate': {
      const agentId = args[1];
      if (!agentId) {
        return {
          success: false,
          output: 'Usage: governance agents activate <agent-id>',
          error: 'Missing agent ID',
        };
      }

      try {
        const agent = governance.activateAgent(agentId, 'cli-admin');
        return {
          success: true,
          output: `Agent "${agent.name}" activated successfully!`,
          artifacts: { json: agent },
        };
      } catch (error) {
        return {
          success: false,
          output: `Failed to activate agent: ${error}`,
          error: String(error),
        };
      }
    }

    case 'suspend': {
      const agentId = args[1];
      const reason = args.slice(2).join(' ') || 'Suspended via CLI';

      if (!agentId) {
        return {
          success: false,
          output: 'Usage: governance agents suspend <agent-id> [reason]',
          error: 'Missing agent ID',
        };
      }

      try {
        const agent = governance.suspendAgent(agentId, reason, 'cli-admin');
        return {
          success: true,
          output: `Agent "${agent.name}" suspended.\nReason: ${reason}`,
          artifacts: { json: agent },
        };
      } catch (error) {
        return {
          success: false,
          output: `Failed to suspend agent: ${error}`,
          error: String(error),
        };
      }
    }

    case 'quarantine': {
      const agentId = args[1];
      const reason = args.slice(2).join(' ') || 'Quarantined via CLI';

      if (!agentId) {
        return {
          success: false,
          output: 'Usage: governance agents quarantine <agent-id> [reason]',
          error: 'Missing agent ID',
        };
      }

      try {
        const agent = registry.quarantineAgent(agentId, reason);
        return {
          success: true,
          output: `Agent "${agent.name}" quarantined.\nReason: ${reason}`,
          artifacts: { json: agent },
        };
      } catch (error) {
        return {
          success: false,
          output: `Failed to quarantine agent: ${error}`,
          error: String(error),
        };
      }
    }

    case 'show': {
      const agentId = args[1];
      if (!agentId) {
        return {
          success: false,
          output: 'Usage: governance agents show <agent-id>',
          error: 'Missing agent ID',
        };
      }

      const agent = registry.getAgent(agentId) || registry.getAgentByName(agentId);
      if (!agent) {
        return {
          success: false,
          output: `Agent not found: ${agentId}`,
          error: 'Agent not found',
        };
      }

      const accessControl = getAccessControl();
      const permissions = accessControl.getAgentPermissions(agent.id);

      let output = `# Agent: ${agent.name}\n\n`;
      output += `| Property | Value |\n|----------|-------|\n`;
      output += `| ID | ${agent.id} |\n`;
      output += `| Type | ${agent.type} |\n`;
      output += `| Status | ${agent.status} |\n`;
      output += `| Owner | ${agent.owner} |\n`;
      output += `| Registered | ${agent.registeredAt} |\n`;
      output += `| Last Seen | ${agent.lastSeenAt || 'Never'} |\n`;
      output += `| Capabilities | ${agent.capabilities.join(', ')} |\n`;

      if (permissions.length > 0) {
        output += `\n## Permissions\n\n`;
        for (const perm of permissions) {
          output += `- ${perm.resourceType}: ${perm.resource} [${perm.actions.join(', ')}]\n`;
        }
      }

      return { success: true, output, artifacts: { json: { agent, permissions } } };
    }

    default:
      return {
        success: false,
        output: `Unknown agents subcommand: ${action}\n\nAvailable: list, register, activate, suspend, quarantine, show`,
        error: 'Unknown subcommand',
      };
  }
}

async function handlePoliciesCommand(args: string[]): Promise<CommandResult> {
  const action = args[0] || 'list';
  const policyEngine = getPolicyEngine();

  switch (action) {
    case 'list': {
      const policySets = policyEngine.listPolicySets();

      if (policySets.length === 0) {
        return {
          success: true,
          output: 'No policy sets configured.',
        };
      }

      let output = '# Security Policy Sets\n\n';

      for (const policySet of policySets) {
        output += `## ${policySet.name}\n`;
        output += `- ID: ${policySet.id.slice(0, 8)}...\n`;
        output += `- Version: ${policySet.version}\n`;
        output += `- Rules: ${policySet.rules.length} (${policySet.rules.filter((r) => r.enabled).length} enabled)\n`;
        output += `- Default Action: ${policySet.defaultAction}\n\n`;
      }

      return { success: true, output, artifacts: { json: policySets } };
    }

    case 'show': {
      const policyId = args[1];
      if (!policyId) {
        // Show default policy set
        const defaultSet = policyEngine.getDefaultPolicySet();
        if (!defaultSet) {
          return {
            success: false,
            output: 'No default policy set configured.',
            error: 'No policy set',
          };
        }

        let output = `# ${defaultSet.name}\n\n`;
        output += `Version: ${defaultSet.version}\n`;
        output += `Default Action: ${defaultSet.defaultAction}\n\n`;
        output += `## Rules\n\n`;
        output += `| Priority | Name | Severity | Action | Enabled |\n`;
        output += `|----------|------|----------|--------|----------|\n`;

        const sortedRules = [...defaultSet.rules].sort((a, b) => b.priority - a.priority);
        for (const rule of sortedRules) {
          output += `| ${rule.priority} | ${rule.name} | ${rule.severity} | ${rule.action} | ${rule.enabled ? 'Yes' : 'No'} |\n`;
        }

        return { success: true, output, artifacts: { json: defaultSet } };
      }

      const policySet = policyEngine.getPolicySet(policyId);
      if (!policySet) {
        return {
          success: false,
          output: `Policy set not found: ${policyId}`,
          error: 'Not found',
        };
      }

      let output = `# ${policySet.name}\n\n`;
      for (const rule of policySet.rules) {
        output += `## ${rule.name}\n`;
        output += `- ${rule.description}\n`;
        output += `- Severity: ${rule.severity}\n`;
        output += `- Action: ${rule.action}\n`;
        output += `- Enabled: ${rule.enabled}\n\n`;
      }

      return { success: true, output, artifacts: { json: policySet } };
    }

    case 'stats': {
      const stats = policyEngine.getStats();

      let output = '# Policy Statistics\n\n';
      output += `| Metric | Value |\n|--------|-------|\n`;
      output += `| Total Policy Sets | ${stats.totalPolicySets} |\n`;
      output += `| Total Rules | ${stats.totalRules} |\n`;
      output += `| Enabled Rules | ${stats.enabledRules} |\n\n`;

      output += `## By Severity\n`;
      for (const [severity, count] of Object.entries(stats.rulesBySeverity)) {
        if (count > 0) output += `- ${severity}: ${count}\n`;
      }

      output += `\n## By Action\n`;
      for (const [action, count] of Object.entries(stats.rulesByAction)) {
        if (count > 0) output += `- ${action}: ${count}\n`;
      }

      return { success: true, output, artifacts: { json: stats } };
    }

    default:
      return {
        success: false,
        output: `Unknown policies subcommand: ${action}\n\nAvailable: list, show, stats`,
        error: 'Unknown subcommand',
      };
  }
}

async function handlePermissionsCommand(args: string[]): Promise<CommandResult> {
  const action = args[0] || 'list';
  const accessControl = getAccessControl();

  switch (action) {
    case 'list': {
      const stats = accessControl.getStats();

      let output = '# Permission Statistics\n\n';
      output += `| Metric | Value |\n|--------|-------|\n`;
      output += `| Total Permissions | ${stats.totalPermissions} |\n`;
      output += `| Active | ${stats.activePermissions} |\n`;
      output += `| Expired | ${stats.expiredPermissions} |\n`;
      output += `| Pending Requests | ${stats.pendingRequests} |\n`;

      return { success: true, output, artifacts: { json: stats } };
    }

    case 'pending': {
      const requests = accessControl.getPendingRequests();

      if (requests.length === 0) {
        return {
          success: true,
          output: 'No pending access requests.',
        };
      }

      let output = '# Pending Access Requests\n\n';
      output += `| ID | Agent | Resource | Action | Requested |\n`;
      output += `|----|-------|----------|--------|------------|\n`;

      for (const req of requests) {
        output += `| ${req.id.slice(0, 8)}... | ${req.agentId.slice(0, 8)}... | ${req.resource} | ${req.action} | ${req.requestedAt} |\n`;
      }

      return { success: true, output, artifacts: { json: requests } };
    }

    default:
      return {
        success: false,
        output: `Unknown permissions subcommand: ${action}\n\nAvailable: list, pending`,
        error: 'Unknown subcommand',
      };
  }
}

async function handleAuditCommand(args: string[]): Promise<CommandResult> {
  const action = args[0] || 'recent';
  const auditLogger = getAuditLogger();

  switch (action) {
    case 'recent': {
      const events = auditLogger.getSecurityEvents(24, 20);

      if (events.length === 0) {
        return {
          success: true,
          output: 'No security events in the last 24 hours.',
        };
      }

      let output = '# Recent Security Events (Last 24h)\n\n';
      output += `| Time | Type | Actor | Target | Outcome |\n`;
      output += `|------|------|-------|--------|----------|\n`;

      for (const event of events) {
        const time = new Date(event.timestamp).toLocaleTimeString();
        output += `| ${time} | ${event.eventType} | ${event.actor.name || event.actor.id} | ${event.target?.name || event.target?.id || '-'} | ${event.outcome} |\n`;
      }

      return { success: true, output, artifacts: { json: events } };
    }

    case 'report': {
      const days = parseInt(args[1]) || 30;
      const report = auditLogger.generateComplianceReport(days);

      let output = `# Compliance Report (${days} days)\n\n`;
      output += `Period: ${report.period.start} to ${report.period.end}\n\n`;

      output += `## Summary\n`;
      output += `| Metric | Count |\n|--------|-------|\n`;
      output += `| Agents Registered | ${report.summary.totalAgentsRegistered} |\n`;
      output += `| Policy Changes | ${report.summary.totalPolicyChanges} |\n`;
      output += `| Permission Changes | ${report.summary.totalPermissionChanges} |\n`;
      output += `| Security Events | ${report.summary.totalSecurityEvents} |\n`;
      output += `| Anomalies | ${report.summary.totalAnomalies} |\n`;
      output += `| Quarantine Events | ${report.summary.quarantineEvents} |\n\n`;

      output += `## Audit Integrity\n`;
      output += `Status: ${report.integrityStatus.valid ? 'VALID' : 'INVALID'}\n`;
      if (!report.integrityStatus.valid) {
        output += `Errors: ${report.integrityStatus.errorCount}\n`;
      }

      if (report.recommendations.length > 0) {
        output += `\n## Recommendations\n`;
        for (const rec of report.recommendations) {
          output += `- ${rec}\n`;
        }
      }

      return { success: true, output, artifacts: { json: report } };
    }

    case 'verify': {
      const result = auditLogger.verifyIntegrity();

      let output = `# Audit Log Integrity Check\n\n`;
      output += `Status: ${result.valid ? 'VALID - Hash chain intact' : 'INVALID - Integrity compromised'}\n\n`;

      if (!result.valid) {
        output += `## Errors\n`;
        for (const error of result.errors.slice(0, 10)) {
          output += `- ${error}\n`;
        }
        if (result.errors.length > 10) {
          output += `\n...and ${result.errors.length - 10} more errors\n`;
        }
      }

      return { success: true, output, artifacts: { json: result } };
    }

    case 'stats': {
      const stats = auditLogger.getStats(7);

      let output = '# Audit Statistics (Last 7 days)\n\n';
      output += `Total Events: ${stats.totalEvents}\n`;
      output += `High Risk Events: ${stats.highRiskCount}\n\n`;

      output += `## By Event Type\n`;
      for (const [type, count] of Object.entries(stats.byEventType)) {
        if (count > 0) output += `- ${type}: ${count}\n`;
      }

      output += `\n## By Outcome\n`;
      for (const [outcome, count] of Object.entries(stats.byOutcome)) {
        if (count > 0) output += `- ${outcome}: ${count}\n`;
      }

      return { success: true, output, artifacts: { json: stats } };
    }

    default:
      return {
        success: false,
        output: `Unknown audit subcommand: ${action}\n\nAvailable: recent, report, verify, stats`,
        error: 'Unknown subcommand',
      };
  }
}

async function showAgentHealth(): Promise<CommandResult> {
  const governance = getGideonGovernance();
  const healthStatuses = governance.getAgentHealthStatuses();

  if (healthStatuses.length === 0) {
    return {
      success: true,
      output: 'No agents registered.',
    };
  }

  let output = '# Agent Health Status\n\n';
  output += `| Agent | Status | Health | Violations | Anomalies | Top Risks |\n`;
  output += `|-------|--------|--------|------------|-----------|------------|\n`;

  for (const health of healthStatuses) {
    const healthIndicator = health.healthScore >= 80 ? 'Good' :
      health.healthScore >= 50 ? 'Fair' : 'Poor';

    output += `| ${health.agentName} | ${health.status} | ${healthIndicator} (${health.healthScore}%) | ${health.violationCount} | ${health.anomalyCount} | ${health.topRisks.slice(0, 2).join(', ') || 'None'} |\n`;
  }

  return { success: true, output, artifacts: { json: healthStatuses } };
}

function showHelp(): Promise<CommandResult> {
  const output = `
# Gideon Agent Security Governance

Centralized security governance for AI agents.

## Commands

### Dashboard
\`governance status\`              - Show governance dashboard

### Agent Management
\`governance agents\`              - List all registered agents
\`governance agents register <name> [--type <type>] [--owner <owner>]\`
\`governance agents show <id>\`    - Show agent details
\`governance agents activate <id>\` - Activate a pending agent
\`governance agents suspend <id> [reason]\` - Suspend an agent
\`governance agents quarantine <id> [reason]\` - Quarantine an agent

### Policy Management
\`governance policies\`            - List all policy sets
\`governance policies show [id]\`  - Show policy details
\`governance policies stats\`      - Show policy statistics

### Permissions
\`governance permissions\`         - Show permission statistics
\`governance permissions pending\` - Show pending access requests

### Audit & Compliance
\`governance audit\`               - Show recent security events
\`governance audit report [days]\` - Generate compliance report
\`governance audit verify\`        - Verify audit log integrity
\`governance audit stats\`         - Show audit statistics

### Health Monitoring
\`governance health\`              - Show agent health statuses

## Agent Types
- claude-code      : Claude Code agents
- openclaw         : OpenClaw agents (https://github.com/openclaw/openclaw)
- custom-langchain : Custom LangChain agents
- autogen          : Microsoft AutoGen
- crewai           : CrewAI agents
- generic          : Generic/unknown agents

## Deprecated Types (auto-migrated)
- moltbot  -> openclaw
- clawdbot -> openclaw
`;

  return Promise.resolve({ success: true, output });
}
