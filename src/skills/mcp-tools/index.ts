/**
 * MCP Tools Skill
 *
 * Connect to and execute security tools via Model Context Protocol
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';
import { getMCPManager, MCPServer, SECURITY_TOOLS } from '../../mcp/index.js';
import { getPhaseManager } from '../../agent/phases.js';
import { getApprovalManager } from '../../agent/approval.js';

// ============================================================================
// Command Implementations
// ============================================================================

async function handleConnect(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const serverArg = args[0];

  if (!serverArg) {
    return {
      success: false,
      output: '',
      error: 'Usage: mcp connect <server-url-or-name>',
    };
  }

  try {
    const manager = getMCPManager();
    let server: MCPServer;

    // Check if it's a URL or a preset name
    if (serverArg.startsWith('http://') || serverArg.startsWith('https://')) {
      const name = args[1] || new URL(serverArg).hostname;
      server = await manager.connectHTTP(name, serverArg);
    } else {
      // Try to connect to preset server
      const presets: Record<string, string> = {
        'security-tools': process.env.MCP_SECURITY_URL || 'http://localhost:8000',
        'local': 'http://localhost:8000',
      };

      const url = presets[serverArg];
      if (!url) {
        return {
          success: false,
          output: '',
          error: `Unknown preset: ${serverArg}. Use a full URL or one of: ${Object.keys(presets).join(', ')}`,
        };
      }

      server = await manager.connectHTTP(serverArg, url);
    }

    const toolList = server.tools.map((t) => `- **${t.name}**: ${t.description}`).join('\n');

    return {
      success: true,
      output: `# Connected to MCP Server

**Name:** ${server.name}
**URL:** ${server.url}
**Status:** ${server.status}

## Available Tools (${server.tools.length})

${toolList || 'No tools discovered'}

## Capabilities
- Tools: ${server.capabilities.tools ? '✓' : '✗'}
- Resources: ${server.capabilities.resources ? '✓' : '✗'}
- Prompts: ${server.capabilities.prompts ? '✓' : '✗'}
- Logging: ${server.capabilities.logging ? '✓' : '✗'}`,
      data: { server },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to connect: ${error}`,
    };
  }
}

async function handleDisconnect(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const serverName = args[0];

  if (!serverName) {
    return {
      success: false,
      output: '',
      error: 'Usage: mcp disconnect <server-name>',
    };
  }

  try {
    const manager = getMCPManager();
    await manager.disconnect(serverName);

    return {
      success: true,
      output: `Disconnected from server: ${serverName}`,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to disconnect: ${error}`,
    };
  }
}

async function handleList(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const manager = getMCPManager();
  const servers = manager.getAllServers();

  if (servers.length === 0) {
    return {
      success: true,
      output: `# MCP Servers

No servers connected.

**Connect with:** \`mcp connect <server-url>\`

## Preset Servers
- \`mcp connect security-tools\` - Connect to security tools server
- \`mcp connect local\` - Connect to localhost:8000`,
    };
  }

  const tools = manager.getAllTools();

  const serverLines = servers.map((s) => {
    const statusIcon = s.status === 'connected' ? '●' : '○';
    return `${statusIcon} **${s.name}** (${s.url}) - ${s.tools.length} tools`;
  }).join('\n');

  const toolLines = tools.map((t) => {
    const secInfo = SECURITY_TOOLS[t.name];
    const phase = secInfo?.phase || 'informational';
    const approval = secInfo?.requiresApproval ? '🔒' : '';
    return `- **${t.name}** (${t.serverName}) ${approval} [${phase}]`;
  }).join('\n');

  return {
    success: true,
    output: `# MCP Servers

## Connected Servers
${serverLines}

## Available Tools (${tools.length})
${toolLines}

🔒 = Requires approval`,
    data: { servers, tools },
  };
}

async function handleRun(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const toolName = args[0];
  const toolArgs = args.slice(1);

  if (!toolName) {
    return {
      success: false,
      output: '',
      error: 'Usage: mcp run <tool-name> [args...]',
    };
  }

  const manager = getMCPManager();
  const tools = manager.getAllTools();
  const tool = tools.find((t) => t.name === toolName);

  if (!tool) {
    return {
      success: false,
      output: '',
      error: `Tool not found: ${toolName}. Run \`mcp list\` to see available tools.`,
    };
  }

  // Check phase restrictions
  const phaseManager = getPhaseManager();
  const phaseCheck = phaseManager.isToolAllowed(toolName);
  if (!phaseCheck.allowed) {
    return {
      success: false,
      output: '',
      error: phaseCheck.reason || `Tool ${toolName} not allowed in current phase`,
    };
  }

  // Check if approval is required
  const secInfo = SECURITY_TOOLS[toolName];
  if (secInfo?.requiresApproval) {
    const approvalManager = getApprovalManager();
    const decision = await approvalManager.requestToolApproval(
      toolName,
      parseToolArgs(toolArgs),
      ctx.env.TARGET_DOMAIN || 'unknown',
      secInfo.riskLevel
    );

    if (!decision.approved) {
      return {
        success: false,
        output: '',
        error: `Tool execution denied: ${decision.reason || 'User declined'}`,
      };
    }
  }

  try {
    const startTime = Date.now();
    const result = await manager.executeToolByName(toolName, parseToolArgs(toolArgs));
    const duration = Date.now() - startTime;

    const output = result.content
      .map((c) => c.text || `[${c.type}]`)
      .join('\n');

    return {
      success: !result.isError,
      output: `# Tool Execution: ${toolName}

**Duration:** ${duration}ms
**Status:** ${result.isError ? 'Error' : 'Success'}

## Output

\`\`\`
${output}
\`\`\``,
      data: { tool: toolName, duration, result },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Tool execution failed: ${error}`,
    };
  }
}

async function handleStatus(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const manager = getMCPManager();
  const servers = manager.getAllServers();
  const executions = manager.getExecutions();

  const recentExecutions = executions
    .slice(-10)
    .reverse()
    .map((e) => {
      const statusIcon = e.status === 'completed' ? '✓' : e.status === 'failed' ? '✗' : '⋯';
      const duration = e.endTime
        ? `${new Date(e.endTime).getTime() - new Date(e.startTime).getTime()}ms`
        : 'running';
      return `${statusIcon} **${e.toolName}** (${e.serverName}) - ${duration}`;
    })
    .join('\n');

  return {
    success: true,
    output: `# MCP Status

## Servers
${servers.map((s) => `- ${s.status === 'connected' ? '●' : '○'} ${s.name}: ${s.status}`).join('\n') || 'None connected'}

## Recent Executions
${recentExecutions || 'No executions yet'}

## Current Phase
${getPhaseManager().getCurrentPhase()}`,
    data: { servers, executions: executions.slice(-10) },
  };
}

async function handleMCPHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# MCP Tools Skill

Connect to and execute security tools via Model Context Protocol.

## Commands

| Command | Description |
|---------|-------------|
| \`mcp connect <url>\` | Connect to an MCP server |
| \`mcp disconnect <name>\` | Disconnect from a server |
| \`mcp list\` | List connected servers and tools |
| \`mcp run <tool> [args]\` | Execute a tool |
| \`mcp status\` | Show connection and execution status |

## Preset Servers

- \`security-tools\` - Default security tools server (localhost:8000)
- \`local\` - Local MCP server

## Tool Arguments

Arguments are parsed as key=value pairs:

\`\`\`bash
mcp run nmap target=192.168.1.1 ports=1-1000 flags=-sV
mcp run nuclei target=example.com templates=cves
\`\`\`

## Phase Restrictions

Some tools are restricted based on the current phase:

- **Informational:** nmap, nuclei, httpx, katana (auto-approved)
- **Exploitation:** sqlmap, hydra (requires approval)
- **Post-Exploitation:** metasploit (requires approval)

## Setup

Start the MCP security tools server:

\`\`\`bash
docker-compose up mcp-security
mcp connect security-tools
\`\`\``,
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

function parseToolArgs(args: string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const arg of args) {
    if (arg.includes('=')) {
      const [key, ...valueParts] = arg.split('=');
      const value = valueParts.join('=');
      result[key] = value;
    } else {
      // Positional argument
      if (!result._args) result._args = [];
      (result._args as string[]).push(arg);
    }
  }

  return result;
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'mcp',
    description: 'MCP tool management (connect, list, run)',
    usage: 'mcp <subcommand>',
    execute: async (args, ctx) => {
      const subcommand = args[0];
      const subArgs = args.slice(1);

      switch (subcommand) {
        case 'connect':
          return handleConnect(subArgs, ctx);
        case 'disconnect':
          return handleDisconnect(subArgs, ctx);
        case 'list':
        case 'ls':
          return handleList(subArgs, ctx);
        case 'run':
        case 'exec':
          return handleRun(subArgs, ctx);
        case 'status':
          return handleStatus(subArgs, ctx);
        case 'help':
        default:
          return handleMCPHelp(subArgs, ctx);
      }
    },
  },
];

export const mcpToolsSkill: Skill = {
  metadata: {
    id: 'mcp-tools',
    name: 'MCP Tools',
    description: 'Connect to and execute security tools via Model Context Protocol',
    version: '1.0.0',
    author: 'Gideon',
    category: 'integration',
    capabilities: {
      providesTools: true,
      requiresGpu: false,
      supportsCpuFallback: true,
      stateful: true,
      requiresExternalService: true,
    },
    optionalEnvVars: ['MCP_SECURITY_URL'],
  },

  commands,

  async isAvailable(): Promise<boolean> {
    // MCP is always "available" - connection is optional
    return true;
  },

  async getStatus(): Promise<SkillStatus> {
    const manager = getMCPManager();
    const servers = manager.getAllServers();
    const connected = servers.filter((s) => s.status === 'connected');

    return {
      healthy: true,
      message: `${connected.length}/${servers.length} servers connected`,
      checkedAt: new Date(),
      details: {
        servers: servers.map((s) => ({ name: s.name, status: s.status })),
      },
    };
  },

  async shutdown(): Promise<void> {
    const manager = getMCPManager();
    await manager.disconnectAll();
  },
};
