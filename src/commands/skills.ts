/**
 * Skills Command
 *
 * Manage and interact with Gideon skills.
 */

import { CommandContext, CommandResult } from './types.js';
import {
  skillRegistry,
  formatSkillsList,
  getSkillHelp,
  initializeSkills,
} from '../skills/index.js';

/**
 * Handle skills command
 */
export async function handleSkillsCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const subcommand = args[0]?.toLowerCase();

  switch (subcommand) {
    case 'list':
    case undefined:
      return handleList();

    case 'status':
      return handleStatus();

    case 'help':
      return handleHelp(args[1]);

    case 'enable':
      return handleEnable(args[1]);

    case 'disable':
      return handleDisable(args[1]);

    case 'init':
      return handleInit();

    case 'run':
      return handleRun(args.slice(1), context);

    default:
      // Try to run as a skill command
      return handleRun(args, context);
  }
}

async function handleList(): Promise<CommandResult> {
  const output = formatSkillsList();
  return {
    success: true,
    output,
  };
}

async function handleStatus(): Promise<CommandResult> {
  const statuses = await skillRegistry.getStatus();
  const lines = ['# Skill Status\n'];

  for (const [skillId, status] of statuses) {
    const icon = status.healthy ? '●' : '○';
    lines.push(`${icon} **${skillId}**`);
    lines.push(`  ${status.message}`);
    lines.push(`  Last checked: ${status.checkedAt.toISOString()}`);
    lines.push('');
  }

  return {
    success: true,
    output: lines.join('\n'),
  };
}

async function handleHelp(skillId?: string): Promise<CommandResult> {
  if (!skillId) {
    return {
      success: true,
      output: `# Skills Command

Manage and interact with Gideon skills.

## Usage

\`\`\`
gideon skills [subcommand]
\`\`\`

## Subcommands

| Command | Description |
|---------|-------------|
| \`skills\` | List all skills |
| \`skills list\` | List all skills |
| \`skills status\` | Show skill health status |
| \`skills help <skill>\` | Show help for a skill |
| \`skills enable <skill>\` | Enable a skill |
| \`skills disable <skill>\` | Disable a skill |
| \`skills run <command>\` | Run a skill command |

## Running Skill Commands

You can run skill commands directly:

\`\`\`bash
# Using skills run
gideon skills run recon example.com

# Or directly (if command is registered)
gideon recon example.com
\`\`\`

## Available Skills

Use \`skills list\` to see all available skills and their commands.`,
    };
  }

  const help = getSkillHelp(skillId);
  if (!help) {
    return {
      success: false,
      output: '',
      error: `Unknown skill: ${skillId}`,
    };
  }

  return {
    success: true,
    output: help,
  };
}

async function handleEnable(skillId?: string): Promise<CommandResult> {
  if (!skillId) {
    return {
      success: false,
      output: '',
      error: 'Usage: skills enable <skill-id>',
    };
  }

  const success = await skillRegistry.enableSkill(skillId);
  if (!success) {
    return {
      success: false,
      output: '',
      error: `Failed to enable skill: ${skillId}. It may not exist or have unmet dependencies.`,
    };
  }

  return {
    success: true,
    output: `Skill enabled: ${skillId}`,
  };
}

async function handleDisable(skillId?: string): Promise<CommandResult> {
  if (!skillId) {
    return {
      success: false,
      output: '',
      error: 'Usage: skills disable <skill-id>',
    };
  }

  const success = await skillRegistry.disableSkill(skillId);
  if (!success) {
    return {
      success: false,
      output: '',
      error: `Failed to disable skill: ${skillId}`,
    };
  }

  return {
    success: true,
    output: `Skill disabled: ${skillId}`,
  };
}

async function handleInit(): Promise<CommandResult> {
  try {
    await initializeSkills();
    const enabled = skillRegistry.getEnabledSkills();
    return {
      success: true,
      output: `Skills initialized. ${enabled.length} skills enabled.`,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to initialize skills: ${error}`,
    };
  }
}

async function handleRun(args: string[], context: CommandContext): Promise<CommandResult> {
  const commandName = args[0];

  if (!commandName) {
    return {
      success: false,
      output: '',
      error: 'Usage: skills run <command> [args...]',
    };
  }

  const result = await skillRegistry.executeCommand(
    commandName,
    args.slice(1),
    {
      cwd: process.cwd(),
      env: process.env as Record<string, string | undefined>,
    }
  );

  return {
    success: result.success,
    output: result.output,
    error: result.error,
  };
}

// Export for command registration
export const skillsCommand = {
  name: 'skills',
  description: 'Manage and interact with Gideon skills',
  usage: 'skills [subcommand] [args...]',
  execute: handleSkillsCommand,
};
