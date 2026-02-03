// ============================================================================
// Gideon Skills System
// ============================================================================

export * from './types.js';
export * from './registry.js';

// Import built-in skills
import { securityResearchSkill } from './security-research/index.js';
import { threatDetectionSkill } from './threat-detection/index.js';
import { dataAnalyticsSkill } from './data-analytics/index.js';
import { codeScanningSkill } from './code-scanning/index.js';
import { voiceSkill } from './voice/index.js';
import { governanceSkill } from './governance/index.js';

import { skillRegistry } from './registry.js';
import { Skill } from './types.js';

// ============================================================================
// Built-in Skills
// ============================================================================

export const builtInSkills: Skill[] = [
  securityResearchSkill,
  threatDetectionSkill,
  dataAnalyticsSkill,
  codeScanningSkill,
  voiceSkill,
  governanceSkill,
];

// Re-export individual skills
export {
  securityResearchSkill,
  threatDetectionSkill,
  dataAnalyticsSkill,
  codeScanningSkill,
  voiceSkill,
  governanceSkill,
};

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize all built-in skills
 */
export async function initializeSkills(): Promise<void> {
  console.log('Initializing Gideon skills...');

  for (const skill of builtInSkills) {
    const result = await skillRegistry.register(skill);
    if (result.success) {
      console.log(`  ✓ ${skill.metadata.name} (${skill.metadata.version})`);
    } else {
      console.warn(`  ✗ ${skill.metadata.name}: ${result.error}`);
    }
  }

  const enabled = skillRegistry.getEnabledSkills();
  console.log(`\n${enabled.length}/${builtInSkills.length} skills enabled`);
}

/**
 * Get a formatted list of all skills for display
 */
export function formatSkillsList(): string {
  const skills = skillRegistry.getAllSkills();

  if (skills.length === 0) {
    return 'No skills registered.';
  }

  const lines: string[] = ['# Gideon Skills\n'];

  // Group by category
  const byCategory = new Map<string, typeof skills>();
  for (const entry of skills) {
    const cat = entry.skill.metadata.category;
    if (!byCategory.has(cat)) {
      byCategory.set(cat, []);
    }
    byCategory.get(cat)!.push(entry);
  }

  for (const [category, categorySkills] of byCategory) {
    lines.push(`\n## ${formatCategory(category)}\n`);

    for (const entry of categorySkills) {
      const { metadata } = entry.skill;
      const status = entry.enabled ? '●' : '○';
      const gpu = metadata.capabilities.requiresGpu ? ' [GPU]' : '';
      lines.push(`${status} **${metadata.name}** v${metadata.version}${gpu}`);
      lines.push(`  ${metadata.description}`);

      if (entry.skill.commands.length > 0) {
        const cmds = entry.skill.commands.map(c => c.name).join(', ');
        lines.push(`  Commands: ${cmds}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Format category name for display
 */
function formatCategory(category: string): string {
  return category
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/**
 * Get skill help for a specific skill
 */
export function getSkillHelp(skillId: string): string | null {
  const skill = skillRegistry.getSkill(skillId);
  if (!skill) {
    return null;
  }

  const { metadata, commands } = skill;
  const lines: string[] = [
    `# ${metadata.name} v${metadata.version}`,
    '',
    metadata.description,
    '',
    '## Commands',
    '',
  ];

  for (const cmd of commands) {
    lines.push(`### ${cmd.name}`);
    lines.push(`Usage: \`${cmd.usage}\``);
    lines.push(cmd.description);
    if (cmd.help) {
      lines.push('');
      lines.push(cmd.help);
    }
    lines.push('');
  }

  if (metadata.requiredEnvVars?.length) {
    lines.push('## Required Environment Variables');
    lines.push('');
    for (const env of metadata.requiredEnvVars) {
      lines.push(`- \`${env}\``);
    }
    lines.push('');
  }

  return lines.join('\n');
}
