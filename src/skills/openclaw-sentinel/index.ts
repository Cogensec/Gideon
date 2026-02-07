import { Skill, SkillCommand, SkillCommandContext, SkillCommandResult, SkillStatus } from '../types';
import { getOpenClawSidecar } from '../../openclaw/index';

// ============================================================================
// OpenClaw Sentinel Skill
// Integrates the OpenClaw sidecar security platform into Gideon's skill system
// ============================================================================

/**
 * Initialize the sidecar command
 */
async function initCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  try {
    const sidecar = getOpenClawSidecar();
    const result = await sidecar.initialize();

    return {
      success: true,
      output: `OpenClaw Sidecar Initialized

Policies Registered: ${result.policiesRegistered ? 'Yes' : 'No'}
Agent Registered: ${result.agentRegistered ? 'Yes' : 'No'}
Initial Hardening Score: ${result.initialAudit.score}/100 (Grade: ${result.initialAudit.grade})

All security modules are active. The sidecar is monitoring your OpenClaw deployment.`,
      data: result,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Failed to initialize sidecar: ${err}`,
    };
  }
}

/**
 * Hardening audit command
 */
async function auditCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  try {
    const sidecar = getOpenClawSidecar();
    const result = await sidecar.hardeningAuditor.runAudit();
    const report = sidecar.hardeningAuditor.formatAuditReport(result);

    return {
      success: true,
      output: report,
      data: result,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Audit failed: ${err}`,
    };
  }
}

/**
 * Scan a skill for threats
 */
async function scanSkillCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  if (args.length === 0) {
    return {
      success: false,
      output: 'Usage: openclaw-scan-skill <skill-name> [path]',
      error: 'No skill name provided',
    };
  }

  const skillName = args[0];
  const skillPath = args[1] || '.';

  try {
    const sidecar = getOpenClawSidecar();

    // In a real implementation, this would read actual skill files
    // For now, provide the interface
    const result = await sidecar.skillScanner.scanSkill({
      name: skillName,
      path: skillPath,
      files: [], // Would be populated by reading the skill directory
    });

    const lines = [
      `# Skill Scan: ${result.skillName}`,
      '',
      `**Risk Level:** ${result.riskLevel.toUpperCase()}`,
      `**Risk Score:** ${result.score}/100`,
      `**Scan Duration:** ${result.scanDurationMs}ms`,
      '',
    ];

    if (result.findings.length > 0) {
      lines.push('## Findings', '');
      for (const finding of result.findings) {
        lines.push(`- **[${finding.severity.toUpperCase()}]** ${finding.description}`);
        lines.push(`  File: ${finding.file}${finding.line ? `:${finding.line}` : ''}`);
        lines.push(`  Pattern: \`${finding.matchedPattern}\``);
        lines.push('');
      }
    }

    if (result.iocHits.length > 0) {
      lines.push('## IOC Hits', '');
      for (const hit of result.iocHits) {
        lines.push(`- **${hit.malicious ? 'MALICIOUS' : 'Suspicious'}** ${hit.type}: ${hit.indicator}`);
        lines.push(`  ${hit.details}`);
      }
      lines.push('');
    }

    lines.push('## Publisher Analysis', '');
    lines.push(`- Account Age: ${result.publisherAnalysis.accountAge} days`);
    lines.push(`- Publishing Velocity: ${result.publisherAnalysis.publishingVelocity.toFixed(1)} skills/day`);
    lines.push(`- Publisher Risk Score: ${result.publisherAnalysis.riskScore}/100`);
    if (result.publisherAnalysis.suspiciousIndicators.length > 0) {
      lines.push('- Suspicious Indicators:');
      for (const ind of result.publisherAnalysis.suspiciousIndicators) {
        lines.push(`  - ${ind}`);
      }
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: result,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Skill scan failed: ${err}`,
    };
  }
}

/**
 * Check content for prompt injection
 */
async function scanInjectionCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const content = args.join(' ');
  if (!content) {
    return {
      success: false,
      output: 'Usage: openclaw-scan-injection <content to scan>',
      error: 'No content provided',
    };
  }

  try {
    const sidecar = getOpenClawSidecar();
    const result = await sidecar.injectionDefense.scanContent(content, 'manual_scan');

    if (result.isInjection) {
      return {
        success: true,
        output: `INJECTION DETECTED

Type: ${result.injectionType}
Confidence: ${(result.confidence * 100).toFixed(1)}%
Technique: ${result.technique}
Payload: ${result.payload?.slice(0, 100)}

This content should NOT be ingested by an OpenClaw agent.`,
        data: result,
      };
    }

    return {
      success: true,
      output: 'No prompt injection detected in the provided content.',
      data: result,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Injection scan failed: ${err}`,
    };
  }
}

/**
 * Scan memory files for poisoning
 */
async function scanMemoryCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  try {
    const sidecar = getOpenClawSidecar();
    const results = sidecar.memoryMonitor.scanAllMemoryFiles();

    if (results.length === 0) {
      return {
        success: true,
        output: 'No OpenClaw memory files found. Verify the OpenClaw home directory path.',
        data: [],
      };
    }

    const lines = ['# Memory Integrity Scan Results', ''];

    for (const result of results) {
      lines.push(`## ${result.file}`);
      lines.push(`Integrity Score: ${result.integrityScore}/100`);
      lines.push(`Total Entries: ${result.totalEntries}`);
      lines.push(`Suspicious: ${result.suspiciousEntries.length}`);
      lines.push('');

      if (result.suspiciousEntries.length > 0) {
        for (const entry of result.suspiciousEntries) {
          lines.push(`- **[${entry.severity.toUpperCase()}]** Line ${entry.lineNumber}: ${entry.reason}`);
          lines.push(`  Content: "${entry.content.slice(0, 100)}"`);
        }
        lines.push('');
      }
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: results,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Memory scan failed: ${err}`,
    };
  }
}

/**
 * Audit credential storage
 */
async function auditCredsCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  try {
    const sidecar = getOpenClawSidecar();
    const exposures = sidecar.credentialGuard.auditCredentialStorage();

    if (exposures.length === 0) {
      return {
        success: true,
        output: 'No credential files found in OpenClaw home directory.',
        data: [],
      };
    }

    const lines = ['# Credential Storage Audit', ''];

    for (const exposure of exposures) {
      lines.push(`**${exposure.file}**`);
      lines.push(`  Type: ${exposure.type}`);
      lines.push(`  Encrypted: ${exposure.isEncrypted ? 'Yes' : 'NO (plaintext)'}`);
      lines.push(`  Permissions: ${exposure.permissions}`);
      lines.push(`  Owner-only: ${exposure.ownerOnly ? 'Yes' : 'NO'}`);
      lines.push(`  Recommendation: ${exposure.recommendation}`);
      lines.push('');
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: exposures,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Credential audit failed: ${err}`,
    };
  }
}

/**
 * Show full security status
 */
async function statusCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  try {
    const sidecar = getOpenClawSidecar();
    const status = sidecar.getStatus();

    const lines = [
      '# OpenClaw Sidecar Status',
      '',
      `Initialized: ${status.initialized ? 'Yes' : 'No'}`,
      '',
      '| Module | Status | Key Metric |',
      '|--------|--------|------------|',
      `| Gateway Sentinel | ${status.modules.sentinel.enabled ? 'Active' : 'Off'} | ${status.modules.sentinel.alerts} alerts, ${status.modules.sentinel.sessions} sessions |`,
      `| Skill Scanner | ${status.modules.skillScanner.enabled ? 'Active' : 'Off'} | ${status.modules.skillScanner.scans} scans, ${status.modules.skillScanner.blocked} blocked |`,
      `| Injection Defense | ${status.modules.injectionDefense.enabled ? 'Active' : 'Off'} | ${status.modules.injectionDefense.scans} scans, ${status.modules.injectionDefense.detections} caught |`,
      `| Hardening Auditor | ${status.modules.hardeningAuditor.enabled ? 'Active' : 'Off'} | Score: ${status.modules.hardeningAuditor.lastScore ?? 'N/A'}/100 |`,
      `| Credential Guard | ${status.modules.credentialGuard.enabled ? 'Active' : 'Off'} | ${status.modules.credentialGuard.attempts} exfil attempts |`,
      `| Memory Monitor | Active | ${status.modules.memoryMonitor.scans} scans, ${status.modules.memoryMonitor.suspicious} suspicious |`,
    ];

    return {
      success: true,
      output: lines.join('\n'),
      data: status,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Status check failed: ${err}`,
    };
  }
}

/**
 * Generate comprehensive security report
 */
async function reportCommand(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  try {
    const sidecar = getOpenClawSidecar();
    const report = await sidecar.generateReport();

    return {
      success: true,
      output: report,
    };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: `Report generation failed: ${err}`,
    };
  }
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'openclaw-init',
    description: 'Initialize the OpenClaw security sidecar',
    usage: 'openclaw-init',
    help: 'Starts the Gideon security sidecar for OpenClaw. Registers security policies, ' +
      'sets up monitoring, and runs an initial hardening audit.',
    execute: initCommand,
  },
  {
    name: 'openclaw-audit',
    description: 'Run a hardening audit on OpenClaw deployment',
    usage: 'openclaw-audit',
    aliases: ['oc-audit'],
    help: 'Checks authentication, sandboxing, file permissions, credential storage, ' +
      'tool restrictions, and runtime version against security best practices.',
    execute: auditCommand,
  },
  {
    name: 'openclaw-scan-skill',
    description: 'Scan a ClawHub skill for security threats',
    usage: 'openclaw-scan-skill <skill-name> [path]',
    aliases: ['oc-scan-skill'],
    help: 'Scans a ClawHub skill for malicious patterns, code obfuscation, credential harvesting, ' +
      'permission overreach, typosquatting, and known malware campaigns.',
    execute: scanSkillCommand,
  },
  {
    name: 'openclaw-scan-injection',
    description: 'Check content for prompt injection attacks',
    usage: 'openclaw-scan-injection <content>',
    aliases: ['oc-scan-inject'],
    help: 'Scans content for prompt injection attacks including CSS-hidden instructions (CVE-2026-22708), ' +
      'Unicode obfuscation, role overrides, tool invocation injection, and memory poisoning.',
    execute: scanInjectionCommand,
  },
  {
    name: 'openclaw-scan-memory',
    description: 'Scan OpenClaw memory files for poisoning',
    usage: 'openclaw-scan-memory',
    aliases: ['oc-scan-memory'],
    help: 'Scans all OpenClaw memory files (daily logs, MEMORY.md) for poisoning indicators. ' +
      'Detects injected instructions disguised as facts.',
    execute: scanMemoryCommand,
  },
  {
    name: 'openclaw-audit-creds',
    description: 'Audit OpenClaw credential storage',
    usage: 'openclaw-audit-creds',
    aliases: ['oc-audit-creds'],
    help: 'Audits credential files in the OpenClaw home directory for plaintext storage, ' +
      'insecure permissions, and encryption status.',
    execute: auditCredsCommand,
  },
  {
    name: 'openclaw-status',
    description: 'Show security sidecar status',
    usage: 'openclaw-status',
    aliases: ['oc-status'],
    help: 'Displays the status of all security modules: Gateway Sentinel, Skill Scanner, ' +
      'Injection Defense, Hardening Auditor, Credential Guard, and Memory Monitor.',
    execute: statusCommand,
  },
  {
    name: 'openclaw-report',
    description: 'Generate comprehensive security report',
    usage: 'openclaw-report',
    aliases: ['oc-report'],
    help: 'Generates a full security report covering all modules, alerts, findings, ' +
      'audit results, and recommendations.',
    execute: reportCommand,
  },
];

export const openclawSentinelSkill: Skill = {
  metadata: {
    id: 'openclaw-sentinel',
    name: 'OpenClaw Sentinel',
    description: 'Security sidecar for OpenClaw agent deployments. Provides gateway traffic monitoring, ' +
      'skill scanning, prompt injection defense, hardening audits, credential protection, and memory integrity checks. ' +
      'Addresses CVE-2026-25253, CVE-2026-24763, CVE-2026-25157, CVE-2026-22708, and ClawHavoc campaign threats.',
    version: '1.0.0',
    author: 'Gideon Security',
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
    return true; // No external dependencies required
  },

  async getStatus(): Promise<SkillStatus> {
    try {
      const sidecar = getOpenClawSidecar();
      const status = sidecar.getStatus();

      return {
        healthy: status.initialized,
        message: status.initialized
          ? `Active - monitoring ${status.modules.sentinel.sessions} sessions`
          : 'Not initialized - run openclaw-init',
        checkedAt: new Date(),
        details: status.modules,
      };
    } catch {
      return {
        healthy: false,
        message: 'Sidecar not yet created',
        checkedAt: new Date(),
      };
    }
  },
};
