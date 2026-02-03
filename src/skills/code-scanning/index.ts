/**
 * Code Scanning Skill
 *
 * Static analysis and vulnerability detection for source code.
 * Supports multiple languages and security patterns.
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';

import {
  scanDirectory,
  scanFile,
  ScanResult,
  ScanOptions,
} from '../../scanner/index.js';

// ============================================================================
// Command Implementations
// ============================================================================

async function handleScan(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const targetPath = args[0] || ctx.cwd;
  const outputFormat = args.find(a => a.startsWith('--format='))?.split('=')[1] || 'markdown';

  try {
    const options: ScanOptions = {
      recursive: !args.includes('--no-recursive'),
      includeTests: args.includes('--include-tests'),
      severity: args.find(a => a.startsWith('--severity='))?.split('=')[1] as any || 'low',
    };

    const result = await scanDirectory(targetPath, options);
    return formatScanResult(result, outputFormat);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Scan failed: ${error}`,
    };
  }
}

async function handleScanFile(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const filePath = args[0];

  if (!filePath) {
    return {
      success: false,
      output: '',
      error: 'Usage: scan-file <file-path>',
    };
  }

  try {
    const result = await scanFile(filePath);
    return formatScanResult(result, 'markdown');
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `File scan failed: ${error}`,
    };
  }
}

async function handlePatterns(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Security Scan Patterns

## Vulnerability Categories

### Injection
- SQL Injection
- Command Injection
- LDAP Injection
- XPath Injection
- Template Injection

### Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS
- DOM-based XSS

### Authentication & Session
- Hardcoded Credentials
- Weak Password Handling
- Session Fixation
- Insecure Token Generation

### Cryptography
- Weak Algorithms (MD5, SHA1)
- Hardcoded Keys
- Insecure Random Generation
- Missing Encryption

### Data Exposure
- Sensitive Data in Logs
- Information Disclosure
- Debug Mode Enabled
- Verbose Errors

### Configuration
- Insecure Defaults
- Missing Security Headers
- CORS Misconfiguration
- SSL/TLS Issues

## Supported Languages
- JavaScript/TypeScript
- Python
- Java
- Go
- Ruby
- PHP
- C/C++
- C#`,
  };
}

async function handleScanHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Code Scanning Skill

Static analysis and vulnerability detection for source code.

## Commands

| Command | Description |
|---------|-------------|
| \`scan [path]\` | Scan directory for vulnerabilities |
| \`scan-file <file>\` | Scan a single file |
| \`patterns\` | Show supported vulnerability patterns |

## Scan Options

| Option | Description |
|--------|-------------|
| \`--format=json\` | Output as JSON |
| \`--format=markdown\` | Output as Markdown (default) |
| \`--severity=high\` | Minimum severity (low/medium/high/critical) |
| \`--no-recursive\` | Don't scan subdirectories |
| \`--include-tests\` | Include test files |

## Examples

\`\`\`bash
# Scan current directory
gideon scan

# Scan specific path with JSON output
gideon scan ./src --format=json

# Scan only high severity issues
gideon scan --severity=high

# Scan single file
gideon scan-file ./src/auth.ts
\`\`\``,
  };
}

function formatScanResult(result: ScanResult, format: string): SkillCommandResult {
  if (format === 'json') {
    return {
      success: true,
      output: JSON.stringify(result, null, 2),
      data: result,
    };
  }

  const lines = [
    '# Security Scan Results\n',
    `**Files Scanned:** ${result.filesScanned}`,
    `**Total Findings:** ${result.findings.length}`,
    `**Scan Duration:** ${result.duration}ms`,
    '',
  ];

  // Summary by severity
  const bySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const finding of result.findings) {
    bySeverity[finding.severity as keyof typeof bySeverity]++;
  }

  lines.push('## Summary by Severity\n');
  lines.push(`- Critical: ${bySeverity.critical}`);
  lines.push(`- High: ${bySeverity.high}`);
  lines.push(`- Medium: ${bySeverity.medium}`);
  lines.push(`- Low: ${bySeverity.low}`);
  lines.push('');

  if (result.findings.length > 0) {
    lines.push('## Findings\n');

    for (const finding of result.findings) {
      lines.push(`### ${finding.title}`);
      lines.push(`- **Severity:** ${finding.severity}`);
      lines.push(`- **File:** ${finding.file}:${finding.line}`);
      lines.push(`- **Category:** ${finding.category}`);
      if (finding.description) {
        lines.push(`- **Description:** ${finding.description}`);
      }
      if (finding.remediation) {
        lines.push(`- **Remediation:** ${finding.remediation}`);
      }
      lines.push('');
    }
  }

  return {
    success: true,
    output: lines.join('\n'),
    data: result,
  };
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'scan',
    description: 'Scan directory for security vulnerabilities',
    usage: 'scan [path] [options]',
    execute: handleScan,
  },
  {
    name: 'scan-file',
    description: 'Scan a single file',
    usage: 'scan-file <file-path>',
    execute: handleScanFile,
  },
  {
    name: 'patterns',
    description: 'Show supported vulnerability patterns',
    usage: 'patterns',
    execute: handlePatterns,
  },
  {
    name: 'scan-help',
    description: 'Show code scanning help',
    usage: 'scan-help',
    execute: handleScanHelp,
  },
];

export const codeScanningSkill: Skill = {
  metadata: {
    id: 'code-scanning',
    name: 'Code Scanning',
    description: 'Static analysis and vulnerability detection for source code',
    version: '1.0.0',
    author: 'Gideon',
    category: 'code-analysis',
    capabilities: {
      providesTools: false,
      requiresGpu: false,
      supportsCpuFallback: true,
      stateful: false,
      requiresExternalService: false,
    },
  },

  commands,

  async isAvailable(): Promise<boolean> {
    return true; // Always available - no external dependencies
  },

  async getStatus(): Promise<SkillStatus> {
    return {
      healthy: true,
      message: 'Code scanning ready',
      checkedAt: new Date(),
    };
  },
};
