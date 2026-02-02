import { resolve, join } from 'path';
import { existsSync, writeFileSync, mkdirSync } from 'fs';
import { CommandContext, CommandResult } from './types';
import {
  CodeScanner,
  ReportGenerator,
  ScanConfig,
  Severity,
  VulnerabilityCategoryType,
  Language,
} from '../scanner';

/**
 * Security Scan Command Handler
 *
 * Scans code repositories for security vulnerabilities and generates
 * detailed reports with fixes.
 *
 * Usage:
 *   scan <path>                          - Scan a directory or file
 *   scan <path> --severity high          - Only report high+ severity
 *   scan <path> --category injection     - Scan specific category
 *   scan <path> --fix                    - Generate fix suggestions
 *   scan <path> --output ./reports       - Custom output directory
 *   scan <path> --format markdown        - Output format (markdown|json|sarif)
 */
export async function handleScanCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  // Parse arguments
  const { targetPath, options, error } = parseArgs(args);

  if (error) {
    return {
      success: false,
      output: error,
      error,
    };
  }

  if (!targetPath) {
    return showHelp();
  }

  // Resolve path
  const resolvedPath = resolve(process.cwd(), targetPath);

  if (!existsSync(resolvedPath)) {
    return {
      success: false,
      output: `Error: Path does not exist: ${resolvedPath}`,
      error: 'Path not found',
    };
  }

  // Build scan config
  const config: ScanConfig = {
    targetPath: resolvedPath,
    recursive: true,
    generateFixes: options.fix !== false,
    deepAnalysis: true,
    minSeverity: options.severity as Severity | undefined,
    categories: options.category ? [options.category as VulnerabilityCategoryType] : undefined,
    languages: options.language ? [options.language as Language] : undefined,
    outputFormat: options.format || 'markdown',
    outputPath: options.output,
  };

  try {
    // Run the scan
    console.log(`\nScanning ${resolvedPath}...\n`);

    const scanner = new CodeScanner(config);
    const result = await scanner.scan();

    // Generate reports
    const reportGenerator = new ReportGenerator(result, options.output);

    let output = reportGenerator.generateCLISummary();

    // Generate full reports if requested
    if (options.report !== false) {
      const outputDir = options.output || join(process.cwd(), 'outputs', getTimestamp());

      if (!existsSync(outputDir)) {
        mkdirSync(outputDir, { recursive: true });
      }

      const reports = await reportGenerator.generateAll();

      output += `\nReports generated:\n`;
      output += `  - Markdown: ${reports.markdown}\n`;
      output += `  - JSON: ${reports.json}\n`;
      output += `  - SARIF: ${reports.sarif}\n`;
    }

    // Return detailed vulnerability information for fixes
    if (options.showFixes && result.vulnerabilities.length > 0) {
      output += '\n' + generateFixOutput(result.vulnerabilities);
    }

    return {
      success: true,
      output,
      artifacts: {
        json: result,
        markdown: reportGenerator.generateMarkdown(),
      },
    };
  } catch (error) {
    return {
      success: false,
      output: `Scan failed: ${error}`,
      error: String(error),
    };
  }
}

/**
 * Parse command arguments
 */
function parseArgs(args: string[]): {
  targetPath: string | null;
  options: Record<string, any>;
  error?: string;
} {
  const options: Record<string, any> = {
    fix: true,
    report: true,
  };
  let targetPath: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const nextArg = args[i + 1];

      switch (key) {
        case 'severity':
          if (!nextArg || !['critical', 'high', 'medium', 'low', 'informational'].includes(nextArg)) {
            return { targetPath: null, options, error: 'Invalid severity. Use: critical, high, medium, low, informational' };
          }
          options.severity = nextArg;
          i++;
          break;

        case 'category':
          options.category = nextArg;
          i++;
          break;

        case 'language':
          options.language = nextArg;
          i++;
          break;

        case 'output':
          options.output = nextArg;
          i++;
          break;

        case 'format':
          if (!nextArg || !['markdown', 'json', 'sarif'].includes(nextArg)) {
            return { targetPath: null, options, error: 'Invalid format. Use: markdown, json, sarif' };
          }
          options.format = nextArg;
          i++;
          break;

        case 'fix':
          options.fix = true;
          options.showFixes = true;
          break;

        case 'no-fix':
          options.fix = false;
          break;

        case 'no-report':
          options.report = false;
          break;

        case 'help':
          return { targetPath: null, options: { help: true }, error: undefined };

        default:
          // Unknown option, ignore
          break;
      }
    } else if (!targetPath) {
      targetPath = arg;
    }
  }

  if (options.help) {
    return { targetPath: null, options, error: undefined };
  }

  return { targetPath, options };
}

/**
 * Generate detailed fix output
 */
function generateFixOutput(vulnerabilities: any[]): string {
  let output = `\n${'='.repeat(70)}\n`;
  output += `VULNERABILITY DETAILS AND FIXES\n`;
  output += `${'='.repeat(70)}\n\n`;

  const criticalAndHigh = vulnerabilities.filter(
    (v) => v.severity === 'critical' || v.severity === 'high'
  );

  for (const v of criticalAndHigh.slice(0, 10)) {
    output += `[${v.severity.toUpperCase()}] ${v.name}\n`;
    output += `${'─'.repeat(60)}\n`;
    output += `File: ${v.location.file}:${v.location.startLine}\n`;
    output += `Category: ${v.category}\n`;
    output += `CWE: ${v.cwe.join(', ')}\n\n`;

    output += `Description:\n${v.description}\n\n`;

    output += `Impact:\n${v.impact}\n\n`;

    output += `Vulnerable Code:\n`;
    output += `┌${'─'.repeat(58)}┐\n`;
    output += `│ ${v.location.snippet.slice(0, 56).padEnd(56)} │\n`;
    output += `└${'─'.repeat(58)}┘\n\n`;

    if (v.fix) {
      output += `Recommended Fix:\n`;
      output += `${v.fix.description}\n\n`;

      output += `Before:\n\`\`\`\n${v.fix.originalCode}\n\`\`\`\n\n`;
      output += `After:\n\`\`\`\n${v.fix.fixedCode}\n\`\`\`\n\n`;

      if (v.fix.breakingChange) {
        output += `⚠️  WARNING: This fix may introduce breaking changes.\n\n`;
      }
    } else {
      output += `Recommendation:\n${v.recommendation}\n\n`;
    }

    output += `References:\n`;
    for (const ref of v.references.slice(0, 2)) {
      output += `  - ${ref}\n`;
    }
    output += '\n';
  }

  if (vulnerabilities.length > 10) {
    output += `\n... and ${vulnerabilities.length - 10} more vulnerabilities.\n`;
    output += `See full report for complete details.\n`;
  }

  return output;
}

/**
 * Get timestamp for output directory
 */
function getTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

/**
 * Show help message
 */
function showHelp(): CommandResult {
  const output = `
# Gideon Security Scanner

Scan code repositories for security vulnerabilities.

## Usage

\`\`\`
scan <path> [options]
\`\`\`

## Options

| Option | Description |
|--------|-------------|
| \`--severity <level>\` | Minimum severity to report (critical, high, medium, low) |
| \`--category <cat>\` | Scan specific category (injection, xss, secrets, etc.) |
| \`--language <lang>\` | Scan specific language (javascript, python, java, etc.) |
| \`--output <dir>\` | Output directory for reports |
| \`--format <fmt>\` | Output format (markdown, json, sarif) |
| \`--fix\` | Show detailed fix suggestions |
| \`--no-fix\` | Disable fix generation |
| \`--no-report\` | Don't generate report files |
| \`--help\` | Show this help message |

## Examples

\`\`\`bash
# Scan current directory
scan .

# Scan with minimum severity
scan ./src --severity high

# Scan for specific vulnerabilities
scan ./app --category injection

# Scan and show fixes
scan ./code --fix

# Custom output location
scan . --output ./security-reports
\`\`\`

## Vulnerability Categories

| Category | Description |
|----------|-------------|
| \`injection\` | SQL, Command, LDAP injection |
| \`xss\` | Cross-Site Scripting |
| \`broken_auth\` | Authentication issues |
| \`broken_access\` | Access control failures |
| \`sensitive_data\` | Data exposure |
| \`security_misconfig\` | Misconfigurations |
| \`crypto_issues\` | Weak cryptography |
| \`hardcoded_secrets\` | Exposed credentials |
| \`ssrf\` | Server-Side Request Forgery |
| \`path_traversal\` | Path traversal attacks |
| \`insecure_deserial\` | Deserialization issues |
| \`memory_safety\` | Buffer overflows, etc. |

## Supported Languages

JavaScript, TypeScript, Python, Java, Go, Rust, C/C++, C#, PHP, Ruby,
Swift, Kotlin, Scala, Shell, SQL, YAML, Terraform, Dockerfile

## Report Formats

- **Markdown**: Human-readable detailed report
- **JSON**: Machine-readable structured data
- **SARIF**: GitHub Code Scanning compatible format

## References

- OWASP Top 10: https://owasp.org/Top10/
- CWE Top 25: https://cwe.mitre.org/top25/
`;

  return { success: true, output };
}
