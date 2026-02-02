import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join, extname, relative, basename } from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  ScanConfig,
  ScanResult,
  Vulnerability,
  CodeLocation,
  Language,
  Severity,
  ProposedFix,
  VulnerabilityPattern,
} from './types';
import { ALL_VULNERABILITY_PATTERNS, getPatternsByLanguage } from './patterns';

// ============================================================================
// Language Detection
// ============================================================================

const EXTENSION_LANGUAGE_MAP: Record<string, Language> = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.py': 'python',
  '.pyw': 'python',
  '.java': 'java',
  '.go': 'go',
  '.rs': 'rust',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.cxx': 'cpp',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.php': 'php',
  '.rb': 'ruby',
  '.swift': 'swift',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.scala': 'scala',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.sql': 'sql',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.json': 'json',
  '.tf': 'terraform',
  '.tfvars': 'terraform',
};

const FILENAME_LANGUAGE_MAP: Record<string, Language> = {
  'Dockerfile': 'dockerfile',
  'dockerfile': 'dockerfile',
  'Containerfile': 'dockerfile',
};

function detectLanguage(filePath: string): Language {
  const fileName = basename(filePath);

  // Check filename first
  if (fileName in FILENAME_LANGUAGE_MAP) {
    return FILENAME_LANGUAGE_MAP[fileName];
  }

  // Check extension
  const ext = extname(filePath).toLowerCase();
  if (ext in EXTENSION_LANGUAGE_MAP) {
    return EXTENSION_LANGUAGE_MAP[ext];
  }

  return 'unknown';
}

// ============================================================================
// Default Exclusions
// ============================================================================

const DEFAULT_EXCLUDE_PATTERNS = [
  'node_modules',
  'vendor',
  '.git',
  '.svn',
  '.hg',
  '__pycache__',
  '.pytest_cache',
  'venv',
  '.venv',
  'env',
  '.env',
  'dist',
  'build',
  'out',
  'target',
  '.next',
  '.nuxt',
  'coverage',
  '.nyc_output',
  '*.min.js',
  '*.min.css',
  '*.map',
  '*.lock',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'Cargo.lock',
  'go.sum',
  'poetry.lock',
  'Pipfile.lock',
  'composer.lock',
  'Gemfile.lock',
];

const DEFAULT_INCLUDE_PATTERNS = [
  '*.js', '*.jsx', '*.ts', '*.tsx',
  '*.py',
  '*.java',
  '*.go',
  '*.rs',
  '*.c', '*.cpp', '*.h', '*.hpp',
  '*.cs',
  '*.php',
  '*.rb',
  '*.swift',
  '*.kt',
  '*.scala',
  '*.sh', '*.bash',
  '*.sql',
  '*.yaml', '*.yml',
  '*.tf',
  'Dockerfile',
];

// ============================================================================
// Code Scanner
// ============================================================================

export class CodeScanner {
  private config: ScanConfig;
  private patterns: VulnerabilityPattern[];
  private filesScanned: number = 0;
  private linesScanned: number = 0;
  private vulnerabilities: Vulnerability[] = [];

  constructor(config: ScanConfig) {
    this.config = {
      recursive: true,
      maxFileSize: 1024 * 1024, // 1MB default
      generateFixes: true,
      deepAnalysis: true,
      excludePatterns: DEFAULT_EXCLUDE_PATTERNS,
      ...config,
    };

    // Initialize patterns based on config
    this.patterns = this.initializePatterns();
  }

  private initializePatterns(): VulnerabilityPattern[] {
    let patterns = [...ALL_VULNERABILITY_PATTERNS];

    // Filter by categories if specified
    if (this.config.categories && this.config.categories.length > 0) {
      patterns = patterns.filter((p) => this.config.categories!.includes(p.category));
    }

    // Filter by minimum severity if specified
    if (this.config.minSeverity) {
      const severityOrder: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
      const minIndex = severityOrder.indexOf(this.config.minSeverity);
      patterns = patterns.filter((p) => severityOrder.indexOf(p.severity) >= minIndex);
    }

    return patterns;
  }

  /**
   * Run the security scan
   */
  async scan(): Promise<ScanResult> {
    const startTime = Date.now();

    // Reset state
    this.filesScanned = 0;
    this.linesScanned = 0;
    this.vulnerabilities = [];

    // Validate target path
    if (!existsSync(this.config.targetPath)) {
      throw new Error(`Target path does not exist: ${this.config.targetPath}`);
    }

    // Scan files
    const stats = statSync(this.config.targetPath);
    if (stats.isFile()) {
      await this.scanFile(this.config.targetPath);
    } else if (stats.isDirectory()) {
      await this.scanDirectory(this.config.targetPath);
    }

    // Build result
    const duration = Date.now() - startTime;
    const result = this.buildResult(duration);

    return result;
  }

  /**
   * Scan a directory recursively
   */
  private async scanDirectory(dirPath: string): Promise<void> {
    const entries = readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);

      // Check exclusions
      if (this.isExcluded(fullPath, entry.name)) {
        continue;
      }

      if (entry.isDirectory()) {
        if (this.config.recursive) {
          await this.scanDirectory(fullPath);
        }
      } else if (entry.isFile()) {
        if (this.isIncluded(entry.name)) {
          await this.scanFile(fullPath);
        }
      }
    }
  }

  /**
   * Check if path should be excluded
   */
  private isExcluded(fullPath: string, name: string): boolean {
    const excludePatterns = this.config.excludePatterns || DEFAULT_EXCLUDE_PATTERNS;

    for (const pattern of excludePatterns) {
      if (pattern.includes('*')) {
        // Glob pattern
        const regex = new RegExp(
          '^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$'
        );
        if (regex.test(name)) return true;
      } else {
        // Exact match
        if (name === pattern || fullPath.includes(`/${pattern}/`)) return true;
      }
    }

    return false;
  }

  /**
   * Check if file should be included
   */
  private isIncluded(fileName: string): boolean {
    const includePatterns = this.config.includePatterns || DEFAULT_INCLUDE_PATTERNS;

    for (const pattern of includePatterns) {
      if (pattern.includes('*')) {
        const regex = new RegExp(
          '^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$'
        );
        if (regex.test(fileName)) return true;
      } else {
        if (fileName === pattern) return true;
      }
    }

    return false;
  }

  /**
   * Scan a single file
   */
  private async scanFile(filePath: string): Promise<void> {
    try {
      // Check file size
      const stats = statSync(filePath);
      if (this.config.maxFileSize && stats.size > this.config.maxFileSize) {
        return;
      }

      // Detect language
      const language = detectLanguage(filePath);
      if (language === 'unknown') {
        return;
      }

      // Filter languages if specified
      if (this.config.languages && this.config.languages.length > 0) {
        if (!this.config.languages.includes(language)) {
          return;
        }
      }

      // Read file content
      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      this.filesScanned++;
      this.linesScanned += lines.length;

      // Get patterns for this language
      const languagePatterns = this.patterns.filter((p) => p.languages.includes(language));

      // Scan with each pattern
      for (const pattern of languagePatterns) {
        const findings = this.findVulnerabilities(filePath, content, lines, pattern, language);
        this.vulnerabilities.push(...findings);
      }
    } catch (error) {
      // Skip files that can't be read
      console.error(`Error scanning ${filePath}:`, error);
    }
  }

  /**
   * Find vulnerabilities matching a pattern
   */
  private findVulnerabilities(
    filePath: string,
    content: string,
    lines: string[],
    pattern: VulnerabilityPattern,
    language: Language
  ): Vulnerability[] {
    const findings: Vulnerability[] = [];

    for (const regex of pattern.patterns) {
      // Reset regex state
      regex.lastIndex = 0;

      let match;
      while ((match = regex.exec(content)) !== null) {
        // Find line number
        const matchIndex = match.index;
        let lineNumber = 1;
        let charCount = 0;

        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1; // +1 for newline
          if (charCount > matchIndex) {
            lineNumber = i + 1;
            break;
          }
        }

        // Check anti-patterns (safe usage)
        const lineContent = lines[lineNumber - 1] || '';
        const contextStart = Math.max(0, lineNumber - 5);
        const contextEnd = Math.min(lines.length, lineNumber + 5);
        const context = lines.slice(contextStart, contextEnd);
        const contextString = context.join('\n');

        if (pattern.antiPatterns) {
          const isSafe = pattern.antiPatterns.some((ap) => {
            ap.lastIndex = 0;
            return ap.test(lineContent) || ap.test(contextString);
          });
          if (isSafe) continue;
        }

        // Determine confidence based on context
        const confidence = this.assessConfidence(pattern, lineContent, contextString);

        // Skip low confidence if context required
        if (pattern.contextRequired && confidence === 'low') {
          continue;
        }

        // Create vulnerability
        const vulnerability = this.createVulnerability(
          filePath,
          pattern,
          lineNumber,
          lineContent,
          context,
          match[0],
          confidence,
          language
        );

        findings.push(vulnerability);

        // Prevent infinite loops
        if (regex.lastIndex === match.index) {
          regex.lastIndex++;
        }
      }
    }

    // Deduplicate by location
    const seen = new Set<string>();
    return findings.filter((v) => {
      const key = `${v.location.file}:${v.location.startLine}:${v.patternId}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Assess confidence level based on context
   */
  private assessConfidence(
    pattern: VulnerabilityPattern,
    lineContent: string,
    contextString: string
  ): 'high' | 'medium' | 'low' {
    // Check for obvious indicators
    const highConfidenceIndicators = [
      /user[\s_-]*input/i,
      /req\.(body|params|query)/i,
      /request\./i,
      /\$_(GET|POST|REQUEST)/i,
      /unsanitized/i,
      /FIXME.*security/i,
      /TODO.*security/i,
    ];

    const lowConfidenceIndicators = [
      /test/i,
      /mock/i,
      /example/i,
      /sample/i,
      /demo/i,
      /\/\/.*(safe|sanitized|validated)/i,
    ];

    // Check high confidence
    for (const indicator of highConfidenceIndicators) {
      if (indicator.test(lineContent) || indicator.test(contextString)) {
        return 'high';
      }
    }

    // Check low confidence
    for (const indicator of lowConfidenceIndicators) {
      if (indicator.test(lineContent) || indicator.test(contextString)) {
        return 'low';
      }
    }

    return 'medium';
  }

  /**
   * Create a vulnerability finding
   */
  private createVulnerability(
    filePath: string,
    pattern: VulnerabilityPattern,
    lineNumber: number,
    lineContent: string,
    context: string[],
    matchedCode: string,
    confidence: 'high' | 'medium' | 'low',
    language: Language
  ): Vulnerability {
    const relPath = relative(this.config.targetPath, filePath);

    const location: CodeLocation = {
      file: relPath,
      startLine: lineNumber,
      endLine: lineNumber,
      snippet: lineContent.trim(),
      context: context,
    };

    // Generate fix if enabled
    let fix: ProposedFix | undefined;
    if (this.config.generateFixes) {
      fix = this.generateFix(pattern, lineContent, matchedCode, language);
    }

    return {
      id: uuidv4(),
      patternId: pattern.id,
      name: pattern.name,
      description: pattern.description,
      category: pattern.category,
      severity: pattern.severity,
      confidence,
      location,
      cwe: pattern.cwe,
      owasp: pattern.owasp,
      impact: this.generateImpactDescription(pattern),
      recommendation: pattern.fixTemplate || 'Review and fix the security issue.',
      fix,
      references: pattern.references,
    };
  }

  /**
   * Generate impact description
   */
  private generateImpactDescription(pattern: VulnerabilityPattern): string {
    const impacts: Record<string, string> = {
      injection: 'Attackers could execute arbitrary code or commands, potentially taking full control of the system or accessing sensitive data.',
      xss: 'Attackers could execute malicious scripts in users\' browsers, steal session cookies, or perform actions on behalf of users.',
      broken_auth: 'Attackers could bypass authentication, impersonate users, or gain unauthorized access to protected resources.',
      sensitive_data: 'Sensitive information such as credentials, personal data, or financial information could be exposed to unauthorized parties.',
      broken_access: 'Attackers could access unauthorized data or functionality, potentially viewing or modifying resources they shouldn\'t have access to.',
      security_misconfig: 'System misconfiguration could expose sensitive information, enable attacks, or weaken overall security posture.',
      crypto_issues: 'Weak cryptography could allow attackers to decrypt sensitive data, forge signatures, or bypass security controls.',
      hardcoded_secrets: 'Exposed credentials could allow attackers to gain unauthorized access to systems, APIs, or sensitive data.',
      ssrf: 'Attackers could access internal services, scan internal networks, or exfiltrate data through the server.',
      path_traversal: 'Attackers could read or write arbitrary files on the server, potentially accessing sensitive configuration or executing code.',
      insecure_deserial: 'Attackers could execute arbitrary code by providing malicious serialized data.',
      memory_safety: 'Memory corruption could lead to arbitrary code execution, system crashes, or information disclosure.',
    };

    return impacts[pattern.category] || 'This vulnerability could compromise the security of the application.';
  }

  /**
   * Generate a fix suggestion
   */
  private generateFix(
    pattern: VulnerabilityPattern,
    lineContent: string,
    matchedCode: string,
    language: Language
  ): ProposedFix | undefined {
    // Generate language-specific fixes for common patterns
    const fixes = this.getFixSuggestions(pattern, language);

    if (!fixes) {
      return {
        description: pattern.fixTemplate || 'Fix the security vulnerability',
        originalCode: lineContent.trim(),
        fixedCode: '// TODO: Apply security fix\n' + lineContent.trim(),
        explanation: pattern.fixTemplate || 'Review and apply appropriate security measures.',
        breakingChange: false,
      };
    }

    return fixes;
  }

  /**
   * Get language-specific fix suggestions
   */
  private getFixSuggestions(pattern: VulnerabilityPattern, language: Language): ProposedFix | undefined {
    const fixMap: Record<string, Record<string, ProposedFix>> = {
      SQL001: {
        javascript: {
          description: 'Use parameterized queries instead of string concatenation',
          originalCode: 'db.query("SELECT * FROM users WHERE id = " + userId)',
          fixedCode: 'db.query("SELECT * FROM users WHERE id = ?", [userId])',
          explanation: 'Parameterized queries prevent SQL injection by separating SQL code from data.',
          breakingChange: false,
          testSuggestions: ['Test with special characters in input: \' OR 1=1 --'],
        },
        python: {
          description: 'Use parameterized queries with placeholders',
          originalCode: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
          fixedCode: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
          explanation: 'Use placeholder syntax and pass parameters separately.',
          breakingChange: false,
        },
      },
      CMD001: {
        javascript: {
          description: 'Use spawn with array arguments instead of exec with string',
          originalCode: 'exec("ls " + userInput)',
          fixedCode: 'spawn("ls", [userInput], { shell: false })',
          explanation: 'spawn with array arguments prevents command injection by not using shell interpretation.',
          breakingChange: false,
        },
        python: {
          description: 'Use subprocess with list arguments',
          originalCode: 'os.system(f"ls {user_input}")',
          fixedCode: 'subprocess.run(["ls", user_input], shell=False)',
          explanation: 'Using list arguments with shell=False prevents command injection.',
          breakingChange: false,
        },
      },
      XSS001: {
        javascript: {
          description: 'Encode user input before rendering',
          originalCode: 'element.innerHTML = userInput',
          fixedCode: 'element.textContent = userInput',
          explanation: 'textContent automatically escapes HTML, preventing XSS.',
          breakingChange: false,
        },
      },
      SECRET001: {
        javascript: {
          description: 'Move secret to environment variable',
          originalCode: 'const apiKey = "sk_live_abc123..."',
          fixedCode: 'const apiKey = process.env.API_KEY',
          explanation: 'Store secrets in environment variables, not in source code.',
          breakingChange: true,
          testSuggestions: ['Verify environment variable is set in all environments'],
        },
        python: {
          description: 'Move secret to environment variable',
          originalCode: 'api_key = "sk_live_abc123..."',
          fixedCode: 'import os\napi_key = os.environ.get("API_KEY")',
          explanation: 'Store secrets in environment variables.',
          breakingChange: true,
        },
      },
    };

    const patternFixes = fixMap[pattern.id];
    if (patternFixes && patternFixes[language]) {
      return patternFixes[language];
    }

    return undefined;
  }

  /**
   * Build the final scan result
   */
  private buildResult(duration: number): ScanResult {
    // Calculate statistics
    const bySeverity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    const byCategory: Record<string, number> = {};

    for (const vuln of this.vulnerabilities) {
      bySeverity[vuln.severity]++;
      byCategory[vuln.category] = (byCategory[vuln.category] || 0) + 1;
    }

    // Calculate risk score
    const riskScore = this.calculateRiskScore(bySeverity);
    const riskLevel = this.getRiskLevel(riskScore);

    // Generate summary
    const summary = this.generateSummary(bySeverity, byCategory, riskScore, riskLevel);

    return {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      config: this.config,
      stats: {
        filesScanned: this.filesScanned,
        linesScanned: this.linesScanned,
        duration,
        vulnerabilitiesFound: this.vulnerabilities.length,
        bySeverity,
        byCategory,
      },
      vulnerabilities: this.vulnerabilities.sort((a, b) => {
        const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
        return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
      }),
      summary,
    };
  }

  /**
   * Calculate overall risk score (0-100)
   */
  private calculateRiskScore(bySeverity: Record<Severity, number>): number {
    const weights = {
      critical: 40,
      high: 25,
      medium: 10,
      low: 3,
      informational: 1,
    };

    let score = 0;
    for (const [severity, count] of Object.entries(bySeverity)) {
      score += weights[severity as Severity] * count;
    }

    // Cap at 100
    return Math.min(100, score);
  }

  /**
   * Get risk level from score
   */
  private getRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'none' {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    if (score > 0) return 'low';
    return 'none';
  }

  /**
   * Generate scan summary
   */
  private generateSummary(
    bySeverity: Record<Severity, number>,
    byCategory: Record<string, number>,
    riskScore: number,
    riskLevel: string
  ): ScanResult['summary'] {
    const topIssues: string[] = [];
    const recommendations: string[] = [];

    // Top issues by category
    const sortedCategories = Object.entries(byCategory)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    for (const [category, count] of sortedCategories) {
      topIssues.push(`${category.replace(/_/g, ' ')}: ${count} issue${count > 1 ? 's' : ''}`);
    }

    // Generate recommendations
    if (bySeverity.critical > 0) {
      recommendations.push('CRITICAL: Address critical vulnerabilities immediately - they pose immediate risk.');
    }
    if (bySeverity.high > 0) {
      recommendations.push('HIGH: Remediate high-severity issues before deploying to production.');
    }
    if (byCategory.hardcoded_secrets > 0) {
      recommendations.push('Rotate all exposed secrets immediately and move to environment variables.');
    }
    if (byCategory.injection > 0) {
      recommendations.push('Review all user input handling and implement parameterized queries.');
    }
    if (byCategory.xss > 0) {
      recommendations.push('Implement output encoding and Content Security Policy.');
    }
    if (byCategory.crypto_issues > 0) {
      recommendations.push('Upgrade to modern cryptographic algorithms (AES-256, SHA-256+, Argon2).');
    }

    // Compliance gaps
    const complianceGaps: string[] = [];
    if (byCategory.hardcoded_secrets > 0 || byCategory.sensitive_data > 0) {
      complianceGaps.push('PCI-DSS: Requirement 3 (Protect Cardholder Data)');
    }
    if (byCategory.broken_auth > 0 || byCategory.broken_access > 0) {
      complianceGaps.push('GDPR: Article 32 (Security of Processing)');
    }

    return {
      riskScore,
      riskLevel: riskLevel as 'critical' | 'high' | 'medium' | 'low' | 'none',
      topIssues,
      recommendations,
      complianceGaps: complianceGaps.length > 0 ? complianceGaps : undefined,
    };
  }
}

/**
 * Quick scan helper function
 */
export async function scanPath(targetPath: string, options?: Partial<ScanConfig>): Promise<ScanResult> {
  const scanner = new CodeScanner({
    targetPath,
    recursive: true,
    ...options,
  });
  return scanner.scan();
}
