import { z } from 'zod';

// ============================================================================
// Vulnerability Classification
// ============================================================================

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'informational']);
export type Severity = z.infer<typeof SeveritySchema>;

export const VulnerabilityCategory = z.enum([
  'injection',           // SQL, NoSQL, Command, LDAP injection
  'broken_auth',         // Authentication/session issues
  'sensitive_data',      // Data exposure, weak crypto
  'xxe',                 // XML External Entities
  'broken_access',       // Access control failures
  'security_misconfig',  // Misconfigurations
  'xss',                 // Cross-site scripting
  'insecure_deserial',   // Insecure deserialization
  'vulnerable_deps',     // Known vulnerable components
  'insufficient_logging', // Logging/monitoring gaps
  'ssrf',                // Server-side request forgery
  'path_traversal',      // Path/directory traversal
  'race_condition',      // Race conditions/TOCTOU
  'memory_safety',       // Buffer overflow, use-after-free
  'crypto_issues',       // Weak cryptography
  'hardcoded_secrets',   // Hardcoded credentials/keys
]);

export type VulnerabilityCategoryType = z.infer<typeof VulnerabilityCategory>;

export const LanguageSchema = z.enum([
  'javascript',
  'typescript',
  'python',
  'java',
  'go',
  'rust',
  'c',
  'cpp',
  'csharp',
  'php',
  'ruby',
  'swift',
  'kotlin',
  'scala',
  'shell',
  'sql',
  'yaml',
  'json',
  'dockerfile',
  'terraform',
  'unknown',
]);

export type Language = z.infer<typeof LanguageSchema>;

// ============================================================================
// Vulnerability Patterns
// ============================================================================

export interface VulnerabilityPattern {
  id: string;
  name: string;
  description: string;
  category: VulnerabilityCategoryType;
  severity: Severity;
  cwe: string[];           // CWE identifiers
  owasp: string[];         // OWASP Top 10 references
  languages: Language[];
  patterns: RegExp[];
  antiPatterns?: RegExp[]; // Patterns that indicate safe usage
  contextRequired?: boolean;
  fixTemplate?: string;
  references: string[];
}

export interface CodeLocation {
  file: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  snippet: string;
  context?: string[];      // Surrounding lines for context
}

export interface Vulnerability {
  id: string;
  patternId: string;
  name: string;
  description: string;
  category: VulnerabilityCategoryType;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  location: CodeLocation;
  cwe: string[];
  owasp: string[];
  impact: string;
  recommendation: string;
  fix?: ProposedFix;
  references: string[];
  metadata?: Record<string, any>;
}

export interface ProposedFix {
  description: string;
  originalCode: string;
  fixedCode: string;
  explanation: string;
  breakingChange: boolean;
  testSuggestions?: string[];
}

// ============================================================================
// Scan Configuration
// ============================================================================

export interface ScanConfig {
  // Target
  targetPath: string;
  recursive: boolean;
  includePatterns?: string[];
  excludePatterns?: string[];

  // Scan options
  languages?: Language[];
  categories?: VulnerabilityCategoryType[];
  minSeverity?: Severity;
  maxFileSize?: number;      // bytes

  // Analysis options
  deepAnalysis?: boolean;    // Enable context-aware analysis
  generateFixes?: boolean;   // Auto-generate fix suggestions
  checkDependencies?: boolean;

  // Output
  outputFormat?: 'json' | 'markdown' | 'sarif';
  outputPath?: string;
}

export interface ScanResult {
  id: string;
  timestamp: string;
  config: ScanConfig;

  // Statistics
  stats: {
    filesScanned: number;
    linesScanned: number;
    duration: number;        // milliseconds
    vulnerabilitiesFound: number;
    bySeverity: Record<Severity, number>;
    byCategory: Record<string, number>;
  };

  // Findings
  vulnerabilities: Vulnerability[];

  // Summary
  summary: ScanSummary;
}

export interface ScanSummary {
  riskScore: number;         // 0-100
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  topIssues: string[];
  recommendations: string[];
  complianceGaps?: string[]; // OWASP, PCI-DSS, etc.
}

// ============================================================================
// Security Report
// ============================================================================

export interface SecurityReport {
  metadata: {
    generatedAt: string;
    scanId: string;
    targetPath: string;
    gideonVersion: string;
  };

  executiveSummary: {
    overallRisk: string;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    topVulnerabilities: string[];
    immediateActions: string[];
  };

  findings: Array<{
    id: string;
    title: string;
    severity: Severity;
    category: string;
    location: string;
    description: string;
    impact: string;
    recommendation: string;
    cweReference: string;
    owaspReference: string;
    codeSnippet: string;
    proposedFix?: string;
  }>;

  technicalDetails: {
    filesAnalyzed: string[];
    languagesDetected: Language[];
    scanDuration: string;
    patternsChecked: number;
  };

  remediationPlan: Array<{
    priority: number;
    issue: string;
    effort: 'low' | 'medium' | 'high';
    recommendation: string;
  }>;
}

// ============================================================================
// Dependency Scanning
// ============================================================================

export interface DependencyVulnerability {
  package: string;
  version: string;
  vulnerableVersions: string;
  severity: Severity;
  cve: string[];
  description: string;
  fixedVersion?: string;
  recommendation: string;
}

export interface DependencyScanResult {
  packageManager: string;
  manifestFile: string;
  dependencies: number;
  vulnerabilities: DependencyVulnerability[];
}
