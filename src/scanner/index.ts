/**
 * Gideon Code Security Scanner
 *
 * A comprehensive security vulnerability scanner for source code.
 * Detects OWASP Top 10, CWE vulnerabilities, and provides automated fixes.
 *
 * Features:
 * - Multi-language support (JavaScript, TypeScript, Python, Java, Go, etc.)
 * - 50+ vulnerability patterns covering injection, XSS, SSRF, secrets, etc.
 * - Automated fix suggestions
 * - Multiple report formats (Markdown, JSON, SARIF)
 * - GitHub-compatible SARIF output
 */

// Types
export * from './types';

// Patterns
export {
  ALL_VULNERABILITY_PATTERNS,
  getPatternsByCategory,
  getPatternsByLanguage,
  getPatternsBySeverity,
  getPatternById,
} from './patterns';

// Scanner
export { CodeScanner, scanPath } from './scanner';

// Report Generator
export { ReportGenerator, generateReport } from './report-generator';
