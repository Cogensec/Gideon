import { v4 as uuidv4 } from 'uuid';
import { existsSync, statSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import {
  HardeningAuditResult,
  HardeningCheck,
  HardeningCategory,
  AlertSeverity,
  OpenClawSidecarConfig,
  OPENCLAW_CVES,
  OPENCLAW_DEFAULT_ALLOWED_TOOLS,
} from './types';

// ============================================================================
// Hardening Auditor & Configuration Enforcer (Workstream 4)
// Audits and enforces security best practices for OpenClaw deployments
// ============================================================================

/**
 * Hardening Auditor - Assesses OpenClaw deployment security posture
 *
 * Checks:
 * - Gateway authentication configuration
 * - Bind mode and network exposure
 * - Docker sandboxing configuration
 * - File permissions on sensitive directories
 * - Credential storage security
 * - Tool allowlist restrictions
 * - Execution approval settings
 * - Node.js version for known CVEs
 * - Skill marketplace security settings
 */
export class HardeningAuditor {
  private config: OpenClawSidecarConfig;
  private openclawHome: string;
  private auditHistory: HardeningAuditResult[] = [];
  private lastAuditResult: HardeningAuditResult | null = null;

  constructor(config: OpenClawSidecarConfig) {
    this.config = config;
    this.openclawHome = config.gateway.openclawHome.replace(/^~/, process.env.HOME || '/root');
  }

  /**
   * Run a full hardening audit
   */
  async runAudit(): Promise<HardeningAuditResult> {
    const checks: HardeningCheck[] = [];

    // Run all check categories
    checks.push(...this.checkAuthentication());
    checks.push(...this.checkNetwork());
    checks.push(...this.checkSandboxing());
    checks.push(...this.checkFilePermissions());
    checks.push(...this.checkCredentialStorage());
    checks.push(...this.checkToolRestrictions());
    checks.push(...this.checkRuntimeVersion());
    checks.push(...this.checkSkillSecurity());

    // Calculate scores
    const { score, grade, criticalFindings, highFindings, mediumFindings, lowFindings } =
      this.calculateScore(checks);

    const result: HardeningAuditResult = {
      overallScore: score,
      grade,
      checks,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      auditedAt: new Date().toISOString(),
    };

    this.lastAuditResult = result;
    this.auditHistory.push(result);

    return result;
  }

  /**
   * Check authentication configuration
   */
  private checkAuthentication(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];

    // Check if gateway auth token is configured
    const hasAuthToken = !!this.config.gateway.authToken ||
      !!process.env.OPENCLAW_GATEWAY_TOKEN;

    checks.push({
      id: 'auth-001',
      name: 'Gateway Authentication Token',
      description: 'Gateway must require authentication for all connections',
      category: 'authentication',
      status: hasAuthToken ? 'pass' : 'fail',
      severity: 'critical',
      currentValue: hasAuthToken ? 'Configured' : 'Not configured',
      expectedValue: 'Token set via gateway.auth.token or OPENCLAW_GATEWAY_TOKEN',
      recommendation: hasAuthToken
        ? 'Token is configured. Ensure it uses a cryptographically random value (32+ chars).'
        : 'Set gateway.auth.token in OpenClaw configuration or OPENCLAW_GATEWAY_TOKEN environment variable. ' +
          'Without auth, anyone on the network can control your agent.',
      cveReferences: ['CVE-2026-25253'],
    });

    // Check token strength (if available)
    const token = this.config.gateway.authToken || process.env.OPENCLAW_GATEWAY_TOKEN || '';
    if (token.length > 0 && token.length < 32) {
      checks.push({
        id: 'auth-002',
        name: 'Authentication Token Strength',
        description: 'Gateway auth token should be cryptographically strong',
        category: 'authentication',
        status: 'fail',
        severity: 'high',
        currentValue: `${token.length} characters`,
        expectedValue: '32+ characters, cryptographically random',
        recommendation: 'Use a token of at least 32 random characters. ' +
          'Generate one with: openssl rand -hex 32',
      });
    } else if (token.length >= 32) {
      checks.push({
        id: 'auth-002',
        name: 'Authentication Token Strength',
        description: 'Gateway auth token should be cryptographically strong',
        category: 'authentication',
        status: 'pass',
        severity: 'high',
        currentValue: `${token.length} characters`,
        expectedValue: '32+ characters',
        recommendation: 'Token meets minimum length requirement.',
      });
    }

    return checks;
  }

  /**
   * Check network bind mode and exposure
   */
  private checkNetwork(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];
    const bindMode = this.config.gateway.bindMode;

    checks.push({
      id: 'net-001',
      name: 'Gateway Bind Mode',
      description: 'Gateway should bind to localhost only unless explicitly needed',
      category: 'network',
      status: bindMode === 'localhost' ? 'pass' :
              bindMode === 'tailnet' ? 'warning' : 'fail',
      severity: bindMode === 'custom' || bindMode === 'lan' ? 'critical' : 'high',
      currentValue: bindMode,
      expectedValue: 'localhost (or tailnet with auth)',
      recommendation: bindMode === 'localhost'
        ? 'Gateway is bound to localhost only - good.'
        : bindMode === 'tailnet'
        ? 'Tailnet binding is acceptable but ensure gateway auth is configured.'
        : `Bind mode "${bindMode}" exposes the gateway to the network. ` +
          'Use localhost binding and SSH tunnels for remote access instead.',
    });

    // Check if non-localhost binding has auth
    if (bindMode !== 'localhost') {
      const hasAuth = !!this.config.gateway.authToken ||
        !!process.env.OPENCLAW_GATEWAY_TOKEN;

      checks.push({
        id: 'net-002',
        name: 'Network-Exposed Gateway Auth',
        description: 'Non-localhost gateway must have authentication enabled',
        category: 'network',
        status: hasAuth ? 'pass' : 'fail',
        severity: 'critical',
        currentValue: hasAuth ? 'Auth enabled' : 'No authentication',
        expectedValue: 'Authentication required for non-localhost bind',
        recommendation: hasAuth
          ? 'Authentication is enabled for network-exposed gateway.'
          : 'CRITICAL: Gateway is network-exposed without authentication. ' +
            'Any device on the network can control your agent. ' +
            'Set gateway.auth.token immediately or switch to localhost binding.',
        cveReferences: ['CVE-2026-25253'],
      });
    }

    // WebSocket origin validation
    checks.push({
      id: 'net-003',
      name: 'WebSocket Origin Validation',
      description: 'Gateway should validate WebSocket connection origins',
      category: 'network',
      status: 'warning', // Can't fully verify without checking OpenClaw version
      severity: 'high',
      recommendation: 'Ensure OpenClaw >= v2026.1.29 which adds WebSocket origin validation. ' +
        'Earlier versions are vulnerable to CVE-2026-25253 cross-site WebSocket hijacking.',
      cveReferences: ['CVE-2026-25253'],
    });

    return checks;
  }

  /**
   * Check Docker sandboxing configuration
   */
  private checkSandboxing(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];

    // Read OpenClaw config to check sandbox settings
    const openclawConfig = this.readOpenClawConfig();

    const sandboxEnabled = openclawConfig?.agents?.defaults?.sandbox?.docker?.enabled === true;
    const sandboxNetwork = openclawConfig?.agents?.defaults?.sandbox?.docker?.network;

    checks.push({
      id: 'sandbox-001',
      name: 'Docker Sandboxing Enabled',
      description: 'Agent exec commands should run in Docker containers',
      category: 'sandboxing',
      status: sandboxEnabled ? 'pass' : 'fail',
      severity: 'critical',
      currentValue: sandboxEnabled ? 'Enabled' : 'Disabled (opt-in, off by default)',
      expectedValue: 'Enabled',
      recommendation: sandboxEnabled
        ? 'Docker sandboxing is enabled.'
        : 'CRITICAL: Docker sandboxing is disabled. Agent exec commands run directly on the host. ' +
          'Enable it in OpenClaw config: agents.defaults.sandbox.docker.enabled = true',
    });

    if (sandboxEnabled) {
      checks.push({
        id: 'sandbox-002',
        name: 'Sandbox Network Isolation',
        description: 'Sandboxed containers should have no network access by default',
        category: 'sandboxing',
        status: sandboxNetwork === 'none' ? 'pass' : 'fail',
        severity: 'high',
        currentValue: sandboxNetwork || 'default (bridge)',
        expectedValue: 'none',
        recommendation: sandboxNetwork === 'none'
          ? 'Sandbox network is set to none - no egress possible.'
          : 'Set sandbox docker network to "none" to prevent containers from making network connections. ' +
            'This prevents data exfiltration from sandboxed commands.',
      });

      // Check resource limits
      const hasMemoryLimit = !!openclawConfig?.agents?.defaults?.sandbox?.docker?.memory;
      const hasPidsLimit = !!openclawConfig?.agents?.defaults?.sandbox?.docker?.pidsLimit;

      checks.push({
        id: 'sandbox-003',
        name: 'Sandbox Resource Limits',
        description: 'Containers should have memory and process limits',
        category: 'sandboxing',
        status: hasMemoryLimit && hasPidsLimit ? 'pass' : 'warning',
        severity: 'medium',
        currentValue: `Memory: ${hasMemoryLimit ? 'Set' : 'Unlimited'}, PIDs: ${hasPidsLimit ? 'Set' : 'Unlimited'}`,
        expectedValue: 'Both memory and PID limits configured',
        recommendation: 'Set resource limits to prevent container-based denial of service. ' +
          'Recommended: memory=512m, pidsLimit=100',
      });
    }

    return checks;
  }

  /**
   * Check file permissions on sensitive directories
   */
  private checkFilePermissions(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];

    const sensitivePaths = [
      { path: this.openclawHome, name: 'OpenClaw Home Directory', expected: '700' },
      { path: join(this.openclawHome, 'credentials'), name: 'Credentials Directory', expected: '700' },
    ];

    for (const { path, name, expected } of sensitivePaths) {
      const resolvedPath = resolve(path);

      if (!existsSync(resolvedPath)) {
        checks.push({
          id: `perms-${name.toLowerCase().replace(/\s/g, '-')}`,
          name: `${name} Permissions`,
          description: `${name} should have restricted permissions`,
          category: 'file_permissions',
          status: 'not_applicable',
          severity: 'high',
          currentValue: 'Path does not exist',
          expectedValue: expected,
          recommendation: `Path ${resolvedPath} not found. Verify OpenClaw home directory location.`,
        });
        continue;
      }

      try {
        const stats = statSync(resolvedPath);
        const mode = (stats.mode & 0o777).toString(8);
        const isSecure = mode === expected || parseInt(mode, 8) <= parseInt(expected, 8);

        checks.push({
          id: `perms-${name.toLowerCase().replace(/\s/g, '-')}`,
          name: `${name} Permissions`,
          description: `${name} should have restricted permissions`,
          category: 'file_permissions',
          status: isSecure ? 'pass' : 'fail',
          severity: 'high',
          currentValue: mode,
          expectedValue: expected,
          recommendation: isSecure
            ? `Permissions are secure (${mode}).`
            : `Set permissions: chmod ${expected} ${resolvedPath}. ` +
              `Current permissions (${mode}) are too permissive.`,
        });
      } catch {
        checks.push({
          id: `perms-${name.toLowerCase().replace(/\s/g, '-')}`,
          name: `${name} Permissions`,
          description: `${name} should have restricted permissions`,
          category: 'file_permissions',
          status: 'warning',
          severity: 'high',
          recommendation: `Unable to check permissions for ${resolvedPath}. Verify manually.`,
        });
      }
    }

    return checks;
  }

  /**
   * Check credential storage security
   */
  private checkCredentialStorage(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];

    // Check for plaintext credential files
    const credentialFiles = [
      'credentials/*.json',
      'agents/*/agent/auth-profiles.json',
      'agents/*/sessions/sessions.json',
    ];

    checks.push({
      id: 'cred-001',
      name: 'Credential Encryption at Rest',
      description: 'Credentials should be encrypted at rest, not stored in plaintext',
      category: 'credential_storage',
      status: 'fail', // OpenClaw stores everything in plaintext
      severity: 'critical',
      currentValue: 'Plaintext (JSON/Markdown files)',
      expectedValue: 'Encrypted at rest',
      recommendation: 'OpenClaw stores all credentials, API keys, tokens, and conversation histories ' +
        'in plaintext. Deploy Gideon Credential Guard to monitor access patterns. ' +
        'Consider using OS keychain or external secrets manager for API keys. ' +
        'Set file permissions to 600 for all credential files.',
    });

    // Check for API keys in environment
    const exposedKeys = [
      'OPENCLAW_GATEWAY_TOKEN',
      'ANTHROPIC_API_KEY',
      'OPENAI_API_KEY',
      'DEEPSEEK_API_KEY',
    ];

    const envKeysFound = exposedKeys.filter(key => !!process.env[key]);
    checks.push({
      id: 'cred-002',
      name: 'API Key Environment Variables',
      description: 'API keys in environment should be from secure sources',
      category: 'credential_storage',
      status: envKeysFound.length > 0 ? 'warning' : 'not_applicable',
      severity: 'medium',
      currentValue: `${envKeysFound.length} API keys in environment`,
      recommendation: 'Prefer loading API keys from encrypted files or secret managers ' +
        'rather than environment variables, which can be read by any process under the same user.',
    });

    return checks;
  }

  /**
   * Check tool allowlist restrictions
   */
  private checkToolRestrictions(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];
    const openclawConfig = this.readOpenClawConfig();

    // Check if exec is in the allowlist (it is by default)
    const allowedTools = openclawConfig?.agents?.defaults?.tools?.allow || OPENCLAW_DEFAULT_ALLOWED_TOOLS;
    const execAllowed = allowedTools.includes('exec');

    checks.push({
      id: 'tools-001',
      name: 'Shell Execution Default',
      description: 'Shell execution (exec) should not be allowed by default',
      category: 'tool_restrictions',
      status: execAllowed ? 'fail' : 'pass',
      severity: 'critical',
      currentValue: execAllowed ? 'exec is ALLOWED by default' : 'exec is denied by default',
      expectedValue: 'exec denied by default, allowed only when needed',
      recommendation: execAllowed
        ? 'Shell execution is allowed by default in OpenClaw. This means any agent session ' +
          'can execute arbitrary commands on your system. Move "exec" from the allow list to the deny ' +
          'list and enable it only for specific trusted sessions.'
        : 'Shell execution is properly restricted.',
    });

    // Check if execution approvals are enabled
    const approvals = openclawConfig?.agents?.defaults?.exec?.approvals;
    checks.push({
      id: 'tools-002',
      name: 'Execution Approval Requirement',
      description: 'Shell command execution should require user approval',
      category: 'tool_restrictions',
      status: approvals === 'on' || approvals === true ? 'pass' : 'fail',
      severity: 'high',
      currentValue: approvals ? `${approvals}` : 'Not configured (likely off)',
      expectedValue: 'on',
      recommendation: 'Enable execution approvals: set exec.approvals = on in your OpenClaw config. ' +
        'This prevents the agent from running shell commands without your explicit confirmation. ' +
        'Disabling approvals is a key step in the CVE-2026-25253 kill chain.',
      cveReferences: ['CVE-2026-25253'],
    });

    return checks;
  }

  /**
   * Check Node.js runtime version for known vulnerabilities
   */
  private checkRuntimeVersion(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0], 10);

    checks.push({
      id: 'runtime-001',
      name: 'Node.js Version',
      description: 'Node.js must be patched for known vulnerabilities',
      category: 'runtime_version',
      status: majorVersion >= 22 ? 'pass' : 'warning',
      severity: 'high',
      currentValue: nodeVersion,
      expectedValue: '>= 22.12.0 with security patches',
      recommendation: majorVersion >= 22
        ? `Node.js ${nodeVersion} meets the minimum requirement. ` +
          'Ensure it includes fixes for CVE-2025-59466 (async_hooks DoS) and ' +
          'CVE-2026-21636 (permission model bypass).'
        : 'OpenClaw requires Node.js >= 22.12.0. Upgrade to the latest LTS release.',
    });

    return checks;
  }

  /**
   * Check skill marketplace security
   */
  private checkSkillSecurity(): HardeningCheck[] {
    const checks: HardeningCheck[] = [];

    checks.push({
      id: 'skill-001',
      name: 'ClawHub Skill Vetting',
      description: 'Skills from ClawHub should be scanned before installation',
      category: 'skill_security',
      status: this.config.skillScanner.enabled ? 'pass' : 'fail',
      severity: 'critical',
      currentValue: this.config.skillScanner.enabled ? 'Gideon Skill Scanner enabled' : 'No scanning',
      expectedValue: 'Automated scanning enabled',
      recommendation: this.config.skillScanner.enabled
        ? 'Gideon Skill Scanner is active. All ClawHub skills will be vetted before installation.'
        : 'Enable Gideon Skill Scanner. Over 800 malicious skills have been found on ClawHub, ' +
          'including the ClawHavoc campaign (341 skills distributing AMOS stealer). ' +
          'Never install skills without scanning.',
    });

    return checks;
  }

  // --- Helper Methods ---

  /**
   * Read OpenClaw configuration file
   */
  private readOpenClawConfig(): Record<string, any> | null {
    const configPaths = [
      join(this.openclawHome, 'config.json'),
      join(this.openclawHome, 'config.yaml'),
      join(this.openclawHome, 'config.yml'),
      join(this.openclawHome, 'gateway.json'),
    ];

    for (const configPath of configPaths) {
      if (existsSync(configPath)) {
        try {
          const content = readFileSync(configPath, 'utf-8');
          return JSON.parse(content);
        } catch {
          // Not JSON or malformed
        }
      }
    }

    return null;
  }

  /**
   * Calculate overall audit score
   */
  private calculateScore(checks: HardeningCheck[]): {
    score: number;
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
  } {
    let score = 100;
    let criticalFindings = 0;
    let highFindings = 0;
    let mediumFindings = 0;
    let lowFindings = 0;

    for (const check of checks) {
      if (check.status === 'fail') {
        switch (check.severity) {
          case 'critical': score -= 20; criticalFindings++; break;
          case 'high': score -= 12; highFindings++; break;
          case 'medium': score -= 6; mediumFindings++; break;
          case 'low': score -= 3; lowFindings++; break;
        }
      } else if (check.status === 'warning') {
        switch (check.severity) {
          case 'critical': score -= 10; break;
          case 'high': score -= 6; break;
          case 'medium': score -= 3; break;
          case 'low': score -= 1; break;
        }
      }
    }

    score = Math.max(0, Math.min(100, score));

    const grade: 'A' | 'B' | 'C' | 'D' | 'F' =
      score >= 90 ? 'A' :
      score >= 75 ? 'B' :
      score >= 60 ? 'C' :
      score >= 40 ? 'D' : 'F';

    return { score, grade, criticalFindings, highFindings, mediumFindings, lowFindings };
  }

  /**
   * Detect configuration drift from last audit
   */
  detectDrift(): HardeningCheck[] | null {
    if (!this.lastAuditResult || !this.config.hardeningAuditor.detectDrift) return null;

    const drifted: HardeningCheck[] = [];
    const currentChecks = [
      ...this.checkAuthentication(),
      ...this.checkNetwork(),
      ...this.checkSandboxing(),
      ...this.checkToolRestrictions(),
    ];

    for (const current of currentChecks) {
      const previous = this.lastAuditResult.checks.find(c => c.id === current.id);
      if (previous && previous.status === 'pass' && current.status === 'fail') {
        drifted.push({
          ...current,
          description: `DRIFT: ${current.name} changed from pass to fail since last audit`,
        });
      }
    }

    return drifted.length > 0 ? drifted : null;
  }

  /**
   * Get formatted audit report
   */
  formatAuditReport(result: HardeningAuditResult): string {
    const lines: string[] = [
      '# OpenClaw Hardening Audit Report',
      '',
      `**Overall Score:** ${result.overallScore}/100 (Grade: ${result.grade})`,
      `**Audited:** ${result.auditedAt}`,
      '',
      '## Finding Summary',
      '',
      `| Severity | Count |`,
      `|----------|-------|`,
      `| Critical | ${result.criticalFindings} |`,
      `| High     | ${result.highFindings} |`,
      `| Medium   | ${result.mediumFindings} |`,
      `| Low      | ${result.lowFindings} |`,
      '',
      '## Detailed Findings',
      '',
    ];

    // Group by category
    const byCategory = new Map<string, HardeningCheck[]>();
    for (const check of result.checks) {
      if (!byCategory.has(check.category)) {
        byCategory.set(check.category, []);
      }
      byCategory.get(check.category)!.push(check);
    }

    for (const [category, categoryChecks] of byCategory) {
      lines.push(`### ${category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}`);
      lines.push('');

      for (const check of categoryChecks) {
        const statusEmoji =
          check.status === 'pass' ? 'PASS' :
          check.status === 'fail' ? 'FAIL' :
          check.status === 'warning' ? 'WARN' : 'N/A';

        lines.push(`**[${statusEmoji}] ${check.name}** (${check.severity})`);
        lines.push(`  ${check.description}`);
        if (check.currentValue) lines.push(`  Current: ${check.currentValue}`);
        if (check.expectedValue) lines.push(`  Expected: ${check.expectedValue}`);
        lines.push(`  Recommendation: ${check.recommendation}`);
        if (check.cveReferences?.length) {
          lines.push(`  CVE References: ${check.cveReferences.join(', ')}`);
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  /**
   * Get audit history
   */
  getAuditHistory(): HardeningAuditResult[] {
    return [...this.auditHistory];
  }

  getLastAudit(): HardeningAuditResult | null {
    return this.lastAuditResult;
  }
}
