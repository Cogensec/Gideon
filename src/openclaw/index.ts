/**
 * Gideon OpenClaw Sidecar Security Platform
 *
 * A comprehensive security sidecar for OpenClaw agent deployments.
 * Runs alongside OpenClaw as an independent process, monitoring
 * gateway traffic, scanning skills, defending against prompt injection,
 * auditing configuration, and protecting credentials.
 *
 * Architecture: Option A (Sidecar)
 * - Zero changes required to OpenClaw codebase
 * - Independent process monitoring via WebSocket and filesystem
 * - Users install Gideon separately and point it at their OpenClaw instance
 *
 * Addresses all known OpenClaw vulnerabilities:
 * - CVE-2026-25253: One-click RCE via token exfiltration (CVSS 8.8)
 * - CVE-2026-24763: Command injection via unsanitized gateway input
 * - CVE-2026-25157: Second command injection vulnerability
 * - CVE-2026-22708: Indirect prompt injection via web browsing
 * - ClawHavoc campaign: 341+ malicious ClawHub skills
 * - Plaintext credential storage
 * - Memory poisoning attacks
 * - Sandbox escape patterns
 */

// Types
export * from './types';

// Core Modules
export { GatewaySentinel } from './gateway-sentinel';
export { SkillScanner } from './skill-scanner';
export { PromptInjectionDefense } from './prompt-injection-defense';
export { HardeningAuditor } from './hardening-auditor';
export { CredentialGuard } from './credential-guard';
export { MemoryIntegrityMonitor } from './memory-integrity';
export { createOpenClawPolicySet } from './policy-rules';

// Internal imports for orchestrator
import { GatewaySentinel } from './gateway-sentinel';
import { SkillScanner } from './skill-scanner';
import { PromptInjectionDefense } from './prompt-injection-defense';
import { HardeningAuditor } from './hardening-auditor';
import { CredentialGuard } from './credential-guard';
import { MemoryIntegrityMonitor } from './memory-integrity';
import { createOpenClawPolicySet } from './policy-rules';
import {
  OpenClawSidecarConfig,
  OpenClawSidecarConfigSchema,
  SentinelAlert,
  GatewayMessage,
} from './types';
import { getPolicyEngine } from '../governance/policy-engine';
import { getAgentRegistry } from '../governance/agent-registry';
import { getAuditLogger } from '../governance/audit-logger';

// ============================================================================
// OpenClaw Sidecar - Unified Orchestrator
// ============================================================================

/**
 * OpenClawSidecar - Main orchestrator for all security workstreams
 *
 * Provides a single entry point to:
 * - Initialize all security modules
 * - Register OpenClaw-specific policies
 * - Monitor gateway traffic
 * - Scan skills before installation
 * - Defend against prompt injection
 * - Audit deployment hardening
 * - Guard credentials and detect exfiltration
 * - Monitor memory integrity
 */
export class OpenClawSidecar {
  readonly config: OpenClawSidecarConfig;
  readonly sentinel: GatewaySentinel;
  readonly skillScanner: SkillScanner;
  readonly injectionDefense: PromptInjectionDefense;
  readonly hardeningAuditor: HardeningAuditor;
  readonly credentialGuard: CredentialGuard;
  readonly memoryMonitor: MemoryIntegrityMonitor;

  private initialized = false;
  private alertHandlers: Array<(alert: SentinelAlert) => void> = [];

  constructor(config?: Partial<OpenClawSidecarConfig>) {
    this.config = OpenClawSidecarConfigSchema.parse(config || {});

    // Initialize all modules
    this.sentinel = new GatewaySentinel(this.config);
    this.skillScanner = new SkillScanner(this.config);
    this.injectionDefense = new PromptInjectionDefense(this.config);
    this.hardeningAuditor = new HardeningAuditor(this.config);
    this.credentialGuard = new CredentialGuard(this.config);
    this.memoryMonitor = new MemoryIntegrityMonitor(this.config);

    // Wire up sentinel alerts to unified handler
    this.sentinel.onAlert((alert) => {
      for (const handler of this.alertHandlers) {
        try { handler(alert); } catch { /* */ }
      }
    });
  }

  /**
   * Initialize the sidecar - registers policies and performs initial audit
   */
  async initialize(): Promise<{
    policiesRegistered: boolean;
    agentRegistered: boolean;
    initialAudit: { score: number; grade: string };
  }> {
    if (this.initialized) {
      const lastAudit = this.hardeningAuditor.getLastAudit();
      return {
        policiesRegistered: true,
        agentRegistered: true,
        initialAudit: {
          score: lastAudit?.overallScore || 0,
          grade: lastAudit?.grade || 'F',
        },
      };
    }

    // 1. Register OpenClaw-specific policies
    let policiesRegistered = false;
    try {
      const policyEngine = getPolicyEngine();
      const openclawPolicies = createOpenClawPolicySet();
      policyEngine.createPolicySet({
        name: openclawPolicies.name,
        description: openclawPolicies.description,
        rules: openclawPolicies.rules,
        defaultAction: openclawPolicies.defaultAction,
      });
      policiesRegistered = true;
    } catch {
      // Policy set may already exist
      policiesRegistered = true;
    }

    // 2. Register sidecar as a governed agent
    let agentRegistered = false;
    try {
      const registry = getAgentRegistry();
      const existing = registry.getAgentByName('gideon-openclaw-sentinel');
      if (!existing) {
        const agent = registry.registerAgent({
          name: 'gideon-openclaw-sentinel',
          type: 'openclaw',
          owner: 'gideon-system',
          capabilities: [
            'gateway_monitoring',
            'skill_scanning',
            'injection_defense',
            'hardening_audit',
            'credential_guard',
            'memory_integrity',
          ],
          description: 'Gideon security sidecar for OpenClaw deployments',
        });
        registry.activateAgent(agent.id);
      }
      agentRegistered = true;
    } catch {
      agentRegistered = false;
    }

    // 3. Run initial hardening audit
    const auditResult = await this.hardeningAuditor.runAudit();

    // 4. Log initialization
    try {
      const logger = getAuditLogger();
      logger.log({
        eventType: 'agent_registered',
        actor: { type: 'system', id: 'gideon-openclaw-sidecar', name: 'Gideon OpenClaw Sidecar' },
        details: {
          action: 'sidecar_initialized',
          policiesRegistered,
          agentRegistered,
          auditScore: auditResult.overallScore,
          auditGrade: auditResult.grade,
          modules: {
            sentinel: this.config.sentinel.enabled,
            skillScanner: this.config.skillScanner.enabled,
            injectionDefense: this.config.injectionDefense.enabled,
            hardeningAuditor: this.config.hardeningAuditor.enabled,
            credentialGuard: this.config.credentialGuard.enabled,
          },
        },
        outcome: 'success',
      });
    } catch { /* */ }

    this.initialized = true;

    return {
      policiesRegistered,
      agentRegistered,
      initialAudit: {
        score: auditResult.overallScore,
        grade: auditResult.grade,
      },
    };
  }

  /**
   * Subscribe to all security alerts
   */
  onAlert(handler: (alert: SentinelAlert) => void): () => void {
    this.alertHandlers.push(handler);
    return () => {
      const idx = this.alertHandlers.indexOf(handler);
      if (idx > -1) this.alertHandlers.splice(idx, 1);
    };
  }

  /**
   * Process an intercepted gateway WebSocket message through all security checks
   */
  async processGatewayMessage(rawMessage: string, sessionId?: string): Promise<{
    alerts: SentinelAlert[];
    injectionResult?: { isInjection: boolean; confidence: number };
  }> {
    // Classify the message
    const message = this.sentinel.classifyMessage(rawMessage, sessionId);

    // Run sentinel analysis
    const alerts = await this.sentinel.analyzeMessage(message);

    // If this is content from web browsing, run injection defense
    let injectionResult;
    if (message.type === 'browser_navigate' || message.type === 'tool_result') {
      const content = JSON.stringify(message.payload);
      injectionResult = await this.injectionDefense.scanContent(content, 'gateway_message');
    }

    // Track file access for credential guard
    if (message.type === 'file_read' || message.type === 'file_write') {
      const file = message.payload.path || message.payload.file || '';
      const action = message.type === 'file_read' ? 'read' : 'write';
      this.credentialGuard.recordFileAccess({
        sessionId: message.sessionId || 'unknown',
        agentId: message.agentId,
        file,
        action,
        timestamp: message.timestamp,
      });
    }

    // Track network calls for credential guard
    if (message.type === 'exec_request' || message.type === 'tool_call') {
      const content = JSON.stringify(message.payload);
      if (/(?:curl|wget|fetch|http|https|axios)/i.test(content)) {
        this.credentialGuard.recordNetworkCall({
          sessionId: message.sessionId || 'unknown',
          agentId: message.agentId,
          target: content.slice(0, 200),
          timestamp: message.timestamp,
        });
      }
    }

    // Check memory writes for poisoning
    if (message.type === 'memory_write') {
      const content = message.payload.content || JSON.stringify(message.payload);
      const entry = this.memoryMonitor.scanMemoryEntry(content, `session:${message.sessionId}`);
      if (entry) {
        alerts.push({
          id: require('crypto').randomUUID(),
          timestamp: new Date().toISOString(),
          severity: entry.severity,
          category: 'memory_poisoning',
          title: 'Memory Poisoning Attempt Detected',
          description: entry.reason,
          evidence: [{
            type: 'message',
            source: 'memory_write',
            content: entry.content,
            timestamp: message.timestamp,
          }],
          recommendation: 'Block this memory write and review the source of the content. ' +
            'Check if it originated from a web page, email, or untrusted message.',
          autoAction: 'block',
          resolved: false,
        });
      }
    }

    return { alerts, injectionResult };
  }

  /**
   * Get comprehensive security status across all modules
   */
  getStatus(): {
    initialized: boolean;
    modules: {
      sentinel: { enabled: boolean; alerts: number; sessions: number };
      skillScanner: { enabled: boolean; scans: number; blocked: number };
      injectionDefense: { enabled: boolean; scans: number; detections: number };
      hardeningAuditor: { enabled: boolean; lastScore: number | null; lastGrade: string | null };
      credentialGuard: { enabled: boolean; attempts: number; blocked: number };
      memoryMonitor: { enabled: boolean; scans: number; suspicious: number };
    };
  } {
    const sentinelStats = this.sentinel.getStats();
    const scannerStats = this.skillScanner.getStats();
    const injectionStats = this.injectionDefense.getStats();
    const lastAudit = this.hardeningAuditor.getLastAudit();
    const credentialStats = this.credentialGuard.getStats();
    const memoryStats = this.memoryMonitor.getStats();

    return {
      initialized: this.initialized,
      modules: {
        sentinel: {
          enabled: this.config.sentinel.enabled,
          alerts: sentinelStats.totalAlerts,
          sessions: sentinelStats.activeSessions,
        },
        skillScanner: {
          enabled: this.config.skillScanner.enabled,
          scans: scannerStats.totalScans,
          blocked: scannerStats.blockedSkills,
        },
        injectionDefense: {
          enabled: this.config.injectionDefense.enabled,
          scans: injectionStats.totalScans,
          detections: injectionStats.detectionsFound,
        },
        hardeningAuditor: {
          enabled: this.config.hardeningAuditor.enabled,
          lastScore: lastAudit?.overallScore || null,
          lastGrade: lastAudit?.grade || null,
        },
        credentialGuard: {
          enabled: this.config.credentialGuard.enabled,
          attempts: credentialStats.totalAttempts,
          blocked: credentialStats.blockedAttempts,
        },
        memoryMonitor: {
          enabled: true,
          scans: memoryStats.totalScans,
          suspicious: memoryStats.totalSuspiciousEntries,
        },
      },
    };
  }

  /**
   * Generate a full security report
   */
  async generateReport(): Promise<string> {
    const status = this.getStatus();
    const auditResult = this.hardeningAuditor.getLastAudit() || await this.hardeningAuditor.runAudit();
    const auditReport = this.hardeningAuditor.formatAuditReport(auditResult);

    const sentinelStats = this.sentinel.getStats();
    const scannerStats = this.skillScanner.getStats();
    const injectionStats = this.injectionDefense.getStats();
    const credentialStats = this.credentialGuard.getStats();
    const memoryStats = this.memoryMonitor.getStats();

    const lines: string[] = [
      '# Gideon OpenClaw Security Report',
      '',
      `**Generated:** ${new Date().toISOString()}`,
      `**Sidecar Status:** ${status.initialized ? 'Active' : 'Not Initialized'}`,
      '',
      '## Security Overview',
      '',
      `| Module | Status | Key Metric |`,
      `|--------|--------|------------|`,
      `| Gateway Sentinel | ${status.modules.sentinel.enabled ? 'Active' : 'Disabled'} | ${sentinelStats.unresolvedAlerts} unresolved alerts |`,
      `| Skill Scanner | ${status.modules.skillScanner.enabled ? 'Active' : 'Disabled'} | ${scannerStats.blockedSkills} skills blocked |`,
      `| Injection Defense | ${status.modules.injectionDefense.enabled ? 'Active' : 'Disabled'} | ${injectionStats.detectionsFound} injections caught |`,
      `| Hardening Auditor | ${status.modules.hardeningAuditor.enabled ? 'Active' : 'Disabled'} | Score: ${auditResult.overallScore}/100 (${auditResult.grade}) |`,
      `| Credential Guard | ${status.modules.credentialGuard.enabled ? 'Active' : 'Disabled'} | ${credentialStats.totalAttempts} exfil attempts |`,
      `| Memory Monitor | Active | ${memoryStats.totalSuspiciousEntries} suspicious entries |`,
      '',
      '## Gateway Sentinel',
      '',
      `- Total alerts: ${sentinelStats.totalAlerts}`,
      `- Unresolved: ${sentinelStats.unresolvedAlerts}`,
      `- Active sessions: ${sentinelStats.activeSessions}`,
      `- Messages analyzed: ${sentinelStats.messagesAnalyzed}`,
      '',
      '### Alerts by Severity',
      '',
      ...Object.entries(sentinelStats.bySeverity).map(([sev, count]) => `- ${sev}: ${count}`),
      '',
      '### Alerts by Category',
      '',
      ...Object.entries(sentinelStats.byCategory).map(([cat, count]) => `- ${cat}: ${count}`),
      '',
      '## Skill Scanner',
      '',
      `- Total scans: ${scannerStats.totalScans}`,
      `- Critical skills: ${scannerStats.criticalSkills}`,
      `- Blocked: ${scannerStats.blockedSkills}`,
      `- Clean: ${scannerStats.cleanSkills}`,
      `- Total findings: ${scannerStats.totalFindings}`,
      `- IOC hits: ${scannerStats.totalIOCHits}`,
      '',
      '## Prompt Injection Defense',
      '',
      `- Total scans: ${injectionStats.totalScans}`,
      `- Detections: ${injectionStats.detectionsFound}`,
      `- Detection rate: ${(injectionStats.detectionRate * 100).toFixed(1)}%`,
      '',
      '### Detections by Type',
      '',
      ...Object.entries(injectionStats.byType).map(([type, count]) => `- ${type}: ${count}`),
      '',
      '## Credential Guard',
      '',
      `- Exfiltration attempts detected: ${credentialStats.totalAttempts}`,
      `- Blocked: ${credentialStats.blockedAttempts}`,
      `- Affected sessions: ${credentialStats.affectedSessions}`,
      '',
      '## Memory Integrity',
      '',
      `- Total scans: ${memoryStats.totalScans}`,
      `- Suspicious entries: ${memoryStats.totalSuspiciousEntries}`,
      `- Average integrity score: ${memoryStats.avgIntegrityScore.toFixed(1)}/100`,
      '',
      '---',
      '',
      auditReport,
    ];

    return lines.join('\n');
  }
}

// ============================================================================
// Singleton Factory
// ============================================================================

let sidecarInstance: OpenClawSidecar | null = null;

/**
 * Get or create the OpenClaw sidecar instance
 */
export function getOpenClawSidecar(config?: Partial<OpenClawSidecarConfig>): OpenClawSidecar {
  if (!sidecarInstance) {
    sidecarInstance = new OpenClawSidecar(config);
  }
  return sidecarInstance;
}

/**
 * Reset the sidecar instance (for testing)
 */
export function resetOpenClawSidecar(): void {
  sidecarInstance = null;
}
