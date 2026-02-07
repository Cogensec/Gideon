import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import {
  GatewayMessage,
  WsMessageType,
  SentinelAlert,
  AlertSeverity,
  AlertCategory,
  AlertEvidence,
  OpenClawSidecarConfig,
  OPENCLAW_CVES,
  OPENCLAW_MITRE_TECHNIQUES,
} from './types';
import { getAgentMonitor } from '../governance/agent-monitor';
import { getPolicyEngine } from '../governance/policy-engine';
import { getAuditLogger } from '../governance/audit-logger';

// ============================================================================
// Gateway Sentinel (Workstream 1)
// Real-time WebSocket traffic analyzer for OpenClaw gateway
// ============================================================================

/** Patterns indicating CVE-2026-25253 kill chain stages */
const CVE_2026_25253_PATTERNS = {
  tokenExfiltration: /gatewayUrl\s*=\s*[^&\s]+/i,
  approvalBypass: /exec\.approvals\.set\s*=\s*off/i,
  sandboxEscape: /tools\.exec\.host\s*=\s*gateway/i,
  operatorAdmin: /operator\.admin/i,
  operatorApprovals: /operator\.approvals/i,
};

/** Patterns indicating privilege escalation */
const PRIVILEGE_ESCALATION_PATTERNS = [
  /sudo\s+/i,
  /chmod\s+[467][467][467]/i,
  /chown\s+root/i,
  /usermod\s+-aG\s+(sudo|wheel|admin)/i,
  /passwd\s+/i,
  /visudo/i,
  /su\s+-\s/i,
  /doas\s+/i,
];

/** Patterns indicating sandbox escape attempts */
const SANDBOX_ESCAPE_PATTERNS = [
  /docker\s+run\s+.*--privileged/i,
  /nsenter\s+/i,
  /mount\s+.*\/proc/i,
  /chroot\s+/i,
  /unshare\s+-/i,
  /--net\s*=\s*host/i,
  /--pid\s*=\s*host/i,
  /tools\.exec\.host\s*=\s*gateway/i,
  /\.docker\.sock/i,
  /cgroup.*release_agent/i,
];

/** Patterns indicating command injection */
const COMMAND_INJECTION_PATTERNS = [
  /;\s*(curl|wget|nc|ncat|bash|sh|python|perl|ruby)\s/i,
  /\$\(.*\)/,
  /`[^`]*`/,
  /\|\s*(bash|sh|python|perl|ruby)\s/i,
  /&&\s*(curl|wget)\s.*\|\s*(bash|sh)/i,
  />\s*\/dev\/(tcp|udp)\//i,
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
];

/** Patterns indicating data exfiltration */
const EXFILTRATION_PATTERNS = [
  /curl\s+.*-d\s.*POST/i,
  /curl\s+.*--data/i,
  /wget\s+.*--post/i,
  /webhook\.site/i,
  /requestbin/i,
  /ngrok\.io/i,
  /burpcollaborator/i,
  /pipedream\.net/i,
  /hookbin\.com/i,
  /canarytokens\.com/i,
  /interact\.sh/i,
  /oast\.fun/i,
  /base64.*\|\s*(curl|wget|nc)/i,
];

/** Credential access patterns */
const CREDENTIAL_ACCESS_PATTERNS = [
  /\.openclaw\/.*credentials/i,
  /\.openclaw\/.*auth-profiles/i,
  /\.openclaw\/.*sessions\.json/i,
  /\.openclaw\/.*gateway\.auth/i,
  /OPENCLAW_GATEWAY_TOKEN/i,
  /ANTHROPIC_API_KEY/i,
  /OPENAI_API_KEY/i,
  /DEEPSEEK_API_KEY/i,
  /api[_-]?key\s*[:=]/i,
  /bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/i,
];

interface SessionProfile {
  sessionId: string;
  firstSeen: string;
  lastSeen: string;
  messageCount: number;
  toolCallCount: number;
  execCount: number;
  fileAccessCount: number;
  credentialAccessCount: number;
  networkCallCount: number;
  anomalyScore: number;
  recentActions: string[];
}

/**
 * Gateway Sentinel - Monitors OpenClaw gateway WebSocket traffic
 * for security threats, anomalies, and known attack patterns.
 *
 * Detects:
 * - CVE-2026-25253 kill chain (token exfil + approval bypass + sandbox escape)
 * - Privilege escalation attempts
 * - Sandbox escape attempts
 * - Command injection patterns
 * - Data exfiltration patterns
 * - Credential access violations
 * - Behavioral anomalies
 */
export class GatewaySentinel {
  private config: OpenClawSidecarConfig;
  private alerts: SentinelAlert[] = [];
  private sessionProfiles: Map<string, SessionProfile> = new Map();
  private messageBuffer: GatewayMessage[] = [];
  private alertHandlers: Array<(alert: SentinelAlert) => void> = [];
  private killChainTracker: Map<string, Set<string>> = new Map();

  constructor(config: OpenClawSidecarConfig) {
    this.config = config;
  }

  /**
   * Subscribe to sentinel alerts
   */
  onAlert(handler: (alert: SentinelAlert) => void): () => void {
    this.alertHandlers.push(handler);
    return () => {
      const idx = this.alertHandlers.indexOf(handler);
      if (idx > -1) this.alertHandlers.splice(idx, 1);
    };
  }

  /**
   * Analyze an intercepted gateway message
   */
  async analyzeMessage(message: GatewayMessage): Promise<SentinelAlert[]> {
    const alerts: SentinelAlert[] = [];

    // Buffer the message
    this.messageBuffer.push(message);
    if (this.messageBuffer.length > 5000) {
      this.messageBuffer = this.messageBuffer.slice(-2500);
    }

    // Update session profile
    this.updateSessionProfile(message);

    // Run all detection checks
    const detectionResults = await Promise.all([
      this.detectCve202625253(message),
      this.detectPrivilegeEscalation(message),
      this.detectSandboxEscape(message),
      this.detectCommandInjection(message),
      this.detectDataExfiltration(message),
      this.detectCredentialAccess(message),
      this.detectApprovalBypass(message),
      this.detectSessionHijack(message),
      this.detectBehavioralAnomaly(message),
    ]);

    for (const result of detectionResults) {
      if (result) {
        alerts.push(result);
      }
    }

    // Store and emit alerts
    for (const alert of alerts) {
      this.alerts.push(alert);
      this.emitAlert(alert);
      this.logToGovernance(alert, message);
    }

    return alerts;
  }

  /**
   * Detect CVE-2026-25253 kill chain
   * Attack stages: token exfil -> CSWSH -> approval bypass -> sandbox escape -> RCE
   */
  private async detectCve202625253(message: GatewayMessage): Promise<SentinelAlert | null> {
    if (!this.config.sentinel.detectCve202625253) return null;

    const payload = JSON.stringify(message.payload);
    const sessionKey = message.sessionId || message.agentId || 'unknown';

    if (!this.killChainTracker.has(sessionKey)) {
      this.killChainTracker.set(sessionKey, new Set());
    }
    const stages = this.killChainTracker.get(sessionKey)!;

    // Track each stage of the kill chain
    if (CVE_2026_25253_PATTERNS.tokenExfiltration.test(payload)) {
      stages.add('token_exfil');
    }
    if (CVE_2026_25253_PATTERNS.operatorAdmin.test(payload)) {
      stages.add('operator_admin');
    }
    if (CVE_2026_25253_PATTERNS.approvalBypass.test(payload)) {
      stages.add('approval_bypass');
    }
    if (CVE_2026_25253_PATTERNS.sandboxEscape.test(payload)) {
      stages.add('sandbox_escape');
    }

    // Alert if multiple stages detected (partial or full kill chain)
    if (stages.size >= 2) {
      const alert = this.createAlert(
        'critical',
        'privilege_escalation',
        'CVE-2026-25253 Kill Chain Detected',
        `Detected ${stages.size}/4 stages of the CVE-2026-25253 attack kill chain ` +
        `(token exfiltration -> CSWSH -> approval bypass -> sandbox escape -> RCE). ` +
        `Stages observed: ${Array.from(stages).join(', ')}`,
        [{ type: 'message', source: 'gateway_ws', content: payload, timestamp: message.timestamp }],
        'Immediately kill the affected session, rotate the gateway auth token, ' +
        'verify no unauthorized commands were executed, and check for persistence mechanisms.',
        ['CVE-2026-25253'],
        ['T1190', 'T1539', 'T1059'],
        'quarantine',
      );

      // Reset tracker for this session after alerting
      this.killChainTracker.set(sessionKey, new Set());
      return alert;
    }

    return null;
  }

  /**
   * Detect privilege escalation attempts
   */
  private async detectPrivilegeEscalation(message: GatewayMessage): Promise<SentinelAlert | null> {
    if (message.type !== 'exec_request' && message.type !== 'tool_call') return null;

    const content = JSON.stringify(message.payload);
    for (const pattern of PRIVILEGE_ESCALATION_PATTERNS) {
      if (pattern.test(content)) {
        return this.createAlert(
          'high',
          'privilege_escalation',
          'Privilege Escalation Attempt',
          `Agent attempted privilege escalation via: ${content.slice(0, 200)}`,
          [{ type: 'message', source: 'gateway_ws', content, timestamp: message.timestamp }],
          'Block the exec request and review agent permissions. ' +
          'Consider quarantining the session if repeated.',
          [],
          ['T1078'],
        );
      }
    }
    return null;
  }

  /**
   * Detect sandbox escape attempts
   */
  private async detectSandboxEscape(message: GatewayMessage): Promise<SentinelAlert | null> {
    const content = JSON.stringify(message.payload);
    for (const pattern of SANDBOX_ESCAPE_PATTERNS) {
      if (pattern.test(content)) {
        return this.createAlert(
          'critical',
          'sandbox_escape',
          'Sandbox Escape Attempt',
          `Detected sandbox escape technique: ${content.slice(0, 200)}`,
          [{ type: 'message', source: 'gateway_ws', content, timestamp: message.timestamp }],
          'Kill the affected session immediately. Verify Docker sandbox integrity ' +
          'and check if the gateway host was compromised.',
          ['CVE-2026-25253'],
          ['T1574'],
          'quarantine',
        );
      }
    }
    return null;
  }

  /**
   * Detect command injection patterns
   */
  private async detectCommandInjection(message: GatewayMessage): Promise<SentinelAlert | null> {
    if (message.type !== 'exec_request' && message.type !== 'tool_call') return null;

    const content = JSON.stringify(message.payload);
    for (const pattern of COMMAND_INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        return this.createAlert(
          'high',
          'command_injection',
          'Command Injection Pattern Detected',
          `Suspicious command injection pattern in exec request: ${content.slice(0, 200)}`,
          [{ type: 'message', source: 'gateway_ws', content, timestamp: message.timestamp }],
          'Block the command execution and review the input source. ' +
          'Check if the command originated from user input or ingested content.',
          ['CVE-2026-24763', 'CVE-2026-25157'],
          ['T1059'],
        );
      }
    }
    return null;
  }

  /**
   * Detect data exfiltration patterns
   */
  private async detectDataExfiltration(message: GatewayMessage): Promise<SentinelAlert | null> {
    const content = JSON.stringify(message.payload);
    for (const pattern of EXFILTRATION_PATTERNS) {
      if (pattern.test(content)) {
        return this.createAlert(
          'critical',
          'data_exfiltration',
          'Data Exfiltration Attempt',
          `Detected data exfiltration pattern: ${content.slice(0, 200)}`,
          [{ type: 'message', source: 'gateway_ws', content, timestamp: message.timestamp }],
          'Block the outbound request immediately. Review what data was accessed ' +
          'in the session and check for credential exposure.',
          [],
          ['T1567'],
          'block',
        );
      }
    }
    return null;
  }

  /**
   * Detect unauthorized credential access
   */
  private async detectCredentialAccess(message: GatewayMessage): Promise<SentinelAlert | null> {
    if (message.type !== 'file_read' && message.type !== 'exec_request' && message.type !== 'tool_call') {
      return null;
    }

    const content = JSON.stringify(message.payload);
    for (const pattern of CREDENTIAL_ACCESS_PATTERNS) {
      if (pattern.test(content)) {
        // Check if this is followed by a network request (more severe)
        const profile = this.sessionProfiles.get(message.sessionId || '');
        const severity: AlertSeverity = profile && profile.networkCallCount > 0 ? 'critical' : 'high';

        return this.createAlert(
          severity,
          'credential_access',
          'Credential File Access Detected',
          `Agent accessed credential storage: ${content.slice(0, 200)}. ` +
          (severity === 'critical'
            ? 'Network activity detected in same session - potential credential exfiltration.'
            : 'Monitor for subsequent network activity.'),
          [{ type: 'message', source: 'gateway_ws', content, timestamp: message.timestamp }],
          'Review session activity for credential exfiltration. ' +
          'Rotate any exposed API keys and tokens immediately.',
          [],
          ['T1552'],
          severity === 'critical' ? 'quarantine' : 'alert_only',
        );
      }
    }
    return null;
  }

  /**
   * Detect approval bypass attempts (exec.approvals.set = off)
   */
  private async detectApprovalBypass(message: GatewayMessage): Promise<SentinelAlert | null> {
    if (message.type !== 'operator_approvals' && message.type !== 'config_change') return null;

    const content = JSON.stringify(message.payload);
    if (CVE_2026_25253_PATTERNS.approvalBypass.test(content)) {
      return this.createAlert(
        'critical',
        'approval_bypass',
        'Exec Approval Controls Disabled',
        'An attempt was made to disable execution approval controls ' +
        '(exec.approvals.set = off). This is a key stage in the CVE-2026-25253 kill chain.',
        [{ type: 'message', source: 'gateway_ws', content, timestamp: message.timestamp }],
        'Re-enable execution approvals immediately. Check if this was triggered by ' +
        'a legitimate admin action or an attacker with stolen credentials.',
        ['CVE-2026-25253'],
        ['T1562'],
        'block',
      );
    }
    return null;
  }

  /**
   * Detect session hijacking patterns
   */
  private async detectSessionHijack(message: GatewayMessage): Promise<SentinelAlert | null> {
    if (message.type !== 'auth_response') return null;

    const content = JSON.stringify(message.payload);

    // Check for cross-origin WebSocket connections (pre-fix CVE-2026-25253 pattern)
    if (message.payload.origin && !this.isLocalOrigin(message.payload.origin)) {
      return this.createAlert(
        'critical',
        'cross_origin_ws',
        'Cross-Origin WebSocket Connection',
        `WebSocket connection from non-local origin: ${message.payload.origin}. ` +
        'This pattern matches CVE-2026-25253 cross-site WebSocket hijacking.',
        [{ type: 'message', source: 'gateway_ws', content, timestamp: message.timestamp }],
        'Reject the connection. Verify WebSocket origin validation is enabled ' +
        'and upgrade OpenClaw to >= v2026.1.29.',
        ['CVE-2026-25253'],
        ['T1557'],
        'block',
      );
    }
    return null;
  }

  /**
   * Detect behavioral anomalies based on session profiles
   */
  private async detectBehavioralAnomaly(message: GatewayMessage): Promise<SentinelAlert | null> {
    if (!this.config.sentinel.behavioralProfiling) return null;

    const profile = this.sessionProfiles.get(message.sessionId || '');
    if (!profile || profile.messageCount < 20) return null; // Need baseline

    // High exec rate anomaly
    const execRate = profile.execCount / Math.max(1, profile.messageCount);
    if (execRate > 0.5 && profile.execCount > 10) {
      return this.createAlert(
        'medium',
        'rate_anomaly',
        'Abnormal Exec Rate Detected',
        `Session ${message.sessionId} has an abnormally high exec rate: ` +
        `${profile.execCount} exec calls out of ${profile.messageCount} messages ` +
        `(${(execRate * 100).toFixed(1)}%). Normal is <20%.`,
        [{ type: 'behavioral', source: 'session_profile', content: JSON.stringify(profile), timestamp: message.timestamp }],
        'Review session activity. High exec rates may indicate automated exploitation.',
      );
    }

    // Credential access after file read pattern
    if (profile.credentialAccessCount > 0 && profile.networkCallCount > profile.credentialAccessCount) {
      const ratio = profile.networkCallCount / profile.credentialAccessCount;
      if (ratio > 3) {
        return this.createAlert(
          'high',
          'data_exfiltration',
          'Credential Read Followed by Network Activity',
          `Session ${message.sessionId} accessed credentials ${profile.credentialAccessCount} times ` +
          `followed by ${profile.networkCallCount} network calls. ` +
          'This pattern is consistent with credential exfiltration.',
          [{ type: 'behavioral', source: 'session_profile', content: JSON.stringify(profile), timestamp: message.timestamp }],
          'Quarantine the session and rotate all accessed credentials.',
          [],
          ['T1552', 'T1567'],
          'quarantine',
        );
      }
    }

    return null;
  }

  // --- Helper Methods ---

  private updateSessionProfile(message: GatewayMessage): void {
    const sessionId = message.sessionId || 'default';
    let profile = this.sessionProfiles.get(sessionId);

    if (!profile) {
      profile = {
        sessionId,
        firstSeen: message.timestamp,
        lastSeen: message.timestamp,
        messageCount: 0,
        toolCallCount: 0,
        execCount: 0,
        fileAccessCount: 0,
        credentialAccessCount: 0,
        networkCallCount: 0,
        anomalyScore: 0,
        recentActions: [],
      };
      this.sessionProfiles.set(sessionId, profile);
    }

    profile.lastSeen = message.timestamp;
    profile.messageCount++;

    if (message.type === 'tool_call') profile.toolCallCount++;
    if (message.type === 'exec_request') profile.execCount++;
    if (message.type === 'file_read' || message.type === 'file_write') profile.fileAccessCount++;

    const content = JSON.stringify(message.payload);
    if (CREDENTIAL_ACCESS_PATTERNS.some(p => p.test(content))) {
      profile.credentialAccessCount++;
    }

    // Track recent actions
    profile.recentActions.push(`${message.type}:${message.timestamp}`);
    if (profile.recentActions.length > 100) {
      profile.recentActions = profile.recentActions.slice(-50);
    }
  }

  private isLocalOrigin(origin: string): boolean {
    const localPatterns = [
      /^https?:\/\/localhost(:\d+)?$/i,
      /^https?:\/\/127\.0\.0\.1(:\d+)?$/i,
      /^https?:\/\/\[::1\](:\d+)?$/i,
      /^https?:\/\/0\.0\.0\.0(:\d+)?$/i,
    ];
    return localPatterns.some(p => p.test(origin));
  }

  private createAlert(
    severity: AlertSeverity,
    category: AlertCategory,
    title: string,
    description: string,
    evidence: AlertEvidence[],
    recommendation: string,
    cveReferences?: string[],
    mitreTechniques?: string[],
    autoAction?: SentinelAlert['autoAction'],
  ): SentinelAlert {
    return {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      severity,
      category,
      title,
      description,
      evidence,
      cveReferences,
      mitreTechniques: mitreTechniques?.map(t =>
        `${t}: ${OPENCLAW_MITRE_TECHNIQUES[t as keyof typeof OPENCLAW_MITRE_TECHNIQUES] || 'Unknown'}`
      ),
      recommendation,
      autoAction: this.config.sentinel.autoResponse ? autoAction : 'alert_only',
      resolved: false,
    };
  }

  private emitAlert(alert: SentinelAlert): void {
    for (const handler of this.alertHandlers) {
      try {
        handler(alert);
      } catch (err) {
        console.error('[Sentinel] Alert handler error:', err);
      }
    }
  }

  private logToGovernance(alert: SentinelAlert, message: GatewayMessage): void {
    try {
      const logger = getAuditLogger();
      logger.log({
        eventType: 'anomaly_detected',
        actor: { type: 'system', id: 'openclaw-sentinel', name: 'OpenClaw Gateway Sentinel' },
        target: message.sessionId
          ? { type: 'session', id: message.sessionId, name: `OpenClaw Session ${message.sessionId}` }
          : undefined,
        details: {
          alertId: alert.id,
          severity: alert.severity,
          category: alert.category,
          title: alert.title,
          cveReferences: alert.cveReferences,
          autoAction: alert.autoAction,
        },
        outcome: alert.autoAction === 'alert_only' ? 'success' : 'partial',
        riskLevel: alert.severity,
      });
    } catch {
      // Don't let logging failures break detection
    }
  }

  // --- Public API ---

  getAlerts(filters?: {
    severity?: AlertSeverity;
    category?: AlertCategory;
    since?: Date;
    resolved?: boolean;
  }): SentinelAlert[] {
    let result = [...this.alerts];
    if (filters?.severity) result = result.filter(a => a.severity === filters.severity);
    if (filters?.category) result = result.filter(a => a.category === filters.category);
    if (filters?.since) result = result.filter(a => new Date(a.timestamp) >= filters.since!);
    if (filters?.resolved !== undefined) result = result.filter(a => a.resolved === filters.resolved);
    return result.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  resolveAlert(alertId: string): boolean {
    const alert = this.alerts.find(a => a.id === alertId);
    if (!alert) return false;
    alert.resolved = true;
    return true;
  }

  getSessionProfiles(): Map<string, SessionProfile> {
    return new Map(this.sessionProfiles);
  }

  getSessionProfile(sessionId: string): SessionProfile | undefined {
    return this.sessionProfiles.get(sessionId);
  }

  getStats(): {
    totalAlerts: number;
    unresolvedAlerts: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    activeSessions: number;
    messagesAnalyzed: number;
  } {
    const bySeverity: Record<string, number> = {};
    const byCategory: Record<string, number> = {};

    for (const alert of this.alerts) {
      bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
      byCategory[alert.category] = (byCategory[alert.category] || 0) + 1;
    }

    return {
      totalAlerts: this.alerts.length,
      unresolvedAlerts: this.alerts.filter(a => !a.resolved).length,
      bySeverity,
      byCategory,
      activeSessions: this.sessionProfiles.size,
      messagesAnalyzed: this.messageBuffer.length,
    };
  }

  /**
   * Classify a raw WebSocket message into a typed GatewayMessage
   */
  classifyMessage(raw: string, sessionId?: string): GatewayMessage {
    let parsed: Record<string, any> = {};
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = { raw };
    }

    const type = this.inferMessageType(parsed);

    return {
      id: uuidv4(),
      type,
      timestamp: new Date().toISOString(),
      sessionId: sessionId || parsed.sessionId || parsed.session_id,
      agentId: parsed.agentId || parsed.agent_id,
      payload: parsed,
      raw,
    };
  }

  private inferMessageType(parsed: Record<string, any>): WsMessageType {
    const type = parsed.type || parsed.method || parsed.action || '';
    const typeStr = String(type).toLowerCase();

    if (typeStr.includes('exec') || typeStr.includes('shell')) return 'exec_request';
    if (typeStr.includes('tool_call') || typeStr.includes('tool.call')) return 'tool_call';
    if (typeStr.includes('tool_result') || typeStr.includes('tool.result')) return 'tool_result';
    if (typeStr.includes('session_spawn') || typeStr.includes('sessions.spawn')) return 'session_spawn';
    if (typeStr.includes('session_send') || typeStr.includes('sessions.send')) return 'session_send';
    if (typeStr.includes('session_kill') || typeStr.includes('sessions.kill')) return 'session_kill';
    if (typeStr.includes('operator.admin')) return 'operator_admin';
    if (typeStr.includes('operator.approvals')) return 'operator_approvals';
    if (typeStr.includes('file.read') || typeStr.includes('read')) return 'file_read';
    if (typeStr.includes('file.write') || typeStr.includes('write')) return 'file_write';
    if (typeStr.includes('browser')) return 'browser_navigate';
    if (typeStr.includes('memory')) return 'memory_write';
    if (typeStr.includes('config')) return 'config_change';
    if (typeStr.includes('auth') && typeStr.includes('challenge')) return 'auth_challenge';
    if (typeStr.includes('auth') && typeStr.includes('response')) return 'auth_response';
    if (typeStr.includes('heartbeat') || typeStr.includes('ping')) return 'heartbeat';

    return 'unknown';
  }
}
