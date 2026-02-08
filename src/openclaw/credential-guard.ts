import { v4 as uuidv4 } from 'uuid';
import { existsSync, statSync, readdirSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import {
  ExfiltrationAttempt,
  CredentialExposure,
  AlertEvidence,
  OpenClawSidecarConfig,
} from './types';
import { containsSensitiveData, redactSensitiveData } from '../utils/redactor';

// ============================================================================
// Credential & Data Protection Layer (Workstream 5)
// Monitors credential access, detects exfiltration, and protects sensitive data
// ============================================================================

/** Patterns matching OpenClaw credential files */
const CREDENTIAL_FILE_PATTERNS = [
  /credentials\/.*\.json$/i,
  /auth-profiles\.json$/i,
  /sessions\.json$/i,
  /gateway\.auth/i,
  /\.env$/,
  /\.env\.local$/,
  /config.*\.json$/i,
];

/** Sensitive data patterns for outbound monitoring */
const SENSITIVE_DATA_PATTERNS = [
  // API Keys
  { pattern: /(?:sk-|pk-)[a-zA-Z0-9]{32,}/g, type: 'api_key', description: 'API key (OpenAI/Anthropic format)' },
  { pattern: /AKIA[0-9A-Z]{16}/g, type: 'api_key', description: 'AWS Access Key ID' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'api_key', description: 'GitHub Personal Access Token' },
  // OAuth tokens
  { pattern: /ya29\.[a-zA-Z0-9_-]{50,}/g, type: 'oauth_token', description: 'Google OAuth Token' },
  { pattern: /xox[bposa]-[a-zA-Z0-9-]+/g, type: 'oauth_token', description: 'Slack Token' },
  // Bearer tokens
  { pattern: /Bearer\s+[a-zA-Z0-9\-_.]+/g, type: 'bearer_token', description: 'Bearer Token' },
  // Private keys
  { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g, type: 'private_key', description: 'Private Key' },
  // Passwords
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"',;]{8,}/gi, type: 'password', description: 'Password' },
  // Connection strings
  { pattern: /(?:mongodb|postgresql|mysql|redis):\/\/[^\s"']+/gi, type: 'connection_string', description: 'Database Connection String' },
  // Webhook URLs
  { pattern: /https:\/\/hooks\.slack\.com\/services\/[^\s"']+/gi, type: 'webhook_url', description: 'Slack Webhook URL' },
  { pattern: /https:\/\/discord\.com\/api\/webhooks\/[^\s"']+/gi, type: 'webhook_url', description: 'Discord Webhook URL' },
];

/** File access sequence patterns indicating exfiltration */
interface AccessSequence {
  sessionId: string;
  credentialReads: Array<{ file: string; timestamp: string }>;
  networkCalls: Array<{ target: string; timestamp: string }>;
  memoryReads: Array<{ file: string; timestamp: string }>;
  fileWrites: Array<{ file: string; timestamp: string }>;
}

/**
 * Credential Guard - Protects OpenClaw credential storage and detects exfiltration
 *
 * Capabilities:
 * - Monitors access to credential files (~/.openclaw/credentials/, auth-profiles.json)
 * - Detects credential-read-then-network-call patterns
 * - Identifies bulk memory/session transcript reads
 * - Scans outbound communications for sensitive data
 * - Audits plaintext credential storage
 * - Redacts sensitive data from outbound messages/API calls
 */
export class CredentialGuard {
  private config: OpenClawSidecarConfig;
  private openclawHome: string;
  private exfiltrationAttempts: ExfiltrationAttempt[] = [];
  private accessSequences: Map<string, AccessSequence> = new Map();
  private alertHandlers: Array<(attempt: ExfiltrationAttempt) => void> = [];

  constructor(config: OpenClawSidecarConfig) {
    this.config = config;
    this.openclawHome = config.gateway.openclawHome.replace(/^~/, process.env.HOME || '/root');
  }

  /**
   * Subscribe to exfiltration alerts
   */
  onExfiltrationDetected(handler: (attempt: ExfiltrationAttempt) => void): () => void {
    this.alertHandlers.push(handler);
    return () => {
      const idx = this.alertHandlers.indexOf(handler);
      if (idx > -1) this.alertHandlers.splice(idx, 1);
    };
  }

  /**
   * Record a file access event and check for exfiltration patterns
   */
  recordFileAccess(params: {
    sessionId: string;
    agentId?: string;
    file: string;
    action: 'read' | 'write';
    timestamp?: string;
  }): ExfiltrationAttempt | null {
    if (!this.config.credentialGuard.monitorCredentials) return null;

    const timestamp = params.timestamp || new Date().toISOString();
    const sequence = this.getOrCreateSequence(params.sessionId);

    // Check if this is a credential file access
    const isCredentialFile = CREDENTIAL_FILE_PATTERNS.some(p => p.test(params.file));

    if (params.action === 'read') {
      if (isCredentialFile) {
        sequence.credentialReads.push({ file: params.file, timestamp });
      }

      // Check for bulk memory reads
      if (params.file.includes('memory/') || params.file.includes('sessions/')) {
        sequence.memoryReads.push({ file: params.file, timestamp });
      }
    }

    if (params.action === 'write') {
      sequence.fileWrites.push({ file: params.file, timestamp });

      // Check for writes to world-readable locations
      const worldReadable = this.isWorldReadableLocation(params.file);
      if (isCredentialFile || this.containsCredentialData(params.file)) {
        if (worldReadable) {
          return this.createExfiltrationAttempt({
            sessionId: params.sessionId,
            agentId: params.agentId,
            type: 'world_readable_write',
            description: `Credential data written to world-readable location: ${params.file}`,
            evidence: [{
              type: 'file',
              source: params.file,
              content: `File write by session ${params.sessionId}`,
              timestamp,
            }],
            blocked: false,
            sensitiveDataTypes: ['credential'],
          });
        }
      }
    }

    // Check for credential-read-then-network pattern
    return this.checkExfiltrationPatterns(params.sessionId, params.agentId);
  }

  /**
   * Record a network call event
   */
  recordNetworkCall(params: {
    sessionId: string;
    agentId?: string;
    target: string;
    timestamp?: string;
  }): ExfiltrationAttempt | null {
    if (!this.config.credentialGuard.detectExfiltration) return null;

    const timestamp = params.timestamp || new Date().toISOString();
    const sequence = this.getOrCreateSequence(params.sessionId);

    sequence.networkCalls.push({ target: params.target, timestamp });

    return this.checkExfiltrationPatterns(params.sessionId, params.agentId);
  }

  /**
   * Scan outbound content for sensitive data and redact if configured
   */
  scanOutboundContent(content: string, destination: string): {
    hasSensitiveData: boolean;
    sensitiveTypes: string[];
    redactedContent: string;
    findings: Array<{ type: string; description: string; match: string }>;
  } {
    const findings: Array<{ type: string; description: string; match: string }> = [];
    const sensitiveTypes = new Set<string>();

    for (const { pattern, type, description } of SENSITIVE_DATA_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        sensitiveTypes.add(type);
        findings.push({
          type,
          description,
          match: match[0].slice(0, 20) + '...',
        });
      }
    }

    // Also use Gideon's existing redactor
    const hasGideonSensitive = containsSensitiveData(content);
    if (hasGideonSensitive) {
      sensitiveTypes.add('gideon_detected');
    }

    const hasSensitiveData = findings.length > 0 || hasGideonSensitive;

    let redactedContent = content;
    if (hasSensitiveData && this.config.credentialGuard.redactOutbound) {
      // Apply pattern-based redaction
      for (const { pattern } of SENSITIVE_DATA_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        redactedContent = redactedContent.replace(regex, '***REDACTED_BY_GIDEON***');
      }
      // Also apply Gideon's built-in redactor
      redactedContent = redactSensitiveData(redactedContent);
    }

    return {
      hasSensitiveData,
      sensitiveTypes: Array.from(sensitiveTypes),
      redactedContent,
      findings,
    };
  }

  /**
   * Audit credential storage in the OpenClaw home directory
   */
  auditCredentialStorage(): CredentialExposure[] {
    if (!this.config.credentialGuard.auditStorage) return [];

    const exposures: CredentialExposure[] = [];
    const resolvedHome = resolve(this.openclawHome);

    if (!existsSync(resolvedHome)) return exposures;

    // Check known credential file locations
    const credentialPaths = [
      { pattern: 'credentials', types: ['api_key', 'oauth_token'] as const },
      { pattern: 'agents/*/agent/auth-profiles.json', types: ['oauth_token'] as const },
      { pattern: 'agents/*/sessions/sessions.json', types: ['bearer_token'] as const },
    ];

    for (const { pattern, types } of credentialPaths) {
      const dir = join(resolvedHome, pattern.split('/')[0]);
      if (!existsSync(dir)) continue;

      try {
        this.walkDirectory(dir, (filePath) => {
          const stats = statSync(filePath);
          const mode = (stats.mode & 0o777).toString(8);
          const ownerOnly = parseInt(mode, 8) <= 0o600;

          // Check if file contains credential-like content
          const isCredentialFile = CREDENTIAL_FILE_PATTERNS.some(p => p.test(filePath));
          if (!isCredentialFile) return;

          for (const type of types) {
            exposures.push({
              file: filePath,
              type,
              isEncrypted: false, // OpenClaw stores everything in plaintext
              permissions: mode,
              ownerOnly,
              recommendation: ownerOnly
                ? `File permissions (${mode}) are acceptable but data is not encrypted at rest.`
                : `URGENT: Set permissions to 600: chmod 600 "${filePath}"`,
            });
          }
        });
      } catch {
        // Permission denied or other errors
      }
    }

    return exposures;
  }

  // --- Private Methods ---

  private getOrCreateSequence(sessionId: string): AccessSequence {
    if (!this.accessSequences.has(sessionId)) {
      this.accessSequences.set(sessionId, {
        sessionId,
        credentialReads: [],
        networkCalls: [],
        memoryReads: [],
        fileWrites: [],
      });
    }
    return this.accessSequences.get(sessionId)!;
  }

  private checkExfiltrationPatterns(sessionId: string, agentId?: string): ExfiltrationAttempt | null {
    const sequence = this.accessSequences.get(sessionId);
    if (!sequence) return null;

    // Pattern 1: Credential read followed by network call
    if (sequence.credentialReads.length > 0 && sequence.networkCalls.length > 0) {
      const lastCredRead = sequence.credentialReads[sequence.credentialReads.length - 1];
      const networkAfterCred = sequence.networkCalls.filter(
        n => new Date(n.timestamp) > new Date(lastCredRead.timestamp)
      );

      if (networkAfterCred.length > 0) {
        const attempt = this.createExfiltrationAttempt({
          sessionId,
          agentId,
          type: 'credential_read_then_network',
          description: `Credential file "${lastCredRead.file}" was read, followed by ` +
            `${networkAfterCred.length} network call(s) to: ${networkAfterCred.map(n => n.target).join(', ')}`,
          evidence: [
            { type: 'file', source: lastCredRead.file, content: `Read at ${lastCredRead.timestamp}`, timestamp: lastCredRead.timestamp },
            ...networkAfterCred.map(n => ({
              type: 'pattern' as const,
              source: n.target,
              content: `Network call to ${n.target}`,
              timestamp: n.timestamp,
            })),
          ],
          blocked: false,
          sensitiveDataTypes: ['credential', 'api_key'],
        });

        // Reset the sequence after detection
        sequence.credentialReads = [];
        sequence.networkCalls = [];

        return attempt;
      }
    }

    // Pattern 2: Bulk memory/session reads
    if (sequence.memoryReads.length >= 5) {
      const attempt = this.createExfiltrationAttempt({
        sessionId,
        agentId,
        type: 'bulk_memory_read',
        description: `Bulk read of ${sequence.memoryReads.length} memory/session files in session ${sessionId}. ` +
          'This pattern is consistent with "cognitive context theft."',
        evidence: sequence.memoryReads.map(m => ({
          type: 'file' as const,
          source: m.file,
          content: `Read at ${m.timestamp}`,
          timestamp: m.timestamp,
        })),
        blocked: false,
        sensitiveDataTypes: ['conversation_history', 'memory', 'workflow_data'],
      });

      sequence.memoryReads = [];
      return attempt;
    }

    return null;
  }

  private createExfiltrationAttempt(params: {
    sessionId: string;
    agentId?: string;
    type: ExfiltrationAttempt['type'];
    description: string;
    evidence: AlertEvidence[];
    blocked: boolean;
    sensitiveDataTypes: string[];
  }): ExfiltrationAttempt {
    const attempt: ExfiltrationAttempt = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      sessionId: params.sessionId,
      agentId: params.agentId,
      type: params.type,
      description: params.description,
      evidence: params.evidence,
      blocked: params.blocked,
      sensitiveDataTypes: params.sensitiveDataTypes,
    };

    this.exfiltrationAttempts.push(attempt);

    for (const handler of this.alertHandlers) {
      try {
        handler(attempt);
      } catch {
        // Don't let handler errors break detection
      }
    }

    return attempt;
  }

  private isWorldReadableLocation(filePath: string): boolean {
    const worldReadable = [
      '/tmp/',
      '/var/tmp/',
      '/public/',
      '/www/',
      '/srv/',
    ];
    return worldReadable.some(p => filePath.startsWith(p));
  }

  private containsCredentialData(filePath: string): boolean {
    try {
      if (!existsSync(filePath)) return false;
      const content = readFileSync(filePath, 'utf-8').slice(0, 5000);
      return SENSITIVE_DATA_PATTERNS.some(({ pattern }) => {
        const regex = new RegExp(pattern.source, pattern.flags);
        return regex.test(content);
      });
    } catch {
      return false;
    }
  }

  private walkDirectory(dir: string, callback: (filePath: string) => void): void {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          this.walkDirectory(fullPath, callback);
        } else if (entry.isFile()) {
          callback(fullPath);
        }
      }
    } catch {
      // Permission denied or other errors
    }
  }

  // --- Public API ---

  getExfiltrationAttempts(filters?: {
    sessionId?: string;
    type?: ExfiltrationAttempt['type'];
    since?: Date;
  }): ExfiltrationAttempt[] {
    let result = [...this.exfiltrationAttempts];
    if (filters?.sessionId) result = result.filter(a => a.sessionId === filters.sessionId);
    if (filters?.type) result = result.filter(a => a.type === filters.type);
    if (filters?.since) result = result.filter(a => new Date(a.timestamp) >= filters.since!);
    return result.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  getStats(): {
    totalAttempts: number;
    blockedAttempts: number;
    byType: Record<string, number>;
    affectedSessions: number;
  } {
    const byType: Record<string, number> = {};
    let blocked = 0;
    const sessions = new Set<string>();

    for (const attempt of this.exfiltrationAttempts) {
      byType[attempt.type] = (byType[attempt.type] || 0) + 1;
      if (attempt.blocked) blocked++;
      sessions.add(attempt.sessionId);
    }

    return {
      totalAttempts: this.exfiltrationAttempts.length,
      blockedAttempts: blocked,
      byType,
      affectedSessions: sessions.size,
    };
  }
}
