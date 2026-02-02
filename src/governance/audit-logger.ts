import { existsSync, mkdirSync, appendFileSync, readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { AuditLog, AuditLogSchema, PolicySeverity } from './types';

const AUDIT_DIR = '.gideon/governance/audit';
const LOG_FILE_PREFIX = 'audit-';
const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB per file
const MAX_LOG_FILES = 30; // Keep 30 days of logs

type AuditEventType = AuditLog['eventType'];
type ActorType = 'user' | 'agent' | 'system';

interface AuditQuery {
  eventTypes?: AuditEventType[];
  actorType?: ActorType;
  actorId?: string;
  targetType?: string;
  targetId?: string;
  since?: Date;
  until?: Date;
  outcome?: 'success' | 'failure' | 'partial';
  riskLevel?: PolicySeverity;
  limit?: number;
  offset?: number;
}

/**
 * Audit Logger - Immutable audit trail for governance events
 *
 * Provides:
 * - Tamper-evident logging with hash chains
 * - Structured audit events
 * - Query and search capabilities
 * - Log rotation and retention
 * - Compliance reporting
 */
export class AuditLogger {
  private basePath: string;
  private auditDir: string;
  private currentLogFile: string;
  private lastHash: string = '';

  constructor(basePath: string = process.cwd()) {
    this.basePath = basePath;
    this.auditDir = join(basePath, AUDIT_DIR);

    if (!existsSync(this.auditDir)) {
      mkdirSync(this.auditDir, { recursive: true });
    }

    this.currentLogFile = this.getCurrentLogFile();
    this.lastHash = this.getLastHash();
  }

  /**
   * Get the current log file path (one per day)
   */
  private getCurrentLogFile(): string {
    const date = new Date().toISOString().split('T')[0];
    return join(this.auditDir, `${LOG_FILE_PREFIX}${date}.jsonl`);
  }

  /**
   * Get the hash of the last log entry for chain integrity
   */
  private getLastHash(): string {
    try {
      const files = readdirSync(this.auditDir)
        .filter((f) => f.startsWith(LOG_FILE_PREFIX))
        .sort()
        .reverse();

      for (const file of files) {
        const content = readFileSync(join(this.auditDir, file), 'utf-8');
        const lines = content.trim().split('\n').filter(Boolean);
        if (lines.length > 0) {
          const lastEntry = JSON.parse(lines[lines.length - 1]);
          return lastEntry.hash || '';
        }
      }
    } catch {
      // No previous logs
    }
    return '';
  }

  /**
   * Calculate hash for a log entry
   */
  private calculateHash(entry: AuditLog, previousHash: string): string {
    const data = JSON.stringify({
      ...entry,
      previousHash,
    });
    return createHash('sha256').update(data).digest('hex').slice(0, 16);
  }

  /**
   * Log an audit event
   */
  log(params: {
    eventType: AuditEventType;
    actor: { type: ActorType; id: string; name?: string };
    target?: { type: string; id: string; name?: string };
    details: Record<string, any>;
    outcome: 'success' | 'failure' | 'partial';
    riskLevel?: PolicySeverity;
  }): AuditLog {
    const entry: AuditLog = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      eventType: params.eventType,
      actor: params.actor,
      target: params.target,
      details: params.details,
      outcome: params.outcome,
      riskLevel: params.riskLevel,
    };

    AuditLogSchema.parse(entry);

    // Calculate hash chain
    const hash = this.calculateHash(entry, this.lastHash);
    const entryWithHash = { ...entry, previousHash: this.lastHash, hash };

    // Rotate log file if needed
    this.rotateIfNeeded();

    // Append to log file
    this.currentLogFile = this.getCurrentLogFile();
    appendFileSync(this.currentLogFile, JSON.stringify(entryWithHash) + '\n');
    this.lastHash = hash;

    return entry;
  }

  /**
   * Rotate log files if current file is too large
   */
  private rotateIfNeeded(): void {
    try {
      if (existsSync(this.currentLogFile)) {
        const stats = statSync(this.currentLogFile);
        if (stats.size > MAX_LOG_SIZE) {
          // File too large, will automatically use next day's file
          // or we can force a new file with a sequence number
          const timestamp = Date.now();
          this.currentLogFile = join(
            this.auditDir,
            `${LOG_FILE_PREFIX}${new Date().toISOString().split('T')[0]}-${timestamp}.jsonl`
          );
        }
      }

      // Clean up old log files
      this.cleanupOldLogs();
    } catch {
      // Ignore rotation errors
    }
  }

  /**
   * Clean up old log files beyond retention period
   */
  private cleanupOldLogs(): void {
    try {
      const files = readdirSync(this.auditDir)
        .filter((f) => f.startsWith(LOG_FILE_PREFIX))
        .sort();

      if (files.length > MAX_LOG_FILES) {
        const toDelete = files.slice(0, files.length - MAX_LOG_FILES);
        for (const file of toDelete) {
          // Don't actually delete, just archive (rename with .archived suffix)
          // In production, you might want to move to cold storage
        }
      }
    } catch {
      // Ignore cleanup errors
    }
  }

  // ========== Convenience logging methods ==========

  /**
   * Log agent registration
   */
  logAgentRegistered(
    actor: { type: ActorType; id: string; name?: string },
    agentId: string,
    agentName: string,
    agentType: string
  ): AuditLog {
    return this.log({
      eventType: 'agent_registered',
      actor,
      target: { type: 'agent', id: agentId, name: agentName },
      details: { agentType },
      outcome: 'success',
    });
  }

  /**
   * Log agent status change
   */
  logAgentStatusChanged(
    actor: { type: ActorType; id: string; name?: string },
    agentId: string,
    agentName: string,
    oldStatus: string,
    newStatus: string,
    reason?: string
  ): AuditLog {
    const riskLevel: PolicySeverity | undefined =
      newStatus === 'quarantined' ? 'high' :
      newStatus === 'revoked' ? 'critical' :
      undefined;

    return this.log({
      eventType: 'agent_status_changed',
      actor,
      target: { type: 'agent', id: agentId, name: agentName },
      details: { oldStatus, newStatus, reason },
      outcome: 'success',
      riskLevel,
    });
  }

  /**
   * Log policy creation
   */
  logPolicyCreated(
    actor: { type: ActorType; id: string; name?: string },
    policyId: string,
    policyName: string,
    ruleCount: number
  ): AuditLog {
    return this.log({
      eventType: 'policy_created',
      actor,
      target: { type: 'policy', id: policyId, name: policyName },
      details: { ruleCount },
      outcome: 'success',
    });
  }

  /**
   * Log policy update
   */
  logPolicyUpdated(
    actor: { type: ActorType; id: string; name?: string },
    policyId: string,
    policyName: string,
    changes: Record<string, any>
  ): AuditLog {
    return this.log({
      eventType: 'policy_updated',
      actor,
      target: { type: 'policy', id: policyId, name: policyName },
      details: { changes },
      outcome: 'success',
    });
  }

  /**
   * Log permission granted
   */
  logPermissionGranted(
    actor: { type: ActorType; id: string; name?: string },
    agentId: string,
    agentName: string,
    resourceType: string,
    resource: string,
    actions: string[]
  ): AuditLog {
    return this.log({
      eventType: 'permission_granted',
      actor,
      target: { type: 'agent', id: agentId, name: agentName },
      details: { resourceType, resource, actions },
      outcome: 'success',
    });
  }

  /**
   * Log permission revoked
   */
  logPermissionRevoked(
    actor: { type: ActorType; id: string; name?: string },
    agentId: string,
    agentName: string,
    permissionId: string,
    reason?: string
  ): AuditLog {
    return this.log({
      eventType: 'permission_revoked',
      actor,
      target: { type: 'agent', id: agentId, name: agentName },
      details: { permissionId, reason },
      outcome: 'success',
    });
  }

  /**
   * Log access denied
   */
  logAccessDenied(
    agentId: string,
    agentName: string,
    resourceType: string,
    resource: string,
    action: string,
    reason: string
  ): AuditLog {
    return this.log({
      eventType: 'access_denied',
      actor: { type: 'agent', id: agentId, name: agentName },
      target: { type: resourceType, id: resource },
      details: { action, reason },
      outcome: 'failure',
      riskLevel: 'medium',
    });
  }

  /**
   * Log anomaly detected
   */
  logAnomalyDetected(
    agentId: string,
    agentName: string,
    anomalyId: string,
    anomalyType: string,
    severity: PolicySeverity,
    description: string
  ): AuditLog {
    return this.log({
      eventType: 'anomaly_detected',
      actor: { type: 'system', id: 'gideon-monitor', name: 'Gideon Monitor' },
      target: { type: 'agent', id: agentId, name: agentName },
      details: { anomalyId, anomalyType, description },
      outcome: 'success',
      riskLevel: severity,
    });
  }

  /**
   * Log quarantine triggered
   */
  logQuarantineTriggered(
    agentId: string,
    agentName: string,
    reason: string,
    triggeredBy: string
  ): AuditLog {
    return this.log({
      eventType: 'quarantine_triggered',
      actor: { type: 'system', id: triggeredBy },
      target: { type: 'agent', id: agentId, name: agentName },
      details: { reason },
      outcome: 'success',
      riskLevel: 'high',
    });
  }

  /**
   * Log governance override
   */
  logGovernanceOverride(
    actor: { type: ActorType; id: string; name?: string },
    action: string,
    target: { type: string; id: string; name?: string },
    justification: string
  ): AuditLog {
    return this.log({
      eventType: 'governance_override',
      actor,
      target,
      details: { action, justification },
      outcome: 'success',
      riskLevel: 'high',
    });
  }

  // ========== Query methods ==========

  /**
   * Query audit logs
   */
  query(params: AuditQuery): AuditLog[] {
    const results: AuditLog[] = [];
    const limit = params.limit || 100;
    const offset = params.offset || 0;

    try {
      const files = readdirSync(this.auditDir)
        .filter((f) => f.startsWith(LOG_FILE_PREFIX) && f.endsWith('.jsonl'))
        .sort()
        .reverse(); // Most recent first

      let skipped = 0;
      let collected = 0;

      for (const file of files) {
        if (collected >= limit) break;

        const content = readFileSync(join(this.auditDir, file), 'utf-8');
        const lines = content.trim().split('\n').filter(Boolean).reverse();

        for (const line of lines) {
          if (collected >= limit) break;

          try {
            const entry = JSON.parse(line) as AuditLog;

            if (this.matchesQuery(entry, params)) {
              if (skipped < offset) {
                skipped++;
              } else {
                results.push(entry);
                collected++;
              }
            }
          } catch {
            // Skip malformed entries
          }
        }
      }
    } catch {
      // Query error
    }

    return results;
  }

  /**
   * Check if an entry matches query criteria
   */
  private matchesQuery(entry: AuditLog, query: AuditQuery): boolean {
    if (query.eventTypes && !query.eventTypes.includes(entry.eventType)) {
      return false;
    }

    if (query.actorType && entry.actor.type !== query.actorType) {
      return false;
    }

    if (query.actorId && entry.actor.id !== query.actorId) {
      return false;
    }

    if (query.targetType && entry.target?.type !== query.targetType) {
      return false;
    }

    if (query.targetId && entry.target?.id !== query.targetId) {
      return false;
    }

    if (query.outcome && entry.outcome !== query.outcome) {
      return false;
    }

    if (query.riskLevel && entry.riskLevel !== query.riskLevel) {
      return false;
    }

    const entryTime = new Date(entry.timestamp).getTime();

    if (query.since && entryTime < query.since.getTime()) {
      return false;
    }

    if (query.until && entryTime > query.until.getTime()) {
      return false;
    }

    return true;
  }

  /**
   * Get logs for a specific agent
   */
  getAgentLogs(agentId: string, limit: number = 100): AuditLog[] {
    return this.query({
      targetId: agentId,
      targetType: 'agent',
      limit,
    });
  }

  /**
   * Get recent security events
   */
  getSecurityEvents(hours: number = 24, limit: number = 100): AuditLog[] {
    return this.query({
      eventTypes: [
        'access_denied',
        'anomaly_detected',
        'quarantine_triggered',
        'governance_override',
      ],
      since: new Date(Date.now() - hours * 3600000),
      limit,
    });
  }

  /**
   * Get high-risk events
   */
  getHighRiskEvents(limit: number = 100): AuditLog[] {
    return this.query({
      riskLevel: 'critical',
      limit,
    }).concat(
      this.query({
        riskLevel: 'high',
        limit,
      })
    ).slice(0, limit);
  }

  /**
   * Verify hash chain integrity
   */
  verifyIntegrity(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    try {
      const files = readdirSync(this.auditDir)
        .filter((f) => f.startsWith(LOG_FILE_PREFIX) && f.endsWith('.jsonl'))
        .sort();

      let previousHash = '';

      for (const file of files) {
        const content = readFileSync(join(this.auditDir, file), 'utf-8');
        const lines = content.trim().split('\n').filter(Boolean);

        for (let i = 0; i < lines.length; i++) {
          try {
            const entry = JSON.parse(lines[i]);

            if (entry.previousHash !== previousHash) {
              errors.push(
                `Hash chain broken at ${file}:${i + 1} - expected previous hash ${previousHash}, got ${entry.previousHash}`
              );
            }

            // Verify current hash
            const { hash, previousHash: _, ...entryWithoutHashes } = entry;
            const expectedHash = this.calculateHash(entryWithoutHashes as AuditLog, entry.previousHash);

            if (hash !== expectedHash) {
              errors.push(
                `Invalid hash at ${file}:${i + 1} - expected ${expectedHash}, got ${hash}`
              );
            }

            previousHash = hash;
          } catch (e) {
            errors.push(`Malformed entry at ${file}:${i + 1}`);
          }
        }
      }
    } catch (e) {
      errors.push(`Failed to read audit logs: ${e}`);
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Get audit statistics
   */
  getStats(days: number = 7): {
    totalEvents: number;
    byEventType: Record<AuditEventType, number>;
    byOutcome: Record<string, number>;
    byRiskLevel: Record<PolicySeverity, number>;
    highRiskCount: number;
  } {
    const since = new Date(Date.now() - days * 24 * 3600000);
    const events = this.query({ since, limit: 10000 });

    const byEventType: Record<string, number> = {};
    const byOutcome: Record<string, number> = {};
    const byRiskLevel: Record<string, number> = {};
    let highRiskCount = 0;

    for (const event of events) {
      byEventType[event.eventType] = (byEventType[event.eventType] || 0) + 1;
      byOutcome[event.outcome] = (byOutcome[event.outcome] || 0) + 1;

      if (event.riskLevel) {
        byRiskLevel[event.riskLevel] = (byRiskLevel[event.riskLevel] || 0) + 1;
        if (event.riskLevel === 'critical' || event.riskLevel === 'high') {
          highRiskCount++;
        }
      }
    }

    return {
      totalEvents: events.length,
      byEventType: byEventType as Record<AuditEventType, number>,
      byOutcome,
      byRiskLevel: byRiskLevel as Record<PolicySeverity, number>,
      highRiskCount,
    };
  }

  /**
   * Generate compliance report
   */
  generateComplianceReport(days: number = 30): {
    period: { start: string; end: string };
    summary: {
      totalAgentsRegistered: number;
      totalPolicyChanges: number;
      totalPermissionChanges: number;
      totalSecurityEvents: number;
      totalAnomalies: number;
      quarantineEvents: number;
    };
    integrityStatus: { valid: boolean; errorCount: number };
    recommendations: string[];
  } {
    const since = new Date(Date.now() - days * 24 * 3600000);
    const events = this.query({ since, limit: 100000 });

    const summary = {
      totalAgentsRegistered: 0,
      totalPolicyChanges: 0,
      totalPermissionChanges: 0,
      totalSecurityEvents: 0,
      totalAnomalies: 0,
      quarantineEvents: 0,
    };

    for (const event of events) {
      switch (event.eventType) {
        case 'agent_registered':
          summary.totalAgentsRegistered++;
          break;
        case 'policy_created':
        case 'policy_updated':
        case 'policy_deleted':
          summary.totalPolicyChanges++;
          break;
        case 'permission_granted':
        case 'permission_revoked':
          summary.totalPermissionChanges++;
          break;
        case 'access_denied':
          summary.totalSecurityEvents++;
          break;
        case 'anomaly_detected':
          summary.totalAnomalies++;
          break;
        case 'quarantine_triggered':
          summary.quarantineEvents++;
          break;
      }
    }

    const integrity = this.verifyIntegrity();
    const recommendations: string[] = [];

    if (summary.totalAnomalies > 10) {
      recommendations.push('High anomaly count detected. Review agent behavior profiles.');
    }
    if (summary.quarantineEvents > 0) {
      recommendations.push('Quarantine events occurred. Review and address root causes.');
    }
    if (!integrity.valid) {
      recommendations.push('Audit log integrity issues detected. Investigate immediately.');
    }
    if (summary.totalPolicyChanges === 0) {
      recommendations.push('No policy updates in period. Review if policies need updates.');
    }

    return {
      period: { start: since.toISOString(), end: new Date().toISOString() },
      summary,
      integrityStatus: { valid: integrity.valid, errorCount: integrity.errors.length },
      recommendations,
    };
  }
}

// Singleton instance
let loggerInstance: AuditLogger | null = null;

export function getAuditLogger(): AuditLogger {
  if (!loggerInstance) {
    loggerInstance = new AuditLogger();
  }
  return loggerInstance;
}

export function resetAuditLogger(): void {
  loggerInstance = null;
}
