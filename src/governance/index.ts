/**
 * Gideon Agent Security Governance
 *
 * A comprehensive security governance framework for AI agents.
 * Provides centralized control, monitoring, and policy enforcement
 * for deployed AI agents (Claude, MoltBot, OpenClaw, etc.)
 *
 * Core Components:
 * - Agent Registry: Track and manage registered AI agents
 * - Policy Engine: Define and enforce security policies
 * - Agent Monitor: Real-time behavioral analysis and anomaly detection
 * - Access Control: Fine-grained permission management
 * - Audit Logger: Immutable audit trail for compliance
 */

// Types
export * from './types';

// Agent Registry
export { AgentRegistry, getAgentRegistry, resetAgentRegistry } from './agent-registry';

// Policy Engine
export { PolicyEngine, getPolicyEngine, resetPolicyEngine } from './policy-engine';

// Agent Monitor
export { AgentMonitor, getAgentMonitor, resetAgentMonitor } from './agent-monitor';

// Access Control
export { AccessControl, getAccessControl, resetAccessControl } from './access-control';

// Audit Logger
export { AuditLogger, getAuditLogger, resetAuditLogger } from './audit-logger';

// Governance Facade for simplified access
import { getAgentRegistry } from './agent-registry';
import { getPolicyEngine } from './policy-engine';
import { getAgentMonitor } from './agent-monitor';
import { getAccessControl } from './access-control';
import { getAuditLogger } from './audit-logger';
import {
  AgentType,
  AgentStatus,
  GovernanceStats,
  AgentHealthStatus,
  GovernanceEvent,
} from './types';

/**
 * Gideon Governance - Unified governance interface
 *
 * Provides a high-level API for common governance operations.
 */
export class GideonGovernance {
  private eventHandlers: Array<(event: GovernanceEvent) => void> = [];

  constructor() {
    // Subscribe to monitor events and forward them
    const monitor = getAgentMonitor();
    monitor.onEvent((event) => {
      for (const handler of this.eventHandlers) {
        handler(event);
      }
    });
  }

  /**
   * Subscribe to governance events
   */
  onEvent(handler: (event: GovernanceEvent) => void): () => void {
    this.eventHandlers.push(handler);
    return () => {
      const index = this.eventHandlers.indexOf(handler);
      if (index > -1) this.eventHandlers.splice(index, 1);
    };
  }

  /**
   * Register a new agent for governance
   */
  registerAgent(params: {
    name: string;
    type: AgentType;
    owner: string;
    capabilities: string[];
    description?: string;
    endpoint?: string;
  }) {
    const registry = getAgentRegistry();
    const logger = getAuditLogger();

    const agent = registry.registerAgent(params);

    logger.logAgentRegistered(
      { type: 'user', id: params.owner, name: params.owner },
      agent.id,
      agent.name,
      agent.type
    );

    return agent;
  }

  /**
   * Activate a pending agent
   */
  activateAgent(agentId: string, approvedBy: string) {
    const registry = getAgentRegistry();
    const logger = getAuditLogger();

    const agent = registry.activateAgent(agentId);

    logger.logAgentStatusChanged(
      { type: 'user', id: approvedBy, name: approvedBy },
      agent.id,
      agent.name,
      'pending',
      'active'
    );

    return agent;
  }

  /**
   * Suspend an agent
   */
  suspendAgent(agentId: string, reason: string, suspendedBy: string) {
    const registry = getAgentRegistry();
    const logger = getAuditLogger();

    const agent = registry.getAgent(agentId);
    const oldStatus = agent?.status || 'unknown';

    const updated = registry.suspendAgent(agentId, reason);

    logger.logAgentStatusChanged(
      { type: 'user', id: suspendedBy, name: suspendedBy },
      updated.id,
      updated.name,
      oldStatus,
      'suspended',
      reason
    );

    return updated;
  }

  /**
   * Record agent activity with full governance evaluation
   */
  async recordActivity(params: {
    agentId: string;
    sessionId?: string;
    type: Parameters<ReturnType<typeof getAgentMonitor>['recordActivity']>[0]['type'];
    action: string;
    resource?: string;
    resourceType?: Parameters<ReturnType<typeof getAgentMonitor>['recordActivity']>[0]['resourceType'];
    parameters?: Record<string, any>;
    success: boolean;
    result?: any;
    error?: string;
  }) {
    const monitor = getAgentMonitor();
    return monitor.recordActivity(params);
  }

  /**
   * Check if an agent has permission for an action
   */
  checkAccess(
    agentId: string,
    resourceType: Parameters<ReturnType<typeof getAccessControl>['checkPermission']>[1],
    resource: string,
    action: 'read' | 'write' | 'execute' | 'delete' | 'admin'
  ) {
    const accessControl = getAccessControl();
    const result = accessControl.checkPermission(agentId, resourceType, resource, action);

    if (!result.allowed) {
      const registry = getAgentRegistry();
      const agent = registry.getAgent(agentId);
      const logger = getAuditLogger();

      logger.logAccessDenied(
        agentId,
        agent?.name || 'Unknown',
        resourceType,
        resource,
        action,
        result.reason
      );
    }

    return result;
  }

  /**
   * Grant permission to an agent
   */
  grantPermission(params: {
    agentId: string;
    resourceType: Parameters<ReturnType<typeof getAccessControl>['grantPermission']>[0]['resourceType'];
    resource: string;
    actions: Array<'read' | 'write' | 'execute' | 'delete' | 'admin'>;
    grantedBy: string;
    expiresAt?: string;
  }) {
    const accessControl = getAccessControl();
    const registry = getAgentRegistry();
    const logger = getAuditLogger();

    const permission = accessControl.grantPermission(params);
    const agent = registry.getAgent(params.agentId);

    logger.logPermissionGranted(
      { type: 'user', id: params.grantedBy, name: params.grantedBy },
      params.agentId,
      agent?.name || 'Unknown',
      params.resourceType,
      params.resource,
      params.actions
    );

    return permission;
  }

  /**
   * Get governance dashboard statistics
   */
  getStats(): GovernanceStats {
    const registry = getAgentRegistry();
    const policyEngine = getPolicyEngine();
    const monitor = getAgentMonitor();

    const registryStats = registry.getStats();
    const policyStats = policyEngine.getStats();
    const monitorStats = monitor.getStats(24);

    return {
      totalAgents: registryStats.total,
      activeAgents: registryStats.byStatus.active || 0,
      suspendedAgents: registryStats.byStatus.suspended || 0,
      quarantinedAgents: registryStats.byStatus.quarantined || 0,
      totalPolicies: policyStats.totalPolicySets,
      activePolicies: policyStats.enabledRules,
      activitiesLast24h: monitorStats.totalActivities,
      violationsLast24h: monitorStats.violations,
      anomaliesLast24h: monitorStats.anomalies,
      complianceScore: this.calculateComplianceScore(monitorStats),
    };
  }

  private calculateComplianceScore(stats: ReturnType<typeof getAgentMonitor>['getStats']): number {
    const total = stats.totalActivities;
    if (total === 0) return 100;

    const violations = stats.violations;
    const anomalies = stats.anomalies;

    // Simple compliance score: 100 - (violations + anomalies) / total * 100
    const score = 100 - ((violations + anomalies) / total) * 100;
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  /**
   * Get health status for all agents
   */
  getAgentHealthStatuses(): AgentHealthStatus[] {
    const registry = getAgentRegistry();
    const monitor = getAgentMonitor();

    return registry.listAgents().map((agent) => {
      const anomalies = monitor.getAnomalies({ agentId: agent.id, status: 'new' });
      const activities = monitor.getAgentActivities(agent.id, 100);
      const violations = activities.filter((a) => a.policyEvaluation?.action === 'deny');

      const avgRisk = activities.reduce((sum, a) => sum + (a.riskScore || 0), 0) /
        Math.max(1, activities.length);

      return {
        agentId: agent.id,
        agentName: agent.name,
        status: agent.status,
        healthScore: Math.max(0, 100 - avgRisk),
        lastActivity: agent.lastSeenAt || agent.registeredAt,
        violationCount: violations.length,
        anomalyCount: anomalies.length,
        topRisks: [...new Set(activities.flatMap((a) => a.riskFactors || []))].slice(0, 5),
      };
    });
  }

  /**
   * Generate compliance report
   */
  generateComplianceReport(days: number = 30) {
    const logger = getAuditLogger();
    return logger.generateComplianceReport(days);
  }

  /**
   * Verify audit log integrity
   */
  verifyAuditIntegrity() {
    const logger = getAuditLogger();
    return logger.verifyIntegrity();
  }
}

// Singleton instance
let governanceInstance: GideonGovernance | null = null;

export function getGideonGovernance(): GideonGovernance {
  if (!governanceInstance) {
    governanceInstance = new GideonGovernance();
  }
  return governanceInstance;
}

export function resetGideonGovernance(): void {
  governanceInstance = null;
}
