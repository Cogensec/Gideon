/**
 * Approval Gate System
 *
 * Human-in-the-loop approval for dangerous operations
 */

import { z } from 'zod';
import { AgentPhase, PhaseTransitionRequest } from './phases.js';

// ============================================================================
// Approval Types
// ============================================================================

export type ApprovalType =
  | 'phase_transition'
  | 'tool_execution'
  | 'data_access'
  | 'external_connection'
  | 'code_modification';

export const ApprovalTypeSchema = z.enum([
  'phase_transition',
  'tool_execution',
  'data_access',
  'external_connection',
  'code_modification',
]);

export interface ApprovalRequest {
  id: string;
  type: ApprovalType;
  title: string;
  description: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, unknown>;
  requestedAt: string;
  expiresAt?: string;
  context: {
    sessionId?: string;
    phase?: AgentPhase;
    target?: string;
  };
}

export interface ApprovalDecision {
  requestId: string;
  approved: boolean;
  decidedBy: string;
  decidedAt: string;
  reason?: string;
  conditions?: string[];
  modifiedDetails?: Record<string, unknown>;
}

export interface ApprovalPolicy {
  type: ApprovalType;
  autoApprove: boolean;
  requiresJustification: boolean;
  maxWaitTime: number; // milliseconds
  escalationContact?: string;
}

// ============================================================================
// Default Policies
// ============================================================================

export const DEFAULT_POLICIES: Record<ApprovalType, ApprovalPolicy> = {
  phase_transition: {
    type: 'phase_transition',
    autoApprove: false,
    requiresJustification: true,
    maxWaitTime: 300000, // 5 minutes
  },
  tool_execution: {
    type: 'tool_execution',
    autoApprove: false,
    requiresJustification: true,
    maxWaitTime: 60000, // 1 minute
  },
  data_access: {
    type: 'data_access',
    autoApprove: true,
    requiresJustification: false,
    maxWaitTime: 30000,
  },
  external_connection: {
    type: 'external_connection',
    autoApprove: true,
    requiresJustification: false,
    maxWaitTime: 30000,
  },
  code_modification: {
    type: 'code_modification',
    autoApprove: false,
    requiresJustification: true,
    maxWaitTime: 120000, // 2 minutes
  },
};

// ============================================================================
// Approval Manager
// ============================================================================

export class ApprovalManager {
  private pendingRequests: Map<string, ApprovalRequest> = new Map();
  private decisions: Map<string, ApprovalDecision> = new Map();
  private policies: Map<ApprovalType, ApprovalPolicy> = new Map();
  private approvalHandler?: (request: ApprovalRequest) => Promise<ApprovalDecision>;

  constructor() {
    // Initialize with default policies
    Object.values(DEFAULT_POLICIES).forEach((policy) => {
      this.policies.set(policy.type, policy);
    });
  }

  /**
   * Set approval handler (UI callback)
   */
  setApprovalHandler(handler: (request: ApprovalRequest) => Promise<ApprovalDecision>): void {
    this.approvalHandler = handler;
  }

  /**
   * Set policy for an approval type
   */
  setPolicy(type: ApprovalType, policy: Partial<ApprovalPolicy>): void {
    const existing = this.policies.get(type) || DEFAULT_POLICIES[type];
    this.policies.set(type, { ...existing, ...policy });
  }

  /**
   * Request approval
   */
  async requestApproval(request: Omit<ApprovalRequest, 'id' | 'requestedAt'>): Promise<ApprovalDecision> {
    const policy = this.policies.get(request.type) || DEFAULT_POLICIES[request.type];

    // Check if auto-approve is enabled
    if (policy.autoApprove) {
      return {
        requestId: crypto.randomUUID(),
        approved: true,
        decidedBy: 'auto',
        decidedAt: new Date().toISOString(),
        reason: 'Auto-approved by policy',
      };
    }

    // Create full request
    const fullRequest: ApprovalRequest = {
      ...request,
      id: crypto.randomUUID(),
      requestedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + policy.maxWaitTime).toISOString(),
    };

    this.pendingRequests.set(fullRequest.id, fullRequest);

    // Use handler if available
    if (this.approvalHandler) {
      try {
        const decision = await Promise.race([
          this.approvalHandler(fullRequest),
          this.waitForTimeout(policy.maxWaitTime),
        ]);

        if (decision) {
          this.decisions.set(fullRequest.id, decision);
          this.pendingRequests.delete(fullRequest.id);
          return decision;
        }
      } catch (error) {
        // Timeout or error - deny by default
      }
    }

    // No handler or timeout - deny
    const denial: ApprovalDecision = {
      requestId: fullRequest.id,
      approved: false,
      decidedBy: 'system',
      decidedAt: new Date().toISOString(),
      reason: 'No approval handler or request timed out',
    };

    this.decisions.set(fullRequest.id, denial);
    this.pendingRequests.delete(fullRequest.id);
    return denial;
  }

  /**
   * Create approval request for tool execution
   */
  async requestToolApproval(
    toolName: string,
    args: Record<string, unknown>,
    target: string,
    riskLevel: 'low' | 'medium' | 'high' | 'critical'
  ): Promise<ApprovalDecision> {
    return this.requestApproval({
      type: 'tool_execution',
      title: `Execute ${toolName}`,
      description: `Request to execute security tool: ${toolName}`,
      riskLevel,
      details: {
        tool: toolName,
        arguments: args,
        target,
      },
      context: { target },
    });
  }

  /**
   * Create approval request for phase transition
   */
  async requestPhaseApproval(request: PhaseTransitionRequest): Promise<ApprovalDecision> {
    const riskLevels: Record<AgentPhase, 'low' | 'medium' | 'high' | 'critical'> = {
      informational: 'low',
      exploitation: 'high',
      'post-exploitation': 'critical',
    };

    return this.requestApproval({
      type: 'phase_transition',
      title: `Phase Transition: ${request.fromPhase} → ${request.toPhase}`,
      description: request.reason,
      riskLevel: riskLevels[request.toPhase],
      details: {
        fromPhase: request.fromPhase,
        toPhase: request.toPhase,
        plannedActions: request.plannedActions,
        risks: request.risks,
        mitigations: request.mitigations,
      },
      context: {
        phase: request.fromPhase,
        target: request.targetInfo.domain || request.targetInfo.ip,
      },
    });
  }

  /**
   * Manually approve a pending request
   */
  approve(requestId: string, approver: string, conditions?: string[]): ApprovalDecision | null {
    const request = this.pendingRequests.get(requestId);
    if (!request) return null;

    const decision: ApprovalDecision = {
      requestId,
      approved: true,
      decidedBy: approver,
      decidedAt: new Date().toISOString(),
      conditions,
    };

    this.decisions.set(requestId, decision);
    this.pendingRequests.delete(requestId);
    return decision;
  }

  /**
   * Manually deny a pending request
   */
  deny(requestId: string, approver: string, reason: string): ApprovalDecision | null {
    const request = this.pendingRequests.get(requestId);
    if (!request) return null;

    const decision: ApprovalDecision = {
      requestId,
      approved: false,
      decidedBy: approver,
      decidedAt: new Date().toISOString(),
      reason,
    };

    this.decisions.set(requestId, decision);
    this.pendingRequests.delete(requestId);
    return decision;
  }

  /**
   * Get pending requests
   */
  getPendingRequests(): ApprovalRequest[] {
    return Array.from(this.pendingRequests.values());
  }

  /**
   * Get decision history
   */
  getDecisionHistory(): ApprovalDecision[] {
    return Array.from(this.decisions.values());
  }

  /**
   * Format approval request for CLI display
   */
  formatRequest(request: ApprovalRequest): string {
    const riskColors: Record<string, string> = {
      low: '🟢',
      medium: '🟡',
      high: '🟠',
      critical: '🔴',
    };

    return `
${riskColors[request.riskLevel]} **${request.title}**

**Type:** ${request.type}
**Risk Level:** ${request.riskLevel.toUpperCase()}
**Request ID:** ${request.id}

## Description
${request.description}

## Details
${Object.entries(request.details)
  .map(([key, value]) => `- **${key}:** ${JSON.stringify(value)}`)
  .join('\n')}

## Context
- Session: ${request.context.sessionId || 'N/A'}
- Phase: ${request.context.phase || 'N/A'}
- Target: ${request.context.target || 'N/A'}

**Requested at:** ${request.requestedAt}
**Expires at:** ${request.expiresAt || 'Never'}
`.trim();
  }

  /**
   * Wait for timeout
   */
  private waitForTimeout(ms: number): Promise<null> {
    return new Promise((resolve) => {
      setTimeout(() => resolve(null), ms);
    });
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let approvalManager: ApprovalManager | null = null;

export function getApprovalManager(): ApprovalManager {
  if (!approvalManager) {
    approvalManager = new ApprovalManager();
  }
  return approvalManager;
}
