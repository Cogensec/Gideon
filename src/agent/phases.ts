/**
 * Phase-Aware Execution System
 *
 * Manages agent execution phases with approval gates for dangerous operations
 */

import { z } from 'zod';

// ============================================================================
// Phase Definitions
// ============================================================================

export type AgentPhase = 'informational' | 'exploitation' | 'post-exploitation';

export const AgentPhaseSchema = z.enum(['informational', 'exploitation', 'post-exploitation']);

export interface PhaseConfig {
  name: AgentPhase;
  description: string;
  autoApprove: boolean;
  allowedTools: string[];
  blockedTools: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  requiresScope: boolean;
}

export const PHASE_CONFIGS: Record<AgentPhase, PhaseConfig> = {
  informational: {
    name: 'informational',
    description: 'Reconnaissance and passive data gathering. No active exploitation.',
    autoApprove: true,
    allowedTools: [
      'nmap', 'nuclei', 'httpx', 'katana', 'subfinder', 'amass',
      'ffuf', 'whois', 'dig', 'curl', 'security_search',
    ],
    blockedTools: ['sqlmap', 'hydra', 'metasploit', 'msfconsole'],
    riskLevel: 'low',
    requiresScope: true,
  },
  exploitation: {
    name: 'exploitation',
    description: 'Active vulnerability testing and exploitation. Requires approval.',
    autoApprove: false,
    allowedTools: [
      'sqlmap', 'hydra', 'nuclei', 'nmap', 'httpx',
    ],
    blockedTools: ['metasploit', 'msfconsole'],
    riskLevel: 'high',
    requiresScope: true,
  },
  'post-exploitation': {
    name: 'post-exploitation',
    description: 'Lateral movement and persistence simulation. Requires approval.',
    autoApprove: false,
    allowedTools: ['metasploit', 'msfconsole'],
    blockedTools: [],
    riskLevel: 'critical',
    requiresScope: true,
  },
};

// ============================================================================
// Phase Transition
// ============================================================================

export interface PhaseTransitionRequest {
  fromPhase: AgentPhase;
  toPhase: AgentPhase;
  reason: string;
  plannedActions: string[];
  risks: string[];
  mitigations: string[];
  targetInfo: {
    domain?: string;
    ip?: string;
    service?: string;
  };
}

export interface PhaseTransitionResult {
  approved: boolean;
  phase: AgentPhase;
  approvedBy?: 'auto' | 'user';
  approvedAt?: string;
  deniedReason?: string;
  conditions?: string[];
}

// ============================================================================
// Phase Manager
// ============================================================================

export class PhaseManager {
  private currentPhase: AgentPhase = 'informational';
  private transitionHistory: PhaseTransitionResult[] = [];
  private approvalCallback?: (request: PhaseTransitionRequest) => Promise<boolean>;

  constructor() {
    this.currentPhase = 'informational';
  }

  /**
   * Get current phase
   */
  getCurrentPhase(): AgentPhase {
    return this.currentPhase;
  }

  /**
   * Get phase configuration
   */
  getPhaseConfig(): PhaseConfig {
    return PHASE_CONFIGS[this.currentPhase];
  }

  /**
   * Check if a tool is allowed in the current phase
   */
  isToolAllowed(toolName: string): { allowed: boolean; reason?: string } {
    const config = PHASE_CONFIGS[this.currentPhase];

    // Check if explicitly blocked
    if (config.blockedTools.includes(toolName)) {
      return {
        allowed: false,
        reason: `Tool '${toolName}' is blocked in ${this.currentPhase} phase`,
      };
    }

    // If allowedTools is specified and non-empty, check membership
    if (config.allowedTools.length > 0 && !config.allowedTools.includes(toolName)) {
      return {
        allowed: false,
        reason: `Tool '${toolName}' is not in the allowed list for ${this.currentPhase} phase`,
      };
    }

    return { allowed: true };
  }

  /**
   * Request phase transition
   */
  async requestTransition(request: PhaseTransitionRequest): Promise<PhaseTransitionResult> {
    const targetConfig = PHASE_CONFIGS[request.toPhase];

    // Check if auto-approve is enabled for the target phase
    if (targetConfig.autoApprove) {
      const result: PhaseTransitionResult = {
        approved: true,
        phase: request.toPhase,
        approvedBy: 'auto',
        approvedAt: new Date().toISOString(),
      };

      this.currentPhase = request.toPhase;
      this.transitionHistory.push(result);
      return result;
    }

    // Request user approval
    if (this.approvalCallback) {
      const approved = await this.approvalCallback(request);

      const result: PhaseTransitionResult = {
        approved,
        phase: approved ? request.toPhase : this.currentPhase,
        approvedBy: approved ? 'user' : undefined,
        approvedAt: approved ? new Date().toISOString() : undefined,
        deniedReason: approved ? undefined : 'User denied phase transition',
      };

      if (approved) {
        this.currentPhase = request.toPhase;
      }

      this.transitionHistory.push(result);
      return result;
    }

    // No approval callback, deny by default
    const result: PhaseTransitionResult = {
      approved: false,
      phase: this.currentPhase,
      deniedReason: 'No approval mechanism configured',
    };

    this.transitionHistory.push(result);
    return result;
  }

  /**
   * Set approval callback for phase transitions
   */
  setApprovalCallback(callback: (request: PhaseTransitionRequest) => Promise<boolean>): void {
    this.approvalCallback = callback;
  }

  /**
   * Get transition history
   */
  getTransitionHistory(): PhaseTransitionResult[] {
    return [...this.transitionHistory];
  }

  /**
   * Reset to informational phase
   */
  reset(): void {
    this.currentPhase = 'informational';
    this.transitionHistory = [];
  }

  /**
   * Format phase transition request for display
   */
  formatTransitionRequest(request: PhaseTransitionRequest): string {
    return `
# Phase Transition Request

**From:** ${request.fromPhase}
**To:** ${request.toPhase}

## Reason
${request.reason}

## Planned Actions
${request.plannedActions.map((a) => `- ${a}`).join('\n')}

## Risks
${request.risks.map((r) => `- ${r}`).join('\n')}

## Mitigations
${request.mitigations.map((m) => `- ${m}`).join('\n')}

## Target Information
- Domain: ${request.targetInfo.domain || 'N/A'}
- IP: ${request.targetInfo.ip || 'N/A'}
- Service: ${request.targetInfo.service || 'N/A'}
`.trim();
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let phaseManager: PhaseManager | null = null;

export function getPhaseManager(): PhaseManager {
  if (!phaseManager) {
    phaseManager = new PhaseManager();
  }
  return phaseManager;
}
