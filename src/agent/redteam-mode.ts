/**
 * Red Team Mode Manager
 *
 * Controls the transition between defensive and red team modes.
 * All offensive capabilities are gated behind authorized engagement activation.
 *
 * Security Model:
 * - Requires explicit engagement authorization with scope, ROE, and time bounds
 * - Every action is audit-logged
 * - Scope enforcement validates all targets before execution
 * - Auto-deactivates after engagement window expires
 */

import { z } from 'zod';

// ============================================================================
// Types
// ============================================================================

export type OperatingMode = 'defensive' | 'redteam';

export const OperatingModeSchema = z.enum(['defensive', 'redteam']);

/**
 * Engagement authorization - required to activate Red Team mode
 */
export interface EngagementAuthorization {
  /** Person/entity who authorized this engagement */
  authorizedBy: string;
  /** Organization the engagement is for */
  organization: string;
  /** Rules of engagement document reference (path or hash) */
  rulesOfEngagement: string;
  /** Engagement start time */
  startDate: string;
  /** Engagement end time */
  endDate: string;
  /** Engagement type */
  engagementType: 'pentest' | 'red-team' | 'purple-team' | 'assumed-breach';
  /** In-scope targets */
  scope: EngagementScope;
}

export interface EngagementScope {
  /** In-scope domains */
  domains: string[];
  /** In-scope wildcard domains (e.g., *.example.com) */
  wildcardDomains: string[];
  /** In-scope IP addresses */
  ipAddresses: string[];
  /** In-scope CIDR ranges */
  cidrRanges: string[];
  /** Explicitly out-of-scope targets */
  exclusions: string[];
  /** Allowed attack techniques (MITRE ATT&CK IDs) */
  allowedTechniques?: string[];
  /** Forbidden attack techniques */
  forbiddenTechniques?: string[];
  /** Maximum privilege escalation level */
  maxPrivilegeLevel?: 'user' | 'admin' | 'system' | 'domain-admin';
  /** Allow lateral movement */
  allowLateralMovement: boolean;
  /** Allow data exfiltration (simulated) */
  allowDataExfiltration: boolean;
  /** Allow persistence mechanisms */
  allowPersistence: boolean;
}

/**
 * Active Red Team engagement
 */
export interface RedTeamEngagement {
  /** Engagement ID */
  id: string;
  /** Operating mode */
  mode: 'redteam';
  /** Authorization details */
  authorization: EngagementAuthorization;
  /** When Red Team mode was activated */
  activatedAt: string;
  /** When it was deactivated (null if still active) */
  deactivatedAt: string | null;
  /** Running audit log */
  auditLog: AuditEntry[];
  /** Current engagement statistics */
  stats: EngagementStats;
}

export interface EngagementStats {
  totalActions: number;
  toolExecutions: number;
  exploitsAttempted: number;
  exploitsSuccessful: number;
  sessionsEstablished: number;
  hostsCompromised: number;
  credentialsHarvested: number;
  lateralMovements: number;
}

export interface AuditEntry {
  timestamp: string;
  action: string;
  category: 'mode_change' | 'tool_execution' | 'exploit' | 'c2' | 'lateral_movement' | 'credential' | 'payload' | 'scope_check';
  target?: string;
  details: Record<string, unknown>;
  result: 'success' | 'failure' | 'blocked' | 'pending';
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

// ============================================================================
// Zod Schemas for Validation
// ============================================================================

export const EngagementScopeSchema = z.object({
  domains: z.array(z.string()),
  wildcardDomains: z.array(z.string()),
  ipAddresses: z.array(z.string()),
  cidrRanges: z.array(z.string()),
  exclusions: z.array(z.string()),
  allowedTechniques: z.array(z.string()).optional(),
  forbiddenTechniques: z.array(z.string()).optional(),
  maxPrivilegeLevel: z.enum(['user', 'admin', 'system', 'domain-admin']).optional(),
  allowLateralMovement: z.boolean(),
  allowDataExfiltration: z.boolean(),
  allowPersistence: z.boolean(),
});

export const EngagementAuthorizationSchema = z.object({
  authorizedBy: z.string().min(1),
  organization: z.string().min(1),
  rulesOfEngagement: z.string().min(1),
  startDate: z.string(),
  endDate: z.string(),
  engagementType: z.enum(['pentest', 'red-team', 'purple-team', 'assumed-breach']),
  scope: EngagementScopeSchema,
});

// ============================================================================
// Red Team Mode Manager (Singleton)
// ============================================================================

export class RedTeamModeManager {
  private currentMode: OperatingMode = 'defensive';
  private activeEngagement: RedTeamEngagement | null = null;
  private activationCallback?: (engagement: RedTeamEngagement) => Promise<boolean>;

  /**
   * Get the current operating mode
   */
  getMode(): OperatingMode {
    // Auto-deactivate if engagement has expired
    if (this.activeEngagement) {
      const now = new Date();
      const endDate = new Date(this.activeEngagement.authorization.endDate);
      if (now > endDate) {
        this.deactivateRedTeamMode('Engagement window expired');
      }
    }
    return this.currentMode;
  }

  /**
   * Check if Red Team mode is currently active
   */
  isRedTeamMode(): boolean {
    return this.getMode() === 'redteam';
  }

  /**
   * Get the active engagement (null if in defensive mode)
   */
  getActiveEngagement(): RedTeamEngagement | null {
    if (!this.isRedTeamMode()) return null;
    return this.activeEngagement;
  }

  /**
   * Get engagement scope (null if not in red team mode)
   */
  getScope(): EngagementScope | null {
    return this.activeEngagement?.authorization.scope ?? null;
  }

  /**
   * Activate Red Team mode with proper authorization
   */
  async activateRedTeamMode(
    authorization: EngagementAuthorization
  ): Promise<{ success: boolean; engagement?: RedTeamEngagement; error?: string }> {
    // Validate authorization
    const parseResult = EngagementAuthorizationSchema.safeParse(authorization);
    if (!parseResult.success) {
      return {
        success: false,
        error: `Invalid authorization: ${parseResult.error.message}`,
      };
    }

    // Validate time window
    const now = new Date();
    const startDate = new Date(authorization.startDate);
    const endDate = new Date(authorization.endDate);

    if (now < startDate) {
      return {
        success: false,
        error: `Engagement has not started yet. Start date: ${authorization.startDate}`,
      };
    }

    if (now > endDate) {
      return {
        success: false,
        error: `Engagement has expired. End date: ${authorization.endDate}`,
      };
    }

    // Validate scope has at least one target
    const scope = authorization.scope;
    const hasTargets =
      scope.domains.length > 0 ||
      scope.wildcardDomains.length > 0 ||
      scope.ipAddresses.length > 0 ||
      scope.cidrRanges.length > 0;

    if (!hasTargets) {
      return {
        success: false,
        error: 'Engagement scope must define at least one target (domain, IP, or CIDR range)',
      };
    }

    // Create engagement
    const engagement: RedTeamEngagement = {
      id: crypto.randomUUID(),
      mode: 'redteam',
      authorization,
      activatedAt: now.toISOString(),
      deactivatedAt: null,
      auditLog: [],
      stats: {
        totalActions: 0,
        toolExecutions: 0,
        exploitsAttempted: 0,
        exploitsSuccessful: 0,
        sessionsEstablished: 0,
        hostsCompromised: 0,
        credentialsHarvested: 0,
        lateralMovements: 0,
      },
    };

    // Record activation in audit log
    engagement.auditLog.push({
      timestamp: now.toISOString(),
      action: 'Red Team mode activated',
      category: 'mode_change',
      details: {
        authorizedBy: authorization.authorizedBy,
        organization: authorization.organization,
        engagementType: authorization.engagementType,
        scopeTargets: scope.domains.length + scope.ipAddresses.length + scope.cidrRanges.length,
      },
      result: 'success',
      riskLevel: 'critical',
    });

    // Request human confirmation if callback is set
    if (this.activationCallback) {
      const approved = await this.activationCallback(engagement);
      if (!approved) {
        return {
          success: false,
          error: 'Red Team mode activation denied by operator',
        };
      }
    }

    this.activeEngagement = engagement;
    this.currentMode = 'redteam';

    return { success: true, engagement };
  }

  /**
   * Deactivate Red Team mode
   */
  deactivateRedTeamMode(reason: string = 'Manual deactivation'): void {
    if (this.activeEngagement) {
      this.activeEngagement.deactivatedAt = new Date().toISOString();
      this.addAuditEntry({
        action: `Red Team mode deactivated: ${reason}`,
        category: 'mode_change',
        details: { reason, stats: { ...this.activeEngagement.stats } },
        result: 'success',
        riskLevel: 'critical',
      });
    }
    this.currentMode = 'defensive';
    this.activeEngagement = null;
  }

  /**
   * Validate a target is within engagement scope
   */
  isTargetInScope(target: string): { inScope: boolean; reason: string } {
    if (!this.activeEngagement) {
      return { inScope: false, reason: 'No active engagement' };
    }

    const scope = this.activeEngagement.authorization.scope;

    // Check exclusions first
    if (scope.exclusions.some(excl => this.matchesTarget(target, excl))) {
      return { inScope: false, reason: `Target '${target}' is explicitly excluded from scope` };
    }

    // Check exact domain match
    if (scope.domains.some(d => target.toLowerCase() === d.toLowerCase())) {
      return { inScope: true, reason: `Target '${target}' matches scoped domain` };
    }

    // Check wildcard domain match (e.g., *.example.com)
    for (const wildcard of scope.wildcardDomains) {
      const baseDomain = wildcard.replace('*.', '');
      if (target.toLowerCase().endsWith(baseDomain.toLowerCase())) {
        return { inScope: true, reason: `Target '${target}' matches wildcard '${wildcard}'` };
      }
    }

    // Check IP address match
    if (scope.ipAddresses.some(ip => target === ip)) {
      return { inScope: true, reason: `Target '${target}' matches scoped IP address` };
    }

    // Check CIDR range match
    for (const cidr of scope.cidrRanges) {
      if (this.isIpInCidr(target, cidr)) {
        return { inScope: true, reason: `Target '${target}' is within CIDR range '${cidr}'` };
      }
    }

    return { inScope: false, reason: `Target '${target}' is not within engagement scope` };
  }

  /**
   * Add an entry to the engagement audit log
   */
  addAuditEntry(entry: Omit<AuditEntry, 'timestamp'>): void {
    if (!this.activeEngagement) return;

    this.activeEngagement.auditLog.push({
      ...entry,
      timestamp: new Date().toISOString(),
    });
    this.activeEngagement.stats.totalActions++;
  }

  /**
   * Increment engagement statistics
   */
  incrementStat(stat: keyof Omit<EngagementStats, 'totalActions'>): void {
    if (!this.activeEngagement) return;
    this.activeEngagement.stats[stat]++;
  }

  /**
   * Get the full audit log
   */
  getAuditLog(): AuditEntry[] {
    return this.activeEngagement?.auditLog ?? [];
  }

  /**
   * Get engagement statistics
   */
  getStats(): EngagementStats | null {
    return this.activeEngagement?.stats ?? null;
  }

  /**
   * Set callback for human-in-the-loop activation approval
   */
  setActivationCallback(callback: (engagement: RedTeamEngagement) => Promise<boolean>): void {
    this.activationCallback = callback;
  }

  /**
   * Format engagement status for display
   */
  formatStatus(): string {
    if (!this.activeEngagement) {
      return '🛡️ **Mode: Defensive** — Red Team mode is not active.';
    }

    const eng = this.activeEngagement;
    const scope = eng.authorization.scope;
    const stats = eng.stats;
    const endDate = new Date(eng.authorization.endDate);
    const remaining = Math.max(0, (endDate.getTime() - Date.now()) / (1000 * 60 * 60));

    return `
🔴 **Mode: RED TEAM** — Authorized engagement active

**Engagement ID:** ${eng.id}
**Type:** ${eng.authorization.engagementType}
**Organization:** ${eng.authorization.organization}
**Authorized By:** ${eng.authorization.authorizedBy}
**Time Remaining:** ${remaining.toFixed(1)} hours
**Activated:** ${eng.activatedAt}

## Scope
- **Domains:** ${scope.domains.join(', ') || 'None'}
- **Wildcards:** ${scope.wildcardDomains.join(', ') || 'None'}
- **IPs:** ${scope.ipAddresses.join(', ') || 'None'}
- **CIDRs:** ${scope.cidrRanges.join(', ') || 'None'}
- **Exclusions:** ${scope.exclusions.join(', ') || 'None'}
- **Lateral Movement:** ${scope.allowLateralMovement ? '✓' : '✗'}
- **Data Exfiltration:** ${scope.allowDataExfiltration ? '✓' : '✗'}
- **Persistence:** ${scope.allowPersistence ? '✓' : '✗'}

## Statistics
- **Total Actions:** ${stats.totalActions}
- **Tool Executions:** ${stats.toolExecutions}
- **Exploits Attempted:** ${stats.exploitsAttempted}
- **Exploits Successful:** ${stats.exploitsSuccessful}
- **Sessions Established:** ${stats.sessionsEstablished}
- **Hosts Compromised:** ${stats.hostsCompromised}
- **Credentials Harvested:** ${stats.credentialsHarvested}
- **Lateral Movements:** ${stats.lateralMovements}
`.trim();
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private matchesTarget(target: string, pattern: string): boolean {
    if (pattern.startsWith('*.')) {
      const base = pattern.slice(2);
      return target.toLowerCase().endsWith(base.toLowerCase());
    }
    return target.toLowerCase() === pattern.toLowerCase();
  }

  private isIpInCidr(ip: string, cidr: string): boolean {
    try {
      const [cidrIp, prefixStr] = cidr.split('/');
      if (!cidrIp || !prefixStr) return false;

      const prefix = parseInt(prefixStr, 10);
      if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

      const ipNum = this.ipToNumber(ip);
      const cidrNum = this.ipToNumber(cidrIp);
      if (ipNum === null || cidrNum === null) return false;

      const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
      return (ipNum & mask) === (cidrNum & mask);
    } catch {
      return false;
    }
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;

    let num = 0;
    for (const part of parts) {
      const octet = parseInt(part, 10);
      if (isNaN(octet) || octet < 0 || octet > 255) return null;
      num = (num << 8) + octet;
    }
    return num >>> 0;
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let redTeamManager: RedTeamModeManager | null = null;

export function getRedTeamManager(): RedTeamModeManager {
  if (!redTeamManager) {
    redTeamManager = new RedTeamModeManager();
  }
  return redTeamManager;
}

/**
 * Convenience: check if Red Team mode is active
 */
export function isRedTeamMode(): boolean {
  return getRedTeamManager().isRedTeamMode();
}

/**
 * Convenience: get active engagement
 */
export function getActiveEngagement(): RedTeamEngagement | null {
  return getRedTeamManager().getActiveEngagement();
}

/**
 * Convenience: validate target scope
 */
export function isTargetInScope(target: string): { inScope: boolean; reason: string } {
  return getRedTeamManager().isTargetInScope(target);
}
