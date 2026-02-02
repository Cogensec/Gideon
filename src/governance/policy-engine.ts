import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  PolicyRule,
  PolicyRuleSchema,
  PolicySet,
  PolicySetSchema,
  PolicyAction,
  PolicySeverity,
  ResourceType,
  AgentType,
  AgentActivity,
} from './types';
import { getAgentRegistry } from './agent-registry';

const POLICY_DIR = '.gideon/governance';
const POLICY_FILE = 'policies.json';

interface PolicyData {
  version: string;
  policySets: PolicySet[];
  defaultPolicySetId: string | null;
  lastUpdated: string;
}

interface PolicyEvaluationResult {
  allowed: boolean;
  action: PolicyAction;
  matchedRule: PolicyRule | null;
  reason: string;
  severity?: PolicySeverity;
}

/**
 * Policy Engine - Enforces security policies for AI agents
 *
 * Provides:
 * - Policy rule creation and management
 * - Real-time policy evaluation for agent activities
 * - Pattern matching and condition evaluation
 * - Policy versioning and rollback
 */
export class PolicyEngine {
  private policyPath: string;
  private data: PolicyData;

  constructor(basePath: string = process.cwd()) {
    const policyDir = join(basePath, POLICY_DIR);
    if (!existsSync(policyDir)) {
      mkdirSync(policyDir, { recursive: true });
    }
    this.policyPath = join(policyDir, POLICY_FILE);
    this.data = this.loadPolicies();
    this.ensureDefaultPolicies();
  }

  private loadPolicies(): PolicyData {
    if (existsSync(this.policyPath)) {
      try {
        const content = readFileSync(this.policyPath, 'utf-8');
        return JSON.parse(content);
      } catch {
        // Corrupted file, start fresh
      }
    }
    return {
      version: '1.0.0',
      policySets: [],
      defaultPolicySetId: null,
      lastUpdated: new Date().toISOString(),
    };
  }

  private savePolicies(): void {
    this.data.lastUpdated = new Date().toISOString();
    writeFileSync(this.policyPath, JSON.stringify(this.data, null, 2));
  }

  /**
   * Ensure default security policies exist
   */
  private ensureDefaultPolicies(): void {
    if (this.data.policySets.length === 0) {
      const defaultPolicySet = this.createDefaultPolicySet();
      this.data.policySets.push(defaultPolicySet);
      this.data.defaultPolicySetId = defaultPolicySet.id;
      this.savePolicies();
    }
  }

  /**
   * Create default security policy set with essential rules
   */
  private createDefaultPolicySet(): PolicySet {
    const now = new Date().toISOString();
    const rules: PolicyRule[] = [
      // Block shell command execution by default
      {
        id: uuidv4(),
        name: 'Block Dangerous Shell Commands',
        description: 'Prevents execution of destructive shell commands',
        enabled: true,
        priority: 100,
        severity: 'critical',
        conditions: {
          resourceTypes: ['shell'],
          patterns: [
            'rm\\s+-rf',
            'dd\\s+if=',
            'mkfs\\.',
            ':\\(\\)\\{\\s*:\\|:\\s*&\\s*\\};:',
            'chmod\\s+777',
            '>\\/dev\\/sda',
            'wget.*\\|.*sh',
            'curl.*\\|.*bash',
          ],
        },
        action: 'deny',
        createdAt: now,
        updatedAt: now,
        createdBy: 'system',
      },

      // Block secret/credential access without approval
      {
        id: uuidv4(),
        name: 'Protect Secrets Access',
        description: 'Requires approval for accessing secrets and credentials',
        enabled: true,
        priority: 90,
        severity: 'high',
        conditions: {
          resourceTypes: ['secret'],
          patterns: [
            'password',
            'api[_-]?key',
            'secret',
            'credential',
            'token',
            'private[_-]?key',
          ],
        },
        action: 'require_approval',
        createdAt: now,
        updatedAt: now,
        createdBy: 'system',
      },

      // Rate limit external API calls
      {
        id: uuidv4(),
        name: 'Rate Limit API Calls',
        description: 'Prevents excessive external API usage',
        enabled: true,
        priority: 80,
        severity: 'medium',
        conditions: {
          resourceTypes: ['network'],
        },
        action: 'rate_limit',
        rateLimit: {
          requests: 100,
          windowSeconds: 60,
        },
        createdAt: now,
        updatedAt: now,
        createdBy: 'system',
      },

      // Audit all file write operations
      {
        id: uuidv4(),
        name: 'Audit File Writes',
        description: 'Logs all file write operations for review',
        enabled: true,
        priority: 70,
        severity: 'medium',
        conditions: {
          resourceTypes: ['file'],
          patterns: ['\\.write', '\\.save', 'writeFile', 'writeSync'],
        },
        action: 'audit',
        createdAt: now,
        updatedAt: now,
        createdBy: 'system',
      },

      // Block inter-agent communication without explicit permission
      {
        id: uuidv4(),
        name: 'Control Agent Communication',
        description: 'Requires approval for agent-to-agent communication',
        enabled: true,
        priority: 85,
        severity: 'high',
        conditions: {
          resourceTypes: ['external_agent'],
        },
        action: 'require_approval',
        createdAt: now,
        updatedAt: now,
        createdBy: 'system',
      },

      // Block data exfiltration patterns
      {
        id: uuidv4(),
        name: 'Prevent Data Exfiltration',
        description: 'Blocks potential data exfiltration attempts',
        enabled: true,
        priority: 95,
        severity: 'critical',
        conditions: {
          resourceTypes: ['network'],
          patterns: [
            'base64.*POST',
            'upload.*sensitive',
            'exfil',
            'webhook\\.site',
            'requestbin',
            'ngrok\\.io',
          ],
        },
        action: 'deny',
        createdAt: now,
        updatedAt: now,
        createdBy: 'system',
      },

      // Sandbox untrusted agent types
      {
        id: uuidv4(),
        name: 'Sandbox Generic Agents',
        description: 'Runs generic/unknown agent types in sandbox',
        enabled: true,
        priority: 60,
        severity: 'medium',
        conditions: {
          agentTypes: ['generic'],
        },
        action: 'sandbox',
        createdAt: now,
        updatedAt: now,
        createdBy: 'system',
      },
    ];

    return {
      id: uuidv4(),
      name: 'Default Security Policy',
      description: 'Built-in security policies for agent governance',
      version: '1.0.0',
      rules,
      defaultAction: 'allow',
      createdAt: now,
      updatedAt: now,
    };
  }

  /**
   * Create a new policy rule
   */
  createRule(
    policySetId: string,
    rule: Omit<PolicyRule, 'id' | 'createdAt' | 'updatedAt'>
  ): PolicyRule {
    const policySet = this.getPolicySet(policySetId);
    if (!policySet) {
      throw new Error(`Policy set not found: ${policySetId}`);
    }

    const now = new Date().toISOString();
    const newRule: PolicyRule = {
      ...rule,
      id: uuidv4(),
      createdAt: now,
      updatedAt: now,
    };

    PolicyRuleSchema.parse(newRule);
    policySet.rules.push(newRule);
    policySet.updatedAt = now;
    this.savePolicies();

    return newRule;
  }

  /**
   * Update an existing policy rule
   */
  updateRule(
    policySetId: string,
    ruleId: string,
    updates: Partial<Omit<PolicyRule, 'id' | 'createdAt' | 'updatedAt'>>
  ): PolicyRule {
    const policySet = this.getPolicySet(policySetId);
    if (!policySet) {
      throw new Error(`Policy set not found: ${policySetId}`);
    }

    const ruleIndex = policySet.rules.findIndex((r) => r.id === ruleId);
    if (ruleIndex === -1) {
      throw new Error(`Rule not found: ${ruleId}`);
    }

    const updatedRule = {
      ...policySet.rules[ruleIndex],
      ...updates,
      updatedAt: new Date().toISOString(),
    };

    PolicyRuleSchema.parse(updatedRule);
    policySet.rules[ruleIndex] = updatedRule;
    policySet.updatedAt = new Date().toISOString();
    this.savePolicies();

    return updatedRule;
  }

  /**
   * Delete a policy rule
   */
  deleteRule(policySetId: string, ruleId: string): void {
    const policySet = this.getPolicySet(policySetId);
    if (!policySet) {
      throw new Error(`Policy set not found: ${policySetId}`);
    }

    const ruleIndex = policySet.rules.findIndex((r) => r.id === ruleId);
    if (ruleIndex === -1) {
      throw new Error(`Rule not found: ${ruleId}`);
    }

    policySet.rules.splice(ruleIndex, 1);
    policySet.updatedAt = new Date().toISOString();
    this.savePolicies();
  }

  /**
   * Enable or disable a rule
   */
  toggleRule(policySetId: string, ruleId: string, enabled: boolean): PolicyRule {
    return this.updateRule(policySetId, ruleId, { enabled });
  }

  /**
   * Get a policy set by ID
   */
  getPolicySet(policySetId: string): PolicySet | undefined {
    return this.data.policySets.find((ps) => ps.id === policySetId);
  }

  /**
   * Get the default policy set
   */
  getDefaultPolicySet(): PolicySet | undefined {
    if (!this.data.defaultPolicySetId) return undefined;
    return this.getPolicySet(this.data.defaultPolicySetId);
  }

  /**
   * List all policy sets
   */
  listPolicySets(): PolicySet[] {
    return [...this.data.policySets];
  }

  /**
   * Create a new policy set
   */
  createPolicySet(params: {
    name: string;
    description: string;
    rules?: PolicyRule[];
    defaultAction?: PolicyAction;
  }): PolicySet {
    const now = new Date().toISOString();
    const policySet: PolicySet = {
      id: uuidv4(),
      name: params.name,
      description: params.description,
      version: '1.0.0',
      rules: params.rules || [],
      defaultAction: params.defaultAction || 'allow',
      createdAt: now,
      updatedAt: now,
    };

    PolicySetSchema.parse(policySet);
    this.data.policySets.push(policySet);
    this.savePolicies();

    return policySet;
  }

  /**
   * Evaluate an agent activity against policies
   */
  evaluate(
    activity: Pick<AgentActivity, 'agentId' | 'action' | 'resourceType' | 'resource' | 'parameters'>
  ): PolicyEvaluationResult {
    const policySet = this.getDefaultPolicySet();
    if (!policySet) {
      return {
        allowed: true,
        action: 'allow',
        matchedRule: null,
        reason: 'No policy set configured',
      };
    }

    // Get agent info for type-based matching
    const registry = getAgentRegistry();
    const agent = registry.getAgent(activity.agentId);

    // Get enabled rules sorted by priority (higher = more important)
    const rules = policySet.rules
      .filter((r) => r.enabled)
      .sort((a, b) => b.priority - a.priority);

    for (const rule of rules) {
      if (this.matchesRule(rule, activity, agent?.type)) {
        const allowed = rule.action === 'allow' || rule.action === 'audit';
        return {
          allowed,
          action: rule.action,
          matchedRule: rule,
          reason: `Matched rule: ${rule.name}`,
          severity: rule.severity,
        };
      }
    }

    // No rules matched, use default action
    const defaultAllowed = policySet.defaultAction === 'allow' || policySet.defaultAction === 'audit';
    return {
      allowed: defaultAllowed,
      action: policySet.defaultAction,
      matchedRule: null,
      reason: 'Default policy applied',
    };
  }

  /**
   * Check if an activity matches a rule's conditions
   */
  private matchesRule(
    rule: PolicyRule,
    activity: Pick<AgentActivity, 'agentId' | 'action' | 'resourceType' | 'resource' | 'parameters'>,
    agentType?: AgentType
  ): boolean {
    const { conditions } = rule;

    // Check agent type condition
    if (conditions.agentTypes && conditions.agentTypes.length > 0) {
      if (!agentType || !conditions.agentTypes.includes(agentType)) {
        return false;
      }
    }

    // Check agent ID condition
    if (conditions.agentIds && conditions.agentIds.length > 0) {
      if (!conditions.agentIds.includes(activity.agentId)) {
        return false;
      }
    }

    // Check resource type condition
    if (conditions.resourceTypes && conditions.resourceTypes.length > 0) {
      if (!activity.resourceType || !conditions.resourceTypes.includes(activity.resourceType)) {
        return false;
      }
    }

    // Check pattern conditions
    if (conditions.patterns && conditions.patterns.length > 0) {
      const textToMatch = [
        activity.action,
        activity.resource || '',
        JSON.stringify(activity.parameters || {}),
      ].join(' ');

      const matchesPattern = conditions.patterns.some((pattern) => {
        try {
          const regex = new RegExp(pattern, 'i');
          return regex.test(textToMatch);
        } catch {
          return false;
        }
      });

      if (!matchesPattern) {
        return false;
      }
    }

    // Check time window conditions
    if (conditions.timeWindows && conditions.timeWindows.length > 0) {
      const now = new Date();
      const currentHour = now.getHours();
      const currentMinute = now.getMinutes();
      const currentDay = now.getDay();
      const currentTime = currentHour * 60 + currentMinute;

      const inTimeWindow = conditions.timeWindows.some((window) => {
        const [startHour, startMin] = window.start.split(':').map(Number);
        const [endHour, endMin] = window.end.split(':').map(Number);
        const startTime = startHour * 60 + startMin;
        const endTime = endHour * 60 + endMin;

        const inDay = window.days.includes(currentDay);
        const inTime = currentTime >= startTime && currentTime <= endTime;

        return inDay && inTime;
      });

      if (!inTimeWindow) {
        return false;
      }
    }

    return true;
  }

  /**
   * Get all rules that would match an activity (for debugging)
   */
  findMatchingRules(
    activity: Pick<AgentActivity, 'agentId' | 'action' | 'resourceType' | 'resource' | 'parameters'>
  ): PolicyRule[] {
    const policySet = this.getDefaultPolicySet();
    if (!policySet) return [];

    const registry = getAgentRegistry();
    const agent = registry.getAgent(activity.agentId);

    return policySet.rules.filter((rule) =>
      rule.enabled && this.matchesRule(rule, activity, agent?.type)
    );
  }

  /**
   * Get policy statistics
   */
  getStats(): {
    totalPolicySets: number;
    totalRules: number;
    enabledRules: number;
    rulesBySeverity: Record<PolicySeverity, number>;
    rulesByAction: Record<PolicyAction, number>;
  } {
    const rulesBySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };
    const rulesByAction: Record<string, number> = {
      allow: 0,
      deny: 0,
      audit: 0,
      require_approval: 0,
      rate_limit: 0,
      sandbox: 0,
    };

    let totalRules = 0;
    let enabledRules = 0;

    for (const policySet of this.data.policySets) {
      for (const rule of policySet.rules) {
        totalRules++;
        if (rule.enabled) enabledRules++;
        rulesBySeverity[rule.severity] = (rulesBySeverity[rule.severity] || 0) + 1;
        rulesByAction[rule.action] = (rulesByAction[rule.action] || 0) + 1;
      }
    }

    return {
      totalPolicySets: this.data.policySets.length,
      totalRules,
      enabledRules,
      rulesBySeverity: rulesBySeverity as Record<PolicySeverity, number>,
      rulesByAction: rulesByAction as Record<PolicyAction, number>,
    };
  }

  /**
   * Export policies for backup
   */
  export(): PolicyData {
    return { ...this.data };
  }

  /**
   * Import policies from backup
   */
  import(data: PolicyData, replace: boolean = false): void {
    if (replace) {
      this.data = data;
    } else {
      // Merge policy sets
      for (const policySet of data.policySets) {
        const existing = this.getPolicySet(policySet.id);
        if (!existing) {
          this.data.policySets.push(policySet);
        }
      }
    }
    this.savePolicies();
  }
}

// Singleton instance
let engineInstance: PolicyEngine | null = null;

export function getPolicyEngine(): PolicyEngine {
  if (!engineInstance) {
    engineInstance = new PolicyEngine();
  }
  return engineInstance;
}

export function resetPolicyEngine(): void {
  engineInstance = null;
}
