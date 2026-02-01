import { existsSync, readFileSync, writeFileSync, mkdirSync, appendFileSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  AgentActivity,
  AgentActivitySchema,
  ActivityType,
  ResourceType,
  BehaviorProfile,
  Anomaly,
  PolicySeverity,
  GovernanceEvent,
} from './types';
import { getAgentRegistry } from './agent-registry';
import { getPolicyEngine } from './policy-engine';

const MONITOR_DIR = '.gideon/governance';
const ACTIVITY_LOG = 'activity.jsonl';
const PROFILES_FILE = 'behavior-profiles.json';
const ANOMALIES_FILE = 'anomalies.json';

type EventHandler = (event: GovernanceEvent) => void;

interface ProfilesData {
  profiles: Record<string, BehaviorProfile>;
  lastUpdated: string;
}

interface AnomaliesData {
  anomalies: Anomaly[];
  lastUpdated: string;
}

/**
 * Agent Monitor - Real-time behavioral analysis and anomaly detection
 *
 * Provides:
 * - Activity logging and tracking
 * - Behavioral profiling
 * - Anomaly detection
 * - Risk scoring
 * - Real-time alerts
 */
export class AgentMonitor {
  private basePath: string;
  private activityLogPath: string;
  private profilesPath: string;
  private anomaliesPath: string;
  private profiles: ProfilesData;
  private anomalies: AnomaliesData;
  private eventHandlers: EventHandler[] = [];
  private activityBuffer: AgentActivity[] = [];
  private rateLimitCounters: Map<string, { count: number; resetAt: number }> = new Map();

  constructor(basePath: string = process.cwd()) {
    this.basePath = basePath;
    const monitorDir = join(basePath, MONITOR_DIR);
    if (!existsSync(monitorDir)) {
      mkdirSync(monitorDir, { recursive: true });
    }

    this.activityLogPath = join(monitorDir, ACTIVITY_LOG);
    this.profilesPath = join(monitorDir, PROFILES_FILE);
    this.anomaliesPath = join(monitorDir, ANOMALIES_FILE);

    this.profiles = this.loadProfiles();
    this.anomalies = this.loadAnomalies();
  }

  private loadProfiles(): ProfilesData {
    if (existsSync(this.profilesPath)) {
      try {
        return JSON.parse(readFileSync(this.profilesPath, 'utf-8'));
      } catch {
        // Corrupted file
      }
    }
    return { profiles: {}, lastUpdated: new Date().toISOString() };
  }

  private saveProfiles(): void {
    this.profiles.lastUpdated = new Date().toISOString();
    writeFileSync(this.profilesPath, JSON.stringify(this.profiles, null, 2));
  }

  private loadAnomalies(): AnomaliesData {
    if (existsSync(this.anomaliesPath)) {
      try {
        return JSON.parse(readFileSync(this.anomaliesPath, 'utf-8'));
      } catch {
        // Corrupted file
      }
    }
    return { anomalies: [], lastUpdated: new Date().toISOString() };
  }

  private saveAnomalies(): void {
    this.anomalies.lastUpdated = new Date().toISOString();
    writeFileSync(this.anomaliesPath, JSON.stringify(this.anomalies, null, 2));
  }

  /**
   * Subscribe to governance events
   */
  onEvent(handler: EventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      const index = this.eventHandlers.indexOf(handler);
      if (index > -1) this.eventHandlers.splice(index, 1);
    };
  }

  private emit(event: GovernanceEvent): void {
    for (const handler of this.eventHandlers) {
      try {
        handler(event);
      } catch (error) {
        console.error('Event handler error:', error);
      }
    }
  }

  /**
   * Record an agent activity
   */
  async recordActivity(params: {
    agentId: string;
    sessionId?: string;
    type: ActivityType;
    action: string;
    resource?: string;
    resourceType?: ResourceType;
    parameters?: Record<string, any>;
    success: boolean;
    result?: any;
    error?: string;
    context?: {
      userQuery?: string;
      parentActivityId?: string;
      ipAddress?: string;
      userAgent?: string;
    };
  }): Promise<AgentActivity> {
    const now = new Date().toISOString();

    // Evaluate against policies
    const policyEngine = getPolicyEngine();
    const policyResult = policyEngine.evaluate({
      agentId: params.agentId,
      action: params.action,
      resourceType: params.resourceType,
      resource: params.resource,
      parameters: params.parameters,
    });

    // Calculate risk score
    const riskAssessment = this.assessRisk(params);

    const activity: AgentActivity = {
      id: uuidv4(),
      agentId: params.agentId,
      sessionId: params.sessionId,
      type: params.type,
      timestamp: now,
      action: params.action,
      resource: params.resource,
      resourceType: params.resourceType,
      parameters: params.parameters,
      success: params.success,
      result: params.result,
      error: params.error,
      policyEvaluation: {
        matched: policyResult.matchedRule !== null,
        ruleId: policyResult.matchedRule?.id,
        ruleName: policyResult.matchedRule?.name,
        action: policyResult.action,
        reason: policyResult.reason,
      },
      riskScore: riskAssessment.score,
      riskFactors: riskAssessment.factors,
      context: params.context,
    };

    AgentActivitySchema.parse(activity);

    // Append to log file
    appendFileSync(this.activityLogPath, JSON.stringify(activity) + '\n');

    // Buffer for analysis
    this.activityBuffer.push(activity);
    if (this.activityBuffer.length > 1000) {
      this.activityBuffer = this.activityBuffer.slice(-500);
    }

    // Update agent heartbeat
    const registry = getAgentRegistry();
    registry.heartbeat(params.agentId);

    // Handle policy violations
    if (!policyResult.allowed) {
      await this.handlePolicyViolation(activity, policyResult);
    }

    // Check for anomalies
    await this.checkForAnomalies(activity);

    // Check rate limits
    if (policyResult.action === 'rate_limit' && policyResult.matchedRule?.rateLimit) {
      const { allowed } = this.checkRateLimit(
        params.agentId,
        policyResult.matchedRule.rateLimit.requests,
        policyResult.matchedRule.rateLimit.windowSeconds
      );
      if (!allowed) {
        this.emit({
          type: 'governance_alert',
          severity: 'medium',
          message: `Agent ${params.agentId} rate limited`,
        });
      }
    }

    return activity;
  }

  /**
   * Assess risk for an activity
   */
  private assessRisk(params: {
    type: ActivityType;
    action: string;
    resourceType?: ResourceType;
    resource?: string;
  }): { score: number; factors: string[] } {
    const factors: string[] = [];
    let score = 0;

    // High-risk activity types
    const highRiskTypes: ActivityType[] = ['shell_command', 'secret_access', 'data_exfil', 'agent_spawn'];
    if (highRiskTypes.includes(params.type)) {
      score += 30;
      factors.push(`High-risk activity type: ${params.type}`);
    }

    // High-risk resource types
    const highRiskResources: ResourceType[] = ['secret', 'shell', 'external_agent'];
    if (params.resourceType && highRiskResources.includes(params.resourceType)) {
      score += 25;
      factors.push(`High-risk resource type: ${params.resourceType}`);
    }

    // Dangerous patterns in action
    const dangerousPatterns = [
      { pattern: /rm\s+-rf/i, score: 40, factor: 'Destructive delete command' },
      { pattern: /sudo/i, score: 20, factor: 'Privilege escalation attempt' },
      { pattern: /chmod\s+[67][67][67]/i, score: 15, factor: 'Dangerous permissions' },
      { pattern: /curl.*\|.*sh/i, score: 35, factor: 'Remote code execution pattern' },
      { pattern: /base64.*decode/i, score: 15, factor: 'Encoded content' },
      { pattern: /eval\(/i, score: 25, factor: 'Dynamic code execution' },
      { pattern: /password|secret|key|token/i, score: 10, factor: 'Sensitive data access' },
    ];

    const textToCheck = `${params.action} ${params.resource || ''}`;
    for (const { pattern, score: patternScore, factor } of dangerousPatterns) {
      if (pattern.test(textToCheck)) {
        score += patternScore;
        factors.push(factor);
      }
    }

    return { score: Math.min(100, score), factors };
  }

  /**
   * Handle a policy violation
   */
  private async handlePolicyViolation(
    activity: AgentActivity,
    policyResult: { matchedRule: any; action: string; reason: string; severity?: PolicySeverity }
  ): Promise<void> {
    // Emit violation event
    if (policyResult.matchedRule) {
      this.emit({
        type: 'policy_violation',
        activity,
        rule: policyResult.matchedRule,
      });
    }

    // Take action based on severity
    if (policyResult.severity === 'critical') {
      // Quarantine agent for critical violations
      const registry = getAgentRegistry();
      try {
        registry.quarantineAgent(
          activity.agentId,
          `Critical policy violation: ${policyResult.matchedRule?.name || 'Unknown'}`
        );
        this.emit({
          type: 'agent_quarantined',
          agentId: activity.agentId,
          reason: `Critical policy violation: ${policyResult.reason}`,
        });
      } catch {
        // Agent may not exist in registry
      }
    }
  }

  /**
   * Check rate limit for an agent
   */
  private checkRateLimit(
    agentId: string,
    maxRequests: number,
    windowSeconds: number
  ): { allowed: boolean; remaining: number } {
    const key = `${agentId}:rate`;
    const now = Date.now();
    const counter = this.rateLimitCounters.get(key);

    if (!counter || counter.resetAt < now) {
      this.rateLimitCounters.set(key, {
        count: 1,
        resetAt: now + windowSeconds * 1000,
      });
      return { allowed: true, remaining: maxRequests - 1 };
    }

    if (counter.count >= maxRequests) {
      return { allowed: false, remaining: 0 };
    }

    counter.count++;
    return { allowed: true, remaining: maxRequests - counter.count };
  }

  /**
   * Check for behavioral anomalies
   */
  private async checkForAnomalies(activity: AgentActivity): Promise<void> {
    const profile = this.profiles.profiles[activity.agentId];
    if (!profile) return;

    const anomalies: Anomaly[] = [];

    // Check for unusual activity rate
    const recentActivities = this.activityBuffer.filter(
      (a) =>
        a.agentId === activity.agentId &&
        new Date(a.timestamp).getTime() > Date.now() - 3600000 // Last hour
    );

    if (recentActivities.length > profile.activityPatterns.avgActivitiesPerHour * 3) {
      anomalies.push(this.createAnomaly(activity.agentId, 'unusual_activity_rate', 'high',
        `Activity rate ${recentActivities.length}/hr exceeds baseline ${profile.activityPatterns.avgActivitiesPerHour}/hr by 3x`,
        [{ activityId: activity.id, description: 'Triggering activity' }]
      ));
    }

    // Check for new resource access
    if (activity.resourceType) {
      const knownResources = profile.activityPatterns.commonResources.map((r) => r.type);
      if (!knownResources.includes(activity.resourceType)) {
        anomalies.push(this.createAnomaly(activity.agentId, 'new_resource_access', 'medium',
          `Agent accessing new resource type: ${activity.resourceType}`,
          [{ activityId: activity.id, description: `Access to ${activity.resource}` }]
        ));
      }
    }

    // Check for off-hours activity
    const hour = new Date(activity.timestamp).getHours();
    if (!profile.activityPatterns.peakActivityHours.includes(hour)) {
      const offHoursActivities = this.activityBuffer.filter(
        (a) =>
          a.agentId === activity.agentId &&
          !profile.activityPatterns.peakActivityHours.includes(new Date(a.timestamp).getHours())
      );

      if (offHoursActivities.length > 5) {
        anomalies.push(this.createAnomaly(activity.agentId, 'off_hours_activity', 'low',
          `Significant activity outside normal hours (${offHoursActivities.length} activities)`,
          [{ activityId: activity.id, description: 'Off-hours activity' }]
        ));
      }
    }

    // Save and emit anomalies
    for (const anomaly of anomalies) {
      this.anomalies.anomalies.push(anomaly);
      this.emit({ type: 'anomaly_detected', anomaly });
    }

    if (anomalies.length > 0) {
      this.saveAnomalies();
    }
  }

  private createAnomaly(
    agentId: string,
    type: Anomaly['type'],
    severity: PolicySeverity,
    description: string,
    evidence: Array<{ activityId: string; description: string }>
  ): Anomaly {
    return {
      id: uuidv4(),
      agentId,
      detectedAt: new Date().toISOString(),
      type,
      severity,
      description,
      evidence,
      status: 'new',
    };
  }

  /**
   * Build behavioral profile for an agent
   */
  async buildProfile(agentId: string, activities: AgentActivity[]): Promise<BehaviorProfile> {
    const agentActivities = activities.filter((a) => a.agentId === agentId);

    // Calculate activity patterns
    const hourCounts: Record<number, number> = {};
    const toolCounts: Record<string, number> = {};
    const resourceCounts: Record<string, number> = {};

    for (const activity of agentActivities) {
      const hour = new Date(activity.timestamp).getHours();
      hourCounts[hour] = (hourCounts[hour] || 0) + 1;

      if (activity.type === 'tool_call') {
        toolCounts[activity.action] = (toolCounts[activity.action] || 0) + 1;
      }

      if (activity.resourceType) {
        resourceCounts[activity.resourceType] = (resourceCounts[activity.resourceType] || 0) + 1;
      }
    }

    // Find peak hours (top 3)
    const peakHours = Object.entries(hourCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([hour]) => parseInt(hour));

    // Common tools
    const commonTools = Object.entries(toolCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, frequency]) => ({ name, frequency }));

    // Common resources
    const commonResources = Object.entries(resourceCounts)
      .map(([type, frequency]) => ({ type: type as ResourceType, frequency }));

    // Calculate averages
    const hourlyRates = Object.values(hourCounts);
    const avgActivitiesPerHour = hourlyRates.length > 0
      ? hourlyRates.reduce((a, b) => a + b, 0) / 24
      : 0;

    const profile: BehaviorProfile = {
      agentId,
      activityPatterns: {
        avgActivitiesPerHour,
        peakActivityHours: peakHours,
        commonTools,
        commonResources,
      },
      baseline: {
        avgResponseTime: 0, // Would need timing data
        avgTokensPerRequest: 0, // Would need token data
        errorRate: agentActivities.filter((a) => !a.success).length / Math.max(1, agentActivities.length),
        uniqueResourcesPerSession: 0,
      },
      thresholds: {
        activityRateDeviation: 2.0, // 2 standard deviations
        responseTimeDeviation: 2.0,
        errorRateThreshold: 0.1, // 10% error rate
        newResourceThreshold: 3,
      },
      lastUpdated: new Date().toISOString(),
    };

    this.profiles.profiles[agentId] = profile;
    this.saveProfiles();

    return profile;
  }

  /**
   * Get behavioral profile for an agent
   */
  getProfile(agentId: string): BehaviorProfile | undefined {
    return this.profiles.profiles[agentId];
  }

  /**
   * Get anomalies for an agent
   */
  getAnomalies(filters?: {
    agentId?: string;
    status?: Anomaly['status'];
    severity?: PolicySeverity;
    since?: Date;
  }): Anomaly[] {
    let result = [...this.anomalies.anomalies];

    if (filters?.agentId) {
      result = result.filter((a) => a.agentId === filters.agentId);
    }
    if (filters?.status) {
      result = result.filter((a) => a.status === filters.status);
    }
    if (filters?.severity) {
      result = result.filter((a) => a.severity === filters.severity);
    }
    if (filters?.since) {
      result = result.filter((a) => new Date(a.detectedAt) >= filters.since!);
    }

    return result.sort((a, b) =>
      new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime()
    );
  }

  /**
   * Update anomaly status
   */
  updateAnomalyStatus(
    anomalyId: string,
    status: Anomaly['status'],
    resolution?: string
  ): Anomaly | undefined {
    const anomaly = this.anomalies.anomalies.find((a) => a.id === anomalyId);
    if (!anomaly) return undefined;

    anomaly.status = status;
    if (resolution) {
      anomaly.resolution = resolution;
    }

    this.saveAnomalies();
    return anomaly;
  }

  /**
   * Get recent activities
   */
  getRecentActivities(limit: number = 100): AgentActivity[] {
    return this.activityBuffer.slice(-limit);
  }

  /**
   * Get activities for a specific agent
   */
  getAgentActivities(agentId: string, limit: number = 100): AgentActivity[] {
    return this.activityBuffer
      .filter((a) => a.agentId === agentId)
      .slice(-limit);
  }

  /**
   * Get activity statistics
   */
  getStats(timeRangeHours: number = 24): {
    totalActivities: number;
    byType: Record<ActivityType, number>;
    byResourceType: Record<ResourceType, number>;
    violations: number;
    anomalies: number;
    avgRiskScore: number;
  } {
    const cutoff = Date.now() - timeRangeHours * 3600000;
    const recentActivities = this.activityBuffer.filter(
      (a) => new Date(a.timestamp).getTime() > cutoff
    );

    const byType: Record<string, number> = {};
    const byResourceType: Record<string, number> = {};
    let violations = 0;
    let totalRisk = 0;
    let riskCount = 0;

    for (const activity of recentActivities) {
      byType[activity.type] = (byType[activity.type] || 0) + 1;

      if (activity.resourceType) {
        byResourceType[activity.resourceType] = (byResourceType[activity.resourceType] || 0) + 1;
      }

      if (activity.policyEvaluation?.action === 'deny') {
        violations++;
      }

      if (activity.riskScore !== undefined) {
        totalRisk += activity.riskScore;
        riskCount++;
      }
    }

    const recentAnomalies = this.anomalies.anomalies.filter(
      (a) => new Date(a.detectedAt).getTime() > cutoff
    );

    return {
      totalActivities: recentActivities.length,
      byType: byType as Record<ActivityType, number>,
      byResourceType: byResourceType as Record<ResourceType, number>,
      violations,
      anomalies: recentAnomalies.length,
      avgRiskScore: riskCount > 0 ? totalRisk / riskCount : 0,
    };
  }
}

// Singleton instance
let monitorInstance: AgentMonitor | null = null;

export function getAgentMonitor(): AgentMonitor {
  if (!monitorInstance) {
    monitorInstance = new AgentMonitor();
  }
  return monitorInstance;
}

export function resetAgentMonitor(): void {
  monitorInstance = null;
}
