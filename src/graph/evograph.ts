/**
 * EvoGraph - Evolutionary Attack Tracking
 *
 * Persistent attack chain graph that tracks every step, finding,
 * decision, and failure across the attack lifecycle.
 * Enables cross-session intelligence accumulation.
 */

import { GraphClient, getGraphClient } from './index.js';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// EvoGraph Types
// ============================================================================

export interface EvoNode {
  id: string;
  type: EvoNodeType;
  sessionId: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export type EvoNodeType =
  | 'Decision'
  | 'Action'
  | 'Finding'
  | 'Failure'
  | 'Checkpoint';

export interface EvoDecision {
  id: string;
  sessionId: string;
  timestamp: string;
  reasoning: string;
  options: string[];
  selectedOption: string;
  confidence: number;
  context: Record<string, unknown>;
}

export interface EvoAction {
  id: string;
  sessionId: string;
  timestamp: string;
  tool: string;
  command: string;
  arguments: Record<string, unknown>;
  result: 'success' | 'failure' | 'partial';
  output?: string;
  duration: number;
}

export interface EvoFinding {
  id: string;
  sessionId: string;
  timestamp: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  evidence: string;
  sourceAction: string;
}

export interface EvoFailure {
  id: string;
  sessionId: string;
  timestamp: string;
  action: string;
  error: string;
  recoveryAttempts: number;
  recovered: boolean;
  lessonsLearned?: string;
}

export interface EvoCheckpoint {
  id: string;
  sessionId: string;
  timestamp: string;
  phase: string;
  state: Record<string, unknown>;
  resumable: boolean;
}

// ============================================================================
// EvoGraph Client
// ============================================================================

export class EvoGraph {
  private client: GraphClient;

  constructor(client?: GraphClient) {
    this.client = client ?? getGraphClient();
  }

  /**
   * Record a decision made by the agent
   */
  async recordDecision(decision: Omit<EvoDecision, 'id' | 'timestamp'>): Promise<EvoDecision> {
    const id = uuidv4();
    const timestamp = new Date().toISOString();

    const node: EvoDecision = { id, timestamp, ...decision };

    await this.client.write(
      `CREATE (n:EvoDecision $props) RETURN n`,
      { props: node }
    );

    return node;
  }

  /**
   * Record an action taken by the agent
   */
  async recordAction(action: Omit<EvoAction, 'id' | 'timestamp'>): Promise<EvoAction> {
    const id = uuidv4();
    const timestamp = new Date().toISOString();

    const node: EvoAction = { id, timestamp, ...action };

    await this.client.write(
      `CREATE (n:EvoAction $props) RETURN n`,
      { props: node }
    );

    return node;
  }

  /**
   * Record a finding discovered during assessment
   */
  async recordFinding(finding: Omit<EvoFinding, 'id' | 'timestamp'>): Promise<EvoFinding> {
    const id = uuidv4();
    const timestamp = new Date().toISOString();

    const node: EvoFinding = { id, timestamp, ...finding };

    await this.client.write(
      `CREATE (n:EvoFinding $props)
       WITH n
       MATCH (a:EvoAction {id: $actionId})
       CREATE (a)-[:PRODUCED]->(n)
       RETURN n`,
      { props: node, actionId: finding.sourceAction }
    );

    return node;
  }

  /**
   * Record a failure that occurred
   */
  async recordFailure(failure: Omit<EvoFailure, 'id' | 'timestamp'>): Promise<EvoFailure> {
    const id = uuidv4();
    const timestamp = new Date().toISOString();

    const node: EvoFailure = { id, timestamp, ...failure };

    await this.client.write(
      `CREATE (n:EvoFailure $props)
       WITH n
       MATCH (a:EvoAction {id: $actionId})
       CREATE (a)-[:FAILED_WITH]->(n)
       RETURN n`,
      { props: node, actionId: failure.action }
    );

    return node;
  }

  /**
   * Create a checkpoint for session resumption
   */
  async createCheckpoint(checkpoint: Omit<EvoCheckpoint, 'id' | 'timestamp'>): Promise<EvoCheckpoint> {
    const id = uuidv4();
    const timestamp = new Date().toISOString();

    const node: EvoCheckpoint = { id, timestamp, ...checkpoint };

    await this.client.write(
      `CREATE (n:EvoCheckpoint $props) RETURN n`,
      { props: { ...node, state: JSON.stringify(node.state) } }
    );

    return node;
  }

  /**
   * Get the latest checkpoint for a session
   */
  async getLatestCheckpoint(sessionId: string): Promise<EvoCheckpoint | null> {
    const results = await this.client.query<{ n: EvoCheckpoint }>(
      `MATCH (n:EvoCheckpoint {sessionId: $sessionId})
       WHERE n.resumable = true
       RETURN n
       ORDER BY n.timestamp DESC
       LIMIT 1`,
      { sessionId }
    );

    if (results.length === 0) return null;

    const checkpoint = results[0].n;
    if (typeof checkpoint.state === 'string') {
      checkpoint.state = JSON.parse(checkpoint.state);
    }
    return checkpoint;
  }

  /**
   * Link a decision to subsequent actions
   */
  async linkDecisionToAction(decisionId: string, actionId: string): Promise<void> {
    await this.client.write(
      `MATCH (d:EvoDecision {id: $decisionId}), (a:EvoAction {id: $actionId})
       CREATE (d)-[:LED_TO]->(a)`,
      { decisionId, actionId }
    );
  }

  /**
   * Get attack chain history for a session
   */
  async getSessionHistory(sessionId: string): Promise<{
    decisions: EvoDecision[];
    actions: EvoAction[];
    findings: EvoFinding[];
    failures: EvoFailure[];
  }> {
    const [decisions, actions, findings, failures] = await Promise.all([
      this.client.query<{ n: EvoDecision }>(
        `MATCH (n:EvoDecision {sessionId: $sessionId}) RETURN n ORDER BY n.timestamp`,
        { sessionId }
      ),
      this.client.query<{ n: EvoAction }>(
        `MATCH (n:EvoAction {sessionId: $sessionId}) RETURN n ORDER BY n.timestamp`,
        { sessionId }
      ),
      this.client.query<{ n: EvoFinding }>(
        `MATCH (n:EvoFinding {sessionId: $sessionId}) RETURN n ORDER BY n.timestamp`,
        { sessionId }
      ),
      this.client.query<{ n: EvoFailure }>(
        `MATCH (n:EvoFailure {sessionId: $sessionId}) RETURN n ORDER BY n.timestamp`,
        { sessionId }
      ),
    ]);

    return {
      decisions: decisions.map((r) => r.n),
      actions: actions.map((r) => r.n),
      findings: findings.map((r) => r.n),
      failures: failures.map((r) => r.n),
    };
  }

  /**
   * Find similar past failures to learn from
   */
  async findSimilarFailures(error: string, limit: number = 5): Promise<EvoFailure[]> {
    const results = await this.client.query<{ n: EvoFailure }>(
      `MATCH (n:EvoFailure)
       WHERE n.error CONTAINS $errorKeyword
       RETURN n
       ORDER BY n.timestamp DESC
       LIMIT $limit`,
      { errorKeyword: error.substring(0, 50), limit }
    );

    return results.map((r) => r.n);
  }

  /**
   * Get successful action patterns for a tool
   */
  async getSuccessfulPatterns(tool: string, limit: number = 10): Promise<EvoAction[]> {
    const results = await this.client.query<{ n: EvoAction }>(
      `MATCH (n:EvoAction {tool: $tool, result: 'success'})
       RETURN n
       ORDER BY n.timestamp DESC
       LIMIT $limit`,
      { tool, limit }
    );

    return results.map((r) => r.n);
  }

  /**
   * Calculate session statistics
   */
  async getSessionStats(sessionId: string): Promise<{
    totalDecisions: number;
    totalActions: number;
    successfulActions: number;
    failedActions: number;
    totalFindings: number;
    findingsBySeverity: Record<string, number>;
    duration: number;
  }> {
    const results = await this.client.query<{
      totalDecisions: number;
      totalActions: number;
      successfulActions: number;
      failedActions: number;
      totalFindings: number;
      minTime: string;
      maxTime: string;
    }>(
      `MATCH (d:EvoDecision {sessionId: $sessionId})
       WITH count(d) as totalDecisions
       MATCH (a:EvoAction {sessionId: $sessionId})
       WITH totalDecisions, count(a) as totalActions,
            sum(CASE WHEN a.result = 'success' THEN 1 ELSE 0 END) as successfulActions,
            sum(CASE WHEN a.result = 'failure' THEN 1 ELSE 0 END) as failedActions,
            min(a.timestamp) as minTime, max(a.timestamp) as maxTime
       MATCH (f:EvoFinding {sessionId: $sessionId})
       RETURN totalDecisions, totalActions, successfulActions, failedActions,
              count(f) as totalFindings, minTime, maxTime`,
      { sessionId }
    );

    const severityResults = await this.client.query<{ severity: string; count: number }>(
      `MATCH (f:EvoFinding {sessionId: $sessionId})
       RETURN f.severity as severity, count(*) as count`,
      { sessionId }
    );

    const findingsBySeverity: Record<string, number> = {};
    severityResults.forEach((r) => {
      findingsBySeverity[r.severity] = r.count;
    });

    const stats = results[0] || {
      totalDecisions: 0,
      totalActions: 0,
      successfulActions: 0,
      failedActions: 0,
      totalFindings: 0,
      minTime: new Date().toISOString(),
      maxTime: new Date().toISOString(),
    };

    const duration = stats.minTime && stats.maxTime
      ? new Date(stats.maxTime).getTime() - new Date(stats.minTime).getTime()
      : 0;

    return {
      ...stats,
      findingsBySeverity,
      duration,
    };
  }

  /**
   * Export session intelligence for cross-session learning
   */
  async exportSessionIntelligence(sessionId: string): Promise<{
    patterns: Array<{ tool: string; successRate: number; commonArgs: string[] }>;
    avoidPatterns: Array<{ tool: string; commonErrors: string[] }>;
    discoveries: Array<{ type: string; count: number }>;
  }> {
    // Get tool success rates
    const toolStats = await this.client.query<{
      tool: string;
      total: number;
      successful: number;
    }>(
      `MATCH (a:EvoAction {sessionId: $sessionId})
       RETURN a.tool as tool, count(*) as total,
              sum(CASE WHEN a.result = 'success' THEN 1 ELSE 0 END) as successful`,
      { sessionId }
    );

    const patterns = toolStats.map((s) => ({
      tool: s.tool,
      successRate: s.total > 0 ? s.successful / s.total : 0,
      commonArgs: [],
    }));

    // Get common errors
    const errorStats = await this.client.query<{ tool: string; errors: string[] }>(
      `MATCH (a:EvoAction {sessionId: $sessionId})-[:FAILED_WITH]->(f:EvoFailure)
       RETURN a.tool as tool, collect(f.error) as errors`,
      { sessionId }
    );

    const avoidPatterns = errorStats.map((e) => ({
      tool: e.tool,
      commonErrors: e.errors,
    }));

    // Get discovery types
    const discoveryStats = await this.client.query<{ type: string; count: number }>(
      `MATCH (f:EvoFinding {sessionId: $sessionId})
       RETURN f.type as type, count(*) as count`,
      { sessionId }
    );

    return {
      patterns,
      avoidPatterns,
      discoveries: discoveryStats,
    };
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let evoGraph: EvoGraph | null = null;

export function getEvoGraph(): EvoGraph {
  if (!evoGraph) {
    evoGraph = new EvoGraph();
  }
  return evoGraph;
}
