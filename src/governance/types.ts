import { z } from 'zod';

// ============================================================================
// Agent Identity & Registration
// ============================================================================

export const AgentTypeSchema = z.enum([
  'claude-code',      // Claude Code agents
  'openclaw',         // OpenClaw agents (https://github.com/openclaw/openclaw)
  'custom-langchain', // Custom LangChain agents
  'autogen',          // Microsoft AutoGen
  'crewai',           // CrewAI agents
  'generic',          // Generic/unknown agent type
]);

export type AgentType = z.infer<typeof AgentTypeSchema>;

/**
 * Deprecated agent types mapped to their replacements.
 * Used for backward compatibility during migration.
 */
export const DEPRECATED_AGENT_TYPES: Record<string, AgentType> = {
  'moltbot': 'openclaw',    // MoltBot/Clawdbot deprecated, use OpenClaw
  'clawdbot': 'openclaw',   // Clawdbot deprecated, use OpenClaw
};

/**
 * Normalize agent type, converting deprecated types to their replacements.
 */
export function normalizeAgentType(type: string): AgentType {
  const normalized = type.toLowerCase();
  if (normalized in DEPRECATED_AGENT_TYPES) {
    return DEPRECATED_AGENT_TYPES[normalized];
  }
  // Validate against schema
  const result = AgentTypeSchema.safeParse(normalized);
  if (result.success) {
    return result.data;
  }
  return 'generic';
}

export const AgentStatusSchema = z.enum([
  'active',           // Agent is running and monitored
  'suspended',        // Agent temporarily suspended
  'quarantined',      // Agent isolated due to policy violation
  'revoked',          // Agent access permanently revoked
  'pending',          // Awaiting approval
]);

export type AgentStatus = z.infer<typeof AgentStatusSchema>;

export const AgentRegistrationSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(128),
  type: AgentTypeSchema,
  version: z.string().optional(),
  owner: z.string(),
  description: z.string().optional(),
  endpoint: z.string().url().optional(),
  publicKey: z.string().optional(),
  capabilities: z.array(z.string()),
  status: AgentStatusSchema,
  registeredAt: z.string().datetime(),
  lastSeenAt: z.string().datetime().optional(),
  metadata: z.record(z.any()).optional(),
});

export type AgentRegistration = z.infer<typeof AgentRegistrationSchema>;

// ============================================================================
// Security Policies
// ============================================================================

export const PolicyActionSchema = z.enum([
  'allow',            // Allow the action
  'deny',             // Deny the action
  'audit',            // Allow but log for audit
  'require_approval', // Require human approval
  'rate_limit',       // Apply rate limiting
  'sandbox',          // Execute in sandbox
]);

export type PolicyAction = z.infer<typeof PolicyActionSchema>;

export const PolicySeveritySchema = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]);

export type PolicySeverity = z.infer<typeof PolicySeveritySchema>;

export const ResourceTypeSchema = z.enum([
  'file',             // File system access
  'network',          // Network/API calls
  'database',         // Database operations
  'shell',            // Shell command execution
  'memory',           // Memory operations
  'model',            // LLM model invocations
  'tool',             // Tool/function calls
  'secret',           // Secret/credential access
  'external_agent',   // Communication with other agents
]);

export type ResourceType = z.infer<typeof ResourceTypeSchema>;

export const PolicyRuleSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  description: z.string(),
  enabled: z.boolean(),
  priority: z.number().int().min(0).max(1000),
  severity: PolicySeveritySchema,

  // Conditions
  conditions: z.object({
    agentTypes: z.array(AgentTypeSchema).optional(),
    agentIds: z.array(z.string().uuid()).optional(),
    resourceTypes: z.array(ResourceTypeSchema).optional(),
    patterns: z.array(z.string()).optional(), // Regex patterns
    timeWindows: z.array(z.object({
      start: z.string(), // HH:MM format
      end: z.string(),
      days: z.array(z.number().int().min(0).max(6)), // 0=Sunday
    })).optional(),
  }),

  // Actions
  action: PolicyActionSchema,
  rateLimit: z.object({
    requests: z.number(),
    windowSeconds: z.number(),
  }).optional(),

  // Metadata
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  createdBy: z.string(),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySetSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  description: z.string(),
  version: z.string(),
  rules: z.array(PolicyRuleSchema),
  defaultAction: PolicyActionSchema,
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export type PolicySet = z.infer<typeof PolicySetSchema>;

// ============================================================================
// Agent Activity & Monitoring
// ============================================================================

export const ActivityTypeSchema = z.enum([
  'tool_call',        // Agent called a tool
  'api_request',      // External API request
  'file_access',      // File system operation
  'shell_command',    // Shell command execution
  'model_invoke',     // LLM invocation
  'agent_spawn',      // Spawned another agent
  'agent_message',    // Inter-agent communication
  'secret_access',    // Accessed secrets/credentials
  'data_exfil',       // Potential data exfiltration
  'policy_violation', // Policy rule triggered
]);

export type ActivityType = z.infer<typeof ActivityTypeSchema>;

export const AgentActivitySchema = z.object({
  id: z.string().uuid(),
  agentId: z.string().uuid(),
  sessionId: z.string().optional(),
  type: ActivityTypeSchema,
  timestamp: z.string().datetime(),

  // Activity details
  action: z.string(),
  resource: z.string().optional(),
  resourceType: ResourceTypeSchema.optional(),
  parameters: z.record(z.any()).optional(),

  // Results
  success: z.boolean(),
  result: z.any().optional(),
  error: z.string().optional(),

  // Policy evaluation
  policyEvaluation: z.object({
    matched: z.boolean(),
    ruleId: z.string().uuid().optional(),
    ruleName: z.string().optional(),
    action: PolicyActionSchema,
    reason: z.string().optional(),
  }).optional(),

  // Risk scoring
  riskScore: z.number().min(0).max(100).optional(),
  riskFactors: z.array(z.string()).optional(),

  // Context
  context: z.object({
    userQuery: z.string().optional(),
    parentActivityId: z.string().uuid().optional(),
    ipAddress: z.string().optional(),
    userAgent: z.string().optional(),
  }).optional(),
});

export type AgentActivity = z.infer<typeof AgentActivitySchema>;

// ============================================================================
// Behavioral Analysis
// ============================================================================

export const BehaviorProfileSchema = z.object({
  agentId: z.string().uuid(),

  // Activity patterns
  activityPatterns: z.object({
    avgActivitiesPerHour: z.number(),
    peakActivityHours: z.array(z.number().int().min(0).max(23)),
    commonTools: z.array(z.object({
      name: z.string(),
      frequency: z.number(),
    })),
    commonResources: z.array(z.object({
      type: ResourceTypeSchema,
      frequency: z.number(),
    })),
  }),

  // Baseline metrics
  baseline: z.object({
    avgResponseTime: z.number(),
    avgTokensPerRequest: z.number(),
    errorRate: z.number(),
    uniqueResourcesPerSession: z.number(),
  }),

  // Anomaly thresholds
  thresholds: z.object({
    activityRateDeviation: z.number(), // Standard deviations
    responseTimeDeviation: z.number(),
    errorRateThreshold: z.number(),
    newResourceThreshold: z.number(),
  }),

  lastUpdated: z.string().datetime(),
});

export type BehaviorProfile = z.infer<typeof BehaviorProfileSchema>;

export const AnomalySchema = z.object({
  id: z.string().uuid(),
  agentId: z.string().uuid(),
  detectedAt: z.string().datetime(),
  type: z.enum([
    'unusual_activity_rate',
    'new_resource_access',
    'policy_violation_spike',
    'error_rate_spike',
    'off_hours_activity',
    'unusual_tool_usage',
    'data_volume_spike',
    'suspicious_pattern',
  ]),
  severity: PolicySeveritySchema,
  description: z.string(),
  evidence: z.array(z.object({
    activityId: z.string().uuid(),
    description: z.string(),
  })),
  status: z.enum(['new', 'investigating', 'resolved', 'false_positive']),
  resolution: z.string().optional(),
});

export type Anomaly = z.infer<typeof AnomalySchema>;

// ============================================================================
// Access Control
// ============================================================================

export const PermissionSchema = z.object({
  id: z.string().uuid(),
  agentId: z.string().uuid(),
  resourceType: ResourceTypeSchema,
  resource: z.string(), // Specific resource or pattern (e.g., "/data/*")
  actions: z.array(z.enum(['read', 'write', 'execute', 'delete', 'admin'])),
  granted: z.boolean(),
  grantedBy: z.string(),
  grantedAt: z.string().datetime(),
  expiresAt: z.string().datetime().optional(),
  conditions: z.object({
    requireMFA: z.boolean().optional(),
    maxUsageCount: z.number().optional(),
    allowedIPs: z.array(z.string()).optional(),
  }).optional(),
});

export type Permission = z.infer<typeof PermissionSchema>;

export const AccessRequestSchema = z.object({
  id: z.string().uuid(),
  agentId: z.string().uuid(),
  requestedAt: z.string().datetime(),
  resourceType: ResourceTypeSchema,
  resource: z.string(),
  action: z.string(),
  justification: z.string().optional(),
  status: z.enum(['pending', 'approved', 'denied', 'expired']),
  reviewedBy: z.string().optional(),
  reviewedAt: z.string().datetime().optional(),
  reviewNotes: z.string().optional(),
});

export type AccessRequest = z.infer<typeof AccessRequestSchema>;

// ============================================================================
// Audit & Compliance
// ============================================================================

export const AuditLogSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.string().datetime(),
  eventType: z.enum([
    'agent_registered',
    'agent_status_changed',
    'policy_created',
    'policy_updated',
    'policy_deleted',
    'permission_granted',
    'permission_revoked',
    'access_denied',
    'anomaly_detected',
    'quarantine_triggered',
    'governance_override',
  ]),
  actor: z.object({
    type: z.enum(['user', 'agent', 'system']),
    id: z.string(),
    name: z.string().optional(),
  }),
  target: z.object({
    type: z.string(),
    id: z.string(),
    name: z.string().optional(),
  }).optional(),
  details: z.record(z.any()),
  outcome: z.enum(['success', 'failure', 'partial']),
  riskLevel: PolicySeveritySchema.optional(),
});

export type AuditLog = z.infer<typeof AuditLogSchema>;

// ============================================================================
// Governance Dashboard Types
// ============================================================================

export interface GovernanceStats {
  totalAgents: number;
  activeAgents: number;
  suspendedAgents: number;
  quarantinedAgents: number;

  totalPolicies: number;
  activePolicies: number;

  activitiesLast24h: number;
  violationsLast24h: number;
  anomaliesLast24h: number;

  complianceScore: number; // 0-100
}

export interface AgentHealthStatus {
  agentId: string;
  agentName: string;
  status: AgentStatus;
  healthScore: number; // 0-100
  lastActivity: string;
  violationCount: number;
  anomalyCount: number;
  topRisks: string[];
}

// ============================================================================
// Governance Events
// ============================================================================

export type GovernanceEvent =
  | { type: 'agent_registered'; agent: AgentRegistration }
  | { type: 'agent_suspended'; agentId: string; reason: string }
  | { type: 'agent_quarantined'; agentId: string; reason: string }
  | { type: 'policy_violation'; activity: AgentActivity; rule: PolicyRule }
  | { type: 'anomaly_detected'; anomaly: Anomaly }
  | { type: 'access_denied'; request: AccessRequest; reason: string }
  | { type: 'governance_alert'; severity: PolicySeverity; message: string };
