import { z } from 'zod';

// ============================================================================
// GIDEON Mode & Session Types
// ============================================================================

export const GideonModeSchema = z.enum([
  'bounty',           // Bug bounty hunting mode
  'pentest',          // Authorized penetration testing
  'research',         // Security research (read-only analysis)
  'ctf',              // Capture the flag competition
]);

export type GideonMode = z.infer<typeof GideonModeSchema>;

export const EngagementStatusSchema = z.enum([
  'scoping',          // Defining scope and rules
  'recon',            // Reconnaissance phase
  'active',           // Active testing
  'reporting',        // Writing reports
  'paused',           // Engagement paused
  'completed',        // Engagement finished
]);

export type EngagementStatus = z.infer<typeof EngagementStatusSchema>;

// ============================================================================
// Scope Definition
// ============================================================================

export interface ScopeDefinition {
  programName: string;
  platform?: 'hackerone' | 'bugcrowd' | 'intigriti' | 'yeswehack' | 'private';

  // In-scope assets
  inScope: {
    domains: string[];
    wildcards: string[];        // *.example.com
    ipRanges: string[];
    applications: string[];
    apis: string[];
  };

  // Explicitly out of scope
  outOfScope: {
    domains: string[];
    ipRanges: string[];
    paths: string[];            // /admin, /internal
    vulnerabilityTypes: string[]; // DoS, social engineering
  };

  // Rules of engagement
  rules: {
    testingWindows?: string;    // "24/7" or "9am-5pm EST weekdays"
    rateLimit?: string;         // "10 req/sec max"
    requiredHeaders?: Record<string, string>;
    prohibitedActions: string[];
    specialInstructions?: string;
  };

  // Reward structure
  rewards?: {
    critical: string;
    high: string;
    medium: string;
    low: string;
    informational?: string;
  };

  // Safe harbor
  safeHarbor: boolean;
  disclosurePolicy?: 'coordinated' | 'full' | 'private';
  disclosureTimeline?: number;  // days
}

// ============================================================================
// Reconnaissance Types
// ============================================================================

export const ReconTypeSchema = z.enum([
  'passive',          // No direct target interaction
  'active',           // Direct target interaction
  'osint',            // Open source intelligence
]);

export type ReconType = z.infer<typeof ReconTypeSchema>;

export interface SubdomainResult {
  subdomain: string;
  source: string;
  ipAddresses?: string[];
  isAlive?: boolean;
  httpStatus?: number;
  technologies?: string[];
  interesting?: boolean;
  notes?: string;
}

export interface TechnologyFingerprint {
  name: string;
  version?: string;
  category: string;        // cms, framework, server, cdn, etc.
  confidence: number;      // 0-100
  evidence: string;
}

export interface PortScanResult {
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  version?: string;
  banner?: string;
}

export interface ReconSummary {
  target: string;
  timestamp: string;

  subdomains: SubdomainResult[];
  technologies: TechnologyFingerprint[];
  ports: PortScanResult[];

  interestingFindings: string[];
  priorityTargets: Array<{
    asset: string;
    reason: string;
    suggestedTests: string[];
  }>;

  nextSteps: string[];
}

// ============================================================================
// Vulnerability Types
// ============================================================================

export const VulnerabilityClassSchema = z.enum([
  // Injection
  'sqli',
  'nosqli',
  'cmdi',
  'ldapi',
  'xpathi',
  'ssti',
  'graphql_injection',

  // Auth & Session
  'auth_bypass',
  'session_fixation',
  'session_hijacking',
  'jwt_vuln',
  'oauth_misconfig',
  'password_reset',
  'mfa_bypass',

  // Access Control
  'idor',
  'privilege_escalation',
  'path_traversal',
  'lfi',
  'rfi',

  // Client-Side
  'xss_reflected',
  'xss_stored',
  'xss_dom',
  'csrf',
  'clickjacking',
  'postmessage',
  'websocket',
  'cors',

  // Business Logic
  'race_condition',
  'price_manipulation',
  'workflow_bypass',
  'rate_limit_bypass',
  'mass_assignment',

  // API
  'api_auth',
  'graphql_dos',
  'api_versioning',
  'undocumented_endpoint',

  // Cloud & Infra
  'ssrf',
  'cloud_misconfig',
  'k8s_misconfig',
  'container_escape',

  // Modern
  'prototype_pollution',
  'deserialization',
  'cache_poisoning',
  'request_smuggling',
  'subdomain_takeover',
]);

export type VulnerabilityClass = z.infer<typeof VulnerabilityClassSchema>;

export const SeverityLevelSchema = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]);

export type SeverityLevel = z.infer<typeof SeverityLevelSchema>;

// ============================================================================
// Finding Types
// ============================================================================

export interface Finding {
  id: string;
  title: string;
  severity: SeverityLevel;

  // Classification
  vulnerabilityClass: VulnerabilityClass;
  cwe: string[];
  owasp?: string[];

  // Location
  asset: string;
  endpoint?: string;
  parameter?: string;

  // Details
  summary: string;
  technicalDetails: string;

  // Reproduction
  stepsToReproduce: string[];
  proofOfConcept: {
    type: 'curl' | 'code' | 'burp' | 'screenshot' | 'video';
    content: string;
  };

  // Assessment
  impact: string;
  cvss?: {
    score: number;
    vector: string;
  };

  // Remediation
  remediation: string;
  references: string[];

  // Evidence
  evidence: Array<{
    type: 'request' | 'response' | 'screenshot' | 'log';
    filename?: string;
    content: string;
    timestamp: string;
  }>;

  // Metadata
  discoveredAt: string;
  reportedAt?: string;
  status: 'discovered' | 'validated' | 'reported' | 'triaged' | 'resolved' | 'duplicate';
}

// ============================================================================
// Attack Chain Types
// ============================================================================

export interface AttackChain {
  id: string;
  name: string;
  description: string;

  // Chain of findings
  steps: Array<{
    order: number;
    findingId: string;
    description: string;
    prerequisite?: string;
  }>;

  // Combined impact
  combinedImpact: string;
  combinedSeverity: SeverityLevel;

  // Narrative
  attackNarrative: string;
}

// ============================================================================
// Session State
// ============================================================================

export interface GideonSession {
  id: string;
  mode: GideonMode;
  status: EngagementStatus;
  startedAt: string;

  // Scope
  scope?: ScopeDefinition;

  // Findings
  findings: Finding[];
  attackChains: AttackChain[];

  // Recon data
  reconSummary?: ReconSummary;

  // Activity log
  activityLog: Array<{
    timestamp: string;
    action: string;
    details: string;
    phase: string;
  }>;

  // Notes
  notes: string[];
}

// ============================================================================
// Tool Recommendations
// ============================================================================

export interface ToolRecommendation {
  name: string;
  category: string;
  description: string;
  command?: string;
  installCommand?: string;
  url?: string;
  useCase: string;
}

export const TOOL_CATEGORIES = [
  'recon',
  'subdomain',
  'portscan',
  'fuzzing',
  'injection',
  'xss',
  'auth',
  'api',
  'cloud',
  'automation',
] as const;

export type ToolCategory = typeof TOOL_CATEGORIES[number];

// ============================================================================
// Command Types
// ============================================================================

export type GideonCommand =
  | { type: 'scope'; programName: string; scopeFile?: string }
  | { type: 'recon'; target: string; mode?: ReconType }
  | { type: 'hunt'; vulnClass: VulnerabilityClass }
  | { type: 'chain' }
  | { type: 'report'; severity: SeverityLevel; findingId?: string }
  | { type: 'tools'; category: ToolCategory }
  | { type: 'check'; target: string }
  | { type: 'severity'; finding?: string }
  | { type: 'status' }
  | { type: 'help' };
