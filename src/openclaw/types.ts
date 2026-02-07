import { z } from 'zod';

// ============================================================================
// OpenClaw Sidecar Types
// Gideon Security Sidecar for OpenClaw Agent Deployments
// ============================================================================

// --- Gateway Connection ---

export const OpenClawBindModeSchema = z.enum([
  'localhost',
  'lan',
  'tailnet',
  'custom',
]);

export type OpenClawBindMode = z.infer<typeof OpenClawBindModeSchema>;

export const OpenClawGatewayConfigSchema = z.object({
  /** WebSocket URL of the OpenClaw gateway */
  gatewayUrl: z.string().default('ws://127.0.0.1:18789'),
  /** Authentication token for gateway connection */
  authToken: z.string().optional(),
  /** How the gateway is bound to the network */
  bindMode: OpenClawBindModeSchema.default('localhost'),
  /** Path to OpenClaw home directory */
  openclawHome: z.string().default('~/.openclaw'),
  /** Reconnection interval in ms */
  reconnectIntervalMs: z.number().default(5000),
  /** Maximum reconnection attempts */
  maxReconnectAttempts: z.number().default(10),
});

export type OpenClawGatewayConfig = z.infer<typeof OpenClawGatewayConfigSchema>;

// --- Gateway Tool Permissions ---

export const OpenClawToolPermissionSchema = z.enum([
  'exec',
  'process',
  'read',
  'write',
  'edit',
  'browser',
  'canvas',
  'nodes',
  'cron',
  'discord',
  'gateway',
  'sessions_list',
  'sessions_history',
  'sessions_send',
  'sessions_spawn',
  'session_status',
]);

export type OpenClawToolPermission = z.infer<typeof OpenClawToolPermissionSchema>;

/** Tools allowed by default in OpenClaw */
export const OPENCLAW_DEFAULT_ALLOWED_TOOLS: OpenClawToolPermission[] = [
  'exec', 'process', 'read', 'write', 'edit',
  'sessions_list', 'sessions_history', 'sessions_send',
  'sessions_spawn', 'session_status',
];

/** Tools denied by default in OpenClaw */
export const OPENCLAW_DEFAULT_DENIED_TOOLS: OpenClawToolPermission[] = [
  'browser', 'canvas', 'nodes', 'cron', 'discord', 'gateway',
];

// --- WebSocket Message Types ---

export const WsMessageTypeSchema = z.enum([
  'tool_call',
  'tool_result',
  'session_spawn',
  'session_send',
  'session_kill',
  'operator_admin',
  'operator_approvals',
  'exec_request',
  'exec_result',
  'file_read',
  'file_write',
  'browser_navigate',
  'memory_write',
  'config_change',
  'auth_challenge',
  'auth_response',
  'heartbeat',
  'unknown',
]);

export type WsMessageType = z.infer<typeof WsMessageTypeSchema>;

export interface GatewayMessage {
  id: string;
  type: WsMessageType;
  timestamp: string;
  sessionId?: string;
  agentId?: string;
  payload: Record<string, any>;
  raw?: string;
}

// --- Sentinel Alert Types ---

export const AlertSeveritySchema = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]);

export type AlertSeverity = z.infer<typeof AlertSeveritySchema>;

export const AlertCategorySchema = z.enum([
  'privilege_escalation',
  'sandbox_escape',
  'token_exfiltration',
  'command_injection',
  'prompt_injection',
  'memory_poisoning',
  'credential_access',
  'data_exfiltration',
  'unauthorized_access',
  'config_tampering',
  'supply_chain',
  'cross_origin_ws',
  'approval_bypass',
  'skill_malware',
  'session_hijack',
  'rate_anomaly',
  'misconfiguration',
]);

export type AlertCategory = z.infer<typeof AlertCategorySchema>;

export interface SentinelAlert {
  id: string;
  timestamp: string;
  severity: AlertSeverity;
  category: AlertCategory;
  title: string;
  description: string;
  evidence: AlertEvidence[];
  cveReferences?: string[];
  mitreTechniques?: string[];
  recommendation: string;
  autoAction?: 'quarantine' | 'kill_session' | 'block' | 'alert_only';
  resolved: boolean;
}

export interface AlertEvidence {
  type: 'message' | 'file' | 'config' | 'pattern' | 'behavioral';
  source: string;
  content: string;
  timestamp: string;
}

// --- Skill Scanner Types ---

export const SkillRiskLevelSchema = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'clean',
]);

export type SkillRiskLevel = z.infer<typeof SkillRiskLevelSchema>;

export interface SkillScanResult {
  skillName: string;
  skillPath: string;
  riskLevel: SkillRiskLevel;
  score: number; // 0-100, higher = more dangerous
  findings: SkillFinding[];
  iocHits: IOCHit[];
  publisherAnalysis: PublisherAnalysis;
  scannedAt: string;
  scanDurationMs: number;
}

export interface SkillFinding {
  type: 'malicious_pattern' | 'obfuscation' | 'permission_overreach' |
        'suspicious_prerequisite' | 'credential_harvesting' | 'reverse_shell' |
        'data_exfiltration' | 'typosquat' | 'known_malware';
  severity: AlertSeverity;
  description: string;
  file: string;
  line?: number;
  matchedPattern: string;
  confidence: number;
}

export interface IOCHit {
  indicator: string;
  type: 'url' | 'domain' | 'ip' | 'hash';
  source: string;
  malicious: boolean;
  details: string;
}

export interface PublisherAnalysis {
  accountAge: number; // days
  totalSkills: number;
  publishingVelocity: number; // skills per day
  hasVerifiedEmail: boolean;
  suspiciousIndicators: string[];
  riskScore: number; // 0-100
}

// --- Prompt Injection Types ---

export interface InjectionScanResult {
  isInjection: boolean;
  confidence: number;
  injectionType?: InjectionType;
  technique?: string;
  payload?: string;
  source: string;
  sanitizedContent?: string;
}

export type InjectionType =
  | 'hidden_instruction'     // CSS-hidden or invisible text
  | 'role_override'          // Attempts to override system prompt
  | 'context_manipulation'   // Manipulates conversation context
  | 'tool_invocation'        // Tricks agent into calling tools
  | 'memory_poisoning'       // Injects false facts into memory
  | 'exfiltration_instruction' // Instructions to send data externally
  | 'unicode_obfuscation'    // Unicode tricks to hide content
  | 'markdown_injection'     // Markdown rendering exploits
  | 'delimiter_escape';      // Escapes prompt delimiters

// --- Memory Integrity Types ---

export interface MemoryEntry {
  content: string;
  source: string;
  sessionId?: string;
  timestamp: string;
  hash: string;
}

export interface MemoryIntegrityResult {
  file: string;
  totalEntries: number;
  suspiciousEntries: MemorySuspiciousEntry[];
  integrityScore: number; // 0-100
  scannedAt: string;
}

export interface MemorySuspiciousEntry {
  lineNumber: number;
  content: string;
  reason: string;
  severity: AlertSeverity;
  confidence: number;
}

// --- Hardening Audit Types ---

export interface HardeningAuditResult {
  overallScore: number; // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  checks: HardeningCheck[];
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  auditedAt: string;
}

export interface HardeningCheck {
  id: string;
  name: string;
  description: string;
  category: HardeningCategory;
  status: 'pass' | 'fail' | 'warning' | 'not_applicable';
  severity: AlertSeverity;
  currentValue?: string;
  expectedValue?: string;
  recommendation: string;
  cveReferences?: string[];
}

export type HardeningCategory =
  | 'authentication'
  | 'authorization'
  | 'sandboxing'
  | 'network'
  | 'file_permissions'
  | 'credential_storage'
  | 'tool_restrictions'
  | 'node_security'
  | 'runtime_version'
  | 'skill_security';

// --- Credential Guard Types ---

export interface ExfiltrationAttempt {
  id: string;
  timestamp: string;
  sessionId?: string;
  agentId?: string;
  type: 'credential_read_then_network' | 'bulk_memory_read' |
        'cross_session_access' | 'world_readable_write' |
        'outbound_sensitive_data';
  description: string;
  evidence: AlertEvidence[];
  blocked: boolean;
  sensitiveDataTypes: string[];
}

export interface CredentialExposure {
  file: string;
  type: 'api_key' | 'oauth_token' | 'password' | 'private_key' |
        'bearer_token' | 'webhook_url' | 'connection_string';
  isEncrypted: boolean;
  permissions: string; // octal file permissions
  ownerOnly: boolean;
  recommendation: string;
}

// --- Sidecar Configuration ---

export const OpenClawSidecarConfigSchema = z.object({
  /** Enable the OpenClaw sidecar */
  enabled: z.boolean().default(true),

  /** Gateway connection settings */
  gateway: OpenClawGatewayConfigSchema.default({}),

  /** Gateway Sentinel (WS1) */
  sentinel: z.object({
    enabled: z.boolean().default(true),
    /** Monitor WebSocket traffic */
    monitorTraffic: z.boolean().default(true),
    /** Build behavioral profiles */
    behavioralProfiling: z.boolean().default(true),
    /** Auto-respond to critical threats */
    autoResponse: z.boolean().default(false),
    /** Alert on CVE-2026-25253 patterns */
    detectCve202625253: z.boolean().default(true),
  }).default({}),

  /** Skill Scanner (WS2) */
  skillScanner: z.object({
    enabled: z.boolean().default(true),
    /** Scan skills before installation */
    scanBeforeInstall: z.boolean().default(true),
    /** Block skills with critical findings */
    blockCritical: z.boolean().default(true),
    /** Check IOCs against threat intel */
    checkIOCs: z.boolean().default(true),
    /** Analyze publisher reputation */
    publisherAnalysis: z.boolean().default(true),
  }).default({}),

  /** Prompt Injection Defense (WS3) */
  injectionDefense: z.object({
    enabled: z.boolean().default(true),
    /** Scan web content ingested by agent */
    scanWebContent: z.boolean().default(true),
    /** Scan incoming messages */
    scanMessages: z.boolean().default(true),
    /** Scan memory files for poisoning */
    scanMemory: z.boolean().default(true),
    /** Detect CSS-hidden instructions (CVE-2026-22708) */
    detectHiddenInstructions: z.boolean().default(true),
    /** Detection confidence threshold (0.0-1.0) */
    confidenceThreshold: z.number().default(0.7),
  }).default({}),

  /** Hardening Auditor (WS4) */
  hardeningAuditor: z.object({
    enabled: z.boolean().default(true),
    /** Scan interval in minutes (0 = manual only) */
    scanIntervalMinutes: z.number().default(60),
    /** Alert on configuration drift */
    detectDrift: z.boolean().default(true),
    /** Check for internet exposure */
    checkExposure: z.boolean().default(true),
  }).default({}),

  /** Credential Guard (WS5) */
  credentialGuard: z.object({
    enabled: z.boolean().default(true),
    /** Monitor credential file access */
    monitorCredentials: z.boolean().default(true),
    /** Detect exfiltration patterns */
    detectExfiltration: z.boolean().default(true),
    /** Redact sensitive data in outbound comms */
    redactOutbound: z.boolean().default(true),
    /** Monitor for plaintext credential storage */
    auditStorage: z.boolean().default(true),
  }).default({}),
});

export type OpenClawSidecarConfig = z.infer<typeof OpenClawSidecarConfigSchema>;

// --- Known Threat Signatures ---

/** Known malicious ClawHub campaign identifiers */
export const KNOWN_MALICIOUS_CAMPAIGNS = [
  'clawhavoc',
] as const;

/** CVE references relevant to OpenClaw */
export const OPENCLAW_CVES = {
  'CVE-2026-25253': {
    severity: 'critical' as const,
    cvss: 8.8,
    description: 'One-click RCE via token exfiltration and cross-site WebSocket hijacking',
    fixed: 'v2026.1.29',
  },
  'CVE-2026-24763': {
    severity: 'high' as const,
    cvss: 7.5,
    description: 'Command injection via improperly sanitized gateway input',
    fixed: 'v2026.1.15',
  },
  'CVE-2026-25157': {
    severity: 'high' as const,
    cvss: 7.5,
    description: 'Second command injection vulnerability',
    fixed: 'v2026.1.20',
  },
  'CVE-2026-22708': {
    severity: 'high' as const,
    cvss: 7.0,
    description: 'Indirect prompt injection via web browsing (CSS-invisible instructions)',
    fixed: null, // Architectural issue, not fully resolved
  },
} as const;

/** MITRE ATT&CK techniques commonly seen in OpenClaw attacks */
export const OPENCLAW_MITRE_TECHNIQUES = {
  'T1059': 'Command and Scripting Interpreter',
  'T1078': 'Valid Accounts',
  'T1190': 'Exploit Public-Facing Application',
  'T1195': 'Supply Chain Compromise',
  'T1539': 'Steal Web Session Cookie',
  'T1552': 'Unsecured Credentials',
  'T1557': 'Adversary-in-the-Middle',
  'T1565': 'Data Manipulation',
  'T1567': 'Exfiltration Over Web Service',
  'T1574': 'Hijack Execution Flow',
  'T1606': 'Forge Web Credentials',
  'T1659': 'Content Injection',
} as const;
