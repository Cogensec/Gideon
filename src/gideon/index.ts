/**
 * GIDEON - Guided Intelligence for Defense, Exploitation, and Offensive Navigation
 *
 * An autonomous security research assistant for bug bounty hunting,
 * penetration testing, and security research.
 *
 * @module gideon
 */

// Core types
export type {
  GideonMode,
  EngagementStatus,
  ScopeDefinition,
  ReconType,
  SubdomainResult,
  TechnologyFingerprint,
  PortScanResult,
  ReconSummary,
  VulnerabilityClass,
  SeverityLevel,
  Finding,
  AttackChain,
  GideonSession,
  ToolRecommendation,
  ToolCategory,
  GideonCommand,
} from './types.js';

// Schemas for validation
export {
  GideonModeSchema,
  EngagementStatusSchema,
  ReconTypeSchema,
  VulnerabilityClassSchema,
  SeverityLevelSchema,
  TOOL_CATEGORIES,
} from './types.js';

// Prompts and identity
export {
  GIDEON_IDENTITY,
  METHODOLOGY_PROMPT,
  VULNERABILITY_PROMPTS,
  SCOPE_VALIDATION_PROMPT,
  buildGideonSystemPrompt,
  buildHuntPrompt,
  buildReconPrompt,
  buildChainPrompt,
  buildReportPrompt,
} from './prompts.js';

// Reconnaissance utilities
export {
  TOOLS_DATABASE,
  getToolsForCategory,
  getAllTools,
  generatePassiveReconCommands,
  generateActiveReconCommands,
  generateSubdomainEnumCommands,
  generateTechStackAnalysis,
  CVSSInput,
  CVSSResult,
  calculateCVSS,
  generateReconSummary,
} from './recon.js';

// Report generation
export {
  FINDING_TEMPLATES,
  generateFindingTemplate,
  formatFindingMarkdown,
  generateExecutiveSummary,
  generateEngagementReport,
  formatCurlPOC,
  generateChainReport,
  exportFindingsJSON,
  formatHackerOneReport,
  formatBugcrowdReport,
} from './reports.js';

// Session management utilities
import { v4 as uuidv4 } from 'uuid';
import type {
  GideonMode,
  GideonSession,
  ScopeDefinition,
  Finding,
  SeverityLevel,
} from './types.js';

/**
 * Create a new GIDEON session
 */
export function createSession(mode: GideonMode): GideonSession {
  return {
    id: uuidv4(),
    mode,
    status: 'scoping',
    startedAt: new Date().toISOString(),
    findings: [],
    attackChains: [],
    activityLog: [
      {
        timestamp: new Date().toISOString(),
        action: 'session_started',
        details: `Started ${mode} session`,
        phase: 'initialization',
      },
    ],
    notes: [],
  };
}

/**
 * Add a finding to the session
 */
export function addFinding(session: GideonSession, finding: Finding): void {
  session.findings.push(finding);
  session.activityLog.push({
    timestamp: new Date().toISOString(),
    action: 'finding_added',
    details: `Added finding: ${finding.title} (${finding.severity})`,
    phase: session.status,
  });
}

/**
 * Update session status
 */
export function updateSessionStatus(
  session: GideonSession,
  status: GideonSession['status']
): void {
  const oldStatus = session.status;
  session.status = status;
  session.activityLog.push({
    timestamp: new Date().toISOString(),
    action: 'status_changed',
    details: `Status changed from ${oldStatus} to ${status}`,
    phase: status,
  });
}

/**
 * Set scope for the session
 */
export function setScope(
  session: GideonSession,
  scope: ScopeDefinition
): void {
  session.scope = scope;
  session.activityLog.push({
    timestamp: new Date().toISOString(),
    action: 'scope_defined',
    details: `Scope set for program: ${scope.programName}`,
    phase: 'scoping',
  });
}

/**
 * Calculate session statistics
 */
export function getSessionStats(session: GideonSession): {
  totalFindings: number;
  bySeverity: Record<SeverityLevel, number>;
  byClass: Record<string, number>;
  chainedFindings: number;
  duration: string;
} {
  const bySeverity: Record<SeverityLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  const byClass: Record<string, number> = {};

  for (const finding of session.findings) {
    bySeverity[finding.severity]++;
    byClass[finding.vulnerabilityClass] =
      (byClass[finding.vulnerabilityClass] || 0) + 1;
  }

  // Calculate duration
  const start = new Date(session.startedAt).getTime();
  const now = Date.now();
  const durationMs = now - start;
  const hours = Math.floor(durationMs / (1000 * 60 * 60));
  const minutes = Math.floor((durationMs % (1000 * 60 * 60)) / (1000 * 60));
  const duration = hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;

  // Count chained findings
  const chainedFindingIds = new Set<string>();
  for (const chain of session.attackChains) {
    for (const step of chain.steps) {
      chainedFindingIds.add(step.findingId);
    }
  }

  return {
    totalFindings: session.findings.length,
    bySeverity,
    byClass,
    chainedFindings: chainedFindingIds.size,
    duration,
  };
}

/**
 * Validate if a target is in scope
 */
export function isInScope(target: string, scope: ScopeDefinition): {
  inScope: boolean;
  reason: string;
} {
  // Check explicit out-of-scope first
  for (const domain of scope.outOfScope.domains) {
    if (target.includes(domain)) {
      return { inScope: false, reason: `Domain ${domain} is explicitly out of scope` };
    }
  }

  for (const path of scope.outOfScope.paths) {
    if (target.includes(path)) {
      return { inScope: false, reason: `Path ${path} is explicitly out of scope` };
    }
  }

  // Check in-scope domains
  for (const domain of scope.inScope.domains) {
    if (target.includes(domain)) {
      return { inScope: true, reason: `Matches in-scope domain: ${domain}` };
    }
  }

  // Check wildcards
  for (const wildcard of scope.inScope.wildcards) {
    const pattern = wildcard.replace('*.', '');
    if (target.includes(pattern)) {
      return { inScope: true, reason: `Matches wildcard: ${wildcard}` };
    }
  }

  // Check APIs
  for (const api of scope.inScope.apis) {
    if (target.includes(api)) {
      return { inScope: true, reason: `Matches in-scope API: ${api}` };
    }
  }

  // Check applications
  for (const app of scope.inScope.applications) {
    if (target.includes(app)) {
      return { inScope: true, reason: `Matches in-scope application: ${app}` };
    }
  }

  return { inScope: false, reason: 'Target not found in scope definition' };
}
