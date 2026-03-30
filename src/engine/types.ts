/**
 * Action Engine Types
 *
 * Type definitions for the tool orchestration and execution system.
 */

import { z } from 'zod';

// ============================================================================
// Execution Types
// ============================================================================

/**
 * A single executable step parsed from an LLM plan
 */
export interface ExecutionStep {
  /** Step ID */
  id: string;
  /** Tool to execute */
  tool: string;
  /** Command or arguments to pass */
  command: string;
  /** Target (IP, domain, URL) for scope validation */
  target: string;
  /** Expected risk level */
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  /** Phase this step belongs to */
  phase: 'reconnaissance' | 'exploitation' | 'post-exploitation';
  /** Whether this step requires human approval */
  requiresApproval: boolean;
  /** Timeout in milliseconds */
  timeoutMs: number;
  /** Dependencies - step IDs that must complete first */
  dependsOn: string[];
  /** Additional metadata */
  metadata: Record<string, unknown>;
}

/**
 * Result of executing a step
 */
export interface ExecutionResult {
  /** Step that was executed */
  stepId: string;
  /** Whether execution succeeded */
  success: boolean;
  /** Exit code of the command */
  exitCode: number;
  /** Standard output */
  stdout: string;
  /** Standard error */
  stderr: string;
  /** Execution duration in milliseconds */
  durationMs: number;
  /** Parsed findings from the output */
  findings: ExecutionFinding[];
  /** Error message if failed */
  error?: string;
}

/**
 * A finding extracted from tool output
 */
export interface ExecutionFinding {
  type: 'vulnerability' | 'service' | 'credential' | 'host' | 'port' | 'technology' | 'info';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  target: string;
  evidence: string;
  metadata: Record<string, unknown>;
}

// ============================================================================
// Sandbox Types
// ============================================================================

export interface SandboxConfig {
  /** Docker image to use */
  image: string;
  /** Network mode (host, bridge, none) */
  networkMode: 'host' | 'bridge' | 'none';
  /** Execution timeout */
  timeoutSeconds: number;
  /** Maximum concurrent sandboxes */
  maxConcurrent: number;
  /** Volume mounts */
  volumes?: Array<{ host: string; container: string; readOnly: boolean }>;
  /** Environment variables to pass */
  envVars?: Record<string, string>;
}

export interface SandboxSession {
  /** Session ID */
  id: string;
  /** Docker container ID */
  containerId: string;
  /** Status */
  status: 'creating' | 'running' | 'stopped' | 'destroyed';
  /** Created at */
  createdAt: string;
  /** Sandbox configuration */
  config: SandboxConfig;
}

export interface CommandOutput {
  /** Exit code */
  exitCode: number;
  /** Standard output */
  stdout: string;
  /** Standard error */
  stderr: string;
  /** Duration in milliseconds */
  durationMs: number;
}

// ============================================================================
// Tool Adapter Types
// ============================================================================

export interface ToolAdapter {
  /** Tool name */
  name: string;
  /** Build CLI command from structured input */
  buildCommand(input: Record<string, unknown>): string;
  /** Parse raw output into structured findings */
  parseOutput(output: string): ExecutionFinding[];
  /** Validate input parameters */
  validateInput(input: Record<string, unknown>): { valid: boolean; error?: string };
  /** Get default timeout */
  defaultTimeoutMs: number;
}

// ============================================================================
// Execution Events (for UI streaming)
// ============================================================================

export interface ExecutionStartEvent {
  type: 'execution_start';
  stepId: string;
  tool: string;
  target: string;
}

export interface ExecutionOutputEvent {
  type: 'execution_output';
  stepId: string;
  stream: 'stdout' | 'stderr';
  data: string;
}

export interface ExecutionCompleteEvent {
  type: 'execution_complete';
  stepId: string;
  result: ExecutionResult;
}

export interface ExecutionBlockedEvent {
  type: 'execution_blocked';
  stepId: string;
  reason: string;
}

export interface ApprovalRequiredEvent {
  type: 'approval_required';
  stepId: string;
  tool: string;
  target: string;
  riskLevel: string;
}

export type ExecutionEvent =
  | ExecutionStartEvent
  | ExecutionOutputEvent
  | ExecutionCompleteEvent
  | ExecutionBlockedEvent
  | ApprovalRequiredEvent;

// ============================================================================
// Zod Schemas
// ============================================================================

export const ExecutionStepSchema = z.object({
  id: z.string(),
  tool: z.string(),
  command: z.string(),
  target: z.string(),
  riskLevel: z.enum(['low', 'medium', 'high', 'critical']),
  phase: z.enum(['reconnaissance', 'exploitation', 'post-exploitation']),
  requiresApproval: z.boolean(),
  timeoutMs: z.number().positive(),
  dependsOn: z.array(z.string()),
  metadata: z.record(z.string(), z.unknown()),
});
