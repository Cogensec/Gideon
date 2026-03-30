/**
 * Action Engine
 *
 * Core execution orchestrator that bridges the gap between LLM plans
 * and actual tool execution. Every step is:
 * 1. Scope-validated against the engagement scope
 * 2. Approved via human-in-the-loop (for high-risk operations)
 * 3. Executed inside a Docker sandbox (or directly if Docker unavailable)
 * 4. Parsed into structured findings for the next agent iteration
 * 5. Audit-logged for the engagement report
 */

import { z } from 'zod';
import { DynamicStructuredTool } from '@langchain/core/tools';
import type { StructuredToolInterface } from '@langchain/core/tools';
import { isTargetInScope, getRedTeamManager, isRedTeamMode } from '../agent/redteam-mode.js';
import { getApprovalManager } from '../agent/approval.js';
import { getPhaseManager } from '../agent/phases.js';
import { ExecutionSandbox, getSandbox } from './sandbox.js';
import { getToolAdapter, getAvailableAdapters } from './tool-adapters.js';
import type {
  ExecutionStep,
  ExecutionResult,
  ExecutionEvent,
  ExecutionFinding,
  ToolAdapter,
} from './types.js';

// ============================================================================
// Action Engine
// ============================================================================

export class ActionEngine {
  private sandbox: ExecutionSandbox;
  private useSandbox: boolean;
  private activeSandboxId: string | null = null;

  constructor(useSandbox: boolean = true) {
    this.sandbox = getSandbox();
    this.useSandbox = useSandbox;
  }

  /**
   * Execute a single tool with structured input.
   * Handles scope validation, approval, sandboxed execution, and output parsing.
   */
  async executeStep(step: ExecutionStep): AsyncGenerator<ExecutionEvent> {
    return this._executeStep(step);
  }

  /**
   * Execute a sequence of steps with dependency resolution.
   */
  async *executePlan(steps: ExecutionStep[]): AsyncGenerator<ExecutionEvent> {
    const completed = new Map<string, ExecutionResult>();

    for (const step of steps) {
      // Check dependencies
      for (const depId of step.dependsOn) {
        if (!completed.has(depId)) {
          yield {
            type: 'execution_blocked',
            stepId: step.id,
            reason: `Dependency '${depId}' has not completed`,
          };
          continue;
        }
      }

      // Execute step
      for await (const event of this._executeStep(step)) {
        yield event;

        if (event.type === 'execution_complete') {
          completed.set(step.id, event.result);
        }
      }
    }
  }

  /**
   * Execute a raw tool by name with input map.
   * Convenience method used by LangChain tool wrappers.
   */
  async executeTool(
    toolName: string,
    input: Record<string, unknown>,
    target: string
  ): Promise<ExecutionResult> {
    const adapter = getToolAdapter(toolName);
    if (!adapter) {
      return {
        stepId: 'direct',
        success: false,
        exitCode: 1,
        stdout: '',
        stderr: `Unknown tool: ${toolName}. Available: ${getAvailableAdapters().join(', ')}`,
        durationMs: 0,
        findings: [],
        error: `Unknown tool: ${toolName}`,
      };
    }

    // Validate input
    const validation = adapter.validateInput(input);
    if (!validation.valid) {
      return {
        stepId: 'direct',
        success: false,
        exitCode: 1,
        stdout: '',
        stderr: validation.error || 'Invalid input',
        durationMs: 0,
        findings: [],
        error: validation.error,
      };
    }

    // Scope check
    if (isRedTeamMode()) {
      const scopeResult = isTargetInScope(target);
      if (!scopeResult.inScope) {
        getRedTeamManager().addAuditEntry({
          action: `Blocked out-of-scope execution: ${toolName}`,
          category: 'scope_check',
          target,
          details: { toolName, input, reason: scopeResult.reason },
          result: 'blocked',
          riskLevel: 'high',
        });

        return {
          stepId: 'direct',
          success: false,
          exitCode: 1,
          stdout: '',
          stderr: `SCOPE VIOLATION: ${scopeResult.reason}`,
          durationMs: 0,
          findings: [],
          error: scopeResult.reason,
        };
      }
    }

    // Build and execute command
    const command = adapter.buildCommand(input);

    // Audit log
    if (isRedTeamMode()) {
      getRedTeamManager().addAuditEntry({
        action: `Execute ${toolName}`,
        category: 'tool_execution',
        target,
        details: { command, input },
        result: 'pending',
        riskLevel: 'medium',
      });
      getRedTeamManager().incrementStat('toolExecutions');
    }

    // Execute
    const output = await this.executeCommand(command, adapter.defaultTimeoutMs);

    // Parse findings
    const findings = adapter.parseOutput(output.stdout);

    return {
      stepId: 'direct',
      success: output.exitCode === 0,
      exitCode: output.exitCode,
      stdout: output.stdout,
      stderr: output.stderr,
      durationMs: output.durationMs,
      findings,
    };
  }

  /**
   * Create LangChain tools for the agent to use.
   * These tools are registered with the agent when Red Team mode is active.
   */
  createLangChainTools(): StructuredToolInterface[] {
    const tools: StructuredToolInterface[] = [];

    // Scope check tool
    tools.push(new DynamicStructuredTool({
      name: 'scope_check',
      description: 'Check if a target is within the authorized engagement scope. ALWAYS use this before targeting any host or domain.',
      schema: z.object({
        target: z.string().describe('The target IP, domain, or URL to check'),
      }),
      func: async (input) => {
        const result = isTargetInScope(input.target);
        return JSON.stringify(result);
      },
    }));

    // Nmap scan tool
    tools.push(new DynamicStructuredTool({
      name: 'nmap_scan',
      description: 'Run an nmap port scan against a target. Requires target to be in scope.',
      schema: z.object({
        target: z.string().describe('Target IP or hostname'),
        scanType: z.enum(['syn', 'connect', 'udp', 'version', 'aggressive']).default('syn').describe('Type of scan'),
        ports: z.string().optional().describe('Port specification (e.g., "80,443", "1-1000", "-")'),
        timing: z.string().default('T3').describe('Timing template (T0-T5)'),
        scripts: z.string().optional().describe('NSE scripts to run (e.g., "vuln", "default")'),
      }),
      func: async (input) => {
        const result = await this.executeTool('nmap', input, input.target);
        return this.formatResult(result);
      },
    }));

    // Nuclei vulnerability scanner
    tools.push(new DynamicStructuredTool({
      name: 'nuclei_scan',
      description: 'Run nuclei vulnerability scanner against a target URL. Identifies vulnerabilities using template matching.',
      schema: z.object({
        target: z.string().describe('Target URL'),
        templates: z.string().optional().describe('Specific template directory or file'),
        severity: z.string().optional().describe('Filter by severity (critical,high,medium,low,info)'),
        tags: z.string().optional().describe('Filter by tags (e.g., "cve,sqli,xss")'),
      }),
      func: async (input) => {
        const hostname = this.extractHostname(input.target);
        const result = await this.executeTool('nuclei', input, hostname);
        return this.formatResult(result);
      },
    }));

    // SQLMap injection testing
    tools.push(new DynamicStructuredTool({
      name: 'sqlmap_scan',
      description: 'Test a URL for SQL injection vulnerabilities using sqlmap.',
      schema: z.object({
        target: z.string().describe('Target URL with parameters'),
        parameter: z.string().optional().describe('Specific parameter to test'),
        technique: z.string().optional().describe('Injection techniques (B,E,U,S,T,Q)'),
        level: z.number().default(1).describe('Test level (1-5)'),
        risk: z.number().default(1).describe('Risk level (1-3)'),
      }),
      func: async (input) => {
        const hostname = this.extractHostname(input.target);
        const result = await this.executeTool('sqlmap', input, hostname);
        return this.formatResult(result);
      },
    }));

    // Generic command execution (sandboxed)
    tools.push(new DynamicStructuredTool({
      name: 'execute_command',
      description: 'Execute a security tool command in the sandboxed environment. Use for tools not covered by specific tools (gobuster, ffuf, nikto, etc.).',
      schema: z.object({
        command: z.string().describe('The full command to execute'),
        target: z.string().describe('The target being assessed (for scope validation)'),
        tool: z.string().describe('Name of the tool being used'),
      }),
      func: async (input) => {
        const scopeResult = isTargetInScope(input.target);
        if (!scopeResult.inScope) {
          return `SCOPE VIOLATION: ${scopeResult.reason}`;
        }

        if (isRedTeamMode()) {
          getRedTeamManager().addAuditEntry({
            action: `Execute command: ${input.tool}`,
            category: 'tool_execution',
            target: input.target,
            details: { command: input.command },
            result: 'pending',
            riskLevel: 'medium',
          });
          getRedTeamManager().incrementStat('toolExecutions');
        }

        const output = await this.executeCommand(input.command);
        return `Exit code: ${output.exitCode}\n\nStdout:\n${output.stdout}\n\nStderr:\n${output.stderr}`;
      },
    }));

    return tools;
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private async *_executeStep(step: ExecutionStep): AsyncGenerator<ExecutionEvent> {
    // 1. Scope validation
    if (isRedTeamMode()) {
      const scopeResult = isTargetInScope(step.target);
      if (!scopeResult.inScope) {
        yield {
          type: 'execution_blocked',
          stepId: step.id,
          reason: `SCOPE VIOLATION: ${scopeResult.reason}`,
        };
        return;
      }
    }

    // 2. Phase check
    const phaseManager = getPhaseManager();
    const toolCheck = phaseManager.isToolAllowed(step.tool);
    if (!toolCheck.allowed) {
      yield {
        type: 'execution_blocked',
        stepId: step.id,
        reason: toolCheck.reason || `Tool '${step.tool}' not allowed in current phase`,
      };
      return;
    }

    // 3. Approval gate for high-risk operations
    if (step.requiresApproval) {
      yield {
        type: 'approval_required',
        stepId: step.id,
        tool: step.tool,
        target: step.target,
        riskLevel: step.riskLevel,
      };

      const approvalManager = getApprovalManager();
      const decision = await approvalManager.requestToolApproval(
        step.tool,
        step.metadata,
        step.target,
        step.riskLevel
      );

      if (!decision.approved) {
        yield {
          type: 'execution_blocked',
          stepId: step.id,
          reason: decision.reason || 'User denied approval',
        };
        return;
      }
    }

    // 4. Execute
    yield {
      type: 'execution_start',
      stepId: step.id,
      tool: step.tool,
      target: step.target,
    };

    // Audit log
    if (isRedTeamMode()) {
      getRedTeamManager().addAuditEntry({
        action: `Execute ${step.tool}`,
        category: 'tool_execution',
        target: step.target,
        details: { command: step.command, phase: step.phase },
        result: 'pending',
        riskLevel: step.riskLevel,
      });
      getRedTeamManager().incrementStat('toolExecutions');
    }

    const output = await this.executeCommand(step.command, step.timeoutMs);

    // 5. Parse output
    const adapter = getToolAdapter(step.tool);
    const findings = adapter ? adapter.parseOutput(output.stdout) : [];

    const result: ExecutionResult = {
      stepId: step.id,
      success: output.exitCode === 0,
      exitCode: output.exitCode,
      stdout: output.stdout,
      stderr: output.stderr,
      durationMs: output.durationMs,
      findings,
    };

    yield { type: 'execution_complete', stepId: step.id, result };
  }

  private async executeCommand(
    command: string,
    timeoutMs?: number
  ): Promise<{ exitCode: number; stdout: string; stderr: string; durationMs: number }> {
    const timeoutSec = timeoutMs ? Math.ceil(timeoutMs / 1000) : undefined;

    if (this.useSandbox) {
      try {
        // Ensure we have an active sandbox
        if (!this.activeSandboxId) {
          const session = await this.sandbox.createSandbox();
          this.activeSandboxId = session.id;
        }
        return await this.sandbox.execute(this.activeSandboxId, command);
      } catch {
        // Fall back to direct execution
        return await this.sandbox.executeDirect(command, timeoutSec);
      }
    }

    return await this.sandbox.executeDirect(command, timeoutSec);
  }

  private formatResult(result: ExecutionResult): string {
    const parts: string[] = [];

    if (!result.success) {
      parts.push(`Error: ${result.error || result.stderr}`);
    }

    if (result.findings.length > 0) {
      parts.push(`Found ${result.findings.length} finding(s):\n`);
      for (const f of result.findings) {
        parts.push(`[${f.severity.toUpperCase()}] ${f.title}`);
        if (f.description) parts.push(`  ${f.description}`);
        if (f.target) parts.push(`  Target: ${f.target}`);
      }
    }

    if (result.stdout) {
      const truncated = result.stdout.length > 5000
        ? result.stdout.substring(0, 5000) + '\n... (truncated)'
        : result.stdout;
      parts.push(`\nRaw output:\n${truncated}`);
    }

    return parts.join('\n') || 'No output';
  }

  private extractHostname(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  /**
   * Cleanup: destroy sandbox on shutdown
   */
  async shutdown(): Promise<void> {
    if (this.activeSandboxId) {
      await this.sandbox.destroy(this.activeSandboxId);
      this.activeSandboxId = null;
    }
  }
}

// ============================================================================
// Singleton
// ============================================================================

let actionEngine: ActionEngine | null = null;

export function getActionEngine(useSandbox?: boolean): ActionEngine {
  if (!actionEngine) {
    actionEngine = new ActionEngine(useSandbox);
  }
  return actionEngine;
}
