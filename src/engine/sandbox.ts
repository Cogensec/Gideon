/**
 * Execution Sandbox
 *
 * Docker-based sandboxed execution environment for offensive security tools.
 * All tool executions run inside isolated containers to prevent
 * accidental damage to the host system.
 */

import type { SandboxConfig, SandboxSession, CommandOutput } from './types.js';

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_SANDBOX_CONFIG: SandboxConfig = {
  image: 'gideon-toolbox:latest',
  networkMode: 'host',
  timeoutSeconds: 300,
  maxConcurrent: 3,
};

// ============================================================================
// Execution Sandbox
// ============================================================================

export class ExecutionSandbox {
  private activeSessions: Map<string, SandboxSession> = new Map();
  private config: SandboxConfig;

  constructor(config: Partial<SandboxConfig> = {}) {
    this.config = { ...DEFAULT_SANDBOX_CONFIG, ...config };
  }

  /**
   * Create a new sandbox session (Docker container)
   */
  async createSandbox(overrides?: Partial<SandboxConfig>): Promise<SandboxSession> {
    const sessionConfig = { ...this.config, ...overrides };

    // Check concurrency limit
    const runningCount = Array.from(this.activeSessions.values())
      .filter(s => s.status === 'running').length;

    if (runningCount >= sessionConfig.maxConcurrent) {
      throw new Error(
        `Maximum concurrent sandboxes (${sessionConfig.maxConcurrent}) reached. ` +
        `Wait for an existing sandbox to complete.`
      );
    }

    const sessionId = crypto.randomUUID();

    // Build docker create command
    const dockerArgs = this.buildDockerArgs(sessionId, sessionConfig);
    const createCmd = `docker create ${dockerArgs.join(' ')}`;

    try {
      const proc = Bun.spawn(['sh', '-c', createCmd], {
        stdout: 'pipe',
        stderr: 'pipe',
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      const exitCode = await proc.exited;

      if (exitCode !== 0) {
        throw new Error(`Failed to create sandbox container: ${stderr.trim()}`);
      }

      const containerId = stdout.trim().substring(0, 12);

      // Start the container
      const startProc = Bun.spawn(['docker', 'start', containerId], {
        stdout: 'pipe',
        stderr: 'pipe',
      });
      await startProc.exited;

      const session: SandboxSession = {
        id: sessionId,
        containerId,
        status: 'running',
        createdAt: new Date().toISOString(),
        config: sessionConfig,
      };

      this.activeSessions.set(sessionId, session);
      return session;
    } catch (error) {
      throw new Error(`Sandbox creation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Execute a command inside an existing sandbox
   */
  async execute(sessionId: string, command: string): Promise<CommandOutput> {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      throw new Error(`Sandbox session '${sessionId}' not found`);
    }
    if (session.status !== 'running') {
      throw new Error(`Sandbox session '${sessionId}' is not running (status: ${session.status})`);
    }

    const startTime = Date.now();

    try {
      const proc = Bun.spawn(
        ['docker', 'exec', session.containerId, 'sh', '-c', command],
        {
          stdout: 'pipe',
          stderr: 'pipe',
        }
      );

      // Apply timeout
      const timeoutMs = session.config.timeoutSeconds * 1000;
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => {
          proc.kill();
          reject(new Error(`Command timed out after ${session.config.timeoutSeconds}s`));
        }, timeoutMs);
      });

      const [stdout, stderr, exitCode] = await Promise.race([
        Promise.all([
          new Response(proc.stdout).text(),
          new Response(proc.stderr).text(),
          proc.exited,
        ]),
        timeoutPromise.then(() => ['', '', 124] as [string, string, number]),
      ]);

      return {
        exitCode: exitCode as number,
        stdout: stdout as string,
        stderr: stderr as string,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Execute a command directly on the host (non-sandboxed, for when Docker isn't available)
   * Use with caution — only for simple, non-destructive tools
   */
  async executeDirect(command: string, timeoutSeconds?: number): Promise<CommandOutput> {
    const startTime = Date.now();
    const timeout = (timeoutSeconds ?? this.config.timeoutSeconds) * 1000;

    try {
      const proc = Bun.spawn(['sh', '-c', command], {
        stdout: 'pipe',
        stderr: 'pipe',
      });

      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => {
          proc.kill();
          reject(new Error(`Command timed out after ${timeout / 1000}s`));
        }, timeout);
      });

      const [stdout, stderr, exitCode] = await Promise.race([
        Promise.all([
          new Response(proc.stdout).text(),
          new Response(proc.stderr).text(),
          proc.exited,
        ]),
        timeoutPromise.then(() => ['', '', 124] as [string, string, number]),
      ]);

      return {
        exitCode: exitCode as number,
        stdout: stdout as string,
        stderr: stderr as string,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Destroy a sandbox session
   */
  async destroy(sessionId: string): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (!session) return;

    try {
      // Force remove the container
      const proc = Bun.spawn(
        ['docker', 'rm', '-f', session.containerId],
        { stdout: 'pipe', stderr: 'pipe' }
      );
      await proc.exited;
    } catch {
      // Best-effort cleanup
    }

    session.status = 'destroyed';
    this.activeSessions.delete(sessionId);
  }

  /**
   * Destroy all active sandboxes
   */
  async destroyAll(): Promise<void> {
    const sessions = Array.from(this.activeSessions.keys());
    await Promise.all(sessions.map(id => this.destroy(id)));
  }

  /**
   * Check if Docker is available
   */
  async isDockerAvailable(): Promise<boolean> {
    try {
      const proc = Bun.spawn(['docker', 'info'], {
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const exitCode = await proc.exited;
      return exitCode === 0;
    } catch {
      return false;
    }
  }

  /**
   * Get active sessions
   */
  getActiveSessions(): SandboxSession[] {
    return Array.from(this.activeSessions.values());
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private buildDockerArgs(sessionId: string, config: SandboxConfig): string[] {
    const args: string[] = [
      `--name`, `gideon-sandbox-${sessionId.substring(0, 8)}`,
      `--network=${config.networkMode}`,
      `--label`, `gideon.sandbox=true`,
      `--label`, `gideon.session=${sessionId}`,
    ];

    // Volume mounts
    if (config.volumes) {
      for (const vol of config.volumes) {
        const ro = vol.readOnly ? ':ro' : '';
        args.push(`-v`, `${vol.host}:${vol.container}${ro}`);
      }
    }

    // Environment variables
    if (config.envVars) {
      for (const [key, value] of Object.entries(config.envVars)) {
        args.push(`-e`, `${key}=${value}`);
      }
    }

    // Keep container running
    args.push(config.image, 'tail', '-f', '/dev/null');

    return args;
  }
}

// ============================================================================
// Singleton
// ============================================================================

let sandbox: ExecutionSandbox | null = null;

export function getSandbox(config?: Partial<SandboxConfig>): ExecutionSandbox {
  if (!sandbox) {
    sandbox = new ExecutionSandbox(config);
  }
  return sandbox;
}
