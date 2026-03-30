/**
 * C2 Framework Types
 *
 * Type definitions for Command and Control framework integration.
 * Supports multiple C2 backends (Sliver, Mythic) through a unified interface.
 */

import { z } from 'zod';

// ============================================================================
// Session & Beacon Types
// ============================================================================

/**
 * A C2 session represents an active connection to a compromised host
 */
export interface C2Session {
  /** Session ID (from C2 framework) */
  id: string;
  /** Session type */
  type: 'interactive' | 'beacon';
  /** Target hostname */
  hostname: string;
  /** Target IP address */
  remoteAddress: string;
  /** Target operating system */
  os: string;
  /** Target architecture */
  arch: string;
  /** Current user context */
  username: string;
  /** Process ID of the implant */
  pid: number;
  /** Process name */
  processName: string;
  /** Whether session has elevated privileges */
  isAdmin: boolean;
  /** C2 framework this session belongs to */
  framework: 'sliver' | 'mythic';
  /** Session status */
  status: 'active' | 'dormant' | 'dead';
  /** Last checkin time */
  lastCheckin: string;
  /** Session creation time */
  createdAt: string;
  /** Beacon interval (for beacon-type sessions) */
  beaconInterval?: number;
  /** Beacon jitter */
  beaconJitter?: number;
}

/**
 * A C2 listener that accepts incoming connections
 */
export interface C2Listener {
  /** Listener ID */
  id: string;
  /** Listener name */
  name: string;
  /** Protocol */
  protocol: 'https' | 'http' | 'mtls' | 'dns' | 'wg' | 'tcp';
  /** Bind address */
  host: string;
  /** Listen port */
  port: number;
  /** Status */
  status: 'active' | 'stopped';
  /** Framework */
  framework: 'sliver' | 'mythic';
  /** Created at */
  createdAt: string;
}

/**
 * Configuration for generating an implant
 */
export interface ImplantConfig {
  /** Implant name */
  name: string;
  /** Target OS */
  os: 'windows' | 'linux' | 'macos';
  /** Target architecture */
  arch: 'x64' | 'x86' | 'arm64';
  /** Implant type */
  type: 'beacon' | 'session';
  /** C2 callback protocol */
  protocol: 'https' | 'mtls' | 'dns' | 'tcp';
  /** C2 callback host */
  c2Host: string;
  /** C2 callback port */
  c2Port: number;
  /** Beacon interval in seconds (for beacon type) */
  beaconInterval?: number;
  /** Beacon jitter percentage (for beacon type) */
  beaconJitter?: number;
  /** Output format */
  format: 'exe' | 'dll' | 'shellcode' | 'shared_lib';
  /** Enable debug mode */
  debug?: boolean;
  /** Obfuscation settings */
  obfuscation?: {
    enabled: boolean;
    level: 'basic' | 'advanced';
  };
}

/**
 * Generated implant payload
 */
export interface ImplantPayload {
  /** Payload name */
  name: string;
  /** Raw payload data */
  data: Buffer;
  /** File extension */
  extension: string;
  /** SHA256 hash */
  sha256: string;
  /** Size in bytes */
  sizeBytes: number;
  /** Configuration used */
  config: ImplantConfig;
}

/**
 * A task to execute on a compromised host
 */
export interface C2Task {
  /** Task type */
  type: 'shell' | 'upload' | 'download' | 'process_list' | 'ifconfig' | 'screenshot' | 'keylog' | 'execute_assembly' | 'socks_proxy';
  /** Command to execute (for shell type) */
  command?: string;
  /** Local path (for upload/download) */
  localPath?: string;
  /** Remote path (for upload/download) */
  remotePath?: string;
  /** Assembly path (for execute_assembly) */
  assemblyPath?: string;
  /** Assembly arguments */
  assemblyArgs?: string[];
  /** SOCKS proxy port (for socks_proxy) */
  socksPort?: number;
}

export interface TaskResult {
  /** Task ID */
  taskId: string;
  /** Session ID */
  sessionId: string;
  /** Whether task completed successfully */
  success: boolean;
  /** Task output */
  output: string;
  /** Raw data (for downloads, screenshots) */
  data?: Buffer;
  /** Error message */
  error?: string;
  /** Duration */
  durationMs: number;
}

// ============================================================================
// C2 Adapter Interface
// ============================================================================

/**
 * Interface that all C2 framework adapters must implement
 */
export interface C2Adapter {
  /** Framework name */
  name: 'sliver' | 'mythic';

  /** Connect to the C2 teamserver */
  connect(config: Record<string, unknown>): Promise<void>;

  /** Disconnect */
  disconnect(): Promise<void>;

  /** Check if connected */
  isConnected(): boolean;

  /** Listener management */
  createListener(config: Partial<C2Listener>): Promise<C2Listener>;
  listListeners(): Promise<C2Listener[]>;
  stopListener(id: string): Promise<void>;

  /** Implant generation */
  generateImplant(config: ImplantConfig): Promise<ImplantPayload>;

  /** Session management */
  getSessions(): Promise<C2Session[]>;
  getSession(id: string): Promise<C2Session | null>;
  killSession(id: string): Promise<void>;

  /** Task execution */
  executeTask(sessionId: string, task: C2Task): Promise<TaskResult>;

  /** Event stream */
  onSessionCreated(callback: (session: C2Session) => void): void;
  onSessionLost(callback: (sessionId: string) => void): void;
}

// ============================================================================
// Zod Schemas
// ============================================================================

export const ImplantConfigSchema = z.object({
  name: z.string().min(1),
  os: z.enum(['windows', 'linux', 'macos']),
  arch: z.enum(['x64', 'x86', 'arm64']),
  type: z.enum(['beacon', 'session']),
  protocol: z.enum(['https', 'mtls', 'dns', 'tcp']),
  c2Host: z.string().min(1),
  c2Port: z.number().positive(),
  beaconInterval: z.number().positive().optional(),
  beaconJitter: z.number().min(0).max(100).optional(),
  format: z.enum(['exe', 'dll', 'shellcode', 'shared_lib']),
  debug: z.boolean().optional(),
  obfuscation: z.object({
    enabled: z.boolean(),
    level: z.enum(['basic', 'advanced']),
  }).optional(),
});

export const C2TaskSchema = z.object({
  type: z.enum(['shell', 'upload', 'download', 'process_list', 'ifconfig', 'screenshot', 'keylog', 'execute_assembly', 'socks_proxy']),
  command: z.string().optional(),
  localPath: z.string().optional(),
  remotePath: z.string().optional(),
  assemblyPath: z.string().optional(),
  assemblyArgs: z.array(z.string()).optional(),
  socksPort: z.number().optional(),
});
