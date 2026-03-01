/**
 * MCP (Model Context Protocol) Client
 *
 * Client for connecting to MCP servers and executing security tools
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import {
  MCPServer,
  MCPTool,
  MCPToolCallRequest,
  MCPToolCallResponse,
  MCPToolExecution,
  MCPCapabilities,
  SECURITY_TOOLS,
} from './types.js';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// MCP Client Manager
// ============================================================================

export class MCPClientManager {
  private servers: Map<string, MCPServerConnection> = new Map();
  private executions: Map<string, MCPToolExecution> = new Map();

  /**
   * Connect to an MCP server via HTTP/SSE
   */
  async connectHTTP(name: string, url: string): Promise<MCPServer> {
    if (this.servers.has(name)) {
      const existing = this.servers.get(name)!;
      if (existing.status === 'connected') {
        return this.getServerInfo(name)!;
      }
    }

    try {
      const transport = new SSEClientTransport(new URL(url));
      const client = new Client({
        name: 'gideon',
        version: '1.0.0',
      }, {
        capabilities: {},
      });

      await client.connect(transport);

      // Get server capabilities
      const capabilities = await this.getCapabilities(client);

      // Get available tools
      const tools = await this.getTools(client);

      const connection: MCPServerConnection = {
        name,
        url,
        client,
        transport,
        status: 'connected',
        tools,
        capabilities,
        connectedAt: new Date().toISOString(),
      };

      this.servers.set(name, connection);

      return this.getServerInfo(name)!;
    } catch (error) {
      const failedConnection: MCPServerConnection = {
        name,
        url,
        client: null as unknown as Client,
        transport: null as unknown as SSEClientTransport,
        status: 'error',
        tools: [],
        capabilities: { tools: false, resources: false, prompts: false, logging: false },
        error: error instanceof Error ? error.message : String(error),
      };

      this.servers.set(name, failedConnection);
      throw error;
    }
  }

  /**
   * Connect to an MCP server via stdio (local process)
   */
  async connectStdio(name: string, command: string, args: string[] = []): Promise<MCPServer> {
    try {
      const transport = new StdioClientTransport({
        command,
        args,
      });

      const client = new Client({
        name: 'gideon',
        version: '1.0.0',
      }, {
        capabilities: {},
      });

      await client.connect(transport);

      const capabilities = await this.getCapabilities(client);
      const tools = await this.getTools(client);

      const connection: MCPServerConnection = {
        name,
        url: `stdio://${command}`,
        client,
        transport,
        status: 'connected',
        tools,
        capabilities,
        connectedAt: new Date().toISOString(),
      };

      this.servers.set(name, connection);

      return this.getServerInfo(name)!;
    } catch (error) {
      throw new Error(`Failed to connect to stdio MCP server: ${error}`);
    }
  }

  /**
   * Disconnect from an MCP server
   */
  async disconnect(name: string): Promise<void> {
    const connection = this.servers.get(name);
    if (!connection) return;

    try {
      await connection.client.close();
    } catch {
      // Ignore close errors
    }

    connection.status = 'disconnected';
    this.servers.delete(name);
  }

  /**
   * Disconnect from all servers
   */
  async disconnectAll(): Promise<void> {
    for (const name of this.servers.keys()) {
      await this.disconnect(name);
    }
  }

  /**
   * Get server info
   */
  getServerInfo(name: string): MCPServer | undefined {
    const connection = this.servers.get(name);
    if (!connection) return undefined;

    return {
      name: connection.name,
      url: connection.url,
      status: connection.status,
      tools: connection.tools,
      capabilities: connection.capabilities,
      lastConnected: connection.connectedAt,
      error: connection.error,
    };
  }

  /**
   * Get all connected servers
   */
  getAllServers(): MCPServer[] {
    return Array.from(this.servers.values()).map((conn) => ({
      name: conn.name,
      url: conn.url,
      status: conn.status,
      tools: conn.tools,
      capabilities: conn.capabilities,
      lastConnected: conn.connectedAt,
      error: conn.error,
    }));
  }

  /**
   * Get all available tools across all servers
   */
  getAllTools(): Array<MCPTool & { serverName: string }> {
    const tools: Array<MCPTool & { serverName: string }> = [];

    for (const [serverName, connection] of this.servers) {
      if (connection.status === 'connected') {
        for (const tool of connection.tools) {
          tools.push({ ...tool, serverName });
        }
      }
    }

    return tools;
  }

  /**
   * Execute a tool on a specific server
   */
  async executeTool(
    serverName: string,
    request: MCPToolCallRequest
  ): Promise<MCPToolCallResponse> {
    const connection = this.servers.get(serverName);
    if (!connection || connection.status !== 'connected') {
      throw new Error(`Server '${serverName}' is not connected`);
    }

    const executionId = uuidv4();
    const execution: MCPToolExecution = {
      id: executionId,
      serverName,
      toolName: request.name,
      arguments: request.arguments,
      status: 'running',
      startTime: new Date().toISOString(),
    };

    this.executions.set(executionId, execution);

    try {
      const result = await connection.client.callTool({
        name: request.name,
        arguments: request.arguments,
      });

      execution.status = 'completed';
      execution.endTime = new Date().toISOString();
      execution.result = {
        content: result.content.map((c) => ({
          type: c.type as 'text' | 'image' | 'resource',
          text: c.type === 'text' ? (c as { text: string }).text : undefined,
          mimeType: (c as { mimeType?: string }).mimeType,
          data: (c as { data?: string }).data,
          uri: (c as { uri?: string }).uri,
        })),
        isError: result.isError,
      };

      return execution.result;
    } catch (error) {
      execution.status = 'failed';
      execution.endTime = new Date().toISOString();
      execution.error = error instanceof Error ? error.message : String(error);

      throw error;
    }
  }

  /**
   * Execute a tool by name (finds the right server)
   */
  async executeToolByName(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<MCPToolCallResponse> {
    // Find which server has this tool
    for (const [serverName, connection] of this.servers) {
      if (connection.status !== 'connected') continue;

      const tool = connection.tools.find((t) => t.name === toolName);
      if (tool) {
        return this.executeTool(serverName, { name: toolName, arguments: args });
      }
    }

    throw new Error(`Tool '${toolName}' not found on any connected server`);
  }

  /**
   * Get execution history
   */
  getExecutions(): MCPToolExecution[] {
    return Array.from(this.executions.values());
  }

  /**
   * Get capabilities from server
   */
  private async getCapabilities(client: Client): Promise<MCPCapabilities> {
    try {
      const serverCapabilities = client.getServerCapabilities();
      return {
        tools: !!serverCapabilities?.tools,
        resources: !!serverCapabilities?.resources,
        prompts: !!serverCapabilities?.prompts,
        logging: !!serverCapabilities?.logging,
      };
    } catch {
      return { tools: false, resources: false, prompts: false, logging: false };
    }
  }

  /**
   * Get tools from server
   */
  private async getTools(client: Client): Promise<MCPTool[]> {
    try {
      const result = await client.listTools();
      return result.tools.map((t) => ({
        name: t.name,
        description: t.description || '',
        inputSchema: t.inputSchema as MCPTool['inputSchema'],
        category: SECURITY_TOOLS[t.name]?.category,
        requiresApproval: SECURITY_TOOLS[t.name]?.requiresApproval,
      }));
    } catch {
      return [];
    }
  }
}

// ============================================================================
// Types
// ============================================================================

interface MCPServerConnection {
  name: string;
  url: string;
  client: Client;
  transport: SSEClientTransport | StdioClientTransport;
  status: 'connected' | 'disconnected' | 'error';
  tools: MCPTool[];
  capabilities: MCPCapabilities;
  connectedAt?: string;
  error?: string;
}

// ============================================================================
// Singleton Instance
// ============================================================================

let mcpManager: MCPClientManager | null = null;

export function getMCPManager(): MCPClientManager {
  if (!mcpManager) {
    mcpManager = new MCPClientManager();
  }
  return mcpManager;
}

// Re-export types
export * from './types.js';
