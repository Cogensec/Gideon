/**
 * MCP (Model Context Protocol) Types
 *
 * Type definitions for MCP client-server communication
 */

import { z } from 'zod';

// ============================================================================
// MCP Protocol Types
// ============================================================================

export interface MCPServer {
  name: string;
  url: string;
  status: 'connected' | 'disconnected' | 'error';
  tools: MCPTool[];
  capabilities: MCPCapabilities;
  lastConnected?: string;
  error?: string;
}

export interface MCPCapabilities {
  tools: boolean;
  resources: boolean;
  prompts: boolean;
  logging: boolean;
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: MCPToolInputSchema;
  category?: string;
  requiresApproval?: boolean;
}

export interface MCPToolInputSchema {
  type: 'object';
  properties: Record<string, MCPPropertySchema>;
  required?: string[];
}

export interface MCPPropertySchema {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description?: string;
  enum?: string[];
  items?: MCPPropertySchema;
  properties?: Record<string, MCPPropertySchema>;
  default?: unknown;
}

// ============================================================================
// MCP Request/Response Types
// ============================================================================

export interface MCPRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface MCPResponse<T = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  result?: T;
  error?: MCPError;
}

export interface MCPError {
  code: number;
  message: string;
  data?: unknown;
}

export interface MCPToolCallRequest {
  name: string;
  arguments: Record<string, unknown>;
}

export interface MCPToolCallResponse {
  content: MCPContent[];
  isError?: boolean;
}

export interface MCPContent {
  type: 'text' | 'image' | 'resource';
  text?: string;
  mimeType?: string;
  data?: string;
  uri?: string;
}

// ============================================================================
// MCP Tool Execution
// ============================================================================

export interface MCPToolExecution {
  id: string;
  serverName: string;
  toolName: string;
  arguments: Record<string, unknown>;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startTime: string;
  endTime?: string;
  result?: MCPToolCallResponse;
  error?: string;
}

// ============================================================================
// Security Tool Categories
// ============================================================================

export type SecurityToolCategory =
  | 'network-scan'
  | 'vuln-scan'
  | 'web-crawl'
  | 'exploitation'
  | 'post-exploitation'
  | 'recon'
  | 'enumeration'
  | 'analysis';

export interface SecurityTool extends MCPTool {
  category: SecurityToolCategory;
  phase: 'informational' | 'exploitation' | 'post-exploitation';
  requiresApproval: boolean;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

// ============================================================================
// Built-in Security Tools
// ============================================================================

export const SECURITY_TOOLS: Record<string, Omit<SecurityTool, 'inputSchema'>> = {
  nmap: {
    name: 'nmap',
    description: 'Network exploration tool and security scanner',
    category: 'network-scan',
    phase: 'informational',
    requiresApproval: false,
    riskLevel: 'low',
  },
  nuclei: {
    name: 'nuclei',
    description: 'Fast and customizable vulnerability scanner with 8000+ templates',
    category: 'vuln-scan',
    phase: 'informational',
    requiresApproval: false,
    riskLevel: 'low',
  },
  httpx: {
    name: 'httpx',
    description: 'HTTP toolkit for probing and technology detection',
    category: 'recon',
    phase: 'informational',
    requiresApproval: false,
    riskLevel: 'low',
  },
  katana: {
    name: 'katana',
    description: 'Web crawler for endpoint and resource discovery',
    category: 'web-crawl',
    phase: 'informational',
    requiresApproval: false,
    riskLevel: 'low',
  },
  sqlmap: {
    name: 'sqlmap',
    description: 'Automatic SQL injection detection and exploitation tool',
    category: 'exploitation',
    phase: 'exploitation',
    requiresApproval: true,
    riskLevel: 'high',
  },
  hydra: {
    name: 'hydra',
    description: 'Network logon cracker supporting many protocols',
    category: 'exploitation',
    phase: 'exploitation',
    requiresApproval: true,
    riskLevel: 'high',
  },
  metasploit: {
    name: 'metasploit',
    description: 'Penetration testing framework for exploitation',
    category: 'exploitation',
    phase: 'exploitation',
    requiresApproval: true,
    riskLevel: 'critical',
  },
  ffuf: {
    name: 'ffuf',
    description: 'Fast web fuzzer for directory and parameter discovery',
    category: 'enumeration',
    phase: 'informational',
    requiresApproval: false,
    riskLevel: 'low',
  },
  subfinder: {
    name: 'subfinder',
    description: 'Subdomain discovery tool using passive sources',
    category: 'recon',
    phase: 'informational',
    requiresApproval: false,
    riskLevel: 'low',
  },
  amass: {
    name: 'amass',
    description: 'Attack surface mapping and subdomain enumeration',
    category: 'recon',
    phase: 'informational',
    requiresApproval: false,
    riskLevel: 'low',
  },
};

// ============================================================================
// Zod Schemas
// ============================================================================

export const MCPServerSchema = z.object({
  name: z.string(),
  url: z.string().url(),
  status: z.enum(['connected', 'disconnected', 'error']),
  tools: z.array(z.object({
    name: z.string(),
    description: z.string(),
  })),
});

export const MCPToolCallRequestSchema = z.object({
  name: z.string(),
  arguments: z.record(z.string(), z.unknown()),
});

export const SecurityToolCategorySchema = z.enum([
  'network-scan',
  'vuln-scan',
  'web-crawl',
  'exploitation',
  'post-exploitation',
  'recon',
  'enumeration',
  'analysis',
]);
