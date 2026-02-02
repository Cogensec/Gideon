import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  AgentRegistration,
  AgentRegistrationSchema,
  AgentType,
  AgentStatus,
  normalizeAgentType,
  DEPRECATED_AGENT_TYPES,
} from './types';

const REGISTRY_DIR = '.gideon/governance';
const REGISTRY_FILE = 'agent-registry.json';

interface AgentRegistryData {
  version: string;
  agents: AgentRegistration[];
  lastUpdated: string;
}

/**
 * Agent Registry - Central registry for all governed AI agents
 *
 * Provides:
 * - Agent registration and lifecycle management
 * - Status tracking (active, suspended, quarantined, revoked)
 * - Capability tracking and validation
 * - Agent discovery and lookup
 */
export class AgentRegistry {
  private registryPath: string;
  private data: AgentRegistryData;

  constructor(basePath: string = process.cwd()) {
    const registryDir = join(basePath, REGISTRY_DIR);
    if (!existsSync(registryDir)) {
      mkdirSync(registryDir, { recursive: true });
    }
    this.registryPath = join(registryDir, REGISTRY_FILE);
    this.data = this.loadRegistry();
  }

  private loadRegistry(): AgentRegistryData {
    if (existsSync(this.registryPath)) {
      try {
        const content = readFileSync(this.registryPath, 'utf-8');
        return JSON.parse(content);
      } catch {
        // Corrupted file, start fresh
      }
    }
    return {
      version: '1.0.0',
      agents: [],
      lastUpdated: new Date().toISOString(),
    };
  }

  private saveRegistry(): void {
    this.data.lastUpdated = new Date().toISOString();
    writeFileSync(this.registryPath, JSON.stringify(this.data, null, 2));
  }

  /**
   * Register a new agent with Gideon governance
   */
  registerAgent(params: {
    name: string;
    type: AgentType | string;
    owner: string;
    capabilities: string[];
    description?: string;
    endpoint?: string;
    publicKey?: string;
    version?: string;
    metadata?: Record<string, any>;
  }): AgentRegistration {
    // Check for duplicate names
    const existing = this.data.agents.find(
      (a) => a.name === params.name && a.status !== 'revoked'
    );
    if (existing) {
      throw new Error(`Agent with name "${params.name}" already registered`);
    }

    // Normalize agent type (handles deprecated types like moltbot -> openclaw)
    const originalType = params.type;
    const normalizedType = normalizeAgentType(params.type);
    const wasDeprecated = originalType.toLowerCase() in DEPRECATED_AGENT_TYPES;

    const now = new Date().toISOString();
    const metadata = { ...params.metadata } || {};

    // Track deprecated type migration
    if (wasDeprecated) {
      metadata.migratedFrom = originalType;
      metadata.migrationNote = `Deprecated type '${originalType}' automatically migrated to '${normalizedType}'`;
      console.warn(
        `[Gideon Governance] Warning: Agent type '${originalType}' is deprecated. ` +
        `Automatically migrated to '${normalizedType}'. Please update your configuration.`
      );
    }

    const agent: AgentRegistration = {
      id: uuidv4(),
      name: params.name,
      type: normalizedType,
      version: params.version,
      owner: params.owner,
      description: params.description,
      endpoint: params.endpoint,
      publicKey: params.publicKey,
      capabilities: params.capabilities,
      status: 'pending',
      registeredAt: now,
      lastSeenAt: now,
      metadata,
    };

    // Validate against schema
    AgentRegistrationSchema.parse(agent);

    this.data.agents.push(agent);
    this.saveRegistry();

    return agent;
  }

  /**
   * Get an agent by ID
   */
  getAgent(agentId: string): AgentRegistration | undefined {
    return this.data.agents.find((a) => a.id === agentId);
  }

  /**
   * Get an agent by name
   */
  getAgentByName(name: string): AgentRegistration | undefined {
    return this.data.agents.find((a) => a.name === name && a.status !== 'revoked');
  }

  /**
   * List all registered agents with optional filters
   */
  listAgents(filters?: {
    status?: AgentStatus;
    type?: AgentType;
    owner?: string;
  }): AgentRegistration[] {
    let agents = [...this.data.agents];

    if (filters?.status) {
      agents = agents.filter((a) => a.status === filters.status);
    }
    if (filters?.type) {
      agents = agents.filter((a) => a.type === filters.type);
    }
    if (filters?.owner) {
      agents = agents.filter((a) => a.owner === filters.owner);
    }

    return agents;
  }

  /**
   * Update agent status
   */
  updateAgentStatus(
    agentId: string,
    status: AgentStatus,
    reason?: string
  ): AgentRegistration {
    const agent = this.getAgent(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    const oldStatus = agent.status;
    agent.status = status;

    if (status === 'active' || status === 'suspended' || status === 'quarantined') {
      agent.lastSeenAt = new Date().toISOString();
    }

    // Store status change in metadata
    agent.metadata = agent.metadata || {};
    agent.metadata.statusHistory = agent.metadata.statusHistory || [];
    agent.metadata.statusHistory.push({
      from: oldStatus,
      to: status,
      reason,
      timestamp: new Date().toISOString(),
    });

    this.saveRegistry();
    return agent;
  }

  /**
   * Activate a pending agent
   */
  activateAgent(agentId: string): AgentRegistration {
    return this.updateAgentStatus(agentId, 'active', 'Agent approved and activated');
  }

  /**
   * Suspend an agent temporarily
   */
  suspendAgent(agentId: string, reason: string): AgentRegistration {
    return this.updateAgentStatus(agentId, 'suspended', reason);
  }

  /**
   * Quarantine an agent due to policy violation
   */
  quarantineAgent(agentId: string, reason: string): AgentRegistration {
    return this.updateAgentStatus(agentId, 'quarantined', reason);
  }

  /**
   * Permanently revoke an agent's access
   */
  revokeAgent(agentId: string, reason: string): AgentRegistration {
    return this.updateAgentStatus(agentId, 'revoked', reason);
  }

  /**
   * Update agent's last seen timestamp
   */
  heartbeat(agentId: string): void {
    const agent = this.getAgent(agentId);
    if (agent && agent.status === 'active') {
      agent.lastSeenAt = new Date().toISOString();
      this.saveRegistry();
    }
  }

  /**
   * Update agent capabilities
   */
  updateCapabilities(agentId: string, capabilities: string[]): AgentRegistration {
    const agent = this.getAgent(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    agent.capabilities = capabilities;
    this.saveRegistry();
    return agent;
  }

  /**
   * Check if an agent has a specific capability
   */
  hasCapability(agentId: string, capability: string): boolean {
    const agent = this.getAgent(agentId);
    if (!agent) return false;
    return agent.capabilities.includes(capability);
  }

  /**
   * Get agents that haven't checked in recently
   */
  getStaleAgents(thresholdMinutes: number = 30): AgentRegistration[] {
    const threshold = Date.now() - thresholdMinutes * 60 * 1000;
    return this.data.agents.filter((a) => {
      if (a.status !== 'active') return false;
      if (!a.lastSeenAt) return true;
      return new Date(a.lastSeenAt).getTime() < threshold;
    });
  }

  /**
   * Get registry statistics
   */
  getStats(): {
    total: number;
    byStatus: Record<AgentStatus, number>;
    byType: Record<AgentType, number>;
  } {
    const byStatus: Record<string, number> = {
      active: 0,
      suspended: 0,
      quarantined: 0,
      revoked: 0,
      pending: 0,
    };
    const byType: Record<string, number> = {};

    for (const agent of this.data.agents) {
      byStatus[agent.status] = (byStatus[agent.status] || 0) + 1;
      byType[agent.type] = (byType[agent.type] || 0) + 1;
    }

    return {
      total: this.data.agents.length,
      byStatus: byStatus as Record<AgentStatus, number>,
      byType: byType as Record<AgentType, number>,
    };
  }

  /**
   * Search agents by query
   */
  searchAgents(query: string): AgentRegistration[] {
    const lowerQuery = query.toLowerCase();
    return this.data.agents.filter(
      (a) =>
        a.name.toLowerCase().includes(lowerQuery) ||
        a.description?.toLowerCase().includes(lowerQuery) ||
        a.owner.toLowerCase().includes(lowerQuery) ||
        a.capabilities.some((c) => c.toLowerCase().includes(lowerQuery))
    );
  }

  /**
   * Export registry data for backup
   */
  export(): AgentRegistryData {
    return { ...this.data };
  }

  /**
   * Import registry data from backup
   */
  import(data: AgentRegistryData, merge: boolean = false): void {
    if (merge) {
      // Merge, preferring newer entries
      for (const agent of data.agents) {
        const existing = this.getAgent(agent.id);
        if (!existing) {
          this.data.agents.push(agent);
        } else if (
          new Date(agent.registeredAt) > new Date(existing.registeredAt)
        ) {
          const index = this.data.agents.findIndex((a) => a.id === agent.id);
          this.data.agents[index] = agent;
        }
      }
    } else {
      this.data = data;
    }
    this.saveRegistry();
  }
}

// Singleton instance
let registryInstance: AgentRegistry | null = null;

export function getAgentRegistry(): AgentRegistry {
  if (!registryInstance) {
    registryInstance = new AgentRegistry();
  }
  return registryInstance;
}

export function resetAgentRegistry(): void {
  registryInstance = null;
}
