import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  Permission,
  PermissionSchema,
  AccessRequest,
  AccessRequestSchema,
  ResourceType,
} from './types';
import { getAgentRegistry } from './agent-registry';

const ACCESS_DIR = '.gideon/governance';
const PERMISSIONS_FILE = 'permissions.json';
const REQUESTS_FILE = 'access-requests.json';

interface PermissionsData {
  version: string;
  permissions: Permission[];
  lastUpdated: string;
}

interface RequestsData {
  requests: AccessRequest[];
  lastUpdated: string;
}

type AccessAction = 'read' | 'write' | 'execute' | 'delete' | 'admin';

/**
 * Access Control - Permission management for AI agents
 *
 * Provides:
 * - Fine-grained permission management
 * - Resource-based access control
 * - Access request workflow
 * - Permission expiration
 * - Conditional access (MFA, IP restrictions)
 */
export class AccessControl {
  private basePath: string;
  private permissionsPath: string;
  private requestsPath: string;
  private permissions: PermissionsData;
  private requests: RequestsData;

  constructor(basePath: string = process.cwd()) {
    this.basePath = basePath;
    const accessDir = join(basePath, ACCESS_DIR);
    if (!existsSync(accessDir)) {
      mkdirSync(accessDir, { recursive: true });
    }

    this.permissionsPath = join(accessDir, PERMISSIONS_FILE);
    this.requestsPath = join(accessDir, REQUESTS_FILE);

    this.permissions = this.loadPermissions();
    this.requests = this.loadRequests();
  }

  private loadPermissions(): PermissionsData {
    if (existsSync(this.permissionsPath)) {
      try {
        return JSON.parse(readFileSync(this.permissionsPath, 'utf-8'));
      } catch {
        // Corrupted file
      }
    }
    return {
      version: '1.0.0',
      permissions: [],
      lastUpdated: new Date().toISOString(),
    };
  }

  private savePermissions(): void {
    this.permissions.lastUpdated = new Date().toISOString();
    writeFileSync(this.permissionsPath, JSON.stringify(this.permissions, null, 2));
  }

  private loadRequests(): RequestsData {
    if (existsSync(this.requestsPath)) {
      try {
        return JSON.parse(readFileSync(this.requestsPath, 'utf-8'));
      } catch {
        // Corrupted file
      }
    }
    return { requests: [], lastUpdated: new Date().toISOString() };
  }

  private saveRequests(): void {
    this.requests.lastUpdated = new Date().toISOString();
    writeFileSync(this.requestsPath, JSON.stringify(this.requests, null, 2));
  }

  /**
   * Grant a permission to an agent
   */
  grantPermission(params: {
    agentId: string;
    resourceType: ResourceType;
    resource: string;
    actions: AccessAction[];
    grantedBy: string;
    expiresAt?: string;
    conditions?: {
      requireMFA?: boolean;
      maxUsageCount?: number;
      allowedIPs?: string[];
    };
  }): Permission {
    // Verify agent exists
    const registry = getAgentRegistry();
    const agent = registry.getAgent(params.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${params.agentId}`);
    }

    // Check for existing permission
    const existing = this.permissions.permissions.find(
      (p) =>
        p.agentId === params.agentId &&
        p.resourceType === params.resourceType &&
        p.resource === params.resource
    );

    if (existing) {
      // Update existing permission
      existing.actions = [...new Set([...existing.actions, ...params.actions])];
      existing.grantedBy = params.grantedBy;
      existing.grantedAt = new Date().toISOString();
      if (params.expiresAt) existing.expiresAt = params.expiresAt;
      if (params.conditions) existing.conditions = params.conditions;
      existing.granted = true;

      PermissionSchema.parse(existing);
      this.savePermissions();
      return existing;
    }

    const permission: Permission = {
      id: uuidv4(),
      agentId: params.agentId,
      resourceType: params.resourceType,
      resource: params.resource,
      actions: params.actions,
      granted: true,
      grantedBy: params.grantedBy,
      grantedAt: new Date().toISOString(),
      expiresAt: params.expiresAt,
      conditions: params.conditions,
    };

    PermissionSchema.parse(permission);
    this.permissions.permissions.push(permission);
    this.savePermissions();

    return permission;
  }

  /**
   * Revoke a permission
   */
  revokePermission(permissionId: string): void {
    const index = this.permissions.permissions.findIndex((p) => p.id === permissionId);
    if (index === -1) {
      throw new Error(`Permission not found: ${permissionId}`);
    }

    this.permissions.permissions.splice(index, 1);
    this.savePermissions();
  }

  /**
   * Revoke all permissions for an agent
   */
  revokeAllPermissions(agentId: string): number {
    const before = this.permissions.permissions.length;
    this.permissions.permissions = this.permissions.permissions.filter(
      (p) => p.agentId !== agentId
    );
    this.savePermissions();
    return before - this.permissions.permissions.length;
  }

  /**
   * Check if an agent has permission for an action
   */
  checkPermission(
    agentId: string,
    resourceType: ResourceType,
    resource: string,
    action: AccessAction,
    context?: { ip?: string; hasMFA?: boolean }
  ): { allowed: boolean; reason: string; permission?: Permission } {
    // Get all matching permissions
    const matchingPermissions = this.permissions.permissions.filter(
      (p) =>
        p.agentId === agentId &&
        p.resourceType === resourceType &&
        p.granted &&
        this.matchesResource(p.resource, resource) &&
        p.actions.includes(action)
    );

    if (matchingPermissions.length === 0) {
      return { allowed: false, reason: 'No matching permission found' };
    }

    // Check each permission's conditions
    for (const permission of matchingPermissions) {
      // Check expiration
      if (permission.expiresAt && new Date(permission.expiresAt) < new Date()) {
        continue; // Expired, try next
      }

      // Check conditions
      if (permission.conditions) {
        if (permission.conditions.requireMFA && !context?.hasMFA) {
          continue; // MFA required but not provided
        }

        if (permission.conditions.allowedIPs && context?.ip) {
          if (!permission.conditions.allowedIPs.includes(context.ip)) {
            continue; // IP not allowed
          }
        }
      }

      // Permission is valid
      return {
        allowed: true,
        reason: `Granted by permission: ${permission.id}`,
        permission,
      };
    }

    return { allowed: false, reason: 'No valid permission found (may be expired or conditions not met)' };
  }

  /**
   * Check if a resource pattern matches a specific resource
   */
  private matchesResource(pattern: string, resource: string): boolean {
    // Exact match
    if (pattern === resource) return true;

    // Wildcard matching
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -2);
      return resource.startsWith(prefix);
    }

    if (pattern.endsWith('/**')) {
      const prefix = pattern.slice(0, -3);
      return resource.startsWith(prefix);
    }

    // Glob-style matching
    if (pattern.includes('*')) {
      const regexPattern = pattern
        .replace(/\./g, '\\.')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*');
      try {
        const regex = new RegExp(`^${regexPattern}$`);
        return regex.test(resource);
      } catch {
        return false;
      }
    }

    return false;
  }

  /**
   * Get all permissions for an agent
   */
  getAgentPermissions(agentId: string): Permission[] {
    return this.permissions.permissions.filter(
      (p) => p.agentId === agentId && p.granted
    );
  }

  /**
   * Get all permissions for a resource type
   */
  getResourcePermissions(resourceType: ResourceType): Permission[] {
    return this.permissions.permissions.filter(
      (p) => p.resourceType === resourceType && p.granted
    );
  }

  /**
   * Create an access request
   */
  requestAccess(params: {
    agentId: string;
    resourceType: ResourceType;
    resource: string;
    action: string;
    justification?: string;
  }): AccessRequest {
    // Verify agent exists
    const registry = getAgentRegistry();
    const agent = registry.getAgent(params.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${params.agentId}`);
    }

    const request: AccessRequest = {
      id: uuidv4(),
      agentId: params.agentId,
      requestedAt: new Date().toISOString(),
      resourceType: params.resourceType,
      resource: params.resource,
      action: params.action,
      justification: params.justification,
      status: 'pending',
    };

    AccessRequestSchema.parse(request);
    this.requests.requests.push(request);
    this.saveRequests();

    return request;
  }

  /**
   * Approve an access request
   */
  approveRequest(
    requestId: string,
    reviewedBy: string,
    options?: {
      expiresAt?: string;
      conditions?: Permission['conditions'];
      notes?: string;
    }
  ): { request: AccessRequest; permission: Permission } {
    const request = this.requests.requests.find((r) => r.id === requestId);
    if (!request) {
      throw new Error(`Access request not found: ${requestId}`);
    }

    if (request.status !== 'pending') {
      throw new Error(`Request is not pending: ${request.status}`);
    }

    request.status = 'approved';
    request.reviewedBy = reviewedBy;
    request.reviewedAt = new Date().toISOString();
    request.reviewNotes = options?.notes;
    this.saveRequests();

    // Create the permission
    const permission = this.grantPermission({
      agentId: request.agentId,
      resourceType: request.resourceType,
      resource: request.resource,
      actions: [request.action as AccessAction],
      grantedBy: reviewedBy,
      expiresAt: options?.expiresAt,
      conditions: options?.conditions,
    });

    return { request, permission };
  }

  /**
   * Deny an access request
   */
  denyRequest(requestId: string, reviewedBy: string, notes?: string): AccessRequest {
    const request = this.requests.requests.find((r) => r.id === requestId);
    if (!request) {
      throw new Error(`Access request not found: ${requestId}`);
    }

    if (request.status !== 'pending') {
      throw new Error(`Request is not pending: ${request.status}`);
    }

    request.status = 'denied';
    request.reviewedBy = reviewedBy;
    request.reviewedAt = new Date().toISOString();
    request.reviewNotes = notes;
    this.saveRequests();

    return request;
  }

  /**
   * Get pending access requests
   */
  getPendingRequests(): AccessRequest[] {
    return this.requests.requests.filter((r) => r.status === 'pending');
  }

  /**
   * Get access requests for an agent
   */
  getAgentRequests(agentId: string): AccessRequest[] {
    return this.requests.requests.filter((r) => r.agentId === agentId);
  }

  /**
   * Get expired permissions
   */
  getExpiredPermissions(): Permission[] {
    const now = new Date();
    return this.permissions.permissions.filter(
      (p) => p.expiresAt && new Date(p.expiresAt) < now
    );
  }

  /**
   * Clean up expired permissions
   */
  cleanupExpired(): number {
    const expired = this.getExpiredPermissions();
    for (const permission of expired) {
      permission.granted = false;
    }
    this.savePermissions();
    return expired.length;
  }

  /**
   * Get permission statistics
   */
  getStats(): {
    totalPermissions: number;
    activePermissions: number;
    expiredPermissions: number;
    pendingRequests: number;
    byResourceType: Record<ResourceType, number>;
    byAction: Record<AccessAction, number>;
  } {
    const byResourceType: Record<string, number> = {};
    const byAction: Record<string, number> = {};
    let active = 0;
    let expired = 0;
    const now = new Date();

    for (const permission of this.permissions.permissions) {
      if (permission.expiresAt && new Date(permission.expiresAt) < now) {
        expired++;
      } else if (permission.granted) {
        active++;
      }

      byResourceType[permission.resourceType] =
        (byResourceType[permission.resourceType] || 0) + 1;

      for (const action of permission.actions) {
        byAction[action] = (byAction[action] || 0) + 1;
      }
    }

    return {
      totalPermissions: this.permissions.permissions.length,
      activePermissions: active,
      expiredPermissions: expired,
      pendingRequests: this.getPendingRequests().length,
      byResourceType: byResourceType as Record<ResourceType, number>,
      byAction: byAction as Record<AccessAction, number>,
    };
  }

  /**
   * Export permissions for backup
   */
  export(): { permissions: PermissionsData; requests: RequestsData } {
    return {
      permissions: { ...this.permissions },
      requests: { ...this.requests },
    };
  }

  /**
   * Import permissions from backup
   */
  import(
    data: { permissions: PermissionsData; requests: RequestsData },
    replace: boolean = false
  ): void {
    if (replace) {
      this.permissions = data.permissions;
      this.requests = data.requests;
    } else {
      // Merge
      for (const permission of data.permissions.permissions) {
        if (!this.permissions.permissions.find((p) => p.id === permission.id)) {
          this.permissions.permissions.push(permission);
        }
      }
      for (const request of data.requests.requests) {
        if (!this.requests.requests.find((r) => r.id === request.id)) {
          this.requests.requests.push(request);
        }
      }
    }
    this.savePermissions();
    this.saveRequests();
  }
}

// Singleton instance
let accessControlInstance: AccessControl | null = null;

export function getAccessControl(): AccessControl {
  if (!accessControlInstance) {
    accessControlInstance = new AccessControl();
  }
  return accessControlInstance;
}

export function resetAccessControl(): void {
  accessControlInstance = null;
}
