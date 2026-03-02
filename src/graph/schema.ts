/**
 * Neo4j Graph Schema
 *
 * Schema definitions and initialization for the attack surface graph
 */

import { GraphClient } from './index.js';
import { NodeLabel, RelationshipType } from './types.js';

// ============================================================================
// Schema Definitions
// ============================================================================

export const NODE_SCHEMAS: Record<NodeLabel, NodeSchema> = {
  Domain: {
    label: 'Domain',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, indexed: true },
      registrar: { type: 'string' },
      creationDate: { type: 'datetime' },
      expirationDate: { type: 'datetime' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Subdomain: {
    label: 'Subdomain',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, indexed: true },
      source: { type: 'string', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  IPAddress: {
    label: 'IPAddress',
    properties: {
      id: { type: 'string', required: true, unique: true },
      address: { type: 'string', required: true, indexed: true },
      version: { type: 'integer', required: true },
      asn: { type: 'string' },
      organization: { type: 'string' },
      country: { type: 'string' },
      city: { type: 'string' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Port: {
    label: 'Port',
    properties: {
      id: { type: 'string', required: true, unique: true },
      number: { type: 'integer', required: true, indexed: true },
      protocol: { type: 'string', required: true },
      state: { type: 'string', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Service: {
    label: 'Service',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, indexed: true },
      version: { type: 'string' },
      product: { type: 'string' },
      banner: { type: 'string' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  URL: {
    label: 'URL',
    properties: {
      id: { type: 'string', required: true, unique: true },
      url: { type: 'string', required: true, indexed: true },
      method: { type: 'string', required: true },
      statusCode: { type: 'integer' },
      contentType: { type: 'string' },
      contentLength: { type: 'integer' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Endpoint: {
    label: 'Endpoint',
    properties: {
      id: { type: 'string', required: true, unique: true },
      path: { type: 'string', required: true, indexed: true },
      methods: { type: 'list' },
      parameters: { type: 'list' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Parameter: {
    label: 'Parameter',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, indexed: true },
      type: { type: 'string', required: true },
      dataType: { type: 'string' },
      required: { type: 'boolean' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Vulnerability: {
    label: 'Vulnerability',
    properties: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true },
      severity: { type: 'string', required: true, indexed: true },
      cvssScore: { type: 'float' },
      description: { type: 'string', required: true },
      remediation: { type: 'string' },
      verified: { type: 'boolean', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  CVE: {
    label: 'CVE',
    properties: {
      id: { type: 'string', required: true, unique: true },
      cveId: { type: 'string', required: true, indexed: true },
      description: { type: 'string', required: true },
      cvssV3Score: { type: 'float' },
      cvssV3Vector: { type: 'string' },
      publishedDate: { type: 'datetime', required: true },
      lastModifiedDate: { type: 'datetime', required: true },
      references: { type: 'list' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Technology: {
    label: 'Technology',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, indexed: true },
      version: { type: 'string' },
      category: { type: 'string', required: true },
      confidence: { type: 'float', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Certificate: {
    label: 'Certificate',
    properties: {
      id: { type: 'string', required: true, unique: true },
      subject: { type: 'string', required: true },
      issuer: { type: 'string', required: true },
      validFrom: { type: 'datetime', required: true },
      validTo: { type: 'datetime', required: true },
      serialNumber: { type: 'string', required: true },
      fingerprint: { type: 'string', required: true, indexed: true },
      isExpired: { type: 'boolean', required: true },
      isSelfSigned: { type: 'boolean', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Header: {
    label: 'Header',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true, indexed: true },
      value: { type: 'string', required: true },
      securityRelevant: { type: 'boolean', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  WhoIsRecord: {
    label: 'WhoIsRecord',
    properties: {
      id: { type: 'string', required: true, unique: true },
      registrar: { type: 'string', required: true },
      registrantName: { type: 'string' },
      registrantEmail: { type: 'string' },
      nameServers: { type: 'list', required: true },
      creationDate: { type: 'datetime', required: true },
      expirationDate: { type: 'datetime', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Finding: {
    label: 'Finding',
    properties: {
      id: { type: 'string', required: true, unique: true },
      title: { type: 'string', required: true },
      severity: { type: 'string', required: true, indexed: true },
      category: { type: 'string', required: true, indexed: true },
      description: { type: 'string', required: true },
      evidence: { type: 'string', required: true },
      remediation: { type: 'string' },
      status: { type: 'string', required: true, indexed: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  AttackChain: {
    label: 'AttackChain',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      description: { type: 'string', required: true },
      impactScore: { type: 'float', required: true },
      likelihood: { type: 'string', required: true },
      steps: { type: 'list', required: true },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
  Session: {
    label: 'Session',
    properties: {
      id: { type: 'string', required: true, unique: true },
      name: { type: 'string', required: true },
      mode: { type: 'string', required: true, indexed: true },
      status: { type: 'string', required: true, indexed: true },
      targetDomain: { type: 'string', required: true },
      startedAt: { type: 'datetime', required: true },
      endedAt: { type: 'datetime' },
      createdAt: { type: 'datetime', required: true },
      updatedAt: { type: 'datetime', required: true },
    },
  },
};

// ============================================================================
// Relationship Schema
// ============================================================================

export const RELATIONSHIP_SCHEMAS: Record<RelationshipType, RelationshipSchema> = {
  HAS_SUBDOMAIN: { from: ['Domain'], to: ['Subdomain'] },
  RESOLVES_TO: { from: ['Domain', 'Subdomain'], to: ['IPAddress'] },
  HAS_PORT: { from: ['IPAddress'], to: ['Port'] },
  RUNS_SERVICE: { from: ['Port'], to: ['Service'] },
  HAS_URL: { from: ['Domain', 'Subdomain', 'Service'], to: ['URL'] },
  HAS_ENDPOINT: { from: ['URL', 'Service'], to: ['Endpoint'] },
  HAS_PARAMETER: { from: ['Endpoint', 'URL'], to: ['Parameter'] },
  HAS_VULNERABILITY: { from: ['Service', 'Endpoint', 'Parameter', 'URL'], to: ['Vulnerability'] },
  REFERENCES_CVE: { from: ['Vulnerability'], to: ['CVE'] },
  USES_TECHNOLOGY: { from: ['URL', 'Service', 'Domain'], to: ['Technology'] },
  HAS_CERTIFICATE: { from: ['Domain', 'Subdomain'], to: ['Certificate'] },
  HAS_HEADER: { from: ['URL'], to: ['Header'] },
  REGISTERED_BY: { from: ['Domain'], to: ['WhoIsRecord'] },
  PART_OF_CHAIN: { from: ['Finding', 'Vulnerability'], to: ['AttackChain'] },
  EXPLOITS: { from: ['AttackChain'], to: ['Vulnerability'] },
  LEADS_TO: { from: ['Vulnerability', 'Finding'], to: ['Vulnerability', 'Finding'] },
  DISCOVERED_IN: { from: ['Finding', 'Vulnerability'], to: ['Session'] },
  HOSTS: { from: ['IPAddress'], to: ['Domain', 'Subdomain'] },
  CONNECTS_TO: { from: ['Service'], to: ['Service', 'IPAddress'] },
  AUTHENTICATES_WITH: { from: ['Endpoint'], to: ['Service'] },
  REDIRECTS_TO: { from: ['URL'], to: ['URL'] },
  CONTAINS: { from: ['Domain'], to: ['Domain', 'Subdomain'] },
  DEPENDS_ON: { from: ['Technology'], to: ['Technology'] },
};

// ============================================================================
// Schema Types
// ============================================================================

interface NodeSchema {
  label: NodeLabel;
  properties: Record<string, PropertySchema>;
}

interface PropertySchema {
  type: 'string' | 'integer' | 'float' | 'boolean' | 'datetime' | 'list' | 'map';
  required?: boolean;
  unique?: boolean;
  indexed?: boolean;
}

interface RelationshipSchema {
  from: NodeLabel[];
  to: NodeLabel[];
  properties?: Record<string, PropertySchema>;
}

// ============================================================================
// Schema Initialization
// ============================================================================

/**
 * Create indexes and constraints for the graph schema
 */
export async function initializeSchema(client: GraphClient): Promise<void> {
  // Create unique constraints and indexes for each node type
  for (const [label, schema] of Object.entries(NODE_SCHEMAS)) {
    for (const [propName, propSchema] of Object.entries(schema.properties)) {
      if (propSchema.unique) {
        await client.query(
          `CREATE CONSTRAINT IF NOT EXISTS FOR (n:${label}) REQUIRE n.${propName} IS UNIQUE`
        ).catch(() => {
          // Constraint may already exist
        });
      } else if (propSchema.indexed) {
        await client.query(
          `CREATE INDEX IF NOT EXISTS FOR (n:${label}) ON (n.${propName})`
        ).catch(() => {
          // Index may already exist
        });
      }
    }
  }
}

/**
 * Validate node properties against schema
 */
export function validateNodeProperties(
  label: NodeLabel,
  properties: Record<string, unknown>
): { valid: boolean; errors: string[] } {
  const schema = NODE_SCHEMAS[label];
  if (!schema) {
    return { valid: false, errors: [`Unknown node label: ${label}`] };
  }

  const errors: string[] = [];

  for (const [propName, propSchema] of Object.entries(schema.properties)) {
    const value = properties[propName];

    if (propSchema.required && (value === undefined || value === null)) {
      errors.push(`Missing required property: ${propName}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Get schema for a node label
 */
export function getNodeSchema(label: NodeLabel): NodeSchema | undefined {
  return NODE_SCHEMAS[label];
}

/**
 * Get schema for a relationship type
 */
export function getRelationshipSchema(type: RelationshipType): RelationshipSchema | undefined {
  return RELATIONSHIP_SCHEMAS[type];
}
