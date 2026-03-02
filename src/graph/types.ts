/**
 * Neo4j Graph Types
 *
 * Type definitions for the attack surface graph
 */

import { z } from 'zod';

// ============================================================================
// Node Types (17 types)
// ============================================================================

export type NodeLabel =
  | 'Domain'
  | 'Subdomain'
  | 'IPAddress'
  | 'Port'
  | 'Service'
  | 'URL'
  | 'Endpoint'
  | 'Parameter'
  | 'Vulnerability'
  | 'CVE'
  | 'Technology'
  | 'Certificate'
  | 'Header'
  | 'WhoIsRecord'
  | 'Finding'
  | 'AttackChain'
  | 'Session';

// ============================================================================
// Base Node Properties
// ============================================================================

export interface BaseNodeProperties {
  id: string;
  createdAt: string;
  updatedAt: string;
  sessionId?: string;
}

export interface DomainNode extends BaseNodeProperties {
  name: string;
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
}

export interface SubdomainNode extends BaseNodeProperties {
  name: string;
  source: 'dns' | 'cert_transparency' | 'bruteforce' | 'crawl';
}

export interface IPAddressNode extends BaseNodeProperties {
  address: string;
  version: 4 | 6;
  asn?: string;
  organization?: string;
  country?: string;
  city?: string;
}

export interface PortNode extends BaseNodeProperties {
  number: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
}

export interface ServiceNode extends BaseNodeProperties {
  name: string;
  version?: string;
  product?: string;
  banner?: string;
}

export interface URLNode extends BaseNodeProperties {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
}

export interface EndpointNode extends BaseNodeProperties {
  path: string;
  methods: string[];
  parameters?: string[];
}

export interface ParameterNode extends BaseNodeProperties {
  name: string;
  type: 'query' | 'body' | 'header' | 'path' | 'cookie';
  dataType?: string;
  required?: boolean;
}

export interface VulnerabilityNode extends BaseNodeProperties {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvssScore?: number;
  description: string;
  remediation?: string;
  verified: boolean;
}

export interface CVENode extends BaseNodeProperties {
  cveId: string;
  description: string;
  cvssV3Score?: number;
  cvssV3Vector?: string;
  publishedDate: string;
  lastModifiedDate: string;
  references: string[];
}

export interface TechnologyNode extends BaseNodeProperties {
  name: string;
  version?: string;
  category: string;
  confidence: number;
}

export interface CertificateNode extends BaseNodeProperties {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  isExpired: boolean;
  isSelfSigned: boolean;
}

export interface HeaderNode extends BaseNodeProperties {
  name: string;
  value: string;
  securityRelevant: boolean;
}

export interface WhoIsRecordNode extends BaseNodeProperties {
  registrar: string;
  registrantName?: string;
  registrantEmail?: string;
  nameServers: string[];
  creationDate: string;
  expirationDate: string;
}

export interface FindingNode extends BaseNodeProperties {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  evidence: string;
  remediation?: string;
  status: 'new' | 'confirmed' | 'false_positive' | 'remediated';
}

export interface AttackChainNode extends BaseNodeProperties {
  name: string;
  description: string;
  impactScore: number;
  likelihood: 'high' | 'medium' | 'low';
  steps: string[];
}

export interface SessionNode extends BaseNodeProperties {
  name: string;
  mode: 'bounty' | 'pentest' | 'research' | 'ctf';
  status: 'active' | 'paused' | 'completed';
  targetDomain: string;
  startedAt: string;
  endedAt?: string;
}

// ============================================================================
// Relationship Types (20+ types)
// ============================================================================

export type RelationshipType =
  | 'HAS_SUBDOMAIN'
  | 'RESOLVES_TO'
  | 'HAS_PORT'
  | 'RUNS_SERVICE'
  | 'HAS_URL'
  | 'HAS_ENDPOINT'
  | 'HAS_PARAMETER'
  | 'HAS_VULNERABILITY'
  | 'REFERENCES_CVE'
  | 'USES_TECHNOLOGY'
  | 'HAS_CERTIFICATE'
  | 'HAS_HEADER'
  | 'REGISTERED_BY'
  | 'PART_OF_CHAIN'
  | 'EXPLOITS'
  | 'LEADS_TO'
  | 'DISCOVERED_IN'
  | 'HOSTS'
  | 'CONNECTS_TO'
  | 'AUTHENTICATES_WITH'
  | 'REDIRECTS_TO'
  | 'CONTAINS'
  | 'DEPENDS_ON';

export interface Relationship {
  type: RelationshipType;
  properties?: Record<string, unknown>;
  sourceId: string;
  targetId: string;
}

// ============================================================================
// Graph Query Types
// ============================================================================

export interface GraphNode {
  id: string;
  labels: NodeLabel[];
  properties: Record<string, unknown>;
}

export interface GraphRelationship {
  id: string;
  type: RelationshipType;
  startNodeId: string;
  endNodeId: string;
  properties: Record<string, unknown>;
}

export interface GraphPath {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

export interface GraphQueryResult {
  records: Array<{
    keys: string[];
    values: unknown[];
  }>;
  summary: {
    counters: {
      nodesCreated: number;
      nodesDeleted: number;
      relationshipsCreated: number;
      relationshipsDeleted: number;
      propertiesSet: number;
    };
  };
}

// ============================================================================
// Attack Surface Types
// ============================================================================

export interface AttackSurface {
  sessionId: string;
  domain: string;
  subdomains: SubdomainNode[];
  ipAddresses: IPAddressNode[];
  ports: PortNode[];
  services: ServiceNode[];
  technologies: TechnologyNode[];
  vulnerabilities: VulnerabilityNode[];
  findings: FindingNode[];
  attackChains: AttackChainNode[];
  statistics: AttackSurfaceStats;
}

export interface AttackSurfaceStats {
  totalNodes: number;
  totalRelationships: number;
  subdomainCount: number;
  openPortCount: number;
  serviceCount: number;
  vulnerabilityCount: number;
  findingsBySeverity: Record<string, number>;
  technologyStack: string[];
}

// ============================================================================
// Zod Schemas
// ============================================================================

export const NodeLabelSchema = z.enum([
  'Domain',
  'Subdomain',
  'IPAddress',
  'Port',
  'Service',
  'URL',
  'Endpoint',
  'Parameter',
  'Vulnerability',
  'CVE',
  'Technology',
  'Certificate',
  'Header',
  'WhoIsRecord',
  'Finding',
  'AttackChain',
  'Session',
]);

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

export const RelationshipTypeSchema = z.enum([
  'HAS_SUBDOMAIN',
  'RESOLVES_TO',
  'HAS_PORT',
  'RUNS_SERVICE',
  'HAS_URL',
  'HAS_ENDPOINT',
  'HAS_PARAMETER',
  'HAS_VULNERABILITY',
  'REFERENCES_CVE',
  'USES_TECHNOLOGY',
  'HAS_CERTIFICATE',
  'HAS_HEADER',
  'REGISTERED_BY',
  'PART_OF_CHAIN',
  'EXPLOITS',
  'LEADS_TO',
  'DISCOVERED_IN',
  'HOSTS',
  'CONNECTS_TO',
  'AUTHENTICATES_WITH',
  'REDIRECTS_TO',
  'CONTAINS',
  'DEPENDS_ON',
]);
