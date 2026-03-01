/**
 * Neo4j Graph Client
 *
 * Connection management and core graph operations for attack surface intelligence
 */

import neo4j, { Driver, Session, Result, QueryResult } from 'neo4j-driver';
import {
  GraphNode,
  GraphRelationship,
  GraphQueryResult,
  NodeLabel,
  RelationshipType,
} from './types.js';

// ============================================================================
// Graph Client
// ============================================================================

export class GraphClient {
  private driver: Driver | null = null;
  private config: GraphConfig;

  constructor(config: GraphConfig) {
    this.config = config;
  }

  /**
   * Connect to Neo4j database
   */
  async connect(): Promise<void> {
    if (this.driver) {
      return;
    }

    this.driver = neo4j.driver(
      this.config.uri,
      neo4j.auth.basic(this.config.user, this.config.password),
      {
        maxConnectionPoolSize: this.config.maxPoolSize ?? 50,
        connectionAcquisitionTimeout: this.config.connectionTimeout ?? 30000,
      }
    );

    // Verify connectivity
    await this.driver.verifyConnectivity();
  }

  /**
   * Disconnect from Neo4j
   */
  async disconnect(): Promise<void> {
    if (this.driver) {
      await this.driver.close();
      this.driver = null;
    }
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.driver !== null;
  }

  /**
   * Get a session for transactions
   */
  getSession(database?: string): Session {
    if (!this.driver) {
      throw new Error('Not connected to Neo4j. Call connect() first.');
    }
    return this.driver.session({
      database: database ?? this.config.database ?? 'neo4j',
    });
  }

  /**
   * Execute a Cypher query
   */
  async query<T = unknown>(
    cypher: string,
    params?: Record<string, unknown>
  ): Promise<T[]> {
    const session = this.getSession();
    try {
      const result = await session.run(cypher, params);
      return result.records.map((record) => {
        const obj: Record<string, unknown> = {};
        record.keys.forEach((key, index) => {
          obj[key] = this.convertNeo4jValue(record.get(index));
        });
        return obj as T;
      });
    } finally {
      await session.close();
    }
  }

  /**
   * Execute a write transaction
   */
  async write<T = unknown>(
    cypher: string,
    params?: Record<string, unknown>
  ): Promise<T[]> {
    const session = this.getSession();
    try {
      const result = await session.executeWrite(async (tx) => {
        return tx.run(cypher, params);
      });
      return result.records.map((record) => {
        const obj: Record<string, unknown> = {};
        record.keys.forEach((key, index) => {
          obj[key] = this.convertNeo4jValue(record.get(index));
        });
        return obj as T;
      });
    } finally {
      await session.close();
    }
  }

  /**
   * Create a node
   */
  async createNode<T extends Record<string, unknown>>(
    label: NodeLabel,
    properties: T
  ): Promise<GraphNode> {
    const id = properties.id ?? crypto.randomUUID();
    const now = new Date().toISOString();

    const result = await this.write<{ n: GraphNode }>(
      `CREATE (n:${label} $props)
       SET n.id = $id, n.createdAt = $now, n.updatedAt = $now
       RETURN n`,
      { props: properties, id, now }
    );

    return result[0]?.n;
  }

  /**
   * Find nodes by label and properties
   */
  async findNodes(
    label: NodeLabel,
    where?: Record<string, unknown>,
    limit?: number
  ): Promise<GraphNode[]> {
    let cypher = `MATCH (n:${label})`;

    if (where && Object.keys(where).length > 0) {
      const conditions = Object.keys(where)
        .map((key) => `n.${key} = $${key}`)
        .join(' AND ');
      cypher += ` WHERE ${conditions}`;
    }

    cypher += ' RETURN n';

    if (limit) {
      cypher += ` LIMIT ${limit}`;
    }

    const results = await this.query<{ n: GraphNode }>(cypher, where);
    return results.map((r) => r.n);
  }

  /**
   * Create a relationship between nodes
   */
  async createRelationship(
    sourceId: string,
    targetId: string,
    type: RelationshipType,
    properties?: Record<string, unknown>
  ): Promise<GraphRelationship> {
    const result = await this.write<{ r: GraphRelationship }>(
      `MATCH (a {id: $sourceId}), (b {id: $targetId})
       CREATE (a)-[r:${type} $props]->(b)
       RETURN r`,
      { sourceId, targetId, props: properties ?? {} }
    );

    return result[0]?.r;
  }

  /**
   * Find paths between nodes
   */
  async findPaths(
    startId: string,
    endId: string,
    maxDepth: number = 5
  ): Promise<Array<{ nodes: GraphNode[]; relationships: GraphRelationship[] }>> {
    const results = await this.query<{
      path: { nodes: GraphNode[]; relationships: GraphRelationship[] };
    }>(
      `MATCH path = shortestPath((a {id: $startId})-[*..${maxDepth}]-(b {id: $endId}))
       RETURN path`,
      { startId, endId }
    );

    return results.map((r) => r.path);
  }

  /**
   * Get node by ID
   */
  async getNode(id: string): Promise<GraphNode | null> {
    const results = await this.query<{ n: GraphNode }>(
      'MATCH (n {id: $id}) RETURN n',
      { id }
    );
    return results[0]?.n ?? null;
  }

  /**
   * Update node properties
   */
  async updateNode(
    id: string,
    properties: Record<string, unknown>
  ): Promise<GraphNode | null> {
    const now = new Date().toISOString();
    const results = await this.write<{ n: GraphNode }>(
      `MATCH (n {id: $id})
       SET n += $props, n.updatedAt = $now
       RETURN n`,
      { id, props: properties, now }
    );
    return results[0]?.n ?? null;
  }

  /**
   * Delete node and its relationships
   */
  async deleteNode(id: string): Promise<boolean> {
    const results = await this.write<{ count: number }>(
      `MATCH (n {id: $id})
       DETACH DELETE n
       RETURN count(*) as count`,
      { id }
    );
    return (results[0]?.count ?? 0) > 0;
  }

  /**
   * Get graph statistics
   */
  async getStats(): Promise<{
    nodeCount: number;
    relationshipCount: number;
    nodesByLabel: Record<string, number>;
  }> {
    const nodeCountResult = await this.query<{ count: number }>(
      'MATCH (n) RETURN count(n) as count'
    );
    const relCountResult = await this.query<{ count: number }>(
      'MATCH ()-[r]->() RETURN count(r) as count'
    );
    const labelCountResult = await this.query<{ label: string; count: number }>(
      'MATCH (n) RETURN labels(n)[0] as label, count(*) as count'
    );

    const nodesByLabel: Record<string, number> = {};
    labelCountResult.forEach((r) => {
      nodesByLabel[r.label] = r.count;
    });

    return {
      nodeCount: nodeCountResult[0]?.count ?? 0,
      relationshipCount: relCountResult[0]?.count ?? 0,
      nodesByLabel,
    };
  }

  /**
   * Clear all data (use with caution!)
   */
  async clearAll(): Promise<void> {
    await this.write('MATCH (n) DETACH DELETE n');
  }

  /**
   * Convert Neo4j values to JavaScript values
   */
  private convertNeo4jValue(value: unknown): unknown {
    if (value === null || value === undefined) {
      return value;
    }

    // Handle Neo4j Integer
    if (neo4j.isInt(value)) {
      return value.toNumber();
    }

    // Handle Neo4j Node
    if (value && typeof value === 'object' && 'properties' in value) {
      const node = value as { labels?: string[]; properties: Record<string, unknown> };
      return {
        ...this.convertNeo4jValue(node.properties),
        _labels: node.labels,
      };
    }

    // Handle arrays
    if (Array.isArray(value)) {
      return value.map((v) => this.convertNeo4jValue(v));
    }

    // Handle objects
    if (typeof value === 'object') {
      const obj: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(value)) {
        obj[key] = this.convertNeo4jValue(val);
      }
      return obj;
    }

    return value;
  }
}

// ============================================================================
// Configuration
// ============================================================================

export interface GraphConfig {
  uri: string;
  user: string;
  password: string;
  database?: string;
  maxPoolSize?: number;
  connectionTimeout?: number;
}

// ============================================================================
// Singleton Instance
// ============================================================================

let graphClient: GraphClient | null = null;

export function getGraphClient(): GraphClient {
  if (!graphClient) {
    const config: GraphConfig = {
      uri: process.env.NEO4J_URI ?? 'bolt://localhost:7687',
      user: process.env.NEO4J_USER ?? 'neo4j',
      password: process.env.NEO4J_PASSWORD ?? 'gideon',
      database: process.env.NEO4J_DATABASE ?? 'neo4j',
    };
    graphClient = new GraphClient(config);
  }
  return graphClient;
}

export async function initializeGraph(): Promise<GraphClient> {
  const client = getGraphClient();
  await client.connect();
  return client;
}

// Re-export types
export * from './types.js';
