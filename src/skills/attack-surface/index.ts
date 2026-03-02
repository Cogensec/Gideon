/**
 * Attack Surface Skill
 *
 * Build and query attack surface graphs using Neo4j
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';
import {
  getGraphClient,
  initializeGraph,
  GraphClient,
  NodeLabel,
} from '../../graph/index.js';
import { initializeSchema } from '../../graph/schema.js';
import { getEvoGraph, EvoGraph } from '../../graph/evograph.js';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Command Implementations
// ============================================================================

async function handleMap(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const domain = args[0];

  if (!domain) {
    return {
      success: false,
      output: '',
      error: 'Usage: surface map <domain>',
    };
  }

  try {
    const client = getGraphClient();
    await client.connect();
    await initializeSchema(client);

    const sessionId = uuidv4();
    const now = new Date().toISOString();

    // Create session node
    await client.createNode('Session', {
      name: `Attack Surface Mapping - ${domain}`,
      mode: 'research',
      status: 'active',
      targetDomain: domain,
      startedAt: now,
    });

    // Create domain node
    const domainNode = await client.createNode('Domain', {
      name: domain,
      sessionId,
    });

    return {
      success: true,
      output: `# Attack Surface Mapping Started

**Domain:** ${domain}
**Session ID:** ${sessionId}
**Started:** ${now}

## Next Steps
1. Run reconnaissance: \`recon ${domain}\`
2. Query the graph: \`surface query "MATCH (n) RETURN n LIMIT 10"\`
3. View statistics: \`surface stats\`

The attack surface graph is being built in Neo4j.`,
      data: { sessionId, domain, nodeId: domainNode?.id },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to initialize graph: ${error}`,
    };
  }
}

async function handleQuery(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const cypher = args.join(' ');

  if (!cypher) {
    return {
      success: false,
      output: '',
      error: 'Usage: surface query <cypher-query>',
    };
  }

  // Security check: block destructive operations
  const destructivePatterns = /\b(DELETE|DETACH|DROP|CREATE|SET|REMOVE|MERGE)\b/i;
  if (destructivePatterns.test(cypher)) {
    return {
      success: false,
      output: '',
      error: 'Destructive queries are not allowed. Use read-only queries.',
    };
  }

  try {
    const client = getGraphClient();
    const results = await client.query(cypher);

    return {
      success: true,
      output: `# Query Results

\`\`\`cypher
${cypher}
\`\`\`

**Found ${results.length} results:**

\`\`\`json
${JSON.stringify(results, null, 2)}
\`\`\``,
      data: { results },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Query failed: ${error}`,
    };
  }
}

async function handleStats(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  try {
    const client = getGraphClient();
    const stats = await client.getStats();

    const lines = [
      '# Attack Surface Statistics\n',
      `**Total Nodes:** ${stats.nodeCount}`,
      `**Total Relationships:** ${stats.relationshipCount}`,
      '',
      '## Nodes by Type',
      '',
    ];

    for (const [label, count] of Object.entries(stats.nodesByLabel)) {
      lines.push(`- **${label}:** ${count}`);
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: stats,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to get stats: ${error}`,
    };
  }
}

async function handleVisualize(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const sessionId = args[0];

  try {
    const client = getGraphClient();

    // Get nodes and relationships for visualization
    const nodes = await client.query<{ n: { id: string; _labels: string[] } }>(
      sessionId
        ? 'MATCH (n {sessionId: $sessionId}) RETURN n LIMIT 100'
        : 'MATCH (n) RETURN n LIMIT 100',
      { sessionId }
    );

    const rels = await client.query<{
      r: { type: string };
      source: string;
      target: string;
    }>(
      sessionId
        ? `MATCH (a {sessionId: $sessionId})-[r]->(b {sessionId: $sessionId})
           RETURN type(r) as type, a.id as source, b.id as target LIMIT 200`
        : `MATCH (a)-[r]->(b)
           RETURN type(r) as type, a.id as source, b.id as target LIMIT 200`,
      { sessionId }
    );

    // Generate ASCII visualization
    const nodeTypes = new Map<string, number>();
    nodes.forEach((n) => {
      const label = n.n._labels?.[0] || 'Unknown';
      nodeTypes.set(label, (nodeTypes.get(label) || 0) + 1);
    });

    const relTypes = new Map<string, number>();
    rels.forEach((r) => {
      relTypes.set(r.r.type, (relTypes.get(r.r.type) || 0) + 1);
    });

    const lines = [
      '# Attack Surface Visualization\n',
      '## Node Distribution',
      '```',
    ];

    for (const [type, count] of nodeTypes) {
      const bar = '█'.repeat(Math.min(count, 50));
      lines.push(`${type.padEnd(15)} ${bar} ${count}`);
    }

    lines.push('```\n', '## Relationship Distribution', '```');

    for (const [type, count] of relTypes) {
      const bar = '█'.repeat(Math.min(count, 50));
      lines.push(`${type.padEnd(20)} ${bar} ${count}`);
    }

    lines.push('```\n');
    lines.push(`**Total Nodes:** ${nodes.length}`);
    lines.push(`**Total Relationships:** ${rels.length}`);
    lines.push('\n*For full visualization, access Neo4j Browser at http://localhost:7474*');

    return {
      success: true,
      output: lines.join('\n'),
      data: { nodes: nodes.length, relationships: rels.length, nodeTypes: Object.fromEntries(nodeTypes) },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Visualization failed: ${error}`,
    };
  }
}

async function handleExport(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const format = args[0] || 'json';
  const sessionId = args[1];

  try {
    const client = getGraphClient();

    const nodes = await client.query(
      sessionId
        ? 'MATCH (n {sessionId: $sessionId}) RETURN n'
        : 'MATCH (n) RETURN n',
      { sessionId }
    );

    const relationships = await client.query(
      sessionId
        ? `MATCH (a {sessionId: $sessionId})-[r]->(b {sessionId: $sessionId})
           RETURN a.id as source, type(r) as type, b.id as target`
        : `MATCH (a)-[r]->(b)
           RETURN a.id as source, type(r) as type, b.id as target`
    );

    const exportData = {
      exportedAt: new Date().toISOString(),
      sessionId: sessionId || 'all',
      nodes,
      relationships,
    };

    if (format === 'csv') {
      const nodesCsv = nodes.map((n: Record<string, unknown>) =>
        Object.values(n).join(',')
      ).join('\n');

      return {
        success: true,
        output: `# Attack Surface Export (CSV)\n\n\`\`\`csv\n${nodesCsv}\n\`\`\``,
        data: exportData,
      };
    }

    return {
      success: true,
      output: `# Attack Surface Export (JSON)\n\n\`\`\`json\n${JSON.stringify(exportData, null, 2)}\n\`\`\``,
      data: exportData,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Export failed: ${error}`,
    };
  }
}

async function handleCompare(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const session1 = args[0];
  const session2 = args[1];

  if (!session1 || !session2) {
    return {
      success: false,
      output: '',
      error: 'Usage: surface compare <session1> <session2>',
    };
  }

  try {
    const client = getGraphClient();

    // Get node counts for each session
    const stats1 = await client.query<{ label: string; count: number }>(
      `MATCH (n {sessionId: $sessionId})
       RETURN labels(n)[0] as label, count(*) as count`,
      { sessionId: session1 }
    );

    const stats2 = await client.query<{ label: string; count: number }>(
      `MATCH (n {sessionId: $sessionId})
       RETURN labels(n)[0] as label, count(*) as count`,
      { sessionId: session2 }
    );

    // Find new nodes in session2
    const newNodes = await client.query<{ label: string; count: number }>(
      `MATCH (n {sessionId: $session2})
       WHERE NOT EXISTS {
         MATCH (m {sessionId: $session1})
         WHERE m.name = n.name OR m.address = n.address OR m.url = n.url
       }
       RETURN labels(n)[0] as label, count(*) as count`,
      { session1, session2 }
    );

    const lines = [
      '# Attack Surface Comparison\n',
      `**Session 1:** ${session1}`,
      `**Session 2:** ${session2}`,
      '',
      '## Node Counts',
      '',
      '| Type | Session 1 | Session 2 | Diff |',
      '|------|-----------|-----------|------|',
    ];

    const allLabels = new Set([
      ...stats1.map((s) => s.label),
      ...stats2.map((s) => s.label),
    ]);

    for (const label of allLabels) {
      const count1 = stats1.find((s) => s.label === label)?.count || 0;
      const count2 = stats2.find((s) => s.label === label)?.count || 0;
      const diff = count2 - count1;
      const diffStr = diff > 0 ? `+${diff}` : diff.toString();
      lines.push(`| ${label} | ${count1} | ${count2} | ${diffStr} |`);
    }

    if (newNodes.length > 0) {
      lines.push('', '## New Discoveries in Session 2', '');
      for (const node of newNodes) {
        lines.push(`- **${node.label}:** ${node.count} new`);
      }
    }

    return {
      success: true,
      output: lines.join('\n'),
      data: { session1: stats1, session2: stats2, newNodes },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Comparison failed: ${error}`,
    };
  }
}

async function handleSurfaceHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Attack Surface Skill

Build and query attack surface graphs using Neo4j.

## Commands

| Command | Description |
|---------|-------------|
| \`surface map <domain>\` | Start mapping attack surface for a domain |
| \`surface query <cypher>\` | Execute a Cypher query (read-only) |
| \`surface stats\` | Show graph statistics |
| \`surface visualize [session]\` | Visualize the attack surface |
| \`surface export [format] [session]\` | Export graph data (json/csv) |
| \`surface compare <s1> <s2>\` | Compare two sessions |

## Example Queries

\`\`\`cypher
# Find all subdomains
MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
RETURN d.name, s.name

# Find open ports
MATCH (ip:IPAddress)-[:HAS_PORT]->(p:Port {state: 'open'})
RETURN ip.address, p.number, p.protocol

# Find vulnerabilities by severity
MATCH (v:Vulnerability)
WHERE v.severity IN ['critical', 'high']
RETURN v.title, v.severity, v.cvssScore
ORDER BY v.cvssScore DESC

# Attack path analysis
MATCH path = (entry:Endpoint)-[*..5]->(vuln:Vulnerability)
RETURN path
\`\`\`

## Requirements

Neo4j must be running. Start with: \`docker-compose up neo4j\``,
  };
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'surface',
    description: 'Attack surface management (map, query, visualize)',
    usage: 'surface <subcommand>',
    execute: async (args, ctx) => {
      const subcommand = args[0];
      const subArgs = args.slice(1);

      switch (subcommand) {
        case 'map':
          return handleMap(subArgs, ctx);
        case 'query':
          return handleQuery(subArgs, ctx);
        case 'stats':
          return handleStats(subArgs, ctx);
        case 'visualize':
        case 'viz':
          return handleVisualize(subArgs, ctx);
        case 'export':
          return handleExport(subArgs, ctx);
        case 'compare':
        case 'diff':
          return handleCompare(subArgs, ctx);
        case 'help':
        default:
          return handleSurfaceHelp(subArgs, ctx);
      }
    },
  },
];

export const attackSurfaceSkill: Skill = {
  metadata: {
    id: 'attack-surface',
    name: 'Attack Surface',
    description: 'Build and query attack surface graphs using Neo4j',
    version: '1.0.0',
    author: 'Gideon',
    category: 'security-research',
    capabilities: {
      providesTools: false,
      requiresGpu: false,
      supportsCpuFallback: true,
      stateful: true,
      requiresExternalService: true,
    },
    requiredEnvVars: ['NEO4J_URI', 'NEO4J_USER', 'NEO4J_PASSWORD'],
  },

  commands,

  async isAvailable(): Promise<boolean> {
    try {
      const client = getGraphClient();
      await client.connect();
      return true;
    } catch {
      return false;
    }
  },

  async getStatus(): Promise<SkillStatus> {
    try {
      const client = getGraphClient();
      await client.connect();
      const stats = await client.getStats();

      return {
        healthy: true,
        message: `Connected. ${stats.nodeCount} nodes, ${stats.relationshipCount} relationships`,
        checkedAt: new Date(),
        details: stats,
      };
    } catch (error) {
      return {
        healthy: false,
        message: `Neo4j not available: ${error}`,
        checkedAt: new Date(),
      };
    }
  },

  async initialize(): Promise<void> {
    try {
      const client = await initializeGraph();
      await initializeSchema(client);
    } catch {
      // Neo4j not available, skill will show as unhealthy
    }
  },

  async shutdown(): Promise<void> {
    try {
      const client = getGraphClient();
      await client.disconnect();
    } catch {
      // Ignore shutdown errors
    }
  },
};
