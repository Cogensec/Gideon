import { CommandContext, CommandResult } from './types.js';
import {
  isRapidsAvailable,
  getRapidsConfig,
  getRapidsCapabilities,
  batchAnalyzeIOCs,
  correlateEvents,
  clusterThreats,
  analyzeNetworkGraph,
  detectAnomalies,
  type RapidsResult,
} from '../utils/rapids.js';
import * as fs from 'fs';

export interface RapidsCommandOptions {
  operation?: 'batch-ioc' | 'correlate' | 'cluster' | 'graph' | 'anomaly' | 'status';
  input?: string;
  output?: 'json' | 'markdown';
  algorithm?: string;
}

/**
 * Parse rapids command arguments
 */
function parseArgs(args: string[]): RapidsCommandOptions {
  const options: RapidsCommandOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--batch-ioc') {
      options.operation = 'batch-ioc';
      if (args[i + 1] && !args[i + 1].startsWith('--')) {
        options.input = args[i + 1];
        i++;
      }
    } else if (arg === '--correlate') {
      options.operation = 'correlate';
      if (args[i + 1] && !args[i + 1].startsWith('--')) {
        options.input = args[i + 1];
        i++;
      }
    } else if (arg === '--cluster') {
      options.operation = 'cluster';
      if (args[i + 1] && !args[i + 1].startsWith('--')) {
        options.input = args[i + 1];
        i++;
      }
    } else if (arg === '--graph') {
      options.operation = 'graph';
      if (args[i + 1] && !args[i + 1].startsWith('--')) {
        options.input = args[i + 1];
        i++;
      }
    } else if (arg === '--anomaly') {
      options.operation = 'anomaly';
      if (args[i + 1] && !args[i + 1].startsWith('--')) {
        options.input = args[i + 1];
        i++;
      }
    } else if (arg === '--status') {
      options.operation = 'status';
    } else if (arg === '--input' && args[i + 1]) {
      options.input = args[i + 1];
      i++;
    } else if (arg === '--output' && args[i + 1]) {
      options.output = args[i + 1] as 'json' | 'markdown';
      i++;
    } else if (arg === '--algorithm' && args[i + 1]) {
      options.algorithm = args[i + 1];
      i++;
    }
  }

  return options;
}

/**
 * Read file content safely
 */
function readFileContent(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Format result as markdown
 */
function formatResultAsMarkdown(result: RapidsResult & Record<string, unknown>, title: string): string {
  let output = `## ${title}\n\n`;
  output += `**Status:** ${result.status}\n`;
  output += `**Processing Time:** ${result.processingTimeMs}ms\n`;
  output += `**Records Processed:** ${result.recordsProcessed}\n`;
  output += `**GPU Accelerated:** ${result.gpuAccelerated ? 'Yes' : 'No'}\n`;
  if (result.gpuMemoryUsedMB) {
    output += `**GPU Memory Used:** ${result.gpuMemoryUsedMB}MB\n`;
  }
  output += '\n';

  if (result.summary) {
    output += `### Summary\n${result.summary}\n\n`;
  }

  return output;
}

/**
 * RAPIDS command - GPU-accelerated data processing for security analytics
 *
 * Usage:
 *   gideon rapids --status                        Check RAPIDS server status
 *   gideon rapids --batch-ioc indicators.csv      Batch analyze IOCs
 *   gideon rapids --correlate events.json         Correlate security events
 *   gideon rapids --cluster threats.json          Cluster similar threats
 *   gideon rapids --graph flows.json              Analyze network graph
 *   gideon rapids --anomaly data.json             Detect anomalies
 */
export async function rapidsCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const options = parseArgs(args);

  // Show help if no arguments
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    return {
      success: true,
      output: `
NVIDIA RAPIDS GPU-Accelerated Data Processing

USAGE:
  gideon rapids [OPTIONS]

OPERATIONS:
  --status                    Check RAPIDS server status and GPU capabilities
  --batch-ioc <file>          Batch analyze IOCs with GPU acceleration (cuDF)
  --correlate <file>          Correlate events into attack chains (cuGraph)
  --cluster <file>            Cluster similar threats (cuML)
  --graph <file>              Analyze network graph for lateral movement (cuGraph)
  --anomaly <file>            Detect anomalies in security data (cuML)

OPTIONS:
  --input <file>              Input file (alternative to inline)
  --output <fmt>              Output format: json, markdown (default: markdown)
  --algorithm <algo>          ML algorithm for clustering/anomaly detection

EXAMPLES:
  gideon rapids --status
  gideon rapids --batch-ioc indicators.csv
  gideon rapids --correlate cloudtrail-events.json
  gideon rapids --cluster threat-intel.json --algorithm hdbscan
  gideon rapids --graph network-flows.json
  gideon rapids --anomaly auth-logs.json --algorithm isolation_forest

PERFORMANCE:
  Batch IOC:     60x faster than CPU (100K IOCs in ~30s)
  Correlation:   100x faster (graph algorithms)
  Clustering:    100x faster (HDBSCAN/DBSCAN)
  Graph:         100x faster (PageRank, BFS, shortest paths)
`,
    };
  }

  // Check status
  if (options.operation === 'status') {
    const available = await isRapidsAvailable();
    const config = getRapidsConfig();

    if (!available) {
      return {
        success: true,
        output: `RAPIDS Server Status: OFFLINE

Server URL: ${config.serverUrl}

To start RAPIDS server:
  docker pull nvcr.io/nvidia/rapidsai/rapidsai
  docker run --gpus all -p 8090:8090 nvcr.io/nvidia/rapidsai/rapidsai

Or set RAPIDS_URL in .env to point to your RAPIDS server.`,
      };
    }

    const capabilities = await getRapidsCapabilities();
    let output = `RAPIDS Server Status: ONLINE\n\n`;
    output += `Server URL: ${config.serverUrl}\n`;
    output += `GPU Available: ${capabilities.gpuAvailable ? 'Yes' : 'No'}\n`;
    if (capabilities.gpuName) {
      output += `GPU Name: ${capabilities.gpuName}\n`;
    }
    if (capabilities.gpuMemoryGB) {
      output += `GPU Memory: ${capabilities.gpuMemoryGB}GB\n`;
    }
    output += `\nAvailable Libraries:\n`;
    for (const lib of capabilities.libraries) {
      output += `  - ${lib}\n`;
    }

    return { success: true, output };
  }

  // Check if RAPIDS is available for other operations
  const available = await isRapidsAvailable();
  if (!available) {
    const config = getRapidsConfig();
    return {
      success: false,
      output: '',
      error: `RAPIDS server not available at ${config.serverUrl}

To start RAPIDS server:
  docker pull nvcr.io/nvidia/rapidsai/rapidsai
  docker run --gpus all -p 8090:8090 nvcr.io/nvidia/rapidsai/rapidsai

Or set RAPIDS_URL in .env to point to your RAPIDS server.`,
    };
  }

  // Validate input file for operations that need it
  if (!options.input && options.operation !== 'status') {
    return {
      success: false,
      output: '',
      error: `Operation --${options.operation} requires an input file. Use --input <file> or provide file directly.`,
    };
  }

  const inputContent = options.input ? readFileContent(options.input) : null;
  if (options.input && !inputContent) {
    return {
      success: false,
      output: '',
      error: `Cannot read file: ${options.input}`,
    };
  }

  let output = '';
  const artifacts: Record<string, unknown> = {};

  try {
    switch (options.operation) {
      case 'batch-ioc': {
        // Parse indicators from file (one per line or CSV)
        const indicators = inputContent!
          .split('\n')
          .map(line => line.split(',')[0].trim())
          .filter(i => i.length > 0);

        const result = await batchAnalyzeIOCs(indicators);
        output = formatResultAsMarkdown(result as RapidsResult & Record<string, unknown>, 'Batch IOC Analysis');

        if (result.topThreats.length > 0) {
          output += `### Top Threats\n\n`;
          for (const threat of result.topThreats) {
            output += `- **${threat.indicator}** (${threat.type})\n`;
            output += `  - Confidence: ${(threat.confidence * 100).toFixed(1)}%\n`;
            output += `  - Sources: ${threat.sources.join(', ')}\n`;
            if (threat.tags && threat.tags.length > 0) {
              output += `  - Tags: ${threat.tags.join(', ')}\n`;
            }
            output += '\n';
          }
        }

        artifacts.batchIoc = result;
        break;
      }

      case 'correlate': {
        const result = await correlateEvents(inputContent!);
        output = formatResultAsMarkdown(result as RapidsResult & Record<string, unknown>, 'Event Correlation');

        if (result.correlations.length > 0) {
          output += `### Attack Chains Detected\n\n`;
          for (const chain of result.correlations.slice(0, 10)) {
            output += `#### Chain ${chain.chainId}\n`;
            output += `- Pattern: ${chain.attackPattern || 'Unknown'}\n`;
            output += `- Confidence: ${(chain.confidence * 100).toFixed(1)}%\n`;
            output += `- Events: ${chain.events.length}\n`;
            if (chain.mitreAttackIds && chain.mitreAttackIds.length > 0) {
              output += `- MITRE ATT&CK: ${chain.mitreAttackIds.join(', ')}\n`;
            }
            output += '\n';
          }
        }

        if (result.recommendations.length > 0) {
          output += `### Recommendations\n\n`;
          for (const rec of result.recommendations) {
            output += `- ${rec}\n`;
          }
        }

        artifacts.correlation = result;
        break;
      }

      case 'cluster': {
        const result = await clusterThreats(inputContent!, {
          algorithm: options.algorithm as 'dbscan' | 'hdbscan' | 'kmeans' | undefined,
        });
        output = formatResultAsMarkdown(result as RapidsResult & Record<string, unknown>, 'Threat Clustering');

        if (result.clusters.length > 0) {
          output += `### Clusters Found\n\n`;
          for (const cluster of result.clusters) {
            output += `#### Cluster ${cluster.clusterId} (${cluster.threatLevel.toUpperCase()})\n`;
            output += `- Size: ${cluster.size} threats\n`;
            output += `- Common Attributes:\n`;
            for (const [key, value] of Object.entries(cluster.commonAttributes)) {
              output += `  - ${key}: ${value}\n`;
            }
            output += '\n';
          }
        }

        artifacts.cluster = result;
        break;
      }

      case 'graph': {
        const result = await analyzeNetworkGraph(inputContent!);
        output = formatResultAsMarkdown(result as RapidsResult & Record<string, unknown>, 'Network Graph Analysis');

        if (result.lateralMovementPaths.length > 0) {
          output += `### Lateral Movement Paths\n\n`;
          for (const path of result.lateralMovementPaths.slice(0, 10)) {
            output += `#### Path ${path.pathId}\n`;
            output += `- Risk: ${(path.risk * 100).toFixed(1)}%\n`;
            output += `- Hops: ${path.hops}\n`;
            output += `- Entry Point: ${path.entryPoint}\n`;
            output += `- Targets: ${path.targets.join(', ')}\n`;
            output += `- Route: ${path.nodes.join(' → ')}\n\n`;
          }
        }

        if (result.centralNodes.length > 0) {
          output += `### High-Risk Central Nodes\n\n`;
          for (const node of result.centralNodes.slice(0, 10)) {
            output += `- **${node.id}** (${node.type})\n`;
            output += `  - Risk: ${(node.risk * 100).toFixed(1)}%\n`;
            output += `  - Connections: ${node.connections}\n`;
          }
        }

        if (result.recommendations.length > 0) {
          output += `\n### Recommendations\n\n`;
          for (const rec of result.recommendations) {
            output += `- ${rec}\n`;
          }
        }

        artifacts.graph = result;
        break;
      }

      case 'anomaly': {
        const result = await detectAnomalies(inputContent!, {
          method: options.algorithm as 'isolation_forest' | 'local_outlier_factor' | 'autoencoder' | undefined,
        });
        output = formatResultAsMarkdown(result as RapidsResult & Record<string, unknown>, 'Anomaly Detection');

        if (result.anomalies.length > 0) {
          output += `### Detected Anomalies\n\n`;
          for (const anomaly of result.anomalies.slice(0, 20)) {
            output += `- **${anomaly.id}** (Score: ${anomaly.score.toFixed(3)})\n`;
            output += `  - ${anomaly.description}\n`;
          }
        }

        artifacts.anomaly = result;
        break;
      }

      default:
        return {
          success: false,
          output: '',
          error: `Unknown operation. Use --help for usage information.`,
        };
    }

    // Format output
    if (options.output === 'json') {
      output = JSON.stringify(artifacts, null, 2);
    }

    return {
      success: true,
      output,
      artifacts: { json: artifacts },
    };

  } catch (error) {
    return {
      success: false,
      output: '',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
