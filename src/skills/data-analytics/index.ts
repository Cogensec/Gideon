/**
 * Data Analytics Skill
 *
 * GPU-accelerated data processing using NVIDIA RAPIDS.
 * Provides batch IOC analysis, event correlation, threat clustering,
 * network graph analysis, and anomaly detection.
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';

import {
  getRapidsConfig,
  runBatchIOCAnalysis,
  runEventCorrelation,
  runThreatClustering,
  runNetworkGraphAnalysis,
  runAnomalyDetection,
  RapidsResult,
} from '../../utils/rapids.js';

// ============================================================================
// Command Implementations
// ============================================================================

async function handleBatchIOC(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const filePath = args[0];

  if (!filePath) {
    return {
      success: false,
      output: '',
      error: 'Usage: batch-ioc <indicators-file>\nAnalyze multiple IOCs in parallel using GPU acceleration.',
    };
  }

  try {
    const result = await runBatchIOCAnalysis(filePath);
    return formatResult('Batch IOC Analysis', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Batch IOC analysis failed: ${error}`,
    };
  }
}

async function handleCorrelate(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const filePath = args[0];

  if (!filePath) {
    return {
      success: false,
      output: '',
      error: 'Usage: correlate <events-file>\nFind relationships between security events.',
    };
  }

  try {
    const result = await runEventCorrelation(filePath);
    return formatResult('Event Correlation', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Event correlation failed: ${error}`,
    };
  }
}

async function handleCluster(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const filePath = args[0];

  if (!filePath) {
    return {
      success: false,
      output: '',
      error: 'Usage: cluster <threats-file>\nGroup similar threats using ML clustering.',
    };
  }

  try {
    const result = await runThreatClustering(filePath);
    return formatResult('Threat Clustering', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Threat clustering failed: ${error}`,
    };
  }
}

async function handleGraph(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const filePath = args[0];

  if (!filePath) {
    return {
      success: false,
      output: '',
      error: 'Usage: graph <flows-file>\nAnalyze network flows and connections.',
    };
  }

  try {
    const result = await runNetworkGraphAnalysis(filePath);
    return formatResult('Network Graph Analysis', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Graph analysis failed: ${error}`,
    };
  }
}

async function handleAnomaly(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const filePath = args[0];

  if (!filePath) {
    return {
      success: false,
      output: '',
      error: 'Usage: anomaly <data-file>\nDetect statistical anomalies in security data.',
    };
  }

  try {
    const result = await runAnomalyDetection(filePath);
    return formatResult('Anomaly Detection', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Anomaly detection failed: ${error}`,
    };
  }
}

async function handleAnalyticsHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Data Analytics Skill

GPU-accelerated security data processing powered by NVIDIA RAPIDS.

## Commands

| Command | Description |
|---------|-------------|
| \`batch-ioc <file>\` | Parallel IOC analysis (cuDF) |
| \`correlate <file>\` | Event correlation (cuGraph) |
| \`cluster <file>\` | Threat clustering (cuML) |
| \`graph <file>\` | Network flow analysis (cuGraph) |
| \`anomaly <file>\` | Statistical anomaly detection (cuML) |

## Performance
- 60-100x speedup over CPU processing
- Handles millions of records in seconds
- GPU memory optimized for large datasets

## RAPIDS Components
- **cuDF**: GPU DataFrames for data manipulation
- **cuML**: GPU Machine Learning algorithms
- **cuGraph**: GPU Graph Analytics

## Requirements
- NVIDIA RAPIDS service (RAPIDS_URL)
- GPU recommended, CPU fallback available`,
  };
}

function formatResult(title: string, result: RapidsResult): SkillCommandResult {
  if (!result.success) {
    return {
      success: false,
      output: '',
      error: result.error || 'Analysis failed',
    };
  }

  const lines = [
    `# ${title} Results\n`,
    `**Status:** Complete`,
    `**Processing Time:** ${result.processingTime || 'N/A'}`,
    `**Records Processed:** ${result.recordCount || 'N/A'}`,
    '',
  ];

  if (result.summary) {
    lines.push('## Summary\n');
    lines.push(result.summary);
    lines.push('');
  }

  if (result.highlights?.length) {
    lines.push('## Key Findings\n');
    for (const highlight of result.highlights) {
      lines.push(`- ${highlight}`);
    }
    lines.push('');
  }

  return {
    success: true,
    output: lines.join('\n'),
    data: result,
  };
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'batch-ioc',
    description: 'Analyze multiple IOCs in parallel',
    usage: 'batch-ioc <indicators-file>',
    execute: handleBatchIOC,
  },
  {
    name: 'correlate',
    description: 'Find relationships between security events',
    usage: 'correlate <events-file>',
    execute: handleCorrelate,
  },
  {
    name: 'cluster',
    description: 'Group similar threats using ML',
    usage: 'cluster <threats-file>',
    execute: handleCluster,
  },
  {
    name: 'graph',
    description: 'Analyze network flows and connections',
    usage: 'graph <flows-file>',
    execute: handleGraph,
  },
  {
    name: 'anomaly',
    description: 'Detect statistical anomalies',
    usage: 'anomaly <data-file>',
    execute: handleAnomaly,
  },
  {
    name: 'analytics-help',
    description: 'Show data analytics help',
    usage: 'analytics-help',
    execute: handleAnalyticsHelp,
  },
];

export const dataAnalyticsSkill: Skill = {
  metadata: {
    id: 'data-analytics',
    name: 'Data Analytics',
    description: 'GPU-accelerated security data processing using NVIDIA RAPIDS',
    version: '1.0.0',
    author: 'Gideon',
    category: 'data-analytics',
    capabilities: {
      providesTools: false,
      requiresGpu: true,
      supportsCpuFallback: true,
      stateful: false,
      requiresExternalService: true,
    },
    optionalEnvVars: ['RAPIDS_URL'],
  },

  commands,

  async isAvailable(): Promise<boolean> {
    const config = getRapidsConfig();
    if (!config.enabled) return false;

    try {
      const response = await fetch(`${config.url}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return true; // Skill provides guidance even without service
    }
  },

  async getStatus(): Promise<SkillStatus> {
    const config = getRapidsConfig();

    if (!config.enabled) {
      return {
        healthy: false,
        message: 'RAPIDS integration disabled',
        checkedAt: new Date(),
      };
    }

    try {
      const response = await fetch(`${config.url}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      return {
        healthy: response.ok,
        message: response.ok ? 'RAPIDS service available' : 'RAPIDS service unhealthy',
        checkedAt: new Date(),
        details: { url: config.url },
      };
    } catch (error) {
      return {
        healthy: false,
        message: `RAPIDS service unavailable: ${error}`,
        checkedAt: new Date(),
        details: { url: config.url },
      };
    }
  },
};
