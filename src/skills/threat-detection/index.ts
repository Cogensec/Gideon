/**
 * Threat Detection Skill
 *
 * GPU-accelerated threat detection using NVIDIA Morpheus.
 * Provides Digital Fingerprinting, DGA, Phishing, and Ransomware detection.
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';

import {
  getMorpheusConfig,
  analyzeWithDFP,
  detectDGA,
  detectPhishing,
  detectRansomware,
  MorpheusAnalysisResult,
} from '../../utils/morpheus.js';

// ============================================================================
// Command Implementations
// ============================================================================

async function handleDFP(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const logsPath = args[0];

  if (!logsPath) {
    return {
      success: false,
      output: '',
      error: 'Usage: dfp <logs-file>\nAnalyze user behavior for anomalies using Digital Fingerprinting.',
    };
  }

  try {
    const result = await analyzeWithDFP(logsPath);
    return formatResult('Digital Fingerprinting', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `DFP analysis failed: ${error}`,
    };
  }
}

async function handleDGA(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const domainsPath = args[0];

  if (!domainsPath) {
    return {
      success: false,
      output: '',
      error: 'Usage: dga <domains-file>\nDetect algorithmically generated domains.',
    };
  }

  try {
    const result = await detectDGA([domainsPath]);
    return formatResult('DGA Detection', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `DGA detection failed: ${error}`,
    };
  }
}

async function handlePhishing(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const emailPath = args[0];

  if (!emailPath) {
    return {
      success: false,
      output: '',
      error: 'Usage: phishing <email-file>\nDetect phishing attempts in emails.',
    };
  }

  try {
    const result = await detectPhishing(emailPath);
    return formatResult('Phishing Detection', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Phishing detection failed: ${error}`,
    };
  }
}

async function handleRansomware(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const eventsPath = args[0];

  if (!eventsPath) {
    return {
      success: false,
      output: '',
      error: 'Usage: ransomware <events-file>\nDetect ransomware behavioral patterns.',
    };
  }

  try {
    const result = await detectRansomware(eventsPath);
    return formatResult('Ransomware Detection', result);
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Ransomware detection failed: ${error}`,
    };
  }
}

async function handleDetectAll(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const dataPath = args[0];

  if (!dataPath) {
    return {
      success: false,
      output: '',
      error: 'Usage: detect-all <data-file>\nRun all detection pipelines on input data.',
    };
  }

  const results: string[] = ['# Comprehensive Threat Detection\n'];

  // Run all pipelines
  const pipelines = [
    { name: 'DFP', fn: (p: string) => analyzeWithDFP(p) },
    { name: 'DGA', fn: (p: string) => detectDGA([p]) },
    { name: 'Phishing', fn: (p: string) => detectPhishing(p) },
    { name: 'Ransomware', fn: (p: string) => detectRansomware(p) },
  ];

  for (const pipeline of pipelines) {
    try {
      const result = await pipeline.fn(dataPath);
      results.push(`## ${pipeline.name}\n`);
      results.push(`- **Status:** ${result.status === 'success' ? 'Complete' : 'Failed'}`);
      results.push(`- **Threats Found:** ${result.threatsDetected || 0}`);
      if (result.anomalies?.length) {
        results.push(`- **Highest Severity:** ${getHighestSeverity(result.anomalies)}`);
      }
      results.push('');
    } catch (error) {
      results.push(`## ${pipeline.name}\n`);
      results.push(`- **Status:** Error - ${error}\n`);
    }
  }

  return {
    success: true,
    output: results.join('\n'),
  };
}

async function handleThreatHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Threat Detection Skill

GPU-accelerated threat detection powered by NVIDIA Morpheus.

## Commands

| Command | Description |
|---------|-------------|
| \`dfp <logs>\` | Digital Fingerprinting - User behavior anomalies |
| \`dga <domains>\` | DGA Detection - Malware domain identification |
| \`phishing <email>\` | Phishing Detection - Email threat analysis |
| \`ransomware <events>\` | Ransomware Detection - Behavioral patterns |
| \`detect-all <data>\` | Run all detection pipelines |

## Performance
- 208,333+ logs/second with GPU acceleration
- 99%+ accuracy on phishing detection
- Real-time streaming support

## Requirements
- NVIDIA Morpheus service (MORPHEUS_URL)
- GPU recommended, CPU fallback available`,
  };
}

function formatResult(title: string, result: MorpheusAnalysisResult): SkillCommandResult {
  if (result.status === 'error') {
    return {
      success: false,
      output: '',
      error: result.summary || 'Analysis failed',
    };
  }

  const lines = [
    `# ${title} Results\n`,
    `**Status:** Complete`,
    `**Processing Time:** ${result.processingTimeMs || 'N/A'}ms`,
    `**Threats Found:** ${result.threatsDetected || 0}`,
    '',
  ];

  if (result.anomalies?.length) {
    lines.push('## Detected Threats\n');
    for (const threat of result.anomalies) {
      lines.push(`### ${threat.type || 'Unknown'}`);
      lines.push(`- **Severity:** ${threat.severity || 'Unknown'}`);
      lines.push(`- **Confidence:** ${(threat.confidence * 100).toFixed(1)}%`);
      if (threat.description) {
        lines.push(`- **Description:** ${threat.description}`);
      }
      lines.push('');
    }
  }

  return {
    success: true,
    output: lines.join('\n'),
    data: result,
  };
}

function getHighestSeverity(threats: Array<{ severity?: string }>): string {
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrder) {
    if (threats.some(t => t.severity?.toLowerCase() === sev)) {
      return sev.charAt(0).toUpperCase() + sev.slice(1);
    }
  }
  return 'Unknown';
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'dfp',
    description: 'Digital Fingerprinting - Detect user behavior anomalies',
    usage: 'dfp <logs-file>',
    execute: handleDFP,
  },
  {
    name: 'dga',
    description: 'Detect algorithmically generated domains',
    usage: 'dga <domains-file>',
    execute: handleDGA,
  },
  {
    name: 'phishing',
    description: 'Detect phishing attempts in emails',
    usage: 'phishing <email-file>',
    execute: handlePhishing,
  },
  {
    name: 'ransomware',
    description: 'Detect ransomware behavioral patterns',
    usage: 'ransomware <events-file>',
    execute: handleRansomware,
  },
  {
    name: 'detect-all',
    description: 'Run all threat detection pipelines',
    usage: 'detect-all <data-file>',
    execute: handleDetectAll,
  },
  {
    name: 'threat-help',
    description: 'Show threat detection help',
    usage: 'threat-help',
    execute: handleThreatHelp,
  },
];

export const threatDetectionSkill: Skill = {
  metadata: {
    id: 'threat-detection',
    name: 'Threat Detection',
    description: 'GPU-accelerated threat detection using NVIDIA Morpheus',
    version: '1.2.0',
    author: 'Gideon',
    category: 'threat-detection',
    capabilities: {
      providesTools: false,
      requiresGpu: true,
      supportsCpuFallback: true,
      stateful: false,
      requiresExternalService: true,
    },
    optionalEnvVars: ['MORPHEUS_URL'],
  },

  commands,

  async isAvailable(): Promise<boolean> {
    const config = getMorpheusConfig();
    if (!config.enabled) return false;

    try {
      const response = await fetch(`${config.serverUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      // Service not available, but skill can still provide guidance
      return true;
    }
  },

  async getStatus(): Promise<SkillStatus> {
    const config = getMorpheusConfig();

    if (!config.enabled) {
      return {
        healthy: false,
        message: 'Morpheus integration disabled',
        checkedAt: new Date(),
      };
    }

    try {
      const response = await fetch(`${config.serverUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      return {
        healthy: response.ok,
        message: response.ok ? 'Morpheus service available' : 'Morpheus service unhealthy',
        checkedAt: new Date(),
        details: { url: config.serverUrl },
      };
    } catch (error) {
      return {
        healthy: false,
        message: `Morpheus service unavailable: ${error}`,
        checkedAt: new Date(),
        details: { url: config.serverUrl },
      };
    }
  },
};
