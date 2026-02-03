import { CommandContext, CommandResult } from './types.js';
import {
  isMorpheusAvailable,
  getMorpheusConfig,
  analyzeWithDFP,
  detectDGA,
  detectPhishing,
  detectRansomware,
  runFullAnalysis,
  type MorpheusAnalysisResult,
} from '../utils/morpheus.js';
import * as fs from 'fs';

export interface AnalyzeCommandOptions {
  type?: 'dfp' | 'dga' | 'phishing' | 'ransomware' | 'all';
  logs?: string;
  domains?: string;
  email?: string;
  events?: string;
  output?: 'json' | 'markdown';
}

/**
 * Parse analyze command arguments
 */
function parseArgs(args: string[]): AnalyzeCommandOptions {
  const options: AnalyzeCommandOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--type' && args[i + 1]) {
      options.type = args[i + 1] as AnalyzeCommandOptions['type'];
      i++;
    } else if (arg === '--logs' && args[i + 1]) {
      options.logs = args[i + 1];
      i++;
    } else if (arg === '--domains' && args[i + 1]) {
      options.domains = args[i + 1];
      i++;
    } else if (arg === '--email' && args[i + 1]) {
      options.email = args[i + 1];
      i++;
    } else if (arg === '--events' && args[i + 1]) {
      options.events = args[i + 1];
      i++;
    } else if (arg === '--output' && args[i + 1]) {
      options.output = args[i + 1] as 'json' | 'markdown';
      i++;
    } else if (arg === '--all') {
      options.type = 'all';
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
 * Format analysis result as markdown
 */
function formatResultAsMarkdown(result: MorpheusAnalysisResult): string {
  let output = `## ${result.pipeline.replace(/_/g, ' ').toUpperCase()} Analysis\n\n`;
  output += `**Status:** ${result.status}\n`;
  output += `**Processing Time:** ${result.processingTimeMs}ms\n`;
  output += `**Records Processed:** ${result.recordsProcessed}\n`;
  output += `**Threats Detected:** ${result.threatsDetected}\n\n`;

  output += `### Summary\n${result.summary}\n\n`;

  if (result.anomalies.length > 0) {
    output += `### Detected Anomalies\n\n`;
    for (const anomaly of result.anomalies) {
      output += `- **[${anomaly.severity.toUpperCase()}]** ${anomaly.description}\n`;
      output += `  - Confidence: ${(anomaly.confidence * 100).toFixed(1)}%\n`;
      output += `  - Type: ${anomaly.type}\n`;
      output += `  - Time: ${anomaly.timestamp}\n\n`;
    }
  }

  if (result.recommendations.length > 0) {
    output += `### Recommendations\n\n`;
    for (const rec of result.recommendations) {
      output += `- ${rec}\n`;
    }
  }

  return output;
}

/**
 * Analyze command - Run Morpheus AI threat detection pipelines
 *
 * Usage:
 *   gideon analyze --logs ./cloudtrail.json --type dfp
 *   gideon analyze --domains domains.txt --type dga
 *   gideon analyze --email suspicious.eml --type phishing
 *   gideon analyze --events ./events.json --type ransomware
 *   gideon analyze --logs ./logs.json --all
 */
export async function analyzeCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const options = parseArgs(args);

  // Show help if no arguments
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    return {
      success: true,
      output: `
Morpheus AI Threat Analysis

USAGE:
  gideon analyze [OPTIONS]

OPTIONS:
  --type <type>     Analysis type: dfp, dga, phishing, ransomware, all
  --logs <file>     Log file for DFP/ransomware analysis (JSON/JSONL)
  --domains <file>  Domain list for DGA detection (one per line)
  --email <file>    Email file for phishing detection (.eml or text)
  --events <file>   Event log for ransomware detection (JSON)
  --output <fmt>    Output format: json, markdown (default: markdown)
  --all             Run all applicable pipelines

EXAMPLES:
  gideon analyze --logs cloudtrail.json --type dfp
  gideon analyze --domains suspicious-domains.txt --type dga
  gideon analyze --email phishing.eml --type phishing
  gideon analyze --events appshield.json --type ransomware

PIPELINES:
  dfp         Digital Fingerprinting - Detect anomalous user behavior
  dga         DGA Detection - Identify malware domain generation
  phishing    Phishing Detection - NLP-based email analysis
  ransomware  Ransomware Detection - Behavioral pattern detection
`,
    };
  }

  // Check if Morpheus is available
  const available = await isMorpheusAvailable();
  if (!available) {
    const config = getMorpheusConfig();
    return {
      success: false,
      output: '',
      error: `Morpheus server not available at ${config.serverUrl}

To start Morpheus:
  1. Pull the container: docker pull nvcr.io/nvidia/morpheus/morpheus
  2. Run: docker run -p 8080:8080 nvcr.io/nvidia/morpheus/morpheus

Or set MORPHEUS_URL in .env to point to your Morpheus server.`,
    };
  }

  // Determine analysis type
  const analysisType = options.type || 'all';
  let output = '';
  const artifacts: Record<string, unknown> = {};

  try {
    if (analysisType === 'all') {
      // Run full analysis with all available data
      const data: {
        logs?: string;
        domains?: string[];
        email?: string;
        events?: string;
      } = {};

      if (options.logs) {
        const content = readFileContent(options.logs);
        if (content) data.logs = content;
      }

      if (options.domains) {
        const content = readFileContent(options.domains);
        if (content) data.domains = content.split('\n').filter(d => d.trim());
      }

      if (options.email) {
        const content = readFileContent(options.email);
        if (content) data.email = content;
      }

      if (options.events) {
        const content = readFileContent(options.events);
        if (content) data.events = content;
      }

      if (Object.keys(data).length === 0) {
        return {
          success: false,
          output: '',
          error: 'No input files provided. Use --logs, --domains, --email, or --events.',
        };
      }

      const results = await runFullAnalysis(data);

      output = `# Morpheus Full Threat Analysis\n\n`;
      output += `**Total Threats Detected:** ${results.totalThreats}\n`;
      output += `**Summary:** ${results.summary}\n\n`;

      if (results.dfp) {
        output += formatResultAsMarkdown(results.dfp);
        artifacts.dfp = results.dfp;
      }
      if (results.dga) {
        output += formatResultAsMarkdown(results.dga);
        artifacts.dga = results.dga;
      }
      if (results.phishing) {
        output += formatResultAsMarkdown(results.phishing);
        artifacts.phishing = results.phishing;
      }
      if (results.ransomware) {
        output += formatResultAsMarkdown(results.ransomware);
        artifacts.ransomware = results.ransomware;
      }

    } else if (analysisType === 'dfp') {
      if (!options.logs) {
        return { success: false, output: '', error: 'DFP analysis requires --logs <file>' };
      }
      const content = readFileContent(options.logs);
      if (!content) {
        return { success: false, output: '', error: `Cannot read file: ${options.logs}` };
      }

      const result = await analyzeWithDFP(content);
      output = formatResultAsMarkdown(result);
      artifacts.dfp = result;

    } else if (analysisType === 'dga') {
      if (!options.domains) {
        return { success: false, output: '', error: 'DGA detection requires --domains <file>' };
      }
      const content = readFileContent(options.domains);
      if (!content) {
        return { success: false, output: '', error: `Cannot read file: ${options.domains}` };
      }

      const domains = content.split('\n').filter(d => d.trim());
      const result = await detectDGA(domains);
      output = formatResultAsMarkdown(result);
      artifacts.dga = result;

    } else if (analysisType === 'phishing') {
      if (!options.email) {
        return { success: false, output: '', error: 'Phishing detection requires --email <file>' };
      }
      const content = readFileContent(options.email);
      if (!content) {
        return { success: false, output: '', error: `Cannot read file: ${options.email}` };
      }

      const result = await detectPhishing(content);
      output = formatResultAsMarkdown(result);
      artifacts.phishing = result;

    } else if (analysisType === 'ransomware') {
      if (!options.events && !options.logs) {
        return { success: false, output: '', error: 'Ransomware detection requires --events <file> or --logs <file>' };
      }
      const filePath = options.events || options.logs!;
      const content = readFileContent(filePath);
      if (!content) {
        return { success: false, output: '', error: `Cannot read file: ${filePath}` };
      }

      const result = await detectRansomware(content);
      output = formatResultAsMarkdown(result);
      artifacts.ransomware = result;

    } else {
      return {
        success: false,
        output: '',
        error: `Unknown analysis type: ${analysisType}. Use: dfp, dga, phishing, ransomware, or all`,
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
