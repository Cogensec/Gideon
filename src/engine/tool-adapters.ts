/**
 * Tool Adapters
 *
 * Adapters that translate structured inputs into CLI commands
 * and parse raw tool output into structured findings.
 */

import type { ToolAdapter, ExecutionFinding } from './types.js';

// ============================================================================
// Nmap Adapter
// ============================================================================

export const nmapAdapter: ToolAdapter = {
  name: 'nmap',
  defaultTimeoutMs: 120_000,

  buildCommand(input: Record<string, unknown>): string {
    const target = input.target as string;
    const scanType = (input.scanType as string) || 'syn';
    const ports = input.ports as string | undefined;
    const scripts = input.scripts as string | undefined;
    const timing = (input.timing as string) || 'T3';

    const args: string[] = ['nmap'];

    // Scan type
    switch (scanType) {
      case 'syn': args.push('-sS'); break;
      case 'connect': args.push('-sT'); break;
      case 'udp': args.push('-sU'); break;
      case 'version': args.push('-sV'); break;
      case 'aggressive': args.push('-A'); break;
      default: args.push('-sS');
    }

    // Timing
    args.push(`-${timing}`);

    // Ports
    if (ports) {
      args.push('-p', ports);
    }

    // NSE scripts
    if (scripts) {
      args.push('--script', scripts);
    }

    // Output as XML for structured parsing
    args.push('-oX', '-');

    // Target
    args.push(target);

    return args.join(' ');
  },

  parseOutput(output: string): ExecutionFinding[] {
    const findings: ExecutionFinding[] = [];

    // Parse open ports from nmap output
    const portRegex = /(\d+)\/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.*))?/g;
    let match;

    while ((match = portRegex.exec(output)) !== null) {
      const [, port, protocol, state, service, version] = match;
      findings.push({
        type: 'port',
        severity: 'info',
        title: `Open port ${port}/${protocol}`,
        description: `Service: ${service}${version ? ` (${version.trim()})` : ''}`,
        target: '',
        evidence: match[0],
        metadata: {
          port: parseInt(port, 10),
          protocol,
          state,
          service,
          version: version?.trim(),
        },
      });
    }

    // Parse host status
    const hostUpRegex = /Host is up \(([^)]+)\)/;
    const hostMatch = hostUpRegex.exec(output);
    if (hostMatch) {
      findings.push({
        type: 'host',
        severity: 'info',
        title: 'Host is up',
        description: `Latency: ${hostMatch[1]}`,
        target: '',
        evidence: hostMatch[0],
        metadata: { latency: hostMatch[1] },
      });
    }

    return findings;
  },

  validateInput(input: Record<string, unknown>): { valid: boolean; error?: string } {
    if (!input.target || typeof input.target !== 'string') {
      return { valid: false, error: 'Target is required' };
    }
    return { valid: true };
  },
};

// ============================================================================
// Nuclei Adapter
// ============================================================================

export const nucleiAdapter: ToolAdapter = {
  name: 'nuclei',
  defaultTimeoutMs: 300_000,

  buildCommand(input: Record<string, unknown>): string {
    const target = input.target as string;
    const templates = input.templates as string | undefined;
    const severity = input.severity as string | undefined;
    const tags = input.tags as string | undefined;

    const args: string[] = ['nuclei', '-u', target];

    if (templates) {
      args.push('-t', templates);
    }

    if (severity) {
      args.push('-severity', severity);
    }

    if (tags) {
      args.push('-tags', tags);
    }

    // JSON output for parsing
    args.push('-jsonl');

    return args.join(' ');
  },

  parseOutput(output: string): ExecutionFinding[] {
    const findings: ExecutionFinding[] = [];

    for (const line of output.split('\n')) {
      if (!line.trim()) continue;

      try {
        const result = JSON.parse(line);
        const severityMap: Record<string, ExecutionFinding['severity']> = {
          critical: 'critical',
          high: 'high',
          medium: 'medium',
          low: 'low',
          info: 'info',
        };

        findings.push({
          type: 'vulnerability',
          severity: severityMap[result.info?.severity?.toLowerCase()] || 'info',
          title: result.info?.name || result['template-id'] || 'Unknown finding',
          description: result.info?.description || '',
          target: result.host || result.matched || '',
          evidence: result['matched-at'] || result.curl || line,
          metadata: {
            templateId: result['template-id'],
            matcherName: result['matcher-name'],
            extractedResults: result['extracted-results'],
            reference: result.info?.reference,
            tags: result.info?.tags,
          },
        });
      } catch {
        // Non-JSON output line, skip
      }
    }

    return findings;
  },

  validateInput(input: Record<string, unknown>): { valid: boolean; error?: string } {
    if (!input.target || typeof input.target !== 'string') {
      return { valid: false, error: 'Target URL is required' };
    }
    return { valid: true };
  },
};

// ============================================================================
// SQLMap Adapter
// ============================================================================

export const sqlmapAdapter: ToolAdapter = {
  name: 'sqlmap',
  defaultTimeoutMs: 600_000,

  buildCommand(input: Record<string, unknown>): string {
    const target = input.target as string;
    const parameter = input.parameter as string | undefined;
    const technique = input.technique as string | undefined;
    const level = (input.level as number) || 1;
    const risk = (input.risk as number) || 1;

    const args: string[] = ['sqlmap', '-u', target, '--batch'];

    if (parameter) {
      args.push('-p', parameter);
    }

    if (technique) {
      args.push('--technique', technique);
    }

    args.push('--level', String(level));
    args.push('--risk', String(risk));

    return args.join(' ');
  },

  parseOutput(output: string): ExecutionFinding[] {
    const findings: ExecutionFinding[] = [];

    // Parse SQLMap vulnerability findings
    const vulnPatterns = [
      { regex: /Parameter:\s+'([^']+)'\s+is\s+vulnerable/i, title: 'SQL Injection' },
      { regex: /Type:\s+(.+)/i, title: 'Injection Type' },
      { regex: /Title:\s+(.+)/i, title: 'Technique' },
    ];

    const paramVulnRegex = /Parameter:\s+'([^']+)'.*?is\s+vulnerable/gi;
    let match;

    while ((match = paramVulnRegex.exec(output)) !== null) {
      findings.push({
        type: 'vulnerability',
        severity: 'critical',
        title: `SQL Injection in parameter '${match[1]}'`,
        description: `The parameter '${match[1]}' is vulnerable to SQL injection`,
        target: '',
        evidence: match[0],
        metadata: { parameter: match[1] },
      });
    }

    // Parse database info if available
    const dbRegex = /back-end DBMS:\s+(.+)/i;
    const dbMatch = dbRegex.exec(output);
    if (dbMatch) {
      findings.push({
        type: 'technology',
        severity: 'info',
        title: `Database: ${dbMatch[1]}`,
        description: `Identified backend DBMS: ${dbMatch[1]}`,
        target: '',
        evidence: dbMatch[0],
        metadata: { dbms: dbMatch[1] },
      });
    }

    return findings;
  },

  validateInput(input: Record<string, unknown>): { valid: boolean; error?: string } {
    if (!input.target || typeof input.target !== 'string') {
      return { valid: false, error: 'Target URL is required' };
    }
    return { valid: true };
  },
};

// ============================================================================
// Metasploit Adapter (via MSGRPC)
// ============================================================================

export const metasploitAdapter: ToolAdapter = {
  name: 'metasploit',
  defaultTimeoutMs: 600_000,

  buildCommand(input: Record<string, unknown>): string {
    // Metasploit uses MSGRPC API, not CLI commands directly
    // This builds an msfconsole resource script instead
    const module = input.module as string;
    const options = (input.options as Record<string, string>) || {};

    const lines: string[] = [`use ${module}`];

    for (const [key, value] of Object.entries(options)) {
      lines.push(`set ${key} ${value}`);
    }

    lines.push('exploit -j'); // Run as background job

    return `msfconsole -q -x "${lines.join('; ')}"`;
  },

  parseOutput(output: string): ExecutionFinding[] {
    const findings: ExecutionFinding[] = [];

    // Parse session opened
    const sessionRegex = /(\w+)\s+session\s+(\d+)\s+opened\s+\(([^)]+)\)/gi;
    let match;

    while ((match = sessionRegex.exec(output)) !== null) {
      findings.push({
        type: 'vulnerability',
        severity: 'critical',
        title: `${match[1]} session established`,
        description: `Session ${match[2]} opened: ${match[3]}`,
        target: match[3].split('->')[1]?.trim() || '',
        evidence: match[0],
        metadata: {
          sessionType: match[1],
          sessionId: parseInt(match[2], 10),
          connection: match[3],
        },
      });
    }

    // Parse exploit success
    if (/exploit completed/i.test(output)) {
      findings.push({
        type: 'info',
        severity: 'info',
        title: 'Exploit completed',
        description: 'Metasploit exploit module execution completed',
        target: '',
        evidence: 'exploit completed',
        metadata: {},
      });
    }

    return findings;
  },

  validateInput(input: Record<string, unknown>): { valid: boolean; error?: string } {
    if (!input.module || typeof input.module !== 'string') {
      return { valid: false, error: 'Metasploit module path is required' };
    }
    return { valid: true };
  },
};

// ============================================================================
// Custom Script Adapter
// ============================================================================

export const customScriptAdapter: ToolAdapter = {
  name: 'custom_script',
  defaultTimeoutMs: 300_000,

  buildCommand(input: Record<string, unknown>): string {
    const script = input.script as string;
    const interpreter = (input.interpreter as string) || 'python3';
    const args = (input.args as string[]) || [];

    // Script is passed as inline code, not a file path (for sandboxed execution)
    return `${interpreter} -c ${JSON.stringify(script)} ${args.join(' ')}`;
  },

  parseOutput(output: string): ExecutionFinding[] {
    // Custom scripts should output JSON findings
    try {
      const results = JSON.parse(output);
      if (Array.isArray(results)) {
        return results.map(r => ({
          type: r.type || 'info',
          severity: r.severity || 'info',
          title: r.title || 'Custom finding',
          description: r.description || '',
          target: r.target || '',
          evidence: r.evidence || output,
          metadata: r.metadata || {},
        }));
      }
    } catch {
      // Not JSON, return as raw info
    }

    return [{
      type: 'info',
      severity: 'info',
      title: 'Script output',
      description: output.substring(0, 500),
      target: '',
      evidence: output,
      metadata: {},
    }];
  },

  validateInput(input: Record<string, unknown>): { valid: boolean; error?: string } {
    if (!input.script || typeof input.script !== 'string') {
      return { valid: false, error: 'Script content is required' };
    }
    return { valid: true };
  },
};

// ============================================================================
// Adapter Registry
// ============================================================================

const adapters: Map<string, ToolAdapter> = new Map([
  ['nmap', nmapAdapter],
  ['nuclei', nucleiAdapter],
  ['sqlmap', sqlmapAdapter],
  ['metasploit', metasploitAdapter],
  ['custom_script', customScriptAdapter],
]);

export function getToolAdapter(name: string): ToolAdapter | undefined {
  return adapters.get(name);
}

export function registerToolAdapter(adapter: ToolAdapter): void {
  adapters.set(adapter.name, adapter);
}

export function getAvailableAdapters(): string[] {
  return Array.from(adapters.keys());
}
