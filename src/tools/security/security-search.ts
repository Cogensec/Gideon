import { DynamicStructuredTool, StructuredToolInterface } from '@langchain/core/tools';
import { AIMessage } from '@langchain/core/messages';
import { z } from 'zod';
import { callLlm } from '../../model/llm.js';
import { CVEConnector } from './cve-connector.js';
import { IOCConnector } from './ioc-connector.js';
import { ExaConnector } from './exa-connector.js';
import { getCurrentDate } from '../../agent/prompts.js';

const SECURITY_CONNECTORS = [
  CVEConnector,
  IOCConnector,
  ExaConnector,
];

const SecuritySearchInputSchema = z.object({
  query: z.string().describe('Natural language security query'),
});

function buildSecurityRouterPrompt(): string {
  return `You are a security data routing assistant for DEFENSIVE PURPOSES ONLY.
Current date: ${getCurrentDate()}

Given a user's query about cybersecurity, call the appropriate security connector(s).

## Available Connectors

1. **cve_connector**: CVE database search (NVD)
   - Use for: vulnerability searches, CVE lookups, security advisories
   - Example queries: "latest critical CVEs", "CVE-2024-1234 details", "log4j vulnerabilities"
   - Focus: Vulnerability information, CVSS scores, affected products, mitigations

3. **exa_connector**: Deep technical research via Exa AI
   - Use for: obscure vulnerability write-ups, security blog posts, technical research
   - Example queries: "XZ Utils backdoor technical analysis", "rare exploitation techniques for kernel heap", "security research on HTTP/2 rapid reset"
   - Focus: In-depth technical articles, semantic search across security blogs and academic papers

## Guidelines

**CVE Queries:**
- Extract CVE IDs (CVE-YYYY-NNNNN format)
- Identify keywords (software names, vulnerability types)
- Include date ranges if mentioned ("last 24 hours", "this week", "2024")
- Focus on defensive information: severity, affected systems, patches

**IOC Queries:**
- Identify the indicator type (IP, domain, URL, hash)
- Single indicator per query for accurate analysis
- Extract the actual indicator value cleanly

**General Security Queries:**
- May require multiple connectors
- Prioritize most relevant connector first
- For broad queries like "latest threats", use cve_connector
- For deep technical exploration or "how it works" research, use exa_connector

**SAFETY CONSTRAINTS:**
- NEVER provide exploitation techniques or attack methodologies
- Focus ONLY on defensive information: detection, mitigation, patching
- If query requests offensive capabilities, refuse and explain defensive-only policy

Call the appropriate connector(s) now based on the query.`;
}

export function createSecuritySearch(model: string): DynamicStructuredTool {
  return new DynamicStructuredTool({
    name: 'security_search',
    description: `Intelligent search for security data and threat intelligence. Routes queries to appropriate data sources:
- CVE vulnerabilities (NVD database)
- IOC reputation (VirusTotal, AbuseIPDB)
- Security advisories and threat intelligence

Use for vulnerability research, indicator analysis, and security investigations. DEFENSIVE USE ONLY - provides detection and mitigation information, never exploitation techniques.`,
    schema: SecuritySearchInputSchema,

    func: async (input: { query: string }): Promise<string> => {
      // Safety check: block obvious offensive queries
      const offensivePatterns = [
        /\b(exploit|payload|shellcode|reverse\s+shell|backdoor)\b/i,
        /\b(hack|hacking|breach|intrude|intrusion)\s+(how|tutorial|guide)/i,
        /\b(create|generate|build)\s+(malware|virus|trojan|ransomware)/i,
      ];

      for (const pattern of offensivePatterns) {
        if (pattern.test(input.query)) {
          return JSON.stringify({
            error: 'SAFETY_BLOCK',
            message: 'This query appears to request offensive capabilities. Gideon operates in DEFENSIVE MODE ONLY and provides information for detection, mitigation, and protection - not for exploitation or attack.',
            suggestion: 'Please rephrase your query to focus on defensive aspects like vulnerability identification, impact assessment, or mitigation strategies.',
          });
        }
      }

      // Use LLM to route query to appropriate connector(s)
      const routerPrompt = `${buildSecurityRouterPrompt()}\n\nUser query: ${input.query}`;

      // Create temporary tools from connectors
      const connectorTools: StructuredToolInterface[] = SECURITY_CONNECTORS.map(connector => {
        return new DynamicStructuredTool({
          name: connector.name,
          description: connector.description,
          schema: z.object({
            query: z.string(),
            timeframe: z.object({
              start: z.string().optional(),
              end: z.string().optional(),
            }).optional(),
          }),
          func: async (args: { query: string; timeframe?: { start?: string; end?: string } }) => {
            try {
              const rawData = await connector.fetch({
                type: 'cve', // Type is inferred by connector from query
                query: args.query,
                timeframe: args.timeframe,
              });
              const normalized = connector.normalize(rawData);
              const ranked = connector.rank(normalized);

              return JSON.stringify({
                connector: connector.name,
                results: ranked,
                cached: rawData._cached || false,
              }, null, 2);
            } catch (error) {
              return JSON.stringify({
                connector: connector.name,
                error: error instanceof Error ? error.message : String(error),
              });
            }
          },
        });
      });

      // Call LLM with connector tools
      const response = await callLlm(routerPrompt, {
        model,
        systemPrompt: 'You are a security data router. Call the appropriate connector tools for DEFENSIVE security research only.',
        tools: connectorTools,
      }) as AIMessage;

      // Execute tool calls if any
      if (response.tool_calls && response.tool_calls.length > 0) {
        const results: string[] = [];

        for (const toolCall of response.tool_calls) {
          const connector = SECURITY_CONNECTORS.find(c => c.name === toolCall.name);
          if (!connector) continue;

          const args = toolCall.args as { query: string; timeframe?: { start?: string; end?: string } };

          try {
            const rawData = await connector.fetch({
              type: 'cve',
              query: args.query,
              timeframe: args.timeframe,
            });
            const normalized = connector.normalize(rawData);
            const ranked = connector.rank(normalized);

            results.push(JSON.stringify({
              connector: connector.name,
              results: ranked,
              cached: rawData._cached || false,
            }, null, 2));
          } catch (error) {
            results.push(JSON.stringify({
              connector: connector.name,
              error: error instanceof Error ? error.message : String(error),
            }));
          }
        }

        return results.join('\n\n---\n\n');
      }

      // Fallback if no tool calls
      return JSON.stringify({
        error: 'NO_CONNECTOR_SELECTED',
        message: 'Unable to determine appropriate connector for this query',
        query: input.query,
      });
    },
  });
}
