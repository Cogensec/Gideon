import { Agent } from '../agent/agent.js';
import { CommandContext, CommandResult } from './types.js';

export async function cveCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  if (args.length === 0) {
    return {
      success: false,
      output: '',
      error: 'Usage: gideon cve <search query>\n\nExample:\n  gideon cve CVE-2024-1234\n  gideon cve log4j vulnerabilities\n  gideon cve latest critical windows vulnerabilities',
    };
  }

  const agent = Agent.create(context);
  const searchQuery = args.join(' ');

  const query = `Search for CVEs matching: ${searchQuery}

For each CVE found, provide:
1. CVE ID and description
2. CVSS score and severity rating
3. Affected products and versions
4. Exploitability status (is it in CISA KEV catalog?)
5. Attack complexity and prerequisites
6. Available mitigations, patches, or workarounds
7. References for more information

Include confidence level for each finding. Focus on defensive information only.`;

  let fullAnswer = '';

  try {
    for await (const event of agent.run(query)) {
      if (event.type === 'answer_chunk') {
        fullAnswer += event.text;
      }
    }

    return {
      success: true,
      output: fullAnswer,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
