import { Agent } from '../agent/agent.js';
import { CommandContext, CommandResult } from './types.js';
import { generateMarkdownReport, generateJSONReport } from '../output/index.js';

export async function briefCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const agent = Agent.create(context);

  const query = `Generate a daily security briefing for today including:

1. Critical CVEs published in the last 24 hours with CVSS >= 8.0
2. Major security advisories from vendors (Microsoft, Apple, Google, Cisco, etc.)
3. Notable security incidents or breaches reported today
4. Emerging threat campaigns or attack trends

For each item, include:
- Severity/impact level
- Affected products or organizations
- Recommended defensive actions
- Confidence level in the assessment

Focus on actionable intelligence for security defenders.`;

  let fullAnswer = '';
  const toolCalls: any[] = [];

  try {
    for await (const event of agent.run(query)) {
      if (event.type === 'answer_chunk') {
        fullAnswer += event.text;
      } else if (event.type === 'done') {
        toolCalls.push(...event.toolCalls);
      }
    }

    // Generate artifacts
    const timestamp = new Date().toISOString();
    const markdown = await generateMarkdownReport({
      title: 'Daily Security Briefing',
      content: fullAnswer,
      toolCalls,
      timestamp,
      metadata: {
        command: 'brief',
        generated_at: timestamp,
      },
    });

    const json = await generateJSONReport({
      type: 'briefing',
      content: fullAnswer,
      toolCalls,
      timestamp,
      metadata: {
        command: 'brief',
      },
    });

    return {
      success: true,
      output: fullAnswer,
      artifacts: { markdown, json },
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
