import { Agent } from '../agent/agent.js';
import { CommandContext, CommandResult } from './types.js';

export async function iocCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  if (args.length === 0) {
    return {
      success: false,
      output: '',
      error: 'Usage: gideon ioc <indicator>\n\nSupported indicators:\n  - IP addresses (e.g., 8.8.8.8)\n  - Domains (e.g., malicious-domain.com)\n  - URLs (e.g., https://suspicious-site.com)\n  - File hashes (MD5, SHA1, SHA256)',
    };
  }

  const ioc = args[0];
  const agent = Agent.create(context);

  const query = `Analyze this indicator of compromise: ${ioc}

Provide comprehensive analysis including:

1. IOC Type: Identify if this is an IP, domain, URL, or hash
2. Reputation Analysis:
   - Malicious/suspicious detections from multiple sources
   - Reputation scores and confidence levels
   - Detection ratios (e.g., X/Y vendors flagged as malicious)

3. Contextual Information:
   - Geolocation (if IP address)
   - ASN/ISP details (if IP)
   - Associated domains or infrastructure
   - First seen / last seen dates

4. Threat Intelligence:
   - Associated malware families or campaigns
   - Attack types or TTPs linked to this indicator
   - Community comments or reports

5. Recommended Actions:
   - Should this be blocked immediately?
   - Suitable for monitoring/alerting?
   - Needs further investigation?

6. Confidence Assessment:
   - Overall confidence in malicious/benign verdict
   - Agreement between sources
   - Any conflicting information

DEFENSIVE FOCUS: Provide detection and blocking guidance, not exploitation techniques.`;

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
