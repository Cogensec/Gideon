import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { loadConfig } from '../utils/config-loader.js';
import { redactSensitiveData } from '../utils/redactor.js';

export interface MarkdownReportInput {
  title: string;
  content: string;
  toolCalls?: any[];
  timestamp: string;
  metadata?: Record<string, any>;
}

export async function generateMarkdownReport(input: MarkdownReportInput): Promise<string> {
  try {
    const config = loadConfig();
    const outputDir = config.output.directory;

    // Create timestamped directory
    const dirName = new Date(input.timestamp).toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const reportDir = join(outputDir, dirName);

    if (!existsSync(reportDir)) {
      mkdirSync(reportDir, { recursive: true });
    }

    // Build markdown
    let markdown = `# ${input.title}\n\n`;
    markdown += `**Generated:** ${new Date(input.timestamp).toLocaleString()}\n\n`;
    markdown += `---\n\n`;
    markdown += `## Analysis\n\n`;
    markdown += `${input.content}\n\n`;

    if (input.toolCalls && input.toolCalls.length > 0) {
      markdown += `---\n\n## Data Sources\n\n`;
      input.toolCalls.forEach((call, i) => {
        markdown += `${i + 1}. **${call.tool}**\n`;
        markdown += `   - Arguments: \`${JSON.stringify(call.args)}\`\n`;
      });
      markdown += `\n`;
    }

    if (input.metadata) {
      markdown += `---\n\n## Metadata\n\n`;
      markdown += `\`\`\`json\n${JSON.stringify(input.metadata, null, 2)}\n\`\`\`\n`;
    }

    // Redact sensitive data
    const redacted = redactSensitiveData(markdown);

    // Write to file
    const filepath = join(reportDir, 'report.md');
    writeFileSync(filepath, redacted);

    return redacted;
  } catch (error) {
    // If config not available or error occurs, return the raw markdown
    console.warn('Failed to generate markdown report:', error);
    return input.content;
  }
}
