import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { loadConfig } from '../utils/config-loader.js';

export interface JSONReportInput {
  type: string;
  content: string;
  toolCalls?: any[];
  timestamp: string;
  metadata?: Record<string, any>;
}

export async function generateJSONReport(input: JSONReportInput): Promise<any> {
  try {
    const config = loadConfig();
    const outputDir = config.output.directory;

    const dirName = new Date(input.timestamp).toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const reportDir = join(outputDir, dirName);

    if (!existsSync(reportDir)) {
      mkdirSync(reportDir, { recursive: true });
    }

    const jsonData = {
      type: input.type,
      timestamp: input.timestamp,
      content: input.content,
      toolCalls: input.toolCalls || [],
      metadata: input.metadata || {},
      version: '1.0.0',
    };

    const filepath = join(reportDir, 'data.json');
    writeFileSync(filepath, JSON.stringify(jsonData, null, 2));

    return jsonData;
  } catch (error) {
    console.warn('Failed to generate JSON report:', error);
    return {
      type: input.type,
      timestamp: input.timestamp,
      content: input.content,
      error: String(error),
    };
  }
}
