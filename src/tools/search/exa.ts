import { DynamicStructuredTool } from '@langchain/core/tools';
import Exa from 'exa-js';
import { z } from 'zod';
import { formatToolResult } from '../types.js';

// Lazily initialized to avoid errors when API key is not set
let exaClient: Exa | null = null;

function getExaClient(): Exa {
  if (!exaClient) {
    const apiKey = process.env.EXA_API_KEY;
    if (!apiKey) {
      throw new Error('EXA_API_KEY is not set in environment variables');
    }
    exaClient = new Exa(apiKey);
  }
  return exaClient;
}

export const exaSearch = new DynamicStructuredTool({
  name: 'exa_search',
  description: 'Perform a semantic search of the web using Exa AI. Best for finding technical articles, obscure research, or complex queries that require semantic understanding rather than just keyword matching.',
  schema: z.object({
    query: z.string().describe('The search query to look up on the web'),
    useAutoprompt: z.boolean().optional().describe('Whether to automatically optimize the prompt for neural search'),
    numResults: z.number().optional().default(5).describe('Number of results to return'),
  }),
  func: async (input) => {
    try {
      const client = getExaClient();
      const result = await client.search(input.query, {
        useAutoprompt: input.useAutoprompt ?? true,
        numResults: input.numResults,
        type: 'neural',
      });

      const urls = result.results
        ?.map((r: { url?: string }) => r.url)
        .filter((url: string | undefined): url is string => Boolean(url)) ?? [];

      return formatToolResult(result, urls);
    } catch (error) {
      return JSON.stringify({
        error: error instanceof Error ? error.message : String(error),
      });
    }
  },
});
