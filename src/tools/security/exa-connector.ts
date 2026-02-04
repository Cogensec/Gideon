import { SecurityConnector, SecurityQuery, NormalizedData } from './types.js';
import Exa from 'exa-js';
import { getCached, setCached, generateCacheKey } from '../../utils/cache.js';
import { getSourceConfig } from '../../utils/config-loader.js';

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

export const ExaConnector: SecurityConnector = {
    name: 'exa_connector',
    description: 'Deep technical research via Exa AI. Best for finding obscure technical write-ups, vulnerability research, and security blog posts.',

    async fetch(query: SecurityQuery): Promise<any> {
        const cacheKey = generateCacheKey('exa', query);
        const cached = getCached(cacheKey);
        if (cached) {
            return { ...cached, _cached: true };
        }

        const config = getSourceConfig('exa') || { enabled: true, cache_ttl: 3600 };
        if (!config.enabled) {
            throw new Error('Exa connector is disabled');
        }

        const client = getExaClient();
        const results = await client.search(query.query, {
            useAutoprompt: true,
            numResults: 10,
            type: 'neural',
            // We could add more filters here, like category: 'technical' or similar if supported
        });

        const ttl = config.cache_ttl || 3600;
        setCached(cacheKey, results, ttl);

        return { ...results, _cached: false };
    },

    normalize(rawData: any): NormalizedData[] {
        const results = rawData.results || [];

        return results.map((result: any) => {
            return {
                id: result.id || result.url,
                source: 'exa',
                type: 'research',
                severity: 'INFORMATIONAL',
                confidence: 0.8, // Neural search is high quality but not authoritative database
                summary: result.title || 'No title',
                details: {
                    excerpt: result.text || result.snippet,
                    author: result.author,
                    publishedDate: result.publishedDate,
                    score: result.score,
                },
                timestamp: result.publishedDate || new Date().toISOString(),
                url: result.url,
            };
        });
    },

    rank(results: NormalizedData[]): NormalizedData[] {
        // Rank by score (provided by Exa for relevance)
        return results.sort((a, b) => {
            const scoreA = Number(a.details?.score) || 0;
            const scoreB = Number(b.details?.score) || 0;
            return scoreB - scoreA;
        });
    },
};
