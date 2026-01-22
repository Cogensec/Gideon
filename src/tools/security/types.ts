import { z } from 'zod';

export const SecurityQuerySchema = z.object({
  type: z.enum(['cve', 'advisory', 'ioc', 'news', 'breach']),
  query: z.string(),
  timeframe: z.object({
    start: z.string().optional(),
    end: z.string().optional(),
  }).optional(),
  filters: z.record(z.any()).optional(),
});

export type SecurityQuery = z.infer<typeof SecurityQuerySchema>;

export interface NormalizedData {
  id: string;
  source: string;
  type: string;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: number;
  summary: string;
  details: Record<string, any>;
  timestamp: string;
  url?: string;
}

export interface SecurityConnector {
  name: string;
  description: string;
  fetch(query: SecurityQuery): Promise<any>;
  normalize(rawData: any): NormalizedData[];
  rank(results: NormalizedData[]): NormalizedData[];
}

export interface ConnectorResult {
  connector: string;
  data: NormalizedData[];
  error?: string;
  cached: boolean;
}
