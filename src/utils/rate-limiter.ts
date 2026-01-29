import Bottleneck from 'bottleneck';
import { getSourceConfig } from './config-loader.js';

const limiters = new Map<string, Bottleneck>();

/**
 * Get or create a rate limiter for a specific source
 */
export function getRateLimiter(sourceName: string): Bottleneck {
  if (limiters.has(sourceName)) {
    return limiters.get(sourceName)!;
  }

  const config = getSourceConfig(sourceName);
  const rateLimit = config?.rate_limit || 5;

  // Default: requests per second
  // If rate limit is very low (< 10), assume it's requests per minute
  const isPerMinute = rateLimit < 10 && sourceName !== 'nvd';
  const minTime = isPerMinute ? 60000 / rateLimit : 1000 / rateLimit;

  const limiter = new Bottleneck({
    minTime, // ms between requests
    maxConcurrent: 1,
  });

  limiters.set(sourceName, limiter);
  return limiter;
}

/**
 * Execute a function with rate limiting
 */
export async function rateLimitedFetch<T>(
  sourceName: string,
  fetchFn: () => Promise<T>
): Promise<T> {
  const limiter = getRateLimiter(sourceName);
  return limiter.schedule(fetchFn);
}

/**
 * Clear all rate limiters (useful for testing)
 */
export function clearRateLimiters(): void {
  for (const limiter of limiters.values()) {
    limiter.stop();
  }
  limiters.clear();
}
