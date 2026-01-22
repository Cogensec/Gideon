import NodeCache from 'node-cache';
import { createHash } from 'crypto';

const cache = new NodeCache({
  stdTTL: 900, // Default 15 minutes
  checkperiod: 120, // Check for expired keys every 2 minutes
  useClones: false,
});

/**
 * Get a cached value
 */
export function getCached<T>(key: string): T | undefined {
  return cache.get<T>(key);
}

/**
 * Set a cached value with optional TTL
 */
export function setCached<T>(key: string, value: T, ttl?: number): void {
  cache.set(key, value, ttl || 900);
}

/**
 * Generate a cache key from prefix and parameters
 */
export function generateCacheKey(prefix: string, params: Record<string, any>): string {
  const hash = createHash('md5')
    .update(JSON.stringify(params))
    .digest('hex')
    .slice(0, 12);
  return `${prefix}:${hash}`;
}

/**
 * Clear all cached data
 */
export function clearCache(): void {
  cache.flushAll();
}

/**
 * Delete a specific cached key
 */
export function deleteCached(key: string): void {
  cache.del(key);
}

/**
 * Get cache statistics
 */
export function getCacheStats() {
  return cache.getStats();
}
