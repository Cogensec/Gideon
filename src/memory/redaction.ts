import { loadConfig } from '../utils/config-loader.js';

// ============================================================================
// Secret redaction for persisted memory
//
// Reuses gideon.config.yaml `output.redaction.patterns` so memory redaction
// stays consistent with report redaction, plus a built-in fallback set so the
// memory subsystem is safe even when config is unavailable (e.g. in tests).
// ============================================================================

const REDACTION_PLACEHOLDER = '[REDACTED]';

/**
 * Built-in fallback patterns (always applied). Mirrors the intent of the
 * config patterns but is hard-coded so memory is never persisted unredacted
 * just because config failed to load.
 */
const BUILTIN_PATTERNS: RegExp[] = [
  // api_key / token / password / secret = <value>
  /(?:api[_-]?key|token|password|passwd|secret|credential)\s*[:=]\s*['"]?[^'"\s]{8,}/gi,
  // Bearer tokens
  /bearer\s+[a-zA-Z0-9\-_]+\.?[a-zA-Z0-9\-_]*\.?[a-zA-Z0-9\-_]*/gi,
  // PEM private keys
  /-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----/gi,
  // AWS access key ids
  /AKIA[0-9A-Z]{16}/g,
  // Generic long hex/base64 secrets following a key-ish word
  /(?:session|gateway)\s+(?:token|key|secret)\s*[:=]\s*[a-zA-Z0-9\-_]{16,}/gi,
];

/**
 * Convert a config pattern string (which may use Python-style inline `(?i)`
 * flags) into a JS RegExp with the global flag set.
 */
function compileConfigPattern(pattern: string): RegExp | null {
  let flags = 'g';
  let body = pattern;
  // Strip leading inline flags like (?i) / (?im) that JS doesn't support.
  const inline = body.match(/^\(\?([a-z]+)\)/);
  if (inline) {
    if (inline[1].includes('i')) flags += 'i';
    if (inline[1].includes('m')) flags += 'm';
    if (inline[1].includes('s')) flags += 's';
    body = body.slice(inline[0].length);
  }
  try {
    return new RegExp(body, flags);
  } catch {
    return null;
  }
}

let cachedConfigPatterns: RegExp[] | null = null;

function getConfigPatterns(): RegExp[] {
  if (cachedConfigPatterns) return cachedConfigPatterns;
  try {
    const cfg = loadConfig();
    if (cfg.output.redaction.enabled) {
      cachedConfigPatterns = cfg.output.redaction.patterns
        .map(compileConfigPattern)
        .filter((r): r is RegExp => r !== null);
    } else {
      cachedConfigPatterns = [];
    }
  } catch {
    cachedConfigPatterns = [];
  }
  return cachedConfigPatterns;
}

/**
 * Redact secrets from text before it is persisted to memory.
 * Always applies the built-in patterns; additionally applies config patterns.
 */
export function redactSecrets(text: string): string {
  let out = text;
  for (const re of [...BUILTIN_PATTERNS, ...getConfigPatterns()]) {
    out = out.replace(re, REDACTION_PLACEHOLDER);
  }
  return out;
}

/**
 * Returns true if redaction changed the text (i.e. a secret was present).
 */
export function containsSecret(text: string): boolean {
  return redactSecrets(text) !== text;
}

/**
 * Test-only: reset the cached config patterns.
 */
export function resetRedactionCache(): void {
  cachedConfigPatterns = null;
}
