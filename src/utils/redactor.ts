import { loadConfig } from './config-loader.js';

/**
 * Redact sensitive data from text based on configured patterns
 */
export function redactSensitiveData(text: string): string {
  try {
    const config = loadConfig();

    if (!config.output.redaction.enabled) {
      return text;
    }

    let redacted = text;

    for (const pattern of config.output.redaction.patterns) {
      const regex = new RegExp(pattern, 'g');
      redacted = redacted.replace(regex, (match) => {
        // Check if the match contains a key-value pattern
        if (match.includes('=') || match.includes(':')) {
          // Extract the key part and redact the value
          const parts = match.split(/[:=]/);
          if (parts.length >= 2) {
            return `${parts[0]}${match.includes('=') ? '=' : ':'}***REDACTED***`;
          }
        }
        // For other patterns (like private keys), redact entirely
        return '***REDACTED***';
      });
    }

    return redacted;
  } catch {
    // If config is not available, return original text
    return text;
  }
}

/**
 * Check if text contains potentially sensitive data
 */
export function containsSensitiveData(text: string): boolean {
  try {
    const config = loadConfig();

    if (!config.output.redaction.enabled) {
      return false;
    }

    for (const pattern of config.output.redaction.patterns) {
      const regex = new RegExp(pattern);
      if (regex.test(text)) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}
