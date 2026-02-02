/**
 * NVIDIA NeMo Guardrails Client
 *
 * Client for integrating with NeMo Guardrails microservice to provide
 * ML-based safety rails for Gideon's LLM interactions.
 *
 * Supports three key guardrail types:
 * - Jailbreak Detection: Blocks attempts to bypass safety measures
 * - Topic Control: Keeps conversations within allowed security topics
 * - Content Safety: Ensures outputs don't contain harmful content
 */

export interface GuardrailsConfig {
  serviceUrl: string;
  enabled: boolean;
  inputRails: {
    jailbreakDetection: boolean;
    topicControl: boolean;
  };
  outputRails: {
    contentSafety: boolean;
  };
  allowedTopics: string[];
  blockedTopics: string[];
}

export interface GuardrailCheckResult {
  allowed: boolean;
  railTriggered?: string;
  reason?: string;
  confidence?: number;
  sanitizedContent?: string;
}

export interface JailbreakCheckResult {
  isJailbreak: boolean;
  confidence: number;
  attackType?: string;
}

export interface TopicCheckResult {
  onTopic: boolean;
  detectedTopic?: string;
  allowedTopics: string[];
}

export interface ContentSafetyResult {
  safe: boolean;
  categories?: string[];
  severity?: 'low' | 'medium' | 'high';
}

// Default configuration
const DEFAULT_CONFIG: GuardrailsConfig = {
  serviceUrl: 'http://localhost:7331',
  enabled: true,
  inputRails: {
    jailbreakDetection: true,
    topicControl: true,
  },
  outputRails: {
    contentSafety: true,
  },
  allowedTopics: [
    'cybersecurity',
    'vulnerability analysis',
    'threat intelligence',
    'security hardening',
    'incident response',
    'malware analysis',
    'network security',
    'compliance',
  ],
  blockedTopics: [
    'offensive security',
    'exploitation techniques',
    'malware development',
    'attack tools',
    'hacking tutorials',
  ],
};

/**
 * Gets NeMo Guardrails configuration from environment
 */
export function getGuardrailsConfig(): GuardrailsConfig {
  return {
    ...DEFAULT_CONFIG,
    serviceUrl: process.env.NEMO_GUARDRAILS_URL || DEFAULT_CONFIG.serviceUrl,
    enabled: process.env.NEMO_GUARDRAILS_ENABLED !== 'false',
  };
}

/**
 * Checks if NeMo Guardrails service is available
 */
export async function isGuardrailsAvailable(): Promise<boolean> {
  const config = getGuardrailsConfig();

  if (!config.enabled) {
    return false;
  }

  try {
    const response = await fetch(`${config.serviceUrl}/v1/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Check input for jailbreak attempts using NeMo Guardrails
 */
export async function checkJailbreak(input: string): Promise<JailbreakCheckResult> {
  const config = getGuardrailsConfig();

  if (!config.enabled || !config.inputRails.jailbreakDetection) {
    return { isJailbreak: false, confidence: 0 };
  }

  try {
    const response = await fetch(`${config.serviceUrl}/v1/guardrail/checks/jailbreak`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: input }),
    });

    if (!response.ok) {
      // Service unavailable, fail open (allow request)
      return { isJailbreak: false, confidence: 0 };
    }

    const result = await response.json();
    return {
      isJailbreak: result.is_jailbreak ?? false,
      confidence: result.confidence ?? 0,
      attackType: result.attack_type,
    };
  } catch {
    // Fail open on error
    return { isJailbreak: false, confidence: 0 };
  }
}

/**
 * Check if input is within allowed topics
 */
export async function checkTopic(input: string): Promise<TopicCheckResult> {
  const config = getGuardrailsConfig();

  if (!config.enabled || !config.inputRails.topicControl) {
    return { onTopic: true, allowedTopics: config.allowedTopics };
  }

  try {
    const response = await fetch(`${config.serviceUrl}/v1/guardrail/checks/topic`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: input,
        allowed_topics: config.allowedTopics,
        blocked_topics: config.blockedTopics,
      }),
    });

    if (!response.ok) {
      return { onTopic: true, allowedTopics: config.allowedTopics };
    }

    const result = await response.json();
    return {
      onTopic: result.on_topic ?? true,
      detectedTopic: result.detected_topic,
      allowedTopics: config.allowedTopics,
    };
  } catch {
    return { onTopic: true, allowedTopics: config.allowedTopics };
  }
}

/**
 * Check output content for safety issues
 */
export async function checkContentSafety(output: string): Promise<ContentSafetyResult> {
  const config = getGuardrailsConfig();

  if (!config.enabled || !config.outputRails.contentSafety) {
    return { safe: true };
  }

  try {
    const response = await fetch(`${config.serviceUrl}/v1/guardrail/checks/content-safety`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: output }),
    });

    if (!response.ok) {
      return { safe: true };
    }

    const result = await response.json();
    return {
      safe: result.safe ?? true,
      categories: result.unsafe_categories,
      severity: result.severity,
    };
  } catch {
    return { safe: true };
  }
}

/**
 * Run all input rails on user input
 */
export async function checkInputRails(input: string): Promise<GuardrailCheckResult> {
  const config = getGuardrailsConfig();

  if (!config.enabled) {
    return { allowed: true };
  }

  // Check for jailbreak attempts
  const jailbreakResult = await checkJailbreak(input);
  if (jailbreakResult.isJailbreak && jailbreakResult.confidence > 0.7) {
    return {
      allowed: false,
      railTriggered: 'jailbreak_detection',
      reason: `Potential jailbreak attempt detected (${jailbreakResult.attackType || 'unknown type'})`,
      confidence: jailbreakResult.confidence,
    };
  }

  // Check topic control
  const topicResult = await checkTopic(input);
  if (!topicResult.onTopic) {
    return {
      allowed: false,
      railTriggered: 'topic_control',
      reason: `Request is outside allowed security topics. Detected: ${topicResult.detectedTopic || 'off-topic'}`,
      confidence: 0.8,
    };
  }

  return { allowed: true };
}

/**
 * Run all output rails on LLM response
 */
export async function checkOutputRails(output: string): Promise<GuardrailCheckResult> {
  const config = getGuardrailsConfig();

  if (!config.enabled) {
    return { allowed: true };
  }

  // Check content safety
  const safetyResult = await checkContentSafety(output);
  if (!safetyResult.safe) {
    return {
      allowed: false,
      railTriggered: 'content_safety',
      reason: `Content flagged for safety: ${safetyResult.categories?.join(', ') || 'harmful content'}`,
      confidence: 0.9,
    };
  }

  return { allowed: true };
}

/**
 * Full guardrails check using NeMo Guardrails chat completions API
 * This is the recommended integration point for full conversation context
 */
export async function guardrailsChatCompletion(
  messages: Array<{ role: string; content: string }>
): Promise<{
  response: string;
  guardrailsApplied: string[];
  blocked: boolean;
  blockReason?: string;
}> {
  const config = getGuardrailsConfig();

  if (!config.enabled) {
    return {
      response: '',
      guardrailsApplied: [],
      blocked: false,
    };
  }

  try {
    const response = await fetch(`${config.serviceUrl}/v1/guardrail/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages,
        config: {
          input_rails: config.inputRails,
          output_rails: config.outputRails,
          allowed_topics: config.allowedTopics,
          blocked_topics: config.blockedTopics,
        },
      }),
    });

    if (!response.ok) {
      return {
        response: '',
        guardrailsApplied: [],
        blocked: false,
      };
    }

    const result = await response.json();
    return {
      response: result.choices?.[0]?.message?.content || '',
      guardrailsApplied: result.guardrails_applied || [],
      blocked: result.blocked || false,
      blockReason: result.block_reason,
    };
  } catch {
    return {
      response: '',
      guardrailsApplied: [],
      blocked: false,
    };
  }
}

/**
 * Fallback pattern-based checks when NeMo Guardrails service is unavailable
 * These complement the existing safety checks in security-search.ts
 */
export function localJailbreakCheck(input: string): boolean {
  const jailbreakPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)/i,
    /disregard\s+(your|all)\s+(rules|guidelines|instructions)/i,
    /pretend\s+(you('re|are)|to\s+be)\s+(not|no\s+longer)\s+(an?\s+)?ai/i,
    /you\s+are\s+now\s+(in\s+)?(dan|developer|jailbreak)\s+mode/i,
    /bypass\s+(your|the)\s+(safety|security|content)\s+(filters?|checks?)/i,
    /act\s+as\s+if\s+(you\s+have\s+)?no\s+(ethical|moral)\s+(guidelines|restrictions)/i,
    /roleplay\s+as\s+(a\s+)?(hacker|attacker|malicious)/i,
  ];

  return jailbreakPatterns.some((pattern) => pattern.test(input));
}

/**
 * Local topic check when service is unavailable
 */
export function localTopicCheck(input: string): boolean {
  const offensivePatterns = [
    /how\s+to\s+(hack|exploit|attack|breach|compromise)/i,
    /write\s+(me\s+)?(a\s+)?(malware|virus|trojan|ransomware|exploit)/i,
    /create\s+(a\s+)?(backdoor|rootkit|keylogger)/i,
    /(reverse|bind)\s+shell/i,
    /sql\s+injection\s+(payload|attack)/i,
    /xss\s+(payload|attack|script)/i,
    /privilege\s+escalation\s+(exploit|technique)/i,
  ];

  return !offensivePatterns.some((pattern) => pattern.test(input));
}
