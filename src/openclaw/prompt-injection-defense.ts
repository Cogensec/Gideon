import { v4 as uuidv4 } from 'uuid';
import {
  InjectionScanResult,
  InjectionType,
  OpenClawSidecarConfig,
} from './types';
import { checkJailbreak, localJailbreakCheck } from '../utils/nemo-guardrails';

// ============================================================================
// Prompt Injection Defense Layer (Workstream 3)
// Protects OpenClaw agents from indirect prompt injection attacks
// ============================================================================

/**
 * CSS-hidden instruction patterns (CVE-2026-22708)
 * Attackers embed instructions in web pages using CSS to make them invisible
 * to users but readable by the agent's web scraper.
 */
const CSS_HIDDEN_PATTERNS = [
  // display:none with content
  /style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // visibility:hidden
  /style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // font-size:0
  /style\s*=\s*["'][^"']*font-size\s*:\s*0[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // opacity:0
  /style\s*=\s*["'][^"']*opacity\s*:\s*0[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // position:absolute with off-screen placement
  /style\s*=\s*["'][^"']*position\s*:\s*absolute[^"']*(?:left|top)\s*:\s*-\d{4,}[^"']*["'][^>]*>[^<]+/i,
  // height:0 / width:0 overflow:hidden
  /style\s*=\s*["'][^"']*(?:height|width)\s*:\s*0[^"']*overflow\s*:\s*hidden[^"']*["'][^>]*>[^<]+/i,
  // CSS class-based hiding (common in attacks)
  /class\s*=\s*["'][^"']*(?:hidden|invisible|sr-only|visually-hidden|d-none|hide)[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke)/i,
];

/**
 * Unicode obfuscation patterns
 * Attackers use Unicode tricks to hide instructions
 */
const UNICODE_OBFUSCATION_PATTERNS = [
  // Right-to-left override (U+202E)
  /\u202E/,
  // Left-to-right override (U+202D)
  /\u202D/,
  // Zero-width space (U+200B)
  /\u200B{3,}/,
  // Zero-width non-joiner (U+200C)
  /\u200C{3,}/,
  // Zero-width joiner (U+200D)
  /\u200D{3,}/,
  // Word joiner (U+2060)
  /\u2060{3,}/,
  // Invisible separator (U+2063)
  /\u2063{3,}/,
  // Tag characters (U+E0001-U+E007F) used for steganography
  /[\uE0001-\uE007F]{3,}/,
  // Homoglyph mixing (Cyrillic/Latin)
  /(?:[\u0400-\u04FF][\u0041-\u005A\u0061-\u007A]){2,}/,
  /(?:[\u0041-\u005A\u0061-\u007A][\u0400-\u04FF]){2,}/,
];

/**
 * Role override / system prompt manipulation patterns
 */
const ROLE_OVERRIDE_PATTERNS = [
  /(?:^|\n)\s*(?:system|assistant|human|user)\s*:\s*/im,
  /\[SYSTEM\s*(?:OVERRIDE|PROMPT|MESSAGE)\]/i,
  /\<\|(?:im_start|system|endoftext)\|?\>/i,
  /---\s*BEGIN\s*(?:NEW|UPDATED|REAL)\s*(?:SYSTEM|INSTRUCTIONS?)(?:\s*---)?/i,
  /(?:new|updated|real|actual)\s+(?:system\s+)?(?:prompt|instructions?|rules?)\s*:/i,
  /you\s+are\s+now\s+(?:in\s+)?(?:a\s+)?(?:new|different|unrestricted)\s+mode/i,
  /forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions?|rules?|constraints?)/i,
  /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)/i,
  /disregard\s+(?:your\s+)?(?:safety|security|content)\s+(?:guidelines?|rules?|policies?)/i,
];

/**
 * Tool invocation injection patterns
 * Attempts to trick the agent into calling tools via injected content
 */
const TOOL_INVOCATION_PATTERNS = [
  /(?:please\s+)?(?:run|execute|call|invoke|use)\s+(?:the\s+)?(?:exec|shell|terminal|command|bash)\s+(?:tool\s+)?(?:to|and|with)/i,
  /\bexec\s*\(\s*['"][^'"]+['"]\s*\)/i,
  /\bshell_exec\s*\(/i,
  /\bspawn\s*\(\s*['"][^'"]+['"]\s*\)/i,
  /(?:use\s+)?sessions_send\s+(?:to\s+)?/i,
  /(?:create|spawn)\s+(?:a\s+)?new\s+session/i,
];

/**
 * Memory poisoning patterns
 * Instructions that attempt to inject false facts into persistent memory
 */
const MEMORY_POISONING_PATTERNS = [
  /(?:remember|memorize|store|save|record)\s+(?:this|that|the\s+following)\s*:/i,
  /(?:important|critical|urgent)\s+(?:fact|note|information|update)\s*:/i,
  /(?:always|never|from\s+now\s+on)\s+(?:run|execute|use|call)\s+(?:commands?\s+)?(?:without|with)\s+(?:confirmation|approval|asking)/i,
  /(?:your|the)\s+(?:new|updated|correct)\s+(?:api[_\s]?key|token|password|secret)\s+is/i,
  /update\s+(?:your\s+)?(?:memory|knowledge|facts?)\s*:/i,
  /add\s+(?:this\s+)?(?:to|into)\s+(?:your\s+)?(?:long[_\s-]?term\s+)?memory/i,
];

/**
 * Exfiltration instruction patterns
 * Instructions that try to get the agent to send data externally
 */
const EXFILTRATION_INSTRUCTION_PATTERNS = [
  /(?:send|post|upload|transmit|forward|share)\s+(?:all\s+)?(?:the\s+)?(?:data|content|information|files?|credentials?|tokens?|keys?|secrets?)\s+(?:to|at)\s+/i,
  /(?:curl|wget|fetch|http)\s+.*(?:with|containing|including)\s+(?:the\s+)?(?:token|key|password|secret|credential)/i,
  /(?:encode|base64|encrypt)\s+(?:and\s+)?(?:send|post|upload)/i,
  /(?:copy|paste|type)\s+(?:the\s+)?(?:api[_\s]?key|token|password)\s+(?:in|into|to)/i,
];

/**
 * Markdown/delimiter escape patterns
 */
const DELIMITER_ESCAPE_PATTERNS = [
  // Triple backtick escape
  /```\s*(?:system|prompt|override|injection)/i,
  // Markdown heading injection
  /^#{1,3}\s+(?:System|Override|New Instructions)/im,
  // XML-style tag injection
  /<(?:system|prompt|instructions?|override|admin)[^>]*>/i,
  // YAML front matter injection
  /^---\s*\n(?:role|system|mode|instructions?)\s*:/im,
];

/**
 * Prompt Injection Defense - Scans content for injection attacks
 *
 * Provides defense against:
 * - CSS-hidden instructions (CVE-2026-22708)
 * - Unicode obfuscation / steganography
 * - Role override / system prompt manipulation
 * - Tool invocation injection
 * - Memory poisoning attempts
 * - Data exfiltration instructions
 * - Delimiter escape attacks
 *
 * This fills the gap that OpenClaw explicitly declares out of scope.
 */
export class PromptInjectionDefense {
  private config: OpenClawSidecarConfig;
  private scanHistory: InjectionScanResult[] = [];

  constructor(config: OpenClawSidecarConfig) {
    this.config = config;
  }

  /**
   * Scan content for prompt injection attacks
   */
  async scanContent(content: string, source: string): Promise<InjectionScanResult> {
    const threshold = this.config.injectionDefense.confidenceThreshold;
    const results: Array<{
      type: InjectionType;
      confidence: number;
      technique: string;
      payload: string;
    }> = [];

    // 1. CSS-hidden instruction detection (CVE-2026-22708)
    if (this.config.injectionDefense.detectHiddenInstructions) {
      for (const pattern of CSS_HIDDEN_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          results.push({
            type: 'hidden_instruction',
            confidence: 0.9,
            technique: 'CSS-hidden text containing agent instructions',
            payload: match[0].slice(0, 200),
          });
        }
      }
    }

    // 2. Unicode obfuscation
    for (const pattern of UNICODE_OBFUSCATION_PATTERNS) {
      if (pattern.test(content)) {
        results.push({
          type: 'unicode_obfuscation',
          confidence: 0.85,
          technique: 'Unicode control characters or homoglyphs',
          payload: 'Unicode obfuscation detected in content',
        });
        break;
      }
    }

    // 3. Role override
    for (const pattern of ROLE_OVERRIDE_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        results.push({
          type: 'role_override',
          confidence: 0.88,
          technique: 'System prompt override attempt',
          payload: match[0].slice(0, 200),
        });
        break;
      }
    }

    // 4. Tool invocation
    for (const pattern of TOOL_INVOCATION_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        results.push({
          type: 'tool_invocation',
          confidence: 0.8,
          technique: 'Injected tool invocation instruction',
          payload: match[0].slice(0, 200),
        });
        break;
      }
    }

    // 5. Memory poisoning
    for (const pattern of MEMORY_POISONING_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        results.push({
          type: 'memory_poisoning',
          confidence: 0.82,
          technique: 'Attempt to inject false facts into agent memory',
          payload: match[0].slice(0, 200),
        });
        break;
      }
    }

    // 6. Exfiltration instructions
    for (const pattern of EXFILTRATION_INSTRUCTION_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        results.push({
          type: 'exfiltration_instruction',
          confidence: 0.87,
          technique: 'Instruction to exfiltrate data',
          payload: match[0].slice(0, 200),
        });
        break;
      }
    }

    // 7. Delimiter escape
    for (const pattern of DELIMITER_ESCAPE_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        results.push({
          type: 'delimiter_escape',
          confidence: 0.75,
          technique: 'Prompt delimiter escape attempt',
          payload: match[0].slice(0, 200),
        });
        break;
      }
    }

    // 8. NeMo Guardrails jailbreak check (if available)
    try {
      const jailbreakResult = await checkJailbreak(content.slice(0, 2000));
      if (jailbreakResult.isJailbreak && jailbreakResult.confidence > threshold) {
        results.push({
          type: 'role_override',
          confidence: jailbreakResult.confidence,
          technique: `NeMo detected: ${jailbreakResult.attackType || 'jailbreak'}`,
          payload: content.slice(0, 200),
        });
      }
    } catch {
      // Fall back to local jailbreak check
      if (localJailbreakCheck(content)) {
        results.push({
          type: 'role_override',
          confidence: 0.7,
          technique: 'Local pattern-based jailbreak detection',
          payload: content.slice(0, 200),
        });
      }
    }

    // Determine highest-confidence result
    const highConfidence = results.filter(r => r.confidence >= threshold);

    if (highConfidence.length > 0) {
      // Pick the highest confidence finding
      highConfidence.sort((a, b) => b.confidence - a.confidence);
      const top = highConfidence[0];

      const scanResult: InjectionScanResult = {
        isInjection: true,
        confidence: top.confidence,
        injectionType: top.type,
        technique: top.technique,
        payload: top.payload,
        source,
        sanitizedContent: this.sanitizeContent(content, results),
      };

      this.scanHistory.push(scanResult);
      return scanResult;
    }

    const cleanResult: InjectionScanResult = {
      isInjection: false,
      confidence: 0,
      source,
    };

    this.scanHistory.push(cleanResult);
    return cleanResult;
  }

  /**
   * Scan web page content specifically (HTML)
   */
  async scanWebContent(html: string, url: string): Promise<InjectionScanResult> {
    if (!this.config.injectionDefense.scanWebContent) {
      return { isInjection: false, confidence: 0, source: url };
    }

    // Strip HTML tags but preserve hidden content for analysis
    const hiddenContent = this.extractHiddenContent(html);
    const visibleContent = this.stripHtml(html);

    // Scan the hidden content specifically
    if (hiddenContent.length > 0) {
      const hiddenResult = await this.scanContent(hiddenContent, `${url} [hidden]`);
      if (hiddenResult.isInjection) {
        return hiddenResult;
      }
    }

    // Scan the full HTML for injection patterns
    return this.scanContent(html, url);
  }

  /**
   * Scan an incoming chat message
   */
  async scanMessage(message: string, channelId: string): Promise<InjectionScanResult> {
    if (!this.config.injectionDefense.scanMessages) {
      return { isInjection: false, confidence: 0, source: channelId };
    }
    return this.scanContent(message, `channel:${channelId}`);
  }

  /**
   * Extract content from hidden HTML elements
   */
  private extractHiddenContent(html: string): string {
    const hiddenParts: string[] = [];

    // Extract content from elements with hiding styles
    const hiddenPatterns = [
      /style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([^<]+)/gi,
      /style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>([^<]+)/gi,
      /style\s*=\s*["'][^"']*font-size\s*:\s*0[^"']*["'][^>]*>([^<]+)/gi,
      /style\s*=\s*["'][^"']*opacity\s*:\s*0[^"']*["'][^>]*>([^<]+)/gi,
      /class\s*=\s*["'][^"']*(?:hidden|invisible|sr-only|d-none)[^"']*["'][^>]*>([^<]+)/gi,
    ];

    for (const pattern of hiddenPatterns) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(html)) !== null) {
        if (match[1] && match[1].trim().length > 5) {
          hiddenParts.push(match[1].trim());
        }
      }
    }

    return hiddenParts.join('\n');
  }

  /**
   * Strip HTML tags to get visible text
   */
  private stripHtml(html: string): string {
    return html
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Sanitize content by removing detected injection payloads
   */
  private sanitizeContent(
    content: string,
    detections: Array<{ type: InjectionType; payload: string }>,
  ): string {
    let sanitized = content;

    // Remove hidden HTML elements
    sanitized = sanitized.replace(
      /(<[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^"']*["'][^>]*>)([^<]*?)(<\/[^>]+>)/gi,
      '$1[REDACTED BY GIDEON]$3',
    );

    // Remove Unicode control characters
    sanitized = sanitized.replace(/[\u200B-\u200D\u2060\u2063\u202D\u202E\uFEFF]/g, '');

    // Remove role override patterns
    sanitized = sanitized.replace(
      /(?:^|\n)\s*(?:system|assistant)\s*:\s*[^\n]+/gim,
      '\n[INJECTION ATTEMPT REMOVED BY GIDEON]',
    );

    return sanitized;
  }

  /**
   * Get scan statistics
   */
  getStats(): {
    totalScans: number;
    detectionsFound: number;
    detectionRate: number;
    byType: Record<string, number>;
    bySource: Record<string, number>;
  } {
    const byType: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    let detectionsFound = 0;

    for (const result of this.scanHistory) {
      if (result.isInjection) {
        detectionsFound++;
        if (result.injectionType) {
          byType[result.injectionType] = (byType[result.injectionType] || 0) + 1;
        }
      }
      const sourceKey = result.source.split('/')[0] || result.source;
      bySource[sourceKey] = (bySource[sourceKey] || 0) + 1;
    }

    return {
      totalScans: this.scanHistory.length,
      detectionsFound,
      detectionRate: this.scanHistory.length > 0 ? detectionsFound / this.scanHistory.length : 0,
      byType,
      bySource,
    };
  }

  /**
   * Get recent scan results
   */
  getRecentScans(limit: number = 50): InjectionScanResult[] {
    return this.scanHistory.slice(-limit);
  }
}
