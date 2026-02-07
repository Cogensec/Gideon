import { createHash } from 'crypto';
import { existsSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import {
  MemoryIntegrityResult,
  MemorySuspiciousEntry,
  AlertSeverity,
  OpenClawSidecarConfig,
} from './types';

// ============================================================================
// Memory Integrity Monitor
// Scans OpenClaw memory files for poisoning and tampering
// ============================================================================

/**
 * Patterns that indicate memory poisoning attempts.
 * These are instructions disguised as facts that an attacker injects
 * via web scraping, email, or messaging to manipulate agent behavior.
 */
const MEMORY_POISONING_INDICATORS = [
  // Instructions masquerading as facts
  {
    pattern: /(?:always|never)\s+(?:run|execute|call|use)\s+(?:commands?\s+)?(?:without|with)\s+(?:confirmation|approval|asking)/i,
    reason: 'Instruction to bypass execution approvals disguised as a fact',
    severity: 'critical' as AlertSeverity,
  },
  {
    pattern: /(?:your|the)\s+(?:new|updated|correct|real)\s+(?:api[_\s-]?key|token|password|secret|credential)\s+(?:is|=|:)\s+/i,
    reason: 'Attempt to inject false credentials into memory',
    severity: 'critical' as AlertSeverity,
  },
  {
    pattern: /(?:send|forward|copy|upload)\s+(?:all\s+)?(?:data|files?|conversations?|messages?|history)\s+to\s+/i,
    reason: 'Exfiltration instruction stored as memory entry',
    severity: 'critical' as AlertSeverity,
  },
  {
    pattern: /(?:disable|turn\s+off|remove)\s+(?:security|safety|sandboxing|docker|approval|verification)/i,
    reason: 'Instruction to disable security controls',
    severity: 'critical' as AlertSeverity,
  },
  {
    pattern: /(?:ignore|disregard|override|bypass)\s+(?:security|policy|rules?|restrictions?|limitations?|guardrails?)/i,
    reason: 'Instruction to bypass security policies',
    severity: 'high' as AlertSeverity,
  },
  {
    pattern: /(?:trust|allow|whitelist|approve)\s+(?:all|any)\s+(?:requests?|commands?|sessions?|connections?)/i,
    reason: 'Instruction to weaken trust controls',
    severity: 'high' as AlertSeverity,
  },
  // Suspicious URL/endpoint injection
  {
    pattern: /(?:webhook|endpoint|server|url)\s*(?:is|=|:)\s*https?:\/\/(?!(?:api\.anthropic|api\.openai|api\.openclaw))/i,
    reason: 'External endpoint injected into memory',
    severity: 'high' as AlertSeverity,
  },
  // Role manipulation
  {
    pattern: /you\s+are\s+(?:now|actually|really)\s+(?:a|an|in)\s+(?:unrestricted|admin|root|superuser|god)\s+mode/i,
    reason: 'Role manipulation instruction in memory',
    severity: 'high' as AlertSeverity,
  },
  // Session credentials
  {
    pattern: /(?:session|gateway)\s+(?:token|key|secret|password)\s*(?:is|=|:)\s*[a-zA-Z0-9\-_]{16,}/i,
    reason: 'Session credentials stored in memory (potential poisoning or exposure)',
    severity: 'high' as AlertSeverity,
  },
  // Persistence instructions
  {
    pattern: /(?:every\s+time|on\s+(?:start|boot|init))\s+(?:run|execute|call|send)\s+/i,
    reason: 'Persistence instruction (triggers action on every session start)',
    severity: 'medium' as AlertSeverity,
  },
  // Behavior modification
  {
    pattern: /(?:from\s+now\s+on|going\s+forward|henceforth)\s+(?:always|never|do\s+not|don'?t)\s+/i,
    reason: 'Persistent behavior modification instruction',
    severity: 'medium' as AlertSeverity,
  },
];

/**
 * Memory Integrity Monitor - Scans OpenClaw memory for poisoning
 *
 * OpenClaw stores persistent memory in:
 * - memory/YYYY-MM-DD.md (daily ephemeral memory)
 * - MEMORY.md (long-term curated memory)
 * - Session transcripts in ~/.openclaw/agents/<agentId>/sessions/*.jsonl
 *
 * Attackers can inject malicious "facts" via:
 * - Web pages scraped by the browser tool (CVE-2026-22708)
 * - Incoming messages from untrusted senders
 * - Email content
 * - Poisoned skill outputs
 *
 * These poisoned memories persist across sessions, creating
 * delayed-execution attacks that trigger days or weeks later.
 */
export class MemoryIntegrityMonitor {
  private config: OpenClawSidecarConfig;
  private openclawHome: string;
  private baselineHashes: Map<string, string> = new Map();
  private scanHistory: MemoryIntegrityResult[] = [];

  constructor(config: OpenClawSidecarConfig) {
    this.config = config;
    this.openclawHome = config.gateway.openclawHome.replace(/^~/, process.env.HOME || '/root');
  }

  /**
   * Scan a memory file for poisoning indicators
   */
  scanMemoryFile(filePath: string, content: string): MemoryIntegrityResult {
    const lines = content.split('\n');
    const suspiciousEntries: MemorySuspiciousEntry[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#') || line.startsWith('---')) continue;

      for (const indicator of MEMORY_POISONING_INDICATORS) {
        if (indicator.pattern.test(line)) {
          suspiciousEntries.push({
            lineNumber: i + 1,
            content: line.slice(0, 200),
            reason: indicator.reason,
            severity: indicator.severity,
            confidence: 0.8,
          });
          break; // One finding per line
        }
      }
    }

    // Check for content that contradicts typical memory patterns
    const contradictions = this.detectContradictions(lines);
    suspiciousEntries.push(...contradictions);

    // Calculate integrity score
    const totalLines = lines.filter(l => l.trim() && !l.startsWith('#')).length;
    const suspiciousRatio = totalLines > 0 ? suspiciousEntries.length / totalLines : 0;
    const integrityScore = Math.max(0, Math.round(100 - suspiciousRatio * 100 * 5));

    const result: MemoryIntegrityResult = {
      file: filePath,
      totalEntries: totalLines,
      suspiciousEntries,
      integrityScore,
      scannedAt: new Date().toISOString(),
    };

    this.scanHistory.push(result);
    return result;
  }

  /**
   * Scan a single memory entry (e.g., before it gets written)
   */
  scanMemoryEntry(entry: string, source: string): MemorySuspiciousEntry | null {
    for (const indicator of MEMORY_POISONING_INDICATORS) {
      if (indicator.pattern.test(entry)) {
        return {
          lineNumber: 0,
          content: entry.slice(0, 200),
          reason: `${indicator.reason} (source: ${source})`,
          severity: indicator.severity,
          confidence: 0.8,
        };
      }
    }
    return null;
  }

  /**
   * Scan all memory files in the OpenClaw installation
   */
  scanAllMemoryFiles(): MemoryIntegrityResult[] {
    const results: MemoryIntegrityResult[] = [];
    const resolvedHome = resolve(this.openclawHome);

    // Scan memory directory
    const memoryDir = join(resolvedHome, 'memory');
    if (existsSync(memoryDir)) {
      try {
        const { readdirSync } = require('fs');
        const files = readdirSync(memoryDir) as string[];
        for (const file of files) {
          if (file.endsWith('.md')) {
            const filePath = join(memoryDir, file);
            const content = readFileSync(filePath, 'utf-8');
            results.push(this.scanMemoryFile(filePath, content));
          }
        }
      } catch {
        // Permission denied or other errors
      }
    }

    // Scan MEMORY.md in project root
    const memoryMd = join(resolvedHome, 'MEMORY.md');
    if (existsSync(memoryMd)) {
      try {
        const content = readFileSync(memoryMd, 'utf-8');
        results.push(this.scanMemoryFile(memoryMd, content));
      } catch {
        // Permission denied
      }
    }

    return results;
  }

  /**
   * Establish a baseline hash for memory files
   * Used for detecting unauthorized modifications
   */
  setBaseline(filePath: string, content: string): void {
    const hash = createHash('sha256').update(content).digest('hex');
    this.baselineHashes.set(filePath, hash);
  }

  /**
   * Check if a memory file has been modified since baseline
   */
  checkBaseline(filePath: string, content: string): {
    modified: boolean;
    baselineHash?: string;
    currentHash: string;
  } {
    const currentHash = createHash('sha256').update(content).digest('hex');
    const baselineHash = this.baselineHashes.get(filePath);

    return {
      modified: baselineHash !== undefined && baselineHash !== currentHash,
      baselineHash,
      currentHash,
    };
  }

  /**
   * Detect contradictions in memory entries
   * (e.g., "always run without confirmation" vs normal safety patterns)
   */
  private detectContradictions(lines: string[]): MemorySuspiciousEntry[] {
    const contradictions: MemorySuspiciousEntry[] = [];

    // Look for lines that contradict safety-first patterns
    const safetyContradictions = [
      {
        pattern: /(?:do\s+not|don'?t|never)\s+(?:ask|prompt|confirm|verify|check|validate)/i,
        reason: 'Memory entry instructs agent to skip safety verifications',
      },
      {
        pattern: /(?:auto-?approve|auto-?accept|auto-?run|auto-?execute)\s+(?:all|everything|any)/i,
        reason: 'Memory entry instructs automatic approval of all actions',
      },
      {
        pattern: /(?:admin|root|superuser|unlimited)\s+(?:access|permission|privilege)/i,
        reason: 'Memory entry claims elevated privileges',
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      for (const { pattern, reason } of safetyContradictions) {
        if (pattern.test(line)) {
          contradictions.push({
            lineNumber: i + 1,
            content: line.slice(0, 200),
            reason,
            severity: 'high',
            confidence: 0.75,
          });
          break;
        }
      }
    }

    return contradictions;
  }

  /**
   * Get scan history
   */
  getScanHistory(): MemoryIntegrityResult[] {
    return [...this.scanHistory];
  }

  /**
   * Get statistics
   */
  getStats(): {
    totalScans: number;
    totalSuspiciousEntries: number;
    avgIntegrityScore: number;
    bySeverity: Record<string, number>;
  } {
    const bySeverity: Record<string, number> = {};
    let totalSuspicious = 0;
    let totalScore = 0;

    for (const result of this.scanHistory) {
      totalScore += result.integrityScore;
      for (const entry of result.suspiciousEntries) {
        totalSuspicious++;
        bySeverity[entry.severity] = (bySeverity[entry.severity] || 0) + 1;
      }
    }

    return {
      totalScans: this.scanHistory.length,
      totalSuspiciousEntries: totalSuspicious,
      avgIntegrityScore: this.scanHistory.length > 0 ? totalScore / this.scanHistory.length : 100,
      bySeverity,
    };
  }
}
