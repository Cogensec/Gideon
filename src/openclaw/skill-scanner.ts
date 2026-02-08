import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import {
  SkillScanResult,
  SkillFinding,
  IOCHit,
  PublisherAnalysis,
  SkillRiskLevel,
  AlertSeverity,
  OpenClawSidecarConfig,
  KNOWN_MALICIOUS_CAMPAIGNS,
} from './types';

// ============================================================================
// ClawHub Skill Scanner (Workstream 2)
// Automated security vetting of ClawHub skills before installation
// ============================================================================

/** AMOS (Atomic macOS Stealer) installer patterns - primary ClawHavoc payload */
const AMOS_PATTERNS = [
  /osascript\s+-e\s+.*display\s+dialog/i,
  /osascript\s+-e\s+.*System\s+Events/i,
  /\/tmp\/\..*\.sh/i,
  /curl.*-o\s+\/tmp\//i,
  /ditto\s+.*-V\s+.*\.app/i,
  /xattr\s+-d\s+com\.apple\.quarantine/i,
  /spctl\s+--master-disable/i,
  /security\s+delete-certificate/i,
];

/** Reverse shell patterns */
const REVERSE_SHELL_PATTERNS = [
  /\/dev\/tcp\//i,
  /\/dev\/udp\//i,
  /mkfifo\s+\/tmp\//i,
  /nc\s+-e\s+\/bin\/(ba)?sh/i,
  /ncat\s+.*-e/i,
  /python.*socket.*connect.*subprocess/i,
  /ruby.*TCPSocket.*exec/i,
  /perl.*socket.*exec/i,
  /bash\s+-i\s+>&?\s+\/dev\/tcp/i,
  /socat\s+exec/i,
  /telnet\s+.*\|\s*\/bin/i,
];

/** Credential harvesting patterns targeting OpenClaw */
const CREDENTIAL_HARVESTING_PATTERNS = [
  /readFileSync.*\.openclaw.*credential/i,
  /readFileSync.*\.openclaw.*auth-profile/i,
  /readFileSync.*\.openclaw.*sessions\.json/i,
  /readFileSync.*\.openclaw.*gateway/i,
  /process\.env\s*\[\s*['"]OPENCLAW_GATEWAY_TOKEN/i,
  /process\.env\s*\[\s*['"]ANTHROPIC_API_KEY/i,
  /process\.env\s*\[\s*['"]OPENAI_API_KEY/i,
  /process\.env\s*\[\s*['"]DEEPSEEK_API_KEY/i,
  /fs\.(readFile|readFileSync).*config.*token/i,
  /fs\.(readFile|readFileSync).*\.env/i,
  /keychain|keytar|node-keytar/i,
];

/** Code obfuscation patterns */
const OBFUSCATION_PATTERNS = [
  // Base64 encoded payloads
  /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]\s*,\s*['"]base64['"]\s*\)/,
  /atob\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]\s*\)/,
  // Hex encoded strings
  /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/,
  // Unicode escape sequences
  /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}/,
  // String concatenation obfuscation
  /\[['"][a-z]['"](?:\s*\+\s*['"][a-z]['"]){5,}\]/i,
  // eval chains
  /eval\s*\(\s*(?:unescape|decodeURI|atob|Buffer\.from)/i,
  // Function constructor
  /new\s+Function\s*\(\s*['"].*['"],?\s*\)/,
  // Dynamic require/import
  /require\s*\(\s*(?:atob|Buffer\.from|decodeURI)/i,
];

/** Suspicious prerequisite install commands */
const SUSPICIOUS_PREREQUISITES = [
  /brew\s+install\s+(?!node|npm|pnpm|yarn|git)/i,
  /pip\s+install\s+/i,
  /curl.*\|\s*(ba)?sh/i,
  /wget.*\|\s*(ba)?sh/i,
  /npx\s+.*@(?!openclaw)/i,
  /apt-get\s+install/i,
  /yum\s+install/i,
  /pacman\s+-S/i,
  /gem\s+install/i,
  /cargo\s+install/i,
];

/** Data exfiltration in skill code */
const SKILL_EXFIL_PATTERNS = [
  /fetch\s*\(\s*['"]https?:\/\/(?!(?:api\.openclaw|api\.anthropic|api\.openai))/i,
  /axios\s*\.\s*(?:post|put)\s*\(\s*['"]https?:\/\//i,
  /XMLHttpRequest/i,
  /\.send\s*\(\s*JSON\.stringify/i,
  /webhook\.site/i,
  /requestbin/i,
  /ngrok\.io/i,
  /pipedream/i,
];

/** Known malicious package names / typosquats */
const KNOWN_TYPOSQUATS = [
  /^openclaw-cli$/i,     // Official is 'openclaw'
  /^opneclaw/i,          // Typo
  /^openclaww/i,         // Typo
  /^opencl4w/i,          // Leetspeak
  /^0penclaw/i,          // Zero substitution
  /^clawdbot-cli$/i,     // Deprecated name
  /^moltbot-cli$/i,      // Deprecated name
  /^clawdbot-update/i,   // Fake updater
  /^openclaw-update/i,   // Fake updater
  /^openclaw-auto/i,     // Fake auto-updater
];

/** Permission combinations that indicate overreach */
const DANGEROUS_PERMISSION_COMBOS = [
  { tools: ['exec', 'write', 'sessions_send'], reason: 'Can execute code, write files, and send messages - full compromise chain' },
  { tools: ['exec', 'read', 'browser'], reason: 'Can execute code, read files, and browse web - data exfiltration chain' },
  { tools: ['exec', 'gateway'], reason: 'Can execute code and access gateway controls - administrative takeover' },
  { tools: ['write', 'cron'], reason: 'Can write files and create scheduled tasks - persistence mechanism' },
];

/**
 * ClawHub Skill Scanner - Scans OpenClaw skills for security threats
 *
 * Detects:
 * - Known malicious patterns (AMOS, reverse shells, keyloggers)
 * - Code obfuscation (base64, hex, eval chains)
 * - Credential harvesting from OpenClaw config files
 * - Suspicious prerequisites (installs unrelated binaries)
 * - Permission overreach (dangerous tool combinations)
 * - Typosquatting of official package names
 * - Data exfiltration endpoints
 * - Known malware campaigns (ClawHavoc)
 * - Publisher reputation analysis
 */
export class SkillScanner {
  private config: OpenClawSidecarConfig;
  private knownMaliciousHashes: Set<string> = new Set();
  private scanHistory: SkillScanResult[] = [];

  constructor(config: OpenClawSidecarConfig) {
    this.config = config;
  }

  /**
   * Scan a skill's source code for security threats
   */
  async scanSkill(params: {
    name: string;
    path: string;
    files: Array<{ path: string; content: string }>;
    packageJson?: Record<string, any>;
    manifest?: Record<string, any>;
    publisherInfo?: {
      username: string;
      accountCreated?: string;
      totalPublishedSkills?: number;
    };
  }): Promise<SkillScanResult> {
    const startTime = Date.now();
    const findings: SkillFinding[] = [];
    const iocHits: IOCHit[] = [];

    // 1. Check for typosquatting
    findings.push(...this.checkTyposquatting(params.name));

    // 2. Scan all source files
    for (const file of params.files) {
      findings.push(...this.scanFileContent(file.path, file.content));
    }

    // 3. Check package.json for suspicious dependencies/scripts
    if (params.packageJson) {
      findings.push(...this.scanPackageJson(params.packageJson, params.name));
    }

    // 4. Check manifest for permission overreach
    if (params.manifest) {
      findings.push(...this.checkPermissionOverreach(params.manifest));
    }

    // 5. Extract and check IOCs
    if (this.config.skillScanner.checkIOCs) {
      const extractedIOCs = this.extractIOCs(params.files);
      iocHits.push(...extractedIOCs);
    }

    // 6. Publisher analysis
    const publisherAnalysis = this.analyzePublisher(params.publisherInfo);

    // 7. Check against known malicious hashes
    for (const file of params.files) {
      const hash = createHash('sha256').update(file.content).digest('hex');
      if (this.knownMaliciousHashes.has(hash)) {
        findings.push({
          type: 'known_malware',
          severity: 'critical',
          description: `File matches known malware signature (SHA-256: ${hash.slice(0, 16)}...)`,
          file: file.path,
          matchedPattern: hash,
          confidence: 1.0,
        });
      }
    }

    // Calculate risk score
    const { riskLevel, score } = this.calculateRiskScore(findings, iocHits, publisherAnalysis);

    const result: SkillScanResult = {
      skillName: params.name,
      skillPath: params.path,
      riskLevel,
      score,
      findings,
      iocHits,
      publisherAnalysis,
      scannedAt: new Date().toISOString(),
      scanDurationMs: Date.now() - startTime,
    };

    this.scanHistory.push(result);
    return result;
  }

  /**
   * Scan a single file's content for threats
   */
  private scanFileContent(filePath: string, content: string): SkillFinding[] {
    const findings: SkillFinding[] = [];

    const patternSets: Array<{
      patterns: RegExp[];
      type: SkillFinding['type'];
      severity: AlertSeverity;
      description: string;
    }> = [
      {
        patterns: AMOS_PATTERNS,
        type: 'known_malware',
        severity: 'critical',
        description: 'Atomic macOS Stealer (AMOS) installer pattern - primary ClawHavoc payload',
      },
      {
        patterns: REVERSE_SHELL_PATTERNS,
        type: 'malicious_pattern',
        severity: 'critical',
        description: 'Reverse shell pattern detected',
      },
      {
        patterns: CREDENTIAL_HARVESTING_PATTERNS,
        type: 'credential_harvesting',
        severity: 'critical',
        description: 'Credential harvesting targeting OpenClaw configuration',
      },
      {
        patterns: OBFUSCATION_PATTERNS,
        type: 'obfuscation',
        severity: 'high',
        description: 'Code obfuscation detected - may hide malicious payload',
      },
      {
        patterns: SUSPICIOUS_PREREQUISITES,
        type: 'suspicious_prerequisite',
        severity: 'high',
        description: 'Suspicious prerequisite installation (installs unrelated binary)',
      },
      {
        patterns: SKILL_EXFIL_PATTERNS,
        type: 'data_exfiltration',
        severity: 'high',
        description: 'Outbound data transmission to external endpoint',
      },
    ];

    const lines = content.split('\n');

    for (const { patterns, type, severity, description } of patternSets) {
      for (const pattern of patterns) {
        for (let i = 0; i < lines.length; i++) {
          const match = lines[i].match(pattern);
          if (match) {
            findings.push({
              type,
              severity,
              description,
              file: filePath,
              line: i + 1,
              matchedPattern: match[0].slice(0, 100),
              confidence: type === 'known_malware' ? 0.95 : 0.85,
            });
            break; // One finding per pattern per file
          }
        }
      }
    }

    return findings;
  }

  /**
   * Check skill name for typosquatting
   */
  private checkTyposquatting(name: string): SkillFinding[] {
    for (const pattern of KNOWN_TYPOSQUATS) {
      if (pattern.test(name)) {
        return [{
          type: 'typosquat',
          severity: 'critical',
          description: `Skill name "${name}" matches known typosquatting pattern of official packages`,
          file: 'package.json',
          matchedPattern: name,
          confidence: 0.9,
        }];
      }
    }
    return [];
  }

  /**
   * Scan package.json for suspicious entries
   */
  private scanPackageJson(pkg: Record<string, any>, skillName: string): SkillFinding[] {
    const findings: SkillFinding[] = [];

    // Check lifecycle scripts
    const dangerousScripts = ['preinstall', 'postinstall', 'preuninstall', 'prepublish'];
    const scripts = pkg.scripts || {};

    for (const scriptName of dangerousScripts) {
      if (scripts[scriptName]) {
        const scriptContent = scripts[scriptName];
        // Check if script does anything beyond normal build tasks
        if (/curl|wget|nc|bash|sh|python|eval|exec/i.test(scriptContent)) {
          findings.push({
            type: 'malicious_pattern',
            severity: 'high',
            description: `Suspicious ${scriptName} script: "${scriptContent.slice(0, 100)}"`,
            file: 'package.json',
            matchedPattern: scriptContent.slice(0, 100),
            confidence: 0.8,
          });
        }
      }
    }

    // Check for suspicious dependencies
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.optionalDependencies,
    };

    const suspiciousDeps = ['node-keytar', 'keytar', 'clipboardy', 'node-screenshot', 'screenshot-desktop'];
    for (const [dep, version] of Object.entries(allDeps || {})) {
      if (suspiciousDeps.includes(dep)) {
        findings.push({
          type: 'suspicious_prerequisite',
          severity: 'medium',
          description: `Suspicious dependency: ${dep}@${version} - commonly used for credential theft or surveillance`,
          file: 'package.json',
          matchedPattern: `${dep}@${version}`,
          confidence: 0.7,
        });
      }
    }

    return findings;
  }

  /**
   * Check manifest for dangerous permission combinations
   */
  private checkPermissionOverreach(manifest: Record<string, any>): SkillFinding[] {
    const findings: SkillFinding[] = [];
    const requestedTools: string[] = manifest.tools || manifest.permissions || [];

    for (const combo of DANGEROUS_PERMISSION_COMBOS) {
      const hasAll = combo.tools.every(t => requestedTools.includes(t));
      if (hasAll) {
        findings.push({
          type: 'permission_overreach',
          severity: 'high',
          description: `Dangerous permission combination: [${combo.tools.join(', ')}]. ${combo.reason}`,
          file: 'manifest.json',
          matchedPattern: combo.tools.join(', '),
          confidence: 0.85,
        });
      }
    }

    return findings;
  }

  /**
   * Extract IOCs (URLs, domains, IPs, hashes) from skill files
   */
  private extractIOCs(files: Array<{ path: string; content: string }>): IOCHit[] {
    const hits: IOCHit[] = [];
    const seen = new Set<string>();

    const urlPattern = /https?:\/\/[^\s'")\]>}{]+/gi;
    const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

    // Known malicious domains from ClawHavoc and other campaigns
    const maliciousDomains = [
      'webhook.site', 'requestbin.com', 'hookbin.com', 'pipedream.net',
      'interact.sh', 'oast.fun', 'canarytokens.com', 'burpcollaborator.net',
      'ngrok.io', 'serveo.net', 'localhost.run',
    ];

    for (const file of files) {
      const urls = file.content.match(urlPattern) || [];
      for (const url of urls) {
        if (seen.has(url)) continue;
        seen.add(url);

        const isMalicious = maliciousDomains.some(d => url.includes(d));
        if (isMalicious) {
          hits.push({
            indicator: url,
            type: 'url',
            source: file.path,
            malicious: true,
            details: `URL contains known malicious/exfiltration domain`,
          });
        }
      }

      const ips = file.content.match(ipPattern) || [];
      for (const ip of ips) {
        if (seen.has(ip)) continue;
        seen.add(ip);

        // Skip private ranges
        if (ip.startsWith('127.') || ip.startsWith('10.') ||
            ip.startsWith('192.168.') || ip.startsWith('172.16.')) continue;

        hits.push({
          indicator: ip,
          type: 'ip',
          source: file.path,
          malicious: false, // Would need VT/AbuseIPDB lookup
          details: 'Public IP found in skill code - verify legitimacy',
        });
      }
    }

    return hits;
  }

  /**
   * Analyze publisher reputation
   */
  private analyzePublisher(publisherInfo?: {
    username: string;
    accountCreated?: string;
    totalPublishedSkills?: number;
  }): PublisherAnalysis {
    if (!publisherInfo) {
      return {
        accountAge: 0,
        totalSkills: 0,
        publishingVelocity: 0,
        hasVerifiedEmail: false,
        suspiciousIndicators: ['No publisher information available'],
        riskScore: 50,
      };
    }

    const indicators: string[] = [];
    let riskScore = 0;

    // Account age
    const accountAge = publisherInfo.accountCreated
      ? Math.floor((Date.now() - new Date(publisherInfo.accountCreated).getTime()) / (1000 * 60 * 60 * 24))
      : 0;

    if (accountAge < 7) {
      indicators.push('Account less than 7 days old (minimum ClawHub requirement)');
      riskScore += 40;
    } else if (accountAge < 30) {
      indicators.push('Account less than 30 days old');
      riskScore += 20;
    }

    // Publishing velocity
    const totalSkills = publisherInfo.totalPublishedSkills || 0;
    const velocity = accountAge > 0 ? totalSkills / accountAge : totalSkills;

    if (velocity > 5) {
      indicators.push(`Extremely high publishing velocity: ${velocity.toFixed(1)} skills/day`);
      riskScore += 35;
    } else if (velocity > 2) {
      indicators.push(`High publishing velocity: ${velocity.toFixed(1)} skills/day`);
      riskScore += 15;
    }

    // Skill count
    if (totalSkills > 50 && accountAge < 30) {
      indicators.push('Mass publisher with new account - matches ClawHavoc campaign pattern');
      riskScore += 30;
    }

    return {
      accountAge,
      totalSkills,
      publishingVelocity: velocity,
      hasVerifiedEmail: false, // Would need API check
      suspiciousIndicators: indicators,
      riskScore: Math.min(100, riskScore),
    };
  }

  /**
   * Calculate overall risk score and level
   */
  private calculateRiskScore(
    findings: SkillFinding[],
    iocHits: IOCHit[],
    publisher: PublisherAnalysis,
  ): { riskLevel: SkillRiskLevel; score: number } {
    let score = 0;

    // Findings-based scoring
    for (const finding of findings) {
      switch (finding.severity) {
        case 'critical': score += 40; break;
        case 'high': score += 25; break;
        case 'medium': score += 10; break;
        case 'low': score += 5; break;
      }
    }

    // IOC-based scoring
    for (const hit of iocHits) {
      if (hit.malicious) score += 30;
      else score += 5;
    }

    // Publisher risk
    score += publisher.riskScore * 0.3;

    score = Math.min(100, Math.round(score));

    const riskLevel: SkillRiskLevel =
      score >= 80 ? 'critical' :
      score >= 60 ? 'high' :
      score >= 40 ? 'medium' :
      score >= 20 ? 'low' : 'clean';

    return { riskLevel, score };
  }

  /**
   * Add known malicious file hashes to the database
   */
  addMaliciousHashes(hashes: string[]): void {
    for (const hash of hashes) {
      this.knownMaliciousHashes.add(hash.toLowerCase());
    }
  }

  /**
   * Get scan history
   */
  getScanHistory(): SkillScanResult[] {
    return [...this.scanHistory];
  }

  /**
   * Get scanner statistics
   */
  getStats(): {
    totalScans: number;
    criticalSkills: number;
    blockedSkills: number;
    cleanSkills: number;
    totalFindings: number;
    totalIOCHits: number;
  } {
    let criticalSkills = 0;
    let blockedSkills = 0;
    let cleanSkills = 0;
    let totalFindings = 0;
    let totalIOCHits = 0;

    for (const result of this.scanHistory) {
      if (result.riskLevel === 'critical') criticalSkills++;
      if (result.riskLevel === 'critical' || result.riskLevel === 'high') blockedSkills++;
      if (result.riskLevel === 'clean') cleanSkills++;
      totalFindings += result.findings.length;
      totalIOCHits += result.iocHits.length;
    }

    return {
      totalScans: this.scanHistory.length,
      criticalSkills,
      blockedSkills,
      cleanSkills,
      totalFindings,
      totalIOCHits,
    };
  }
}
