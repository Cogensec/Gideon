/**
 * NVIDIA Morpheus Client
 *
 * Client for integrating with NVIDIA Morpheus cybersecurity AI framework.
 * Morpheus provides GPU-accelerated threat detection pipelines including:
 * - Digital Fingerprinting (DFP) for user behavior anomaly detection
 * - DGA Detection for malware domain generation algorithms
 * - Phishing Detection using NLP
 * - Ransomware Detection for behavioral patterns
 *
 * Performance: 208,333+ logs/second with GPU acceleration
 */

export interface MorpheusConfig {
  serverUrl: string;
  enabled: boolean;
  pipelines: {
    digitalFingerprinting: boolean;
    dgaDetection: boolean;
    phishingDetection: boolean;
    ransomwareDetection: boolean;
  };
  thresholds: {
    anomaly: number;
    dga: number;
    phishing: number;
    ransomware: number;
  };
}

export interface Anomaly {
  id: string;
  type: 'user_behavior' | 'network' | 'file_access' | 'authentication' | 'data_exfiltration';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  description: string;
  timestamp: string;
  source?: string;
  details?: Record<string, unknown>;
}

export interface DGAResult {
  domain: string;
  isDGA: boolean;
  confidence: number;
  algorithmType?: string;
  malwareFamily?: string;
}

export interface PhishingResult {
  isPhishing: boolean;
  confidence: number;
  indicators: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

export interface RansomwareResult {
  isRansomware: boolean;
  confidence: number;
  behaviorType?: string;
  affectedPaths?: string[];
}

export interface MorpheusAnalysisResult {
  pipeline: string;
  status: 'success' | 'error' | 'partial';
  processingTimeMs: number;
  recordsProcessed: number;
  threatsDetected: number;
  anomalies: Anomaly[];
  summary: string;
  recommendations: string[];
}

export interface DFPAnalysisResult extends MorpheusAnalysisResult {
  pipeline: 'digital_fingerprinting';
  userProfiles: number;
  baselinePeriod: string;
}

export interface DGAAnalysisResult extends MorpheusAnalysisResult {
  pipeline: 'dga_detection';
  domainsAnalyzed: number;
  dgaDomainsFound: number;
  results: DGAResult[];
}

export interface PhishingAnalysisResult extends MorpheusAnalysisResult {
  pipeline: 'phishing_detection';
  emailsAnalyzed: number;
  phishingDetected: number;
  results: PhishingResult[];
}

export interface RansomwareAnalysisResult extends MorpheusAnalysisResult {
  pipeline: 'ransomware_detection';
  eventsAnalyzed: number;
  ransomwareDetected: boolean;
  results: RansomwareResult[];
}

// Default configuration
const DEFAULT_CONFIG: MorpheusConfig = {
  serverUrl: 'http://localhost:8080',
  enabled: true,
  pipelines: {
    digitalFingerprinting: true,
    dgaDetection: true,
    phishingDetection: true,
    ransomwareDetection: true,
  },
  thresholds: {
    anomaly: 0.7,
    dga: 0.8,
    phishing: 0.75,
    ransomware: 0.85,
  },
};

/**
 * Gets Morpheus configuration from environment
 */
export function getMorpheusConfig(): MorpheusConfig {
  return {
    ...DEFAULT_CONFIG,
    serverUrl: process.env.MORPHEUS_URL || DEFAULT_CONFIG.serverUrl,
    enabled: process.env.MORPHEUS_ENABLED !== 'false',
  };
}

/**
 * Checks if Morpheus server is available
 */
export async function isMorpheusAvailable(): Promise<boolean> {
  const config = getMorpheusConfig();

  if (!config.enabled) {
    return false;
  }

  try {
    const response = await fetch(`${config.serverUrl}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Get available Morpheus pipelines from server
 */
export async function getAvailablePipelines(): Promise<string[]> {
  const config = getMorpheusConfig();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/pipelines`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      return [];
    }

    const data = await response.json();
    return data.pipelines || [];
  } catch {
    return [];
  }
}

/**
 * Analyze logs using Digital Fingerprinting pipeline
 * Detects anomalous user/system behavior patterns
 */
export async function analyzeWithDFP(
  logs: string,
  options?: { userId?: string; timeRange?: string }
): Promise<DFPAnalysisResult> {
  const config = getMorpheusConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/pipelines/dfp/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        logs,
        user_id: options?.userId,
        time_range: options?.timeRange,
        anomaly_threshold: config.thresholds.anomaly,
      }),
    });

    if (!response.ok) {
      return createErrorResult('digital_fingerprinting', `Server error: ${response.statusText}`, startTime);
    }

    const result = await response.json();
    return {
      pipeline: 'digital_fingerprinting',
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: result.records_processed || 0,
      threatsDetected: result.anomalies?.length || 0,
      anomalies: (result.anomalies || []).map(mapAnomaly),
      summary: result.summary || 'Analysis complete',
      recommendations: result.recommendations || [],
      userProfiles: result.user_profiles || 0,
      baselinePeriod: result.baseline_period || 'unknown',
    };
  } catch (error) {
    return createErrorResult('digital_fingerprinting', error instanceof Error ? error.message : String(error), startTime);
  }
}

/**
 * Detect Domain Generation Algorithms (DGA) in domain list
 * Identifies malware-generated domains
 */
export async function detectDGA(domains: string[]): Promise<DGAAnalysisResult> {
  const config = getMorpheusConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/pipelines/dga/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domains,
        confidence_threshold: config.thresholds.dga,
      }),
    });

    if (!response.ok) {
      return createDGAErrorResult(`Server error: ${response.statusText}`, startTime, domains.length);
    }

    const result = await response.json();
    const dgaResults: DGAResult[] = (result.results || []).map((r: Record<string, unknown>) => ({
      domain: String(r.domain || ''),
      isDGA: Boolean(r.is_dga),
      confidence: Number(r.confidence) || 0,
      algorithmType: r.algorithm_type as string | undefined,
      malwareFamily: r.malware_family as string | undefined,
    }));

    const dgaCount = dgaResults.filter(r => r.isDGA).length;

    return {
      pipeline: 'dga_detection',
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: domains.length,
      threatsDetected: dgaCount,
      anomalies: dgaResults.filter(r => r.isDGA).map(r => ({
        id: `dga-${r.domain}`,
        type: 'network' as const,
        severity: r.confidence > 0.9 ? 'critical' : r.confidence > 0.8 ? 'high' : 'medium',
        confidence: r.confidence,
        description: `DGA domain detected: ${r.domain}${r.malwareFamily ? ` (${r.malwareFamily})` : ''}`,
        timestamp: new Date().toISOString(),
      })),
      summary: `Analyzed ${domains.length} domains, found ${dgaCount} potential DGA domains`,
      recommendations: dgaCount > 0 ? [
        'Block identified DGA domains at firewall/DNS level',
        'Investigate systems that queried these domains',
        'Check for malware infections on affected hosts',
      ] : [],
      domainsAnalyzed: domains.length,
      dgaDomainsFound: dgaCount,
      results: dgaResults,
    };
  } catch (error) {
    return createDGAErrorResult(error instanceof Error ? error.message : String(error), startTime, domains.length);
  }
}

/**
 * Detect phishing in email content
 * Uses NLP to identify phishing attempts
 */
export async function detectPhishing(
  emailContent: string,
  options?: { subject?: string; sender?: string; headers?: Record<string, string> }
): Promise<PhishingAnalysisResult> {
  const config = getMorpheusConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/pipelines/phishing/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: emailContent,
        subject: options?.subject,
        sender: options?.sender,
        headers: options?.headers,
        confidence_threshold: config.thresholds.phishing,
      }),
    });

    if (!response.ok) {
      return createPhishingErrorResult(`Server error: ${response.statusText}`, startTime);
    }

    const result = await response.json();
    const phishingResult: PhishingResult = {
      isPhishing: Boolean(result.is_phishing),
      confidence: Number(result.confidence) || 0,
      indicators: result.indicators || [],
      riskLevel: result.risk_level || 'low',
    };

    return {
      pipeline: 'phishing_detection',
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: 1,
      threatsDetected: phishingResult.isPhishing ? 1 : 0,
      anomalies: phishingResult.isPhishing ? [{
        id: `phishing-${Date.now()}`,
        type: 'network' as const,
        severity: phishingResult.riskLevel === 'high' ? 'critical' : phishingResult.riskLevel === 'medium' ? 'high' : 'medium',
        confidence: phishingResult.confidence,
        description: `Phishing email detected with ${phishingResult.indicators.length} indicators`,
        timestamp: new Date().toISOString(),
        details: { indicators: phishingResult.indicators },
      }] : [],
      summary: phishingResult.isPhishing
        ? `Phishing detected with ${(phishingResult.confidence * 100).toFixed(1)}% confidence`
        : 'No phishing indicators detected',
      recommendations: phishingResult.isPhishing ? [
        'Do not click any links in this email',
        'Do not download any attachments',
        'Report this email to your security team',
        'Block the sender domain',
      ] : [],
      emailsAnalyzed: 1,
      phishingDetected: phishingResult.isPhishing ? 1 : 0,
      results: [phishingResult],
    };
  } catch (error) {
    return createPhishingErrorResult(error instanceof Error ? error.message : String(error), startTime);
  }
}

/**
 * Detect ransomware behavior patterns
 * Analyzes file system and process events
 */
export async function detectRansomware(
  events: string,
  options?: { processName?: string; timeWindow?: number }
): Promise<RansomwareAnalysisResult> {
  const config = getMorpheusConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/pipelines/ransomware/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events,
        process_name: options?.processName,
        time_window: options?.timeWindow,
        confidence_threshold: config.thresholds.ransomware,
      }),
    });

    if (!response.ok) {
      return createRansomwareErrorResult(`Server error: ${response.statusText}`, startTime);
    }

    const result = await response.json();
    const ransomwareResult: RansomwareResult = {
      isRansomware: Boolean(result.is_ransomware),
      confidence: Number(result.confidence) || 0,
      behaviorType: result.behavior_type,
      affectedPaths: result.affected_paths || [],
    };

    return {
      pipeline: 'ransomware_detection',
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: result.events_analyzed || 0,
      threatsDetected: ransomwareResult.isRansomware ? 1 : 0,
      anomalies: ransomwareResult.isRansomware ? [{
        id: `ransomware-${Date.now()}`,
        type: 'file_access' as const,
        severity: 'critical',
        confidence: ransomwareResult.confidence,
        description: `Ransomware behavior detected: ${ransomwareResult.behaviorType || 'encryption pattern'}`,
        timestamp: new Date().toISOString(),
        details: { affectedPaths: ransomwareResult.affectedPaths },
      }] : [],
      summary: ransomwareResult.isRansomware
        ? `CRITICAL: Ransomware behavior detected with ${(ransomwareResult.confidence * 100).toFixed(1)}% confidence`
        : 'No ransomware behavior detected',
      recommendations: ransomwareResult.isRansomware ? [
        'IMMEDIATELY isolate affected systems from the network',
        'Do NOT pay the ransom',
        'Preserve system state for forensic analysis',
        'Activate incident response procedures',
        'Contact law enforcement',
      ] : [],
      eventsAnalyzed: result.events_analyzed || 0,
      ransomwareDetected: ransomwareResult.isRansomware,
      results: [ransomwareResult],
    };
  } catch (error) {
    return createRansomwareErrorResult(error instanceof Error ? error.message : String(error), startTime);
  }
}

/**
 * Run comprehensive threat analysis using all available pipelines
 */
export async function runFullAnalysis(
  data: {
    logs?: string;
    domains?: string[];
    email?: string;
    events?: string;
  }
): Promise<{
  dfp?: DFPAnalysisResult;
  dga?: DGAAnalysisResult;
  phishing?: PhishingAnalysisResult;
  ransomware?: RansomwareAnalysisResult;
  summary: string;
  totalThreats: number;
}> {
  const results: {
    dfp?: DFPAnalysisResult;
    dga?: DGAAnalysisResult;
    phishing?: PhishingAnalysisResult;
    ransomware?: RansomwareAnalysisResult;
  } = {};

  const promises: Promise<void>[] = [];

  if (data.logs) {
    promises.push(
      analyzeWithDFP(data.logs).then(r => { results.dfp = r; })
    );
  }

  if (data.domains && data.domains.length > 0) {
    promises.push(
      detectDGA(data.domains).then(r => { results.dga = r; })
    );
  }

  if (data.email) {
    promises.push(
      detectPhishing(data.email).then(r => { results.phishing = r; })
    );
  }

  if (data.events) {
    promises.push(
      detectRansomware(data.events).then(r => { results.ransomware = r; })
    );
  }

  await Promise.all(promises);

  const totalThreats =
    (results.dfp?.threatsDetected || 0) +
    (results.dga?.threatsDetected || 0) +
    (results.phishing?.threatsDetected || 0) +
    (results.ransomware?.threatsDetected || 0);

  const summaryParts: string[] = [];
  if (results.dfp) summaryParts.push(`DFP: ${results.dfp.threatsDetected} anomalies`);
  if (results.dga) summaryParts.push(`DGA: ${results.dga.dgaDomainsFound} malicious domains`);
  if (results.phishing) summaryParts.push(`Phishing: ${results.phishing.phishingDetected} detected`);
  if (results.ransomware) summaryParts.push(`Ransomware: ${results.ransomware.ransomwareDetected ? 'DETECTED' : 'none'}`);

  return {
    ...results,
    summary: summaryParts.length > 0 ? summaryParts.join(' | ') : 'No analysis performed',
    totalThreats,
  };
}

// Helper functions

function mapAnomaly(raw: Record<string, unknown>): Anomaly {
  return {
    id: String(raw.id || `anomaly-${Date.now()}`),
    type: (raw.type as Anomaly['type']) || 'user_behavior',
    severity: (raw.severity as Anomaly['severity']) || 'medium',
    confidence: Number(raw.confidence) || 0,
    description: String(raw.description || 'Unknown anomaly'),
    timestamp: String(raw.timestamp || new Date().toISOString()),
    source: raw.source as string | undefined,
    details: raw.details as Record<string, unknown> | undefined,
  };
}

function createErrorResult(pipeline: string, error: string, startTime: number): DFPAnalysisResult {
  return {
    pipeline: 'digital_fingerprinting',
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    threatsDetected: 0,
    anomalies: [],
    summary: `Error: ${error}`,
    recommendations: ['Check Morpheus server connectivity', 'Verify input data format'],
    userProfiles: 0,
    baselinePeriod: 'unknown',
  };
}

function createDGAErrorResult(error: string, startTime: number, domainsCount: number): DGAAnalysisResult {
  return {
    pipeline: 'dga_detection',
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    threatsDetected: 0,
    anomalies: [],
    summary: `Error: ${error}`,
    recommendations: ['Check Morpheus server connectivity'],
    domainsAnalyzed: domainsCount,
    dgaDomainsFound: 0,
    results: [],
  };
}

function createPhishingErrorResult(error: string, startTime: number): PhishingAnalysisResult {
  return {
    pipeline: 'phishing_detection',
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    threatsDetected: 0,
    anomalies: [],
    summary: `Error: ${error}`,
    recommendations: ['Check Morpheus server connectivity'],
    emailsAnalyzed: 0,
    phishingDetected: 0,
    results: [],
  };
}

function createRansomwareErrorResult(error: string, startTime: number): RansomwareAnalysisResult {
  return {
    pipeline: 'ransomware_detection',
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    threatsDetected: 0,
    anomalies: [],
    summary: `Error: ${error}`,
    recommendations: ['Check Morpheus server connectivity'],
    eventsAnalyzed: 0,
    ransomwareDetected: false,
    results: [],
  };
}
