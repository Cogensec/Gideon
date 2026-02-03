/**
 * NVIDIA RAPIDS Client
 *
 * Client for integrating with NVIDIA RAPIDS GPU-accelerated data processing.
 * RAPIDS provides massive speedups for data science operations:
 * - cuDF: GPU DataFrames (5-150x faster than pandas)
 * - cuML: GPU Machine Learning (10-50x faster than scikit-learn)
 * - cuGraph: GPU Graph Analytics (100x+ faster than NetworkX)
 *
 * Used in Gideon for:
 * - Batch IOC analysis at scale
 * - Event correlation and attack chain detection
 * - Threat clustering and pattern identification
 * - Network graph analysis for lateral movement detection
 */

export interface RapidsConfig {
  serverUrl: string;
  enabled: boolean;
  processing: {
    batchSize: number;
    memoryLimit: string;
  };
  analytics: {
    anomalyThreshold: number;
    minClusterSize: number;
    maxGraphDepth: number;
  };
}

export interface RapidsResult {
  status: 'success' | 'error' | 'partial';
  processingTimeMs: number;
  recordsProcessed: number;
  gpuAccelerated: boolean;
  gpuMemoryUsedMB?: number;
}

export interface IOCRecord {
  indicator: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  malicious: boolean;
  confidence: number;
  sources: string[];
  firstSeen?: string;
  lastSeen?: string;
  tags?: string[];
}

export interface BatchIOCResult extends RapidsResult {
  totalIndicators: number;
  maliciousCount: number;
  benignCount: number;
  unknownCount: number;
  results: IOCRecord[];
  topThreats: IOCRecord[];
  summary: string;
}

export interface EventCorrelation {
  chainId: string;
  events: string[];
  attackPattern?: string;
  confidence: number;
  timeline: Array<{ timestamp: string; event: string }>;
  mitreAttackIds?: string[];
}

export interface CorrelationResult extends RapidsResult {
  totalEvents: number;
  correlatedChains: number;
  attackChainsDetected: number;
  correlations: EventCorrelation[];
  summary: string;
  recommendations: string[];
}

export interface ThreatCluster {
  clusterId: string;
  size: number;
  centroid: string;
  members: string[];
  commonAttributes: Record<string, string>;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface ClusterResult extends RapidsResult {
  totalThreats: number;
  clustersFound: number;
  outliers: number;
  clusters: ThreatCluster[];
  summary: string;
}

export interface NetworkNode {
  id: string;
  type: 'host' | 'user' | 'service' | 'external';
  risk: number;
  connections: number;
  attributes?: Record<string, unknown>;
}

export interface NetworkEdge {
  source: string;
  target: string;
  weight: number;
  protocol?: string;
  portRange?: string;
  dataVolume?: number;
}

export interface LateralMovementPath {
  pathId: string;
  nodes: string[];
  risk: number;
  hops: number;
  entryPoint: string;
  targets: string[];
}

export interface GraphAnalysisResult extends RapidsResult {
  totalNodes: number;
  totalEdges: number;
  components: number;
  centralNodes: NetworkNode[];
  lateralMovementPaths: LateralMovementPath[];
  anomalousConnections: NetworkEdge[];
  summary: string;
  recommendations: string[];
}

export interface AnomalyResult extends RapidsResult {
  totalRecords: number;
  anomaliesDetected: number;
  anomalyRate: number;
  anomalies: Array<{
    id: string;
    score: number;
    features: Record<string, number>;
    description: string;
  }>;
  summary: string;
}

// Default configuration
const DEFAULT_CONFIG: RapidsConfig = {
  serverUrl: 'http://localhost:8090',
  enabled: true,
  processing: {
    batchSize: 10000,
    memoryLimit: '8GB',
  },
  analytics: {
    anomalyThreshold: 0.8,
    minClusterSize: 5,
    maxGraphDepth: 10,
  },
};

/**
 * Gets RAPIDS configuration from environment
 */
export function getRapidsConfig(): RapidsConfig {
  return {
    ...DEFAULT_CONFIG,
    serverUrl: process.env.RAPIDS_URL || DEFAULT_CONFIG.serverUrl,
    enabled: process.env.RAPIDS_ENABLED !== 'false',
  };
}

/**
 * Checks if RAPIDS server is available
 */
export async function isRapidsAvailable(): Promise<boolean> {
  const config = getRapidsConfig();

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
 * Get RAPIDS server capabilities
 */
export async function getRapidsCapabilities(): Promise<{
  gpuAvailable: boolean;
  gpuName?: string;
  gpuMemoryGB?: number;
  libraries: string[];
}> {
  const config = getRapidsConfig();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/capabilities`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      return { gpuAvailable: false, libraries: [] };
    }

    return response.json();
  } catch {
    return { gpuAvailable: false, libraries: [] };
  }
}

/**
 * Batch analyze IOCs using GPU-accelerated processing (cuDF)
 * Processes thousands of indicators in parallel
 */
export async function batchAnalyzeIOCs(
  indicators: string[],
  options?: { enrichment?: boolean; dedup?: boolean }
): Promise<BatchIOCResult> {
  const config = getRapidsConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/ioc/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indicators,
        batch_size: config.processing.batchSize,
        enrichment: options?.enrichment ?? true,
        dedup: options?.dedup ?? true,
      }),
    });

    if (!response.ok) {
      return createBatchIOCError(`Server error: ${response.statusText}`, startTime, indicators.length);
    }

    const result = await response.json();
    const iocResults: IOCRecord[] = (result.results || []).map((r: Record<string, unknown>) => ({
      indicator: String(r.indicator || ''),
      type: r.type as IOCRecord['type'],
      malicious: Boolean(r.malicious),
      confidence: Number(r.confidence) || 0,
      sources: (r.sources as string[]) || [],
      firstSeen: r.first_seen as string | undefined,
      lastSeen: r.last_seen as string | undefined,
      tags: r.tags as string[] | undefined,
    }));

    const maliciousCount = iocResults.filter(r => r.malicious).length;
    const topThreats = iocResults
      .filter(r => r.malicious)
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 10);

    return {
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: indicators.length,
      gpuAccelerated: result.gpu_accelerated ?? false,
      gpuMemoryUsedMB: result.gpu_memory_mb,
      totalIndicators: indicators.length,
      maliciousCount,
      benignCount: iocResults.filter(r => !r.malicious && r.confidence > 0.7).length,
      unknownCount: iocResults.filter(r => r.confidence <= 0.7).length,
      results: iocResults,
      topThreats,
      summary: `Analyzed ${indicators.length} indicators: ${maliciousCount} malicious, processed in ${Date.now() - startTime}ms`,
    };
  } catch (error) {
    return createBatchIOCError(error instanceof Error ? error.message : String(error), startTime, indicators.length);
  }
}

/**
 * Correlate security events to identify attack chains (cuGraph)
 * Builds event graphs and detects attack patterns
 */
export async function correlateEvents(
  events: string,
  options?: { timeWindow?: string; minChainLength?: number }
): Promise<CorrelationResult> {
  const config = getRapidsConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/correlate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events,
        time_window: options?.timeWindow || '24h',
        min_chain_length: options?.minChainLength || 3,
        max_depth: config.analytics.maxGraphDepth,
      }),
    });

    if (!response.ok) {
      return createCorrelationError(`Server error: ${response.statusText}`, startTime);
    }

    const result = await response.json();
    const correlations: EventCorrelation[] = (result.correlations || []).map((c: Record<string, unknown>) => ({
      chainId: String(c.chain_id || ''),
      events: (c.events as string[]) || [],
      attackPattern: c.attack_pattern as string | undefined,
      confidence: Number(c.confidence) || 0,
      timeline: (c.timeline as EventCorrelation['timeline']) || [],
      mitreAttackIds: c.mitre_attack_ids as string[] | undefined,
    }));

    const attackChains = correlations.filter(c => c.attackPattern);

    return {
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: result.events_processed || 0,
      gpuAccelerated: result.gpu_accelerated ?? false,
      gpuMemoryUsedMB: result.gpu_memory_mb,
      totalEvents: result.events_processed || 0,
      correlatedChains: correlations.length,
      attackChainsDetected: attackChains.length,
      correlations,
      summary: `Correlated ${result.events_processed || 0} events into ${correlations.length} chains, ${attackChains.length} attack patterns identified`,
      recommendations: attackChains.length > 0 ? [
        'Review identified attack chains immediately',
        'Isolate affected systems if active compromise detected',
        'Collect forensic evidence from chain endpoints',
        'Update detection rules based on identified patterns',
      ] : [],
    };
  } catch (error) {
    return createCorrelationError(error instanceof Error ? error.message : String(error), startTime);
  }
}

/**
 * Cluster similar threats for pattern identification (cuML)
 * Groups related security incidents
 */
export async function clusterThreats(
  threats: string,
  options?: { algorithm?: 'dbscan' | 'hdbscan' | 'kmeans'; features?: string[] }
): Promise<ClusterResult> {
  const config = getRapidsConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/cluster`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        threats,
        algorithm: options?.algorithm || 'hdbscan',
        min_cluster_size: config.analytics.minClusterSize,
        features: options?.features,
      }),
    });

    if (!response.ok) {
      return createClusterError(`Server error: ${response.statusText}`, startTime);
    }

    const result = await response.json();
    const clusters: ThreatCluster[] = (result.clusters || []).map((c: Record<string, unknown>) => ({
      clusterId: String(c.cluster_id || ''),
      size: Number(c.size) || 0,
      centroid: String(c.centroid || ''),
      members: (c.members as string[]) || [],
      commonAttributes: (c.common_attributes as Record<string, string>) || {},
      threatLevel: (c.threat_level as ThreatCluster['threatLevel']) || 'medium',
    }));

    return {
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: result.threats_processed || 0,
      gpuAccelerated: result.gpu_accelerated ?? false,
      gpuMemoryUsedMB: result.gpu_memory_mb,
      totalThreats: result.threats_processed || 0,
      clustersFound: clusters.length,
      outliers: result.outliers || 0,
      clusters,
      summary: `Clustered ${result.threats_processed || 0} threats into ${clusters.length} groups, ${result.outliers || 0} outliers`,
    };
  } catch (error) {
    return createClusterError(error instanceof Error ? error.message : String(error), startTime);
  }
}

/**
 * Analyze network graph for lateral movement detection (cuGraph)
 * Identifies attack paths and high-risk connections
 */
export async function analyzeNetworkGraph(
  flows: string,
  options?: { detectLateralMovement?: boolean; findCentralNodes?: boolean }
): Promise<GraphAnalysisResult> {
  const config = getRapidsConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/graph/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        flows,
        detect_lateral_movement: options?.detectLateralMovement ?? true,
        find_central_nodes: options?.findCentralNodes ?? true,
        max_depth: config.analytics.maxGraphDepth,
      }),
    });

    if (!response.ok) {
      return createGraphError(`Server error: ${response.statusText}`, startTime);
    }

    const result = await response.json();

    const centralNodes: NetworkNode[] = (result.central_nodes || []).map((n: Record<string, unknown>) => ({
      id: String(n.id || ''),
      type: (n.type as NetworkNode['type']) || 'host',
      risk: Number(n.risk) || 0,
      connections: Number(n.connections) || 0,
      attributes: n.attributes as Record<string, unknown> | undefined,
    }));

    const lateralPaths: LateralMovementPath[] = (result.lateral_paths || []).map((p: Record<string, unknown>) => ({
      pathId: String(p.path_id || ''),
      nodes: (p.nodes as string[]) || [],
      risk: Number(p.risk) || 0,
      hops: Number(p.hops) || 0,
      entryPoint: String(p.entry_point || ''),
      targets: (p.targets as string[]) || [],
    }));

    const anomalousEdges: NetworkEdge[] = (result.anomalous_connections || []).map((e: Record<string, unknown>) => ({
      source: String(e.source || ''),
      target: String(e.target || ''),
      weight: Number(e.weight) || 0,
      protocol: e.protocol as string | undefined,
      portRange: e.port_range as string | undefined,
      dataVolume: e.data_volume as number | undefined,
    }));

    return {
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: result.flows_processed || 0,
      gpuAccelerated: result.gpu_accelerated ?? false,
      gpuMemoryUsedMB: result.gpu_memory_mb,
      totalNodes: result.total_nodes || 0,
      totalEdges: result.total_edges || 0,
      components: result.components || 0,
      centralNodes,
      lateralMovementPaths: lateralPaths,
      anomalousConnections: anomalousEdges,
      summary: `Analyzed ${result.total_nodes || 0} nodes, ${result.total_edges || 0} edges. Found ${lateralPaths.length} potential lateral movement paths.`,
      recommendations: lateralPaths.length > 0 ? [
        'Review lateral movement paths for unauthorized access',
        'Implement network segmentation to limit lateral movement',
        'Monitor central nodes for suspicious activity',
        'Audit anomalous connections immediately',
      ] : [],
    };
  } catch (error) {
    return createGraphError(error instanceof Error ? error.message : String(error), startTime);
  }
}

/**
 * Detect anomalies in security data using GPU-accelerated ML (cuML)
 */
export async function detectAnomalies(
  data: string,
  options?: { method?: 'isolation_forest' | 'local_outlier_factor' | 'autoencoder' }
): Promise<AnomalyResult> {
  const config = getRapidsConfig();
  const startTime = Date.now();

  try {
    const response = await fetch(`${config.serverUrl}/api/v1/anomaly/detect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data,
        method: options?.method || 'isolation_forest',
        threshold: config.analytics.anomalyThreshold,
      }),
    });

    if (!response.ok) {
      return createAnomalyError(`Server error: ${response.statusText}`, startTime);
    }

    const result = await response.json();
    const anomalies = (result.anomalies || []).map((a: Record<string, unknown>) => ({
      id: String(a.id || ''),
      score: Number(a.score) || 0,
      features: (a.features as Record<string, number>) || {},
      description: String(a.description || 'Unknown anomaly'),
    }));

    return {
      status: 'success',
      processingTimeMs: Date.now() - startTime,
      recordsProcessed: result.records_processed || 0,
      gpuAccelerated: result.gpu_accelerated ?? false,
      gpuMemoryUsedMB: result.gpu_memory_mb,
      totalRecords: result.records_processed || 0,
      anomaliesDetected: anomalies.length,
      anomalyRate: result.anomaly_rate || 0,
      anomalies,
      summary: `Analyzed ${result.records_processed || 0} records, detected ${anomalies.length} anomalies (${((result.anomaly_rate || 0) * 100).toFixed(2)}% anomaly rate)`,
    };
  } catch (error) {
    return createAnomalyError(error instanceof Error ? error.message : String(error), startTime);
  }
}

// Error helper functions

function createBatchIOCError(error: string, startTime: number, count: number): BatchIOCResult {
  return {
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    gpuAccelerated: false,
    totalIndicators: count,
    maliciousCount: 0,
    benignCount: 0,
    unknownCount: count,
    results: [],
    topThreats: [],
    summary: `Error: ${error}`,
  };
}

function createCorrelationError(error: string, startTime: number): CorrelationResult {
  return {
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    gpuAccelerated: false,
    totalEvents: 0,
    correlatedChains: 0,
    attackChainsDetected: 0,
    correlations: [],
    summary: `Error: ${error}`,
    recommendations: ['Check RAPIDS server connectivity'],
  };
}

function createClusterError(error: string, startTime: number): ClusterResult {
  return {
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    gpuAccelerated: false,
    totalThreats: 0,
    clustersFound: 0,
    outliers: 0,
    clusters: [],
    summary: `Error: ${error}`,
  };
}

function createGraphError(error: string, startTime: number): GraphAnalysisResult {
  return {
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    gpuAccelerated: false,
    totalNodes: 0,
    totalEdges: 0,
    components: 0,
    centralNodes: [],
    lateralMovementPaths: [],
    anomalousConnections: [],
    summary: `Error: ${error}`,
    recommendations: ['Check RAPIDS server connectivity'],
  };
}

function createAnomalyError(error: string, startTime: number): AnomalyResult {
  return {
    status: 'error',
    processingTimeMs: Date.now() - startTime,
    recordsProcessed: 0,
    gpuAccelerated: false,
    totalRecords: 0,
    anomaliesDetected: 0,
    anomalyRate: 0,
    anomalies: [],
    summary: `Error: ${error}`,
  };
}
