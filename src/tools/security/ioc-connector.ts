import { SecurityConnector, SecurityQuery, NormalizedData } from './types.js';
import { rateLimitedFetch } from '../../utils/rate-limiter.js';
import { getCached, setCached, generateCacheKey } from '../../utils/cache.js';
import { getSourceConfig } from '../../utils/config-loader.js';

function detectIOCType(value: string): 'ip' | 'domain' | 'url' | 'hash' | 'unknown' {
  // IP address (basic IPv4 check)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
    const parts = value.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) return 'ip';
  }

  // Hash (MD5, SHA1, SHA256)
  if (/^[a-fA-F0-9]{32}$/.test(value)) return 'hash'; // MD5
  if (/^[a-fA-F0-9]{40}$/.test(value)) return 'hash'; // SHA1
  if (/^[a-fA-F0-9]{64}$/.test(value)) return 'hash'; // SHA256

  // URL
  if (value.startsWith('http://') || value.startsWith('https://')) return 'url';

  // Domain (basic check)
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(value)) return 'domain';

  return 'unknown';
}

export const IOCConnector: SecurityConnector = {
  name: 'ioc_connector',
  description: 'Analyzes indicators of compromise (IP, domain, URL, hash) using VirusTotal and AbuseIPDB',

  async fetch(query: SecurityQuery): Promise<any> {
    const iocValue = query.query.trim();
    const iocType = detectIOCType(iocValue);

    if (iocType === 'unknown') {
      throw new Error(`Unable to determine IOC type for: ${iocValue}`);
    }

    const cacheKey = generateCacheKey('ioc', { value: iocValue, type: iocType });
    const cached = getCached(cacheKey);
    if (cached) {
      return { ...cached, _cached: true };
    }

    const results: any = {
      ioc: iocValue,
      type: iocType,
      sources: {},
    };

    // Fetch from VirusTotal
    if (process.env.VIRUSTOTAL_API_KEY) {
      try {
        const vtData = await fetchVirusTotal(iocValue, iocType);
        results.sources.virustotal = vtData;
      } catch (err) {
        results.sources.virustotal = {
          error: err instanceof Error ? err.message : String(err)
        };
      }
    }

    // Fetch from AbuseIPDB (only for IPs)
    if (iocType === 'ip' && process.env.ABUSEIPDB_API_KEY) {
      try {
        const abuseData = await fetchAbuseIPDB(iocValue);
        results.sources.abuseipdb = abuseData;
      } catch (err) {
        results.sources.abuseipdb = {
          error: err instanceof Error ? err.message : String(err)
        };
      }
    }

    const ttl = getSourceConfig('virustotal')?.cache_ttl || 300;
    setCached(cacheKey, results, ttl);

    return { ...results, _cached: false };
  },

  normalize(rawData: any): NormalizedData[] {
    const normalized: NormalizedData[] = [];
    const iocValue = rawData.ioc;
    const iocType = rawData.type;

    // Normalize VirusTotal data
    if (rawData.sources.virustotal && !rawData.sources.virustotal.error) {
      const vt = rawData.sources.virustotal;
      const stats = vt.data?.attributes?.last_analysis_stats || {};

      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;

      const total = malicious + suspicious + harmless + undetected;
      const reputation = total > 0 ? (harmless + undetected) / total : 0;

      const severity: NormalizedData['severity'] =
        malicious > 10 ? 'CRITICAL' :
        malicious > 5 ? 'HIGH' :
        malicious > 2 ? 'MEDIUM' :
        malicious > 0 ? 'LOW' : 'INFORMATIONAL';

      normalized.push({
        id: `vt-${iocValue}`,
        source: 'virustotal',
        type: 'ioc',
        severity,
        confidence: 0.9,
        summary: `VirusTotal: ${malicious}/${total} vendors flagged as malicious`,
        details: {
          ioc: iocValue,
          iocType,
          maliciousCount: malicious,
          suspiciousCount: suspicious,
          totalVendors: total,
          reputation,
          categories: vt.data?.attributes?.categories || {},
          lastAnalysisDate: vt.data?.attributes?.last_analysis_date,
        },
        timestamp: new Date().toISOString(),
        url: `https://www.virustotal.com/gui/${iocType === 'hash' ? 'file' : iocType}/${iocValue}`,
      });
    }

    // Normalize AbuseIPDB data
    if (rawData.sources.abuseipdb && !rawData.sources.abuseipdb.error) {
      const abuse = rawData.sources.abuseipdb;
      const abuseScore = abuse.data?.abuseConfidenceScore || 0;
      const totalReports = abuse.data?.totalReports || 0;

      const severity: NormalizedData['severity'] =
        abuseScore > 75 ? 'HIGH' :
        abuseScore > 50 ? 'MEDIUM' :
        abuseScore > 25 ? 'LOW' : 'INFORMATIONAL';

      normalized.push({
        id: `abuse-${iocValue}`,
        source: 'abuseipdb',
        type: 'ioc',
        severity,
        confidence: 0.85,
        summary: `AbuseIPDB: ${abuseScore}% abuse confidence (${totalReports} reports)`,
        details: {
          ioc: iocValue,
          abuseScore,
          totalReports,
          country: abuse.data?.countryCode || 'Unknown',
          isp: abuse.data?.isp || 'Unknown',
          domain: abuse.data?.domain || 'Unknown',
          usageType: abuse.data?.usageType || 'Unknown',
          isWhitelisted: abuse.data?.isWhitelisted || false,
        },
        timestamp: new Date().toISOString(),
        url: `https://www.abuseipdb.com/check/${iocValue}`,
      });
    }

    return normalized;
  },

  rank(results: NormalizedData[]): NormalizedData[] {
    // Sort by confidence (highest first) then severity
    return results.sort((a, b) => {
      const confidenceDiff = b.confidence - a.confidence;
      if (Math.abs(confidenceDiff) > 0.01) return confidenceDiff;

      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4 };
      return (severityOrder[a.severity || 'INFORMATIONAL'] || 4) -
             (severityOrder[b.severity || 'INFORMATIONAL'] || 4);
    });
  },
};

async function fetchVirusTotal(ioc: string, type: string): Promise<any> {
  return rateLimitedFetch('virustotal', async () => {
    const config = getSourceConfig('virustotal');
    if (!config || !config.enabled) {
      throw new Error('VirusTotal connector is not enabled');
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY!;

    const endpoint = type === 'hash' ? `files/${ioc}` :
                     type === 'domain' ? `domains/${ioc}` :
                     type === 'url' ? `urls/${Buffer.from(ioc).toString('base64url')}` :
                     type === 'ip' ? `ip_addresses/${ioc}` : '';

    if (!endpoint) {
      throw new Error(`Unsupported IOC type for VirusTotal: ${type}`);
    }

    const response = await fetch(`${config.base_url}/${endpoint}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (response.status === 404) {
      return { data: null, message: 'Not found in VirusTotal database' };
    }

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  });
}

async function fetchAbuseIPDB(ip: string): Promise<any> {
  return rateLimitedFetch('abuseipdb', async () => {
    const config = getSourceConfig('abuseipdb');
    if (!config || !config.enabled) {
      throw new Error('AbuseIPDB connector is not enabled');
    }

    const apiKey = process.env.ABUSEIPDB_API_KEY!;

    const params = new URLSearchParams({
      ipAddress: ip,
      maxAgeInDays: '90',
      verbose: 'true',
    });

    const response = await fetch(`${config.base_url}/check?${params}`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  });
}
