---
title: Security Connectors
description: Learn how Gideon integrates with external security intelligence providers like NVD, VirusTotal, and AbuseIPDB.
---

Gideon uses a plugin-based **Security Connector** architecture to fetch and normalize data from various threat intelligence sources.

## Overview

Each connector is responsible for:
1.  **Fetching**: Querying the external API with proper authentication and rate limiting.
2.  **Normalizing**: Converting vendor-specific JSON into Gideon's standard `NormalizedData` format.
3.  **Ranking**: Sorting and scoring results based on severity and confidence.

## Supported Connectors

### 1. CVE Connector (NVD)
The CVE connector searches the **National Vulnerability Database (NVD)** and **CISA's KEV (Known Exploited Vulnerabilities)** catalog.

-   **Capability**: Vulnerability research, CVSS scoring, and affected product analysis.
-   **Configuration**:
    ```bash
    NVD_API_KEY=your_key_here
    ```
-   **Data Points**:
    -   CVE ID & Summary
    -   CVSS 3.1 Severity & Vector
    -   Affected CPEs (Vendor/Product)
    -   Reference URLs

### 2. IOC Connector (VirusTotal & AbuseIPDB)
The IOC (Indicator of Compromise) connector analyzes IPs, Domains, URLs, and File Hashes.

-   **Capability**: Reputation checks and malware analysis.
-   **Configuration**:
    ```bash
    VIRUSTOTAL_API_KEY=your_key_here
    ABUSEIPDB_API_KEY=your_key_here
    ```
-   **Detection Logic**:
    -   **IPs**: Checked against AbuseIPDB for report history and VirusTotal for malicious flags.
    -   **Hashes**: Searched in VirusTotal's file database.
    -   **Domains/URLs**: Analyzed for phishing and DGA patterns.

## Data Normalization

All security data in Gideon is normalized to a common schema:

```typescript
interface NormalizedData {
  id: string;
  source: string;
  type: 'cve' | 'ioc' | 'summary';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: number; // 0.0 to 1.0
  summary: string;
  details: Record<string, any>;
  timestamp: string;
  url?: string;
}
```

## Adding Custom Connectors

Gideon is designed to be extensible. To add a new connector:
1.  Create a new file in `src/tools/security/`.
2.  Implement the `SecurityConnector` interface.
3.  Register it in the `ConnectorRegistry`.
