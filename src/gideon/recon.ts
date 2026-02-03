import {
  ReconSummary,
  SubdomainResult,
  TechnologyFingerprint,
  PortScanResult,
  ToolRecommendation,
  ToolCategory,
} from './types';

/**
 * GIDEON Reconnaissance Module
 *
 * Provides reconnaissance workflows, tool recommendations,
 * and attack surface analysis.
 */

// ============================================================================
// Tool Recommendations Database
// ============================================================================

export const TOOLS_DATABASE: ToolRecommendation[] = [
  // Subdomain Enumeration
  {
    name: 'subfinder',
    category: 'subdomain',
    description: 'Fast passive subdomain enumeration tool',
    command: 'subfinder -d TARGET -silent',
    installCommand: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    url: 'https://github.com/projectdiscovery/subfinder',
    useCase: 'Passive subdomain discovery from multiple sources',
  },
  {
    name: 'amass',
    category: 'subdomain',
    description: 'In-depth attack surface mapping and asset discovery',
    command: 'amass enum -passive -d TARGET',
    installCommand: 'go install -v github.com/owasp-amass/amass/v4/...@master',
    url: 'https://github.com/owasp-amass/amass',
    useCase: 'Comprehensive subdomain enumeration with data sources',
  },
  {
    name: 'assetfinder',
    category: 'subdomain',
    description: 'Find domains and subdomains related to a given domain',
    command: 'assetfinder --subs-only TARGET',
    installCommand: 'go install github.com/tomnomnom/assetfinder@latest',
    url: 'https://github.com/tomnomnom/assetfinder',
    useCase: 'Quick subdomain discovery',
  },
  {
    name: 'crt.sh',
    category: 'subdomain',
    description: 'Certificate Transparency log search',
    command: 'curl -s "https://crt.sh/?q=%25.TARGET&output=json" | jq -r \'.[].name_value\' | sort -u',
    url: 'https://crt.sh',
    useCase: 'Find subdomains from SSL certificates',
  },

  // Alive Checking
  {
    name: 'httpx',
    category: 'recon',
    description: 'Fast and multi-purpose HTTP toolkit',
    command: 'httpx -l subdomains.txt -silent -status-code -title -tech-detect',
    installCommand: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    url: 'https://github.com/projectdiscovery/httpx',
    useCase: 'Probe for alive hosts and gather HTTP metadata',
  },
  {
    name: 'httprobe',
    category: 'recon',
    description: 'Take a list of domains and probe for working HTTP/HTTPS servers',
    command: 'cat subdomains.txt | httprobe',
    installCommand: 'go install github.com/tomnomnom/httprobe@latest',
    url: 'https://github.com/tomnomnom/httprobe',
    useCase: 'Quick HTTP/HTTPS probing',
  },

  // Port Scanning
  {
    name: 'nmap',
    category: 'portscan',
    description: 'Network exploration and security auditing tool',
    command: 'nmap -sV -sC -T4 TARGET',
    installCommand: 'apt install nmap',
    url: 'https://nmap.org',
    useCase: 'Port scanning and service detection',
  },
  {
    name: 'masscan',
    category: 'portscan',
    description: 'Fast TCP port scanner',
    command: 'masscan -p1-65535 TARGET --rate=1000',
    installCommand: 'apt install masscan',
    url: 'https://github.com/robertdavidgraham/masscan',
    useCase: 'High-speed port scanning',
  },
  {
    name: 'rustscan',
    category: 'portscan',
    description: 'Fast port scanner that integrates with nmap',
    command: 'rustscan -a TARGET -- -sV -sC',
    installCommand: 'cargo install rustscan',
    url: 'https://github.com/RustScan/RustScan',
    useCase: 'Quick port scan with nmap integration',
  },

  // Fuzzing
  {
    name: 'ffuf',
    category: 'fuzzing',
    description: 'Fast web fuzzer written in Go',
    command: 'ffuf -u "https://TARGET/FUZZ" -w wordlist.txt -mc 200,301,302,403',
    installCommand: 'go install github.com/ffuf/ffuf@latest',
    url: 'https://github.com/ffuf/ffuf',
    useCase: 'Directory brute-forcing and parameter fuzzing',
  },
  {
    name: 'feroxbuster',
    category: 'fuzzing',
    description: 'Fast, simple, recursive content discovery tool',
    command: 'feroxbuster -u https://TARGET -w wordlist.txt',
    installCommand: 'cargo install feroxbuster',
    url: 'https://github.com/epi052/feroxbuster',
    useCase: 'Recursive directory discovery',
  },
  {
    name: 'gobuster',
    category: 'fuzzing',
    description: 'Directory/file & DNS busting tool',
    command: 'gobuster dir -u https://TARGET -w wordlist.txt',
    installCommand: 'go install github.com/OJ/gobuster/v3@latest',
    url: 'https://github.com/OJ/gobuster',
    useCase: 'Directory and DNS brute-forcing',
  },

  // SQL Injection
  {
    name: 'sqlmap',
    category: 'injection',
    description: 'Automatic SQL injection and database takeover tool',
    command: 'sqlmap -u "URL?param=1" --dbs --batch',
    installCommand: 'apt install sqlmap',
    url: 'https://sqlmap.org',
    useCase: 'SQL injection detection and exploitation',
  },
  {
    name: 'ghauri',
    category: 'injection',
    description: 'SQL injection detection and exploitation tool',
    command: 'ghauri -u "URL?param=1" --dbs',
    installCommand: 'pip install ghauri',
    url: 'https://github.com/r0oth3x49/ghauri',
    useCase: 'Alternative SQL injection tool',
  },

  // XSS
  {
    name: 'XSStrike',
    category: 'xss',
    description: 'Advanced XSS detection suite',
    command: 'xsstrike -u "URL?param=test"',
    installCommand: 'git clone https://github.com/s0md3v/XSStrike && pip install -r requirements.txt',
    url: 'https://github.com/s0md3v/XSStrike',
    useCase: 'XSS detection with WAF bypass',
  },
  {
    name: 'dalfox',
    category: 'xss',
    description: 'Parameter analysis and XSS scanning tool',
    command: 'dalfox url "URL?param=test"',
    installCommand: 'go install github.com/hahwul/dalfox/v2@latest',
    url: 'https://github.com/hahwul/dalfox',
    useCase: 'Fast XSS scanning',
  },

  // Authentication
  {
    name: 'jwt_tool',
    category: 'auth',
    description: 'JWT exploitation toolkit',
    command: 'jwt_tool TOKEN',
    installCommand: 'pip install jwt_tool',
    url: 'https://github.com/ticarpi/jwt_tool',
    useCase: 'JWT analysis and exploitation',
  },

  // API Testing
  {
    name: 'nuclei',
    category: 'api',
    description: 'Fast vulnerability scanner based on templates',
    command: 'nuclei -u https://TARGET -t ~/nuclei-templates/',
    installCommand: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    url: 'https://github.com/projectdiscovery/nuclei',
    useCase: 'Template-based vulnerability scanning',
  },
  {
    name: 'arjun',
    category: 'api',
    description: 'HTTP parameter discovery suite',
    command: 'arjun -u https://TARGET/endpoint',
    installCommand: 'pip install arjun',
    url: 'https://github.com/s0md3v/Arjun',
    useCase: 'Hidden parameter discovery',
  },

  // Cloud
  {
    name: 'ScoutSuite',
    category: 'cloud',
    description: 'Multi-cloud security auditing tool',
    command: 'scout aws',
    installCommand: 'pip install scoutsuite',
    url: 'https://github.com/nccgroup/ScoutSuite',
    useCase: 'Cloud security configuration review',
  },
  {
    name: 's3scanner',
    category: 'cloud',
    description: 'Scan for open S3 buckets',
    command: 's3scanner scan --bucket BUCKET',
    installCommand: 'pip install s3scanner',
    url: 'https://github.com/sa7mon/S3Scanner',
    useCase: 'S3 bucket enumeration and permission testing',
  },
  {
    name: 'cloudfox',
    category: 'cloud',
    description: 'Automating situational awareness for cloud penetration tests',
    command: 'cloudfox aws all-checks',
    installCommand: 'go install github.com/BishopFox/cloudfox@latest',
    url: 'https://github.com/BishopFox/cloudfox',
    useCase: 'AWS penetration testing',
  },

  // Automation
  {
    name: 'gau',
    category: 'automation',
    description: 'Fetch known URLs from various sources',
    command: 'gau TARGET',
    installCommand: 'go install github.com/lc/gau/v2/cmd/gau@latest',
    url: 'https://github.com/lc/gau',
    useCase: 'Historical URL discovery',
  },
  {
    name: 'waybackurls',
    category: 'automation',
    description: 'Fetch URLs from the Wayback Machine',
    command: 'waybackurls TARGET',
    installCommand: 'go install github.com/tomnomnom/waybackurls@latest',
    url: 'https://github.com/tomnomnom/waybackurls',
    useCase: 'Historical URL analysis',
  },
  {
    name: 'trufflehog',
    category: 'automation',
    description: 'Find credentials in git repositories',
    command: 'trufflehog github --repo=https://github.com/ORG/REPO',
    installCommand: 'pip install trufflehog',
    url: 'https://github.com/trufflesecurity/trufflehog',
    useCase: 'Secret scanning in repositories',
  },
];

/**
 * Get tools by category
 */
export function getToolsByCategory(category: ToolCategory): ToolRecommendation[] {
  return TOOLS_DATABASE.filter(t => t.category === category);
}

/**
 * Get all tool categories with counts
 */
export function getToolCategories(): Record<string, number> {
  const categories: Record<string, number> = {};
  for (const tool of TOOLS_DATABASE) {
    categories[tool.category] = (categories[tool.category] || 0) + 1;
  }
  return categories;
}

/**
 * Format tools as markdown
 */
export function formatToolsMarkdown(category?: ToolCategory): string {
  const tools = category ? getToolsByCategory(category) : TOOLS_DATABASE;

  let md = `# Recommended Tools${category ? ` - ${category.toUpperCase()}` : ''}\n\n`;

  const byCategory: Record<string, ToolRecommendation[]> = {};
  for (const tool of tools) {
    if (!byCategory[tool.category]) {
      byCategory[tool.category] = [];
    }
    byCategory[tool.category].push(tool);
  }

  for (const [cat, catTools] of Object.entries(byCategory)) {
    md += `## ${cat.charAt(0).toUpperCase() + cat.slice(1)}\n\n`;

    for (const tool of catTools) {
      md += `### ${tool.name}\n`;
      md += `${tool.description}\n\n`;
      md += `**Use Case:** ${tool.useCase}\n\n`;
      if (tool.command) {
        md += `**Command:**\n\`\`\`bash\n${tool.command}\n\`\`\`\n\n`;
      }
      if (tool.installCommand) {
        md += `**Install:**\n\`\`\`bash\n${tool.installCommand}\n\`\`\`\n\n`;
      }
      if (tool.url) {
        md += `**URL:** ${tool.url}\n\n`;
      }
    }
  }

  return md;
}

// ============================================================================
// Reconnaissance Workflows
// ============================================================================

/**
 * Generate passive recon commands for a target
 */
export function generatePassiveReconCommands(target: string): string[] {
  return [
    `# Certificate Transparency`,
    `curl -s "https://crt.sh/?q=%25.${target}&output=json" | jq -r '.[].name_value' | sort -u > crt_subdomains.txt`,
    ``,
    `# Subfinder (passive mode)`,
    `subfinder -d ${target} -silent > subfinder_subdomains.txt`,
    ``,
    `# Amass (passive enum)`,
    `amass enum -passive -d ${target} -o amass_subdomains.txt`,
    ``,
    `# Combine and dedupe`,
    `cat *_subdomains.txt | sort -u > all_subdomains.txt`,
    ``,
    `# Historical URLs`,
    `gau ${target} > historical_urls.txt`,
    `waybackurls ${target} >> historical_urls.txt`,
    `sort -u historical_urls.txt -o historical_urls.txt`,
    ``,
    `# GitHub dorking (manual)`,
    `# Search: site:github.com "${target}"`,
    `# Search: site:github.com "${target}" password OR api_key OR token`,
    ``,
    `# Google dorking (manual)`,
    `# site:${target} filetype:pdf`,
    `# site:${target} ext:sql OR ext:env OR ext:log`,
    `# site:${target} inurl:admin OR inurl:login`,
  ];
}

/**
 * Generate active recon commands for a target
 */
export function generateActiveReconCommands(target: string): string[] {
  return [
    `# ⚠️ ENSURE ${target} IS IN SCOPE BEFORE RUNNING`,
    ``,
    `# Probe for alive hosts`,
    `cat all_subdomains.txt | httpx -silent -status-code -title -tech-detect -o alive_hosts.txt`,
    ``,
    `# Port scanning (adjust rate as needed)`,
    `nmap -sV -sC -T4 ${target} -oA nmap_scan`,
    ``,
    `# Directory brute-forcing`,
    `ffuf -u "https://${target}/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o ffuf_results.json`,
    ``,
    `# Technology detection`,
    `whatweb -v https://${target}`,
    ``,
    `# Parameter discovery (on specific endpoints)`,
    `arjun -u "https://${target}/api/endpoint" -oT arjun_params.txt`,
    ``,
    `# JavaScript file analysis`,
    `cat alive_hosts.txt | getJS -complete | tee js_files.txt`,
    `# Then analyze with: LinkFinder, secretfinder`,
    ``,
    `# Nuclei scanning`,
    `nuclei -l alive_hosts.txt -t ~/nuclei-templates/ -severity critical,high -o nuclei_findings.txt`,
  ];
}

/**
 * Generate quick check commands for a URL
 */
export function generateQuickCheckCommands(url: string): string[] {
  return [
    `# Quick Security Checklist for ${url}`,
    ``,
    `# 1. Headers & Security Config`,
    `curl -I "${url}" | grep -i "x-frame-options\\|x-content-type\\|strict-transport\\|content-security"`,
    ``,
    `# 2. Technology Detection`,
    `whatweb "${url}"`,
    ``,
    `# 3. SSL/TLS Check`,
    `# Use: https://www.ssllabs.com/ssltest/`,
    ``,
    `# 4. Quick Nuclei Scan`,
    `nuclei -u "${url}" -t ~/nuclei-templates/http/misconfiguration/ -severity medium,high,critical`,
    ``,
    `# 5. Check for common files`,
    `curl -s "${url}/robots.txt"`,
    `curl -s "${url}/.git/HEAD"`,
    `curl -s "${url}/.env"`,
    `curl -s "${url}/sitemap.xml"`,
    `curl -s "${url}/crossdomain.xml"`,
    ``,
    `# 6. Parameter testing (manual)`,
    `# Test: ${url}?id=1'`,
    `# Test: ${url}?search=<script>alert(1)</script>`,
    `# Test: ${url}?redirect=//evil.com`,
  ];
}

// ============================================================================
// CVSS Calculator
// ============================================================================

export interface CVSSInput {
  // Base Metrics
  attackVector: 'network' | 'adjacent' | 'local' | 'physical';
  attackComplexity: 'low' | 'high';
  privilegesRequired: 'none' | 'low' | 'high';
  userInteraction: 'none' | 'required';
  scope: 'unchanged' | 'changed';
  confidentialityImpact: 'none' | 'low' | 'high';
  integrityImpact: 'none' | 'low' | 'high';
  availabilityImpact: 'none' | 'low' | 'high';
}

export interface CVSSResult {
  score: number;
  severity: string;
  vector: string;
}

/**
 * Calculate CVSS 3.1 score
 */
export function calculateCVSS(input: CVSSInput): CVSSResult {
  // Attack Vector (AV)
  const avValues: Record<string, number> = {
    network: 0.85,
    adjacent: 0.62,
    local: 0.55,
    physical: 0.2,
  };

  // Attack Complexity (AC)
  const acValues: Record<string, number> = {
    low: 0.77,
    high: 0.44,
  };

  // Privileges Required (PR) - varies by scope
  const prUnchanged: Record<string, number> = {
    none: 0.85,
    low: 0.62,
    high: 0.27,
  };
  const prChanged: Record<string, number> = {
    none: 0.85,
    low: 0.68,
    high: 0.5,
  };

  // User Interaction (UI)
  const uiValues: Record<string, number> = {
    none: 0.85,
    required: 0.62,
  };

  // Impact values
  const impactValues: Record<string, number> = {
    none: 0,
    low: 0.22,
    high: 0.56,
  };

  // Calculate exploitability
  const av = avValues[input.attackVector];
  const ac = acValues[input.attackComplexity];
  const pr = input.scope === 'changed'
    ? prChanged[input.privilegesRequired]
    : prUnchanged[input.privilegesRequired];
  const ui = uiValues[input.userInteraction];

  const exploitability = 8.22 * av * ac * pr * ui;

  // Calculate impact
  const confImpact = impactValues[input.confidentialityImpact];
  const intImpact = impactValues[input.integrityImpact];
  const availImpact = impactValues[input.availabilityImpact];

  const iss = 1 - ((1 - confImpact) * (1 - intImpact) * (1 - availImpact));

  let impact: number;
  if (input.scope === 'unchanged') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  // Calculate base score
  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (input.scope === 'unchanged') {
    score = Math.min(exploitability + impact, 10);
  } else {
    score = Math.min(1.08 * (exploitability + impact), 10);
  }

  // Round to 1 decimal place
  score = Math.round(score * 10) / 10;

  // Determine severity
  let severity: string;
  if (score === 0) severity = 'None';
  else if (score < 4) severity = 'Low';
  else if (score < 7) severity = 'Medium';
  else if (score < 9) severity = 'High';
  else severity = 'Critical';

  // Build vector string
  const vectorParts = [
    `AV:${input.attackVector[0].toUpperCase()}`,
    `AC:${input.attackComplexity[0].toUpperCase()}`,
    `PR:${input.privilegesRequired[0].toUpperCase()}`,
    `UI:${input.userInteraction[0].toUpperCase()}`,
    `S:${input.scope[0].toUpperCase()}`,
    `C:${input.confidentialityImpact[0].toUpperCase()}`,
    `I:${input.integrityImpact[0].toUpperCase()}`,
    `A:${input.availabilityImpact[0].toUpperCase()}`,
  ];

  return {
    score,
    severity,
    vector: `CVSS:3.1/${vectorParts.join('/')}`,
  };
}

/**
 * Format CVSS helper prompt
 */
export function formatCVSSHelper(): string {
  return `
# CVSS 3.1 Score Calculator

## Attack Vector (AV)
- **Network (N)**: Remotely exploitable over the internet
- **Adjacent (A)**: Requires same network segment (LAN, Bluetooth)
- **Local (L)**: Requires local access (malicious file, local user)
- **Physical (P)**: Requires physical access

## Attack Complexity (AC)
- **Low (L)**: No special conditions, exploit works reliably
- **High (H)**: Requires specific conditions, race conditions, etc.

## Privileges Required (PR)
- **None (N)**: No authentication needed
- **Low (L)**: Basic user privileges (regular account)
- **High (H)**: Admin/root privileges required

## User Interaction (UI)
- **None (N)**: No user action needed
- **Required (R)**: User must click link, open file, etc.

## Scope (S)
- **Unchanged (U)**: Impact limited to vulnerable component
- **Changed (C)**: Impact extends to other components

## Impact (C/I/A)
- **None (N)**: No impact
- **Low (L)**: Limited impact, some data affected
- **High (H)**: Total compromise of confidentiality/integrity/availability

## Common Scenarios

| Vulnerability | Typical Score | Vector |
|--------------|--------------|--------|
| RCE (unauth, no interaction) | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| SQLi (data disclosure) | 7.5-8.6 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Stored XSS | 6.1-8.0 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| IDOR (read) | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| CSRF | 4.3-6.5 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N |
| Open Redirect | 4.7 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
`;
}
