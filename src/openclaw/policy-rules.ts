import { v4 as uuidv4 } from 'uuid';
import { PolicyRule, PolicySet } from '../governance/types';

// ============================================================================
// OpenClaw-Specific Policy Rules
// Pre-built security policies targeting OpenClaw's unique attack surface
// ============================================================================

/**
 * Create the OpenClaw-specific policy set with rules targeting
 * all known CVEs, attack patterns, and architectural weaknesses.
 */
export function createOpenClawPolicySet(): PolicySet {
  const now = new Date().toISOString();

  const rules: PolicyRule[] = [
    // --- CVE-2026-25253: Token Exfiltration & CSWSH ---
    {
      id: uuidv4(),
      name: 'Block CVE-2026-25253 Token Exfiltration',
      description: 'Blocks patterns associated with CVE-2026-25253 gateway token exfiltration via malicious URL parameters',
      enabled: true,
      priority: 1000,
      severity: 'critical',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['network', 'shell'],
        patterns: [
          'gatewayUrl\\s*=',
          'connect\\.params\\.auth\\.token',
          'ws:\\/\\/[^1][^2][^7]',  // Non-localhost WS connections
          'wss:\\/\\/(?!127\\.0\\.0\\.1|localhost)',
        ],
      },
      action: 'deny',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- CVE-2026-25253: Approval Bypass ---
    {
      id: uuidv4(),
      name: 'Block Exec Approval Bypass',
      description: 'Prevents disabling execution approval controls (key CVE-2026-25253 kill chain stage)',
      enabled: true,
      priority: 999,
      severity: 'critical',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['shell', 'tool'],
        patterns: [
          'exec\\.approvals\\.set\\s*=\\s*off',
          'operator\\.approvals.*disable',
          'approvals.*false',
        ],
      },
      action: 'deny',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- CVE-2026-25253: Sandbox Escape ---
    {
      id: uuidv4(),
      name: 'Block Sandbox Escape',
      description: 'Prevents Docker sandbox escape attempts (CVE-2026-25253 final stage)',
      enabled: true,
      priority: 998,
      severity: 'critical',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['shell'],
        patterns: [
          'tools\\.exec\\.host\\s*=\\s*gateway',
          'docker.*--privileged',
          'nsenter\\s+',
          '\\.docker\\.sock',
          'mount.*\\/proc',
          'cgroup.*release_agent',
          '--net\\s*=\\s*host',
          '--pid\\s*=\\s*host',
        ],
      },
      action: 'deny',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- CVE-2026-24763 / CVE-2026-25157: Command Injection ---
    {
      id: uuidv4(),
      name: 'Block Command Injection Patterns',
      description: 'Blocks command injection patterns targeting OpenClaw gateway input sanitization',
      enabled: true,
      priority: 995,
      severity: 'critical',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['shell'],
        patterns: [
          ';\\s*(?:curl|wget|nc|ncat|bash|sh|python|perl|ruby)\\s',
          '\\$\\(.*\\)',
          '`[^`]+`',
          '\\|\\s*(?:bash|sh|python)\\s',
          '&&\\s*(?:curl|wget).*\\|\\s*(?:bash|sh)',
          '>\\s*\\/dev\\/(?:tcp|udp)\\/',
        ],
      },
      action: 'deny',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- Credential File Protection ---
    {
      id: uuidv4(),
      name: 'Protect OpenClaw Credential Files',
      description: 'Requires approval for accessing OpenClaw credential storage files',
      enabled: true,
      priority: 950,
      severity: 'high',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['file', 'shell'],
        patterns: [
          '\\.openclaw\\/.*credentials',
          '\\.openclaw\\/.*auth-profiles',
          '\\.openclaw\\/.*sessions\\.json',
          '\\.openclaw\\/.*gateway\\.auth',
          'OPENCLAW_GATEWAY_TOKEN',
          'ANTHROPIC_API_KEY',
          'OPENAI_API_KEY',
          'DEEPSEEK_API_KEY',
        ],
      },
      action: 'require_approval',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- Data Exfiltration Prevention ---
    {
      id: uuidv4(),
      name: 'Block OpenClaw Data Exfiltration',
      description: 'Blocks known exfiltration endpoints and patterns used against OpenClaw agents',
      enabled: true,
      priority: 990,
      severity: 'critical',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['network', 'shell'],
        patterns: [
          'webhook\\.site',
          'requestbin',
          'ngrok\\.io',
          'pipedream\\.net',
          'hookbin\\.com',
          'interact\\.sh',
          'oast\\.fun',
          'canarytokens\\.com',
          'burpcollaborator',
          'base64.*\\|\\s*(?:curl|wget|nc)',
        ],
      },
      action: 'deny',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- Memory Poisoning Prevention ---
    {
      id: uuidv4(),
      name: 'Audit Memory Write Operations',
      description: 'Audits all writes to OpenClaw memory files to detect poisoning attempts',
      enabled: true,
      priority: 900,
      severity: 'high',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['memory', 'file'],
        patterns: [
          'memory\\/.*\\.md',
          'MEMORY\\.md',
          'memory_write',
        ],
      },
      action: 'audit',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- Privilege Escalation Prevention ---
    {
      id: uuidv4(),
      name: 'Block Privilege Escalation',
      description: 'Blocks common privilege escalation techniques in agent exec commands',
      enabled: true,
      priority: 980,
      severity: 'critical',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['shell'],
        patterns: [
          'sudo\\s+',
          'su\\s+-\\s',
          'chmod\\s+[467][467][467]',
          'chown\\s+root',
          'usermod\\s+-aG\\s+(?:sudo|wheel|admin)',
          'visudo',
          'doas\\s+',
        ],
      },
      action: 'deny',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- Inter-Agent Communication Control ---
    {
      id: uuidv4(),
      name: 'Control OpenClaw Session Communication',
      description: 'Requires approval for spawning new sessions or cross-session messaging',
      enabled: true,
      priority: 870,
      severity: 'high',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['external_agent'],
        patterns: [
          'sessions_spawn',
          'sessions_send',
          'session_kill',
        ],
      },
      action: 'require_approval',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- Rate Limiting for OpenClaw Agents ---
    {
      id: uuidv4(),
      name: 'Rate Limit OpenClaw Exec Calls',
      description: 'Prevents rapid shell command execution that may indicate automated exploitation',
      enabled: true,
      priority: 800,
      severity: 'medium',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['shell'],
      },
      action: 'rate_limit',
      rateLimit: {
        requests: 30,
        windowSeconds: 60,
      },
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- Browser Tool Audit ---
    {
      id: uuidv4(),
      name: 'Audit OpenClaw Browser Activity',
      description: 'Logs all browser automation activity for CVE-2026-22708 monitoring',
      enabled: true,
      priority: 850,
      severity: 'medium',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['network'],
        patterns: [
          'browser',
          'navigate',
          'CDP',
          'chromium',
        ],
      },
      action: 'audit',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },

    // --- ClawHub Supply Chain ---
    {
      id: uuidv4(),
      name: 'Block Known Malicious Skill Patterns',
      description: 'Blocks execution patterns associated with ClawHavoc and other malicious ClawHub skills',
      enabled: true,
      priority: 970,
      severity: 'critical',
      conditions: {
        agentTypes: ['openclaw'],
        resourceTypes: ['shell', 'tool'],
        patterns: [
          'osascript.*display\\s+dialog',
          'xattr\\s+-d\\s+com\\.apple\\.quarantine',
          'spctl\\s+--master-disable',
          'security\\s+delete-certificate',
          'ditto.*\\.app',
        ],
      },
      action: 'deny',
      createdAt: now,
      updatedAt: now,
      createdBy: 'gideon-openclaw-sentinel',
    },
  ];

  return {
    id: uuidv4(),
    name: 'OpenClaw Security Policy',
    description: 'Comprehensive security policies for OpenClaw agent deployments. ' +
      'Covers all known CVEs (CVE-2026-25253, CVE-2026-24763, CVE-2026-25157, CVE-2026-22708), ' +
      'ClawHavoc campaign patterns, and architectural vulnerabilities.',
    version: '1.0.0',
    rules,
    defaultAction: 'audit',
    createdAt: now,
    updatedAt: now,
  };
}
