import { VulnerabilityPattern, Language } from './types';

/**
 * Comprehensive vulnerability pattern definitions for code security scanning.
 * Patterns are organized by category following OWASP Top 10 and CWE classifications.
 */

// ============================================================================
// A03:2021 - Injection Vulnerabilities
// ============================================================================

const SQL_INJECTION_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'SQL001',
    name: 'SQL Injection via String Concatenation',
    description: 'SQL query built using string concatenation with user input, allowing SQL injection attacks.',
    category: 'injection',
    severity: 'critical',
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'go'],
    patterns: [
      /["'`]SELECT\s+.*?\+\s*(?:req\.|request\.|params\.|query\.|input|user)/gi,
      /["'`]INSERT\s+INTO\s+.*?\+\s*(?:req\.|request\.|params\.|query\.|input|user)/gi,
      /["'`]UPDATE\s+.*?SET\s+.*?\+\s*(?:req\.|request\.|params\.|query\.|input|user)/gi,
      /["'`]DELETE\s+FROM\s+.*?\+\s*(?:req\.|request\.|params\.|query\.|input|user)/gi,
      /query\s*\(\s*["'`](?:SELECT|INSERT|UPDATE|DELETE).*?\$\{/gi,
      /execute\s*\(\s*["'`].*?\+.*?(?:req\.|request\.|params\.)/gi,
      /\.raw\s*\(\s*["'`].*?\$\{/gi,
      /f["'](?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}/gi,  // Python f-strings
      /\.format\s*\(.*?(?:request|input|user)/gi,
    ],
    antiPatterns: [
      /\?\s*,\s*\[/,           // Parameterized queries
      /\$\d+/,                  // PostgreSQL parameters
      /:[\w]+/,                 // Named parameters
      /PreparedStatement/i,
      /parameterized/i,
    ],
    fixTemplate: 'Use parameterized queries or prepared statements instead of string concatenation.',
    references: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/89.html',
    ],
  },
  {
    id: 'SQL002',
    name: 'NoSQL Injection',
    description: 'NoSQL query vulnerable to injection through unvalidated user input.',
    category: 'injection',
    severity: 'critical',
    cwe: ['CWE-943'],
    owasp: ['A03:2021'],
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      /\.find\s*\(\s*\{[^}]*:\s*req\./gi,
      /\.findOne\s*\(\s*\{[^}]*:\s*req\./gi,
      /\$where\s*:\s*["'`].*?\+/gi,
      /\$regex\s*:\s*(?:req\.|request\.|params\.)/gi,
      /collection\.(?:find|update|delete)\s*\(\s*JSON\.parse/gi,
    ],
    fixTemplate: 'Validate and sanitize user input. Use schema validation libraries like Joi or express-validator.',
    references: [
      'https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf',
    ],
  },
];

const COMMAND_INJECTION_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'CMD001',
    name: 'OS Command Injection',
    description: 'System command executed with unsanitized user input, allowing arbitrary command execution.',
    category: 'injection',
    severity: 'critical',
    cwe: ['CWE-78'],
    owasp: ['A03:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'go', 'shell'],
    patterns: [
      /exec\s*\(\s*["'`].*?\+.*?(?:req\.|request\.|params\.|input|user)/gi,
      /execSync\s*\(\s*["'`].*?\+/gi,
      /spawn\s*\(\s*["'`].*?\+/gi,
      /child_process\.exec\s*\(\s*`[^`]*\$\{/gi,
      /os\.system\s*\(\s*f?["'].*?(?:\{|\+)/gi,
      /subprocess\.(?:call|run|Popen)\s*\(\s*f?["'].*?(?:\{|\+)/gi,
      /Runtime\.getRuntime\(\)\.exec\s*\(.*?\+/gi,
      /ProcessBuilder\s*\(.*?\+.*?(?:request|input|user)/gi,
      /shell_exec\s*\(\s*["'].*?\./gi,
      /system\s*\(\s*["'].*?\$(?:_GET|_POST|_REQUEST)/gi,
      /`.*?\$\(.*?(?:req\.|request\.|params\.)/gi,
      /eval\s*\(\s*["'`].*?(?:req\.|request\.|params\.)/gi,
    ],
    antiPatterns: [
      /escapeshellarg/i,
      /escapeshellcmd/i,
      /shlex\.quote/i,
      /shell:\s*false/i,
    ],
    fixTemplate: 'Use parameterized commands or safe APIs. Validate and sanitize all user input. Avoid shell execution when possible.',
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
      'https://cwe.mitre.org/data/definitions/78.html',
    ],
  },
  {
    id: 'CMD002',
    name: 'Code Injection via eval()',
    description: 'Dynamic code execution using eval() with user-controlled input.',
    category: 'injection',
    severity: 'critical',
    cwe: ['CWE-94', 'CWE-95'],
    owasp: ['A03:2021'],
    languages: ['javascript', 'typescript', 'python', 'php', 'ruby'],
    patterns: [
      /eval\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/gi,
      /eval\s*\(\s*["'`].*?\+/gi,
      /new\s+Function\s*\(\s*["'`].*?\+/gi,
      /setTimeout\s*\(\s*["'`].*?\+.*?,/gi,
      /setInterval\s*\(\s*["'`].*?\+.*?,/gi,
      /exec\s*\(\s*compile\s*\(/gi,  // Python
      /create_function\s*\(/gi,       // PHP
    ],
    fixTemplate: 'Never use eval() with user input. Use safer alternatives like JSON.parse() for data parsing.',
    references: [
      'https://cwe.mitre.org/data/definitions/94.html',
    ],
  },
];

const LDAP_INJECTION_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'LDAP001',
    name: 'LDAP Injection',
    description: 'LDAP query constructed with unsanitized user input.',
    category: 'injection',
    severity: 'high',
    cwe: ['CWE-90'],
    owasp: ['A03:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'csharp'],
    patterns: [
      /ldap.*?filter.*?["'`].*?\+.*?(?:req\.|request\.|input|user)/gi,
      /search\s*\(\s*["'`]\([^)]*=.*?\+/gi,
      /\(\w+\s*=\s*["'`]\s*\+\s*(?:req\.|request\.)/gi,
    ],
    fixTemplate: 'Use LDAP encoding functions to escape special characters in user input.',
    references: [
      'https://owasp.org/www-community/attacks/LDAP_Injection',
      'https://cwe.mitre.org/data/definitions/90.html',
    ],
  },
];

// ============================================================================
// A07:2021 - Cross-Site Scripting (XSS)
// ============================================================================

const XSS_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'XSS001',
    name: 'Reflected XSS',
    description: 'User input directly reflected in HTML response without encoding.',
    category: 'xss',
    severity: 'high',
    cwe: ['CWE-79'],
    owasp: ['A07:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby'],
    patterns: [
      /res\.(?:send|write)\s*\(\s*(?:req\.|request\.)/gi,
      /innerHTML\s*=\s*(?:req\.|request\.|params\.|query\.)/gi,
      /document\.write\s*\(\s*(?:location\.|window\.)/gi,
      /\$\s*\(\s*["'`].*?\)\.html\s*\(\s*(?:req\.|request\.)/gi,
      /render\s*\(\s*["'`].*?["'`]\s*,\s*\{[^}]*:\s*req\./gi,
      /echo\s+\$_(?:GET|POST|REQUEST)/gi,
      /print\s*\(\s*request\./gi,
      /\{\{\s*\w+\s*\|\s*safe\s*\}\}/gi,  // Django/Jinja unsafe
      /<%=\s*(?:params|request)/gi,        // ERB
      /dangerouslySetInnerHTML/gi,
    ],
    antiPatterns: [
      /escape/i,
      /sanitize/i,
      /encode/i,
      /DOMPurify/i,
      /htmlspecialchars/i,
      /\.text\s*\(/i,
    ],
    fixTemplate: 'Encode user input before rendering in HTML. Use context-appropriate encoding (HTML, JavaScript, URL, CSS).',
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cwe.mitre.org/data/definitions/79.html',
    ],
  },
  {
    id: 'XSS002',
    name: 'DOM-based XSS',
    description: 'Client-side code that manipulates DOM with user-controlled data.',
    category: 'xss',
    severity: 'high',
    cwe: ['CWE-79'],
    owasp: ['A07:2021'],
    languages: ['javascript', 'typescript'],
    patterns: [
      /document\.write\s*\(\s*(?:location|document\.URL|document\.referrer)/gi,
      /\.innerHTML\s*=\s*(?:location|window\.name|document\.)/gi,
      /\.outerHTML\s*=\s*(?:location|window\.)/gi,
      /eval\s*\(\s*(?:location\.|document\.URL)/gi,
      /document\.location\s*=\s*(?:location\.hash|window\.name)/gi,
    ],
    fixTemplate: 'Use textContent instead of innerHTML. Validate and sanitize data from URL parameters and other client-side sources.',
    references: [
      'https://owasp.org/www-community/attacks/DOM_Based_XSS',
    ],
  },
];

// ============================================================================
// A02:2021 - Cryptographic Failures
// ============================================================================

const CRYPTO_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'CRYPTO001',
    name: 'Weak Cryptographic Algorithm',
    description: 'Use of cryptographically weak or broken algorithms (MD5, SHA1, DES).',
    category: 'crypto_issues',
    severity: 'high',
    cwe: ['CWE-327', 'CWE-328'],
    owasp: ['A02:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'csharp', 'ruby'],
    patterns: [
      /createHash\s*\(\s*["'`]md5["'`]\s*\)/gi,
      /createHash\s*\(\s*["'`]sha1["'`]\s*\)/gi,
      /hashlib\.md5\s*\(/gi,
      /hashlib\.sha1\s*\(/gi,
      /MessageDigest\.getInstance\s*\(\s*["'`]MD5["'`]\s*\)/gi,
      /MessageDigest\.getInstance\s*\(\s*["'`]SHA-?1["'`]\s*\)/gi,
      /md5\s*\(/gi,
      /sha1\s*\(/gi,
      /DES(?:ede)?/gi,
      /Blowfish/gi,
      /RC4/gi,
      /\.createCipher\s*\(/gi,  // Deprecated in Node.js
    ],
    antiPatterns: [
      /sha256/i,
      /sha384/i,
      /sha512/i,
      /argon2/i,
      /bcrypt/i,
      /scrypt/i,
    ],
    fixTemplate: 'Use strong cryptographic algorithms: SHA-256+ for hashing, AES-256-GCM for encryption, Argon2/bcrypt for passwords.',
    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/327.html',
    ],
  },
  {
    id: 'CRYPTO002',
    name: 'Hardcoded Cryptographic Key',
    description: 'Cryptographic key hardcoded in source code.',
    category: 'crypto_issues',
    severity: 'critical',
    cwe: ['CWE-321'],
    owasp: ['A02:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
    patterns: [
      /(?:secret|key|password|token|apiKey|api_key|privateKey|private_key)\s*[:=]\s*["'`][A-Za-z0-9+/=]{16,}["'`]/gi,
      /(?:AES|DES|RSA).*?key.*?["'`][A-Fa-f0-9]{32,}["'`]/gi,
      /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
      /-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----/gi,
    ],
    fixTemplate: 'Store cryptographic keys in environment variables, secure vaults (HashiCorp Vault, AWS Secrets Manager), or key management systems.',
    references: [
      'https://cwe.mitre.org/data/definitions/321.html',
    ],
  },
  {
    id: 'CRYPTO003',
    name: 'Insecure Random Number Generation',
    description: 'Use of weak random number generators for security-sensitive operations.',
    category: 'crypto_issues',
    severity: 'high',
    cwe: ['CWE-330', 'CWE-338'],
    owasp: ['A02:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go'],
    patterns: [
      /Math\.random\s*\(\s*\).*?(?:token|session|key|password|secret|auth)/gi,
      /random\.random\s*\(\s*\).*?(?:token|session|key|password|secret)/gi,
      /java\.util\.Random/gi,
      /rand\s*\(\s*\).*?(?:token|key|password|secret)/gi,
      /mt_rand\s*\(/gi,
    ],
    antiPatterns: [
      /crypto\.randomBytes/i,
      /secrets\./i,
      /SecureRandom/i,
      /crypto\.getRandomValues/i,
      /random_bytes/i,
    ],
    fixTemplate: 'Use cryptographically secure random number generators: crypto.randomBytes (Node.js), secrets module (Python), SecureRandom (Java).',
    references: [
      'https://cwe.mitre.org/data/definitions/338.html',
    ],
  },
];

// ============================================================================
// A01:2021 - Broken Access Control
// ============================================================================

const ACCESS_CONTROL_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'ACCESS001',
    name: 'Missing Authorization Check',
    description: 'Endpoint or function lacks authorization verification.',
    category: 'broken_access',
    severity: 'high',
    cwe: ['CWE-862'],
    owasp: ['A01:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    patterns: [
      /app\.(?:get|post|put|delete|patch)\s*\(\s*["'`][^"'`]+["'`]\s*,\s*(?:async\s*)?\(?(?:\w+,\s*)?(?:req|request)/gi,
      /@(?:Get|Post|Put|Delete|Patch)Mapping.*?\n(?:(?!@PreAuthorize|@Secured|@RolesAllowed).)*/gis,
    ],
    antiPatterns: [
      /isAuthenticated/i,
      /isAuthorized/i,
      /checkPermission/i,
      /requireAuth/i,
      /authenticate/i,
      /authorize/i,
      /passport\./i,
      /@PreAuthorize/i,
      /@Secured/i,
    ],
    contextRequired: true,
    fixTemplate: 'Add authorization middleware or decorators to verify user permissions before processing requests.',
    references: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/862.html',
    ],
  },
  {
    id: 'ACCESS002',
    name: 'Insecure Direct Object Reference (IDOR)',
    description: 'Direct use of user-supplied ID to access objects without ownership verification.',
    category: 'broken_access',
    severity: 'high',
    cwe: ['CWE-639'],
    owasp: ['A01:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby'],
    patterns: [
      /findById\s*\(\s*(?:req\.params|request\.params|params\[)/gi,
      /\.get\s*\(\s*["'`]\/\w+\/:id["'`].*?findById\s*\(\s*req\.params\.id/gis,
      /User\.find\s*\(\s*\{.*?_id\s*:\s*req\.(?:params|body)/gi,
      /WHERE\s+id\s*=\s*\$\{?(?:req|request)\.(?:params|body)/gi,
    ],
    antiPatterns: [
      /user\.id\s*===?\s*req\.params/i,
      /req\.user\.id/i,
      /ownership/i,
      /belongsTo/i,
    ],
    fixTemplate: 'Verify object ownership or user permissions before accessing resources. Use indirect references or access control lists.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
    ],
  },
  {
    id: 'ACCESS003',
    name: 'Path Traversal',
    description: 'File path constructed with user input without proper validation.',
    category: 'path_traversal',
    severity: 'high',
    cwe: ['CWE-22'],
    owasp: ['A01:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby'],
    patterns: [
      /(?:readFile|writeFile|appendFile|unlink|rmdir)(?:Sync)?\s*\(\s*(?:req\.|request\.|params\.)/gi,
      /path\.join\s*\([^)]*(?:req\.|request\.|params\.)/gi,
      /open\s*\(\s*(?:request\.|params\.)/gi,
      /new\s+File\s*\([^)]*\+[^)]*(?:request|params)/gi,
      /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /include\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /sendFile\s*\(\s*(?:req\.|request\.)/gi,
    ],
    antiPatterns: [
      /path\.normalize/i,
      /path\.resolve/i,
      /\.replace\s*\(\s*["'`]\.\.["'`]/i,
      /realpath/i,
      /basename/i,
    ],
    fixTemplate: 'Validate and sanitize file paths. Use path.basename() to extract filename. Verify resolved path is within allowed directory.',
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
      'https://cwe.mitre.org/data/definitions/22.html',
    ],
  },
];

// ============================================================================
// A10:2021 - Server-Side Request Forgery (SSRF)
// ============================================================================

const SSRF_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'SSRF001',
    name: 'Server-Side Request Forgery',
    description: 'HTTP request made to user-controlled URL without validation.',
    category: 'ssrf',
    severity: 'high',
    cwe: ['CWE-918'],
    owasp: ['A10:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby'],
    patterns: [
      /(?:fetch|axios|request|got|http\.get|https\.get)\s*\(\s*(?:req\.|request\.|params\.|body\.)/gi,
      /urllib\.request\.urlopen\s*\(\s*(?:request\.|params\.)/gi,
      /requests\.(?:get|post|put|delete)\s*\(\s*(?:request\.|params\.)/gi,
      /HttpClient.*?\.(?:Get|Post)Async\s*\([^)]*\+[^)]*(?:request|params)/gi,
      /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /curl_setopt.*?CURLOPT_URL.*?\$_(?:GET|POST|REQUEST)/gi,
    ],
    antiPatterns: [
      /allowlist/i,
      /whitelist/i,
      /validateUrl/i,
      /isAllowedHost/i,
    ],
    fixTemplate: 'Validate and sanitize URLs. Use allowlists for permitted hosts. Block internal IP ranges (127.0.0.1, 10.x, 192.168.x, etc.).',
    references: [
      'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
      'https://cwe.mitre.org/data/definitions/918.html',
    ],
  },
];

// ============================================================================
// A05:2021 - Security Misconfiguration
// ============================================================================

const MISCONFIG_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'CONFIG001',
    name: 'Debug Mode Enabled in Production',
    description: 'Debug or development mode enabled, potentially exposing sensitive information.',
    category: 'security_misconfig',
    severity: 'medium',
    cwe: ['CWE-489'],
    owasp: ['A05:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby'],
    patterns: [
      /DEBUG\s*[:=]\s*(?:true|True|1|["'`]true["'`])/gi,
      /app\.debug\s*=\s*True/gi,
      /FLASK_DEBUG\s*=\s*1/gi,
      /NODE_ENV\s*[:=]\s*["'`]development["'`]/gi,
      /\.enableStackTraces\s*\(\s*\)/gi,
    ],
    fixTemplate: 'Disable debug mode in production. Use environment variables to control debug settings.',
    references: [
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    ],
  },
  {
    id: 'CONFIG002',
    name: 'CORS Misconfiguration',
    description: 'Overly permissive CORS configuration allowing any origin.',
    category: 'security_misconfig',
    severity: 'medium',
    cwe: ['CWE-942'],
    owasp: ['A05:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    patterns: [
      /Access-Control-Allow-Origin['"`:]\s*['"`:]\s*\*/gi,
      /cors\s*\(\s*\{?\s*origin\s*:\s*(?:true|\*|["'`]\*["'`])/gi,
      /\.allowedOrigins\s*\(\s*["'`]\*["'`]\s*\)/gi,
      /header\s*\(\s*["'`]Access-Control-Allow-Origin:\s*\*["'`]\s*\)/gi,
    ],
    fixTemplate: 'Configure CORS with specific allowed origins instead of wildcard (*). Validate Origin header for sensitive operations.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
    ],
  },
  {
    id: 'CONFIG003',
    name: 'Missing Security Headers',
    description: 'HTTP security headers not configured.',
    category: 'security_misconfig',
    severity: 'medium',
    cwe: ['CWE-693'],
    owasp: ['A05:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    patterns: [
      /app\.(?:use|listen)\s*\(/gi,  // Flag for manual review
    ],
    antiPatterns: [
      /helmet/i,
      /X-Frame-Options/i,
      /X-Content-Type-Options/i,
      /Content-Security-Policy/i,
      /Strict-Transport-Security/i,
    ],
    contextRequired: true,
    fixTemplate: 'Add security headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security.',
    references: [
      'https://owasp.org/www-project-secure-headers/',
    ],
  },
  {
    id: 'CONFIG004',
    name: 'Insecure Cookie Configuration',
    description: 'Cookie set without secure flags (HttpOnly, Secure, SameSite).',
    category: 'security_misconfig',
    severity: 'medium',
    cwe: ['CWE-614', 'CWE-1004'],
    owasp: ['A05:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    patterns: [
      /res\.cookie\s*\([^)]*\)\s*(?!.*(?:httpOnly|secure|sameSite))/gi,
      /Set-Cookie[^;]*(?!.*(?:HttpOnly|Secure|SameSite))/gi,
      /session.*?cookie.*?secure\s*:\s*false/gi,
    ],
    antiPatterns: [
      /httpOnly\s*:\s*true/i,
      /secure\s*:\s*true/i,
      /sameSite/i,
    ],
    fixTemplate: 'Set cookie flags: HttpOnly (prevents XSS access), Secure (HTTPS only), SameSite (CSRF protection).',
    references: [
      'https://owasp.org/www-community/controls/SecureCookieAttribute',
    ],
  },
];

// ============================================================================
// A04:2021 - Hardcoded Secrets
// ============================================================================

const SECRETS_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'SECRET001',
    name: 'Hardcoded API Key',
    description: 'API key or token hardcoded in source code.',
    category: 'hardcoded_secrets',
    severity: 'critical',
    cwe: ['CWE-798'],
    owasp: ['A04:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    patterns: [
      /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'`][A-Za-z0-9_\-]{20,}["'`]/gi,
      /(?:AWS|AZURE|GCP|GOOGLE|STRIPE|TWILIO|SENDGRID)[_-]?(?:ACCESS|SECRET|API)[_-]?(?:KEY|TOKEN|ID)?\s*[:=]\s*["'`][^"'`]{10,}["'`]/gi,
      /Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi,  // JWT
      /ghp_[A-Za-z0-9]{36}/gi,  // GitHub PAT
      /gho_[A-Za-z0-9]{36}/gi,  // GitHub OAuth
      /sk_live_[A-Za-z0-9]{24,}/gi,  // Stripe
      /rk_live_[A-Za-z0-9]{24,}/gi,  // Stripe
      /AKIA[A-Z0-9]{16}/gi,    // AWS Access Key
      /xox[baprs]-[A-Za-z0-9\-]{10,}/gi,  // Slack tokens
    ],
    fixTemplate: 'Store secrets in environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.).',
    references: [
      'https://owasp.org/Top10/A04_2021-Insecure_Design/',
      'https://cwe.mitre.org/data/definitions/798.html',
    ],
  },
  {
    id: 'SECRET002',
    name: 'Hardcoded Password',
    description: 'Password hardcoded in source code.',
    category: 'hardcoded_secrets',
    severity: 'critical',
    cwe: ['CWE-798', 'CWE-259'],
    owasp: ['A04:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    patterns: [
      /(?:password|passwd|pwd)\s*[:=]\s*["'`][^"'`]{4,}["'`]/gi,
      /(?:db_pass|database_password|mysql_pwd)\s*[:=]\s*["'`][^"'`]+["'`]/gi,
      /(?:admin_pass|root_password|master_key)\s*[:=]\s*["'`][^"'`]+["'`]/gi,
    ],
    antiPatterns: [
      /process\.env/i,
      /os\.environ/i,
      /getenv/i,
      /\.env/i,
      /config\./i,
    ],
    fixTemplate: 'Never hardcode passwords. Use environment variables, secrets managers, or secure configuration systems.',
    references: [
      'https://cwe.mitre.org/data/definitions/259.html',
    ],
  },
  {
    id: 'SECRET003',
    name: 'Private Key in Source',
    description: 'Private cryptographic key embedded in source code.',
    category: 'hardcoded_secrets',
    severity: 'critical',
    cwe: ['CWE-321'],
    owasp: ['A04:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    patterns: [
      /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
      /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----/g,
      /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
      /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
    ],
    fixTemplate: 'Store private keys in secure key management systems. Never commit private keys to source control.',
    references: [
      'https://cwe.mitre.org/data/definitions/321.html',
    ],
  },
];

// ============================================================================
// A08:2021 - Software and Data Integrity Failures
// ============================================================================

const INTEGRITY_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'INTEGRITY001',
    name: 'Insecure Deserialization',
    description: 'Deserialization of untrusted data without validation.',
    category: 'insecure_deserial',
    severity: 'critical',
    cwe: ['CWE-502'],
    owasp: ['A08:2021'],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
    patterns: [
      /pickle\.loads?\s*\(\s*(?:request|req|data|input)/gi,
      /yaml\.(?:load|unsafe_load)\s*\(/gi,
      /ObjectInputStream.*?readObject/gi,
      /unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi,
      /Marshal\.load\s*\(/gi,
      /JSON\.parse\s*\(.*?\).*?eval/gi,
    ],
    antiPatterns: [
      /yaml\.safe_load/i,
      /JSON\.parse/i,  // JSON is generally safe
      /SafeLoader/i,
    ],
    fixTemplate: 'Use safe deserialization methods. Validate and sanitize serialized data. Avoid deserializing from untrusted sources.',
    references: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cwe.mitre.org/data/definitions/502.html',
    ],
  },
];

// ============================================================================
// Memory Safety Issues (C/C++/Rust)
// ============================================================================

const MEMORY_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'MEM001',
    name: 'Buffer Overflow Risk',
    description: 'Unsafe buffer operations that may cause overflow.',
    category: 'memory_safety',
    severity: 'critical',
    cwe: ['CWE-120', 'CWE-119'],
    owasp: [],
    languages: ['c', 'cpp'],
    patterns: [
      /strcpy\s*\(/gi,
      /strcat\s*\(/gi,
      /sprintf\s*\(/gi,
      /gets\s*\(/gi,
      /scanf\s*\(\s*["'`]%s["'`]/gi,
    ],
    antiPatterns: [
      /strncpy/i,
      /strncat/i,
      /snprintf/i,
      /fgets/i,
    ],
    fixTemplate: 'Use safe alternatives: strncpy, strncat, snprintf, fgets. Always specify buffer sizes.',
    references: [
      'https://cwe.mitre.org/data/definitions/120.html',
    ],
  },
  {
    id: 'MEM002',
    name: 'Format String Vulnerability',
    description: 'User-controlled format string in printf-style functions.',
    category: 'memory_safety',
    severity: 'critical',
    cwe: ['CWE-134'],
    owasp: [],
    languages: ['c', 'cpp'],
    patterns: [
      /printf\s*\(\s*(?:argv|input|buffer|user|data)\s*\)/gi,
      /fprintf\s*\([^,]+,\s*(?:argv|input|buffer|user|data)\s*\)/gi,
      /sprintf\s*\([^,]+,\s*(?:argv|input|buffer|user|data)\s*\)/gi,
    ],
    fixTemplate: 'Always use format strings as the first argument: printf("%s", user_input).',
    references: [
      'https://cwe.mitre.org/data/definitions/134.html',
    ],
  },
];

// ============================================================================
// Dockerfile/Container Security
// ============================================================================

const CONTAINER_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'DOCKER001',
    name: 'Running as Root',
    description: 'Container running as root user without explicitly changing to non-root.',
    category: 'security_misconfig',
    severity: 'medium',
    cwe: ['CWE-250'],
    owasp: ['A05:2021'],
    languages: ['dockerfile'],
    patterns: [
      /^FROM\s+(?!scratch)/gim,
    ],
    antiPatterns: [
      /USER\s+(?!root)\w+/i,
      /--user/i,
    ],
    contextRequired: true,
    fixTemplate: 'Add USER directive to run as non-root: USER nobody or USER 1000:1000',
    references: [
      'https://docs.docker.com/engine/reference/builder/#user',
    ],
  },
  {
    id: 'DOCKER002',
    name: 'Latest Tag Usage',
    description: 'Using :latest tag which can lead to unpredictable builds.',
    category: 'security_misconfig',
    severity: 'low',
    cwe: ['CWE-829'],
    owasp: ['A05:2021'],
    languages: ['dockerfile'],
    patterns: [
      /FROM\s+\S+:latest/gi,
      /FROM\s+[^:\s]+\s*$/gim,
    ],
    fixTemplate: 'Pin to specific image versions: FROM node:18.17.0-alpine instead of FROM node:latest',
    references: [
      'https://docs.docker.com/develop/dev-best-practices/',
    ],
  },
  {
    id: 'DOCKER003',
    name: 'Secrets in Dockerfile',
    description: 'Secrets or credentials passed in Dockerfile.',
    category: 'hardcoded_secrets',
    severity: 'critical',
    cwe: ['CWE-798'],
    owasp: ['A05:2021'],
    languages: ['dockerfile'],
    patterns: [
      /ENV\s+(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY|PRIVATE_KEY)\s*[=:]/gi,
      /ARG\s+(?:PASSWORD|SECRET|KEY|TOKEN)\s*=/gi,
    ],
    fixTemplate: 'Use Docker secrets, environment variables at runtime, or secrets managers instead of embedding in Dockerfile.',
    references: [
      'https://docs.docker.com/engine/swarm/secrets/',
    ],
  },
];

// ============================================================================
// Infrastructure as Code (Terraform)
// ============================================================================

const TERRAFORM_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'TF001',
    name: 'Public S3 Bucket',
    description: 'S3 bucket configured with public access.',
    category: 'security_misconfig',
    severity: 'critical',
    cwe: ['CWE-284'],
    owasp: ['A01:2021'],
    languages: ['terraform'],
    patterns: [
      /acl\s*=\s*["']public-read["']/gi,
      /acl\s*=\s*["']public-read-write["']/gi,
      /block_public_acls\s*=\s*false/gi,
      /block_public_policy\s*=\s*false/gi,
    ],
    fixTemplate: 'Set block_public_acls = true, block_public_policy = true, ignore_public_acls = true, restrict_public_buckets = true',
    references: [
      'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block',
    ],
  },
  {
    id: 'TF002',
    name: 'Unencrypted Storage',
    description: 'Storage resource without encryption enabled.',
    category: 'crypto_issues',
    severity: 'high',
    cwe: ['CWE-311'],
    owasp: ['A02:2021'],
    languages: ['terraform'],
    patterns: [
      /resource\s*"aws_ebs_volume"[\s\S]*?encrypted\s*=\s*false/gi,
      /resource\s*"aws_rds_cluster"[\s\S]*?storage_encrypted\s*=\s*false/gi,
    ],
    antiPatterns: [
      /encrypted\s*=\s*true/i,
      /storage_encrypted\s*=\s*true/i,
    ],
    fixTemplate: 'Enable encryption: encrypted = true for EBS, storage_encrypted = true for RDS.',
    references: [
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    ],
  },
  {
    id: 'TF003',
    name: 'Overly Permissive Security Group',
    description: 'Security group allowing unrestricted inbound access.',
    category: 'broken_access',
    severity: 'critical',
    cwe: ['CWE-284'],
    owasp: ['A01:2021'],
    languages: ['terraform'],
    patterns: [
      /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/gi,
      /ipv6_cidr_blocks\s*=\s*\[\s*["']::\/:0["']\s*\]/gi,
    ],
    fixTemplate: 'Restrict CIDR blocks to specific IP ranges. Never use 0.0.0.0/0 for production resources.',
    references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    ],
  },
];

// ============================================================================
// Export All Patterns
// ============================================================================

export const ALL_VULNERABILITY_PATTERNS: VulnerabilityPattern[] = [
  ...SQL_INJECTION_PATTERNS,
  ...COMMAND_INJECTION_PATTERNS,
  ...LDAP_INJECTION_PATTERNS,
  ...XSS_PATTERNS,
  ...CRYPTO_PATTERNS,
  ...ACCESS_CONTROL_PATTERNS,
  ...SSRF_PATTERNS,
  ...MISCONFIG_PATTERNS,
  ...SECRETS_PATTERNS,
  ...INTEGRITY_PATTERNS,
  ...MEMORY_PATTERNS,
  ...CONTAINER_PATTERNS,
  ...TERRAFORM_PATTERNS,
];

export function getPatternsByCategory(category: string): VulnerabilityPattern[] {
  return ALL_VULNERABILITY_PATTERNS.filter((p) => p.category === category);
}

export function getPatternsByLanguage(language: Language): VulnerabilityPattern[] {
  return ALL_VULNERABILITY_PATTERNS.filter((p) => p.languages.includes(language));
}

export function getPatternsBySeverity(severity: string): VulnerabilityPattern[] {
  return ALL_VULNERABILITY_PATTERNS.filter((p) => p.severity === severity);
}

export function getPatternById(id: string): VulnerabilityPattern | undefined {
  return ALL_VULNERABILITY_PATTERNS.find((p) => p.id === id);
}
