import type { SastRule } from '@/lib/types/sast'

/**
 * HemisX SAST Rule Library
 * 55 rules covering OWASP Top 10 (2021), mapped to CWE identifiers.
 * Patterns are intentionally conservative (prefer fewer false positives).
 */
export const SAST_RULES: SastRule[] = [

  // ══════════════════════════════════════════════════════════════════════════
  // A03:2021 — INJECTION  (SQL, Command, LDAP, XPath)
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-SQL-001',
    name: 'SQL Injection via string concatenation',
    description: 'SQL query built by concatenating user-controlled data. An attacker can manipulate the query structure to bypass auth or exfiltrate data.',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|FROM|WHERE)\s+.*(?:\+\s*(?:req\.|request\.|params\.|query\.|body\.|user\.|input)|f["'].*\{(?:request|req|params|query|body|user|input))/gi,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-89',
    category: 'Injection',
    remediation: 'Use parameterized queries or an ORM. Never concatenate user input into SQL strings.',
  },

  {
    id: 'SAST-SQL-002',
    name: 'Raw SQL query with variable interpolation (Python)',
    description: 'Python f-string or % formatting used inside a SQL execute call exposes the app to SQL injection.',
    pattern: /(?:cursor|conn|db|session)\.execute\s*\(\s*(?:f["']|["'].*%\s*\()/gi,
    languages: ['python'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-89',
    category: 'Injection',
    remediation: 'Pass parameters as a separate tuple: cursor.execute("SELECT * FROM t WHERE id=%s", (id,))',
  },

  {
    id: 'SAST-SQL-003',
    name: 'mysqli / mysql_query with variable concatenation (PHP)',
    description: 'PHP MySQL query built with string concatenation is vulnerable to SQL injection.',
    pattern: /(?:mysqli_query|mysql_query|pg_query)\s*\(\s*\$\w+\s*,\s*["'][^"']*"\s*\.\s*\$/gi,
    languages: ['php'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-89',
    category: 'Injection',
    remediation: 'Use prepared statements (mysqli_prepare) or PDO with bound parameters.',
  },

  {
    id: 'SAST-CMD-001',
    name: 'OS command injection — exec/system with variable',
    description: 'Shell command execution with user-controlled data. An attacker can append arbitrary commands.',
    pattern: /(?:exec|system|popen|passthru|shell_exec|proc_open)\s*\(\s*(?:[^"')]*(?:req\.|request\.|params\.|query\.|body\.|user\.|input\.|argv\[|\$_(?:GET|POST|REQUEST|COOKIE)))/gi,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-78',
    category: 'Injection',
    remediation: 'Avoid shell execution entirely. Use language-native APIs. If unavoidable, whitelist allowed values and escape with shlex.quote() (Python) or escapeshellarg() (PHP).',
  },

  {
    id: 'SAST-CMD-002',
    name: 'Node.js child_process.exec with variable',
    description: 'child_process.exec passes arguments to a shell — variable content enables command injection.',
    pattern: /child_process\.exec\s*\(|require\s*\(\s*['"]child_process['"]\s*\)\s*\.\s*exec\s*\(/gi,
    languages: ['javascript', 'typescript'],
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-78',
    category: 'Injection',
    remediation: 'Use child_process.execFile() or spawn() with an argument array (no shell interpolation). Validate and whitelist all user inputs.',
  },

  {
    id: 'SAST-CMD-003',
    name: 'Python subprocess with shell=True',
    description: 'subprocess called with shell=True enables shell injection if any argument contains user data.',
    pattern: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/gi,
    languages: ['python'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-78',
    category: 'Injection',
    remediation: 'Remove shell=True and pass command as a list: subprocess.run(["ls", path]). Use shlex.quote() if shell=True is unavoidable.',
  },

  {
    id: 'SAST-CMD-004',
    name: 'Python os.system / os.popen with variable',
    description: 'os.system and os.popen execute shell commands — any user-controlled argument leads to RCE.',
    pattern: /os\.(?:system|popen|execv|execve|execl|spawnl)\s*\(\s*(?!["'])/gi,
    languages: ['python'],
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-78',
    category: 'Injection',
    remediation: 'Replace with subprocess.run() with a list argument and no shell=True.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A03:2021 — XSS (Cross-Site Scripting)
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-XSS-001',
    name: 'Unsafe innerHTML assignment',
    description: 'Assigning user-controlled data to innerHTML enables stored/reflected XSS attacks.',
    pattern: /\.innerHTML\s*=/gi,
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-79',
    category: 'XSS',
    remediation: 'Use textContent instead of innerHTML. If HTML rendering is required, sanitize with DOMPurify before assignment.',
  },

  {
    id: 'SAST-XSS-002',
    name: 'document.write with variable',
    description: 'document.write() with dynamic content is a classic XSS vector.',
    pattern: /document\.write\s*\(/gi,
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-79',
    category: 'XSS',
    remediation: 'Avoid document.write(). Use DOM manipulation APIs with proper encoding instead.',
  },

  {
    id: 'SAST-XSS-003',
    name: 'React dangerouslySetInnerHTML',
    description: 'dangerouslySetInnerHTML bypasses React\'s XSS protection. Any unsanitized content can execute scripts.',
    pattern: /dangerouslySetInnerHTML\s*=/gi,
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-79',
    category: 'XSS',
    remediation: 'Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(html) }',
  },

  {
    id: 'SAST-XSS-004',
    name: 'eval() with dynamic content',
    description: 'eval() executes arbitrary JavaScript. If any user input reaches eval, it results in XSS or RCE.',
    pattern: /\beval\s*\(/gi,
    languages: ['javascript', 'typescript', 'php', 'ruby'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-95',
    category: 'Injection',
    remediation: 'Remove eval() entirely. Use JSON.parse() for JSON, and structured data instead of dynamic code execution.',
  },

  {
    id: 'SAST-XSS-005',
    name: 'new Function() constructor (JS code injection)',
    description: 'Function constructor is equivalent to eval and enables arbitrary code execution.',
    pattern: /new\s+Function\s*\(/gi,
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-95',
    category: 'XSS',
    remediation: 'Avoid the Function constructor. Use defined functions and structured data to avoid dynamic code evaluation.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A02:2021 — CRYPTOGRAPHIC FAILURES
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-CRYPTO-001',
    name: 'MD5 used for hashing',
    description: 'MD5 is cryptographically broken and unsuitable for passwords or integrity verification.',
    pattern: /\bmd5\s*\(|hashlib\.md5\s*\(|MessageDigest\.getInstance\s*\(\s*["']MD5["']/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-327',
    category: 'Cryptography',
    remediation: 'Use bcrypt, Argon2id, or scrypt for password hashing. Use SHA-256 or SHA-3 for integrity checksums (not passwords).',
  },

  {
    id: 'SAST-CRYPTO-002',
    name: 'SHA-1 used for hashing',
    description: 'SHA-1 is considered weak and collision-prone. Do not use for passwords or security-sensitive contexts.',
    pattern: /\bsha1\s*\(|hashlib\.sha1\s*\(|MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']/gi,
    languages: ['all'],
    severity: 'MEDIUM',
    confidence: 'HIGH',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-327',
    category: 'Cryptography',
    remediation: 'Migrate to SHA-256 or SHA-3 for checksums. Use bcrypt/Argon2 for password storage.',
  },

  {
    id: 'SAST-CRYPTO-003',
    name: 'Math.random() used for security-sensitive operation',
    description: 'Math.random() is not cryptographically secure and must not be used for tokens, session IDs, or security values.',
    pattern: /Math\.random\s*\(\s*\)/gi,
    languages: ['javascript', 'typescript'],
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-338',
    category: 'Cryptography',
    remediation: 'Use crypto.randomBytes() or crypto.getRandomValues() for security tokens and session IDs.',
  },

  {
    id: 'SAST-CRYPTO-004',
    name: 'random.random() used in Python security context',
    description: 'Python random module is not cryptographically secure. Tokens generated with it are predictable.',
    pattern: /random\.(?:random|randint|choice|randrange)\s*\(/gi,
    languages: ['python'],
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-338',
    category: 'Cryptography',
    remediation: 'Use secrets.token_hex() or secrets.token_urlsafe() from the secrets module for all security-sensitive values.',
  },

  {
    id: 'SAST-CRYPTO-005',
    name: 'Hardcoded static initialization vector (IV)',
    description: 'A static IV defeats the purpose of encryption by making ciphertext deterministic and enabling replay attacks.',
    pattern: /(?:iv|IV|initialization_vector)\s*=\s*(?:b?["'][\x00-\xff]{8,}["']|bytes\s*\(\s*\[\s*0)/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-329',
    category: 'Cryptography',
    remediation: 'Generate a random IV for every encryption operation and store/transmit it alongside the ciphertext.',
  },

  {
    id: 'SAST-CRYPTO-006',
    name: 'SSL/TLS certificate verification disabled',
    description: 'Disabling certificate verification exposes communications to man-in-the-middle attacks.',
    pattern: /(?:verify\s*=\s*False|ssl_verify\s*=\s*false|rejectUnauthorized\s*:\s*false|InsecureRequestWarning)/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-295',
    category: 'Cryptography',
    remediation: 'Never disable certificate verification in production. Use trusted CA certificates and fix any verification issues properly.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A02 / A07 — HARDCODED SECRETS & CREDENTIALS
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-SEC-001',
    name: 'Hardcoded password in source code',
    description: 'Plaintext password found in source code. Credentials committed to source control are trivially discoverable.',
    pattern: /(?:password|passwd|pwd|pass)\s*(?:=|:)\s*["'][^"'\s]{4,}["']/gi,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-798',
    category: 'Secrets',
    remediation: 'Move credentials to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit secrets to source control.',
  },

  {
    id: 'SAST-SEC-002',
    name: 'Hardcoded API key or token',
    description: 'API key, token, or secret found hardcoded in source. Exposure allows unauthorized API access.',
    pattern: /(?:api_key|apikey|api_secret|access_token|secret_key|auth_token|client_secret)\s*(?:=|:)\s*["'][a-zA-Z0-9_\-./+]{8,}["']/gi,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-798',
    category: 'Secrets',
    remediation: 'Store API keys in environment variables and load via process.env / os.environ. Rotate any exposed keys immediately.',
  },

  {
    id: 'SAST-SEC-003',
    name: 'AWS access key pattern detected',
    description: 'String matching AWS Access Key ID format (AKIA...) found in source code.',
    pattern: /AKIA[0-9A-Z]{16}/g,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-798',
    category: 'Secrets',
    remediation: 'Revoke the exposed key immediately in AWS IAM. Use IAM roles or AWS Secrets Manager instead of hardcoded keys.',
  },

  {
    id: 'SAST-SEC-004',
    name: 'Private key PEM header detected',
    description: 'Private key material (RSA, EC, or generic) detected in source file.',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-321',
    category: 'Secrets',
    remediation: 'Remove private key from source immediately. Rotate/revoke the key. Store keys in a secure vault or use certificate management services.',
  },

  {
    id: 'SAST-SEC-005',
    name: 'Generic secret or token variable assignment',
    description: 'Variable named "secret" or "token" assigned a literal string value.',
    pattern: /(?:secret|token|private_key|signing_key)\s*(?:=|:)\s*["'][a-zA-Z0-9_\-./+]{8,}["']/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'LOW',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-798',
    category: 'Secrets',
    remediation: 'Load sensitive values from environment variables at runtime. Use a .env file (git-ignored) for local development.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A01:2021 — BROKEN ACCESS CONTROL
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-AUTHZ-001',
    name: 'Path traversal via user-controlled file path',
    description: 'File path constructed from user input without sanitization. Allows reading arbitrary files outside intended directory.',
    pattern: /(?:open|readFile|readFileSync|createReadStream|fopen|file_get_contents|include|require_once)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|user\.|input\.\w+|\$_(?:GET|POST|REQUEST))/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-22',
    category: 'Path Traversal',
    remediation: 'Resolve and canonicalize the path (path.resolve, realpath), then verify it starts with the expected base directory. Reject any path containing "..".',
  },

  {
    id: 'SAST-AUTHZ-002',
    name: 'Directory traversal sequence in user input',
    description: 'Path containing "../" or "..\\" in user-supplied input may enable directory traversal.',
    pattern: /(?:req\.|request\.|params\.|query\.|body\.)\w+.*(?:\.\.\/|\.\.\\)/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-22',
    category: 'Path Traversal',
    remediation: 'Validate that the resolved path falls within the intended base directory using path.resolve() comparison.',
  },

  {
    id: 'SAST-AUTHZ-003',
    name: 'Missing authorization check on route handler',
    description: 'Route handler accesses sensitive data without apparent authorization/authentication check.',
    pattern: /(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*["'][^"']*(?:admin|user|account|profile|settings|delete|update)[^"']*["']/gi,
    languages: ['javascript', 'typescript'],
    severity: 'MEDIUM',
    confidence: 'LOW',
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-862',
    category: 'Authorization',
    remediation: 'Apply authentication middleware to all sensitive routes. Verify the authenticated user has permission for the requested resource.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A07:2021 — IDENTIFICATION AND AUTHENTICATION FAILURES
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-AUTH-001',
    name: 'Plaintext password comparison',
    description: 'Password compared directly as plaintext string instead of a secure hash comparison.',
    pattern: /(?:password|passwd|pwd)\s*(?:===|==|!=|!==)\s*(?:req\.|request\.|params\.|query\.|body\.)\w+|(?:req\.|request\.|params\.|query\.|body\.)\w+\s*(?:===|==)\s*(?:password|passwd|pwd)/gi,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-256',
    category: 'Authentication',
    remediation: 'Use bcrypt.compare() or Argon2.verify() for password comparison. Never compare plaintext passwords.',
  },

  {
    id: 'SAST-AUTH-002',
    name: 'JWT "none" algorithm not rejected',
    description: 'JWT decoded without explicitly rejecting the "none" algorithm allows signature bypass attacks.',
    pattern: /jwt\.(?:decode|verify)\s*\([^)]*\)/gi,
    languages: ['javascript', 'typescript'],
    severity: 'CRITICAL',
    confidence: 'LOW',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-347',
    category: 'Authentication',
    remediation: 'Always specify algorithms explicitly: jwt.verify(token, secret, { algorithms: ["HS256"] }). Never accept "none" as a valid algorithm.',
  },

  {
    id: 'SAST-AUTH-003',
    name: 'Token or session ID passed in URL query string',
    description: 'Authentication tokens in URLs are logged by servers, browsers, and CDNs — easily leaked.',
    pattern: /(?:token|session|auth|jwt|api_key|key)=(?:\$\{|<%=|{{|\{)/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-598',
    category: 'Authentication',
    remediation: 'Transmit authentication tokens only in Authorization headers or httpOnly cookies — never in URL parameters.',
  },

  {
    id: 'SAST-AUTH-004',
    name: 'Weak or short secret key for HMAC/JWT',
    description: 'A short or predictable secret key for HMAC signing can be brute-forced to forge tokens.',
    pattern: /(?:secret|jwt_secret|hmac_key|signing_key)\s*(?:=|:)\s*["'][^"']{1,12}["']/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-521',
    category: 'Authentication',
    remediation: 'Use a cryptographically random secret of at least 256 bits (32 bytes). Generate with: openssl rand -hex 64',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A08:2021 — SOFTWARE AND DATA INTEGRITY FAILURES (Deserialization)
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-DESER-001',
    name: 'Insecure Python pickle deserialization',
    description: 'pickle.loads() on untrusted data allows arbitrary code execution. Pickle is not safe for untrusted input.',
    pattern: /pickle\.loads?\s*\(/gi,
    languages: ['python'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-502',
    category: 'Deserialization',
    remediation: 'Never unpickle untrusted data. Use JSON or other safe serialization formats for data exchange.',
  },

  {
    id: 'SAST-DESER-002',
    name: 'Unsafe YAML load (Python)',
    description: 'yaml.load() without explicit Loader executes arbitrary Python code in the YAML document.',
    pattern: /yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=)/gi,
    languages: ['python'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-502',
    category: 'Deserialization',
    remediation: 'Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) to prevent code execution.',
  },

  {
    id: 'SAST-DESER-003',
    name: 'PHP unserialize() on user input',
    description: 'PHP unserialize() on untrusted data allows PHP object injection and potentially RCE.',
    pattern: /unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)/gi,
    languages: ['php'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-502',
    category: 'Deserialization',
    remediation: 'Never unserialize user-controlled data. Use JSON for data exchange. If serialization is needed, verify an HMAC signature before deserializing.',
  },

  {
    id: 'SAST-DESER-004',
    name: 'Java ObjectInputStream deserialization',
    description: 'Java native deserialization of untrusted data can lead to remote code execution via gadget chains.',
    pattern: /ObjectInputStream\s*\(|\.readObject\s*\(/gi,
    languages: ['java'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-502',
    category: 'Deserialization',
    remediation: 'Avoid Java native serialization for untrusted data. Use JSON, Protocol Buffers, or apply a deserialization filter (JEP 290).',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A10:2021 — SERVER-SIDE REQUEST FORGERY (SSRF)
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-SSRF-001',
    name: 'fetch/axios/http.get with user-controlled URL',
    description: 'HTTP request made to a URL derived from user input. Allows SSRF to access internal services.',
    pattern: /(?:fetch|axios\.get|axios\.post|axios\.request|http\.get|https\.get|request\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)\w+/gi,
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A10:2021 – Server-Side Request Forgery',
    cwe: 'CWE-918',
    category: 'SSRF',
    remediation: 'Validate and whitelist allowed URL schemes, hosts, and ports. Block requests to private IP ranges (169.254.0.0/16, 10.0.0.0/8, etc.). Use an allowlist of permitted destinations.',
  },

  {
    id: 'SAST-SSRF-002',
    name: 'Python requests.get/post with user-controlled URL',
    description: 'requests library call with user-supplied URL enables SSRF to internal services or cloud metadata endpoints.',
    pattern: /requests\.(?:get|post|put|delete|patch|request)\s*\(\s*(?!["'])/gi,
    languages: ['python'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A10:2021 – Server-Side Request Forgery',
    cwe: 'CWE-918',
    category: 'SSRF',
    remediation: 'Validate URLs against an allowlist. Block access to link-local (169.254.x.x) and private ranges. Consider a proxy with egress filtering.',
  },

  {
    id: 'SAST-SSRF-003',
    name: 'Cloud metadata endpoint access detected',
    description: 'Code references the cloud instance metadata service (169.254.169.254), which leaks IAM credentials if accessed from a compromised context.',
    pattern: /169\.254\.169\.254|metadata\.google\.internal|instance-data\.ec2\.internal/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A10:2021 – Server-Side Request Forgery',
    cwe: 'CWE-918',
    category: 'SSRF',
    remediation: 'Block access to IMDS from application code. Enable IMDSv2 (require session tokens). Apply network-level controls to prevent SSRF to 169.254.169.254.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A05:2021 — SECURITY MISCONFIGURATION
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-CFG-001',
    name: 'Django/Flask DEBUG mode enabled',
    description: 'DEBUG=True in production exposes stack traces, source code, and environment variables to end users.',
    pattern: /DEBUG\s*=\s*True/g,
    languages: ['python'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-489',
    category: 'Misconfiguration',
    remediation: 'Set DEBUG=False in production. Load it from an environment variable: DEBUG = os.environ.get("DEBUG", "false") == "true"',
  },

  {
    id: 'SAST-CFG-002',
    name: 'Wildcard CORS origin',
    description: 'Access-Control-Allow-Origin: * permits any site to make authenticated requests to this API.',
    pattern: /Access-Control-Allow-Origin['":\s]*\*/gi,
    languages: ['all'],
    severity: 'MEDIUM',
    confidence: 'HIGH',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-942',
    category: 'Misconfiguration',
    remediation: 'Restrict CORS origins to an explicit allowlist of trusted domains. Never use "*" for APIs that handle authenticated requests.',
  },

  {
    id: 'SAST-CFG-003',
    name: 'Hardcoded development endpoint or localhost URL',
    description: 'Hardcoded localhost or 127.0.0.1 URL may leak to production configuration, causing connection failures or misdirected traffic.',
    pattern: /(?:http|https):\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?\/(?!$)/gi,
    languages: ['all'],
    severity: 'LOW',
    confidence: 'MEDIUM',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-547',
    category: 'Misconfiguration',
    remediation: 'Move all endpoint URLs to environment variables. Use environment-specific configuration files.',
  },

  {
    id: 'SAST-CFG-004',
    name: 'HTTP (non-TLS) endpoint in production code',
    description: 'Plain HTTP URL for an external service transmits data in cleartext — vulnerable to interception.',
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1)[a-zA-Z0-9_\-.]+\.[a-zA-Z]{2,}/gi,
    languages: ['all'],
    severity: 'MEDIUM',
    confidence: 'LOW',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-319',
    category: 'Misconfiguration',
    remediation: 'Use HTTPS for all external service endpoints. Enforce TLS in your HTTP client configuration.',
  },

  {
    id: 'SAST-CFG-005',
    name: 'Cookie without Secure or HttpOnly flag',
    description: 'Cookies set without Secure/HttpOnly flags are accessible via JavaScript and transmitted over HTTP.',
    pattern: /(?:set-cookie|res\.cookie|setcookie)\b[^;]*(?!\bsecure\b)(?!\bhttponly\b)/gi,
    languages: ['all'],
    severity: 'MEDIUM',
    confidence: 'LOW',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-614',
    category: 'Misconfiguration',
    remediation: 'Always set Secure and HttpOnly flags on session cookies: res.cookie("session", val, { httpOnly: true, secure: true, sameSite: "strict" })',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A09:2021 — SECURITY LOGGING FAILURES
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-LOG-001',
    name: 'Password or sensitive data logged',
    description: 'Password or credential value passed to a logging function exposes secrets in log files.',
    pattern: /(?:console\.log|logger\.\w+|log\.\w+|print|printf|logging\.\w+)\s*\([^)]*(?:password|passwd|secret|token|api_key|credit_card|ssn)/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A09:2021 – Security Logging and Monitoring Failures',
    cwe: 'CWE-532',
    category: 'Logging',
    remediation: 'Never log credentials, tokens, or PII. Redact sensitive fields before logging. Apply a log sanitizer or structured logging library.',
  },

  {
    id: 'SAST-LOG-002',
    name: 'Stack trace or error details sent to client',
    description: 'Detailed error messages or stack traces returned to the client expose internal structure to attackers.',
    pattern: /(?:res\.send|res\.json|response\.send)\s*\([^)]*(?:err\.stack|error\.stack|exception\.stack|err\.message|error\.message)/gi,
    languages: ['javascript', 'typescript'],
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    owasp: 'A09:2021 – Security Logging and Monitoring Failures',
    cwe: 'CWE-209',
    category: 'Logging',
    remediation: 'Return generic error messages to clients. Log full details server-side only. Use an error boundary with safe user-facing messages.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A06:2021 — VULNERABLE AND OUTDATED COMPONENTS (detection patterns)
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-DEP-001',
    name: 'Use of deprecated Node.js crypto.createCipher',
    description: 'crypto.createCipher is deprecated as of Node 10 — it derives the key in an insecure way (no salt).',
    pattern: /crypto\.createCipher\s*\(/gi,
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    cwe: 'CWE-327',
    category: 'Cryptography',
    remediation: 'Use crypto.createCipheriv() with a properly derived key (PBKDF2 or scrypt) and a random IV.',
  },

  {
    id: 'SAST-DEP-002',
    name: 'Python hashlib.new with insecure algorithm',
    description: 'hashlib.new("md5") or hashlib.new("sha1") creates a weak hash object.',
    pattern: /hashlib\.new\s*\(\s*["'](?:md5|sha1)["']/gi,
    languages: ['python'],
    severity: 'MEDIUM',
    confidence: 'HIGH',
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    cwe: 'CWE-327',
    category: 'Cryptography',
    remediation: 'Use hashlib.new("sha256") or higher. For passwords, use hashlib.scrypt or the bcrypt library.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // A04:2021 — INSECURE DESIGN
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-DESIGN-001',
    name: 'Regex Denial of Service (ReDoS) pattern',
    description: 'Regex with nested quantifiers applied to user input may cause catastrophic backtracking.',
    pattern: /new RegExp\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/gi,
    languages: ['javascript', 'typescript'],
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    owasp: 'A04:2021 – Insecure Design',
    cwe: 'CWE-1333',
    category: 'Injection',
    remediation: 'Never construct RegExp objects from user-supplied strings. Validate and sanitize input before use in regex. Consider using a ReDoS detector like safe-regex.',
  },

  {
    id: 'SAST-DESIGN-002',
    name: 'Mass assignment / object spread from request body',
    description: 'Spreading entire request body into a model update can allow privilege escalation via mass assignment.',
    pattern: /(?:\.update|\.create|\.save|\.set)\s*\(\s*\{?\s*\.\.\.(?:req|request)\.body/gi,
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A04:2021 – Insecure Design',
    cwe: 'CWE-915',
    category: 'Authorization',
    remediation: 'Explicitly pick allowed fields from request body: const { name, email } = req.body. Never spread the entire body into a database update.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // XML EXTERNAL ENTITY (XXE)
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-XXE-001',
    name: 'XML parsing without disabling external entities',
    description: 'XML parser with external entity processing enabled can be abused to read local files or cause SSRF.',
    pattern: /(?:libxml2|DOMParser|SAXParser|XMLReader|etree\.parse|lxml\.etree|xml\.etree)\s*[.(]/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'LOW',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-611',
    category: 'XXE',
    remediation: 'Disable external entity processing: parser.resolveEntities = false; defusedxml is recommended for Python. Set FEATURE_EXTERNAL_GENERAL_ENTITIES to false in Java SAXParser.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // TEMPLATE INJECTION
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-TMPL-001',
    name: 'Server-side template injection',
    description: 'Template engine called with user-controlled template string enables SSTI leading to RCE.',
    pattern: /(?:render|compile|template)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)\w+/gi,
    languages: ['all'],
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-94',
    category: 'Injection',
    remediation: 'Never render user-supplied template strings. Pass user data only as template variables, not as the template itself.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // LDAP INJECTION
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-LDAP-001',
    name: 'LDAP query with user-controlled input',
    description: 'LDAP filter built from user input without escaping allows LDAP injection to bypass authentication.',
    pattern: /(?:ldap_search|ldap\.search|ldapSearch)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/gi,
    languages: ['all'],
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-90',
    category: 'Injection',
    remediation: 'Escape all user-supplied values before including them in LDAP filters using RFC 4515 escaping.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // RACE CONDITIONS
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-RACE-001',
    name: 'Time-of-check to time-of-use (TOCTOU) pattern',
    description: 'File existence check followed by file operation without atomic locking creates a race condition window.',
    pattern: /(?:os\.path\.exists|fs\.existsSync|File\.exists)\s*\([^)]+\)[^;{]*\n[^;{]*(?:open|fs\.readFile|fs\.writeFile|fopen)/gi,
    languages: ['python', 'javascript', 'typescript', 'java'],
    severity: 'MEDIUM',
    confidence: 'LOW',
    owasp: 'A04:2021 – Insecure Design',
    cwe: 'CWE-367',
    category: 'Race Condition',
    remediation: 'Use atomic file operations or advisory locks. In Python, use try/open rather than checking existence first.',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // GO-SPECIFIC
  // ══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-GO-001',
    name: 'Go http.ListenAndServe on all interfaces without TLS',
    description: 'Binding HTTP server to 0.0.0.0 without TLS exposes plaintext traffic.',
    pattern: /http\.ListenAndServe\s*\(\s*["']:(?:8080|8000|3000|80)["']/gi,
    languages: ['go'],
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-319',
    category: 'Misconfiguration',
    remediation: 'Use http.ListenAndServeTLS with a valid certificate, or ensure TLS termination happens at a load balancer.',
  },

  {
    id: 'SAST-GO-002',
    name: 'Go sql.Open with format string query',
    description: 'SQL query built with fmt.Sprintf or string concatenation in Go leads to SQL injection.',
    pattern: /fmt\.Sprintf\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
    languages: ['go'],
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-89',
    category: 'Injection',
    remediation: 'Use parameterized queries: db.Query("SELECT * FROM users WHERE id = ?", id)',
  },
]

// ─── OWASP category metadata ────────────────────────────────────────────────
export const OWASP_CATEGORIES = [
  { id: 'A01', name: 'Broken Access Control' },
  { id: 'A02', name: 'Cryptographic Failures' },
  { id: 'A03', name: 'Injection' },
  { id: 'A04', name: 'Insecure Design' },
  { id: 'A05', name: 'Security Misconfiguration' },
  { id: 'A06', name: 'Vulnerable Components' },
  { id: 'A07', name: 'Auth Failures' },
  { id: 'A08', name: 'Integrity Failures' },
  { id: 'A09', name: 'Logging Failures' },
  { id: 'A10', name: 'SSRF' },
]
