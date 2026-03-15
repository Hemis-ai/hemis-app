/**
 * Mock Vulnerability Scanner
 * Simulates red team scanning and returns realistic findings
 */

import type { Finding } from '@/lib/types'
import { getMitreMapping } from './mitre-mapper'
import { estimateCVSSByType } from './cvss-calculator'

const VULN_DATABASE = [
  {
    type: 'sql_injection',
    severity: 'CRITICAL' as const,
    component: 'POST /api/v1/login',
    description: 'SQL injection vulnerability in login endpoint. User input not sanitized in SQL query.',
    remediation: 'Use parameterized queries or prepared statements. Implement input validation.',
    poc: "' OR '1'='1",
  },
  {
    type: 'xss',
    severity: 'HIGH' as const,
    component: 'POST /api/v1/feedback',
    description: 'Reflected XSS vulnerability. User input echoed back in HTML response without sanitization.',
    remediation: 'Sanitize all user inputs. Use HTML entity encoding. Implement Content Security Policy headers.',
    poc: '<script>alert("XSS")</script>',
  },
  {
    type: 'command_injection',
    severity: 'CRITICAL' as const,
    component: 'GET /api/v1/execute',
    description: 'Command injection vulnerability allowing arbitrary system command execution.',
    remediation: 'Avoid shell execution. Use language APIs instead. Implement strict input validation.',
    poc: '; cat /etc/passwd',
  },
  {
    type: 'path_traversal',
    severity: 'HIGH' as const,
    component: 'GET /api/v1/download',
    description: 'Path traversal vulnerability allowing access to arbitrary files.',
    remediation: 'Implement path canonicalization. Whitelist allowed directories.',
    poc: '../../../etc/passwd',
  },
  {
    type: 'ssrf',
    severity: 'HIGH' as const,
    component: 'POST /api/v1/proxy',
    description: 'Server-side request forgery allowing requests to internal systems.',
    remediation: 'Implement URL whitelist. Disable access to internal IPs.',
    poc: 'http://169.254.169.254/latest/meta-data/',
  },
  {
    type: 'auth_bypass',
    severity: 'CRITICAL' as const,
    component: 'JWT token validation',
    description: 'JWT token signature verification disabled or improperly implemented.',
    remediation: 'Always verify JWT signatures. Remove debug modes.',
    poc: 'Modified JWT payload without signature',
  },
  {
    type: 'privilege_escalation',
    severity: 'CRITICAL' as const,
    component: 'IAM policy: deploy-bot',
    description: 'Service account has excessive permissions enabling account compromise.',
    remediation: 'Apply principle of least privilege. Restrict IAM permissions.',
    poc: 'Assume role with admin permissions',
  },
  {
    type: 'exposed_credentials',
    severity: 'CRITICAL' as const,
    component: 'S3 bucket: prod-config',
    description: 'Credentials exposed in publicly accessible storage.',
    remediation: 'Rotate credentials. Enable bucket encryption and access restrictions.',
    poc: 'AWS_ACCESS_KEY_ID found in .env',
  },
  {
    type: 'weak_encryption',
    severity: 'MEDIUM' as const,
    component: 'Database password hashing',
    description: 'Weak hash algorithm (MD5) used for password storage instead of bcrypt.',
    remediation: 'Migrate to bcrypt or Argon2. Use appropriate work factor.',
    poc: 'Rainbow table attack',
  },
  {
    type: 'missing_headers',
    severity: 'MEDIUM' as const,
    component: 'HTTP response headers',
    description: 'Missing security headers (HSTS, X-Frame-Options, CSP).',
    remediation: 'Implement standard security headers for all responses.',
    poc: 'Browser vulnerability exploitation',
  },
]

/**
 * Mock scan simulation
 * @param target - Target URL/IP
 * @param scope - List of authorized scopes (CIDR/domains)
 * @returns Promise<Finding[]> - Array of discovered vulnerabilities
 */
export async function mockScan(target: string, scope: string[]): Promise<Finding[]> {
  // Simulate scan processing time
  await new Promise(resolve => setTimeout(resolve, 500))

  // Randomly select 3-8 vulnerabilities for this scan
  const findingCount = Math.floor(Math.random() * 6) + 3

  const findings: Finding[] = []

  // Shuffle and take random subset
  const shuffled = [...VULN_DATABASE].sort(() => Math.random() - 0.5)

  for (let i = 0; i < findingCount && i < shuffled.length; i++) {
    const vuln = shuffled[i]
    const mitre = getMitreMapping(vuln.type)
    const cvss = estimateCVSSByType(vuln.type)

    findings.push({
      id: `find_${Date.now()}_${i}`,
      type: vuln.type,
      severity: vuln.severity,
      cvssScore: cvss.score,
      affectedComponent: vuln.component,
      description: vuln.description,
      remediation: vuln.remediation,
      proof_of_concept: vuln.poc,
      detectedAt: new Date().toISOString(),
      mitreId: mitre.techniqueId,
      status: 'OPEN',
    })
  }

  return findings.sort((a, b) => {
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
    return severityOrder[a.severity] - severityOrder[b.severity]
  })
}

/**
 * Get vulnerability details for a specific type
 */
export function getVulnerabilityDetails(type: string): (typeof VULN_DATABASE)[0] | null {
  return VULN_DATABASE.find(v => v.type === type) || null
}

/**
 * Get all available vulnerability types
 */
export function getAvailableVulnTypes(): string[] {
  return VULN_DATABASE.map(v => v.type)
}
