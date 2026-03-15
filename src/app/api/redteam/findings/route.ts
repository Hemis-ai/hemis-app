import { NextRequest, NextResponse } from 'next/server'
import type { Finding } from '@/lib/types'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /api/redteam/findings
 * List red team vulnerabilities with filtering and pagination.
 * Query params: ?page=1&limit=20&severity=CRITICAL&scanId=<id>
 *
 * Returns DB findings when connected, falls back to mock data.
 */

interface FindingsResponse {
  findings: Finding[]
  total:    number
  page:     number
  limit:    number
  pages:    number
  source:   'db' | 'mock'
}

// Mock findings — used when DB is unavailable (demo mode)
const MOCK_FINDINGS: Finding[] = [
  {
    id: 'find_001', type: 'sql_injection', severity: 'CRITICAL', cvssScore: 9.2,
    affectedComponent: 'POST /api/v1/login',
    description: 'SQL injection vulnerability in login endpoint. User input not sanitized in SQL query.',
    remediation: 'Use parameterized queries or prepared statements. Implement input validation.',
    proof_of_concept: "' OR '1'='1", detectedAt: '2026-03-14T10:30:00Z', mitreId: 'T1190', status: 'OPEN',
  },
  {
    id: 'find_002', type: 'exposed_aws_key', severity: 'CRITICAL', cvssScore: 9.8,
    affectedComponent: 'S3 bucket: prod-config',
    description: 'AWS credentials exposed in publicly readable S3 bucket.',
    remediation: 'Rotate AWS keys immediately. Enable S3 bucket encryption and restrict access via IAM policies.',
    proof_of_concept: 'AWS_ACCESS_KEY_ID found in .env file', detectedAt: '2026-03-14T10:28:00Z', mitreId: 'T1552', status: 'OPEN',
  },
  {
    id: 'find_003', type: 'privilege_escalation', severity: 'CRITICAL', cvssScore: 9.5,
    affectedComponent: 'IAM policy: deploy-bot',
    description: 'Service account has AdministratorAccess policy, enabling full AWS account compromise.',
    remediation: 'Apply principle of least privilege. Restrict IAM permissions to only required services and actions.',
    proof_of_concept: 'Assume role deploy-bot and execute destructive AWS API calls', detectedAt: '2026-03-14T10:25:00Z', mitreId: 'T1068', status: 'OPEN',
  },
  {
    id: 'find_004', type: 'xss_vulnerability', severity: 'HIGH', cvssScore: 7.1,
    affectedComponent: 'POST /api/v1/feedback',
    description: 'Reflected XSS vulnerability. User input echoed back in HTML response without sanitization.',
    remediation: 'Sanitize all user inputs. Use HTML entity encoding. Implement Content Security Policy headers.',
    proof_of_concept: '<script>alert("XSS")</script>', detectedAt: '2026-03-14T10:20:00Z', mitreId: 'T1059', status: 'OPEN',
  },
  {
    id: 'find_005', type: 'auth_bypass', severity: 'HIGH', cvssScore: 8.2,
    affectedComponent: 'JWT token validation',
    description: 'JWT token signature verification disabled in development mode not removed in production.',
    remediation: 'Ensure JWT signature verification is always enabled. Remove all debug flags before deployment.',
    proof_of_concept: 'Modified JWT payload without valid signature accepted by API', detectedAt: '2026-03-14T10:15:00Z', mitreId: 'T1078', status: 'OPEN',
  },
  {
    id: 'find_006', type: 'command_injection', severity: 'CRITICAL', cvssScore: 9.8,
    affectedComponent: 'GET /api/v1/execute',
    description: 'Command injection vulnerability allowing arbitrary system command execution.',
    remediation: 'Avoid shell execution. Use language APIs instead. Implement strict input validation.',
    proof_of_concept: '; cat /etc/passwd', detectedAt: '2026-03-14T10:10:00Z', mitreId: 'T1059', status: 'ACKNOWLEDGED',
  },
  {
    id: 'find_007', type: 'weak_encryption', severity: 'MEDIUM', cvssScore: 5.3,
    affectedComponent: 'Database password hashing',
    description: 'Database uses deprecated MD5 hashing for passwords instead of bcrypt.',
    remediation: 'Migrate to bcrypt or Argon2. Use salt with appropriate work factor.',
    proof_of_concept: 'Rainbow table attack on extracted password hashes', detectedAt: '2026-03-14T10:05:00Z', mitreId: 'T1110', status: 'ACKNOWLEDGED',
  },
  {
    id: 'find_008', type: 'path_traversal', severity: 'HIGH', cvssScore: 7.5,
    affectedComponent: 'GET /api/v1/download',
    description: 'Path traversal vulnerability allowing access to arbitrary files.',
    remediation: 'Implement path canonicalization. Whitelist allowed directories.',
    proof_of_concept: '../../../etc/passwd', detectedAt: '2026-03-14T10:00:00Z', mitreId: 'T1083', status: 'OPEN',
  },
]

export async function GET(req: NextRequest): Promise<NextResponse<FindingsResponse>> {
  try {
    const sp       = req.nextUrl.searchParams
    const page     = Math.max(1, parseInt(sp.get('page')  ?? '1'))
    const limit    = Math.min(100, parseInt(sp.get('limit') ?? '20'))
    const severity = sp.get('severity')
    const scanId   = sp.get('scanId')

    const dbReachable = await isDatabaseReachable()

    // ── DB path ─────────────────────────────────────────────────────────────
    if (dbReachable) {
      const token   = req.cookies.get(ACCESS_COOKIE)?.value
      const payload = token ? await verifyAccessToken(token) : null

      const where: Record<string, unknown> = {}

      if (payload) {
        // Scope to org's scans
        where.scan = { orgId: payload.orgId }
      }
      if (scanId)   where.scanId   = scanId
      if (severity && ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(severity)) {
        where.severity = severity
      }

      const [total, rows] = await Promise.all([
        prisma.redTeamFinding.count({ where }),
        prisma.redTeamFinding.findMany({
          where,
          skip:    (page - 1) * limit,
          take:    limit,
          orderBy: [{ severity: 'asc' }, { detectedAt: 'desc' }],
        }),
      ])

      const findings: Finding[] = rows.map(r => ({
        id:                r.id,
        type:              r.type,
        severity:          r.severity as Finding['severity'],
        cvssScore:         r.cvssScore,
        affectedComponent: r.affectedComponent,
        description:       r.description,
        remediation:       r.remediation,
        proof_of_concept:  r.proofOfConcept ?? '',
        detectedAt:        r.detectedAt.toISOString(),
        mitreId:           r.mitreId ?? '',
        status:            r.status as Finding['status'],
      }))

      return NextResponse.json({ findings, total, page, limit, pages: Math.ceil(total / limit), source: 'db' })
    }

    // ── Mock fallback ────────────────────────────────────────────────────────
    let filtered = MOCK_FINDINGS
    if (severity && ['CRITICAL','HIGH','MEDIUM','LOW'].includes(severity)) {
      filtered = MOCK_FINDINGS.filter(f => f.severity === severity)
    }

    const total   = filtered.length
    const pages   = Math.ceil(total / limit)
    const start   = (page - 1) * limit
    const findings = filtered.slice(start, start + limit)

    console.log('[REDTEAM][DEMO] Findings queried:', { page, limit, severity: severity ?? 'ALL', total, returned: findings.length })

    return NextResponse.json({ findings, total, page, limit, pages, source: 'mock' })
  } catch (err) {
    console.error('[REDTEAM] Findings query error:', err)
    return NextResponse.json({ findings: [], total: 0, page: 1, limit: 20, pages: 0, source: 'mock' }, { status: 500 })
  }
}
