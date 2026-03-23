import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { runDastScan } from '@/lib/dast/scan-orchestrator'
import { isDastEngineRunning, proxyToEngine } from '@/lib/dast/engine-proxy'
import { runBuiltinScan } from '@/lib/dast/builtin-scanner'

// In-memory store for direct scans (no DB mode)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const directScanStore = new Map<string, { scan: any; findings: any[]; promise?: Promise<void>; error?: string }>()

/**
 * GET /api/dast/scans — List DAST scans for the org
 * Proxies to Python engine if available, falls back to Prisma/demo mode.
 */
export async function GET(req: NextRequest) {
  try {
    // Try Python DAST engine first
    const engineOk = await isDastEngineRunning()
    if (engineOk) {
      const params = req.nextUrl.searchParams.toString()
      const engineRes = await proxyToEngine(`/api/dast/scans${params ? '?' + params : ''}`)
      if (engineRes?.ok) {
        const data = await engineRes.json()
        // Merge engine scans with DB scans
        const dbScans = await _getDbScans(req)
        return NextResponse.json({
          scans: [...(data.scans || []), ...(dbScans.scans || [])],
          pagination: data.pagination || dbScans.pagination,
          engineConnected: true,
        })
      }
    }

    // Fallback to database + in-memory direct scans
    const dbResult = await _getDbScans(req)
    // Include any direct (in-memory) scans
    const directScans = Array.from(directScanStore.values()).map(d => d.scan)
    return NextResponse.json({
      scans: [...directScans, ...(dbResult.scans || [])],
      pagination: dbResult.pagination,
    })
  } catch (error) {
    console.error('GET /api/dast/scans error:', error)
    // Still return any direct scans even on error
    const directScans = Array.from(directScanStore.values()).map(d => d.scan)
    return NextResponse.json({ scans: directScans, pagination: { page: 1, pageSize: 20, total: directScans.length, totalPages: 1 } })
  }
}

async function _getDbScans(req: NextRequest) {
  const dbOk = await isDatabaseReachable()
  if (!dbOk) {
    return { scans: [], pagination: { page: 1, pageSize: 20, total: 0, totalPages: 0 }, demo: true }
  }

  const token = req.cookies.get(ACCESS_COOKIE)?.value
  const payload = token ? await verifyAccessToken(token) : null
  const orgId = payload?.orgId || 'org-demo'

  const status = req.nextUrl.searchParams.get('status') || undefined
  const page = parseInt(req.nextUrl.searchParams.get('page') || '1', 10)
  const pageSize = parseInt(req.nextUrl.searchParams.get('pageSize') || '20', 10)

  const where = { orgId, ...(status && { status: status as 'CREATED' | 'QUEUED' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED' }) }
  const [scans, total] = await Promise.all([
    prisma.dastScan.findMany({
      where, orderBy: { createdAt: 'desc' }, skip: (page - 1) * pageSize, take: pageSize,
      include: { _count: { select: { dastFindings: true } } },
    }),
    prisma.dastScan.count({ where }),
  ])

  return { scans, pagination: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) } }
}

/**
 * POST /api/dast/scans — Create and start a new DAST scan
 * Routes to Python engine when available for real vulnerability detection.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { name, targetUrl, scope, excludedPaths, authConfig, scanProfile } = body

    if (!name?.trim()) return NextResponse.json({ error: 'Scan name is required' }, { status: 400 })
    if (!targetUrl?.trim()) return NextResponse.json({ error: 'Target URL is required' }, { status: 400 })

    // Validate URL format
    try { new URL(targetUrl) } catch { return NextResponse.json({ error: 'Invalid target URL' }, { status: 400 }) }

    // Try Python DAST engine first — this does REAL scanning
    const engineOk = await isDastEngineRunning()
    if (engineOk) {
      const engineRes = await proxyToEngine('/api/dast/scans', {
        method: 'POST',
        body: JSON.stringify({ name, targetUrl, scanProfile: scanProfile || 'full', authConfig, scope }),
        timeout: 60000,
      })
      if (engineRes?.ok) {
        const data = await engineRes.json()
        return NextResponse.json(data, { status: 201 })
      }
    }

    // Fallback to database-based scan
    const dbOk = await isDatabaseReachable()
    if (dbOk) {
      const token = req.cookies.get(ACCESS_COOKIE)?.value
      const payload = token ? await verifyAccessToken(token) : null
      const orgId = payload?.orgId || 'org-demo'

      const scan = await prisma.dastScan.create({
        data: {
          orgId, name: name.trim(), targetUrl: targetUrl.trim(),
          scope: scope ?? [], excludedPaths: excludedPaths ?? [],
          authConfig: authConfig ?? null, scanProfile: scanProfile ?? 'full',
          status: 'CREATED',
        },
      })

      // Start scan in background (fire-and-forget)
      runDastScan(scan.id).catch((err) => console.error('Background scan error:', err))

      return NextResponse.json({ scan }, { status: 201 })
    }

    // No engine, no database — run built-in scanner directly and return results
    // This is the "standalone" mode: scan runs inline and returns findings immediately
    const scanId = `direct-${Date.now()}`
    const scan = {
      id: scanId, orgId: 'org-demo', name: name.trim(), targetUrl: targetUrl.trim(),
      scanProfile: scanProfile ?? 'full', status: 'RUNNING' as const, progress: 0,
      currentPhase: 'initializing', startedAt: new Date().toISOString(),
    }

    // Return scan immediately, then the frontend will poll /api/dast/scans/[id] for progress
    // But since we don't have a DB, we'll run the scan and store results in-memory
    const directScanPromise = runBuiltinScan(targetUrl).then(result => {
      const criticalCount = result.findings.filter(f => f.severity === 'CRITICAL').length
      const highCount = result.findings.filter(f => f.severity === 'HIGH').length
      const mediumCount = result.findings.filter(f => f.severity === 'MEDIUM').length
      const lowCount = result.findings.filter(f => f.severity === 'LOW').length
      const infoCount = result.findings.filter(f => f.severity === 'INFO').length
      const riskScore = Math.min(100, criticalCount * 25 + highCount * 10 + mediumCount * 3)

      // Generate executive summary
      const keyFindings = result.findings
        .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
        .map(f => `- **${f.title}** (${f.severity}) — ${f.affectedUrl}`)
        .join('\n') || '- No critical or high severity issues found'
      const summary = `## Scan Overview\nBuilt-in DAST scan of **${targetUrl}** identified **${result.findings.length} issues** across ${criticalCount} critical, ${highCount} high, ${mediumCount} medium, ${lowCount} low, and ${infoCount} informational severity levels.\n\n## Key Findings\n${keyFindings}\n\n## Technology Stack\n${result.techStack.length > 0 ? result.techStack.join(', ') : 'Not detected'}`

      directScanStore.set(scanId, {
        scan: {
          ...scan, status: 'COMPLETED', progress: 100, currentPhase: 'complete',
          completedAt: new Date().toISOString(), riskScore,
          criticalCount, highCount, mediumCount, lowCount, infoCount,
          endpointsDiscovered: result.endpointsDiscovered, endpointsTested: result.endpointsTested,
          payloadsSent: result.payloadsSent,
          techStackDetected: result.techStack,
          executiveSummary: summary,
        },
        findings: result.findings.map((f, i) => ({
          id: `${scanId}-f${i}`, scanId,
          ...f,
          // Ensure all DastFinding fields are present for reports/dashboard
          cvssVector: f.cvssVector ?? null,
          remediationCode: f.remediationCode ?? null,
          isConfirmed: f.isConfirmed ?? false,
          pciDssRefs: f.pciDssRefs ?? [],
          soc2Refs: f.soc2Refs ?? [],
          mitreAttackIds: f.mitreAttackIds ?? [],
          businessImpact: f.businessImpact ?? null,
          status: 'OPEN',
        })),
      })
    }).catch(err => {
      directScanStore.set(scanId, {
        scan: { ...scan, status: 'FAILED', progress: -1, currentPhase: 'failed', completedAt: new Date().toISOString() },
        findings: [],
        error: err instanceof Error ? err.message : 'Scan failed',
      })
    })

    // Store the promise so polling knows a scan is running
    directScanStore.set(scanId, { scan, findings: [], promise: directScanPromise })

    return NextResponse.json({ scan }, { status: 201 })
  } catch (error) {
    console.error('POST /api/dast/scans error:', error)
    return NextResponse.json({ error: 'Failed to create scan' }, { status: 500 })
  }
}
