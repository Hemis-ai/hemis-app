import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { isDastEngineRunning, proxyToEngine } from '@/lib/dast/engine-proxy'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { directScanStore } from '@/app/api/dast/scans/route'

/**
 * GET /api/dast/findings?scanId=xxx — List findings for a scan
 * Proxies to Python engine when available for real findings.
 */
export async function GET(req: NextRequest) {
  try {
    const scanId = req.nextUrl.searchParams.get('scanId')
    if (!scanId) return NextResponse.json({ error: 'scanId is required' }, { status: 400 })

    // Try Python engine first
    const engineOk = await isDastEngineRunning()
    if (engineOk) {
      const params = req.nextUrl.searchParams.toString()
      const engineRes = await proxyToEngine(`/api/dast/findings?${params}`)
      if (engineRes?.ok) {
        const data = await engineRes.json()
        return NextResponse.json(data)
      }
    }

    // Fallback to DB
    const dbOk = await isDatabaseReachable()
    if (!dbOk) {
      // Check in-memory direct scan store for findings
      const directEntry = directScanStore.get(scanId)
      if (directEntry) {
        return NextResponse.json({
          findings: directEntry.findings,
          pagination: { page: 1, pageSize: 50, total: directEntry.findings.length, totalPages: 1 },
        })
      }
      return NextResponse.json({ findings: [], pagination: { page: 1, pageSize: 50, total: 0, totalPages: 0 } })
    }

    // Verify org ownership of this scan
    const token = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    const orgId = payload?.orgId || 'org-demo'
    const scanOwner = await prisma.dastScan.findUnique({ where: { id: scanId }, select: { orgId: true } })
    if (!scanOwner || scanOwner.orgId !== orgId) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
    }

    const severity = req.nextUrl.searchParams.get('severity') || undefined
    const status = req.nextUrl.searchParams.get('status') || undefined
    const page = parseInt(req.nextUrl.searchParams.get('page') || '1', 10)
    const pageSize = parseInt(req.nextUrl.searchParams.get('pageSize') || '50', 10)

    const where = { scanId, ...(severity && { severity: severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' }), ...(status && { status: status as 'OPEN' | 'ACKNOWLEDGED' | 'REMEDIATED' | 'FALSE_POSITIVE' | 'IN_PROGRESS' }) }

    const [findings, total] = await Promise.all([
      prisma.dastFinding.findMany({
        where, orderBy: [{ cvssScore: 'desc' }, { confidenceScore: 'desc' }, { discoveredAt: 'desc' }],
        skip: (page - 1) * pageSize, take: pageSize,
      }),
      prisma.dastFinding.count({ where }),
    ])

    return NextResponse.json({ findings, pagination: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) } })
  } catch (error) {
    console.error('GET /api/dast/findings error:', error)
    return NextResponse.json({ error: 'Failed to fetch findings' }, { status: 500 })
  }
}
