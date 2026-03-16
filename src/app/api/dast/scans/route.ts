import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { runDastScan } from '@/lib/dast/scan-orchestrator'

/**
 * GET /api/dast/scans — List DAST scans for the org
 */
export async function GET(req: NextRequest) {
  try {
    const dbOk = await isDatabaseReachable()
    if (!dbOk) {
      return NextResponse.json({ scans: [], pagination: { page: 1, pageSize: 20, total: 0, totalPages: 0 }, demo: true })
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

    return NextResponse.json({ scans, pagination: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) } })
  } catch (error) {
    console.error('GET /api/dast/scans error:', error)
    return NextResponse.json({ scans: [], pagination: { page: 1, pageSize: 20, total: 0, totalPages: 0 }, demo: true })
  }
}

/**
 * POST /api/dast/scans — Create and start a new DAST scan
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { name, targetUrl, scope, excludedPaths, authConfig, scanProfile } = body

    if (!name?.trim()) return NextResponse.json({ error: 'Scan name is required' }, { status: 400 })
    if (!targetUrl?.trim()) return NextResponse.json({ error: 'Target URL is required' }, { status: 400 })

    // Validate URL format
    try { new URL(targetUrl) } catch { return NextResponse.json({ error: 'Invalid target URL' }, { status: 400 }) }

    const dbOk = await isDatabaseReachable()
    if (!dbOk) return NextResponse.json({ error: 'Database not available' }, { status: 503 })

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
  } catch (error) {
    console.error('POST /api/dast/scans error:', error)
    return NextResponse.json({ error: 'Failed to create scan' }, { status: 500 })
  }
}
