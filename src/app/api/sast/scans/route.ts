import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /api/sast/scans
 * List all SAST scans for the authenticated org (paginated).
 * Query: ?page=1&limit=20
 */
export async function GET(req: NextRequest) {
  try {
    const sp    = req.nextUrl.searchParams
    const page  = Math.max(1, parseInt(sp.get('page')  ?? '1'))
    const limit = Math.min(50, parseInt(sp.get('limit') ?? '20'))

    const dbReachable = await isDatabaseReachable()
    if (!dbReachable) {
      return NextResponse.json({ scans: [], total: 0, page, limit, pages: 0, source: 'demo' })
    }

    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    if (!payload) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })

    const where = { orgId: payload.orgId }

    const [total, scans] = await Promise.all([
      prisma.sastScan.count({ where }),
      prisma.sastScan.findMany({
        where,
        skip:    (page - 1) * limit,
        take:    limit,
        orderBy: { startedAt: 'desc' },
        select: {
          id: true, name: true, language: true, linesOfCode: true,
          filesScanned: true, status: true, duration: true,
          startedAt: true, completedAt: true,
          criticalCount: true, highCount: true, mediumCount: true,
          lowCount: true, infoCount: true,
        },
      }),
    ])

    return NextResponse.json({ scans, total, page, limit, pages: Math.ceil(total / limit), source: 'db' })
  } catch (err) {
    console.error('[SAST] List scans error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
