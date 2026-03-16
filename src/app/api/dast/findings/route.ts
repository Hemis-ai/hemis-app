import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /api/dast/findings?scanId=xxx — List findings for a scan
 */
export async function GET(req: NextRequest) {
  try {
    const scanId = req.nextUrl.searchParams.get('scanId')
    if (!scanId) return NextResponse.json({ error: 'scanId is required' }, { status: 400 })

    const dbOk = await isDatabaseReachable()
    if (!dbOk) {
      return NextResponse.json({ findings: [], pagination: { page: 1, pageSize: 50, total: 0, totalPages: 0 }, demo: true })
    }

    const severity = req.nextUrl.searchParams.get('severity') || undefined
    const status = req.nextUrl.searchParams.get('status') || undefined
    const page = parseInt(req.nextUrl.searchParams.get('page') || '1', 10)
    const pageSize = parseInt(req.nextUrl.searchParams.get('pageSize') || '50', 10)

    const where = { scanId, ...(severity && { severity: severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' }), ...(status && { status: status as 'OPEN' | 'ACKNOWLEDGED' | 'REMEDIATED' | 'FALSE_POSITIVE' | 'IN_PROGRESS' }) }

    const [findings, total] = await Promise.all([
      prisma.dastFinding.findMany({
        where, orderBy: [{ severity: 'asc' }, { cvssScore: 'desc' }, { discoveredAt: 'desc' }],
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
