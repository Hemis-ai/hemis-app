import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /api/sast/scan/:id
 * Returns the full result of a completed SAST scan.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    if (!id) return NextResponse.json({ error: 'Scan ID required' }, { status: 400 })

    const dbReachable = await isDatabaseReachable()
    if (!dbReachable) {
      return NextResponse.json({ error: 'Database unavailable — scan results are in-memory only in demo mode' }, { status: 503 })
    }

    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    if (!payload) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })

    const scan = await prisma.sastScan.findFirst({
      where:   { id, orgId: payload.orgId },
      include: { findings: { orderBy: [{ severity: 'asc' }, { detectedAt: 'desc' }] } },
    })

    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    return NextResponse.json(scan)
  } catch (err) {
    console.error('[SAST] Get scan error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

/**
 * PATCH /api/sast/scan/:id — update scan metadata (e.g. name).
 */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    if (!id) return NextResponse.json({ error: 'Scan ID required' }, { status: 400 })

    const dbReachable = await isDatabaseReachable()
    if (!dbReachable) {
      return NextResponse.json({ error: 'Database unavailable' }, { status: 503 })
    }

    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    if (!payload) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })

    const body = await req.json()
    const { name } = body as { name?: string }

    const scan = await prisma.sastScan.findFirst({ where: { id, orgId: payload.orgId } })
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    const updated = await prisma.sastScan.update({
      where: { id },
      data:  { ...(name ? { name } : {}) },
    })

    return NextResponse.json(updated)
  } catch (err) {
    console.error('[SAST] Update scan error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
