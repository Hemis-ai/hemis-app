import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * PATCH /api/sast/findings/:id
 * Update a finding's status or mark it as a false positive.
 * Body: { status?, falsePositive? }
 */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    if (!id) return NextResponse.json({ error: 'Finding ID required' }, { status: 400 })

    const dbReachable = await isDatabaseReachable()
    if (!dbReachable) {
      return NextResponse.json({ error: 'Database unavailable' }, { status: 503 })
    }

    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    if (!payload) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })

    const body = await req.json()
    const { status, falsePositive } = body as { status?: string; falsePositive?: boolean }

    // Validate status if provided
    const validStatuses = ['OPEN', 'ACKNOWLEDGED', 'REMEDIATED', 'IN_PROGRESS']
    if (status && !validStatuses.includes(status)) {
      return NextResponse.json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` }, { status: 400 })
    }

    // Verify finding belongs to the user's org
    const finding = await prisma.sastFinding.findFirst({
      where: { id },
      include: { scan: { select: { orgId: true } } },
    })

    if (!finding || finding.scan.orgId !== payload.orgId) {
      return NextResponse.json({ error: 'Finding not found' }, { status: 404 })
    }

    // Build update payload
    const update: Record<string, unknown> = {}
    if (status !== undefined) update.status = status
    if (falsePositive !== undefined) update.falsePositive = falsePositive

    if (Object.keys(update).length === 0) {
      return NextResponse.json({ error: 'No fields to update' }, { status: 400 })
    }

    const updated = await prisma.sastFinding.update({
      where: { id },
      data:  update,
    })

    // Audit log
    await prisma.auditLog.create({
      data: {
        orgId:    payload.orgId,
        userId:   payload.userId,
        action:   'sast.finding.update',
        resource: id,
        meta:     { scanId: finding.scanId, changes: JSON.parse(JSON.stringify(update)) },
        ipAddress: req.headers.get('x-forwarded-for') ?? undefined,
      },
    }).catch(() => null)

    return NextResponse.json(updated)
  } catch (err) {
    console.error('[SAST] Update finding error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
