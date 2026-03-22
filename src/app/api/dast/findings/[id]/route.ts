import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { directScanStore } from '@/app/api/dast/scans/route'

/**
 * GET /api/dast/findings/:id — Get finding detail
 */
export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const dbOk = await isDatabaseReachable()

    if (!dbOk) {
      // Check in-memory direct scan store for findings
      for (const entry of directScanStore.values()) {
        const found = entry.findings.find((f: { id: string }) => f.id === id)
        if (found) return NextResponse.json({ finding: found })
      }
      return NextResponse.json({ error: 'Finding not found' }, { status: 404 })
    }

    const finding = await prisma.dastFinding.findUnique({
      where: { id },
      include: { scan: { select: { id: true, name: true, targetUrl: true, orgId: true } } },
    })
    if (!finding) return NextResponse.json({ error: 'Finding not found' }, { status: 404 })

    // Verify org ownership
    const token = _req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    const orgId = payload?.orgId || 'org-demo'
    if (finding.scan.orgId !== orgId) return NextResponse.json({ error: 'Finding not found' }, { status: 404 })

    return NextResponse.json({ finding })
  } catch (error) {
    console.error('GET /api/dast/findings/:id error:', error)
    return NextResponse.json({ error: 'Failed to fetch finding' }, { status: 500 })
  }
}

/**
 * PUT /api/dast/findings/:id — Update finding status/notes
 */
export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const body = await req.json()
    const { status, notes, isConfirmed } = body

    const finding = await prisma.dastFinding.findUnique({ where: { id }, include: { scan: { select: { orgId: true } } } })
    if (!finding) return NextResponse.json({ error: 'Finding not found' }, { status: 404 })

    // Verify org ownership
    const token = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    const orgId = payload?.orgId || 'org-demo'
    if (finding.scan.orgId !== orgId) return NextResponse.json({ error: 'Finding not found' }, { status: 404 })

    const updateData: Record<string, unknown> = {}
    if (status !== undefined) updateData.status = status
    if (notes !== undefined) updateData.notes = notes
    if (isConfirmed !== undefined) {
      updateData.isConfirmed = isConfirmed
      if (isConfirmed) updateData.verifiedAt = new Date()
    }
    if (status === 'REMEDIATED') updateData.remediatedAt = new Date()
    if (status === 'FALSE_POSITIVE') { updateData.isConfirmed = false; updateData.verifiedAt = new Date() }

    const updated = await prisma.dastFinding.update({ where: { id }, data: updateData })
    return NextResponse.json({ finding: updated })
  } catch (error) {
    console.error('PUT /api/dast/findings/:id error:', error)
    return NextResponse.json({ error: 'Failed to update finding' }, { status: 500 })
  }
}
