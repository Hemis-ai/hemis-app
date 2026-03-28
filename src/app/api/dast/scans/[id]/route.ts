import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { getProgress, getProgressLog } from '@/lib/dast/scan-orchestrator'
import { isDastEngineRunning, proxyToEngine } from '@/lib/dast/engine-proxy'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { directScanStore } from '../route'

/**
 * GET /api/dast/scans/:id — Get scan details + progress
 */
export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params

    // Check in-memory direct scan store first (no-DB mode)
    const directScan = directScanStore.get(id)
    if (directScan) {
      return NextResponse.json({ scan: directScan.scan, progress: null, findings: directScan.findings })
    }

    // Try Python engine first
    const engineOk = await isDastEngineRunning()
    if (engineOk) {
      const engineRes = await proxyToEngine(`/api/dast/scans/${id}`)
      if (engineRes?.ok) {
        const data = await engineRes.json()
        return NextResponse.json(data)
      }
    }

    // Fallback to DB
    const dbOk = await isDatabaseReachable()
    if (!dbOk) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
    }

    const scan = await prisma.dastScan.findUnique({
      where: { id },
      include: { _count: { select: { dastFindings: true } } },
    })
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    // Verify org ownership
    const token = _req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    const orgId = payload?.orgId || 'org-demo'
    if (scan.orgId !== orgId) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    const progress = getProgress(id)
    const logSince = parseInt(_req.nextUrl.searchParams.get('logSince') || '0', 10)
    const progressLog = getProgressLog(id, logSince)
    return NextResponse.json({ scan, progress: progress ?? null, progressLog })
  } catch (error) {
    console.error('GET /api/dast/scans/:id error:', error)
    return NextResponse.json({ error: 'Failed to fetch scan' }, { status: 500 })
  }
}

/**
 * DELETE /api/dast/scans/:id — Delete a scan
 */
export async function DELETE(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params

    // Try Python engine first
    const engineOk = await isDastEngineRunning()
    if (engineOk) {
      const engineRes = await proxyToEngine(`/api/dast/scans/${id}`, { method: 'DELETE' })
      if (engineRes?.ok) {
        return NextResponse.json({ success: true })
      }
    }

    // Fallback to DB
    const scan = await prisma.dastScan.findUnique({ where: { id } })
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    // Verify org ownership
    const delToken = _req.cookies.get(ACCESS_COOKIE)?.value
    const delPayload = delToken ? await verifyAccessToken(delToken) : null
    const delOrgId = delPayload?.orgId || 'org-demo'
    if (scan.orgId !== delOrgId) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    if (['RUNNING', 'QUEUED'].includes(scan.status)) {
      return NextResponse.json({ error: `Cannot delete scan in ${scan.status} state` }, { status: 409 })
    }
    await prisma.dastScan.delete({ where: { id } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('DELETE /api/dast/scans/:id error:', error)
    return NextResponse.json({ error: 'Failed to delete scan' }, { status: 500 })
  }
}
