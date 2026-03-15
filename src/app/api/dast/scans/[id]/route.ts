import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { getProgress } from '@/lib/dast/scan-orchestrator'
import { MOCK_DAST_SCANS } from '@/lib/mock-data/dast'

/**
 * GET /api/dast/scans/:id — Get scan details + progress
 */
export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const dbOk = await isDatabaseReachable()

    if (!dbOk) {
      const mock = MOCK_DAST_SCANS.find((s) => s.id === id)
      if (!mock) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
      return NextResponse.json({ scan: mock, demo: true })
    }

    const scan = await prisma.dastScan.findUnique({
      where: { id },
      include: { _count: { select: { dastFindings: true } } },
    })
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    const progress = getProgress(id)
    return NextResponse.json({ scan, progress: progress ?? null })
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
    const scan = await prisma.dastScan.findUnique({ where: { id } })
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
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
