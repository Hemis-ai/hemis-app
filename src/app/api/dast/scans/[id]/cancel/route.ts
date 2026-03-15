import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { clearProgress } from '@/lib/dast/scan-orchestrator'

/**
 * POST /api/dast/scans/:id/cancel — Cancel a running/queued scan
 */
export async function POST(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params

    const dbOk = await isDatabaseReachable()
    if (!dbOk) return NextResponse.json({ error: 'Database not available' }, { status: 503 })

    const scan = await prisma.dastScan.findUnique({ where: { id } })
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    if (!['CREATED', 'QUEUED', 'RUNNING', 'PAUSED'].includes(scan.status)) {
      return NextResponse.json(
        { error: `Cannot cancel scan in ${scan.status} state` },
        { status: 409 }
      )
    }

    const updated = await prisma.dastScan.update({
      where: { id },
      data: {
        status: 'CANCELLED',
        completedAt: new Date(),
        currentPhase: 'cancelled',
      },
    })

    // Clean up in-memory progress
    clearProgress(id)

    return NextResponse.json({ scan: updated })
  } catch (error) {
    console.error('POST /api/dast/scans/:id/cancel error:', error)
    return NextResponse.json({ error: 'Failed to cancel scan' }, { status: 500 })
  }
}
