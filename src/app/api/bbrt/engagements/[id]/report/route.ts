import { NextRequest, NextResponse } from 'next/server'
import { getEngagement, ensureMockSeeded } from '@/lib/bbrt/engagement-orchestrator'

/**
 * GET /api/bbrt/engagements/[id]/report — Get the final BBRT report
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    ensureMockSeeded()
    const { id } = await params
    const engagement = getEngagement(id)
    if (!engagement) {
      return NextResponse.json({ error: 'Engagement not found' }, { status: 404 })
    }

    if (!engagement.report) {
      return NextResponse.json({ error: 'Report not generated yet' }, { status: 404 })
    }

    return NextResponse.json({ report: engagement.report })
  } catch (err) {
    console.error('[BBRT] GET /api/bbrt/engagements/[id]/report error:', err)
    return NextResponse.json({ error: 'Failed to fetch report' }, { status: 500 })
  }
}
