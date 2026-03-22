import { NextRequest, NextResponse } from 'next/server'
import { getEngagement, runEngagement } from '@/lib/bbrt/engagement-orchestrator'

/**
 * POST /api/bbrt/engagements/[id]/run — Start the 7-phase BBRT pipeline
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params
    const engagement = getEngagement(id)
    if (!engagement) {
      return NextResponse.json({ error: 'Engagement not found' }, { status: 404 })
    }

    if (engagement.status !== 'CREATED' && engagement.status !== 'FAILED') {
      return NextResponse.json(
        { error: `Cannot run engagement in status: ${engagement.status}` },
        { status: 400 },
      )
    }

    // Fire-and-forget — same pattern as WBRT
    runEngagement(id).catch(err => {
      console.error(`[BBRT] Background run failed: ${id}`, err)
    })

    return NextResponse.json({
      message: 'Engagement started',
      engagementId: id,
      status: 'INITIALIZING',
    })
  } catch (err) {
    console.error('[BBRT] POST run error:', err)
    return NextResponse.json({ error: 'Failed to start engagement' }, { status: 500 })
  }
}
