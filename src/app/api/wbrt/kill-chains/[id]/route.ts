import { NextRequest, NextResponse } from 'next/server'
import { getEngagement } from '@/lib/wbrt/engagement-orchestrator'

/**
 * GET /api/wbrt/kill-chains/[id] — Get kill chains for an engagement
 *
 * The [id] parameter is the engagement ID.
 * Returns the killChains array from the engagement.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params
    const engagement = getEngagement(id)

    if (!engagement) {
      return NextResponse.json({ error: 'Engagement not found' }, { status: 404 })
    }

    if (engagement.killChains.length === 0 && engagement.status !== 'COMPLETED') {
      return NextResponse.json(
        { error: 'Kill chains not yet generated. Run the analysis first.' },
        { status: 404 },
      )
    }

    return NextResponse.json({ killChains: engagement.killChains })
  } catch (err) {
    console.error('[WBRT] GET /api/wbrt/kill-chains/[id] error:', err)
    return NextResponse.json({ error: 'Failed to fetch kill chains' }, { status: 500 })
  }
}
