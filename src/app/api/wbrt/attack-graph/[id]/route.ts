import { NextRequest, NextResponse } from 'next/server'
import { getEngagement } from '@/lib/wbrt/engagement-orchestrator'

/**
 * GET /api/wbrt/attack-graph/[id] — Get attack graph for an engagement
 *
 * The [id] parameter is the engagement ID.
 * Returns the attackGraph from the engagement if analysis is complete.
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

    if (!engagement.attackGraph) {
      return NextResponse.json(
        { error: 'Attack graph not yet generated. Run the analysis first.' },
        { status: 404 },
      )
    }

    return NextResponse.json({ attackGraph: engagement.attackGraph })
  } catch (err) {
    console.error('[WBRT] GET /api/wbrt/attack-graph/[id] error:', err)
    return NextResponse.json({ error: 'Failed to fetch attack graph' }, { status: 500 })
  }
}
