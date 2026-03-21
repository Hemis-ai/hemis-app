import { NextRequest, NextResponse } from 'next/server'
import { getEngagement } from '@/lib/wbrt/engagement-orchestrator'

/**
 * GET /api/wbrt/engagements/[id] — Get engagement detail by ID
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

    return NextResponse.json({ engagement })
  } catch (err) {
    console.error('[WBRT] GET /api/wbrt/engagements/[id] error:', err)
    return NextResponse.json({ error: 'Failed to fetch engagement' }, { status: 500 })
  }
}
