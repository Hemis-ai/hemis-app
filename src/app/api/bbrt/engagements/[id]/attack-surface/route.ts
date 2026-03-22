import { NextRequest, NextResponse } from 'next/server'
import { getEngagement, ensureMockSeeded } from '@/lib/bbrt/engagement-orchestrator'

/**
 * GET /api/bbrt/engagements/[id]/attack-surface — Get attack surface mapping
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

    if (!engagement.attackSurface) {
      return NextResponse.json({ error: 'Attack surface data not available yet' }, { status: 404 })
    }

    return NextResponse.json({ attackSurface: engagement.attackSurface })
  } catch (err) {
    console.error('[BBRT] GET /api/bbrt/engagements/[id]/attack-surface error:', err)
    return NextResponse.json({ error: 'Failed to fetch attack surface data' }, { status: 500 })
  }
}
