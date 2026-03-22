import { NextRequest, NextResponse } from 'next/server'
import { getEngagement, ensureMockSeeded } from '@/lib/bbrt/engagement-orchestrator'

/**
 * GET /api/bbrt/engagements/[id]/recon — Get reconnaissance results
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

    if (!engagement.reconResult) {
      return NextResponse.json({ error: 'Recon data not available yet' }, { status: 404 })
    }

    return NextResponse.json({ recon: engagement.reconResult })
  } catch (err) {
    console.error('[BBRT] GET /api/bbrt/engagements/[id]/recon error:', err)
    return NextResponse.json({ error: 'Failed to fetch recon data' }, { status: 500 })
  }
}
