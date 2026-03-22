import { NextRequest, NextResponse } from 'next/server'
import { progressStore } from '@/lib/bbrt/engagement-orchestrator'

/**
 * GET /api/bbrt/engagements/[id]/progress — Poll current analysis progress
 *
 * Returns the latest BbrtProgressEvent for the engagement.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params
    const progress = progressStore.get(id)

    if (!progress) {
      return NextResponse.json({
        engagementId: id,
        status: 'CREATED',
        progress: 0,
        currentPhase: 'created',
        message: 'Engagement created, awaiting analysis start',
        timestamp: new Date().toISOString(),
      })
    }

    return NextResponse.json(progress)
  } catch (err) {
    console.error('[BBRT] GET /api/bbrt/engagements/[id]/progress error:', err)
    return NextResponse.json({ error: 'Failed to fetch progress' }, { status: 500 })
  }
}
