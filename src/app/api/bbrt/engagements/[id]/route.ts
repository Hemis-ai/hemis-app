import { NextRequest, NextResponse } from 'next/server'
import { getEngagement, deleteEngagement, ensureMockSeeded } from '@/lib/bbrt/engagement-orchestrator'

/**
 * GET /api/bbrt/engagements/[id] — Get engagement details
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
    return NextResponse.json({ engagement })
  } catch (err) {
    console.error('[BBRT] GET engagement error:', err)
    return NextResponse.json({ error: 'Failed to get engagement' }, { status: 500 })
  }
}

/**
 * DELETE /api/bbrt/engagements/[id] — Delete engagement
 */
export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params
    const deleted = deleteEngagement(id)
    if (!deleted) {
      return NextResponse.json({ error: 'Engagement not found' }, { status: 404 })
    }
    return NextResponse.json({ success: true })
  } catch (err) {
    console.error('[BBRT] DELETE engagement error:', err)
    return NextResponse.json({ error: 'Failed to delete engagement' }, { status: 500 })
  }
}
