import { NextRequest, NextResponse } from 'next/server'
import { getEngagement, ensureMockSeeded } from '@/lib/bbrt/engagement-orchestrator'

/**
 * GET /api/bbrt/engagements/[id]/findings — Get vulnerability findings
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

    return NextResponse.json({ findings: engagement.findings || [] })
  } catch (err) {
    console.error('[BBRT] GET /api/bbrt/engagements/[id]/findings error:', err)
    return NextResponse.json({ error: 'Failed to fetch findings' }, { status: 500 })
  }
}
