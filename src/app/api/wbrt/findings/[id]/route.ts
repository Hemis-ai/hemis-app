import { NextRequest, NextResponse } from 'next/server'
import { getEngagement } from '@/lib/wbrt/engagement-orchestrator'
import type { WbrtFindingStatus } from '@/lib/types/wbrt'

const VALID_STATUSES: WbrtFindingStatus[] = ['OPEN', 'ACKNOWLEDGED', 'REMEDIATED', 'ACCEPTED_RISK', 'IN_PROGRESS']

/**
 * GET /api/wbrt/findings/[id] — Get chained findings for an engagement
 *
 * The [id] parameter is the engagement ID.
 * Returns the findings array from the engagement.
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

    if (engagement.findings.length === 0 && engagement.status !== 'COMPLETED') {
      return NextResponse.json(
        { error: 'Findings not yet generated. Run the analysis first.' },
        { status: 404 },
      )
    }

    return NextResponse.json({ findings: engagement.findings })
  } catch (err) {
    console.error('[WBRT] GET /api/wbrt/findings/[id] error:', err)
    return NextResponse.json({ error: 'Failed to fetch findings' }, { status: 500 })
  }
}

/**
 * PATCH /api/wbrt/findings/[id] — Update finding status
 *
 * The [id] parameter is the engagement ID.
 * Body: { findingId, status }
 */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params
    const body = await req.json()
    const { findingId, status } = body

    if (!findingId) {
      return NextResponse.json({ error: 'findingId is required' }, { status: 400 })
    }
    if (!status || !VALID_STATUSES.includes(status)) {
      return NextResponse.json(
        { error: `Invalid status. Must be one of: ${VALID_STATUSES.join(', ')}` },
        { status: 400 },
      )
    }

    const engagement = getEngagement(id)
    if (!engagement) {
      return NextResponse.json({ error: 'Engagement not found' }, { status: 404 })
    }

    const finding = engagement.findings.find(f => f.id === findingId)
    if (!finding) {
      return NextResponse.json({ error: 'Finding not found' }, { status: 404 })
    }

    finding.status = status as WbrtFindingStatus

    console.log(`[WBRT] Finding status updated: ${findingId} → ${status}`)

    return NextResponse.json({ finding })
  } catch (err) {
    console.error('[WBRT] PATCH /api/wbrt/findings/[id] error:', err)
    return NextResponse.json({ error: 'Failed to update finding' }, { status: 500 })
  }
}
