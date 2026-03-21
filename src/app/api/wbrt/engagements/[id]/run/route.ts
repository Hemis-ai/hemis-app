import { NextRequest, NextResponse } from 'next/server'
import { getEngagement, runEngagement } from '@/lib/wbrt/engagement-orchestrator'
import type { SastFindingResult } from '@/lib/types/sast'

/**
 * POST /api/wbrt/engagements/[id]/run — Trigger WBRT analysis
 *
 * Gets the engagement, fetches SAST findings if sastScanId is set,
 * then kicks off the 6-phase pipeline (fire-and-forget).
 * Returns 202 Accepted immediately.
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
        { error: `Engagement is already ${engagement.status.toLowerCase()}` },
        { status: 409 },
      )
    }

    // Fetch SAST findings if a scan ID was provided
    let findings: SastFindingResult[] = []
    if (engagement.sastScanId) {
      try {
        // Try to fetch from internal SAST API
        const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:7777'
        const res = await fetch(`${baseUrl}/api/sast/scan/${engagement.sastScanId}`, {
          headers: { 'Content-Type': 'application/json' },
        })
        if (res.ok) {
          const data = await res.json()
          findings = data.findings || []
        }
      } catch {
        // SAST fetch failed — will run in demo mode with empty findings
        console.warn(`[WBRT] Could not fetch SAST scan ${engagement.sastScanId}, running in demo mode`)
      }
    }

    // Fire-and-forget: start the analysis pipeline
    runEngagement(id, findings).catch((err) =>
      console.error(`[WBRT] Background engagement error: ${id}`, err)
    )

    console.log(`[WBRT] Analysis triggered: ${id}`, {
      findings: findings.length,
      sastScanId: engagement.sastScanId || 'none',
    })

    return NextResponse.json(
      { message: 'Analysis started', engagementId: id, findingsIngested: findings.length },
      { status: 202 },
    )
  } catch (err) {
    console.error('[WBRT] POST /api/wbrt/engagements/[id]/run error:', err)
    return NextResponse.json({ error: 'Failed to start analysis' }, { status: 500 })
  }
}
