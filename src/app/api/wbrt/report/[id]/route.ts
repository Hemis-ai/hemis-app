import { NextRequest, NextResponse } from 'next/server'
import { getEngagement } from '@/lib/wbrt/engagement-orchestrator'
import { generateReport } from '@/lib/wbrt/report-generator'

/**
 * GET /api/wbrt/report/[id] — Get the executive report for an engagement
 *
 * The [id] parameter is the engagement ID.
 * Returns the report if it exists.
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

    if (!engagement.report) {
      return NextResponse.json(
        { error: 'Report not yet generated. Run the analysis first.' },
        { status: 404 },
      )
    }

    return NextResponse.json({ report: engagement.report })
  } catch (err) {
    console.error('[WBRT] GET /api/wbrt/report/[id] error:', err)
    return NextResponse.json({ error: 'Failed to fetch report' }, { status: 500 })
  }
}

/**
 * POST /api/wbrt/report/[id] — Generate (or regenerate) the report
 *
 * The [id] parameter is the engagement ID.
 * Requires the analysis to be complete (findings, kill chains, attack graph present).
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

    if (!engagement.attackGraph || engagement.findings.length === 0) {
      return NextResponse.json(
        { error: 'Analysis must be complete before generating a report' },
        { status: 400 },
      )
    }

    const report = generateReport(
      id,
      engagement.findings,
      engagement.killChains,
      engagement.attackGraph,
      engagement.architectureContext,
    )

    engagement.report = report

    console.log(`[WBRT] Report generated for engagement: ${id}`, {
      riskScore: report.overallRiskScore,
      riskLevel: report.riskLevel,
    })

    return NextResponse.json({ report }, { status: 201 })
  } catch (err) {
    console.error('[WBRT] POST /api/wbrt/report/[id] error:', err)
    return NextResponse.json({ error: 'Failed to generate report' }, { status: 500 })
  }
}
