import { NextRequest, NextResponse } from 'next/server'
import { enrichFinding, enrichFindings, enrichScanSummary } from '@/lib/sast/ai-enrichment'
import type { SastFindingResult, SastScanResult } from '@/lib/types/sast'

/**
 * POST /api/sast/enrich
 * AI-powered enrichment of SAST findings.
 *
 * Modes:
 *   { action: "finding", finding: SastFindingResult, fileContext?: string }
 *   { action: "batch", findings: SastFindingResult[] }
 *   { action: "summary", scan: SastScanResult }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { action } = body

    switch (action) {
      case 'finding': {
        const { finding, fileContext } = body as {
          finding: SastFindingResult
          fileContext?: string
          action: string
        }
        if (!finding) {
          return NextResponse.json({ error: 'finding is required' }, { status: 400 })
        }
        const enrichment = await enrichFinding(finding, fileContext)
        return NextResponse.json({ enrichment })
      }

      case 'batch': {
        const { findings } = body as { findings: SastFindingResult[]; action: string }
        if (!Array.isArray(findings) || findings.length === 0) {
          return NextResponse.json({ error: 'findings array is required' }, { status: 400 })
        }
        // Limit batch size
        const limited = findings.slice(0, 10)
        const enrichments = await enrichFindings(limited)
        // Convert Map to plain object for JSON serialization
        const result: Record<string, unknown> = {}
        enrichments.forEach((v, k) => { result[k] = v })
        return NextResponse.json({ enrichments: result, processed: limited.length })
      }

      case 'summary': {
        const { scan } = body as { scan: SastScanResult; action: string }
        if (!scan) {
          return NextResponse.json({ error: 'scan is required' }, { status: 400 })
        }
        const summary = await enrichScanSummary(scan)
        return NextResponse.json({ summary })
      }

      default:
        return NextResponse.json(
          { error: 'Invalid action. Use "finding", "batch", or "summary"' },
          { status: 400 }
        )
    }
  } catch (err) {
    console.error('[SAST Enrich] Error:', err)
    return NextResponse.json({ error: 'Enrichment failed' }, { status: 500 })
  }
}
