import { NextRequest, NextResponse } from 'next/server'
import { generateExecutiveReport } from '@/lib/sast/report-generator'
import { mapToCompliance } from '@/lib/sast/compliance-mapper'
import type { SastScanResult } from '@/lib/types/sast'

/**
 * POST /api/sast/report
 * Generate an executive security report from scan results.
 * Body: { scan: SastScanResult, includeCompliance?: boolean }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { scan, includeCompliance } = body as {
      scan: SastScanResult
      includeCompliance?: boolean
    }

    if (!scan || !scan.findings) {
      return NextResponse.json({ error: 'scan with findings is required' }, { status: 400 })
    }

    const compliance = includeCompliance ? mapToCompliance(scan.findings) : undefined
    const report = generateExecutiveReport(scan, compliance)

    return NextResponse.json({ report })
  } catch (err) {
    console.error('[SAST] Report generation error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
