import { NextRequest, NextResponse } from 'next/server'
import { generateExecutiveReport } from '@/lib/sast/report-generator'
import { mapToCompliance } from '@/lib/sast/compliance-mapper'
import { generatePdf } from '@/lib/sast/pdf-generator'
import type { SastScanResult } from '@/lib/types/sast'

/**
 * POST /api/sast/report/pdf
 * Generate a PDF executive security report.
 * Body: { scan: SastScanResult, includeCompliance?: boolean }
 * Returns: PDF binary with Content-Disposition header
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

    // Generate the structured report data
    const compliance = includeCompliance ? mapToCompliance(scan.findings) : undefined
    const report = generateExecutiveReport(scan, compliance)

    // Render to PDF
    const pdfBuffer = await generatePdf(report)

    const scanSlug = scan.id ? scan.id.slice(0, 8) : 'report'

    return new NextResponse(new Uint8Array(pdfBuffer), {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="hemisx-sast-${scanSlug}.pdf"`,
        'Content-Length': String(pdfBuffer.length),
        'Cache-Control': 'no-store',
      },
    })
  } catch (err) {
    console.error('[SAST] PDF generation error:', err)
    return NextResponse.json({ error: 'PDF generation failed' }, { status: 500 })
  }
}
