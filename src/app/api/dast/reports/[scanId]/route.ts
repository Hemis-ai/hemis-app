import { NextRequest, NextResponse } from 'next/server'
import { isDatabaseReachable } from '@/lib/db'
import { generateReport, type ReportFormat } from '@/lib/dast/reports/report-service'

/**
 * POST /api/dast/reports/:scanId — Generate a report (PDF/JSON/CSV)
 */
export async function POST(req: NextRequest, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params
    const body = await req.json()
    const format = (body.format as ReportFormat) || 'json'

    if (!['pdf', 'json', 'csv'].includes(format)) {
      return NextResponse.json({ error: 'Invalid format. Use pdf, json, or csv.' }, { status: 400 })
    }

    const dbOk = await isDatabaseReachable()
    if (!dbOk) return NextResponse.json({ error: 'Database not available' }, { status: 503 })

    const report = await generateReport(scanId, format)

    // Return the report content directly for download
    if (format === 'json' || format === 'csv') {
      return new NextResponse(report.content as string, {
        headers: {
          'Content-Type': report.contentType,
          'Content-Disposition': `attachment; filename="${report.fileName}"`,
        },
      })
    }

    // For PDF, return HTML that can be printed/saved as PDF
    return new NextResponse(report.content as string, {
      headers: {
        'Content-Type': 'text/html',
        'Content-Disposition': `inline; filename="${report.fileName}"`,
      },
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to generate report'
    const status = message.includes('not found') ? 404 : message.includes('completed') ? 400 : 500
    console.error('POST /api/dast/reports/:scanId error:', error)
    return NextResponse.json({ error: message }, { status })
  }
}
