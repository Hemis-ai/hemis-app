import { NextRequest, NextResponse } from 'next/server'
import { isDatabaseReachable } from '@/lib/db'
import { generateReport, type ReportFormat, type GeneratedReport } from '@/lib/dast/reports/report-service'
import type { ReportData } from '@/lib/dast/reports/html-template'
import { renderReport } from '@/lib/dast/reports/html-template'
import { generateJsonReport } from '@/lib/dast/reports/json-exporter'
import { generateCsvReport } from '@/lib/dast/reports/csv-exporter'
import { isDastEngineRunning, proxyToEngine } from '@/lib/dast/engine-proxy'
import { directScanStore } from '@/app/api/dast/scans/route'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'

/**
 * Build ReportData from in-memory direct scan store when the database is not available.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildDirectScanReportData(scanId: string): ReportData {
  const entry = directScanStore.get(scanId)
  if (!entry) throw new Error(`Scan ${scanId} not found`)
  if (entry.scan.status !== 'COMPLETED') throw new Error('Report can only be generated for completed scans')

  const s = entry.scan
  const total = (s.criticalCount ?? 0) + (s.highCount ?? 0) + (s.mediumCount ?? 0) + (s.lowCount ?? 0) + (s.infoCount ?? 0)

  return {
    scan: {
      id: s.id, name: s.name, targetUrl: s.targetUrl, scanProfile: s.scanProfile ?? 'full',
      startedAt: s.startedAt ?? null, completedAt: s.completedAt ?? null,
      endpointsDiscovered: s.endpointsDiscovered ?? 0, endpointsTested: s.endpointsTested ?? 0,
      payloadsSent: 0, riskScore: s.riskScore ?? 0, techStackDetected: s.techStackDetected ?? [],
    },
    counts: { critical: s.criticalCount ?? 0, high: s.highCount ?? 0, medium: s.mediumCount ?? 0, low: s.lowCount ?? 0, info: s.infoCount ?? 0, total },
    executiveSummary: s.executiveSummary ?? null,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    findings: entry.findings.map((f: any) => ({
      title: f.title, severity: f.severity, cvssScore: f.cvssScore ?? null, cvssVector: f.cvssVector ?? null,
      owaspCategory: f.owaspCategory ?? null, cweId: f.cweId ?? null,
      affectedUrl: f.affectedUrl, affectedParameter: f.affectedParameter ?? null,
      description: f.description ?? '', businessImpact: f.businessImpact ?? null,
      remediation: f.remediation ?? '', remediationCode: f.remediationCode ?? null,
      pciDssRefs: f.pciDssRefs ?? [], soc2Refs: f.soc2Refs ?? [], mitreAttackIds: f.mitreAttackIds ?? [],
      confidenceScore: f.confidenceScore ?? null,
    })),
    generatedAt: new Date().toISOString(),
    orgId: s.orgId ?? 'org-demo',
  }
}

/**
 * Generate a report from in-memory scan data using the same report rendering functions.
 */
function generateDirectScanReport(scanId: string, format: ReportFormat): GeneratedReport {
  const data = buildDirectScanReportData(scanId)
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')

  switch (format) {
    case 'json': {
      const content = generateJsonReport(data)
      return { scanId, format, fileName: `hemisx-dast-${scanId.substring(0, 8)}-${timestamp}.json`, contentType: 'application/json', content }
    }
    case 'csv': {
      const content = generateCsvReport(data)
      return { scanId, format, fileName: `hemisx-dast-${scanId.substring(0, 8)}-${timestamp}.csv`, contentType: 'text/csv', content }
    }
    case 'pdf': {
      const html = renderReport(data)
      return { scanId, format, fileName: `hemisx-dast-${scanId.substring(0, 8)}-${timestamp}.html`, contentType: 'text/html', content: html }
    }
  }
}

/**
 * POST /api/dast/reports/:scanId — Generate a report (PDF/JSON/CSV)
 * Routes to Python engine for real PDF generation when available.
 */
export async function POST(req: NextRequest, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params
    const body = await req.json()
    const format = (body.format as ReportFormat) || 'json'

    if (!['pdf', 'json', 'csv'].includes(format)) {
      return NextResponse.json({ error: 'Invalid format. Use pdf, json, or csv.' }, { status: 400 })
    }

    // Try Python engine first — generates real PDF with ReportLab
    const engineOk = await isDastEngineRunning()
    if (engineOk) {
      const engineRes = await proxyToEngine(`/api/dast/reports/${scanId}`, {
        method: 'POST',
        body: JSON.stringify({ format }),
        timeout: 60000,
      })
      if (engineRes?.ok) {
        if (format === 'pdf') {
          const pdfBuffer = await engineRes.arrayBuffer()
          return new NextResponse(pdfBuffer, {
            headers: {
              'Content-Type': 'application/pdf',
              'Content-Disposition': `attachment; filename="hemisx-dast-${scanId.substring(0, 8)}-report.pdf"`,
            },
          })
        }
        if (format === 'csv') {
          const csvText = await engineRes.text()
          return new NextResponse(csvText, {
            headers: {
              'Content-Type': 'text/csv',
              'Content-Disposition': `attachment; filename="hemisx-dast-${scanId.substring(0, 8)}-report.csv"`,
            },
          })
        }
        // JSON
        const data = await engineRes.json()
        return NextResponse.json(data)
      }
    }

    // Extract orgId for tenant isolation
    const token = req.cookies.get(ACCESS_COOKIE)?.value
    const jwtPayload = token ? await verifyAccessToken(token) : null
    const orgId = jwtPayload?.orgId || 'org-demo'

    // Fallback to existing report generation
    const dbOk = await isDatabaseReachable()
    const report = dbOk
      ? await generateReport(scanId, format, orgId)
      : generateDirectScanReport(scanId, format)

    if (format === 'json' || format === 'csv') {
      return new NextResponse(report.content as string, {
        headers: {
          'Content-Type': report.contentType,
          'Content-Disposition': `attachment; filename="${report.fileName}"`,
        },
      })
    }

    // For PDF fallback, return HTML that can be printed/saved as PDF
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
