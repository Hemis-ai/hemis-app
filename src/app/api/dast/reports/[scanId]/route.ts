import { NextRequest, NextResponse } from 'next/server'
import { isDatabaseReachable } from '@/lib/db'
import { generateReport, type ReportFormat, type GeneratedReport } from '@/lib/dast/reports/report-service'
import type { ReportData } from '@/lib/dast/reports/html-template'
import { renderReport } from '@/lib/dast/reports/html-template'
import { generateJsonReport } from '@/lib/dast/reports/json-exporter'
import { generateCsvReport } from '@/lib/dast/reports/csv-exporter'
import { MOCK_DAST_SCANS, MOCK_DAST_FINDINGS } from '@/lib/mock-data/dast'
import { isDastEngineRunning, proxyToEngine } from '@/lib/dast/engine-proxy'

/**
 * Build ReportData from mock data when the database is not available.
 */
function buildMockReportData(scanId: string): ReportData {
  const scan = MOCK_DAST_SCANS.find(s => s.id === scanId)
  if (!scan) throw new Error(`Scan ${scanId} not found`)
  if (scan.status !== 'COMPLETED') throw new Error('Report can only be generated for completed scans')

  const findings = MOCK_DAST_FINDINGS.filter(f => f.scanId === scanId)

  const total =
    (scan.criticalCount ?? 0) +
    (scan.highCount ?? 0) +
    (scan.mediumCount ?? 0) +
    (scan.lowCount ?? 0) +
    (scan.infoCount ?? 0)

  return {
    scan: {
      id: scan.id,
      name: scan.name,
      targetUrl: scan.targetUrl,
      scanProfile: scan.scanProfile,
      startedAt: scan.startedAt ?? null,
      completedAt: scan.completedAt ?? null,
      endpointsDiscovered: scan.endpointsDiscovered ?? 0,
      endpointsTested: scan.endpointsTested ?? 0,
      payloadsSent: scan.payloadsSent ?? 0,
      riskScore: scan.riskScore ?? 0,
      techStackDetected: scan.techStackDetected ?? [],
    },
    counts: {
      critical: scan.criticalCount ?? 0,
      high: scan.highCount ?? 0,
      medium: scan.mediumCount ?? 0,
      low: scan.lowCount ?? 0,
      info: scan.infoCount ?? 0,
      total,
    },
    executiveSummary: scan.executiveSummary ?? null,
    findings: findings.map(f => ({
      title: f.title,
      severity: f.severity,
      cvssScore: f.cvssScore,
      cvssVector: f.cvssVector,
      owaspCategory: f.owaspCategory,
      cweId: f.cweId,
      affectedUrl: f.affectedUrl,
      affectedParameter: f.affectedParameter,
      description: f.description,
      businessImpact: f.businessImpact,
      remediation: f.remediation,
      remediationCode: f.remediationCode,
      pciDssRefs: f.pciDssRefs,
      soc2Refs: f.soc2Refs,
      mitreAttackIds: f.mitreAttackIds,
      confidenceScore: f.confidenceScore,
    })),
    generatedAt: new Date().toISOString(),
    orgId: scan.orgId,
  }
}

/**
 * Generate a report from mock data using the same report rendering functions.
 */
function generateMockReport(scanId: string, format: ReportFormat): GeneratedReport {
  const data = buildMockReportData(scanId)
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')

  switch (format) {
    case 'json': {
      const content = generateJsonReport(data)
      return {
        scanId,
        format,
        fileName: `hemisx-dast-${scanId.substring(0, 8)}-${timestamp}.json`,
        contentType: 'application/json',
        content,
      }
    }
    case 'csv': {
      const content = generateCsvReport(data)
      return {
        scanId,
        format,
        fileName: `hemisx-dast-${scanId.substring(0, 8)}-${timestamp}.csv`,
        contentType: 'text/csv',
        content,
      }
    }
    case 'pdf': {
      const html = renderReport(data)
      return {
        scanId,
        format,
        fileName: `hemisx-dast-${scanId.substring(0, 8)}-${timestamp}.html`,
        contentType: 'text/html',
        content: html,
      }
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

    // Fallback to existing report generation
    const dbOk = await isDatabaseReachable()
    const report = dbOk
      ? await generateReport(scanId, format)
      : generateMockReport(scanId, format)

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
