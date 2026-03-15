import { prisma } from '@/lib/db'
import type { ReportData } from './html-template'
import { renderReport } from './html-template'
import { generateJsonReport } from './json-exporter'
import { generateCsvReport } from './csv-exporter'

// ─── Types ──────────────────────────────────────────────────────────────────

export type ReportFormat = 'pdf' | 'json' | 'csv'

export interface GeneratedReport {
  scanId: string
  format: ReportFormat
  fileName: string
  contentType: string
  content: string | Buffer
}

// ─── Build Report Data ──────────────────────────────────────────────────────

export async function buildReportData(scanId: string): Promise<ReportData> {
  const scan = await prisma.dastScan.findUnique({
    where: { id: scanId },
    include: {
      dastFindings: {
        orderBy: [{ severity: 'asc' }, { cvssScore: 'desc' }],
      },
    },
  })

  if (!scan) throw new Error(`Scan ${scanId} not found`)
  if (scan.status !== 'COMPLETED') throw new Error('Report can only be generated for completed scans')

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
      startedAt: scan.startedAt?.toISOString() ?? null,
      completedAt: scan.completedAt?.toISOString() ?? null,
      endpointsDiscovered: scan.endpointsDiscovered ?? 0,
      endpointsTested: scan.endpointsTested ?? 0,
      payloadsSent: scan.payloadsSent ?? 0,
      riskScore: scan.riskScore ?? 0,
      techStackDetected: (scan.techStackDetected as string[]) ?? [],
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
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    findings: scan.dastFindings.map((f: any) => ({
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

// ─── Generate Report ────────────────────────────────────────────────────────

export async function generateReport(scanId: string, format: ReportFormat): Promise<GeneratedReport> {
  const data = await buildReportData(scanId)
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
      // For PDF, return the HTML to be rendered by the client or a PDF library
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
