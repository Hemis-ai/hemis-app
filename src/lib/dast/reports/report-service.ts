import { prisma } from '@/lib/db'
import type { ReportData, OwaspHeatmapEntry, CvssDistEntry, AttackSurfaceEntry } from './html-template'
import { renderReport } from './html-template'
import { generateJsonReport } from './json-exporter'
import { generateCsvReport } from './csv-exporter'
import { generatePdfReport } from './pdf-generator'

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

export async function buildReportData(scanId: string, orgId?: string): Promise<ReportData> {
  const scan = await prisma.dastScan.findUnique({
    where: { id: scanId },
    include: {
      dastFindings: {
        orderBy: [{ cvssScore: 'desc' }, { confidenceScore: 'desc' }],
      },
    },
  })

  if (!scan) throw new Error(`Scan ${scanId} not found`)
  if (orgId && scan.orgId !== orgId) throw new Error(`Scan ${scanId} not found`)
  if (scan.status !== 'COMPLETED') throw new Error('Report can only be generated for completed scans')

  const total =
    (scan.criticalCount ?? 0) +
    (scan.highCount ?? 0) +
    (scan.mediumCount ?? 0) +
    (scan.lowCount ?? 0) +
    (scan.infoCount ?? 0)

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const findings = scan.dastFindings.map((f: any) => ({
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
  }))

  // Compute OWASP heatmap data (mirrors OWASPHeatmap.tsx)
  const SEV_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }
  const owaspMap = new Map<string, { count: number; highestSev: string; score: number }>()
  for (const f of findings) {
    const cat = f.owaspCategory || 'Unknown'
    const entry = owaspMap.get(cat) ?? { count: 0, highestSev: 'INFO', score: 0 }
    entry.count++
    entry.score += SEV_WEIGHT[f.severity] ?? 1
    if ((SEV_WEIGHT[f.severity] ?? 0) > (SEV_WEIGHT[entry.highestSev] ?? 0)) entry.highestSev = f.severity
    owaspMap.set(cat, entry)
  }
  const owaspHeatmap: OwaspHeatmapEntry[] = Array.from(owaspMap.entries())
    .map(([cat, v]) => ({ categoryId: cat, categoryName: cat, findingCount: v.count, highestSeverity: v.highestSev, weightedScore: v.score }))
    .sort((a, b) => b.weightedScore - a.weightedScore)

  // Compute CVSS distribution
  const cvssBuckets = [
    { rangeLabel: '9.0 - 10.0', count: 0 },
    { rangeLabel: '7.0 - 8.9', count: 0 },
    { rangeLabel: '4.0 - 6.9', count: 0 },
    { rangeLabel: '0.1 - 3.9', count: 0 },
    { rangeLabel: 'N/A', count: 0 },
  ]
  for (const f of findings) {
    const s = f.cvssScore
    if (s == null) cvssBuckets[4].count++
    else if (s >= 9) cvssBuckets[0].count++
    else if (s >= 7) cvssBuckets[1].count++
    else if (s >= 4) cvssBuckets[2].count++
    else cvssBuckets[3].count++
  }
  const cvssDistribution: CvssDistEntry[] = cvssBuckets.filter(b => b.count > 0)

  // Compute attack surface map (group by affectedUrl)
  const surfMap = new Map<string, { count: number; highestSev: string }>()
  for (const f of findings) {
    const url = f.affectedUrl
    const entry = surfMap.get(url) ?? { count: 0, highestSev: 'INFO' }
    entry.count++
    if ((SEV_WEIGHT[f.severity] ?? 0) > (SEV_WEIGHT[entry.highestSev] ?? 0)) entry.highestSev = f.severity
    surfMap.set(url, entry)
  }
  const attackSurface: AttackSurfaceEntry[] = Array.from(surfMap.entries())
    .map(([url, v]) => {
      let path = url
      try { path = new URL(url).pathname } catch { /* keep full URL */ }
      return { url, path, findingCount: v.count, highestSeverity: v.highestSev }
    })
    .sort((a, b) => b.findingCount - a.findingCount)
    .slice(0, 20)

  // Parse AI data from scan record
  let attackChainData = null
  let complianceData = null
  try { if (scan.aiCorrelationData) attackChainData = JSON.parse(scan.aiCorrelationData as string) } catch { /* skip */ }
  try { if (scan.aiComplianceData) complianceData = JSON.parse(scan.aiComplianceData as string) } catch { /* skip */ }

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
    findings,
    owaspHeatmap,
    cvssDistribution,
    attackSurface,
    attackChainData,
    complianceData,
    generatedAt: new Date().toISOString(),
    orgId: scan.orgId,
  }
}

// ─── Generate Report ────────────────────────────────────────────────────────

export async function generateReport(scanId: string, format: ReportFormat, orgId?: string): Promise<GeneratedReport> {
  const data = await buildReportData(scanId, orgId)
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
      // Generate real PDF using PDFKit
      try {
        const pdfBuffer = await generatePdfReport(data)
        return {
          scanId,
          format,
          fileName: `hemisx-dast-${scanId.substring(0, 8)}-${timestamp}.pdf`,
          contentType: 'application/pdf',
          content: pdfBuffer,
        }
      } catch (pdfError) {
        // Fallback to HTML if PDF generation fails
        console.warn('PDF generation failed, falling back to HTML:', pdfError)
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
}
