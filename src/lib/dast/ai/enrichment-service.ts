import { prisma } from '@/lib/db'
import { analyzeFinding } from './prompts/finding-analysis'
import { generateExecutiveSummary } from './prompts/executive-summary'
import { generateRemediationCode, type RemediationCode } from './prompts/remediation-code'
import { correlateFindings, type CorrelationResult } from './prompts/vulnerability-correlation'
import { generateComplianceReport, type ComplianceReport } from './prompts/compliance-mapper'

interface EnrichmentResult {
  findingsEnriched: number
  findingsSkipped: number
  remediationsGenerated: number
  executiveSummary: string | null
  correlationResult: CorrelationResult | null
  complianceReport: ComplianceReport | null
}

interface EnrichmentCallbacks {
  onProgress?: (percent: number, message: string) => void
}

const MAX_FINDINGS_TO_ENRICH = 50
const REMEDIATION_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM']
const INTER_CALL_DELAY_MS = 300

export async function enrichScanFindings(scanId: string, callbacks: EnrichmentCallbacks = {}): Promise<EnrichmentResult> {
  const result: EnrichmentResult = {
    findingsEnriched: 0, findingsSkipped: 0, remediationsGenerated: 0,
    executiveSummary: null, correlationResult: null, complianceReport: null,
  }

  if (!process.env.ANTHROPIC_API_KEY) return result

  const scan = await prisma.dastScan.findUnique({
    where: { id: scanId },
    include: { dastFindings: { orderBy: [{ severity: 'asc' }, { cvssScore: 'desc' }], take: MAX_FINDINGS_TO_ENRICH } },
  })
  if (!scan || scan.dastFindings.length === 0) return result

  const findings = scan.dastFindings
  const techStack = (scan.techStackDetected as string[]) ?? []
  const authConfig = scan.authConfig as { type?: string } | null
  const authType = authConfig?.type
  const allFindingTypes = findings.map((f: typeof findings[number]) => f.type)

  // ─── Stage 1: Enrich individual findings (0-55%) ───
  callbacks.onProgress?.(0, 'Starting AI analysis of individual findings...')

  // Process findings in batches of 3 for better throughput
  const batchSize = 3
  for (let batchStart = 0; batchStart < findings.length; batchStart += batchSize) {
    const batch = findings.slice(batchStart, batchStart + batchSize)
    const batchPromises = batch.map(async (finding: typeof findings[number]) => {
      try {
        const analysis = await analyzeFinding({
          type: finding.type, owaspCategory: finding.owaspCategory, severity: finding.severity,
          cvssScore: finding.cvssScore ?? undefined, title: finding.title, description: finding.description,
          affectedUrl: finding.affectedUrl, affectedParameter: finding.affectedParameter ?? undefined,
          payload: finding.payload ?? undefined, requestEvidence: finding.requestEvidence ?? undefined,
          responseEvidence: finding.responseEvidence ?? undefined, techStack,
          scanProfile: scan.scanProfile ?? undefined,
          authType: authType ?? undefined,
          otherFindingTypes: allFindingTypes,
        })

        if (analysis) {
          const updateData: Record<string, unknown> = { businessImpact: analysis.businessImpact }

          // Store enhanced analysis data as JSON in the finding
          const enrichedMeta: Record<string, unknown> = {}
          if (analysis.attackScenario) enrichedMeta.attackScenario = analysis.attackScenario
          if (analysis.falsePositiveLikelihood) enrichedMeta.falsePositiveLikelihood = analysis.falsePositiveLikelihood
          if (analysis.falsePositiveReason) enrichedMeta.falsePositiveReason = analysis.falsePositiveReason
          if (analysis.priorityScore) enrichedMeta.priorityScore = analysis.priorityScore
          if (analysis.priorityReason) enrichedMeta.priorityReason = analysis.priorityReason
          if (analysis.relatedCwes) enrichedMeta.relatedCwes = analysis.relatedCwes
          if (analysis.mitigationUrgency) enrichedMeta.mitigationUrgency = analysis.mitigationUrgency
          if (analysis.technicalDetail) enrichedMeta.technicalDetail = analysis.technicalDetail
          if (analysis.exploitDifficulty) enrichedMeta.exploitDifficulty = analysis.exploitDifficulty
          if (analysis.dataAtRisk) enrichedMeta.dataAtRisk = analysis.dataAtRisk
          if (analysis.complianceImplications) enrichedMeta.complianceImplications = analysis.complianceImplications

          if (Object.keys(enrichedMeta).length > 0) {
            updateData.aiEnrichmentData = JSON.stringify(enrichedMeta)
          }

          // Generate remediation for critical, high, AND medium findings
          if (REMEDIATION_SEVERITIES.includes(finding.severity)) {
            const remediation: RemediationCode | null = await generateRemediationCode({
              type: finding.type, title: finding.title, description: finding.description,
              affectedUrl: finding.affectedUrl, affectedParameter: finding.affectedParameter ?? undefined,
              techStack, payload: finding.payload ?? undefined, severity: finding.severity,
            })
            if (remediation) { updateData.remediationCode = JSON.stringify(remediation); result.remediationsGenerated++ }
          }

          await prisma.dastFinding.update({ where: { id: finding.id }, data: updateData })
          result.findingsEnriched++
          return true
        } else { result.findingsSkipped++; return false }
      } catch { result.findingsSkipped++; return false }
    })

    await Promise.all(batchPromises)

    const overallIndex = Math.min(batchStart + batchSize, findings.length)
    const progressPercent = Math.round((overallIndex / findings.length) * 55)
    callbacks.onProgress?.(progressPercent, `Analyzed ${overallIndex}/${findings.length} findings (${result.remediationsGenerated} remediations generated)`)

    if (batchStart + batchSize < findings.length) await delay(INTER_CALL_DELAY_MS)
  }

  // ─── Stage 2: Vulnerability Correlation (55-70%) ───
  callbacks.onProgress?.(55, 'Correlating findings for attack chain analysis...')
  try {
    const findingSummaries = findings.map((f: typeof findings[number], i: number) => ({
      index: i,
      type: f.type,
      severity: f.severity,
      title: f.title,
      affectedUrl: f.affectedUrl,
      affectedParameter: f.affectedParameter ?? undefined,
      owaspCategory: f.owaspCategory,
      cvssScore: f.cvssScore ?? undefined,
    }))

    const correlation = await correlateFindings(findingSummaries, techStack, scan.targetUrl)
    if (correlation) {
      result.correlationResult = correlation
      await prisma.dastScan.update({
        where: { id: scanId },
        data: { aiCorrelationData: JSON.stringify(correlation) },
      })
      callbacks.onProgress?.(70, `Found ${correlation.attackChains.length} attack chains, ${correlation.duplicateGroups.length} duplicate groups`)
    } else {
      callbacks.onProgress?.(70, 'No significant attack chains identified')
    }
  } catch (err) {
    console.warn('Vulnerability correlation failed:', err)
    callbacks.onProgress?.(70, 'Correlation analysis skipped')
  }

  // ─── Stage 3: Compliance Report (70-80%) ───
  callbacks.onProgress?.(70, 'Generating compliance impact report...')
  try {
    const complianceSummaries = findings.map((f: typeof findings[number], i: number) => ({
      index: i,
      type: f.type,
      severity: f.severity,
      owaspCategory: f.owaspCategory,
      pciDssRefs: (f.pciDssRefs as string[]) ?? [],
      soc2Refs: (f.soc2Refs as string[]) ?? [],
      cweId: f.cweId ?? undefined,
    }))

    const complianceReport = await generateComplianceReport(complianceSummaries, scan.targetUrl)
    if (complianceReport) {
      result.complianceReport = complianceReport
      await prisma.dastScan.update({
        where: { id: scanId },
        data: { aiComplianceData: JSON.stringify(complianceReport) },
      })
      callbacks.onProgress?.(80, `Compliance score: ${complianceReport.complianceScore}/100 — Audit readiness: ${complianceReport.auditReadiness}`)
    } else {
      callbacks.onProgress?.(80, 'Compliance report generation skipped')
    }
  } catch (err) {
    console.warn('Compliance report generation failed:', err)
    callbacks.onProgress?.(80, 'Compliance analysis skipped')
  }

  // ─── Stage 4: Executive Summary (80-95%) ───
  callbacks.onProgress?.(80, 'Generating executive summary...')
  try {
    // Count findings by OWASP category
    const owaspCategoryCounts: Record<string, number> = {}
    for (const f of findings) {
      owaspCategoryCounts[f.owaspCategory] = (owaspCategoryCounts[f.owaspCategory] || 0) + 1
    }

    // Try to get previous scan for trend comparison
    let previousScanFindingsCount: number | undefined
    try {
      const prevScan = await prisma.dastScan.findFirst({
        where: { targetUrl: scan.targetUrl, status: 'COMPLETED', id: { not: scanId } },
        orderBy: { completedAt: 'desc' },
        select: { criticalCount: true, highCount: true, mediumCount: true, lowCount: true, infoCount: true },
      })
      if (prevScan) {
        previousScanFindingsCount = (prevScan.criticalCount ?? 0) + (prevScan.highCount ?? 0) +
          (prevScan.mediumCount ?? 0) + (prevScan.lowCount ?? 0) + (prevScan.infoCount ?? 0)
      }
    } catch { /* previous scan lookup is best-effort */ }

    const criticalFindings = findings.filter((f: typeof findings[number]) => f.severity === 'CRITICAL').slice(0, 5).map((f: typeof findings[number]) => ({ title: f.title, url: f.affectedUrl }))
    const highFindings = findings.filter((f: typeof findings[number]) => f.severity === 'HIGH').slice(0, 5).map((f: typeof findings[number]) => ({ title: f.title, url: f.affectedUrl }))

    const summary = await generateExecutiveSummary({
      scanName: scan.name, targetUrl: scan.targetUrl, scanProfileName: scan.scanProfile ?? 'full',
      scanDurationMs: scan.completedAt && scan.startedAt ? new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime() : 0,
      endpointsDiscovered: scan.endpointsDiscovered ?? 0, endpointsTested: scan.endpointsTested ?? 0,
      payloadsSent: scan.payloadsSent ?? 0, techStackDetected: techStack,
      criticalCount: scan.criticalCount ?? 0, highCount: scan.highCount ?? 0,
      mediumCount: scan.mediumCount ?? 0, lowCount: scan.lowCount ?? 0, infoCount: scan.infoCount ?? 0,
      topCriticalFindings: criticalFindings, topHighFindings: highFindings,
      owaspCategoryCounts,
      authType: authType ?? undefined,
      riskScore: scan.riskScore ?? undefined,
      previousScanFindingsCount,
    })

    if (summary) {
      result.executiveSummary = summary
      await prisma.dastScan.update({ where: { id: scanId }, data: { executiveSummary: summary } })
    }
  } catch { /* summary generation is best-effort */ }

  callbacks.onProgress?.(100, `AI enrichment complete: ${result.findingsEnriched} analyzed, ${result.remediationsGenerated} remediations, ${result.correlationResult?.attackChains.length ?? 0} attack chains`)
  return result
}

function delay(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)) }
