import { prisma } from '@/lib/db'
import { analyzeFinding } from './prompts/finding-analysis'
import { generateExecutiveSummary } from './prompts/executive-summary'
import { generateRemediationCode, type RemediationCode } from './prompts/remediation-code'

interface EnrichmentResult {
  findingsEnriched: number
  findingsSkipped: number
  remediationsGenerated: number
  executiveSummary: string | null
}

interface EnrichmentCallbacks {
  onProgress?: (percent: number, message: string) => void
}

const MAX_FINDINGS_TO_ENRICH = 30
const REMEDIATION_SEVERITIES = ['CRITICAL', 'HIGH']
const INTER_CALL_DELAY_MS = 500

export async function enrichScanFindings(scanId: string, callbacks: EnrichmentCallbacks = {}): Promise<EnrichmentResult> {
  const result: EnrichmentResult = { findingsEnriched: 0, findingsSkipped: 0, remediationsGenerated: 0, executiveSummary: null }

  if (!process.env.ANTHROPIC_API_KEY) return result

  const scan = await prisma.dastScan.findUnique({
    where: { id: scanId },
    include: { dastFindings: { orderBy: [{ severity: 'asc' }, { cvssScore: 'desc' }], take: MAX_FINDINGS_TO_ENRICH } },
  })
  if (!scan || scan.dastFindings.length === 0) return result

  const findings = scan.dastFindings
  const techStack = (scan.techStackDetected as string[]) ?? []

  // Stage 1: Enrich individual findings
  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i]
    callbacks.onProgress?.(Math.round(((i + 1) / findings.length) * 80), `Analyzing finding ${i + 1}/${findings.length}: ${finding.title}`)

    try {
      const analysis = await analyzeFinding({
        type: finding.type, owaspCategory: finding.owaspCategory, severity: finding.severity,
        cvssScore: finding.cvssScore ?? undefined, title: finding.title, description: finding.description,
        affectedUrl: finding.affectedUrl, affectedParameter: finding.affectedParameter ?? undefined,
        payload: finding.payload ?? undefined, requestEvidence: finding.requestEvidence ?? undefined,
        responseEvidence: finding.responseEvidence ?? undefined, techStack,
      })

      if (analysis) {
        const updateData: Record<string, unknown> = { businessImpact: analysis.businessImpact }

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
      } else { result.findingsSkipped++ }
    } catch { result.findingsSkipped++ }

    if (i < findings.length - 1) await delay(INTER_CALL_DELAY_MS)
  }

  // Stage 2: Executive summary
  callbacks.onProgress?.(85, 'Generating executive summary...')
  try {
    const criticalFindings = findings.filter((f: typeof findings[number]) => f.severity === 'CRITICAL').slice(0, 5).map((f: typeof findings[number]) => ({ title: f.title, url: f.affectedUrl }))
    const highFindings = findings.filter((f: typeof findings[number]) => f.severity === 'HIGH').slice(0, 5).map((f: typeof findings[number]) => ({ title: f.title, url: f.affectedUrl }))

    const summary = await generateExecutiveSummary({
      scanName: scan.name, targetUrl: scan.targetUrl, scanProfileName: scan.scanProfile,
      scanDurationMs: scan.completedAt && scan.startedAt ? new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime() : 0,
      endpointsDiscovered: scan.endpointsDiscovered ?? 0, endpointsTested: scan.endpointsTested ?? 0,
      payloadsSent: scan.payloadsSent ?? 0, techStackDetected: techStack,
      criticalCount: scan.criticalCount ?? 0, highCount: scan.highCount ?? 0,
      mediumCount: scan.mediumCount ?? 0, lowCount: scan.lowCount ?? 0, infoCount: scan.infoCount ?? 0,
      topCriticalFindings: criticalFindings, topHighFindings: highFindings,
    })

    if (summary) {
      result.executiveSummary = summary
      await prisma.dastScan.update({ where: { id: scanId }, data: { executiveSummary: summary } })
    }
  } catch { /* summary generation is best-effort */ }

  callbacks.onProgress?.(100, 'AI enrichment complete')
  return result
}

function delay(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)) }
