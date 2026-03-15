// DAST Scan Orchestrator — adapted from hemisx-dast scan.worker.ts
// Runs the 7-phase scan pipeline as an async function (no Bull queue needed)

import { prisma } from '@/lib/db'
import type { AuthConfig, ZapAlert, CreateFindingInput, DastScanStatus, ScanProgressEvent } from './types'
import { ZapClient } from './engine/zap/zap-client'
import { configureAuth, cleanupAuth } from './engine/zap/auth'
import { runSpider } from './engine/zap/spider'
import { runActiveScan } from './engine/zap/scanner'
import { fetchAlerts } from './engine/zap/alerts'
import { calculateCvss, PRESET_VECTORS, cvssToSeverity } from './engine/scoring/cvss-calculator'
import { getOwaspMappingOrDefault } from './engine/scoring/owasp-mapper'
import { enrichScanFindings } from './ai/enrichment-service'

// In-memory progress store for SSE polling
const progressStore = new Map<string, ScanProgressEvent>()

export function getProgress(scanId: string): ScanProgressEvent | undefined {
  return progressStore.get(scanId)
}

export function clearProgress(scanId: string): void {
  progressStore.delete(scanId)
}

function emitProgress(scanId: string, status: DastScanStatus, progress: number, currentPhase: string, message: string) {
  const event: ScanProgressEvent = {
    scanId, status, progress, currentPhase,
    endpointsDiscovered: 0, endpointsTested: 0, payloadsSent: 0, findingsCount: 0,
    timestamp: new Date().toISOString(), message,
  }
  progressStore.set(scanId, event)
}

/**
 * Run a full DAST scan. Called from the API route after creating the scan record.
 * This runs in the background (fire-and-forget from the route handler).
 */
export async function runDastScan(scanId: string): Promise<void> {
  const scan = await prisma.dastScan.findUnique({ where: { id: scanId } })
  if (!scan) return

  const { targetUrl, scope, excludedPaths, authConfig, scanProfile } = scan
  const client = new ZapClient()

  try {
    // Phase 1: Initializing (0-5%)
    emitProgress(scanId, 'RUNNING', 0, 'initializing', 'Initializing scan session...')
    await prisma.dastScan.update({ where: { id: scanId }, data: { status: 'RUNNING', startedAt: new Date(), currentPhase: 'initializing' } })

    await client.newSession(`hemisx-${scanId}`)
    const contextName = `ctx-${scanId}`
    const contextId = await client.createContext(contextName)

    await client.includeInContext(contextName, `${escapeRegex(targetUrl)}.*`)
    for (const s of scope) await client.includeInContext(contextName, `${escapeRegex(s)}.*`)
    for (const path of excludedPaths) await client.excludeFromContext(contextName, `.*${escapeRegex(path)}.*`)

    const parsedAuth = (authConfig as AuthConfig) ?? { type: 'none' as const }
    await configureAuth(client, contextId, parsedAuth)
    emitProgress(scanId, 'RUNNING', 5, 'initializing', 'Session initialized')

    // Phase 2: Crawling (5-40%)
    await prisma.dastScan.update({ where: { id: scanId }, data: { currentPhase: 'crawling' } })
    const spiderResult = await runSpider(client, {
      targetUrl, contextName, includeAjaxSpider: scanProfile !== 'api_only',
      onProgress: (percent, phase) => emitProgress(scanId, 'RUNNING', Math.round(5 + (percent / 100) * 35), 'crawling', `${phase}: ${percent}%`),
    })
    await prisma.dastScan.update({ where: { id: scanId }, data: { zapSpiderScanId: spiderResult.scanId, endpointsDiscovered: spiderResult.urlsDiscovered, progress: 40 } })
    emitProgress(scanId, 'RUNNING', 40, 'crawling', `Crawling complete. ${spiderResult.urlsDiscovered} endpoints discovered.`)

    // Phase 3: Scanning (40-85%)
    await prisma.dastScan.update({ where: { id: scanId }, data: { currentPhase: 'scanning' } })
    const scanResult = await runActiveScan(client, {
      targetUrl, contextId, recurse: true,
      onProgress: (percent) => emitProgress(scanId, 'RUNNING', Math.round(40 + (percent / 100) * 45), 'scanning', `Active scan: ${percent}%`),
    })
    await prisma.dastScan.update({ where: { id: scanId }, data: { zapScanId: scanResult.scanId, endpointsTested: spiderResult.urlsDiscovered, progress: 85 } })
    emitProgress(scanId, 'RUNNING', 85, 'scanning', 'Active scan complete')

    // Phase 4: Extracting (85-90%)
    await prisma.dastScan.update({ where: { id: scanId }, data: { currentPhase: 'extracting' } })
    emitProgress(scanId, 'RUNNING', 85, 'extracting', 'Extracting alerts...')
    const alerts = await fetchAlerts(client, targetUrl)
    const findingInputs = alerts.map((alert) => alertToFinding(scanId, alert))

    // Persist findings
    if (findingInputs.length > 0) {
      await prisma.$transaction(findingInputs.map((f) => prisma.dastFinding.create({ data: {
        scanId: f.scanId, zapAlertId: f.zapAlertId ?? null, pluginId: f.pluginId ?? null,
        type: f.type, owaspCategory: f.owaspCategory, cweId: f.cweId ?? null,
        severity: f.severity, cvssScore: f.cvssScore ?? null, cvssVector: f.cvssVector ?? null,
        riskScore: f.riskScore, title: f.title, description: f.description, businessImpact: f.businessImpact ?? null,
        affectedUrl: f.affectedUrl, affectedParameter: f.affectedParameter ?? null,
        injectionPoint: f.injectionPoint ?? null, payload: f.payload ?? null,
        requestEvidence: f.requestEvidence ?? null, responseEvidence: f.responseEvidence ?? null,
        remediation: f.remediation, remediationCode: f.remediationCode ?? null,
        pciDssRefs: f.pciDssRefs ?? [], soc2Refs: f.soc2Refs ?? [], mitreAttackIds: f.mitreAttackIds ?? [],
        confidenceScore: f.confidenceScore, status: 'OPEN',
      } })))
    }

    // Get severity counts
    const counts = await prisma.dastFinding.groupBy({ by: ['severity'], where: { scanId }, _count: true })
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const row of counts) severityCounts[row.severity.toLowerCase() as keyof typeof severityCounts] = row._count
    const totalFindings = severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low + severityCounts.info

    await prisma.dastScan.update({ where: { id: scanId }, data: {
      criticalCount: severityCounts.critical, highCount: severityCounts.high, mediumCount: severityCounts.medium,
      lowCount: severityCounts.low, infoCount: severityCounts.info, progress: 90,
    } })
    emitProgress(scanId, 'RUNNING', 90, 'extracting', `Extracted ${totalFindings} findings (${severityCounts.critical} critical, ${severityCounts.high} high)`)

    // Phase 5-6: AI Enrichment (90-99%)
    await prisma.dastScan.update({ where: { id: scanId }, data: { currentPhase: 'analyzing' } })
    emitProgress(scanId, 'RUNNING', 90, 'analyzing', 'Starting AI enrichment...')
    await enrichScanFindings(scanId, {
      onProgress: (percent, message) => {
        const overallProgress = Math.round(90 + (percent / 100) * 9)
        const phase = percent <= 80 ? 'analyzing' : 'summarizing'
        emitProgress(scanId, 'RUNNING', overallProgress, phase, message)
      },
    })

    // Phase 7: Complete (100%)
    const riskScore = Math.min(100, severityCounts.critical * 25 + severityCounts.high * 10 + severityCounts.medium * 3 + severityCounts.low * 1)
    await prisma.dastScan.update({ where: { id: scanId }, data: { status: 'COMPLETED', progress: 100, currentPhase: 'complete', completedAt: new Date(), riskScore } })
    emitProgress(scanId, 'COMPLETED', 100, 'complete', 'Scan completed')
    await cleanupAuth(client, parsedAuth)
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error'
    console.error('DAST scan failed', { scanId, error: errorMsg })
    await prisma.dastScan.update({ where: { id: scanId }, data: { status: 'FAILED', currentPhase: 'failed', completedAt: new Date() } })
    emitProgress(scanId, 'FAILED', -1, 'failed', `Scan failed: ${errorMsg}`)
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function escapeRegex(str: string): string { return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') }

function alertToFinding(scanId: string, alert: ZapAlert): CreateFindingInput {
  const mapping = getOwaspMappingOrDefault(alert.pluginId, alert.risk)
  const presetKey = mapping.type
  const cvssInput = PRESET_VECTORS[presetKey]
  let cvssScore: number | undefined
  let cvssVector: string | undefined
  let severity = riskToSeverity(alert.risk)

  if (cvssInput) {
    const result = calculateCvss(cvssInput)
    cvssScore = result.score; cvssVector = result.vector; severity = result.severity
  }

  return {
    scanId, zapAlertId: alert.id, pluginId: alert.pluginId,
    type: mapping.type, owaspCategory: mapping.owaspCategory,
    cweId: mapping.cweId || alert.cweId || undefined, severity, cvssScore, cvssVector,
    riskScore: cvssScore ? Math.round(cvssScore * 10) : riskToScore(alert.risk),
    title: alert.name, description: alert.description, affectedUrl: alert.url,
    affectedParameter: alert.param || undefined, injectionPoint: alert.method || undefined,
    payload: alert.attack || undefined, requestEvidence: alert.evidence || undefined,
    remediation: alert.solution || 'Review and remediate this finding.',
    pciDssRefs: mapping.pciDssRefs, soc2Refs: mapping.soc2Refs, mitreAttackIds: mapping.mitreAttackIds,
    confidenceScore: mapConfidence(alert.confidence),
  }
}

function riskToSeverity(risk: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  switch (risk) { case 'High': return 'HIGH'; case 'Medium': return 'MEDIUM'; case 'Low': return 'LOW'; default: return 'INFO' }
}

function riskToScore(risk: string): number {
  switch (risk) { case 'High': return 80; case 'Medium': return 50; case 'Low': return 20; default: return 5 }
}

function mapConfidence(confidence: string): number {
  switch (confidence) { case 'Confirmed': return 100; case 'High': return 85; case 'Medium': return 60; case 'Low': return 30; default: return 50 }
}
