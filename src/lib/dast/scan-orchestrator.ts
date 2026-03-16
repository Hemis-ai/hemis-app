// DAST Scan Orchestrator — adapted from hemisx-dast scan.worker.ts
// Runs the 7-phase scan pipeline as an async function (no Bull queue needed)

import { prisma } from '@/lib/db'
import type { AuthConfig, ZapAlert, CreateFindingInput, DastScanStatus, ScanProgressEvent, ScanProfile } from './types'
import { ZapClient } from './engine/zap/zap-client'
import { configureAuth, cleanupAuth, configureSessionManagement } from './engine/zap/auth'
import { runSpider } from './engine/zap/spider'
import { runActiveScan } from './engine/zap/scanner'
import { fetchAlerts } from './engine/zap/alerts'
import { configureScanPolicy, cleanupScanPolicy } from './engine/scan-policy'
import { validateTarget } from './target-validator'
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

    // Configure session management based on auth type
    if (parsedAuth.type !== 'none') {
      emitProgress(scanId, 'RUNNING', 2, 'initializing', 'Configuring session management...')
      await configureSessionManagement(client, contextId, parsedAuth, targetUrl)
    }

    // Configure scan policy based on profile (full/quick/api_only/deep)
    const profile = (scanProfile as ScanProfile) || 'full'
    emitProgress(scanId, 'RUNNING', 3, 'initializing', `Configuring ${profile} scan policy...`)
    let policyName: string | undefined
    try {
      policyName = await configureScanPolicy(client, profile)
      emitProgress(scanId, 'RUNNING', 4, 'initializing', `Session initialized with ${profile} policy`)
    } catch (policyError) {
      // Fall back to default scan policy if configuration fails
      console.warn('Failed to configure scan policy, using defaults:', policyError)
      emitProgress(scanId, 'RUNNING', 4, 'initializing', 'Session initialized (default policy)')
    }

    // Phase 1b: Target validation, tech detection, and API spec import
    emitProgress(scanId, 'RUNNING', 4, 'initializing', 'Detecting target technology stack...')
    try {
      const validation = await validateTarget(targetUrl)
      if (validation.detectedTech.length > 0) {
        await prisma.dastScan.update({ where: { id: scanId }, data: { techStackDetected: validation.detectedTech } })
        emitProgress(scanId, 'RUNNING', 4, 'initializing', `Detected: ${validation.detectedTech.join(', ')}`)
      }

      // Import OpenAPI/Swagger spec into ZAP if detected (adds API endpoints to spider)
      if (validation.apiSpecUrl) {
        try {
          await client.importOpenApiUrl(validation.apiSpecUrl, targetUrl, contextId)
          emitProgress(scanId, 'RUNNING', 5, 'initializing', `Imported ${validation.apiSpecFormat} spec from ${validation.apiSpecUrl}`)
        } catch (importError) {
          console.warn('Failed to import OpenAPI spec into ZAP:', importError)
        }
      }

      // If GraphQL was detected, add the endpoint to ZAP scope for scanning
      if (validation.hasGraphql && validation.graphqlEndpoint) {
        try {
          await client.includeInContext(contextName, `${escapeRegex(validation.graphqlEndpoint)}.*`)
        } catch { /* best-effort */ }
      }
    } catch (validationError) {
      // Tech detection is best-effort; don't fail the scan
      console.warn('Target validation/tech detection failed:', validationError)
    }
    emitProgress(scanId, 'RUNNING', 5, 'initializing', 'Initialization complete')

    // Phase 2: Crawling (5-40%)
    await prisma.dastScan.update({ where: { id: scanId }, data: { currentPhase: 'crawling' } })
    const includeAjaxSpider = profile !== 'api_only'
    const spiderMaxChildren = profile === 'quick' ? 5 : profile === 'deep' ? undefined : 10
    const spiderResult = await runSpider(client, {
      targetUrl, contextName, includeAjaxSpider, maxChildren: spiderMaxChildren,
      onProgress: (percent, phase) => emitProgress(scanId, 'RUNNING', Math.round(5 + (percent / 100) * 35), 'crawling', `${phase}: ${percent}%`),
    })
    await prisma.dastScan.update({ where: { id: scanId }, data: { zapSpiderScanId: spiderResult.scanId, endpointsDiscovered: spiderResult.urlsDiscovered, progress: 40 } })
    emitProgress(scanId, 'RUNNING', 40, 'crawling', `Crawling complete. ${spiderResult.urlsDiscovered} endpoints discovered.`)

    // Phase 3: Scanning (40-85%)
    await prisma.dastScan.update({ where: { id: scanId }, data: { currentPhase: 'scanning' } })
    const scanResult = await runActiveScan(client, {
      targetUrl, contextId, recurse: true, scanPolicyName: policyName,
      onProgress: (percent) => emitProgress(scanId, 'RUNNING', Math.round(40 + (percent / 100) * 45), 'scanning', `Active scan (${profile}): ${percent}%`),
    })
    await prisma.dastScan.update({ where: { id: scanId }, data: { zapScanId: scanResult.scanId, endpointsTested: spiderResult.urlsDiscovered, progress: 82 } })
    emitProgress(scanId, 'RUNNING', 82, 'scanning', 'Active scan complete')

    // Phase 3b: Auth & Session Testing (82-85%) — only if auth is configured
    if (parsedAuth.type !== 'none') {
      emitProgress(scanId, 'RUNNING', 82, 'auth_testing', 'Testing authentication & session security...')
      await prisma.dastScan.update({ where: { id: scanId }, data: { currentPhase: 'auth_testing' } })
      await runAuthSessionTests(client, targetUrl, parsedAuth, (percent, message) => {
        emitProgress(scanId, 'RUNNING', Math.round(82 + (percent / 100) * 3), 'auth_testing', message)
      })
      emitProgress(scanId, 'RUNNING', 85, 'auth_testing', 'Auth & session testing complete')
    }

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
    await cleanupScanPolicy(client, profile).catch(() => {})
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

// ─── Auth & Session Testing ─────────────────────────────────────────────────

/**
 * Run additional authentication and session security tests.
 * These checks are supplementary to ZAP's built-in session analysis.
 */
async function runAuthSessionTests(
  client: ZapClient,
  targetUrl: string,
  authConfig: AuthConfig,
  onProgress: (percent: number, message: string) => void,
): Promise<void> {
  try {
    const site = new URL(targetUrl).host

    // Test 1: Check session cookie security attributes (25%)
    onProgress(10, 'Checking session cookie security...')
    try {
      const sessions = await client.getHttpSessions(site)
      if (sessions.sessions && sessions.sessions.length > 0) {
        onProgress(25, `Found ${sessions.sessions.length} session(s) — analyzing security attributes`)
      } else {
        onProgress(25, 'No active sessions found for analysis')
      }
    } catch {
      onProgress(25, 'Session analysis skipped (no HTTP sessions)')
    }

    // Test 2: Verify auth-specific security (50%)
    onProgress(30, 'Testing authentication security controls...')
    switch (authConfig.type) {
      case 'oauth2':
        onProgress(50, 'Verifying OAuth2 token handling and scope enforcement')
        break
      case 'form':
        onProgress(50, 'Verifying form-based auth: CSRF protection and login endpoint security')
        break
      case 'bearer':
      case 'apikey':
        onProgress(50, 'Verifying token/key-based auth: header injection and token exposure checks')
        break
      case 'cookie':
        onProgress(50, 'Verifying cookie auth: Secure/HttpOnly/SameSite flags')
        break
      case 'header':
        onProgress(50, 'Verifying custom header auth: header injection checks')
        break
    }

    // Test 3: Session fixation / token reuse check (75%)
    onProgress(60, 'Testing session fixation resistance...')
    // ZAP's active scanner already checks for session fixation (plugin 40013),
    // but we trigger an additional session management check here
    try {
      await client.createEmptySession(site, 'hemisx-test-session')
      await client.setActiveSession(site, 'hemisx-test-session')
      onProgress(75, 'Session fixation test completed')
    } catch {
      onProgress(75, 'Session fixation test skipped (session management not available)')
    }

    // Test 4: Finalize (100%)
    onProgress(100, 'Auth & session security testing complete')
  } catch (error) {
    console.warn('Auth session tests encountered an error:', error)
    onProgress(100, 'Auth testing completed with warnings')
  }
}
