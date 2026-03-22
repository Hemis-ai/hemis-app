// src/lib/bbrt/engagement-orchestrator.ts
// BBRT 7-Phase Pipeline Orchestrator
import type { BbrtEngagement, BbrtProgressEvent, BbrtTargetConfig } from '@/lib/types/bbrt'
import { runReconnaissance } from './recon-engine'
import { mapAttackSurface } from './attack-surface-mapper'
import { scanVulnerabilities } from './vulnerability-scanner'
import { constructKillChains } from './exploit-chain-engine'
import { calculateOverallRiskScore, classifyRiskLevel } from './impact-scorer'
import { generateReport } from './report-generator'
import {
  generateAttackPlan,
  generateKillChainNarrative,
  generateExecutiveSummary,
  generateAiInsights,
} from './ai-orchestrator'
import { randomUUID } from 'crypto'

// ─── In-Memory Stores (same pattern as WBRT) ────────────────────────────────

export const progressStore = new Map<string, BbrtProgressEvent>()
const engagementStore = new Map<string, BbrtEngagement>()

function updateProgress(
  engagementId: string,
  status: BbrtProgressEvent['status'],
  progress: number,
  phase: string,
  message: string,
  details?: Record<string, number | string>,
) {
  progressStore.set(engagementId, {
    engagementId,
    status,
    progress,
    currentPhase: phase,
    message,
    timestamp: new Date().toISOString(),
    details,
  })
}

// ─── CRUD Operations ────────────────────────────────────────────────────────

export function getEngagement(id: string): BbrtEngagement | null {
  return engagementStore.get(id) || null
}

export function listEngagements(): BbrtEngagement[] {
  return Array.from(engagementStore.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  )
}

export function deleteEngagement(id: string): boolean {
  const deleted = engagementStore.delete(id)
  progressStore.delete(id)
  return deleted
}

export function createEngagement(
  name: string,
  targetConfig: BbrtTargetConfig,
): BbrtEngagement {
  const engagement: BbrtEngagement = {
    id: randomUUID(),
    orgId: 'org-demo',
    name,
    targetConfig,
    status: 'CREATED',
    progress: 0,
    currentPhase: 'created',
    findings: [],
    killChains: [],
    createdAt: new Date().toISOString(),
  }

  engagementStore.set(engagement.id, engagement)
  return engagement
}

// ─── Seed Mock Engagement on Module Load ────────────────────────────────────

let mockSeeded = false

export function ensureMockSeeded() {
  if (mockSeeded) return
  mockSeeded = true

  // Dynamic import to avoid circular deps at module init
  try {
    // We'll seed mock data when the mock-data module is available
    const loadMock = async () => {
      try {
        const { MOCK_BBRT_ENGAGEMENT } = await import('@/lib/mock-data/bbrt')
        if (MOCK_BBRT_ENGAGEMENT && !engagementStore.has(MOCK_BBRT_ENGAGEMENT.id)) {
          engagementStore.set(MOCK_BBRT_ENGAGEMENT.id, MOCK_BBRT_ENGAGEMENT)
          console.log('[BBRT] Mock engagement seeded:', MOCK_BBRT_ENGAGEMENT.id)
        }
      } catch {
        console.log('[BBRT] Mock data not available yet')
      }
    }
    loadMock()
  } catch {
    // Mock data not available — that's fine
  }
}

// ─── 7-Phase Pipeline ───────────────────────────────────────────────────────

export async function runEngagement(engagementId: string): Promise<void> {
  const engagement = engagementStore.get(engagementId)
  if (!engagement) throw new Error(`Engagement ${engagementId} not found`)

  try {
    engagement.status = 'INITIALIZING'
    engagement.startedAt = new Date().toISOString()
    engagementStore.set(engagementId, engagement)

    // ── Phase 1: Initialization (0-5%) ──
    updateProgress(engagementId, 'INITIALIZING', 2, 'Initializing',
      `Validating target: ${engagement.targetConfig.targetDomain}`)
    await sleep(500)
    updateProgress(engagementId, 'INITIALIZING', 5, 'Initializing',
      `Scope configured: ${engagement.targetConfig.engagementType} engagement for ${engagement.targetConfig.targetDomain}`)
    await sleep(300)

    // ── Phase 2: Reconnaissance (5-25%) ──
    updateProgress(engagementId, 'RECONNAISSANCE', 8, 'Reconnaissance',
      'Starting external reconnaissance — subdomain enumeration...')
    await sleep(600)

    const reconResult = runReconnaissance(engagement.targetConfig)
    engagement.reconResult = reconResult

    updateProgress(engagementId, 'RECONNAISSANCE', 15, 'Reconnaissance',
      `Discovered ${reconResult.subdomains.length} subdomains, ${reconResult.openPorts.length} open ports`,
      { subdomains: reconResult.subdomains.length, ports: reconResult.openPorts.length })
    await sleep(400)

    updateProgress(engagementId, 'RECONNAISSANCE', 20, 'Reconnaissance',
      `Tech stack: ${reconResult.techStack.map(t => t.name).join(', ')}`)
    await sleep(300)

    updateProgress(engagementId, 'RECONNAISSANCE', 25, 'Reconnaissance',
      `OSINT: ${reconResult.osintFindings.length} findings, ${reconResult.cloudAssets.length} cloud assets, ${reconResult.emailAddresses.length} emails`)

    // Generate AI attack plan in background (non-blocking)
    const attackPlanPromise = generateAttackPlan(engagement.targetConfig, reconResult)

    // ── Phase 3: Attack Surface Mapping (25-40%) ──
    updateProgress(engagementId, 'SURFACE_MAPPING', 28, 'Surface Mapping',
      'Building attack surface graph from recon data...')
    await sleep(500)

    const attackSurface = mapAttackSurface(reconResult, engagement.targetConfig)
    engagement.attackSurface = attackSurface

    updateProgress(engagementId, 'SURFACE_MAPPING', 35, 'Surface Mapping',
      `Mapped ${attackSurface.totalAssets} assets: ${attackSurface.entryPoints.length} entry points, ${attackSurface.crownJewels.length} crown jewels`,
      { assets: attackSurface.totalAssets, entryPoints: attackSurface.entryPoints.length, shadowAssets: attackSurface.shadowAssets.length })
    await sleep(300)

    updateProgress(engagementId, 'SURFACE_MAPPING', 40, 'Surface Mapping',
      `Exposure score: ${attackSurface.exposureScore}/100 — ${attackSurface.shadowAssets.length} shadow assets detected`)

    // ── Phase 4: Vulnerability Discovery (40-60%) ──
    updateProgress(engagementId, 'VULN_DISCOVERY', 42, 'Vulnerability Discovery',
      'Scanning for zero-knowledge vulnerabilities...')
    await sleep(600)

    const findings = scanVulnerabilities(reconResult, attackSurface, engagement.targetConfig, engagementId)
    engagement.findings = findings

    const critCount = findings.filter(f => f.severity === 'CRITICAL').length
    const highCount = findings.filter(f => f.severity === 'HIGH').length
    updateProgress(engagementId, 'VULN_DISCOVERY', 55, 'Vulnerability Discovery',
      `Discovered ${findings.length} vulnerabilities: ${critCount} critical, ${highCount} high`,
      { total: findings.length, critical: critCount, high: highCount })
    await sleep(400)

    updateProgress(engagementId, 'VULN_DISCOVERY', 60, 'Vulnerability Discovery',
      `Vulnerability types: ${[...new Set(findings.map(f => f.type))].join(', ')}`)

    // Wait for attack plan
    const attackPlan = await attackPlanPromise
    if (attackPlan) {
      console.log(`[BBRT] AI attack plan generated: ${attackPlan.phases.length} phases, complexity: ${attackPlan.estimatedComplexity}`)
    }

    // ── Phase 5: Exploit Chaining (60-80%) ──
    updateProgress(engagementId, 'EXPLOIT_CHAINING', 62, 'Exploit Chaining',
      'Claude Opus 4.6 is analyzing vulnerability chains and constructing kill chains...')
    await sleep(500)

    const killChains = constructKillChains(attackSurface, findings, engagement.targetConfig, engagementId)

    // Generate AI narratives for each kill chain
    updateProgress(engagementId, 'EXPLOIT_CHAINING', 70, 'Exploit Chaining',
      `Constructed ${killChains.length} kill chains — generating AI narratives...`)

    for (let i = 0; i < killChains.length; i++) {
      const narrative = await generateKillChainNarrative(killChains[i], engagement.targetConfig)
      killChains[i].narrative = narrative
      updateProgress(engagementId, 'EXPLOIT_CHAINING', 70 + Math.round((i + 1) / killChains.length * 10), 'Exploit Chaining',
        `Generated narrative for chain ${i + 1}/${killChains.length}: ${killChains[i].name}`)
    }

    engagement.killChains = killChains

    // ── Phase 6: Impact Scoring (80-90%) ──
    updateProgress(engagementId, 'IMPACT_SCORING', 82, 'Impact Scoring',
      'Calculating business-context risk scores...')
    await sleep(400)

    const overallRiskScore = calculateOverallRiskScore(findings, killChains, attackSurface, engagement.targetConfig)
    const riskLevel = classifyRiskLevel(overallRiskScore)

    updateProgress(engagementId, 'IMPACT_SCORING', 88, 'Impact Scoring',
      `Overall risk score: ${overallRiskScore}/100 (${riskLevel})`,
      { riskScore: overallRiskScore, riskLevel })
    await sleep(300)

    updateProgress(engagementId, 'IMPACT_SCORING', 90, 'Impact Scoring',
      `Business impact assessed for ${engagement.targetConfig.businessContext.industry} vertical`)

    // ── Phase 7: Report Generation (90-100%) ──
    updateProgress(engagementId, 'REPORTING', 92, 'Reporting',
      'Claude is generating executive summary and AI insights...')

    // Generate AI content in parallel
    const [executiveSummary, aiInsights] = await Promise.all([
      generateExecutiveSummary(engagement.targetConfig, findings, killChains, overallRiskScore),
      generateAiInsights(engagement.targetConfig, findings, killChains, attackSurface),
    ])

    updateProgress(engagementId, 'REPORTING', 96, 'Reporting',
      'Compiling final report with compliance gaps and remediation roadmap...')
    await sleep(300)

    const report = generateReport(
      engagementId, findings, killChains, attackSurface, reconResult,
      engagement.targetConfig, executiveSummary, aiInsights,
    )
    engagement.report = report

    // Build summary
    engagement.summary = {
      totalAssets: attackSurface.totalAssets,
      totalFindings: findings.length,
      criticalFindings: critCount,
      highFindings: highCount,
      mediumFindings: findings.filter(f => f.severity === 'MEDIUM').length,
      lowFindings: findings.filter(f => f.severity === 'LOW').length,
      totalKillChains: killChains.length,
      overallRiskScore,
      exposureScore: attackSurface.exposureScore,
    }

    engagement.status = 'COMPLETED'
    engagement.progress = 100
    engagement.currentPhase = 'complete'
    engagement.completedAt = new Date().toISOString()
    engagementStore.set(engagementId, engagement)

    updateProgress(engagementId, 'COMPLETED', 100, 'Complete',
      `Analysis complete: ${findings.length} findings, ${killChains.length} kill chains, risk score ${overallRiskScore}/100`)

    console.log(`[BBRT] Engagement complete: ${engagementId}`, {
      findings: findings.length,
      killChains: killChains.length,
      riskScore: overallRiskScore,
      assets: attackSurface.totalAssets,
    })

  } catch (err) {
    console.error(`[BBRT] Engagement failed: ${engagementId}`, err)
    engagement.status = 'FAILED'
    engagement.currentPhase = 'failed'
    engagementStore.set(engagementId, engagement)
    updateProgress(engagementId, 'FAILED', engagement.progress, 'Failed',
      `Analysis failed: ${(err as Error).message}`)
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
