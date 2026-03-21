// src/lib/wbrt/engagement-orchestrator.ts
import type { WbrtEngagement, WbrtProgressEvent, ArchitectureContext } from '@/lib/types/wbrt'
import type { SastFindingResult } from '@/lib/types/sast'
import { mapAttackSurface } from './attack-surface-mapper'
import { generateAttackGraph } from './attack-graph-engine'
import { constructKillChains } from './kill-chain-engine'
import { scoreFindings } from './impact-scorer'
import { generateReport } from './report-generator'
import { MOCK_WBRT_ENGAGEMENT } from '@/lib/mock-data/wbrt'
import { randomUUID } from 'crypto'

// In-memory progress store (same pattern as DAST)
export const progressStore = new Map<string, WbrtProgressEvent>()

// In-memory engagement store (demo mode)
const engagementStore = new Map<string, WbrtEngagement>()

function updateProgress(
  engagementId: string,
  status: WbrtProgressEvent['status'],
  progress: number,
  phase: string,
  message: string,
) {
  progressStore.set(engagementId, {
    engagementId,
    status,
    progress,
    currentPhase: phase,
    message,
    timestamp: new Date().toISOString(),
  })
}

export function getEngagement(id: string): WbrtEngagement | null {
  return engagementStore.get(id) || null
}

export function listEngagements(): WbrtEngagement[] {
  return Array.from(engagementStore.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  )
}

export function createEngagement(
  name: string,
  inputSource: WbrtEngagement['inputSource'],
  arch: ArchitectureContext,
  sastScanId?: string,
): WbrtEngagement {
  const engagement: WbrtEngagement = {
    id: randomUUID(),
    orgId: 'org-demo',
    name,
    inputSource,
    status: 'CREATED',
    progress: 0,
    currentPhase: 'created',
    architectureContext: arch,
    sastScanId,
    killChains: [],
    findings: [],
    createdAt: new Date().toISOString(),
  }

  engagementStore.set(engagement.id, engagement)
  return engagement
}

/**
 * Run the full 6-phase WBRT analysis pipeline.
 * Fire-and-forget from the API route (same as DAST pattern).
 */
export async function runEngagement(
  engagementId: string,
  findings: SastFindingResult[],
): Promise<void> {
  const engagement = engagementStore.get(engagementId)
  if (!engagement) throw new Error(`Engagement ${engagementId} not found`)

  try {
    engagement.status = 'INGESTING'
    engagement.startedAt = new Date().toISOString()
    engagementStore.set(engagementId, engagement)

    // ── Phase 1: Ingest & Normalize (0-15%) ──
    updateProgress(engagementId, 'INGESTING', 5, 'Ingesting', 'Normalizing SAST findings and source context...')
    await sleep(800) // Simulate processing time

    if (findings.length === 0) {
      // Demo mode: use mock data
      const mock = MOCK_WBRT_ENGAGEMENT
      Object.assign(engagement, {
        ...mock,
        id: engagementId,
        name: engagement.name,
        architectureContext: engagement.architectureContext,
        status: 'COMPLETED',
        progress: 100,
        currentPhase: 'complete',
        completedAt: new Date().toISOString(),
      })
      engagementStore.set(engagementId, engagement)
      updateProgress(engagementId, 'COMPLETED', 100, 'Complete', 'Analysis complete (demo mode)')
      return
    }

    updateProgress(engagementId, 'INGESTING', 15, 'Ingesting', `Ingested ${findings.length} findings from SAST scan`)

    // ── Phase 2: Attack Surface Mapping (15-30%) ──
    updateProgress(engagementId, 'MAPPING', 20, 'Mapping Attack Surface', 'Identifying entry points, assets, and crown jewels...')
    const surface = mapAttackSurface(findings, engagement.architectureContext)
    updateProgress(engagementId, 'MAPPING', 30, 'Mapping Attack Surface',
      `Mapped ${surface.entryPoints.length} entry points, ${surface.assets.length} assets, ${surface.crownJewels.length} crown jewels`)

    // ── Phase 3: Attack Graph Generation (30-55%) ──
    updateProgress(engagementId, 'GRAPHING', 35, 'Generating Attack Graph', 'Claude is analyzing vulnerability chains...')
    const attackGraph = await generateAttackGraph({ engagementId, findings, surface })
    engagement.attackGraph = attackGraph
    updateProgress(engagementId, 'GRAPHING', 55, 'Generating Attack Graph',
      `Generated graph with ${attackGraph.nodes.length} nodes and ${attackGraph.edges.length} edges`)

    // ── Phase 4: Kill Chain Construction (55-75%) ──
    updateProgress(engagementId, 'CHAINING', 60, 'Constructing Kill Chains', 'Mapping attack paths to MITRE ATT&CK framework...')
    const killChains = constructKillChains(attackGraph, engagementId)
    engagement.killChains = killChains
    updateProgress(engagementId, 'CHAINING', 75, 'Constructing Kill Chains',
      `Constructed ${killChains.length} kill chains with full MITRE mapping`)

    // ── Phase 5: Business Impact Scoring (75-90%) ──
    updateProgress(engagementId, 'SCORING', 80, 'Scoring Business Impact', 'Calculating financial, compliance, and reputational impact...')
    const wbrtFindings = scoreFindings(attackGraph, killChains, findings, engagement.architectureContext, engagementId)
    engagement.findings = wbrtFindings
    updateProgress(engagementId, 'SCORING', 90, 'Scoring Business Impact',
      `Scored ${wbrtFindings.length} chained findings with business impact`)

    // ── Phase 6: Report Synthesis (90-100%) ──
    updateProgress(engagementId, 'REPORTING', 92, 'Generating Report', 'Synthesizing executive red team report...')
    const report = generateReport(engagementId, wbrtFindings, killChains, attackGraph, engagement.architectureContext)
    engagement.report = report

    // Build summary
    engagement.summary = {
      totalAttackPaths: attackGraph.edges.length,
      totalKillChains: killChains.length,
      criticalFindings: wbrtFindings.filter(f => f.severity === 'CRITICAL').length,
      highFindings: wbrtFindings.filter(f => f.severity === 'HIGH').length,
      mediumFindings: wbrtFindings.filter(f => f.severity === 'MEDIUM').length,
      lowFindings: wbrtFindings.filter(f => f.severity === 'LOW').length,
      overallRiskScore: report.overallRiskScore,
    }

    engagement.status = 'COMPLETED'
    engagement.progress = 100
    engagement.currentPhase = 'complete'
    engagement.completedAt = new Date().toISOString()
    engagementStore.set(engagementId, engagement)

    updateProgress(engagementId, 'COMPLETED', 100, 'Complete',
      `Analysis complete: ${wbrtFindings.length} findings, ${killChains.length} kill chains, risk score ${report.overallRiskScore}/100`)

    console.log(`[WBRT] Engagement complete: ${engagementId}`, {
      findings: wbrtFindings.length,
      killChains: killChains.length,
      riskScore: report.overallRiskScore,
    })

  } catch (err) {
    console.error(`[WBRT] Engagement failed: ${engagementId}`, err)
    engagement.status = 'FAILED'
    engagement.currentPhase = 'failed'
    engagementStore.set(engagementId, engagement)
    updateProgress(engagementId, 'FAILED', engagement.progress, 'Failed', `Analysis failed: ${(err as Error).message}`)
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
