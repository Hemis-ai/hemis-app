// src/lib/bbrt/impact-scorer.ts
// Phase 6: Business Impact Scoring
import type {
  BbrtFinding,
  BbrtKillChain,
  BbrtAttackSurface,
  BbrtTargetConfig,
} from '@/lib/types/bbrt'
import type { SastSeverity } from '@/lib/types/sast'

// ─── Industry Breach Cost Data (IBM/Ponemon 2024) ───────────────────────────
const INDUSTRY_COST_PER_RECORD: Record<string, number> = {
  fintech: 188, healthcare: 211, saas: 164, ecommerce: 171,
  government: 156, education: 137, media: 148, manufacturing: 144,
  energy: 178, telecom: 161, other: 164,
}

const SEVERITY_WEIGHT: Record<SastSeverity, number> = {
  CRITICAL: 1.0, HIGH: 0.75, MEDIUM: 0.5, LOW: 0.25, INFO: 0.1,
}

// ─── Overall Risk Score Calculator ──────────────────────────────────────────

export function calculateOverallRiskScore(
  findings: BbrtFinding[],
  killChains: BbrtKillChain[],
  surface: BbrtAttackSurface,
  config: BbrtTargetConfig,
): number {
  if (findings.length === 0) return 0

  // Component 1: Finding severity (40% weight)
  const findingSeverityScore = findings.reduce((sum, f) => {
    return sum + SEVERITY_WEIGHT[f.severity] * f.cvssScore * 10
  }, 0) / findings.length
  const normalizedFindingScore = Math.min(findingSeverityScore, 100)

  // Component 2: Kill chain risk (30% weight)
  const impactScores: Record<string, number> = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25 }
  const chainScore = killChains.length > 0
    ? killChains.reduce((max, kc) => Math.max(max, impactScores[kc.impact] || 0), 0)
    : 0

  // Component 3: Attack surface exposure (20% weight)
  const surfaceScore = surface.exposureScore

  // Component 4: Industry risk multiplier (10% weight)
  const highRiskIndustries = new Set(['fintech', 'healthcare', 'government'])
  const industryBonus = highRiskIndustries.has(config.businessContext.industry) ? 100 : 50

  // Weighted combination
  const overallScore = Math.round(
    normalizedFindingScore * 0.40 +
    chainScore * 0.30 +
    surfaceScore * 0.20 +
    industryBonus * 0.10
  )

  return Math.min(overallScore, 100)
}

// ─── Risk Level Classification ──────────────────────────────────────────────

export function classifyRiskLevel(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  return 'LOW'
}

// ─── Financial Impact Estimator ─────────────────────────────────────────────

export function estimateFinancialImpact(
  findings: BbrtFinding[],
  config: BbrtTargetConfig,
): { low: number; high: number; currency: string } {
  const costPerRecord = INDUSTRY_COST_PER_RECORD[config.businessContext.industry] || 164

  // Sum all findings' records at risk (deduplicated by max per severity)
  const maxRecordsAtRisk = findings.reduce((max, f) => {
    return Math.max(max, f.businessImpact.dataRecordsAtRisk)
  }, 0)

  // Range estimate: 0.5x to 1.5x of the base calculation
  const baseCost = maxRecordsAtRisk * costPerRecord
  return {
    low: Math.round(baseCost * 0.5),
    high: Math.round(baseCost * 1.5),
    currency: 'USD',
  }
}
