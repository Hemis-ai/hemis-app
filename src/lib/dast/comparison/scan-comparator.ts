/**
 * DAST Scan Comparator — Diff two scans to show regression/improvement trends.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ScanComparisonInput {
  id: string
  name: string
  targetUrl: string
  riskScore: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
  endpointsDiscovered: number
  endpointsTested: number
  payloadsSent: number
  completedAt: string | null
  findings: ComparisonFinding[]
}

export interface ComparisonFinding {
  id: string
  type: string
  severity: string
  title: string
  affectedUrl: string
  affectedParameter: string | null
  cvssScore: number | null
  owaspCategory: string
  cweId: string | null
  riskScore: number
}

export interface ScanDelta {
  metric: string
  baseline: number
  current: number
  delta: number
  direction: 'improved' | 'regressed' | 'unchanged'
  percentage: number
}

export interface FindingDiff {
  /** Findings that exist in current but NOT in baseline (new vulnerabilities) */
  newFindings: ComparisonFinding[]
  /** Findings that existed in baseline but NOT in current (resolved) */
  resolvedFindings: ComparisonFinding[]
  /** Findings that appear in both (still open) */
  persistentFindings: ComparisonFinding[]
  /** Findings that got worse (higher severity in current) */
  escalatedFindings: Array<{ finding: ComparisonFinding; previousSeverity: string }>
  /** Findings that improved (lower severity in current) */
  deescalatedFindings: Array<{ finding: ComparisonFinding; previousSeverity: string }>
}

export interface ScanComparisonResult {
  baseline: { id: string; name: string; completedAt: string | null }
  current: { id: string; name: string; completedAt: string | null }
  deltas: ScanDelta[]
  findingDiff: FindingDiff
  overallTrend: 'improved' | 'regressed' | 'stable'
  trendScore: number // -100 (worst regression) to +100 (best improvement)
  summary: string
}

// ─── Severity Ordering ─────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

const SEV_WEIGHT: Record<string, number> = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0.2,
}

// ─── Fingerprint ────────────────────────────────────────────────────────────
// We match findings across scans by type + affected URL + parameter (not by ID)

function fingerprintFinding(f: ComparisonFinding): string {
  return `${f.type}|${f.affectedUrl}|${f.affectedParameter ?? ''}`
}

// ─── Compare Two Scans ─────────────────────────────────────────────────────

export function compareScans(
  baseline: ScanComparisonInput,
  current: ScanComparisonInput,
): ScanComparisonResult {
  // 1. Compute metric deltas
  const deltas = computeDeltas(baseline, current)

  // 2. Diff findings
  const findingDiff = diffFindings(baseline.findings, current.findings)

  // 3. Calculate trend score
  const trendScore = calculateTrendScore(deltas, findingDiff)
  const overallTrend: ScanComparisonResult['overallTrend'] =
    trendScore > 5 ? 'improved' : trendScore < -5 ? 'regressed' : 'stable'

  // 4. Generate summary
  const summary = generateSummary(deltas, findingDiff, overallTrend, trendScore)

  return {
    baseline: { id: baseline.id, name: baseline.name, completedAt: baseline.completedAt },
    current: { id: current.id, name: current.name, completedAt: current.completedAt },
    deltas,
    findingDiff,
    overallTrend,
    trendScore,
    summary,
  }
}

// ─── Metric Deltas ──────────────────────────────────────────────────────────

function computeDeltas(baseline: ScanComparisonInput, current: ScanComparisonInput): ScanDelta[] {
  const metrics: Array<{ metric: string; bVal: number; cVal: number; lowerIsBetter: boolean }> = [
    { metric: 'Risk Score', bVal: baseline.riskScore, cVal: current.riskScore, lowerIsBetter: true },
    { metric: 'Critical', bVal: baseline.criticalCount, cVal: current.criticalCount, lowerIsBetter: true },
    { metric: 'High', bVal: baseline.highCount, cVal: current.highCount, lowerIsBetter: true },
    { metric: 'Medium', bVal: baseline.mediumCount, cVal: current.mediumCount, lowerIsBetter: true },
    { metric: 'Low', bVal: baseline.lowCount, cVal: current.lowCount, lowerIsBetter: true },
    { metric: 'Info', bVal: baseline.infoCount, cVal: current.infoCount, lowerIsBetter: true },
    { metric: 'Endpoints Discovered', bVal: baseline.endpointsDiscovered, cVal: current.endpointsDiscovered, lowerIsBetter: false },
    { metric: 'Endpoints Tested', bVal: baseline.endpointsTested, cVal: current.endpointsTested, lowerIsBetter: false },
    { metric: 'Total Findings', bVal: baseline.findings.length, cVal: current.findings.length, lowerIsBetter: true },
  ]

  return metrics.map(({ metric, bVal, cVal, lowerIsBetter }) => {
    const delta = cVal - bVal
    const percentage = bVal === 0 ? (cVal === 0 ? 0 : 100) : Math.round((delta / bVal) * 100)
    let direction: ScanDelta['direction'] = 'unchanged'
    if (delta !== 0) {
      direction = (lowerIsBetter ? delta < 0 : delta > 0) ? 'improved' : 'regressed'
    }
    return { metric, baseline: bVal, current: cVal, delta, direction, percentage }
  })
}

// ─── Findings Diff ──────────────────────────────────────────────────────────

function diffFindings(
  baselineFindings: ComparisonFinding[],
  currentFindings: ComparisonFinding[],
): FindingDiff {
  const baselineMap = new Map<string, ComparisonFinding>()
  const currentMap = new Map<string, ComparisonFinding>()

  for (const f of baselineFindings) baselineMap.set(fingerprintFinding(f), f)
  for (const f of currentFindings) currentMap.set(fingerprintFinding(f), f)

  const newFindings: ComparisonFinding[] = []
  const resolvedFindings: ComparisonFinding[] = []
  const persistentFindings: ComparisonFinding[] = []
  const escalatedFindings: FindingDiff['escalatedFindings'] = []
  const deescalatedFindings: FindingDiff['deescalatedFindings'] = []

  // Current findings not in baseline → new
  for (const [fp, f] of currentMap) {
    if (!baselineMap.has(fp)) {
      newFindings.push(f)
    } else {
      // Present in both → persistent. Check for severity changes.
      const baseF = baselineMap.get(fp)!
      persistentFindings.push(f)
      const baseOrd = SEV_ORDER[baseF.severity] ?? 5
      const curOrd = SEV_ORDER[f.severity] ?? 5
      if (curOrd < baseOrd) {
        // Severity went up (e.g., MEDIUM → HIGH)
        escalatedFindings.push({ finding: f, previousSeverity: baseF.severity })
      } else if (curOrd > baseOrd) {
        deescalatedFindings.push({ finding: f, previousSeverity: baseF.severity })
      }
    }
  }

  // Baseline findings not in current → resolved
  for (const [fp, f] of baselineMap) {
    if (!currentMap.has(fp)) {
      resolvedFindings.push(f)
    }
  }

  return { newFindings, resolvedFindings, persistentFindings, escalatedFindings, deescalatedFindings }
}

// ─── Trend Score ────────────────────────────────────────────────────────────

function calculateTrendScore(deltas: ScanDelta[], diff: FindingDiff): number {
  let score = 0

  // Resolved findings are positive
  for (const f of diff.resolvedFindings) {
    score += (SEV_WEIGHT[f.severity] ?? 1) * 2
  }
  // New findings are negative
  for (const f of diff.newFindings) {
    score -= (SEV_WEIGHT[f.severity] ?? 1) * 2
  }
  // Escalations are bad, de-escalations are good
  score -= diff.escalatedFindings.length * 3
  score += diff.deescalatedFindings.length * 3

  // Risk score delta
  const riskDelta = deltas.find(d => d.metric === 'Risk Score')
  if (riskDelta) {
    score += riskDelta.delta < 0 ? Math.abs(riskDelta.delta) * 0.3 : -riskDelta.delta * 0.3
  }

  // Clamp to -100 .. +100
  return Math.max(-100, Math.min(100, Math.round(score)))
}

// ─── Summary ────────────────────────────────────────────────────────────────

function generateSummary(
  deltas: ScanDelta[],
  diff: FindingDiff,
  trend: string,
  trendScore: number,
): string {
  const parts: string[] = []

  if (trend === 'improved') {
    parts.push(`Security posture improved (trend score: +${trendScore}).`)
  } else if (trend === 'regressed') {
    parts.push(`Security posture regressed (trend score: ${trendScore}).`)
  } else {
    parts.push(`Security posture remained stable.`)
  }

  if (diff.resolvedFindings.length > 0) {
    parts.push(`${diff.resolvedFindings.length} finding(s) resolved.`)
  }
  if (diff.newFindings.length > 0) {
    const critNew = diff.newFindings.filter(f => f.severity === 'CRITICAL').length
    parts.push(`${diff.newFindings.length} new finding(s) introduced${critNew > 0 ? ` (${critNew} critical)` : ''}.`)
  }
  if (diff.escalatedFindings.length > 0) {
    parts.push(`${diff.escalatedFindings.length} finding(s) escalated in severity.`)
  }

  const riskDelta = deltas.find(d => d.metric === 'Risk Score')
  if (riskDelta && riskDelta.delta !== 0) {
    parts.push(`Risk score ${riskDelta.delta < 0 ? 'decreased' : 'increased'} from ${riskDelta.baseline} to ${riskDelta.current}.`)
  }

  return parts.join(' ')
}
