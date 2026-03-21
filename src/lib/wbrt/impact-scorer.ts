// src/lib/wbrt/impact-scorer.ts
import type { AttackGraph, KillChain, WbrtFinding, BusinessImpact, ArchitectureContext, DataClassification, ComplianceFramework } from '@/lib/types/wbrt'
import type { SastFindingResult, SastSeverity } from '@/lib/types/sast'
import { randomUUID } from 'crypto'

const SEVERITY_WEIGHT: Record<SastSeverity, number> = {
  CRITICAL: 1.0, HIGH: 0.75, MEDIUM: 0.5, LOW: 0.25, INFO: 0.1,
}

const DATA_CLASS_WEIGHT: Record<DataClassification, number> = {
  RESTRICTED: 1.0, PHI: 0.95, PCI: 0.9, PII: 0.85, CONFIDENTIAL: 0.7, INTERNAL: 0.3, PUBLIC: 0.05,
}

const RECORDS_BY_USER_COUNT: Record<string, number> = {
  '1-100': 5_000, '100-1K': 50_000, '1K-10K': 500_000, '10K+': 5_000_000,
}

const COST_PER_RECORD = 164 // IBM Cost of a Data Breach 2025 average

export function scoreFindings(
  graph: AttackGraph,
  killChains: KillChain[],
  findings: SastFindingResult[],
  arch: ArchitectureContext,
  engagementId: string,
): WbrtFinding[] {
  const wbrtFindings: WbrtFinding[] = []
  const findingMap = new Map(findings.map(f => [`vuln-${f.id}`, f]))
  let priority = 0

  for (const chain of killChains) {
    priority++

    // Collect source SAST findings in this chain
    const sourceIds: string[] = []
    const severities: SastSeverity[] = []
    for (const step of chain.steps) {
      for (const nodeId of step.nodeIds) {
        const finding = findingMap.get(nodeId)
        if (finding) {
          sourceIds.push(finding.id)
          severities.push(finding.severity)
        }
      }
    }

    // Calculate composite severity
    const maxSeverityWeight = Math.max(...severities.map(s => SEVERITY_WEIGHT[s] || 0), 0.25)
    const chainLengthMultiplier = Math.min(chain.steps.length / 3, 2) // longer chains = more impactful

    // Data classification impact
    const dataWeights = arch.dataClassifications.map(d => DATA_CLASS_WEIGHT[d] || 0.1)
    const maxDataWeight = Math.max(...dataWeights, 0.1)

    // Business impact score (1-100)
    const rawScore = (maxSeverityWeight * 40) + (maxDataWeight * 30) + (chainLengthMultiplier * 15) +
      (chain.likelihood === 'VERY_HIGH' ? 15 : chain.likelihood === 'HIGH' ? 10 : chain.likelihood === 'MEDIUM' ? 5 : 2)
    const score = Math.min(100, Math.round(rawScore))

    // Financial estimate
    const estimatedRecords = RECORDS_BY_USER_COUNT[arch.userCount] || 50_000
    const recordsAtRisk = Math.round(estimatedRecords * maxDataWeight * maxSeverityWeight)
    const minCost = recordsAtRisk * COST_PER_RECORD * 0.5
    const maxCost = recordsAtRisk * COST_PER_RECORD * 1.5

    const formatCost = (n: number) => {
      if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`
      if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`
      return `$${n}`
    }

    // Compliance frameworks affected
    const affectedFrameworks = determineAffectedFrameworks(severities, arch.complianceRequirements)

    // Reputational score
    const reputationalScore = Math.round(score * 0.8 + (arch.dataClassifications.includes('PII') ? 15 : 0))

    const businessImpact: BusinessImpact = {
      score,
      financialEstimate: `${formatCost(minCost)} - ${formatCost(maxCost)}`,
      dataRecordsAtRisk: recordsAtRisk,
      dataTypes: arch.dataClassifications.filter(d => DATA_CLASS_WEIGHT[d] >= 0.7),
      complianceFrameworksAffected: affectedFrameworks,
      reputationalScore: Math.min(100, reputationalScore),
      operationalImpact: score >= 80 ? 'Extended service disruption (48-72 hrs)' :
        score >= 60 ? 'Significant service degradation (12-24 hrs)' :
        score >= 40 ? 'Partial service impact (4-8 hrs)' : 'Minimal operational impact',
      legalExposure: affectedFrameworks.length >= 2
        ? 'Class-action risk, regulatory fines, mandatory breach notification'
        : affectedFrameworks.length === 1
        ? 'Regulatory fines possible, breach notification required'
        : 'Limited legal exposure',
    }

    const severity: SastSeverity = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'

    // Remediation steps
    const remediationSteps = generateRemediationSteps(chain, findingMap)

    wbrtFindings.push({
      id: randomUUID(),
      engagementId,
      name: chain.name,
      attackPathNodeIds: chain.steps.flatMap(s => s.nodeIds),
      attackPathDescription: chain.narrative,
      sourceFindingIds: [...new Set(sourceIds)],
      severity,
      businessImpact,
      killChainId: chain.id,
      mitreMapping: chain.mitreMapping,
      remediationPriority: priority,
      remediationSteps,
      status: 'OPEN',
    })
  }

  return wbrtFindings
}

function determineAffectedFrameworks(
  severities: SastSeverity[],
  required: ComplianceFramework[]
): ComplianceFramework[] {
  const hasCritical = severities.includes('CRITICAL')
  const hasHigh = severities.includes('HIGH')

  // All required frameworks are affected if critical/high vulns exist
  if (hasCritical) return required
  if (hasHigh) return required.filter(f => ['PCI_DSS', 'HIPAA', 'SOC2'].includes(f))
  return required.filter(f => f === 'PCI_DSS')
}

function generateRemediationSteps(
  chain: KillChain,
  findingMap: Map<string, SastFindingResult>
): string[] {
  const steps: string[] = []
  const seen = new Set<string>()

  for (const step of chain.steps) {
    for (const nodeId of step.nodeIds) {
      const finding = findingMap.get(nodeId)
      if (finding && !seen.has(finding.remediation)) {
        seen.add(finding.remediation)
        steps.push(`[${finding.severity}] ${finding.ruleName}: ${finding.remediation}`)
      }
    }
  }

  if (steps.length === 0) {
    steps.push('Review and remediate all vulnerabilities in this attack chain')
    steps.push('Implement network segmentation to limit lateral movement')
    steps.push('Add monitoring for the MITRE techniques identified in this kill chain')
  }

  return steps
}
