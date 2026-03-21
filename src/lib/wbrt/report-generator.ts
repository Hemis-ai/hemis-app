// src/lib/wbrt/report-generator.ts
import type { WbrtReport, WbrtFinding, KillChain, AttackGraph, ArchitectureContext, ComplianceGap, RemediationItem } from '@/lib/types/wbrt'
import type { SastSeverity } from '@/lib/types/sast'
import { randomUUID } from 'crypto'

export function generateReport(
  engagementId: string,
  findings: WbrtFinding[],
  killChains: KillChain[],
  graph: AttackGraph,
  arch: ArchitectureContext,
): WbrtReport {
  // Overall risk score = weighted average of finding impact scores
  const totalScore = findings.reduce((sum, f) => sum + f.businessImpact.score, 0)
  const overallRiskScore = findings.length > 0 ? Math.round(totalScore / findings.length) : 0
  const riskLevel: SastSeverity = overallRiskScore >= 80 ? 'CRITICAL' : overallRiskScore >= 60 ? 'HIGH' : overallRiskScore >= 40 ? 'MEDIUM' : 'LOW'

  // Compliance gaps
  const complianceGaps = buildComplianceGaps(findings, arch)

  // Remediation roadmap
  const remediationRoadmap = buildRemediationRoadmap(findings)

  // Executive summary
  const executiveSummary = buildExecutiveSummary(findings, killChains, graph, overallRiskScore, riskLevel, arch)

  return {
    id: randomUUID(),
    engagementId,
    executiveSummary,
    overallRiskScore,
    riskLevel: riskLevel as any,
    attackPathCount: graph.edges.length,
    killChainCount: killChains.length,
    topFindings: findings.slice(0, 5),
    complianceGaps,
    remediationRoadmap,
    generatedAt: new Date().toISOString(),
  }
}

function buildExecutiveSummary(
  findings: WbrtFinding[],
  killChains: KillChain[],
  graph: AttackGraph,
  riskScore: number,
  riskLevel: string,
  arch: ArchitectureContext,
): string {
  const critCount = findings.filter(f => f.severity === 'CRITICAL').length
  const highCount = findings.filter(f => f.severity === 'HIGH').length
  const totalFinancial = findings.reduce((max, f) => {
    const match = f.businessImpact.financialEstimate.match(/\$[\d.]+[MK]/g)
    return match ? f.businessImpact.financialEstimate : max
  }, '$0')

  return `## White Box Red Team Assessment \u2014 Executive Summary

### Overall Risk Posture: **${riskLevel}** (${riskScore}/100)

This white box red team assessment analyzed the application architecture (${arch.techStack.join(', ')}) with full source code access, simulating an insider threat with complete knowledge of the system.

### Key Findings

- **${findings.length} exploitable attack paths** identified across ${graph.nodes.length} system components
- **${killChains.length} complete kill chains** from initial access to data exfiltration
- **${critCount} critical** and **${highCount} high** severity attack paths require immediate remediation
- **${graph.entryPoints.length} entry points** identified with exploitable vulnerabilities
- **${graph.crownJewels.length} crown jewels** (sensitive data stores) are reachable through chained attacks

### Risk Categories

${critCount > 0 ? `- **CRITICAL**: ${critCount} attack paths enable full system compromise or data exfiltration` : ''}
${highCount > 0 ? `- **HIGH**: ${highCount} attack paths enable significant unauthorized access` : ''}
${findings.filter(f => f.severity === 'MEDIUM').length > 0 ? `- **MEDIUM**: ${findings.filter(f => f.severity === 'MEDIUM').length} attack paths with moderate business impact` : ''}

### Compliance Impact

${arch.complianceRequirements.map(f => `- **${f}**: Gaps identified \u2014 remediation required before audit`).join('\n')}

### Recommended Actions

1. **Immediate (0-48 hrs)**: Remediate all CRITICAL attack paths \u2014 focus on breaking the kill chains at their weakest links
2. **Short-term (1-2 weeks)**: Address HIGH severity paths, implement network segmentation
3. **Medium-term (1-3 months)**: Full remediation roadmap, detection rule deployment for identified MITRE techniques
4. **Ongoing**: Re-run WBRT assessment quarterly to track remediation progress`
}

function buildComplianceGaps(
  findings: WbrtFinding[],
  arch: ArchitectureContext,
): ComplianceGap[] {
  const gaps: ComplianceGap[] = []

  const frameworkControls: Record<string, { controlId: string; controlName: string }[]> = {
    PCI_DSS: [
      { controlId: 'PCI-6.2.4', controlName: 'Injection prevention' },
      { controlId: 'PCI-6.3.1', controlName: 'Vulnerability identification' },
      { controlId: 'PCI-1.3.1', controlName: 'Network segmentation' },
      { controlId: 'PCI-8.3.1', controlName: 'Strong authentication' },
    ],
    SOC2: [
      { controlId: 'CC6.1', controlName: 'Logical access controls' },
      { controlId: 'CC6.6', controlName: 'Boundary protection' },
      { controlId: 'CC7.1', controlName: 'Vulnerability management' },
      { controlId: 'CC7.2', controlName: 'Anomaly monitoring' },
    ],
    HIPAA: [
      { controlId: '164.312(a)(1)', controlName: 'Access control' },
      { controlId: '164.312(e)(1)', controlName: 'Transmission security' },
      { controlId: '164.308(a)(1)', controlName: 'Security management' },
    ],
    ISO27001: [
      { controlId: 'A.14.2.1', controlName: 'Secure development policy' },
      { controlId: 'A.12.6.1', controlName: 'Technical vulnerability management' },
    ],
    GDPR: [
      { controlId: 'Art.32', controlName: 'Security of processing' },
      { controlId: 'Art.25', controlName: 'Data protection by design' },
    ],
    CIS: [
      { controlId: 'CIS-7', controlName: 'Continuous vulnerability management' },
      { controlId: 'CIS-16', controlName: 'Application software security' },
    ],
    NIST: [
      { controlId: 'SI-10', controlName: 'Information input validation' },
      { controlId: 'AC-6', controlName: 'Least privilege' },
    ],
  }

  for (const framework of arch.complianceRequirements) {
    const controls = frameworkControls[framework] || []
    const affectedFindings = findings.filter(f =>
      f.businessImpact.complianceFrameworksAffected.includes(framework)
    )

    if (affectedFindings.length > 0) {
      for (const control of controls) {
        gaps.push({
          framework,
          controlId: control.controlId,
          controlName: control.controlName,
          status: affectedFindings.some(f => f.severity === 'CRITICAL') ? 'FAIL' : 'PARTIAL',
          affectedFindingIds: affectedFindings.map(f => f.id),
          remediationNote: `Address attack paths affecting ${control.controlName} \u2014 ${affectedFindings.length} findings impact this control`,
        })
      }
    }
  }

  return gaps
}

function buildRemediationRoadmap(findings: WbrtFinding[]): RemediationItem[] {
  return findings.map((f, i) => ({
    priority: i + 1,
    title: `Break kill chain: ${f.name}`,
    description: f.remediationSteps.join('; '),
    effort: f.severity === 'CRITICAL' ? 'HIGH' as const : f.severity === 'HIGH' ? 'MEDIUM' as const : 'LOW' as const,
    impact: f.severity as any,
    affectedFindingIds: [f.id],
    estimatedHours: f.severity === 'CRITICAL' ? 16 : f.severity === 'HIGH' ? 8 : 4,
  }))
}
