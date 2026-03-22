// src/lib/bbrt/report-generator.ts
// Phase 7: Report Generation
import type {
  BbrtReport,
  BbrtFinding,
  BbrtKillChain,
  BbrtAttackSurface,
  BbrtTargetConfig,
  BbrtAttackSurfaceStats,
  BbrtFindingStats,
  BbrtFindingType,
  BbrtReconResult,
} from '@/lib/types/bbrt'
import type { ComplianceGap, RemediationItem, ComplianceFramework } from '@/lib/types/wbrt'
import type { SastSeverity } from '@/lib/types/sast'
import { calculateOverallRiskScore, classifyRiskLevel } from './impact-scorer'
import { randomUUID } from 'crypto'

// ─── Main Report Generator ──────────────────────────────────────────────────

export function generateReport(
  engagementId: string,
  findings: BbrtFinding[],
  killChains: BbrtKillChain[],
  surface: BbrtAttackSurface,
  recon: BbrtReconResult,
  config: BbrtTargetConfig,
  executiveSummary: string,
  aiInsights: string,
): BbrtReport {
  const overallRiskScore = calculateOverallRiskScore(findings, killChains, surface, config)
  const riskLevel = classifyRiskLevel(overallRiskScore)

  return {
    id: `bbrt-report-${randomUUID().slice(0, 8)}`,
    engagementId,
    executiveSummary,
    overallRiskScore,
    riskLevel,
    attackSurfaceStats: buildAttackSurfaceStats(surface, recon),
    findingStats: buildFindingStats(findings),
    killChainCount: killChains.length,
    topKillChains: killChains.slice(0, 5),
    criticalFindings: findings.filter(f => f.severity === 'CRITICAL'),
    complianceGaps: buildComplianceGaps(findings, config),
    remediationRoadmap: buildRemediationRoadmap(findings),
    aiInsights,
    generatedAt: new Date().toISOString(),
  }
}

// ─── Attack Surface Stats ───────────────────────────────────────────────────

function buildAttackSurfaceStats(
  surface: BbrtAttackSurface,
  recon: BbrtReconResult,
): BbrtAttackSurfaceStats {
  return {
    totalAssets: surface.totalAssets,
    publicAssets: surface.publicAssets,
    shadowAssets: surface.shadowAssets.length,
    entryPoints: surface.entryPoints.length,
    crownJewels: surface.crownJewels.length,
    exposureScore: surface.exposureScore,
    openPorts: recon.openPorts.length,
    subdomains: recon.subdomains.length,
  }
}

// ─── Finding Stats ──────────────────────────────────────────────────────────

function buildFindingStats(findings: BbrtFinding[]): BbrtFindingStats {
  const byType: Record<BbrtFindingType, number> = {
    RECON_EXPOSURE: 0, MISCONFIG: 0, VULN: 0, CREDENTIAL_LEAK: 0,
    CLOUD_EXPOSURE: 0, SUPPLY_CHAIN: 0, LLM_VULN: 0, INFO_DISCLOSURE: 0,
    CERT_ISSUE: 0, AUTH_WEAKNESS: 0,
  }

  for (const f of findings) {
    byType[f.type] = (byType[f.type] || 0) + 1
  }

  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high: findings.filter(f => f.severity === 'HIGH').length,
    medium: findings.filter(f => f.severity === 'MEDIUM').length,
    low: findings.filter(f => f.severity === 'LOW').length,
    info: findings.filter(f => f.severity === 'INFO').length,
    byType,
  }
}

// ─── Compliance Gap Analysis ────────────────────────────────────────────────

const COMPLIANCE_CONTROLS: Record<ComplianceFramework, Array<{
  controlId: string
  controlName: string
  findingTypes: BbrtFindingType[]
  severities: SastSeverity[]
}>> = {
  PCI_DSS: [
    { controlId: 'PCI-6.5.1', controlName: 'Injection Flaws', findingTypes: ['VULN'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'PCI-6.5.10', controlName: 'Broken Authentication', findingTypes: ['AUTH_WEAKNESS', 'CREDENTIAL_LEAK'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'PCI-2.1', controlName: 'Change Default Credentials', findingTypes: ['AUTH_WEAKNESS'], severities: ['CRITICAL'] },
    { controlId: 'PCI-3.4', controlName: 'Render PAN Unreadable', findingTypes: ['CLOUD_EXPOSURE', 'INFO_DISCLOSURE'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'PCI-11.3', controlName: 'Penetration Testing', findingTypes: ['VULN', 'MISCONFIG'], severities: ['CRITICAL', 'HIGH', 'MEDIUM'] },
  ],
  SOC2: [
    { controlId: 'SOC2-CC6.1', controlName: 'Logical Access Controls', findingTypes: ['AUTH_WEAKNESS', 'CREDENTIAL_LEAK'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'SOC2-CC6.6', controlName: 'Vulnerability Management', findingTypes: ['VULN', 'MISCONFIG'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'SOC2-CC7.1', controlName: 'Monitoring', findingTypes: ['INFO_DISCLOSURE'], severities: ['MEDIUM', 'HIGH'] },
    { controlId: 'SOC2-CC6.7', controlName: 'Data Encryption', findingTypes: ['CERT_ISSUE', 'CLOUD_EXPOSURE'], severities: ['HIGH', 'MEDIUM'] },
  ],
  HIPAA: [
    { controlId: 'HIPAA-164.312(a)', controlName: 'Access Control', findingTypes: ['AUTH_WEAKNESS', 'CREDENTIAL_LEAK'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'HIPAA-164.312(e)', controlName: 'Transmission Security', findingTypes: ['CERT_ISSUE', 'MISCONFIG'], severities: ['HIGH', 'MEDIUM'] },
    { controlId: 'HIPAA-164.312(c)', controlName: 'Integrity Controls', findingTypes: ['VULN', 'CLOUD_EXPOSURE'], severities: ['CRITICAL', 'HIGH'] },
  ],
  ISO27001: [
    { controlId: 'A.9.4.1', controlName: 'Information Access Restriction', findingTypes: ['AUTH_WEAKNESS', 'CLOUD_EXPOSURE'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'A.12.6.1', controlName: 'Management of Technical Vulnerabilities', findingTypes: ['VULN', 'MISCONFIG'], severities: ['CRITICAL', 'HIGH', 'MEDIUM'] },
    { controlId: 'A.14.1.2', controlName: 'Securing Application Services', findingTypes: ['CERT_ISSUE'], severities: ['HIGH', 'MEDIUM'] },
  ],
  GDPR: [
    { controlId: 'GDPR-Art.32', controlName: 'Security of Processing', findingTypes: ['CLOUD_EXPOSURE', 'CREDENTIAL_LEAK'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'GDPR-Art.25', controlName: 'Data Protection by Design', findingTypes: ['MISCONFIG', 'INFO_DISCLOSURE'], severities: ['HIGH', 'MEDIUM'] },
  ],
  CIS: [
    { controlId: 'CIS-4', controlName: 'Secure Configuration', findingTypes: ['MISCONFIG'], severities: ['CRITICAL', 'HIGH', 'MEDIUM'] },
    { controlId: 'CIS-5', controlName: 'Account Management', findingTypes: ['AUTH_WEAKNESS', 'CREDENTIAL_LEAK'], severities: ['CRITICAL', 'HIGH'] },
  ],
  NIST: [
    { controlId: 'NIST-AC-2', controlName: 'Account Management', findingTypes: ['AUTH_WEAKNESS'], severities: ['CRITICAL', 'HIGH'] },
    { controlId: 'NIST-SI-2', controlName: 'Flaw Remediation', findingTypes: ['VULN'], severities: ['CRITICAL', 'HIGH', 'MEDIUM'] },
    { controlId: 'NIST-SC-8', controlName: 'Transmission Confidentiality', findingTypes: ['CERT_ISSUE'], severities: ['HIGH', 'MEDIUM'] },
  ],
}

function buildComplianceGaps(
  findings: BbrtFinding[],
  config: BbrtTargetConfig,
): ComplianceGap[] {
  const gaps: ComplianceGap[] = []

  for (const framework of config.complianceRequirements) {
    const controls = COMPLIANCE_CONTROLS[framework]
    if (!controls) continue

    for (const control of controls) {
      const matchingFindings = findings.filter(f =>
        control.findingTypes.includes(f.type) && control.severities.includes(f.severity)
      )

      if (matchingFindings.length > 0) {
        const hasCritical = matchingFindings.some(f => f.severity === 'CRITICAL')
        gaps.push({
          framework,
          controlId: control.controlId,
          controlName: control.controlName,
          status: hasCritical ? 'FAIL' : 'PARTIAL',
          affectedFindingIds: matchingFindings.map(f => f.id),
          remediationNote: `Remediate ${matchingFindings.length} finding(s) affecting this control: ${matchingFindings.map(f => f.title).join('; ')}`,
        })
      }
    }
  }

  return gaps
}

// ─── Remediation Roadmap ────────────────────────────────────────────────────

function buildRemediationRoadmap(findings: BbrtFinding[]): RemediationItem[] {
  const items: RemediationItem[] = []
  const severityOrder: Record<SastSeverity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

  // Group findings by remediation theme
  const themes: Array<{
    title: string
    description: string
    matchTypes: BbrtFindingType[]
    effort: RemediationItem['effort']
    estimatedHours: number
  }> = [
    {
      title: 'Rotate and Protect Leaked Credentials',
      description: 'Immediately rotate all exposed credentials (API keys, database passwords, cloud access keys). Implement secret scanning in CI/CD pipelines to prevent future leaks.',
      matchTypes: ['CREDENTIAL_LEAK'],
      effort: 'LOW',
      estimatedHours: 4,
    },
    {
      title: 'Restrict CI/CD and Admin Panel Access',
      description: 'Remove public internet access to Jenkins, admin panels, and monitoring dashboards. Implement VPN/zero-trust network access with MFA enforcement.',
      matchTypes: ['AUTH_WEAKNESS'],
      effort: 'MEDIUM',
      estimatedHours: 16,
    },
    {
      title: 'Secure Cloud Storage Configuration',
      description: 'Enable S3 Block Public Access at account level. Audit all cloud storage for public access. Enable encryption at rest and access logging.',
      matchTypes: ['CLOUD_EXPOSURE'],
      effort: 'LOW',
      estimatedHours: 8,
    },
    {
      title: 'Patch Vulnerable Software Components',
      description: 'Update all internet-facing services to latest patched versions. Prioritize database servers and web frameworks with known CVEs.',
      matchTypes: ['VULN'],
      effort: 'MEDIUM',
      estimatedHours: 24,
    },
    {
      title: 'Implement Security Headers and TLS Hardening',
      description: 'Deploy CSP, HSTS, X-Content-Type-Options, and X-Frame-Options headers. Upgrade all TLS certificates to SHA-256+ and disable legacy protocols.',
      matchTypes: ['MISCONFIG', 'CERT_ISSUE'],
      effort: 'LOW',
      estimatedHours: 8,
    },
    {
      title: 'Reduce External Attack Surface',
      description: 'Firewall all non-essential ports. Decommission shadow assets. Implement network segmentation to isolate databases from public internet.',
      matchTypes: ['INFO_DISCLOSURE', 'RECON_EXPOSURE'],
      effort: 'HIGH',
      estimatedHours: 40,
    },
  ]

  let priority = 0
  for (const theme of themes) {
    const matchingFindings = findings.filter(f => theme.matchTypes.includes(f.type))
    if (matchingFindings.length === 0) continue

    priority++
    const worstSeverity = matchingFindings.reduce((worst, f) =>
      severityOrder[f.severity] < severityOrder[worst] ? f.severity : worst
    , 'INFO' as SastSeverity)

    items.push({
      priority,
      title: theme.title,
      description: theme.description,
      effort: theme.effort,
      impact: worstSeverity === 'CRITICAL' ? 'CRITICAL' :
        worstSeverity === 'HIGH' ? 'HIGH' :
          worstSeverity === 'MEDIUM' ? 'MEDIUM' : 'LOW',
      affectedFindingIds: matchingFindings.map(f => f.id),
      estimatedHours: theme.estimatedHours,
    })
  }

  return items
}
