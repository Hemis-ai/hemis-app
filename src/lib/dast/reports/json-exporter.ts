import type { ReportData } from './html-template'

/**
 * JSON export with structured metadata.
 * Suitable for API integrations, SIEM imports, and programmatic consumption.
 */
export function generateJsonReport(data: ReportData): string {
  const output = {
    meta: {
      generatedAt: data.generatedAt,
      generatedBy: 'HemisX DAST',
      version: '1.0.0',
      format: 'hemisx-dast-report-v1',
    },
    scan: {
      id: data.scan.id,
      name: data.scan.name,
      targetUrl: data.scan.targetUrl,
      profile: data.scan.scanProfile,
      startedAt: data.scan.startedAt,
      completedAt: data.scan.completedAt,
      durationMs:
        data.scan.startedAt && data.scan.completedAt
          ? new Date(data.scan.completedAt).getTime() - new Date(data.scan.startedAt).getTime()
          : null,
      endpointsDiscovered: data.scan.endpointsDiscovered,
      endpointsTested: data.scan.endpointsTested,
      payloadsSent: data.scan.payloadsSent,
      riskScore: data.scan.riskScore,
      techStack: data.scan.techStackDetected,
    },
    summary: {
      counts: data.counts,
      executiveSummary: data.executiveSummary,
    },
    findings: data.findings.map((f, i) => ({
      index: i + 1,
      title: f.title,
      severity: f.severity,
      cvss: {
        score: f.cvssScore,
        vector: f.cvssVector,
      },
      classification: {
        owasp: f.owaspCategory,
        cwe: f.cweId,
        mitre: f.mitreAttackIds,
      },
      location: {
        url: f.affectedUrl,
        parameter: f.affectedParameter,
      },
      description: f.description,
      businessImpact: f.businessImpact,
      remediation: f.remediation,
      remediationCode: f.remediationCode ? (() => { try { return JSON.parse(f.remediationCode!) } catch { return null } })() : null,
      compliance: {
        pciDss: f.pciDssRefs,
        soc2: f.soc2Refs,
      },
      confidence: f.confidenceScore,
    })),
  }

  return JSON.stringify(output, null, 2)
}
