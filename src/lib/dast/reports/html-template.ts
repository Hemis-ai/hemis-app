/**
 * HemisX DAST Report — HTML template for PDF rendering.
 * Adapted from hemisx-dast/src/reports/html.template.ts
 */

export interface ReportData {
  scan: {
    id: string
    name: string
    targetUrl: string
    scanProfile: string
    startedAt: string | null
    completedAt: string | null
    endpointsDiscovered: number
    endpointsTested: number
    payloadsSent: number
    riskScore: number
    techStackDetected: string[]
  }
  counts: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
    total: number
  }
  executiveSummary: string | null
  findings: Array<{
    title: string
    severity: string
    cvssScore: number | null
    cvssVector: string | null
    owaspCategory: string
    cweId: string | null
    affectedUrl: string
    affectedParameter: string | null
    description: string
    businessImpact: string | null
    remediation: string
    remediationCode: string | null
    pciDssRefs: string[]
    soc2Refs: string[]
    mitreAttackIds: string[]
    confidenceScore: number
  }>
  generatedAt: string
  orgId: string
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff4d6a',
  HIGH: '#ff8c42',
  MEDIUM: '#ffc857',
  LOW: '#4ecdc4',
  INFO: '#6c8eef',
}

function severityBadge(severity: string): string {
  const color = SEVERITY_COLORS[severity] ?? '#8e8ea0'
  return `<span style="display:inline-block;padding:2px 10px;border-radius:4px;background:${color};color:#0f0f1a;font-weight:700;font-size:11px;letter-spacing:0.5px;">${severity}</span>`
}

function riskGauge(score: number): string {
  let color = '#4ecdc4'
  let label = 'Low Risk'
  if (score >= 75) { color = '#ff4d6a'; label = 'Critical Risk' }
  else if (score >= 50) { color = '#ff8c42'; label = 'High Risk' }
  else if (score >= 25) { color = '#ffc857'; label = 'Medium Risk' }

  return `
    <div style="text-align:center;margin:20px 0;">
      <div style="font-size:64px;font-weight:800;color:${color};">${score}</div>
      <div style="font-size:14px;color:${color};font-weight:600;">${label}</div>
      <div style="width:200px;height:8px;background:#2a2a3e;border-radius:4px;margin:10px auto;">
        <div style="width:${score}%;height:100%;background:${color};border-radius:4px;"></div>
      </div>
    </div>`
}

function severityChart(counts: ReportData['counts']): string {
  const entries = [
    { label: 'Critical', count: counts.critical, color: '#ff4d6a' },
    { label: 'High', count: counts.high, color: '#ff8c42' },
    { label: 'Medium', count: counts.medium, color: '#ffc857' },
    { label: 'Low', count: counts.low, color: '#4ecdc4' },
    { label: 'Info', count: counts.info, color: '#6c8eef' },
  ]
  const max = Math.max(...entries.map((e) => e.count), 1)

  return entries
    .map(
      (e) => `
    <div style="display:flex;align-items:center;margin:6px 0;">
      <div style="width:70px;font-size:12px;color:#8e8ea0;">${e.label}</div>
      <div style="flex:1;height:20px;background:#2a2a3e;border-radius:4px;overflow:hidden;margin:0 10px;">
        <div style="width:${(e.count / max) * 100}%;height:100%;background:${e.color};border-radius:4px;"></div>
      </div>
      <div style="width:30px;text-align:right;font-weight:700;color:${e.color};">${e.count}</div>
    </div>`,
    )
    .join('')
}

function complianceSection(finding: ReportData['findings'][0]): string {
  const refs: string[] = []
  if (finding.pciDssRefs.length) refs.push(`<strong>PCI-DSS:</strong> ${finding.pciDssRefs.join(', ')}`)
  if (finding.soc2Refs.length) refs.push(`<strong>SOC 2:</strong> ${finding.soc2Refs.join(', ')}`)
  if (finding.mitreAttackIds.length) refs.push(`<strong>MITRE ATT&CK:</strong> ${finding.mitreAttackIds.join(', ')}`)
  if (finding.cweId) refs.push(`<strong>CWE:</strong> ${finding.cweId}`)
  if (!refs.length) return ''
  return `<div style="margin-top:8px;padding:8px 12px;background:#1e1e30;border-radius:4px;font-size:11px;color:#8e8ea0;">${refs.join(' &nbsp;|&nbsp; ')}</div>`
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function findingCard(finding: ReportData['findings'][0], index: number): string {
  let remediationCodeBlock = ''
  if (finding.remediationCode) {
    try {
      const rc = JSON.parse(finding.remediationCode)
      remediationCodeBlock = `
        <div style="margin-top:12px;">
          <div style="font-size:11px;color:#8e8ea0;margin-bottom:4px;">Vulnerable Code:</div>
          <pre style="background:#12121f;padding:10px;border-radius:4px;font-size:11px;color:#ff4d6a;overflow-x:auto;white-space:pre-wrap;">${escapeHtml(rc.vulnerableCode)}</pre>
          <div style="font-size:11px;color:#8e8ea0;margin:8px 0 4px;">Remediated Code:</div>
          <pre style="background:#12121f;padding:10px;border-radius:4px;font-size:11px;color:#4ecdc4;overflow-x:auto;white-space:pre-wrap;">${escapeHtml(rc.remediatedCode)}</pre>
          <div style="font-size:11px;color:#8e8ea0;margin-top:6px;">${escapeHtml(rc.explanation)}</div>
        </div>`
    } catch {
      // Invalid JSON — skip code block
    }
  }

  return `
    <div style="background:#1a1a2e;border-radius:8px;padding:16px 20px;margin-bottom:16px;border-left:4px solid ${SEVERITY_COLORS[finding.severity] ?? '#8e8ea0'};page-break-inside:avoid;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-size:14px;font-weight:700;color:#e0e0e0;">${index + 1}. ${escapeHtml(finding.title)}</div>
        ${severityBadge(finding.severity)}
      </div>
      <div style="font-size:11px;color:#8e8ea0;margin-bottom:8px;">
        ${finding.cvssScore ? `CVSS ${finding.cvssScore}` : ''} &nbsp;|&nbsp; ${escapeHtml(finding.owaspCategory)} &nbsp;|&nbsp; Confidence: ${finding.confidenceScore}%
      </div>
      <div style="font-size:11px;color:#a259ff;margin-bottom:10px;word-break:break-all;">${escapeHtml(finding.affectedUrl)}${finding.affectedParameter ? ` → <strong>${escapeHtml(finding.affectedParameter)}</strong>` : ''}</div>
      <div style="font-size:12px;color:#c0c0d0;margin-bottom:10px;">${escapeHtml(finding.description).substring(0, 500)}</div>
      ${finding.businessImpact ? `<div style="font-size:12px;color:#ffc857;margin-bottom:10px;"><strong>Business Impact:</strong> ${escapeHtml(finding.businessImpact).substring(0, 400)}</div>` : ''}
      <div style="font-size:12px;color:#4ecdc4;"><strong>Remediation:</strong> ${escapeHtml(finding.remediation).substring(0, 400)}</div>
      ${remediationCodeBlock}
      ${complianceSection(finding)}
    </div>`
}

export function renderReport(data: ReportData): string {
  const scanDuration =
    data.scan.startedAt && data.scan.completedAt
      ? `${Math.round((new Date(data.scan.completedAt).getTime() - new Date(data.scan.startedAt).getTime()) / 60000)} min`
      : 'N/A'

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0f0f1a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; line-height: 1.6; }
    .page { padding: 40px 50px; }
    @media print { .page-break { page-break-before: always; } }
  </style>
</head>
<body>

<!-- Cover Page -->
<div class="page" style="min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;">
  <div style="font-size:16px;letter-spacing:4px;color:#a259ff;font-weight:600;margin-bottom:20px;">HEMISX</div>
  <div style="font-size:36px;font-weight:800;color:#e0e0e0;margin-bottom:10px;">DAST Security Assessment</div>
  <div style="font-size:18px;color:#8e8ea0;margin-bottom:40px;">${escapeHtml(data.scan.targetUrl)}</div>
  ${riskGauge(data.scan.riskScore)}
  <div style="margin-top:40px;font-size:12px;color:#8e8ea0;">
    <div>Scan: ${escapeHtml(data.scan.name)} (${escapeHtml(data.scan.scanProfile)})</div>
    <div>Duration: ${scanDuration} &nbsp;|&nbsp; Generated: ${new Date(data.generatedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</div>
  </div>
</div>

<!-- Executive Summary -->
<div class="page page-break">
  <div style="font-size:22px;font-weight:700;color:#a259ff;margin-bottom:20px;border-bottom:2px solid #a259ff;padding-bottom:8px;">Executive Summary</div>

  <div style="display:flex;gap:12px;margin-bottom:24px;">
    ${[
      { label: 'Critical', count: data.counts.critical, color: '#ff4d6a' },
      { label: 'High', count: data.counts.high, color: '#ff8c42' },
      { label: 'Medium', count: data.counts.medium, color: '#ffc857' },
      { label: 'Low', count: data.counts.low, color: '#4ecdc4' },
      { label: 'Info', count: data.counts.info, color: '#6c8eef' },
    ]
      .map(
        (e) => `<div style="flex:1;background:#1a1a2e;border-radius:8px;padding:14px;text-align:center;border-top:3px solid ${e.color};">
          <div style="font-size:28px;font-weight:800;color:${e.color};">${e.count}</div>
          <div style="font-size:11px;color:#8e8ea0;">${e.label}</div>
        </div>`,
      )
      .join('')}
  </div>

  <div style="background:#1a1a2e;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
    <div style="font-size:13px;font-weight:600;color:#e0e0e0;margin-bottom:10px;">Severity Distribution</div>
    ${severityChart(data.counts)}
  </div>

  <div style="display:flex;gap:12px;margin-bottom:24px;">
    ${[
      { label: 'Endpoints Discovered', value: data.scan.endpointsDiscovered },
      { label: 'Endpoints Tested', value: data.scan.endpointsTested },
      { label: 'Payloads Sent', value: data.scan.payloadsSent },
      { label: 'Total Findings', value: data.counts.total },
    ]
      .map(
        (m) => `<div style="flex:1;background:#1a1a2e;border-radius:8px;padding:14px;text-align:center;">
          <div style="font-size:24px;font-weight:700;color:#a259ff;">${m.value}</div>
          <div style="font-size:11px;color:#8e8ea0;">${m.label}</div>
        </div>`,
      )
      .join('')}
  </div>

  ${data.scan.techStackDetected.length ? `<div style="background:#1a1a2e;border-radius:8px;padding:12px 16px;margin-bottom:24px;font-size:12px;color:#8e8ea0;"><strong style="color:#e0e0e0;">Detected Technology:</strong> ${data.scan.techStackDetected.map((t) => escapeHtml(t)).join(', ')}</div>` : ''}

  ${data.executiveSummary ? `<div style="background:#1a1a2e;border-radius:8px;padding:20px;font-size:13px;color:#c0c0d0;line-height:1.8;">${escapeHtml(data.executiveSummary)}</div>` : ''}
</div>

<!-- Detailed Findings -->
<div class="page page-break">
  <div style="font-size:22px;font-weight:700;color:#a259ff;margin-bottom:20px;border-bottom:2px solid #a259ff;padding-bottom:8px;">Detailed Findings (${data.counts.total})</div>
  ${data.findings.map((f, i) => findingCard(f, i)).join('')}
</div>

<!-- Footer -->
<div class="page" style="margin-top:40px;text-align:center;font-size:11px;color:#8e8ea0;border-top:1px solid #2a2a3e;padding-top:16px;">
  Generated by HemisX DAST &nbsp;|&nbsp; ${new Date(data.generatedAt).toISOString()} &nbsp;|&nbsp; Confidential
</div>

</body>
</html>`
}
