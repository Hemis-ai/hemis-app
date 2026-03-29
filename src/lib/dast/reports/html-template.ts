/**
 * HemisX DAST Report — HTML template for PDF rendering.
 * Adapted from hemisx-dast/src/reports/html.template.ts
 */

export interface ReportFinding {
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
}

export interface OwaspHeatmapEntry {
  categoryId: string
  categoryName: string
  findingCount: number
  highestSeverity: string
  weightedScore: number
}

export interface CvssDistEntry { rangeLabel: string; count: number }
export interface AttackSurfaceEntry { url: string; path: string; findingCount: number; highestSeverity: string }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface AttackChainData { attackChains?: any[]; duplicateGroups?: any[]; riskAmplifiers?: any[]; overallChainedRiskScore?: number }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface ComplianceData { frameworks?: any[]; highestRiskFramework?: string; complianceScore?: number; auditReadiness?: string; keyGaps?: string[] }

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
  findings: ReportFinding[]
  // Rich data matching the history tab
  owaspHeatmap?: OwaspHeatmapEntry[]
  cvssDistribution?: CvssDistEntry[]
  attackSurface?: AttackSurfaceEntry[]
  attackChainData?: AttackChainData | null
  complianceData?: ComplianceData | null
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

  // Risk gauge + grade calculations
  const risk = data.scan.riskScore
  const riskC = risk < 25 ? '#4ecdc4' : risk < 50 ? '#ffc857' : risk < 75 ? '#ff8c42' : '#ff4d6a'
  const riskLabel = risk < 25 ? 'Low Risk' : risk < 50 ? 'Medium Risk' : risk < 75 ? 'High Risk' : 'Critical Risk'
  const gradeThresholds = [{ max: 20, g: 'A', c: '#4ecdc4', l: 'EXCELLENT' },{ max: 40, g: 'B', c: '#84cc16', l: 'GOOD' },{ max: 60, g: 'C', c: '#ffc857', l: 'FAIR' },{ max: 80, g: 'D', c: '#ff8c42', l: 'POOR' },{ max: 101, g: 'F', c: '#ff4d6a', l: 'CRITICAL' }]
  const grade = gradeThresholds.find(t => risk < t.max) || gradeThresholds[4]

  // Severity donut SVG
  const total = data.counts.total || 1
  const sevEntries: [string, number][] = [['CRITICAL', data.counts.critical],['HIGH', data.counts.high],['MEDIUM', data.counts.medium],['LOW', data.counts.low],['INFO', data.counts.info]]
  const donutR = 38, donutCx = 50, donutCy = 50, donutCirc = 2 * Math.PI * donutR
  let donutOffset = 0
  const donutParts = sevEntries.map(([sev, count]) => {
    const pct = count / total
    const dash = pct * donutCirc
    const svg = `<circle cx="${donutCx}" cy="${donutCy}" r="${donutR}" fill="none" stroke="${SEVERITY_COLORS[sev]}" stroke-width="12" stroke-dasharray="${dash} ${donutCirc - dash}" stroke-dashoffset="${-donutOffset}" transform="rotate(-90 50 50)"/>`
    donutOffset += dash
    return svg
  }).join('')

  // Breach cost estimate
  const breachCost = data.findings.reduce((sum, f) => sum + (f.cvssScore || 0) * 52000, 0)
  const breachStr = breachCost >= 1000000 ? `$${(breachCost / 1000000).toFixed(1)}M` : breachCost >= 1000 ? `$${(breachCost / 1000).toFixed(0)}K` : `$${breachCost.toFixed(0)}`
  const breachColor = breachCost > 500000 ? '#ff4d6a' : breachCost > 100000 ? '#ff8c42' : '#4ecdc4'

  // OWASP grid data
  const OWASP_CATS = [
    { id: 'A01:2021', name: 'Broken Access Control', short: 'A01' },
    { id: 'A02:2021', name: 'Cryptographic Failures', short: 'A02' },
    { id: 'A03:2021', name: 'Injection', short: 'A03' },
    { id: 'A04:2021', name: 'Insecure Design', short: 'A04' },
    { id: 'A05:2021', name: 'Security Misconfiguration', short: 'A05' },
    { id: 'A06:2021', name: 'Vulnerable Components', short: 'A06' },
    { id: 'A07:2021', name: 'Auth Failures', short: 'A07' },
    { id: 'A08:2021', name: 'Data Integrity Failures', short: 'A08' },
    { id: 'A09:2021', name: 'Logging Failures', short: 'A09' },
    { id: 'A10:2021', name: 'SSRF', short: 'A10' },
  ]
  const owaspGrid: Record<string, { total: number; weight: number; highest: string }> = {}
  for (const cat of OWASP_CATS) owaspGrid[cat.id] = { total: 0, weight: 0, highest: 'INFO' }
  const SW: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0.5 }
  for (const f of data.findings) {
    const cat = f.owaspCategory
    if (owaspGrid[cat]) {
      owaspGrid[cat].total++
      owaspGrid[cat].weight += SW[f.severity] || 0
      const sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
      if (sevOrder.indexOf(f.severity) < sevOrder.indexOf(owaspGrid[cat].highest)) owaspGrid[cat].highest = f.severity
    }
  }
  const maxOWeight = Math.max(...Object.values(owaspGrid).map(c => c.weight), 1)
  const heatColorFn = (w: number, h: string) => {
    if (w === 0) return '#1e1e30'
    const int = Math.min(w / maxOWeight, 1)
    const base = h === 'CRITICAL' ? [239,68,68] : h === 'HIGH' ? [249,115,22] : h === 'MEDIUM' ? [234,179,8] : [59,130,246]
    return `rgba(${base[0]},${base[1]},${base[2]},${(0.15 + int * 0.55).toFixed(2)})`
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0f0f1a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; line-height: 1.6; }
    .page { padding: 40px 50px; }
    .section-title { font-size:22px;font-weight:700;color:#a259ff;margin-bottom:20px;border-bottom:2px solid #a259ff;padding-bottom:8px; }
    .card { background:#1a1a2e;border-radius:8px; }
    @media print { .page-break { page-break-before: always; } .page { padding: 20px 30px; } }
  </style>
</head>
<body>

<!-- Cover Page -->
<div class="page" style="min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;">
  <div style="font-size:16px;letter-spacing:4px;color:#a259ff;font-weight:600;margin-bottom:20px;">HEMISX</div>
  <div style="font-size:36px;font-weight:800;color:#e0e0e0;margin-bottom:10px;">DAST Security Assessment</div>
  <div style="font-size:18px;color:#8e8ea0;margin-bottom:40px;">${escapeHtml(data.scan.targetUrl)}</div>
  <div style="text-align:center;margin:20px 0;">
    <svg viewBox="0 0 120 80" width="180" height="120">
      <path d="M 10 70 A 50 50 0 0 1 110 70" fill="none" stroke="#2a2a3e" stroke-width="8" stroke-linecap="round"/>
      <path d="M 10 70 A 50 50 0 0 1 110 70" fill="none" stroke="${riskC}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${(risk / 100) * 157} 157"/>
      <text x="60" y="55" text-anchor="middle" font-size="24" font-weight="800" fill="${riskC}" font-family="monospace">${risk}</text>
      <text x="60" y="72" text-anchor="middle" font-size="9" fill="#8e8ea0" font-family="monospace">/ 100</text>
    </svg>
    <div style="font-size:14px;color:${riskC};font-weight:600;margin-top:8px;">${riskLabel}</div>
  </div>
  <div style="margin-top:40px;font-size:12px;color:#8e8ea0;">
    <div>Scan: ${escapeHtml(data.scan.name)} (${escapeHtml(data.scan.scanProfile)})</div>
    <div>Duration: ${scanDuration} &nbsp;|&nbsp; Generated: ${new Date(data.generatedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</div>
  </div>
</div>

<!-- Security Posture Overview -->
<div class="page page-break">
  <div class="section-title">Security Posture Overview</div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px;margin-bottom:24px;">
    <!-- Risk Score Gauge -->
    <div class="card" style="padding:20px;text-align:center;">
      <div style="font-size:10px;letter-spacing:0.12em;color:#8e8ea0;margin-bottom:12px;font-family:monospace;">RISK SCORE</div>
      <svg viewBox="0 0 120 80" width="120" height="80" style="display:block;margin:0 auto;">
        <path d="M 10 70 A 50 50 0 0 1 110 70" fill="none" stroke="#2a2a3e" stroke-width="8" stroke-linecap="round"/>
        <path d="M 10 70 A 50 50 0 0 1 110 70" fill="none" stroke="${riskC}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${(risk / 100) * 157} 157"/>
        <text x="60" y="55" text-anchor="middle" font-size="24" font-weight="800" fill="${riskC}" font-family="monospace">${risk}</text>
        <text x="60" y="72" text-anchor="middle" font-size="9" fill="#8e8ea0" font-family="monospace">/ 100</text>
      </svg>
    </div>
    <!-- Security Grade -->
    <div class="card" style="padding:20px;text-align:center;">
      <div style="font-size:10px;letter-spacing:0.12em;color:#8e8ea0;margin-bottom:12px;font-family:monospace;">SECURITY GRADE</div>
      <div style="width:64px;height:64px;border-radius:50%;margin:0 auto;display:flex;align-items:center;justify-content:center;border:3px solid ${grade.c};background:${grade.c}15;">
        <span style="font-size:32px;font-weight:900;color:${grade.c};font-family:monospace;">${grade.g}</span>
      </div>
      <div style="font-size:10px;color:${grade.c};margin-top:8px;letter-spacing:0.1em;font-family:monospace;">${grade.l}</div>
    </div>
    <!-- Severity Donut -->
    <div class="card" style="padding:20px;text-align:center;">
      <div style="font-size:10px;letter-spacing:0.12em;color:#8e8ea0;margin-bottom:12px;font-family:monospace;">SEVERITY BREAKDOWN</div>
      <svg viewBox="0 0 100 100" width="80" height="80" style="display:block;margin:0 auto;">
        ${donutParts}
        <text x="50" y="48" text-anchor="middle" font-size="18" font-weight="800" fill="#e0e0e0" font-family="monospace">${total}</text>
        <text x="50" y="60" text-anchor="middle" font-size="8" fill="#8e8ea0" font-family="monospace">FINDINGS</text>
      </svg>
      <div style="display:flex;justify-content:center;gap:8px;margin-top:8px;flex-wrap:wrap;">
        ${sevEntries.filter(([, c]) => c > 0).map(([sev, count]) =>
          `<span style="font-size:9px;padding:1px 5px;border-radius:3px;color:${SEVERITY_COLORS[sev]};border:1px solid ${SEVERITY_COLORS[sev]}40;font-family:monospace;">${count} ${sev[0]}</span>`
        ).join('')}
      </div>
    </div>
    <!-- Breach Exposure -->
    <div class="card" style="padding:20px;text-align:center;">
      <div style="font-size:10px;letter-spacing:0.12em;color:#8e8ea0;margin-bottom:12px;font-family:monospace;">EST. BREACH EXPOSURE</div>
      <div style="font-size:28px;font-weight:800;color:${breachColor};font-family:monospace;margin-top:20px;">${breachStr}</div>
      <div style="font-size:9px;color:#8e8ea0;margin-top:8px;font-family:monospace;">BASED ON CVSS SEVERITY</div>
    </div>
  </div>

  <!-- Severity Count Cards -->
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

<!-- OWASP Top 10 Grid -->
<div class="page page-break">
  <div class="section-title">OWASP Top 10 Coverage</div>
  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:24px;">
    ${OWASP_CATS.map(cat => {
      const d = owaspGrid[cat.id]
      return `<div style="padding:12px 10px;border-radius:6px;text-align:center;background:${heatColorFn(d.weight, d.highest)};border:1px solid #2a2a3e;">
        <div style="font-size:11px;font-weight:700;color:#e0e0e0;margin-bottom:2px;font-family:monospace;">${cat.short}</div>
        <div style="font-size:8px;color:#8e8ea0;line-height:1.2;margin-bottom:4px;">${cat.name}</div>
        <div style="font-size:16px;font-weight:800;color:${d.total > 0 ? '#e0e0e0' : '#8e8ea0'};font-family:monospace;">${d.total}</div>
      </div>`
    }).join('')}
  </div>
</div>

<!-- CVSS Distribution -->
${data.cvssDistribution && data.cvssDistribution.length > 0 ? `
<div class="page">
  <div style="font-size:18px;font-weight:700;color:#a259ff;margin:24px 0 16px;">CVSS Score Distribution</div>
  <div style="background:#1a1a2e;border-radius:8px;padding:16px 20px;">
    ${data.cvssDistribution.map(d => {
      const color = d.rangeLabel.startsWith('9') ? '#ff4d6a' : d.rangeLabel.startsWith('7') ? '#ff8c42' : d.rangeLabel.startsWith('4') ? '#ffc857' : d.rangeLabel.startsWith('0') ? '#4ecdc4' : '#6c8eef'
      const max = Math.max(...(data.cvssDistribution ?? []).map(x => x.count), 1)
      return `<div style="display:flex;align-items:center;margin:6px 0;">
        <div style="width:90px;font-size:12px;color:#8e8ea0;">${d.rangeLabel}</div>
        <div style="flex:1;height:20px;background:#2a2a3e;border-radius:4px;overflow:hidden;margin:0 10px;">
          <div style="width:${(d.count / max) * 100}%;height:100%;background:${color};border-radius:4px;"></div>
        </div>
        <div style="width:30px;text-align:right;font-weight:700;color:${color};">${d.count}</div>
      </div>`
    }).join('')}
  </div>
</div>` : ''}

<!-- Attack Surface Map -->
${data.attackSurface && data.attackSurface.length > 0 ? `
<div class="page">
  <div style="font-size:18px;font-weight:700;color:#a259ff;margin:24px 0 16px;">Attack Surface — Most Affected Endpoints</div>
  <div style="background:#1a1a2e;border-radius:8px;padding:16px 20px;">
    ${data.attackSurface.slice(0, 15).map(e => `
      <div style="display:flex;align-items:center;margin:6px 0;gap:10px;">
        <div style="width:20px;text-align:center;">${severityBadge(e.highestSeverity)}</div>
        <div style="flex:1;font-size:11px;color:#a259ff;word-break:break-all;">${escapeHtml(e.path)}</div>
        <div style="font-size:12px;font-weight:700;color:#e0e0e0;">${e.findingCount} finding${e.findingCount !== 1 ? 's' : ''}</div>
      </div>
    `).join('')}
  </div>
</div>` : ''}

<!-- Attack Chains (AI) -->
${data.attackChainData?.attackChains?.length ? `
<div class="page page-break">
  <div style="font-size:22px;font-weight:700;color:#a259ff;margin-bottom:20px;border-bottom:2px solid #a259ff;padding-bottom:8px;">Attack Chains</div>
  ${data.attackChainData.overallChainedRiskScore != null ? `
    <div style="background:#1a1a2e;border-radius:8px;padding:14px 18px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;">
      <div><div style="font-size:11px;color:#8e8ea0;letter-spacing:1px;">CHAINED RISK SCORE</div><div style="font-size:11px;color:#c0c0d0;margin-top:2px;">Combined risk considering attack chain amplification</div></div>
      <div style="font-size:32px;font-weight:800;color:${data.attackChainData.overallChainedRiskScore >= 75 ? '#ff4d6a' : data.attackChainData.overallChainedRiskScore >= 50 ? '#ff8c42' : '#ffc857'};">${data.attackChainData.overallChainedRiskScore}</div>
    </div>` : ''}
  ${data.attackChainData.attackChains.map((chain: { name: string; description: string; severity: string; exploitationSteps?: string[]; businessImpact?: string; likelihoodOfExploitation?: string }) => `
    <div style="background:#1a1a2e;border-radius:8px;padding:16px 20px;margin-bottom:12px;border-left:4px solid ${SEVERITY_COLORS[chain.severity] ?? '#8e8ea0'};">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-size:14px;font-weight:700;color:#e0e0e0;">${escapeHtml(chain.name)}</div>
        ${severityBadge(chain.severity)}
      </div>
      <div style="font-size:12px;color:#c0c0d0;margin-bottom:10px;">${escapeHtml(chain.description)}</div>
      ${chain.exploitationSteps?.length ? `
        <div style="font-size:10px;color:#8e8ea0;letter-spacing:1px;margin-bottom:4px;">EXPLOITATION PATH</div>
        <div style="background:#12121f;padding:10px;border-radius:4px;margin-bottom:8px;">
          ${chain.exploitationSteps.map((s: string, i: number) => `<div style="font-size:11px;color:#c0c0d0;margin-bottom:4px;"><span style="color:#a259ff;font-weight:700;">${i + 1}.</span> ${escapeHtml(s)}</div>`).join('')}
        </div>` : ''}
      ${chain.businessImpact ? `<div style="font-size:11px;color:#ffc857;font-style:italic;background:#1e1e30;padding:8px 10px;border-radius:4px;">${escapeHtml(chain.businessImpact)}</div>` : ''}
    </div>
  `).join('')}
</div>` : ''}

<!-- Compliance Overview (AI) -->
${data.complianceData?.frameworks?.length ? `
<div class="page page-break">
  <div style="font-size:22px;font-weight:700;color:#a259ff;margin-bottom:20px;border-bottom:2px solid #a259ff;padding-bottom:8px;">Compliance Overview</div>
  <div style="display:flex;gap:12px;margin-bottom:20px;">
    ${data.complianceData.complianceScore != null ? `<div style="flex:1;background:#1a1a2e;border-radius:8px;padding:14px;text-align:center;">
      <div style="font-size:28px;font-weight:800;color:${(data.complianceData.complianceScore ?? 0) >= 80 ? '#4ecdc4' : (data.complianceData.complianceScore ?? 0) >= 50 ? '#ffc857' : '#ff4d6a'};">${data.complianceData.complianceScore}%</div>
      <div style="font-size:11px;color:#8e8ea0;">Compliance Score</div>
    </div>` : ''}
    ${data.complianceData.auditReadiness ? `<div style="flex:1;background:#1a1a2e;border-radius:8px;padding:14px;text-align:center;">
      <div style="font-size:16px;font-weight:700;color:#e0e0e0;">${escapeHtml(data.complianceData.auditReadiness)}</div>
      <div style="font-size:11px;color:#8e8ea0;">Audit Readiness</div>
    </div>` : ''}
    ${data.complianceData.highestRiskFramework ? `<div style="flex:1;background:#1a1a2e;border-radius:8px;padding:14px;text-align:center;">
      <div style="font-size:16px;font-weight:700;color:#ff8c42;">${escapeHtml(data.complianceData.highestRiskFramework)}</div>
      <div style="font-size:11px;color:#8e8ea0;">Highest Risk Framework</div>
    </div>` : ''}
  </div>
  ${data.complianceData.frameworks.map((fw: { name: string; overallStatus: string; controlsAffected: number; totalControlsChecked: number }) => `
    <div style="background:#1a1a2e;border-radius:8px;padding:14px 18px;margin-bottom:10px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div style="font-size:14px;font-weight:600;color:#e0e0e0;">${escapeHtml(fw.name)}</div>
        <div style="font-size:11px;color:#8e8ea0;">${fw.controlsAffected}/${fw.totalControlsChecked} Controls Affected</div>
      </div>
    </div>
  `).join('')}
  ${data.complianceData.keyGaps?.length ? `
    <div style="margin-top:16px;">
      <div style="font-size:13px;font-weight:600;color:#e0e0e0;margin-bottom:8px;">Key Compliance Gaps</div>
      ${data.complianceData.keyGaps.map((g: string, i: number) => `<div style="font-size:12px;color:#ff8c42;margin-bottom:4px;">${i + 1}. ${escapeHtml(g)}</div>`).join('')}
    </div>` : ''}
</div>` : ''}

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
