'use client'

import { useState, useRef, useEffect, useCallback, lazy, Suspense } from 'react'
import type { Severity, DastScan, DastFinding, DastScanProgress } from '@/lib/types'
import PostureCard from '@/components/dast/PostureCard'
import OWASPHeatmap from '@/components/dast/OWASPHeatmap'
import AttackSurfaceMap from '@/components/dast/AttackSurfaceMap'
import CVSSDistribution from '@/components/dast/CVSSDistribution'
import MitreAttackMatrix from '@/components/dast/MitreAttackMatrix'
import RemediationTab from '@/components/dast/RemediationTab'
import MonitoringTab from '@/components/dast/MonitoringTab'
import IntegrationsTab from '@/components/dast/IntegrationsTab'

const AttackGraph3D = lazy(() => import('@/components/dast/AttackGraph3D'))

// ─── Constants ──────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

const PROFILE_ESTIMATES: Record<string, string> = {
  quick: '~2\u20135 min',
  full: '~10\u201320 min',
  api_only: '~5\u201310 min',
  deep: '~30\u201360 min',
}

function formatEta(seconds?: number | null): string {
  if (!seconds || seconds <= 0) return '\u2014'
  if (seconds < 60) return `${Math.round(seconds)}s`
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
}
const PHASE_LABELS: Record<string, string> = {
  initializing: 'Initializing',
  crawling: 'Crawling Endpoints',
  auth_testing: 'Auth & Session Testing',
  scanning: 'Active Scanning',
  extracting: 'Extracting Alerts',
  analyzing: 'AI Analysis',
  summarizing: 'Generating Summary',
  complete: 'Complete',
  failed: 'Failed',
}

type TopTab = 'scanner' | 'history' | 'attack-chains' | 'attack-map' | 'compliance' | 'remediation' | 'monitoring' | 'integrations' | 'compare' | 'report'
type AuthType = 'none' | 'bearer' | 'apikey' | 'oauth2' | 'cookie' | 'header' | 'form'

// ─── Markdown Renderer ──────────────────────────────────────────────────────

function renderMarkdown(md: string) {
  const lines = md.split('\n')
  const elements: React.ReactNode[] = []
  let inList = false
  let listItems: React.ReactNode[] = []

  const flushList = () => {
    if (listItems.length > 0) {
      elements.push(<ul key={`ul-${elements.length}`} style={{ paddingLeft: 18, marginBottom: 10 }}>{listItems}</ul>)
      listItems = []
      inList = false
    }
  }

  lines.forEach((line, i) => {
    const trimmed = line.trim()
    if (trimmed.startsWith('## ')) {
      flushList()
      elements.push(
        <h3 key={`h-${i}`} style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-dast)', marginTop: 16, marginBottom: 6, letterSpacing: '0.02em' }}>
          {trimmed.replace('## ', '')}
        </h3>
      )
    } else if (trimmed.startsWith('- ')) {
      inList = true
      const text = trimmed.replace(/^- /, '')
      const boldMatch = text.match(/^\*\*(.+?)\*\*(.*)$/)
      listItems.push(
        <li key={`li-${i}`} style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 2 }}>
          {boldMatch ? <><strong style={{ color: 'var(--color-text-primary)' }}>{boldMatch[1]}</strong>{boldMatch[2]}</> : text}
        </li>
      )
    } else if (trimmed === '') {
      flushList()
    } else {
      flushList()
      const rendered = trimmed.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
      elements.push(
        <p key={`p-${i}`} style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 8 }} dangerouslySetInnerHTML={{ __html: rendered }} />
      )
    }
  })
  flushList()
  return elements
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function DastPage() {
  const [activeTab, setActiveTab] = useState<TopTab>('scanner')
  const [scans, setScans] = useState<DastScan[]>([])
  const [selectedScan, setSelectedScan] = useState<DastScan | null>(null)
  const [findings, setFindings] = useState<DastFinding[]>([])
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<DastFinding | null>(null)

  // ── Scan form state ──
  const [newScanName, setNewScanName] = useState('')
  const [newScanUrl, setNewScanUrl] = useState('')
  const [newScanProfile, setNewScanProfile] = useState<'full' | 'quick' | 'api_only' | 'deep'>('full')

  // ── Advanced config state ──
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [authType, setAuthType] = useState<AuthType>('none')
  const [authBearerToken, setAuthBearerToken] = useState('')
  const [authApiKey, setAuthApiKey] = useState('')
  const [authApiKeyHeader, setAuthApiKeyHeader] = useState('X-API-Key')
  const [authOauth2TokenUrl, setAuthOauth2TokenUrl] = useState('')
  const [authOauth2ClientId, setAuthOauth2ClientId] = useState('')
  const [authOauth2ClientSecret, setAuthOauth2ClientSecret] = useState('')
  const [authOauth2Scope, setAuthOauth2Scope] = useState('')
  const [authCookieValue, setAuthCookieValue] = useState('')
  const [authHeaderName, setAuthHeaderName] = useState('')
  const [authHeaderValue, setAuthHeaderValue] = useState('')
  const [authFormLoginUrl, setAuthFormLoginUrl] = useState('')
  const [authFormUsername, setAuthFormUsername] = useState('')
  const [authFormPassword, setAuthFormPassword] = useState('')
  const [authFormUsernameField, setAuthFormUsernameField] = useState('username')
  const [authFormPasswordField, setAuthFormPasswordField] = useState('password')
  const [scopeInclude, setScopeInclude] = useState('')
  const [scopeExclude, setScopeExclude] = useState('')

  // ── Comparison state ──
  const [compBaselineId, setCompBaselineId] = useState<string>('')
  const [compCurrentId, setCompCurrentId] = useState<string>('')
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [compResult, setCompResult] = useState<any>(null)
  const [compLoading, setCompLoading] = useState(false)

  // ── Scan progress state ──
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState<DastScanProgress | null>(null)
  const progressRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // ── Report state ──
  const [reportScanId, setReportScanId] = useState<string>('')
  const [reportFormat, setReportFormat] = useState<'pdf' | 'json' | 'csv'>('pdf')
  const [reportGenerating, setReportGenerating] = useState(false)
  const [reportSuccess, setReportSuccess] = useState<string | null>(null)
  const [reportError, setReportError] = useState<string | null>(null)

  // ── Scan completion state ──
  const [lastCompletedScanId, setLastCompletedScanId] = useState<string | null>(null)

  // ── Scan error state ──
  const [scanError, setScanError] = useState<string | null>(null)

  // ── Scan timing state ──
  const [scanStartTime, setScanStartTime] = useState<number | null>(null)

  // ── Notification state ──
  const [notificationsEnabled, setNotificationsEnabled] = useState(false)

  // ── Build auth config from form state ──
  function buildAuthConfig() {
    switch (authType) {
      case 'bearer': return { type: 'bearer' as const, token: authBearerToken }
      case 'apikey': return { type: 'apikey' as const, key: authApiKey, header: authApiKeyHeader }
      case 'oauth2': return { type: 'oauth2' as const, tokenUrl: authOauth2TokenUrl, clientId: authOauth2ClientId, clientSecret: authOauth2ClientSecret, scope: authOauth2Scope || undefined }
      case 'cookie': return { type: 'cookie' as const, value: authCookieValue }
      case 'header': return { type: 'header' as const, name: authHeaderName, value: authHeaderValue }
      case 'form': return { type: 'form' as const, loginUrl: authFormLoginUrl, usernameField: authFormUsernameField, passwordField: authFormPasswordField, username: authFormUsername, password: authFormPassword }
      default: return { type: 'none' as const }
    }
  }

  // ── Fetch scans from API on mount ──
  const fetchScans = useCallback(async () => {
    try {
      const res = await fetch('/api/dast/scans')
      if (res.ok) {
        const data = await res.json()
        const apiScans = data.scans ?? []
        if (apiScans.length > 0) {
          setScans(apiScans)
        }
      }
    } catch { /* API unavailable */ }
  }, [])

  // ── Fetch findings for selected scan ──
  const fetchFindings = useCallback(async (scanId: string) => {
    try {
      const res = await fetch(`/api/dast/findings?scanId=${scanId}`)
      if (res.ok) {
        const data = await res.json()
        const apiFnd = data.findings ?? []
        if (apiFnd.length > 0) {
          setFindings((prev) => {
            const otherFindings = prev.filter((f) => f.scanId !== scanId)
            return [...otherFindings, ...apiFnd]
          })
        }
      }
    } catch { /* API unavailable */ }
  }, [])

  // ── Client-side comparison for mock scans ──
  function compareScansLocally(baselineId: string, currentId: string) {
    const baseScan = scans.find(s => s.id === baselineId)
    const currScan = scans.find(s => s.id === currentId)
    if (!baseScan || !currScan) return null

    const baseFindings = findings.filter(f => f.scanId === baselineId)
    const currFindings = findings.filter(f => f.scanId === currentId)

    // Fingerprint-based matching: type + affectedUrl + affectedParameter
    const fingerprint = (f: DastFinding) => `${f.type}|${f.affectedUrl}|${f.affectedParameter ?? ''}`
    const baseMap = new Map(baseFindings.map(f => [fingerprint(f), f]))
    const currMap = new Map(currFindings.map(f => [fingerprint(f), f]))

    const newFindings = currFindings.filter(f => !baseMap.has(fingerprint(f)))
    const resolvedFindings = baseFindings.filter(f => !currMap.has(fingerprint(f)))
    const persistentFindings = currFindings.filter(f => baseMap.has(fingerprint(f)))

    const deltas = [
      { metric: 'Total Findings', baseline: baseFindings.length, current: currFindings.length, delta: currFindings.length - baseFindings.length, direction: currFindings.length < baseFindings.length ? 'improved' : currFindings.length > baseFindings.length ? 'regressed' : 'unchanged', percentage: baseFindings.length ? Math.round(((currFindings.length - baseFindings.length) / baseFindings.length) * 100) : 0 },
      { metric: 'Critical', baseline: baseScan.criticalCount ?? 0, current: currScan.criticalCount ?? 0, delta: (currScan.criticalCount ?? 0) - (baseScan.criticalCount ?? 0), direction: (currScan.criticalCount ?? 0) < (baseScan.criticalCount ?? 0) ? 'improved' : (currScan.criticalCount ?? 0) > (baseScan.criticalCount ?? 0) ? 'regressed' : 'unchanged', percentage: (baseScan.criticalCount ?? 0) ? Math.round((((currScan.criticalCount ?? 0) - (baseScan.criticalCount ?? 0)) / (baseScan.criticalCount ?? 1)) * 100) : 0 },
      { metric: 'High', baseline: baseScan.highCount ?? 0, current: currScan.highCount ?? 0, delta: (currScan.highCount ?? 0) - (baseScan.highCount ?? 0), direction: (currScan.highCount ?? 0) < (baseScan.highCount ?? 0) ? 'improved' : (currScan.highCount ?? 0) > (baseScan.highCount ?? 0) ? 'regressed' : 'unchanged', percentage: (baseScan.highCount ?? 0) ? Math.round((((currScan.highCount ?? 0) - (baseScan.highCount ?? 0)) / (baseScan.highCount ?? 1)) * 100) : 0 },
      { metric: 'Risk Score', baseline: baseScan.riskScore ?? 0, current: currScan.riskScore ?? 0, delta: (currScan.riskScore ?? 0) - (baseScan.riskScore ?? 0), direction: (currScan.riskScore ?? 0) < (baseScan.riskScore ?? 0) ? 'improved' : (currScan.riskScore ?? 0) > (baseScan.riskScore ?? 0) ? 'regressed' : 'unchanged', percentage: (baseScan.riskScore ?? 0) ? Math.round((((currScan.riskScore ?? 0) - (baseScan.riskScore ?? 0)) / (baseScan.riskScore ?? 1)) * 100) : 0 },
    ]

    const totalDelta = deltas.reduce((acc, d) => acc + (d.direction === 'improved' ? 1 : d.direction === 'regressed' ? -1 : 0), 0)
    const overallTrend = totalDelta > 0 ? 'improved' : totalDelta < 0 ? 'regressed' : 'unchanged'

    return {
      summary: `Compared "${baseScan.name}" → "${currScan.name}": ${newFindings.length} new, ${resolvedFindings.length} resolved, ${persistentFindings.length} persistent findings.`,
      overallTrend,
      trendScore: totalDelta * 10,
      deltas,
      findingDiff: { newFindings, resolvedFindings, persistentFindings },
    }
  }

  // ── Run comparison ──
  const runComparison = useCallback(async () => {
    if (!compBaselineId || !compCurrentId || compBaselineId === compCurrentId) return

    setCompLoading(true)
    setCompResult(null)

    try {
      const res = await fetch('/api/dast/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baselineScanId: compBaselineId, currentScanId: compCurrentId }),
      })
      if (res.ok) {
        const data = await res.json()
        setCompResult(data.comparison)
      }
    } catch { /* ignore */ }
    setCompLoading(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [compBaselineId, compCurrentId, scans, findings])

  useEffect(() => {
    fetchScans()
    if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
      setNotificationsEnabled(true)
    }
    return () => {
      if (progressRef.current) clearInterval(progressRef.current)
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [fetchScans])

  useEffect(() => {
    if (selectedScan) fetchFindings(selectedScan.id)
  }, [selectedScan, fetchFindings])

  const filteredFindings = selectedScan
    ? findings
        .filter(f => f.scanId === selectedScan.id)
        .filter(f => severityFilter === 'ALL' || f.severity === severityFilter)
        .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
    : []

  const totalForScan = selectedScan ? findings.filter(f => f.scanId === selectedScan.id).length : 0

  // ── Start real scan via API ──
  async function startRealScan(name: string, targetUrl: string, scanProfile: string) {
    setScanError(null)
    const authConfig = buildAuthConfig()
    const scopeConfig = {
      includePaths: scopeInclude.split('\n').map(s => s.trim()).filter(Boolean),
      excludePaths: scopeExclude.split('\n').map(s => s.trim()).filter(Boolean),
    }
    try {
      const res = await fetch('/api/dast/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, targetUrl, scanProfile, authConfig, scope: scopeConfig }),
      })
      if (res.ok) {
        const data = await res.json()
        const newScan = data.scan
        setIsScanning(true)
        setScanStartTime(Date.now())
        // Poll for progress
        pollRef.current = setInterval(async () => {
          try {
            const pollRes = await fetch(`/api/dast/scans/${newScan.id}`)
            if (pollRes.ok) {
              const pollData = await pollRes.json()
              const scan = pollData.scan
              const progress = pollData.progress
              if (progress) setScanProgress(progress)
              // Update progress from scan object if no separate progress event
              if (!progress && scan.progress != null && scan.status === 'RUNNING') {
                setScanProgress({
                  scanId: scan.id, status: 'RUNNING', progress: scan.progress,
                  currentPhase: scan.currentPhase || 'scanning',
                  endpointsDiscovered: scan.endpointsDiscovered || 0,
                  endpointsTested: scan.endpointsTested || 0,
                  payloadsSent: scan.payloadsSent || 0,
                  findingsCount: 0, message: `Scanning... ${scan.progress}%`,
                  timestamp: new Date().toISOString(),
                })
              }
              if (scan.status === 'COMPLETED' || scan.status === 'FAILED') {
                if (pollRef.current) clearInterval(pollRef.current)
                pollRef.current = null
                // If findings came back in the response (direct/no-DB mode), add them to state
                if (pollData.findings && Array.isArray(pollData.findings) && pollData.findings.length > 0) {
                  setFindings(prev => {
                    const otherFindings = prev.filter((f: DastFinding) => f.scanId !== scan.id)
                    return [...otherFindings, ...pollData.findings]
                  })
                }
                if (scan.status === 'COMPLETED') {
                  setLastCompletedScanId(scan.id)
                  setSelectedScan(scan)
                  if (notificationsEnabled && 'Notification' in window && Notification.permission === 'granted') {
                    new Notification('HemisX DAST Scan Complete', {
                      body: `${scan.name} \u2014 ${scan.criticalCount ?? 0} critical, ${scan.highCount ?? 0} high findings`,
                      icon: '/favicon.ico',
                    })
                  }
                }
                if (scan.status === 'FAILED') {
                  setScanError(`Scan failed: ${scan.failureReason || 'Unknown error during scan execution'}`)
                  if (notificationsEnabled && 'Notification' in window && Notification.permission === 'granted') {
                    new Notification('HemisX DAST Scan Failed', {
                      body: `${scan.name} \u2014 ${scan.failureReason || 'Unknown error'}`,
                      icon: '/favicon.ico',
                    })
                  }
                }
                setTimeout(() => { setIsScanning(false); setScanProgress(null); setScanStartTime(null); fetchScans() }, 2000)
              }
            }
          } catch { /* ignore poll errors */ }
        }, 2000)
        return
      }
      // Non-OK response
      const errData = await res.json().catch(() => null)
      setScanError(errData?.error || `Scan failed to start (HTTP ${res.status}). Ensure the DAST engine is running.`)
    } catch {
      setScanError('DAST engine is not reachable. Start the engine with: cd tools/dast-engine && uvicorn dast_engine.main:app --reload')
    }
    setIsScanning(false)
  }

  // ── Generate client-side report from scan data ──
  function generateClientReport(scan: DastScan, scanFindings: DastFinding[], format: 'pdf' | 'json' | 'csv') {
    if (format === 'json') {
      const reportData = {
        report: {
          generatedAt: new Date().toISOString(),
          scan: {
            id: scan.id, name: scan.name, targetUrl: scan.targetUrl, scanProfile: scan.scanProfile,
            status: scan.status, riskScore: scan.riskScore,
            severityCounts: { critical: scan.criticalCount, high: scan.highCount, medium: scan.mediumCount, low: scan.lowCount, info: scan.infoCount },
            endpoints: { discovered: scan.endpointsDiscovered, tested: scan.endpointsTested },
            payloadsSent: scan.payloadsSent,
            techStack: scan.techStackDetected,
            startedAt: scan.startedAt, completedAt: scan.completedAt,
          },
          executiveSummary: scan.executiveSummary,
          findings: scanFindings.map(f => ({
            id: f.id, type: f.type, severity: f.severity, title: f.title,
            description: f.description, affectedUrl: f.affectedUrl, affectedParameter: f.affectedParameter,
            cvssScore: f.cvssScore, cweId: f.cweId, owaspCategory: f.owaspCategory,
            remediation: f.remediation, confidenceScore: f.confidenceScore, status: f.status,
            pciDssRefs: f.pciDssRefs, soc2Refs: f.soc2Refs, mitreAttackIds: f.mitreAttackIds,
          })),
        },
      }
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `dast-report-${scan.id}.json`
      a.click()
      URL.revokeObjectURL(url)
      return 'JSON report downloaded.'
    }

    if (format === 'csv') {
      const headers = ['ID', 'Severity', 'Title', 'Type', 'OWASP Category', 'CWE', 'CVSS', 'Affected URL', 'Parameter', 'Confidence', 'Status', 'Remediation']
      const rows = scanFindings.map(f => [
        f.id, f.severity, `"${f.title.replace(/"/g, '""')}"`, f.type, f.owaspCategory, f.cweId ?? '',
        f.cvssScore?.toString() ?? '', `"${f.affectedUrl}"`, f.affectedParameter ?? '', f.confidenceScore.toString(),
        f.status, `"${f.remediation.replace(/"/g, '""')}"`,
      ].join(','))
      const csv = [headers.join(','), ...rows].join('\n')
      const blob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `dast-report-${scan.id}.csv`
      a.click()
      URL.revokeObjectURL(url)
      return 'CSV report downloaded.'
    }

    // PDF (HTML report)
    const findingsHtml = scanFindings.map(f => `
      <tr>
        <td><span class="sev-${f.severity.toLowerCase()}">${f.severity}</span></td>
        <td>${f.title}</td>
        <td>${f.owaspCategory}</td>
        <td>${f.cvssScore ?? '-'}</td>
        <td style="font-size:11px;word-break:break-all">${f.affectedUrl}</td>
        <td style="font-size:11px">${f.remediation}</td>
      </tr>
    `).join('')

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>DAST Report - ${scan.name}</title>
    <style>
      body{font-family:system-ui,sans-serif;max-width:1100px;margin:0 auto;padding:40px;color:#1a1a2e;background:#fff}
      h1{font-size:24px;border-bottom:3px solid #7c3aed;padding-bottom:8px}
      h2{font-size:16px;color:#7c3aed;margin-top:28px;letter-spacing:0.05em;text-transform:uppercase}
      .meta{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin:16px 0}
      .meta-box{background:#f8f7ff;border:1px solid #e5e0ff;padding:14px;text-align:center}
      .meta-box .val{font-size:28px;font-weight:700;color:#7c3aed}
      .meta-box .lbl{font-size:11px;color:#888;margin-top:4px}
      table{width:100%;border-collapse:collapse;font-size:12px;margin:12px 0}
      th{background:#7c3aed;color:#fff;padding:8px 10px;text-align:left;font-size:10px;letter-spacing:0.08em;text-transform:uppercase}
      td{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top}
      tr:nth-child(even){background:#faf9ff}
      .sev-critical{color:#dc2626;font-weight:700}.sev-high{color:#ea580c;font-weight:700}
      .sev-medium{color:#ca8a04;font-weight:700}.sev-low{color:#2563eb}.sev-info{color:#6b7280}
      .summary{background:#f8f7ff;border-left:4px solid #7c3aed;padding:16px;margin:12px 0;line-height:1.7;white-space:pre-line;font-size:13px}
      @media print{body{padding:20px}h1{font-size:20px}}
    </style></head><body>
    <h1>DAST Security Report</h1>
    <div class="meta">
      <div class="meta-box"><div class="val">${scan.riskScore}</div><div class="lbl">Risk Score</div></div>
      <div class="meta-box"><div class="val">${scanFindings.length}</div><div class="lbl">Total Findings</div></div>
      <div class="meta-box"><div class="val">${scan.endpointsTested}</div><div class="lbl">Endpoints Tested</div></div>
    </div>
    <table><tr><td><strong>Target:</strong> ${scan.targetUrl}</td><td><strong>Profile:</strong> ${scan.scanProfile}</td><td><strong>Date:</strong> ${scan.completedAt ? new Date(scan.completedAt).toLocaleDateString() : 'N/A'}</td></tr>
    <tr><td><strong>Critical:</strong> ${scan.criticalCount}</td><td><strong>High:</strong> ${scan.highCount}</td><td><strong>Medium:</strong> ${scan.mediumCount} | <strong>Low:</strong> ${scan.lowCount} | <strong>Info:</strong> ${scan.infoCount}</td></tr></table>
    ${scan.executiveSummary ? `<h2>Executive Summary</h2><div class="summary">${scan.executiveSummary}</div>` : ''}
    <h2>Findings</h2>
    <table><thead><tr><th>Severity</th><th>Title</th><th>OWASP</th><th>CVSS</th><th>URL</th><th>Remediation</th></tr></thead><tbody>${findingsHtml}</tbody></table>
    <p style="margin-top:40px;font-size:11px;color:#aaa;text-align:center">Generated by HemisX DAST Scanner on ${new Date().toLocaleString()}</p>
    </body></html>`

    const blob = new Blob([html], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    window.open(url, '_blank')
    return 'Report opened in new tab. Use Ctrl+P / Cmd+P to save as PDF.'
  }

  // ── Generate report ──
  async function handleGenerateReport() {
    if (!reportScanId) return
    setReportGenerating(true)
    setReportSuccess(null)
    setReportError(null)

    const targetScan = scans.find(s => s.id === reportScanId)
    const targetFindings = findings.filter(f => f.scanId === reportScanId)

    try {
      const res = await fetch(`/api/dast/reports/${reportScanId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: reportFormat }),
      })
      if (!res.ok) {
        const errData = await res.json().catch(() => null)
        // If API fails and we have in-memory data, fall back to client-side generation
        if (targetScan) {
          const msg = generateClientReport(targetScan, targetFindings, reportFormat)
          setReportSuccess(msg)
          setReportGenerating(false)
          return
        }
        throw new Error(errData?.error || `Report generation failed (${res.status})`)
      }

      if (reportFormat === 'pdf') {
        // HTML response - open in new tab for Ctrl+P
        const html = await res.text()
        const blob = new Blob([html], { type: 'text/html' })
        const url = URL.createObjectURL(blob)
        window.open(url, '_blank')
        setReportSuccess('Report opened in new tab. Use Ctrl+P / Cmd+P to save as PDF.')
      } else if (reportFormat === 'json') {
        const data = await res.json()
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `dast-report-${reportScanId}.json`
        a.click()
        URL.revokeObjectURL(url)
        setReportSuccess('JSON report downloaded.')
      } else if (reportFormat === 'csv') {
        const text = await res.text()
        const blob = new Blob([text], { type: 'text/csv' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `dast-report-${reportScanId}.csv`
        a.click()
        URL.revokeObjectURL(url)
        setReportSuccess('CSV report downloaded.')
      }
    } catch (err) {
      // Last resort: try client-side generation if we have in-memory data
      if (targetScan) {
        try {
          const msg = generateClientReport(targetScan, targetFindings, reportFormat)
          setReportSuccess(msg)
          setReportGenerating(false)
          return
        } catch { /* fall through to error */ }
      }
      setReportError(err instanceof Error ? err.message : 'Report generation failed')
    }
    setReportGenerating(false)
  }

  // ── Parse AI data from selected scan ──
  let correlationData: { attackChains?: Array<{ chainId: string; name: string; description: string; severity: string; findingIndices: number[]; exploitationSteps: string[]; businessImpact: string; likelihoodOfExploitation: string }>; duplicateGroups?: Array<{ reason: string; findingIndices: number[]; recommendedAction: string }>; riskAmplifiers?: Array<{ description: string; affectedFindings: number[]; amplificationFactor: number }>; overallChainedRiskScore?: number } | null = null
  let complianceData: { frameworks?: Array<{ name: string; overallStatus: string; controlsAffected: number; totalControlsChecked: number; affectedControls: Array<{ framework: string; controlId: string; controlName: string; status: string; findingIndices: number[]; remediationNote: string }> }>; highestRiskFramework?: string; complianceScore?: number; auditReadiness?: string; keyGaps?: string[] } | null = null

  try { if (selectedScan?.aiCorrelationData) correlationData = JSON.parse(selectedScan.aiCorrelationData) } catch { /* skip */ }
  try { if (selectedScan?.aiComplianceData) complianceData = JSON.parse(selectedScan.aiComplianceData) } catch { /* skip */ }

  const scanFindings = selectedScan
    ? findings.filter(f => f.scanId === selectedScan.id).sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
    : []

  const completedScans = scans.filter(s => s.status === 'COMPLETED')

  const reportScan = completedScans.find(s => s.id === reportScanId) ?? null

  return (
    <div style={{ padding: '24px 28px', height: '100%', overflowY: 'auto' }}>

      {/* ── Page Header ── */}
      <div style={{ marginBottom: 20 }}>
        <div className="display" style={{ fontSize: 26, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0, marginBottom: 6 }}>
          DAST Scanner
        </div>
        <p style={{ fontSize: 14, color: 'var(--color-text-secondary)', margin: 0 }}>
          Dynamic Application Security Testing &nbsp;&middot;&nbsp; OWASP ZAP Engine &nbsp;&middot;&nbsp; AI-Enriched Analysis
        </p>
      </div>

      {/* ── Top Tab Bar ── */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 0, borderBottom: '1px solid var(--color-border)' }}>
        {([
          { id: 'scanner' as TopTab, label: 'SCANNER' },
          { id: 'history' as TopTab, label: 'HISTORY' },
          { id: 'attack-chains' as TopTab, label: 'ATTACK CHAINS' },
          { id: 'attack-map' as TopTab, label: 'ATTACK MAP' },
          { id: 'compliance' as TopTab, label: 'COMPLIANCE' },
          { id: 'remediation' as TopTab, label: 'REMEDIATION' },
          { id: 'monitoring' as TopTab, label: 'MONITORING' },
          { id: 'integrations' as TopTab, label: 'INTEGRATIONS' },
          { id: 'compare' as TopTab, label: 'COMPARE' },
          { id: 'report' as TopTab, label: 'REPORT' },
        ]).map(p => (
          <button
            key={p.id}
            onClick={() => setActiveTab(p.id)}
            className="mono"
            style={{
              padding: '10px 20px', fontSize: 11, letterSpacing: '0.12em',
              textTransform: 'uppercase', cursor: 'pointer',
              background: 'none', border: 'none',
              borderBottom: activeTab === p.id ? '2px solid var(--color-dast)' : '2px solid transparent',
              color: activeTab === p.id ? 'var(--color-dast)' : 'var(--color-text-secondary)',
              marginBottom: -1,
            }}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── SCANNER TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'scanner' && (
        <div style={{ marginTop: 20 }}>

          {/* Live Scan Progress */}
          {isScanning && scanProgress && (
            <div className="bracket-card bracket-dast" style={{ padding: 20, marginBottom: 20, position: 'relative', overflow: 'hidden' }}>
              {scanProgress.status === 'RUNNING' && <div className="scan-line purple" />}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-dast)', letterSpacing: '0.1em' }}>
                  SCAN IN PROGRESS
                </div>
                <span className="mono" style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-dast)' }}>
                  {scanProgress.progress}%
                </span>
              </div>
              <div className="tac-progress" style={{ marginBottom: 12 }}>
                <div className="tac-progress-fill" style={{ width: `${scanProgress.progress}%`, background: 'var(--color-dast)' }} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>
                  {PHASE_LABELS[scanProgress.currentPhase] ?? scanProgress.currentPhase}
                </div>
                <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                  {scanProgress.message}
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginTop: 14 }}>
                {[
                  { label: 'Endpoints', value: scanProgress.endpointsDiscovered },
                  { label: 'Tested', value: scanProgress.endpointsTested },
                  { label: 'Payloads', value: scanProgress.payloadsSent },
                  { label: 'Findings', value: scanProgress.findingsCount },
                  { label: 'Elapsed', value: scanStartTime ? formatEta((Date.now() - scanStartTime) / 1000) : '\u2014' },
                  { label: 'ETA', value: formatEta(scanProgress.estimatedTimeRemaining) },
                ].map(m => (
                  <div key={m.label} style={{ background: 'var(--color-bg-elevated)', padding: '8px 10px', textAlign: 'center' }}>
                    <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: 'var(--color-dast)' }}>{m.value}</div>
                    <div style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{m.label}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan Error Banner */}
          {scanError && !isScanning && (
            <div style={{
              padding: '16px 20px', marginBottom: 20,
              background: 'rgba(220, 38, 38, 0.08)',
              border: '1px solid rgba(220, 38, 38, 0.3)',
              display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12,
            }}>
              <div>
                <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#dc2626', letterSpacing: '0.08em', marginBottom: 6 }}>
                  SCAN FAILED TO START
                </div>
                <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
                  {scanError}
                </div>
              </div>
              <button
                onClick={() => setScanError(null)}
                style={{ background: 'none', border: 'none', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 14, padding: '0 4px', flexShrink: 0 }}
              >
                &#x2715;
              </button>
            </div>
          )}

          {/* Scan Complete Banner */}
          {!isScanning && lastCompletedScanId && (() => {
            const completedScan = scans.find(s => s.id === lastCompletedScanId)
            if (!completedScan) return null
            return (
              <div className="bracket-card bracket-dast" style={{ padding: 20, marginBottom: 20, borderColor: 'var(--color-scanner)', background: 'var(--color-bg-surface)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                      <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-scanner)', letterSpacing: '0.08em' }}>
                        SCAN COMPLETED SUCCESSFULLY
                      </div>
                      <button
                        onClick={() => setLastCompletedScanId(null)}
                        style={{ background: 'none', border: 'none', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 14, padding: '0 4px' }}
                      >
                        &#x2715;
                      </button>
                    </div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginBottom: 4 }}>
                      {completedScan.name} &mdash; {completedScan.targetUrl}
                    </div>
                    <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
                      <span className="label-tag sev-critical">Critical: {completedScan.criticalCount}</span>
                      <span className="label-tag sev-high">High: {completedScan.highCount}</span>
                      <span className="label-tag sev-medium">Medium: {completedScan.mediumCount}</span>
                      <span className="label-tag sev-low">Low: {completedScan.lowCount}</span>
                      <span className="label-tag sev-info">Info: {completedScan.infoCount}</span>
                    </div>
                    <div style={{ display: 'flex', gap: 10 }}>
                      <button
                        onClick={() => {
                          setSelectedScan(completedScan)
                          setSelectedFinding(null)
                          setSeverityFilter('ALL')
                          setActiveTab('history')
                        }}
                        className="mono"
                        style={{
                          background: 'var(--color-dast)', color: '#fff', border: 'none',
                          padding: '8px 20px', fontSize: 10, fontWeight: 600, letterSpacing: '0.1em',
                          textTransform: 'uppercase', cursor: 'pointer',
                        }}
                      >
                        VIEW RESULTS
                      </button>
                      <button
                        onClick={() => {
                          setReportScanId(completedScan.id)
                          setReportSuccess(null)
                          setReportError(null)
                          setActiveTab('report')
                        }}
                        className="mono"
                        style={{
                          background: 'transparent', color: 'var(--color-dast)',
                          border: '1px solid var(--color-dast)',
                          padding: '8px 20px', fontSize: 10, fontWeight: 600, letterSpacing: '0.1em',
                          textTransform: 'uppercase', cursor: 'pointer',
                        }}
                      >
                        GENERATE REPORT
                      </button>
                    </div>
                  </div>
                  <div className="mono" style={{ fontSize: 32, fontWeight: 700, color: riskColor(completedScan.riskScore) }}>
                    {completedScan.riskScore}
                  </div>
                </div>
              </div>
            )
          })()}

          {/* Scan Configuration Form (show when NOT scanning) */}
          {!isScanning && (
            <div className="bracket-card bracket-dast" style={{ padding: 24 }}>
              <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-dast)', letterSpacing: '0.1em', marginBottom: 18 }}>
                NEW SCAN CONFIGURATION
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 16 }}>
                <div>
                  <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>TARGET URL</label>
                  <input className="tac-input" placeholder="https://example.com" style={{ marginTop: 4 }} value={newScanUrl} onChange={e => setNewScanUrl(e.target.value)} />
                </div>
                <div>
                  <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SCAN NAME</label>
                  <input className="tac-input" placeholder="My Web App Scan" style={{ marginTop: 4 }} value={newScanName} onChange={e => setNewScanName(e.target.value)} />
                </div>
              </div>

              {/* Profile Selector */}
              <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8 }}>SCAN PROFILE</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 12, marginBottom: 18 }}>
                {(['full', 'quick', 'api_only', 'deep'] as const).map(profile => (
                  <div
                    key={profile}
                    onClick={() => setNewScanProfile(profile)}
                    style={{
                      background: newScanProfile === profile ? 'var(--color-dast-dim)' : 'var(--color-bg-elevated)',
                      border: `1px solid ${newScanProfile === profile ? 'var(--color-dast)' : 'var(--color-border)'}`,
                      padding: '10px 14px',
                      cursor: 'pointer',
                      textAlign: 'center',
                    }}
                  >
                    <div className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      {profile.replace('_', ' ')}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>
                      {profile === 'full' ? 'Spider + Active Scan' : profile === 'quick' ? 'Top 10 checks' : profile === 'api_only' ? 'API endpoints only' : 'All checks, max intensity'}
                    </div>
                    <div className="mono" style={{ fontSize: 9, color: 'var(--color-dast)', marginTop: 4, opacity: 0.8 }}>
                      {PROFILE_ESTIMATES[profile]}
                    </div>
                  </div>
                ))}
              </div>

              {/* Advanced Configuration Toggle */}
              <div
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="mono"
                style={{
                  fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-dast)',
                  cursor: 'pointer', marginBottom: showAdvanced ? 14 : 0, userSelect: 'none',
                }}
              >
                {showAdvanced ? '\u25BE' : '\u25B8'} ADVANCED CONFIGURATION
              </div>

              {showAdvanced && (
                <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', padding: 16, marginBottom: 16 }}>
                  {/* Auth Type Selector */}
                  <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)', marginBottom: 8 }}>
                    AUTHENTICATION
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
                    {(['none', 'bearer', 'apikey', 'oauth2', 'cookie', 'header', 'form'] as const).map(at => (
                      <button
                        key={at}
                        onClick={() => setAuthType(at)}
                        className="mono"
                        style={{
                          background: authType === at ? 'var(--color-dast-dim)' : 'transparent',
                          border: `1px solid ${authType === at ? 'var(--color-dast)' : 'var(--color-border)'}`,
                          color: authType === at ? 'var(--color-dast)' : 'var(--color-text-dim)',
                          padding: '4px 10px', fontSize: 10, fontWeight: 600, letterSpacing: '0.08em',
                          cursor: 'pointer', textTransform: 'uppercase',
                        }}
                      >
                        {at}
                      </button>
                    ))}
                  </div>

                  {/* Auth-specific fields */}
                  {authType === 'bearer' && (
                    <div style={{ marginBottom: 14 }}>
                      <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>BEARER TOKEN</label>
                      <input className="tac-input" placeholder="eyJhbGciOiJIUzI1NiIs..." style={{ marginTop: 4 }} value={authBearerToken} onChange={e => setAuthBearerToken(e.target.value)} />
                    </div>
                  )}
                  {authType === 'apikey' && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>API KEY</label>
                        <input className="tac-input" placeholder="sk-..." style={{ marginTop: 4 }} value={authApiKey} onChange={e => setAuthApiKey(e.target.value)} />
                      </div>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>HEADER NAME</label>
                        <input className="tac-input" placeholder="X-API-Key" style={{ marginTop: 4 }} value={authApiKeyHeader} onChange={e => setAuthApiKeyHeader(e.target.value)} />
                      </div>
                    </div>
                  )}
                  {authType === 'oauth2' && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>TOKEN URL</label>
                        <input className="tac-input" placeholder="https://auth.example.com/token" style={{ marginTop: 4 }} value={authOauth2TokenUrl} onChange={e => setAuthOauth2TokenUrl(e.target.value)} />
                      </div>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>CLIENT ID</label>
                        <input className="tac-input" placeholder="client_id" style={{ marginTop: 4 }} value={authOauth2ClientId} onChange={e => setAuthOauth2ClientId(e.target.value)} />
                      </div>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>CLIENT SECRET</label>
                        <input className="tac-input" type="password" placeholder="client_secret" style={{ marginTop: 4 }} value={authOauth2ClientSecret} onChange={e => setAuthOauth2ClientSecret(e.target.value)} />
                      </div>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SCOPE (optional)</label>
                        <input className="tac-input" placeholder="read write" style={{ marginTop: 4 }} value={authOauth2Scope} onChange={e => setAuthOauth2Scope(e.target.value)} />
                      </div>
                    </div>
                  )}
                  {authType === 'cookie' && (
                    <div style={{ marginBottom: 14 }}>
                      <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>COOKIE VALUE</label>
                      <input className="tac-input" placeholder="session=abc123; token=xyz" style={{ marginTop: 4 }} value={authCookieValue} onChange={e => setAuthCookieValue(e.target.value)} />
                    </div>
                  )}
                  {authType === 'header' && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>HEADER NAME</label>
                        <input className="tac-input" placeholder="X-Custom-Auth" style={{ marginTop: 4 }} value={authHeaderName} onChange={e => setAuthHeaderName(e.target.value)} />
                      </div>
                      <div>
                        <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>HEADER VALUE</label>
                        <input className="tac-input" placeholder="custom-token-value" style={{ marginTop: 4 }} value={authHeaderValue} onChange={e => setAuthHeaderValue(e.target.value)} />
                      </div>
                    </div>
                  )}
                  {authType === 'form' && (
                    <div style={{ marginBottom: 14 }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 10 }}>
                        <div>
                          <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>LOGIN URL</label>
                          <input className="tac-input" placeholder="https://example.com/login" style={{ marginTop: 4 }} value={authFormLoginUrl} onChange={e => setAuthFormLoginUrl(e.target.value)} />
                        </div>
                        <div>
                          <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>USERNAME</label>
                          <input className="tac-input" placeholder="testuser" style={{ marginTop: 4 }} value={authFormUsername} onChange={e => setAuthFormUsername(e.target.value)} />
                        </div>
                        <div>
                          <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>PASSWORD</label>
                          <input className="tac-input" type="password" placeholder="password" style={{ marginTop: 4 }} value={authFormPassword} onChange={e => setAuthFormPassword(e.target.value)} />
                        </div>
                        <div>
                          <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>USERNAME FIELD NAME</label>
                          <input className="tac-input" placeholder="username" style={{ marginTop: 4 }} value={authFormUsernameField} onChange={e => setAuthFormUsernameField(e.target.value)} />
                        </div>
                        <div>
                          <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>PASSWORD FIELD NAME</label>
                          <input className="tac-input" placeholder="password" style={{ marginTop: 4 }} value={authFormPasswordField} onChange={e => setAuthFormPasswordField(e.target.value)} />
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Scope Configuration */}
                  <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)', marginBottom: 8, marginTop: 10 }}>
                    SCOPE CONFIGURATION
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div>
                      <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>INCLUDE PATHS (one per line)</label>
                      <textarea
                        className="tac-input"
                        placeholder={'/api/*\n/app/*\n/admin/*'}
                        rows={3}
                        style={{ marginTop: 4, resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11 }}
                        value={scopeInclude}
                        onChange={e => setScopeInclude(e.target.value)}
                      />
                    </div>
                    <div>
                      <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>EXCLUDE PATHS (one per line)</label>
                      <textarea
                        className="tac-input"
                        placeholder={'/logout\n/static/*\n*.pdf'}
                        rows={3}
                        style={{ marginTop: 4, resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11 }}
                        value={scopeExclude}
                        onChange={e => setScopeExclude(e.target.value)}
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Launch Button + Notification Toggle */}
              <div style={{ display: 'flex', gap: 10, marginTop: showAdvanced ? 0 : 18, alignItems: 'center' }}>
                <button
                  onClick={() => {
                    const name = newScanName.trim() || 'DAST Scan'
                    const url = newScanUrl.trim()
                    if (!url) return
                    setScanError(null)
                    startRealScan(name, url, newScanProfile)
                    setNewScanName(''); setNewScanUrl(''); setNewScanProfile('full')
                    setAuthType('none'); setShowAdvanced(false)
                  }}
                  disabled={!newScanUrl.trim()}
                  style={{
                    background: 'var(--color-dast)',
                    color: '#fff',
                    border: 'none',
                    padding: '10px 28px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    fontWeight: 600,
                    letterSpacing: '0.12em',
                    textTransform: 'uppercase',
                    cursor: !newScanUrl.trim() ? 'not-allowed' : 'pointer',
                    opacity: !newScanUrl.trim() ? 0.5 : 1,
                  }}
                >
                  START SCAN
                </button>
                <button
                  onClick={async () => {
                    if (typeof window === 'undefined' || !('Notification' in window)) return
                    if (Notification.permission === 'default') {
                      const permission = await Notification.requestPermission()
                      setNotificationsEnabled(permission === 'granted')
                    } else if (Notification.permission === 'granted') {
                      setNotificationsEnabled(prev => !prev)
                    }
                  }}
                  className="mono"
                  title={notificationsEnabled ? 'Notifications enabled — click to disable' : 'Click to enable browser notifications when scan completes'}
                  style={{
                    background: notificationsEnabled ? 'var(--color-dast-dim)' : 'transparent',
                    border: `1px solid ${notificationsEnabled ? 'var(--color-dast)' : 'var(--color-border)'}`,
                    color: notificationsEnabled ? 'var(--color-dast)' : 'var(--color-text-dim)',
                    padding: '8px 14px',
                    fontSize: 11,
                    fontWeight: 600,
                    letterSpacing: '0.08em',
                    cursor: 'pointer',
                  }}
                >
                  {notificationsEnabled ? 'NOTIFY ON' : 'NOTIFY OFF'}
                </button>
              </div>
            </div>
          )}

          {/* Empty State (no scans, not scanning) */}
          {scans.length === 0 && !isScanning && (
            <div style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--color-text-dim)', marginTop: 20 }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 8 }}>No scans yet</div>
              <div className="mono" style={{ fontSize: 11 }}>
                Configure the form above and click &quot;START SCAN&quot; to run your first DAST scan.
              </div>
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── HISTORY TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'history' && (
        <div style={{ marginTop: 20 }}>
          {scans.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 8 }}>No scan history</div>
              <div className="mono" style={{ fontSize: 11 }}>Run a scan from the SCANNER tab to see it here.</div>
            </div>
          ) : (
            <>
              {/* Security Posture Overview */}
              <PostureCard scans={scans} findings={findings} />

              {/* Visualizations Row */}
              {selectedScan && scanFindings.length > 0 && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
                  <div className="bracket-card" style={{ padding: 16 }}>
                    <OWASPHeatmap findings={scanFindings} onCategoryClick={(cat) => { setSeverityFilter('ALL'); setActiveTab('history') }} />
                  </div>
                  <div className="bracket-card" style={{ padding: 16 }}>
                    <CVSSDistribution findings={scanFindings} />
                  </div>
                </div>
              )}

              {selectedScan && scanFindings.length > 0 && (
                <div className="bracket-card" style={{ padding: 16, marginBottom: 20 }}>
                  <AttackSurfaceMap findings={scanFindings} onEndpointClick={() => {}} />
                </div>
              )}

              {/* Scan Table */}
              <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
                <div className="mono" style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr 90px 70px 50px 50px 50px 70px 130px',
                  padding: '8px 14px',
                  borderBottom: '1px solid var(--color-border)',
                  fontSize: 9,
                  fontWeight: 600,
                  letterSpacing: '0.1em',
                  color: 'var(--color-text-dim)',
                }}>
                  <span>NAME</span>
                  <span>TARGET</span>
                  <span>STATUS</span>
                  <span style={{ textAlign: 'center' }}>RISK</span>
                  <span style={{ textAlign: 'center' }}>C</span>
                  <span style={{ textAlign: 'center' }}>H</span>
                  <span style={{ textAlign: 'center' }}>M</span>
                  <span style={{ textAlign: 'center' }}>L+I</span>
                  <span style={{ textAlign: 'right' }}>DATE</span>
                </div>

                {scans.map(s => (
                  <div
                    key={s.id}
                    onClick={() => { setSelectedScan(s); setSelectedFinding(null); setSeverityFilter('ALL') }}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr 90px 70px 50px 50px 50px 70px 130px',
                      padding: '10px 14px',
                      borderBottom: '1px solid var(--color-border)',
                      cursor: 'pointer',
                      background: selectedScan?.id === s.id ? 'var(--color-dast-dim)' : 'transparent',
                      transition: 'background 0.1s',
                      alignItems: 'center',
                    }}
                  >
                    <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: selectedScan?.id === s.id ? 'var(--color-dast)' : 'var(--color-text-primary)', letterSpacing: '0.04em' }}>
                      {s.name}
                    </span>
                    <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {s.targetUrl}
                    </span>
                    <span className={`label-tag sev-${s.status === 'COMPLETED' ? 'low' : s.status === 'FAILED' ? 'critical' : s.status === 'RUNNING' ? 'medium' : 'info'}`} style={{ fontSize: 9, textAlign: 'center' }}>
                      {s.status}
                    </span>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: riskColor(s.riskScore), textAlign: 'center' }}>
                      {s.riskScore ?? '\u2014'}
                    </span>
                    <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-critical)', textAlign: 'center' }}>{s.criticalCount ?? 0}</span>
                    <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-high)', textAlign: 'center' }}>{s.highCount ?? 0}</span>
                    <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-medium)', textAlign: 'center' }}>{s.mediumCount ?? 0}</span>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', textAlign: 'center' }}>
                      {(s.lowCount ?? 0) + (s.infoCount ?? 0)}
                    </span>
                    <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', textAlign: 'right' }}>
                      {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : s.createdAt ? new Date(s.createdAt).toLocaleDateString() : '\u2014'}
                    </span>
                  </div>
                ))}
              </div>

              {/* Selected Scan Detail */}
              {selectedScan && (
                <div style={{ marginTop: 24 }}>
                  {/* Score Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10, marginBottom: 20 }}>
                    <div className="bracket-card bracket-dast" style={{ padding: '12px 14px', textAlign: 'center' }}>
                      <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: riskColor(selectedScan.riskScore) }}>{selectedScan.riskScore}</div>
                      <div style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>Risk Score</div>
                    </div>
                    {([
                      { label: 'CRITICAL', count: selectedScan.criticalCount, sev: 'critical' },
                      { label: 'HIGH', count: selectedScan.highCount, sev: 'high' },
                      { label: 'MEDIUM', count: selectedScan.mediumCount, sev: 'medium' },
                      { label: 'LOW', count: selectedScan.lowCount, sev: 'low' },
                      { label: 'INFO', count: selectedScan.infoCount, sev: 'info' },
                    ] as const).map(c => (
                      <div key={c.label} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: '12px 14px', textAlign: 'center' }}>
                        <div className="mono" style={{ fontSize: 22, fontWeight: 700, color: `var(--color-${c.sev === 'info' ? 'blueteam' : c.sev})` }}>{c.count}</div>
                        <div className={`label-tag sev-${c.sev}`} style={{ fontSize: 9 }}>{c.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* Executive Summary */}
                  {selectedScan.executiveSummary && (
                    <div className="bracket-card bracket-dast" style={{ padding: 24, marginBottom: 20 }}>
                      <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.14em', color: 'var(--color-dast)', marginBottom: 12 }}>EXECUTIVE SUMMARY</div>
                      <div>{renderMarkdown(selectedScan.executiveSummary)}</div>
                    </div>
                  )}

                  {/* Severity Filter */}
                  <div style={{ display: 'flex', gap: 6, marginBottom: 14 }}>
                    {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map(sev => (
                      <button
                        key={sev}
                        onClick={() => setSeverityFilter(sev)}
                        className="mono"
                        style={{
                          background: severityFilter === sev ? 'var(--color-bg-elevated)' : 'transparent',
                          border: `1px solid ${severityFilter === sev ? 'var(--color-border-bright)' : 'var(--color-border)'}`,
                          color: severityFilter === sev ? 'var(--color-text-primary)' : 'var(--color-text-dim)',
                          padding: '4px 12px',
                          fontSize: 10,
                          fontWeight: 600,
                          letterSpacing: '0.1em',
                          cursor: 'pointer',
                        }}
                      >
                        {sev} {sev === 'ALL' ? `(${totalForScan})` : ''}
                      </button>
                    ))}
                  </div>

                  {/* Findings Table */}
                  <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
                    <div className="mono" style={{
                      display: 'grid',
                      gridTemplateColumns: '80px 1fr 100px 80px 60px',
                      padding: '8px 14px',
                      borderBottom: '1px solid var(--color-border)',
                      fontSize: 10,
                      fontWeight: 600,
                      letterSpacing: '0.1em',
                      color: 'var(--color-text-dim)',
                    }}>
                      <span>SEV</span>
                      <span>FINDING</span>
                      <span>OWASP</span>
                      <span>CVSS</span>
                      <span>CONF</span>
                    </div>

                    {filteredFindings.length === 0 && (
                      <div style={{ padding: 24, textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
                        No findings match the current filter.
                      </div>
                    )}

                    {filteredFindings.map(f => (
                      <div key={f.id}>
                        <div
                          onClick={() => setSelectedFinding(selectedFinding?.id === f.id ? null : f)}
                          style={{
                            display: 'grid',
                            gridTemplateColumns: '80px 1fr 100px 80px 60px',
                            padding: '10px 14px',
                            borderBottom: '1px solid var(--color-border)',
                            cursor: 'pointer',
                            background: selectedFinding?.id === f.id ? 'var(--color-dast-dim)' : 'transparent',
                            transition: 'background 0.1s',
                            alignItems: 'center',
                          }}
                        >
                          <span className={`label-tag sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--color-text-primary)' }}>{f.title}</div>
                            <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 2 }}>{f.affectedUrl}</div>
                          </div>
                          <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)' }}>{f.owaspCategory.split(' ')[0]}</span>
                          <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: cvssColor(f.cvssScore) }}>{f.cvssScore ?? '\u2014'}</span>
                          <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>{f.confidenceScore}%</span>
                        </div>

                        {/* Inline Finding Detail (expanded) */}
                        {selectedFinding?.id === f.id && (
                          <FindingDetail finding={f} onClose={() => setSelectedFinding(null)} />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── ATTACK CHAINS TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'attack-chains' && (
        <div style={{ marginTop: 20 }}>
          {!selectedScan ? (
            <div style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 8 }}>No scan selected</div>
              <div className="mono" style={{ fontSize: 11 }}>Select a scan from the HISTORY tab to view attack chain analysis.</div>
            </div>
          ) : (
            <AttackChainsPanel correlationData={correlationData} scanFindings={scanFindings} />
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── COMPLIANCE TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'compliance' && (
        <div style={{ marginTop: 20 }}>
          {!selectedScan ? (
            <div style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 8 }}>No scan selected</div>
              <div className="mono" style={{ fontSize: 11 }}>Select a scan from the HISTORY tab to view compliance mapping.</div>
            </div>
          ) : (
            <CompliancePanel complianceData={complianceData} />
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── ATTACK MAP TAB (3D) ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'attack-map' && (
        <div style={{ marginTop: 20 }}>
          {!selectedScan ? (
            <div style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 8 }}>No scan selected</div>
              <div className="mono" style={{ fontSize: 11 }}>Select a scan from the HISTORY tab to view the 3D attack map.</div>
            </div>
          ) : (
            <>
              <MitreAttackMatrix findings={scanFindings} />
              <Suspense fallback={
                <div style={{ textAlign: 'center', padding: 60, color: 'var(--color-text-secondary)' }}>
                  <div className="mono" style={{ fontSize: 12 }}>Loading 3D Attack Graph...</div>
                </div>
              }>
                <AttackGraph3D
                  findings={scanFindings}
                  attackChains={correlationData}
                  onFindingClick={(f) => setSelectedFinding(f)}
                />
              </Suspense>
            </>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── REMEDIATION TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'remediation' && (
        <div style={{ marginTop: 20 }}>
          {!selectedScan ? (
            <div style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: 8 }}>No scan selected</div>
              <div className="mono" style={{ fontSize: 11 }}>Select a scan from the HISTORY tab to view remediation priorities.</div>
            </div>
          ) : (
            <RemediationTab findings={scanFindings} />
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── MONITORING TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'monitoring' && (
        <MonitoringTab scans={scans} />
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── INTEGRATIONS TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'integrations' && (
        <IntegrationsTab />
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── COMPARE TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'compare' && (
        <div style={{ marginTop: 20 }}>
          <ComparisonPanel
            scans={scans}
            compBaselineId={compBaselineId}
            compCurrentId={compCurrentId}
            setCompBaselineId={setCompBaselineId}
            setCompCurrentId={setCompCurrentId}
            compResult={compResult}
            compLoading={compLoading}
            runComparison={runComparison}
          />
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* ── REPORT TAB ── */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'report' && (
        <div style={{ marginTop: 20 }}>
          <div className="bracket-card bracket-dast" style={{ padding: 24 }}>
            <div className="mono" style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-dast)', marginBottom: 18 }}>
              GENERATE SECURITY REPORT
            </div>

            {completedScans.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--color-text-dim)' }}>
                <div style={{ fontSize: 14, marginBottom: 8 }}>No completed scans available</div>
                <div className="mono" style={{ fontSize: 11 }}>Complete a DAST scan first to generate a report.</div>
              </div>
            ) : (
              <>
                {/* Scan Selector */}
                <div style={{ marginBottom: 18 }}>
                  <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SELECT SCAN</label>
                  <select
                    className="tac-input"
                    style={{ marginTop: 4 }}
                    value={reportScanId}
                    onChange={e => { setReportScanId(e.target.value); setReportSuccess(null); setReportError(null) }}
                  >
                    <option value="">Select a completed scan...</option>
                    {completedScans.map(s => (
                      <option key={s.id} value={s.id}>
                        {s.name} -- {s.targetUrl} ({s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Format Selector */}
                <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 10 }}>
                  REPORT FORMAT
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
                  {([
                    { id: 'pdf' as const, label: 'PDF', desc: 'HTML report (save as PDF via browser)' },
                    { id: 'json' as const, label: 'JSON', desc: 'Structured data for integrations' },
                    { id: 'csv' as const, label: 'CSV', desc: 'Spreadsheet-compatible export' },
                  ]).map(fmt => (
                    <div
                      key={fmt.id}
                      onClick={() => setReportFormat(fmt.id)}
                      style={{
                        background: reportFormat === fmt.id ? 'var(--color-dast-dim)' : 'var(--color-bg-elevated)',
                        border: `1px solid ${reportFormat === fmt.id ? 'var(--color-dast)' : 'var(--color-border)'}`,
                        padding: '14px 16px',
                        cursor: 'pointer',
                        textAlign: 'center',
                      }}
                    >
                      <div className="mono" style={{ fontSize: 14, fontWeight: 700, color: reportFormat === fmt.id ? 'var(--color-dast)' : 'var(--color-text-primary)', letterSpacing: '0.1em', marginBottom: 4 }}>
                        {fmt.label}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                        {fmt.desc}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Selected Scan Summary */}
                {reportScan && (
                  <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', padding: 16, marginBottom: 20 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>{reportScan.name}</div>
                        <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 2 }}>{reportScan.targetUrl}</div>
                      </div>
                      <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: riskColor(reportScan.riskScore) }}>
                        {reportScan.riskScore}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 12 }}>
                      <span className="label-tag sev-critical">C: {reportScan.criticalCount ?? 0}</span>
                      <span className="label-tag sev-high">H: {reportScan.highCount ?? 0}</span>
                      <span className="label-tag sev-medium">M: {reportScan.mediumCount ?? 0}</span>
                      <span className="label-tag sev-low">L: {reportScan.lowCount ?? 0}</span>
                      <span className="label-tag sev-info">I: {reportScan.infoCount ?? 0}</span>
                    </div>
                  </div>
                )}

                {/* Generate Button */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <button
                    onClick={handleGenerateReport}
                    disabled={!reportScanId || reportGenerating}
                    style={{
                      background: (!reportScanId || reportGenerating) ? 'var(--color-bg-elevated)' : 'var(--color-dast)',
                      color: (!reportScanId || reportGenerating) ? 'var(--color-text-dim)' : '#fff',
                      border: 'none',
                      padding: '10px 28px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 11,
                      fontWeight: 700,
                      letterSpacing: '0.12em',
                      textTransform: 'uppercase',
                      cursor: (!reportScanId || reportGenerating) ? 'not-allowed' : 'pointer',
                    }}
                  >
                    {reportGenerating ? 'GENERATING...' : 'GENERATE REPORT'}
                  </button>
                  {reportSuccess && (
                    <div className="mono" style={{ fontSize: 11, color: 'var(--color-scanner)' }}>
                      {reportSuccess}
                    </div>
                  )}
                  {reportError && (
                    <div className="mono" style={{ fontSize: 11, color: 'var(--color-critical)' }}>
                      {reportError}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Attack Chains Panel ────────────────────────────────────────────────────

function AttackChainsPanel({ correlationData, scanFindings }: {
  correlationData: { attackChains?: Array<{ chainId: string; name: string; description: string; severity: string; findingIndices: number[]; exploitationSteps: string[]; businessImpact: string; likelihoodOfExploitation: string }>; duplicateGroups?: Array<{ reason: string; findingIndices: number[]; recommendedAction: string }>; riskAmplifiers?: Array<{ description: string; affectedFindings: number[]; amplificationFactor: number }>; overallChainedRiskScore?: number } | null
  scanFindings: DastFinding[]
}) {
  if (!correlationData) {
    return (
      <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-dim)' }}>
        <div style={{ fontSize: 14, marginBottom: 8 }}>No attack chain analysis available</div>
        <div className="mono" style={{ fontSize: 11 }}>Run a scan with AI enrichment to generate attack chain correlation.</div>
      </div>
    )
  }

  return (
    <div>
      {/* Overall Score */}
      {correlationData.overallChainedRiskScore !== undefined && (
        <div className="bracket-card bracket-dast" style={{ padding: '14px 18px', marginBottom: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)' }}>CHAINED RISK SCORE</div>
            <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginTop: 2 }}>Combined risk considering attack chain amplification</div>
          </div>
          <div className="mono" style={{ fontSize: 28, fontWeight: 700, color: riskColor(correlationData.overallChainedRiskScore) }}>
            {correlationData.overallChainedRiskScore}
          </div>
        </div>
      )}

      {/* Attack Chains */}
      {correlationData.attackChains && correlationData.attackChains.length > 0 && (
        <>
          <SectionLabel label="ATTACK CHAINS" />
          {correlationData.attackChains.map((chain) => (
            <div key={chain.chainId} className="bracket-card" style={{ padding: 16, marginBottom: 12, borderColor: chain.severity === 'CRITICAL' ? 'var(--color-critical)' : chain.severity === 'HIGH' ? 'var(--color-high)' : 'var(--color-medium)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>{chain.name}</div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                    <span className={`label-tag sev-${chain.severity.toLowerCase()}`}>{chain.severity}</span>
                    <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
                      Likelihood: {chain.likelihoodOfExploitation}
                    </span>
                  </div>
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 12 }}>{chain.description}</div>

              {/* Exploitation Steps */}
              <div className="mono" style={{ fontSize: 10, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 6 }}>EXPLOITATION PATH</div>
              <div style={{ background: 'var(--color-bg-elevated)', padding: 12, marginBottom: 12 }}>
                {chain.exploitationSteps.map((step, idx) => (
                  <div key={idx} style={{ display: 'flex', gap: 8, marginBottom: 6, alignItems: 'flex-start' }}>
                    <span className="mono" style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-dast)', minWidth: 18 }}>{idx + 1}.</span>
                    <span style={{ fontSize: 11, color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>{step}</span>
                  </div>
                ))}
              </div>

              {/* Involved Findings */}
              <div className="mono" style={{ fontSize: 10, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 6 }}>INVOLVED FINDINGS</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                {chain.findingIndices.map(idx => {
                  const f = scanFindings[idx]
                  return f ? (
                    <span key={idx} className="mono" style={{ fontSize: 10, background: 'var(--color-bg-elevated)', padding: '2px 8px', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border)' }}>
                      {f.title.length > 40 ? f.title.substring(0, 40) + '...' : f.title}
                    </span>
                  ) : null
                })}
              </div>

              {/* Business Impact */}
              <div style={{ fontSize: 12, color: 'var(--color-medium)', fontStyle: 'italic', background: 'var(--color-bg-elevated)', padding: '8px 12px' }}>
                {chain.businessImpact}
              </div>
            </div>
          ))}
        </>
      )}

      {/* Risk Amplifiers */}
      {correlationData.riskAmplifiers && correlationData.riskAmplifiers.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <SectionLabel label="RISK AMPLIFIERS" />
          {correlationData.riskAmplifiers.map((amp, i) => (
            <div key={i} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: '12px 14px', marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', flex: 1 }}>{amp.description}</div>
                <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: 'var(--color-high)', marginLeft: 12 }}>
                  x{amp.amplificationFactor.toFixed(1)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Duplicate Groups */}
      {correlationData.duplicateGroups && correlationData.duplicateGroups.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <SectionLabel label="DUPLICATE / RELATED FINDINGS" />
          {correlationData.duplicateGroups.map((dup, i) => (
            <div key={i} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: '12px 14px', marginBottom: 8 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 6 }}>{dup.reason}</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {dup.findingIndices.map(idx => (
                    <span key={idx} className="mono" style={{ fontSize: 10, background: 'var(--color-bg-elevated)', padding: '1px 6px', color: 'var(--color-text-dim)' }}>
                      #{idx}
                    </span>
                  ))}
                </div>
                <span className="mono" style={{ fontSize: 10, fontWeight: 600, color: 'var(--color-dast)', letterSpacing: '0.08em' }}>
                  {dup.recommendedAction}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Compliance Panel ───────────────────────────────────────────────────────

function CompliancePanel({ complianceData }: {
  complianceData: { frameworks?: Array<{ name: string; overallStatus: string; controlsAffected: number; totalControlsChecked: number; affectedControls: Array<{ framework: string; controlId: string; controlName: string; status: string; findingIndices: number[]; remediationNote: string }> }>; highestRiskFramework?: string; complianceScore?: number; auditReadiness?: string; keyGaps?: string[] } | null
}) {
  if (!complianceData) {
    return (
      <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-dim)' }}>
        <div style={{ fontSize: 14, marginBottom: 8 }}>No compliance analysis available</div>
        <div className="mono" style={{ fontSize: 11 }}>Run a scan with AI enrichment to generate compliance mapping.</div>
      </div>
    )
  }

  const statusColors: Record<string, string> = {
    CRITICAL_GAPS: 'var(--color-critical)',
    SIGNIFICANT_GAPS: 'var(--color-high)',
    MINOR_GAPS: 'var(--color-medium)',
    PASSING: 'var(--color-scanner)',
  }

  const auditColors: Record<string, string> = {
    NOT_READY: 'var(--color-critical)',
    NEEDS_WORK: 'var(--color-high)',
    MOSTLY_READY: 'var(--color-medium)',
    READY: 'var(--color-scanner)',
  }

  const controlStatusColors: Record<string, string> = {
    FAIL: 'var(--color-critical)',
    AT_RISK: 'var(--color-high)',
    NEEDS_REVIEW: 'var(--color-medium)',
  }

  return (
    <div>
      {/* Top-level metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
        {complianceData.complianceScore !== undefined && (
          <div className="bracket-card bracket-dast" style={{ padding: '14px 18px', textAlign: 'center' }}>
            <div className="mono" style={{ fontSize: 28, fontWeight: 700, color: riskColor(100 - complianceData.complianceScore) }}>
              {complianceData.complianceScore}%
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>Compliance Score</div>
          </div>
        )}
        {complianceData.auditReadiness && (
          <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: '14px 18px', textAlign: 'center' }}>
            <div className="mono" style={{ fontSize: 14, fontWeight: 700, color: auditColors[complianceData.auditReadiness] ?? 'var(--color-text-secondary)' }}>
              {complianceData.auditReadiness.replace(/_/g, ' ')}
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>Audit Readiness</div>
          </div>
        )}
        {complianceData.highestRiskFramework && (
          <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: '14px 18px', textAlign: 'center' }}>
            <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-high)' }}>
              {complianceData.highestRiskFramework}
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>Highest Risk Framework</div>
          </div>
        )}
      </div>

      {/* Frameworks */}
      {complianceData.frameworks && complianceData.frameworks.map((fw) => (
        <div key={fw.name} className="bracket-card" style={{ padding: 16, marginBottom: 14, borderColor: statusColors[fw.overallStatus] ?? 'var(--color-border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>{fw.name}</div>
              <div className="mono" style={{ fontSize: 10, color: statusColors[fw.overallStatus] ?? 'var(--color-text-dim)', marginTop: 2, fontWeight: 600, letterSpacing: '0.08em' }}>
                {fw.overallStatus.replace(/_/g, ' ')}
              </div>
            </div>
            <div className="mono" style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--color-text-primary)' }}>
                {fw.controlsAffected}<span style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>/{fw.totalControlsChecked}</span>
              </div>
              <div style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>Controls Affected</div>
            </div>
          </div>

          {/* Affected Controls */}
          {fw.affectedControls && fw.affectedControls.length > 0 && (
            <div style={{ background: 'var(--color-bg-elevated)', padding: 12 }}>
              {fw.affectedControls.map((ctrl) => (
                <div key={ctrl.controlId} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '6px 0', borderBottom: '1px solid var(--color-border)' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span className="mono" style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-dast)' }}>{ctrl.controlId}</span>
                      <span style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>{ctrl.controlName}</span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>{ctrl.remediationNote}</div>
                  </div>
                  <span className="mono" style={{ fontSize: 9, fontWeight: 700, color: controlStatusColors[ctrl.status] ?? 'var(--color-text-dim)', marginLeft: 8, letterSpacing: '0.08em' }}>
                    {ctrl.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      {/* Key Gaps */}
      {complianceData.keyGaps && complianceData.keyGaps.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <SectionLabel label="KEY COMPLIANCE GAPS" />
          <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: 14 }}>
            {complianceData.keyGaps.map((gap, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'flex-start' }}>
                <span className="mono" style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-high)', minWidth: 18 }}>{i + 1}.</span>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>{gap}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Finding Detail (Inline Expansion) ──────────────────────────────────────

function FindingDetail({ finding, onClose }: { finding: DastFinding; onClose: () => void }) {
  let remCode: { vulnerableCode?: string; remediatedCode?: string; explanation?: string; language?: string; framework?: string; configurationFix?: string; securityHeaders?: string; wafRule?: string } | null = null
  if (finding.remediationCode) {
    try { remCode = JSON.parse(finding.remediationCode) } catch { /* skip */ }
  }

  let aiData: { attackScenario?: string; falsePositiveLikelihood?: string; falsePositiveReason?: string; priorityScore?: number; priorityReason?: string; relatedCwes?: string[]; mitigationUrgency?: string; dataAtRisk?: string; exploitDifficulty?: string } | null = null
  if (finding.aiEnrichmentData) {
    try { aiData = JSON.parse(finding.aiEnrichmentData) } catch { /* skip */ }
  }

  return (
    <div style={{ padding: '20px 18px', background: 'var(--color-bg-surface)', borderBottom: '2px solid var(--color-dast)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--color-text-primary)', lineHeight: 1.3 }}>{finding.title}</div>
          <div style={{ display: 'flex', gap: 8, marginTop: 6, flexWrap: 'wrap' }}>
            <span className={`label-tag sev-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
            {finding.cvssScore && (
              <span className="mono" style={{ fontSize: 10, color: cvssColor(finding.cvssScore), fontWeight: 600 }}>
                CVSS {finding.cvssScore}
              </span>
            )}
            <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{finding.owaspCategory}</span>
          </div>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 16 }}>&#x2715;</button>
      </div>

      {/* AI Priority & Urgency */}
      {aiData && (aiData.priorityScore || aiData.mitigationUrgency) && (
        <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
          {aiData.priorityScore && (
            <div style={{ background: 'var(--color-bg-elevated)', padding: '8px 14px', textAlign: 'center', flex: 1 }}>
              <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: riskColor(aiData.priorityScore) }}>{aiData.priorityScore}</div>
              <div style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>AI Priority</div>
            </div>
          )}
          {aiData.mitigationUrgency && (
            <div style={{ background: 'var(--color-bg-elevated)', padding: '8px 14px', textAlign: 'center', flex: 1 }}>
              <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: aiData.mitigationUrgency === 'IMMEDIATE' ? 'var(--color-critical)' : aiData.mitigationUrgency === 'HIGH' ? 'var(--color-high)' : 'var(--color-medium)' }}>
                {aiData.mitigationUrgency}
              </div>
              <div style={{ fontSize: 9, color: 'var(--color-text-dim)', marginTop: 2 }}>Urgency</div>
            </div>
          )}
          {aiData.exploitDifficulty && (
            <div style={{ background: 'var(--color-bg-elevated)', padding: '8px 14px', textAlign: 'center', flex: 1 }}>
              <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: 'var(--color-text-secondary)' }}>{aiData.exploitDifficulty}</div>
              <div style={{ fontSize: 9, color: 'var(--color-text-dim)', marginTop: 2 }}>Exploit Difficulty</div>
            </div>
          )}
        </div>
      )}

      {/* Meta */}
      <div style={{ background: 'var(--color-bg-elevated)', padding: '10px 12px', marginBottom: 14, fontSize: 11 }}>
        <div style={{ color: 'var(--color-text-dim)', marginBottom: 4 }}>
          <strong style={{ color: 'var(--color-text-secondary)' }}>URL:</strong> <span style={{ color: 'var(--color-dast)', wordBreak: 'break-all' }}>{finding.affectedUrl}</span>
        </div>
        {finding.affectedParameter && (
          <div style={{ color: 'var(--color-text-dim)' }}>
            <strong style={{ color: 'var(--color-text-secondary)' }}>Parameter:</strong> <span className="mono" style={{ color: 'var(--color-dast)' }}>{finding.affectedParameter}</span>
          </div>
        )}
        {finding.cweId && (
          <div style={{ color: 'var(--color-text-dim)', marginTop: 4 }}>
            <strong style={{ color: 'var(--color-text-secondary)' }}>CWE:</strong> {finding.cweId}
          </div>
        )}
      </div>

      {/* AI Attack Scenario */}
      {aiData?.attackScenario && (
        <>
          <SectionLabel label="ATTACK SCENARIO" />
          <div style={{ fontSize: 12, color: 'var(--color-high)', lineHeight: 1.7, marginBottom: 14, background: 'var(--color-bg-elevated)', padding: '10px 12px' }}>
            {aiData.attackScenario}
          </div>
        </>
      )}

      {/* AI Data at Risk */}
      {aiData?.dataAtRisk && (
        <>
          <SectionLabel label="DATA AT RISK" />
          <div style={{ fontSize: 12, color: 'var(--color-critical)', lineHeight: 1.7, marginBottom: 14, background: 'var(--color-bg-elevated)', padding: '10px 12px' }}>
            {aiData.dataAtRisk}
          </div>
        </>
      )}

      {/* False Positive Assessment */}
      {aiData?.falsePositiveLikelihood && (
        <>
          <SectionLabel label="FALSE POSITIVE ASSESSMENT" />
          <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 14, background: 'var(--color-bg-elevated)', padding: '10px 12px' }}>
            <span className="mono" style={{ fontWeight: 600, color: aiData.falsePositiveLikelihood === 'LOW' ? 'var(--color-scanner)' : aiData.falsePositiveLikelihood === 'MEDIUM' ? 'var(--color-medium)' : 'var(--color-high)' }}>
              {aiData.falsePositiveLikelihood}
            </span>
            {aiData.falsePositiveReason && <span style={{ marginLeft: 8 }}>{aiData.falsePositiveReason}</span>}
          </div>
        </>
      )}

      {/* Description */}
      <SectionLabel label="DESCRIPTION" />
      <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 16 }}>{finding.description}</div>

      {/* Business Impact */}
      {finding.businessImpact && (
        <>
          <SectionLabel label="BUSINESS IMPACT" />
          <div style={{ fontSize: 12, color: 'var(--color-medium)', lineHeight: 1.7, marginBottom: 16, background: 'var(--color-bg-elevated)', padding: '10px 12px' }}>
            {finding.businessImpact}
          </div>
        </>
      )}

      {/* Remediation */}
      <SectionLabel label="REMEDIATION" />
      <div style={{ fontSize: 12, color: 'var(--color-scanner)', lineHeight: 1.7, marginBottom: 16 }}>{finding.remediation}</div>

      {/* Remediation Code */}
      {remCode && (
        <>
          <SectionLabel label="CODE FIX" />
          <div style={{ marginBottom: 16 }}>
            {remCode.language && (
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <span className="mono" style={{ fontSize: 9, background: 'var(--color-dast-dim)', color: 'var(--color-dast)', padding: '2px 8px', letterSpacing: '0.08em' }}>
                  {remCode.language}
                </span>
                {remCode.framework && (
                  <span className="mono" style={{ fontSize: 9, background: 'var(--color-bg-elevated)', color: 'var(--color-text-dim)', padding: '2px 8px', letterSpacing: '0.08em' }}>
                    {remCode.framework}
                  </span>
                )}
              </div>
            )}
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-hemis)', marginBottom: 4, fontWeight: 600 }}>VULNERABLE:</div>
            <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 8 }}>
              <code className="terminal-error">{remCode.vulnerableCode}</code>
            </pre>
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-scanner)', marginBottom: 4, fontWeight: 600 }}>FIXED:</div>
            <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 8 }}>
              <code className="terminal-success">{remCode.remediatedCode}</code>
            </pre>
            {remCode.explanation && (
              <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontStyle: 'italic', marginBottom: 8 }}>{remCode.explanation}</div>
            )}

            {/* Configuration Fix */}
            {remCode.configurationFix && (
              <>
                <div className="mono" style={{ fontSize: 10, color: 'var(--color-dast)', marginBottom: 4, fontWeight: 600, marginTop: 10 }}>CONFIGURATION FIX:</div>
                <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 8 }}>
                  <code style={{ color: 'var(--color-text-secondary)' }}>{remCode.configurationFix}</code>
                </pre>
              </>
            )}

            {/* Security Headers */}
            {remCode.securityHeaders && (
              <>
                <div className="mono" style={{ fontSize: 10, color: 'var(--color-blueteam)', marginBottom: 4, fontWeight: 600, marginTop: 10 }}>SECURITY HEADERS:</div>
                <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 8 }}>
                  <code style={{ color: 'var(--color-text-secondary)' }}>{remCode.securityHeaders}</code>
                </pre>
              </>
            )}

            {/* WAF Rule */}
            {remCode.wafRule && (
              <>
                <div className="mono" style={{ fontSize: 10, color: 'var(--color-hemis)', marginBottom: 4, fontWeight: 600, marginTop: 10 }}>WAF RULE:</div>
                <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 8 }}>
                  <code style={{ color: 'var(--color-text-secondary)' }}>{remCode.wafRule}</code>
                </pre>
              </>
            )}
          </div>
        </>
      )}

      {/* Related CWEs from AI */}
      {aiData?.relatedCwes && aiData.relatedCwes.length > 0 && (
        <>
          <SectionLabel label="RELATED WEAKNESSES" />
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
            {aiData.relatedCwes.map((cwe) => (
              <span key={cwe} className="mono" style={{ fontSize: 10, background: 'var(--color-bg-elevated)', padding: '2px 8px', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border)' }}>
                {cwe}
              </span>
            ))}
          </div>
        </>
      )}

      {/* Compliance */}
      {(finding.pciDssRefs.length > 0 || finding.soc2Refs.length > 0 || finding.mitreAttackIds.length > 0) && (
        <>
          <SectionLabel label="COMPLIANCE REFERENCES" />
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
            {finding.pciDssRefs.map((r: string) => (
              <span key={r} className="label-tag" style={{ color: 'var(--color-dast)', borderColor: 'var(--color-dast)', background: 'var(--color-dast-dim)' }}>PCI {r}</span>
            ))}
            {finding.soc2Refs.map((r: string) => (
              <span key={r} className="label-tag" style={{ color: 'var(--color-blueteam)', borderColor: 'var(--color-blueteam)', background: 'var(--color-blueteam-dim)' }}>SOC2 {r}</span>
            ))}
            {finding.mitreAttackIds.map((r: string) => (
              <span key={r} className="label-tag" style={{ color: 'var(--color-hemis)', borderColor: 'var(--color-hemis)', background: 'var(--color-hemis-dim)' }}>ATT&CK {r}</span>
            ))}
          </div>
        </>
      )}

      {/* AI Priority Reason */}
      {aiData?.priorityReason && (
        <>
          <SectionLabel label="PRIORITY RATIONALE" />
          <div style={{ fontSize: 11, color: 'var(--color-text-dim)', lineHeight: 1.7, marginBottom: 16, fontStyle: 'italic' }}>
            {aiData.priorityReason}
          </div>
        </>
      )}

      {/* Payload */}
      {finding.payload && (
        <>
          <SectionLabel label="PAYLOAD" />
          <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 16 }}>
            <code className="terminal-accent">{finding.payload}</code>
          </pre>
        </>
      )}
    </div>
  )
}

// ─── Comparison Panel ────────────────────────────────────────────────────────

function ComparisonPanel({ scans, compBaselineId, compCurrentId, setCompBaselineId, setCompCurrentId, compResult, compLoading, runComparison }: {
  scans: DastScan[]
  compBaselineId: string
  compCurrentId: string
  setCompBaselineId: (id: string) => void
  setCompCurrentId: (id: string) => void
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  compResult: any
  compLoading: boolean
  runComparison: () => void
}) {
  const completedScans = scans.filter(s => s.status === 'COMPLETED')

  const trendColor = (dir: string) =>
    dir === 'improved' ? 'var(--color-scanner)' : dir === 'regressed' ? 'var(--color-critical)' : 'var(--color-text-dim)'

  return (
    <div>
      {/* Scan Selector */}
      <div className="bracket-card bracket-dast" style={{ padding: 16, marginBottom: 16 }}>
        <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)', marginBottom: 10 }}>
          SELECT SCANS TO COMPARE
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr auto', gap: 12, alignItems: 'end' }}>
          <div>
            <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>BASELINE (older)</label>
            <select className="tac-input" style={{ marginTop: 4 }} value={compBaselineId} onChange={e => setCompBaselineId(e.target.value)}>
              <option value="">Select scan...</option>
              {completedScans.map(s => (
                <option key={s.id} value={s.id}>{s.name} -- {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'}</option>
              ))}
            </select>
          </div>
          <div className="mono" style={{ fontSize: 14, color: 'var(--color-text-dim)', paddingBottom: 8 }}>vs</div>
          <div>
            <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>CURRENT (newer)</label>
            <select className="tac-input" style={{ marginTop: 4 }} value={compCurrentId} onChange={e => setCompCurrentId(e.target.value)}>
              <option value="">Select scan...</option>
              {completedScans.map(s => (
                <option key={s.id} value={s.id}>{s.name} -- {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'}</option>
              ))}
            </select>
          </div>
          <button
            onClick={runComparison}
            disabled={!compBaselineId || !compCurrentId || compBaselineId === compCurrentId || compLoading}
            style={{
              background: 'var(--color-dast)',
              color: '#fff',
              border: 'none',
              padding: '8px 20px',
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              cursor: (!compBaselineId || !compCurrentId || compBaselineId === compCurrentId) ? 'not-allowed' : 'pointer',
              opacity: (!compBaselineId || !compCurrentId || compBaselineId === compCurrentId) ? 0.5 : 1,
            }}
          >
            {compLoading ? 'COMPARING...' : 'COMPARE'}
          </button>
        </div>
      </div>

      {/* Mock scan comparison warning */}
      {compResult?._mockWarning && (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-dim)' }}>
          <div style={{ fontSize: 14, marginBottom: 8, color: 'var(--color-medium)' }}>Comparison requires scans stored in the database.</div>
          <div className="mono" style={{ fontSize: 11 }}>Mock scans are stored in-memory only. Run real scans with a connected database to enable comparison.</div>
        </div>
      )}

      {/* Comparison Results */}
      {compResult && !compResult._mockWarning && (
        <div>
          {/* Overall Trend */}
          <div className="bracket-card bracket-dast" style={{ padding: '14px 18px', marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)' }}>OVERALL TREND</div>
              <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginTop: 2 }}>{compResult.summary}</div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div className="mono" style={{
                fontSize: 24, fontWeight: 700,
                color: compResult.trendScore > 0 ? 'var(--color-scanner)' : compResult.trendScore < 0 ? 'var(--color-critical)' : 'var(--color-text-dim)',
              }}>
                {compResult.trendScore > 0 ? '+' : ''}{compResult.trendScore}
              </div>
              <div className="mono" style={{
                fontSize: 11, fontWeight: 700, letterSpacing: '0.08em',
                color: trendColor(compResult.overallTrend),
              }}>
                {compResult.overallTrend.toUpperCase()}
              </div>
            </div>
          </div>

          {/* Metric Deltas */}
          <SectionLabel label="METRIC CHANGES" />
          <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', marginBottom: 16 }}>
            <div className="mono" style={{
              display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 70px',
              padding: '8px 14px', borderBottom: '1px solid var(--color-border)',
              fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)',
            }}>
              <span>METRIC</span><span style={{ textAlign: 'right' }}>BASELINE</span><span style={{ textAlign: 'right' }}>CURRENT</span><span style={{ textAlign: 'right' }}>DELTA</span><span style={{ textAlign: 'right' }}>TREND</span>
            </div>
            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
            {compResult.deltas.map((d: any) => (
              <div key={d.metric} style={{
                display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 70px',
                padding: '8px 14px', borderBottom: '1px solid var(--color-border)', alignItems: 'center',
              }}>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{d.metric}</span>
                <span className="mono" style={{ fontSize: 12, color: 'var(--color-text-dim)', textAlign: 'right' }}>{d.baseline}</span>
                <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)', textAlign: 'right' }}>{d.current}</span>
                <span className="mono" style={{ fontSize: 12, fontWeight: 600, textAlign: 'right', color: trendColor(d.direction) }}>
                  {d.delta > 0 ? '+' : ''}{d.delta}
                </span>
                <span className="mono" style={{ fontSize: 9, fontWeight: 700, textAlign: 'right', letterSpacing: '0.08em', color: trendColor(d.direction) }}>
                  {d.direction === 'unchanged' ? '\u2014' : d.direction === 'improved' ? '\u25B2' : '\u25BC'} {d.percentage !== 0 ? `${Math.abs(d.percentage)}%` : ''}
                </span>
              </div>
            ))}
          </div>

          {/* New Findings */}
          {compResult.findingDiff.newFindings.length > 0 && (
            <>
              <SectionLabel label={`NEW FINDINGS (${compResult.findingDiff.newFindings.length})`} />
              <div style={{ marginBottom: 16 }}>
                {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                {compResult.findingDiff.newFindings.map((f: any) => (
                  <div key={f.id} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-critical)', borderLeft: '3px solid var(--color-critical)', padding: '10px 14px', marginBottom: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-primary)' }}>{f.title}</div>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 2 }}>{f.affectedUrl}</div>
                    </div>
                    <span className={`label-tag sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                  </div>
                ))}
              </div>
            </>
          )}

          {/* Resolved Findings */}
          {compResult.findingDiff.resolvedFindings.length > 0 && (
            <>
              <SectionLabel label={`RESOLVED FINDINGS (${compResult.findingDiff.resolvedFindings.length})`} />
              <div style={{ marginBottom: 16 }}>
                {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                {compResult.findingDiff.resolvedFindings.map((f: any) => (
                  <div key={f.id} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-scanner)', borderLeft: '3px solid var(--color-scanner)', padding: '10px 14px', marginBottom: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-primary)', textDecoration: 'line-through', opacity: 0.7 }}>{f.title}</div>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 2 }}>{f.affectedUrl}</div>
                    </div>
                    <span className="mono" style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-scanner)', letterSpacing: '0.08em' }}>RESOLVED</span>
                  </div>
                ))}
              </div>
            </>
          )}

          {/* Persistent Findings */}
          {compResult.findingDiff.persistentFindings.length > 0 && (
            <>
              <SectionLabel label={`PERSISTENT FINDINGS (${compResult.findingDiff.persistentFindings.length})`} />
              <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: 14, marginBottom: 16 }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                  {compResult.findingDiff.persistentFindings.map((f: any) => (
                    <span key={f.id} className="mono" style={{ fontSize: 10, background: 'var(--color-bg-elevated)', padding: '2px 8px', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border)' }}>
                      {f.title.length > 35 ? f.title.substring(0, 35) + '...' : f.title}
                    </span>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {!compResult && !compLoading && (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-dim)' }}>
          <div style={{ fontSize: 14, marginBottom: 8 }}>Select two scans to compare</div>
          <div className="mono" style={{ fontSize: 11 }}>Choose a baseline and current scan to see trends, new findings, and resolved issues.</div>
        </div>
      )}
    </div>
  )
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function SectionLabel({ label }: { label: string }) {
  return (
    <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.14em', color: 'var(--color-text-dim)', marginBottom: 6, textTransform: 'uppercase' }}>
      {label}
    </div>
  )
}

function riskColor(score: number): string {
  if (score >= 75) return 'var(--color-critical)'
  if (score >= 50) return 'var(--color-high)'
  if (score >= 25) return 'var(--color-medium)'
  return 'var(--color-scanner)'
}

function cvssColor(score: number | null): string {
  if (!score) return 'var(--color-text-dim)'
  if (score >= 9.0) return 'var(--color-critical)'
  if (score >= 7.0) return 'var(--color-high)'
  if (score >= 4.0) return 'var(--color-medium)'
  return 'var(--color-low)'
}
