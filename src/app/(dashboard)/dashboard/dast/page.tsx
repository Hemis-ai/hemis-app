'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import type { Severity, DastScan, DastFinding, DastScanProgress } from '@/lib/types'
import { MOCK_DAST_SCANS, MOCK_DAST_FINDINGS } from '@/lib/mock-data/dast'

// ─── Constants ──────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
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

type TabId = 'findings' | 'executive' | 'attack-chains' | 'compliance' | 'comparison' | 'schedules'
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
  const [scans, setScans] = useState<DastScan[]>(MOCK_DAST_SCANS)
  const [selectedScan, setSelectedScan] = useState<DastScan>(MOCK_DAST_SCANS[0])
  const [findings, setFindings] = useState<DastFinding[]>(MOCK_DAST_FINDINGS)
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<DastFinding | null>(null)
  const [activeTab, setActiveTab] = useState<TabId>('findings')
  const [showNewScan, setShowNewScan] = useState(false)
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

  // ── Schedules state ──
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [schedules, setSchedules] = useState<any[]>([])
  const [schedulesLoaded, setSchedulesLoaded] = useState(false)
  const [showNewSchedule, setShowNewSchedule] = useState(false)
  const [schedName, setSchedName] = useState('')
  const [schedUrl, setSchedUrl] = useState('')
  const [schedProfile, setSchedProfile] = useState('full')
  const [schedFrequency, setSchedFrequency] = useState('weekly')

  // ── Scan progress state ──
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState<DastScanProgress | null>(null)
  const progressRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

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
        if (data.scans?.length > 0) {
          setScans(data.scans)
          setSelectedScan(data.scans[0])
        }
      }
    } catch { /* fallback to mock data */ }
  }, [])

  // ── Fetch findings for selected scan ──
  const fetchFindings = useCallback(async (scanId: string) => {
    try {
      const res = await fetch(`/api/dast/findings?scanId=${scanId}`)
      if (res.ok) {
        const data = await res.json()
        if (data.findings?.length > 0) {
          setFindings((prev) => {
            const otherFindings = prev.filter((f) => f.scanId !== scanId)
            return [...otherFindings, ...data.findings]
          })
        }
      }
    } catch { /* fallback to mock data */ }
  }, [])

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
  }, [compBaselineId, compCurrentId])

  // ── Fetch schedules ──
  const fetchSchedules = useCallback(async () => {
    try {
      const res = await fetch('/api/dast/schedules')
      if (res.ok) {
        const data = await res.json()
        setSchedules(data.schedules ?? [])
        setSchedulesLoaded(true)
      }
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    fetchScans()
    return () => {
      if (progressRef.current) clearInterval(progressRef.current)
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [fetchScans])

  useEffect(() => {
    if (selectedScan) fetchFindings(selectedScan.id)
  }, [selectedScan, fetchFindings])

  const filteredFindings = findings
    .filter(f => f.scanId === selectedScan.id)
    .filter(f => severityFilter === 'ALL' || f.severity === severityFilter)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))

  const totalForScan = findings.filter(f => f.scanId === selectedScan.id).length

  // ── Start real scan via API ──
  async function startRealScan(name: string, targetUrl: string, scanProfile: string) {
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
        setShowNewScan(false)
        // Poll for progress
        pollRef.current = setInterval(async () => {
          try {
            const pollRes = await fetch(`/api/dast/scans/${newScan.id}`)
            if (pollRes.ok) {
              const pollData = await pollRes.json()
              const scan = pollData.scan
              const progress = pollData.progress
              if (progress) setScanProgress(progress)
              if (scan.status === 'COMPLETED' || scan.status === 'FAILED') {
                if (pollRef.current) clearInterval(pollRef.current)
                pollRef.current = null
                setTimeout(() => { setIsScanning(false); setScanProgress(null); fetchScans() }, 2000)
              }
            }
          } catch { /* ignore poll errors */ }
        }, 2000)
        return
      }
    } catch { /* fallback to mock scan */ }
    // Fallback: mock scan
    startMockScan()
  }

  // ── Simulated scan (fallback when API unavailable) ──
  function startMockScan() {
    setIsScanning(true)
    setShowNewScan(false)
    const phases = [
      { p: 5, phase: 'initializing', msg: 'Creating scan session...' },
      { p: 15, phase: 'crawling', msg: 'Spidering target...' },
      { p: 30, phase: 'crawling', msg: 'AJAX spider active...' },
      { p: 38, phase: 'crawling', msg: '87 endpoints discovered' },
      { p: 45, phase: 'auth_testing', msg: 'Testing authentication flows...' },
      { p: 52, phase: 'auth_testing', msg: 'Session management analysis...' },
      { p: 58, phase: 'scanning', msg: 'Active scan: 20%' },
      { p: 70, phase: 'scanning', msg: 'Active scan: 60%' },
      { p: 82, phase: 'scanning', msg: 'Active scan: 100%' },
      { p: 88, phase: 'extracting', msg: 'Extracting 14 alerts...' },
      { p: 92, phase: 'analyzing', msg: 'AI analyzing finding 3/14...' },
      { p: 96, phase: 'analyzing', msg: 'AI correlating attack chains...' },
      { p: 98, phase: 'summarizing', msg: 'Generating executive summary...' },
      { p: 100, phase: 'complete', msg: 'Scan completed' },
    ]
    let step = 0
    progressRef.current = setInterval(() => {
      if (step < phases.length) {
        const s = phases[step]
        setScanProgress({
          scanId: 'sim-live',
          status: s.p === 100 ? 'COMPLETED' : 'RUNNING',
          progress: s.p,
          currentPhase: s.phase,
          endpointsDiscovered: Math.round(s.p * 1.2),
          endpointsTested: Math.round(s.p * 0.9),
          payloadsSent: Math.round(s.p * 28),
          findingsCount: s.p > 85 ? 14 : 0,
          message: s.msg,
          timestamp: new Date().toISOString(),
        })
        step++
      } else {
        clearInterval(progressRef.current!)
        progressRef.current = null
        setTimeout(() => { setIsScanning(false); setScanProgress(null) }, 2000)
      }
    }, 1200)
  }

  // ── Parse AI data from selected scan ──
  let correlationData: { attackChains?: Array<{ chainId: string; name: string; description: string; severity: string; findingIndices: number[]; exploitationSteps: string[]; businessImpact: string; likelihoodOfExploitation: string }>; duplicateGroups?: Array<{ reason: string; findingIndices: number[]; recommendedAction: string }>; riskAmplifiers?: Array<{ description: string; affectedFindings: number[]; amplificationFactor: number }>; overallChainedRiskScore?: number } | null = null
  let complianceData: { frameworks?: Array<{ name: string; overallStatus: string; controlsAffected: number; totalControlsChecked: number; affectedControls: Array<{ framework: string; controlId: string; controlName: string; status: string; findingIndices: number[]; remediationNote: string }> }>; highestRiskFramework?: string; complianceScore?: number; auditReadiness?: string; keyGaps?: string[] } | null = null

  try { if (selectedScan.aiCorrelationData) correlationData = JSON.parse(selectedScan.aiCorrelationData) } catch { /* skip */ }
  try { if (selectedScan.aiComplianceData) complianceData = JSON.parse(selectedScan.aiComplianceData) } catch { /* skip */ }

  const scanFindings = findings.filter(f => f.scanId === selectedScan.id).sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))

  return (
    <div className="tac-grid" style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* ═══ Left: Main Content ═══ */}
      <div style={{ flex: 1, padding: '24px 28px', overflowY: 'auto' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div>
            <div className="display" style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text-primary)' }}>
              DAST Scanner
            </div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', letterSpacing: '0.08em', marginTop: 2 }}>
              Dynamic Application Security Testing &nbsp;·&nbsp; OWASP ZAP Engine
            </div>
          </div>
          <button
            onClick={() => setShowNewScan(true)}
            disabled={isScanning}
            style={{
              background: 'var(--color-dast)',
              color: '#fff',
              border: 'none',
              padding: '8px 20px',
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              fontWeight: 600,
              letterSpacing: '0.12em',
              textTransform: 'uppercase',
              cursor: isScanning ? 'not-allowed' : 'pointer',
              opacity: isScanning ? 0.5 : 1,
            }}
          >
            + NEW SCAN
          </button>
        </div>

        {/* ── New Scan Form ── */}
        {showNewScan && (
          <div className="bracket-card bracket-dast" style={{ padding: 20, marginBottom: 20 }}>
            <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-dast)', letterSpacing: '0.1em', marginBottom: 14 }}>
              NEW SCAN CONFIGURATION
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
              <div>
                <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>TARGET URL</label>
                <input className="tac-input" placeholder="https://example.com" style={{ marginTop: 4 }} value={newScanUrl} onChange={e => setNewScanUrl(e.target.value)} />
              </div>
              <div>
                <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SCAN NAME</label>
                <input className="tac-input" placeholder="My Web App Scan" style={{ marginTop: 4 }} value={newScanName} onChange={e => setNewScanName(e.target.value)} />
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 12, marginBottom: 16 }}>
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
                </div>
              ))}
            </div>

            {/* ── Advanced Configuration Toggle ── */}
            <div
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="mono"
              style={{
                fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-dast)',
                cursor: 'pointer', marginBottom: showAdvanced ? 14 : 0, userSelect: 'none',
              }}
            >
              {showAdvanced ? '▾' : '▸'} ADVANCED CONFIGURATION
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

            <div style={{ display: 'flex', gap: 10, marginTop: showAdvanced ? 0 : 16 }}>
              <button
                onClick={() => {
                  const name = newScanName.trim() || 'DAST Scan'
                  const url = newScanUrl.trim()
                  if (!url) return
                  startRealScan(name, url, newScanProfile)
                  setNewScanName(''); setNewScanUrl(''); setNewScanProfile('full')
                  setAuthType('none'); setShowAdvanced(false)
                }}
                disabled={!newScanUrl.trim()}
                style={{
                  background: 'var(--color-dast)',
                  color: '#fff',
                  border: 'none',
                  padding: '8px 24px',
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
                onClick={() => { setShowNewScan(false); setShowAdvanced(false) }}
                style={{
                  background: 'transparent',
                  color: 'var(--color-text-dim)',
                  border: '1px solid var(--color-border)',
                  padding: '8px 18px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  letterSpacing: '0.1em',
                  cursor: 'pointer',
                }}
              >
                CANCEL
              </button>
            </div>
          </div>
        )}

        {/* ── Live Scan Progress ── */}
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
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginTop: 14 }}>
              {[
                { label: 'Endpoints', value: scanProgress.endpointsDiscovered },
                { label: 'Tested', value: scanProgress.endpointsTested },
                { label: 'Payloads', value: scanProgress.payloadsSent },
                { label: 'Findings', value: scanProgress.findingsCount },
              ].map(m => (
                <div key={m.label} style={{ background: 'var(--color-bg-elevated)', padding: '8px 10px', textAlign: 'center' }}>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: 'var(--color-dast)' }}>{m.value}</div>
                  <div style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{m.label}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Scan Selector ── */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
          {scans.map(s => (
            <div
              key={s.id}
              onClick={() => { setSelectedScan(s); setSelectedFinding(null); setSeverityFilter('ALL'); setActiveTab('findings') }}
              style={{
                flex: 1,
                background: selectedScan.id === s.id ? 'var(--color-dast-dim)' : 'var(--color-bg-surface)',
                border: `1px solid ${selectedScan.id === s.id ? 'var(--color-dast)' : 'var(--color-border)'}`,
                padding: '12px 14px',
                cursor: 'pointer',
                transition: 'all 0.12s',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: selectedScan.id === s.id ? 'var(--color-dast)' : 'var(--color-text-secondary)', letterSpacing: '0.08em' }}>
                  {s.name}
                </span>
                <span className={`label-tag sev-${s.criticalCount > 0 ? 'critical' : s.highCount > 0 ? 'high' : 'medium'}`}>
                  {s.status}
                </span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 4 }}>{s.targetUrl}</div>
              {s.techStackDetected && s.techStackDetected.length > 0 && (
                <div style={{ display: 'flex', gap: 4, marginTop: 6, flexWrap: 'wrap' }}>
                  {s.techStackDetected.slice(0, 4).map(tech => (
                    <span key={tech} className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', background: 'var(--color-bg-elevated)', padding: '1px 6px', letterSpacing: '0.05em' }}>
                      {tech}
                    </span>
                  ))}
                  {s.techStackDetected.length > 4 && (
                    <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>+{s.techStackDetected.length - 4}</span>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* ── Score Cards ── */}
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

        {/* ── Tab Navigation ── */}
        <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid var(--color-border)' }}>
          {([
            { id: 'findings' as TabId, label: 'FINDINGS', count: totalForScan },
            { id: 'executive' as TabId, label: 'EXECUTIVE SUMMARY', count: null },
            { id: 'attack-chains' as TabId, label: 'ATTACK CHAINS', count: correlationData?.attackChains?.length ?? null },
            { id: 'compliance' as TabId, label: 'COMPLIANCE', count: complianceData?.frameworks?.length ?? null },
            { id: 'comparison' as TabId, label: 'COMPARE', count: null },
            { id: 'schedules' as TabId, label: 'SCHEDULES', count: null },
          ]).map(tab => (
            <button
              key={tab.id}
              onClick={() => { setActiveTab(tab.id); setSelectedFinding(null) }}
              className="mono"
              style={{
                background: 'transparent',
                border: 'none',
                borderBottom: activeTab === tab.id ? '2px solid var(--color-dast)' : '2px solid transparent',
                color: activeTab === tab.id ? 'var(--color-dast)' : 'var(--color-text-dim)',
                padding: '8px 16px',
                fontSize: 10,
                fontWeight: 600,
                letterSpacing: '0.1em',
                cursor: 'pointer',
                transition: 'all 0.12s',
              }}
            >
              {tab.label}{tab.count !== null ? ` (${tab.count})` : ''}
            </button>
          ))}
        </div>

        {/* ── Tab Content ── */}

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <>
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
                <div
                  key={f.id}
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
              ))}
            </div>
          </>
        )}

        {/* Executive Summary Tab */}
        {activeTab === 'executive' && (
          <div className="bracket-card bracket-dast" style={{ padding: 24 }}>
            {selectedScan.executiveSummary ? (
              <div>{renderMarkdown(selectedScan.executiveSummary)}</div>
            ) : (
              <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-dim)' }}>
                <div style={{ fontSize: 14, marginBottom: 8 }}>No executive summary available</div>
                <div className="mono" style={{ fontSize: 11 }}>Run a scan with AI enrichment enabled to generate an executive summary.</div>
              </div>
            )}
          </div>
        )}

        {/* Attack Chains Tab */}
        {activeTab === 'attack-chains' && (
          <AttackChainsPanel correlationData={correlationData} scanFindings={scanFindings} />
        )}

        {/* Compliance Tab */}
        {activeTab === 'compliance' && (
          <CompliancePanel complianceData={complianceData} />
        )}

        {/* Comparison Tab */}
        {activeTab === 'comparison' && (
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
        )}

        {/* Schedules Tab */}
        {activeTab === 'schedules' && (
          <SchedulesPanel
            schedules={schedules}
            schedulesLoaded={schedulesLoaded}
            fetchSchedules={fetchSchedules}
            showNewSchedule={showNewSchedule}
            setShowNewSchedule={setShowNewSchedule}
            schedName={schedName}
            setSchedName={setSchedName}
            schedUrl={schedUrl}
            setSchedUrl={setSchedUrl}
            schedProfile={schedProfile}
            setSchedProfile={setSchedProfile}
            schedFrequency={schedFrequency}
            setSchedFrequency={setSchedFrequency}
          />
        )}
      </div>

      {/* ═══ Right: Detail Panel ═══ */}
      <div style={{
        width: selectedFinding ? 440 : 0,
        minWidth: selectedFinding ? 440 : 0,
        borderLeft: selectedFinding ? '1px solid var(--color-border)' : 'none',
        background: 'var(--color-bg-surface)',
        overflowY: 'auto',
        transition: 'width 0.2s, min-width 0.2s',
      }}>
        {selectedFinding && <FindingDetail finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
      </div>
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

// ─── Finding Detail Panel ────────────────────────────────────────────────────

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
    <div style={{ padding: '20px 18px' }}>
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
                <option key={s.id} value={s.id}>{s.name} — {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'}</option>
              ))}
            </select>
          </div>
          <div className="mono" style={{ fontSize: 14, color: 'var(--color-text-dim)', paddingBottom: 8 }}>vs</div>
          <div>
            <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>CURRENT (newer)</label>
            <select className="tac-input" style={{ marginTop: 4 }} value={compCurrentId} onChange={e => setCompCurrentId(e.target.value)}>
              <option value="">Select scan...</option>
              {completedScans.map(s => (
                <option key={s.id} value={s.id}>{s.name} — {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'}</option>
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

      {/* Comparison Results */}
      {compResult && (
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
                  {d.direction === 'unchanged' ? '—' : d.direction === 'improved' ? '▲' : '▼'} {d.percentage !== 0 ? `${Math.abs(d.percentage)}%` : ''}
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

// ─── Schedules Panel ─────────────────────────────────────────────────────────

function SchedulesPanel({ schedules, schedulesLoaded, fetchSchedules, showNewSchedule, setShowNewSchedule, schedName, setSchedName, schedUrl, setSchedUrl, schedProfile, setSchedProfile, schedFrequency, setSchedFrequency }: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schedules: any[]
  schedulesLoaded: boolean
  fetchSchedules: () => void
  showNewSchedule: boolean
  setShowNewSchedule: (v: boolean) => void
  schedName: string
  setSchedName: (v: string) => void
  schedUrl: string
  setSchedUrl: (v: string) => void
  schedProfile: string
  setSchedProfile: (v: string) => void
  schedFrequency: string
  setSchedFrequency: (v: string) => void
}) {
  useEffect(() => {
    if (!schedulesLoaded) fetchSchedules()
  }, [schedulesLoaded, fetchSchedules])

  const statusColor = (s: string) =>
    s === 'active' ? 'var(--color-scanner)' : s === 'paused' ? 'var(--color-medium)' : 'var(--color-text-dim)'

  const freqLabel: Record<string, string> = {
    daily: 'Daily', weekly: 'Weekly', biweekly: 'Biweekly', monthly: 'Monthly', quarterly: 'Quarterly',
  }

  async function handleCreateSchedule() {
    if (!schedName.trim() || !schedUrl.trim()) return
    try {
      await fetch('/api/dast/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'create', name: schedName.trim(), targetUrl: schedUrl.trim(), scanProfile: schedProfile, frequency: schedFrequency }),
      })
      setShowNewSchedule(false)
      setSchedName(''); setSchedUrl(''); setSchedProfile('full'); setSchedFrequency('weekly')
      fetchSchedules()
    } catch { /* ignore */ }
  }

  async function toggleStatus(id: string, currentStatus: string) {
    const newStatus = currentStatus === 'active' ? 'paused' : 'active'
    try {
      await fetch('/api/dast/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'update', id, status: newStatus }),
      })
      fetchSchedules()
    } catch { /* ignore */ }
  }

  async function handleDelete(id: string) {
    try {
      await fetch('/api/dast/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete', id }),
      })
      fetchSchedules()
    } catch { /* ignore */ }
  }

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-secondary)', letterSpacing: '0.08em' }}>
            Recurring Scan Schedules
          </div>
          <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>
            Automated DAST scans run on configured intervals
          </div>
        </div>
        <button
          onClick={() => setShowNewSchedule(!showNewSchedule)}
          style={{
            background: 'var(--color-dast)', color: '#fff', border: 'none',
            padding: '6px 16px', fontFamily: 'var(--font-mono)', fontSize: 10,
            fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', cursor: 'pointer',
          }}
        >
          + NEW SCHEDULE
        </button>
      </div>

      {/* New Schedule Form */}
      {showNewSchedule && (
        <div className="bracket-card bracket-dast" style={{ padding: 16, marginBottom: 16 }}>
          <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-dast)', marginBottom: 12 }}>
            CREATE SCHEDULE
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SCHEDULE NAME</label>
              <input className="tac-input" placeholder="Production Weekly Scan" style={{ marginTop: 4 }} value={schedName} onChange={e => setSchedName(e.target.value)} />
            </div>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>TARGET URL</label>
              <input className="tac-input" placeholder="https://example.com" style={{ marginTop: 4 }} value={schedUrl} onChange={e => setSchedUrl(e.target.value)} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SCAN PROFILE</label>
              <select className="tac-input" style={{ marginTop: 4 }} value={schedProfile} onChange={e => setSchedProfile(e.target.value)}>
                <option value="full">Full Scan</option>
                <option value="quick">Quick Scan</option>
                <option value="api_only">API Only</option>
                <option value="deep">Deep Scan</option>
              </select>
            </div>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>FREQUENCY</label>
              <select className="tac-input" style={{ marginTop: 4 }} value={schedFrequency} onChange={e => setSchedFrequency(e.target.value)}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="biweekly">Every 2 Weeks</option>
                <option value="monthly">Monthly</option>
                <option value="quarterly">Quarterly</option>
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              onClick={handleCreateSchedule}
              disabled={!schedName.trim() || !schedUrl.trim()}
              style={{
                background: 'var(--color-dast)', color: '#fff', border: 'none',
                padding: '6px 18px', fontFamily: 'var(--font-mono)', fontSize: 10,
                fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase',
                cursor: (!schedName.trim() || !schedUrl.trim()) ? 'not-allowed' : 'pointer',
                opacity: (!schedName.trim() || !schedUrl.trim()) ? 0.5 : 1,
              }}
            >
              CREATE
            </button>
            <button
              onClick={() => setShowNewSchedule(false)}
              style={{
                background: 'transparent', color: 'var(--color-text-dim)', border: '1px solid var(--color-border)',
                padding: '6px 14px', fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.1em', cursor: 'pointer',
              }}
            >
              CANCEL
            </button>
          </div>
        </div>
      )}

      {/* Schedule List */}
      {schedules.length === 0 && schedulesLoaded && (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-dim)' }}>
          <div style={{ fontSize: 14, marginBottom: 8 }}>No schedules configured</div>
          <div className="mono" style={{ fontSize: 11 }}>Create a schedule to run automated recurring DAST scans.</div>
        </div>
      )}

      {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
      {schedules.map((sched: any) => (
        <div key={sched.id} className="bracket-card" style={{ padding: 16, marginBottom: 10, borderColor: statusColor(sched.status) }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>{sched.name}</span>
                <span className="mono" style={{ fontSize: 9, fontWeight: 700, color: statusColor(sched.status), letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  {sched.status}
                </span>
              </div>
              <div className="mono" style={{ fontSize: 11, color: 'var(--color-dast)', marginBottom: 6 }}>{sched.targetUrl}</div>
              <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--color-text-dim)' }}>
                <span><strong style={{ color: 'var(--color-text-secondary)' }}>Profile:</strong> {sched.scanProfile}</span>
                <span><strong style={{ color: 'var(--color-text-secondary)' }}>Frequency:</strong> {freqLabel[sched.frequency] ?? sched.frequency}</span>
                <span><strong style={{ color: 'var(--color-text-secondary)' }}>Runs:</strong> {sched.totalRuns}</span>
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--color-text-dim)', marginTop: 4 }}>
                <span><strong style={{ color: 'var(--color-text-secondary)' }}>Next:</strong> {sched.nextRunAt ? new Date(sched.nextRunAt).toLocaleString() : 'N/A'}</span>
                <span><strong style={{ color: 'var(--color-text-secondary)' }}>Last:</strong> {sched.lastRunAt ? new Date(sched.lastRunAt).toLocaleString() : 'Never'}</span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => toggleStatus(sched.id, sched.status)}
                className="mono"
                style={{
                  background: 'transparent', border: '1px solid var(--color-border)',
                  color: sched.status === 'active' ? 'var(--color-medium)' : 'var(--color-scanner)',
                  padding: '4px 10px', fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', cursor: 'pointer',
                }}
              >
                {sched.status === 'active' ? 'PAUSE' : 'RESUME'}
              </button>
              <button
                onClick={() => handleDelete(sched.id)}
                className="mono"
                style={{
                  background: 'transparent', border: '1px solid var(--color-border)',
                  color: 'var(--color-critical)', padding: '4px 10px', fontSize: 9,
                  fontWeight: 600, letterSpacing: '0.08em', cursor: 'pointer',
                }}
              >
                DELETE
              </button>
            </div>
          </div>
        </div>
      ))}
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
