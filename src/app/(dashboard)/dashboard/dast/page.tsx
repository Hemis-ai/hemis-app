'use client'

import { useState, useRef, useEffect } from 'react'
import type { Severity, DastScan, DastFinding, DastScanProgress } from '@/lib/types'
import { MOCK_DAST_SCANS, MOCK_DAST_FINDINGS } from '@/lib/mock-data/dast'

// ─── Constants ──────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const PHASE_LABELS: Record<string, string> = {
  initializing: 'Initializing',
  crawling: 'Crawling Endpoints',
  scanning: 'Active Scanning',
  extracting: 'Extracting Alerts',
  analyzing: 'AI Analysis',
  summarizing: 'Generating Summary',
  complete: 'Complete',
  failed: 'Failed',
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function DastPage() {
  const [scans] = useState<DastScan[]>(MOCK_DAST_SCANS)
  const [selectedScan, setSelectedScan] = useState<DastScan>(MOCK_DAST_SCANS[0])
  const [findings] = useState<DastFinding[]>(MOCK_DAST_FINDINGS)
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<DastFinding | null>(null)
  const [showNewScan, setShowNewScan] = useState(false)

  // ── Simulated scan progress state ──
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState<DastScanProgress | null>(null)
  const progressRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    return () => { if (progressRef.current) clearInterval(progressRef.current) }
  }, [])

  const filteredFindings = findings
    .filter(f => f.scanId === selectedScan.id)
    .filter(f => severityFilter === 'ALL' || f.severity === severityFilter)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))

  const totalForScan = findings.filter(f => f.scanId === selectedScan.id).length

  // ── Simulated scan ──
  function startMockScan() {
    setIsScanning(true)
    setShowNewScan(false)
    const phases = [
      { p: 5, phase: 'initializing', msg: 'Creating scan session...' },
      { p: 15, phase: 'crawling', msg: 'Spidering target...' },
      { p: 30, phase: 'crawling', msg: 'AJAX spider active...' },
      { p: 40, phase: 'crawling', msg: '87 endpoints discovered' },
      { p: 55, phase: 'scanning', msg: 'Active scan: 30%' },
      { p: 70, phase: 'scanning', msg: 'Active scan: 65%' },
      { p: 85, phase: 'scanning', msg: 'Active scan: 100%' },
      { p: 88, phase: 'extracting', msg: 'Extracting 14 alerts...' },
      { p: 92, phase: 'analyzing', msg: 'AI analyzing finding 3/14...' },
      { p: 96, phase: 'analyzing', msg: 'AI analyzing finding 12/14...' },
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
                <input className="tac-input" placeholder="https://example.com" style={{ marginTop: 4 }} />
              </div>
              <div>
                <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SCAN NAME</label>
                <input className="tac-input" placeholder="My Web App Scan" style={{ marginTop: 4 }} />
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 16 }}>
              {(['full', 'quick', 'api_only'] as const).map(profile => (
                <div
                  key={profile}
                  style={{
                    background: 'var(--color-bg-elevated)',
                    border: '1px solid var(--color-border)',
                    padding: '10px 14px',
                    cursor: 'pointer',
                    textAlign: 'center',
                  }}
                >
                  <div className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                    {profile.replace('_', ' ')}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>
                    {profile === 'full' ? 'Spider + Active Scan' : profile === 'quick' ? 'Top 10 checks' : 'API endpoints only'}
                  </div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button
                onClick={startMockScan}
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
                  cursor: 'pointer',
                }}
              >
                START SCAN
              </button>
              <button
                onClick={() => setShowNewScan(false)}
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
              onClick={() => { setSelectedScan(s); setSelectedFinding(null); setSeverityFilter('ALL') }}
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

        {/* ── Severity Filter ── */}
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

        {/* ── Findings Table ── */}
        <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
          {/* Header row */}
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
              <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: cvssColor(f.cvssScore) }}>{f.cvssScore ?? '—'}</span>
              <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>{f.confidenceScore}%</span>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ Right: Detail Panel ═══ */}
      <div style={{
        width: selectedFinding ? 420 : 0,
        minWidth: selectedFinding ? 420 : 0,
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

// ─── Finding Detail Panel ────────────────────────────────────────────────────

function FindingDetail({ finding, onClose }: { finding: DastFinding; onClose: () => void }) {
  let remCode: { vulnerableCode?: string; remediatedCode?: string; explanation?: string } | null = null
  if (finding.remediationCode) {
    try { remCode = JSON.parse(finding.remediationCode) } catch { /* skip */ }
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
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 16 }}>✕</button>
      </div>

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
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-hemis)', marginBottom: 4, fontWeight: 600 }}>VULNERABLE:</div>
            <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 8 }}>
              <code className="terminal-error">{remCode.vulnerableCode}</code>
            </pre>
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-scanner)', marginBottom: 4, fontWeight: 600 }}>FIXED:</div>
            <pre className="terminal" style={{ padding: '8px 10px', fontSize: 11, whiteSpace: 'pre-wrap', marginBottom: 8 }}>
              <code className="terminal-success">{remCode.remediatedCode}</code>
            </pre>
            {remCode.explanation && (
              <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontStyle: 'italic' }}>{remCode.explanation}</div>
            )}
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
