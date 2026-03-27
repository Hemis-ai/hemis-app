'use client'

import { useState, useEffect, useCallback } from 'react'
import type { DastScan } from '@/lib/types'

// ─── Types ──────────────────────────────────────────────────────────────────

type ReportFormat = 'pdf' | 'json' | 'csv'
type ReportTab = 'generate' | 'history' | 'comparison'

interface ReportHistoryEntry {
  id: string
  scanId: string
  scanName: string
  format: ReportFormat
  generatedAt: string
  fileSize: string
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [activeTab, setActiveTab] = useState<ReportTab>('generate')
  const [scans, setScans] = useState<DastScan[]>([])
  const [selectedScanId, setSelectedScanId] = useState<string>('')
  const [selectedFormat, setSelectedFormat] = useState<ReportFormat>('pdf')
  const [generating, setGenerating] = useState(false)
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null)
  const [reportError, setReportError] = useState<string | null>(null)
  const [reportGenerated, setReportGenerated] = useState(false)
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [reportHistory, setReportHistory] = useState<ReportHistoryEntry[]>([])

  // Comparison state
  const [compBaseId, setCompBaseId] = useState<string>('')
  const [compCurId, setCompCurId] = useState<string>('')
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [compResult, setCompResult] = useState<any>(null)
  const [compLoading, setCompLoading] = useState(false)

  const fetchScans = useCallback(async () => {
    try {
      const res = await fetch('/api/dast/scans')
      if (res.ok) {
        const data = await res.json()
        if (data.scans?.length > 0) setScans(data.scans)
      }
    } catch { /* API unavailable */ }
  }, [])

  useEffect(() => { fetchScans() }, [fetchScans])

  const completedScans = scans.filter(s => s.status === 'COMPLETED')

  async function generateReport() {
    if (!selectedScanId) return
    setGenerating(true)
    setDownloadUrl(null)
    setReportError(null)
    setReportGenerated(false)
    try {
      const res = await fetch(`/api/dast/reports/${selectedScanId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: selectedFormat }),
      })
      if (!res.ok) {
        let errorMsg = `Report generation failed (${res.status})`
        try {
          const errData = await res.json()
          if (errData.error) errorMsg = errData.error
        } catch { /* response was not JSON, use default message */ }
        setReportError(errorMsg)
      } else {
        const blob = await res.blob()
        const url = URL.createObjectURL(blob)
        setDownloadUrl(url)
        setReportGenerated(true)
      }
    } catch {
      setReportError('Network error: could not reach the report API.')
    }
    setGenerating(false)
  }

  async function runComparison() {
    if (!compBaseId || !compCurId || compBaseId === compCurId) return
    setCompLoading(true)
    setCompResult(null)
    try {
      const res = await fetch('/api/dast/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baselineScanId: compBaseId, currentScanId: compCurId }),
      })
      if (res.ok) {
        const data = await res.json()
        setCompResult(data.comparison)
      }
    } catch { /* ignore */ }
    setCompLoading(false)
  }

  const trendColor = (dir: string) =>
    dir === 'improved' ? 'var(--color-scanner)' : dir === 'regressed' ? 'var(--color-critical)' : 'var(--color-text-dim)'

  const formatIcon: Record<ReportFormat, string> = { pdf: 'PDF', json: 'JSON', csv: 'CSV' }
  const formatColor: Record<ReportFormat, string> = { pdf: 'var(--color-critical)', json: 'var(--color-scanner)', csv: 'var(--color-blueteam)' }

  return (
    <div style={{ padding: '24px 28px', overflowY: 'auto', height: '100%' }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 className="display" style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
          Reports & Analysis
        </h1>
        <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', margin: '4px 0 0' }}>
          Generate reports · Scan comparison · Trend analysis
        </p>
      </div>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--color-border)' }}>
        {([
          { id: 'generate' as ReportTab, label: 'Generate Report' },
          { id: 'history' as ReportTab, label: 'Report History' },
          { id: 'comparison' as ReportTab, label: 'Scan Comparison' },
        ]).map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--color-dast)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--color-dast)' : 'var(--color-text-secondary)',
              padding: '8px 18px',
              fontSize: 13,
              fontWeight: activeTab === tab.id ? 600 : 400,
              cursor: 'pointer',
              transition: 'all 0.12s',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Generate Report Tab ── */}
      {activeTab === 'generate' && (
        <div style={{ maxWidth: 800 }}>
          <div className="bracket-card bracket-dast" style={{ padding: 20, marginBottom: 20 }}>
            <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-dast)', letterSpacing: '0.1em', marginBottom: 16 }}>
              GENERATE DAST REPORT
            </div>

            {/* Scan Selector */}
            <div style={{ marginBottom: 16 }}>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>SELECT SCAN</label>
              <select className="tac-input" style={{ marginTop: 4 }} value={selectedScanId} onChange={e => setSelectedScanId(e.target.value)}>
                <option value="">Choose a completed scan...</option>
                {completedScans.map(s => (
                  <option key={s.id} value={s.id}>
                    {s.name} — {s.targetUrl} ({s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'})
                  </option>
                ))}
              </select>
            </div>

            {/* Format Selection */}
            <div style={{ marginBottom: 16 }}>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8, display: 'block' }}>FORMAT</label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                {(['pdf', 'json', 'csv'] as const).map(fmt => (
                  <div
                    key={fmt}
                    onClick={() => setSelectedFormat(fmt)}
                    style={{
                      background: selectedFormat === fmt ? 'var(--color-dast-dim)' : 'var(--color-bg-elevated)',
                      border: `1px solid ${selectedFormat === fmt ? 'var(--color-dast)' : 'var(--color-border)'}`,
                      padding: '14px',
                      cursor: 'pointer',
                      textAlign: 'center',
                    }}
                  >
                    <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: formatColor[fmt], marginBottom: 4 }}>
                      {formatIcon[fmt]}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                      {fmt === 'pdf' ? 'Full HTML report with charts' : fmt === 'json' ? 'Structured data export' : 'Spreadsheet-compatible'}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Selected Scan Summary */}
            {selectedScanId && (() => {
              const scan = scans.find(s => s.id === selectedScanId)
              if (!scan) return null
              return (
                <div style={{ background: 'var(--color-bg-elevated)', padding: 14, marginBottom: 16 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8, textAlign: 'center' }}>
                    {[
                      { label: 'Risk', value: scan.riskScore, color: scan.riskScore >= 75 ? 'var(--color-critical)' : scan.riskScore >= 50 ? 'var(--color-high)' : 'var(--color-medium)' },
                      { label: 'Critical', value: scan.criticalCount, color: 'var(--color-critical)' },
                      { label: 'High', value: scan.highCount, color: 'var(--color-high)' },
                      { label: 'Medium', value: scan.mediumCount, color: 'var(--color-medium)' },
                      { label: 'Low', value: scan.lowCount, color: 'var(--color-low)' },
                    ].map(m => (
                      <div key={m.label}>
                        <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: m.color }}>{m.value}</div>
                        <div style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>{m.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })()}

            {/* Generate Button */}
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <button
                onClick={generateReport}
                disabled={!selectedScanId || generating}
                style={{
                  background: 'var(--color-dast)', color: '#fff', border: 'none',
                  padding: '10px 28px', fontFamily: 'var(--font-mono)', fontSize: 11,
                  fontWeight: 600, letterSpacing: '0.12em', textTransform: 'uppercase',
                  cursor: !selectedScanId || generating ? 'not-allowed' : 'pointer',
                  opacity: !selectedScanId || generating ? 0.5 : 1,
                }}
              >
                {generating ? 'GENERATING...' : `GENERATE ${selectedFormat.toUpperCase()}`}
              </button>

              {downloadUrl && (
                <a
                  href={downloadUrl}
                  download={`hemisx-dast-report.${selectedFormat === 'pdf' ? 'html' : selectedFormat}`}
                  style={{
                    background: 'var(--color-scanner)', color: '#fff', border: 'none',
                    padding: '10px 20px', fontFamily: 'var(--font-mono)', fontSize: 11,
                    fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase',
                    textDecoration: 'none', display: 'inline-block',
                  }}
                >
                  DOWNLOAD
                </a>
              )}
            </div>

            {reportError && (
              <div className="mono" style={{
                marginTop: 12, padding: '10px 14px',
                background: 'rgba(255, 77, 106, 0.1)',
                border: '1px solid var(--color-critical)',
                color: 'var(--color-critical)',
                fontSize: 11, fontWeight: 500,
              }}>
                {reportError}
              </div>
            )}

            {reportGenerated && !reportError && (
              <div className="mono" style={{
                marginTop: 12, padding: '10px 14px',
                background: 'rgba(78, 205, 196, 0.1)',
                border: '1px solid var(--color-scanner)',
                color: 'var(--color-scanner)',
                fontSize: 11, fontWeight: 500,
              }}>
                Report generated successfully. Click DOWNLOAD to save the file.
              </div>
            )}
          </div>

          {/* Report Content Preview */}
          <div className="bracket-card" style={{ padding: 20, borderColor: 'var(--color-border)' }}>
            <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)', marginBottom: 12 }}>
              REPORT INCLUDES
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {[
                { title: 'Executive Summary', desc: 'AI-generated security posture overview' },
                { title: 'Severity Distribution', desc: 'Charts showing finding breakdown' },
                { title: 'Detailed Findings', desc: 'Each vulnerability with remediation' },
                { title: 'Compliance Mapping', desc: 'PCI DSS, SOC 2, HIPAA, GDPR' },
                { title: 'Attack Chains', desc: 'AI-correlated multi-step attack paths' },
                { title: 'Remediation Code', desc: 'Code fixes with before/after examples' },
                { title: 'Tech Stack', desc: 'Detected technologies and frameworks' },
                { title: 'Risk Score', desc: 'Quantified risk with gauge visualization' },
              ].map(item => (
                <div key={item.title} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--color-dast)', fontWeight: 700, marginTop: 2 }}>&#x2713;</span>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-primary)' }}>{item.title}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>{item.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Report History Tab ── */}
      {activeTab === 'history' && (
        <div style={{ maxWidth: 900 }}>
          {reportHistory.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 14, marginBottom: 8 }}>No reports generated yet</div>
              <div className="mono" style={{ fontSize: 11 }}>Generate a report from the Generate Report tab to see it here.</div>
            </div>
          ) : (
          <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
            <div className="mono" style={{
              display: 'grid', gridTemplateColumns: '1fr 120px 70px 180px 80px',
              padding: '8px 14px', borderBottom: '1px solid var(--color-border)',
              fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)',
            }}>
              <span>SCAN</span>
              <span>FORMAT</span>
              <span>SIZE</span>
              <span>GENERATED</span>
              <span></span>
            </div>

            {reportHistory.map(rpt => (
              <div key={rpt.id} style={{
                display: 'grid', gridTemplateColumns: '1fr 120px 70px 180px 80px',
                padding: '10px 14px', borderBottom: '1px solid var(--color-border)', alignItems: 'center',
              }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-primary)' }}>{rpt.scanName}</div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{rpt.scanId}</div>
                </div>
                <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: formatColor[rpt.format] }}>
                  {formatIcon[rpt.format]}
                </span>
                <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>{rpt.fileSize}</span>
                <span style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>
                  {new Date(rpt.generatedAt).toLocaleString()}
                </span>
                <button
                  className="mono"
                  style={{
                    background: 'transparent', border: '1px solid var(--color-border)',
                    color: 'var(--color-dast)', padding: '3px 10px', fontSize: 9,
                    fontWeight: 600, letterSpacing: '0.08em', cursor: 'pointer',
                  }}
                >
                  DOWNLOAD
                </button>
              </div>
            ))}
          </div>
          )}
        </div>
      )}

      {/* ── Comparison Tab ── */}
      {activeTab === 'comparison' && (
        <div style={{ maxWidth: 900 }}>
          {/* Scan Selector */}
          <div className="bracket-card bracket-dast" style={{ padding: 16, marginBottom: 16 }}>
            <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)', marginBottom: 10 }}>
              SELECT SCANS TO COMPARE
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr auto', gap: 12, alignItems: 'end' }}>
              <div>
                <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>BASELINE</label>
                <select className="tac-input" style={{ marginTop: 4 }} value={compBaseId} onChange={e => setCompBaseId(e.target.value)}>
                  <option value="">Select scan...</option>
                  {completedScans.map(s => (
                    <option key={s.id} value={s.id}>{s.name} — {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'}</option>
                  ))}
                </select>
              </div>
              <div className="mono" style={{ fontSize: 14, color: 'var(--color-text-dim)', paddingBottom: 8 }}>vs</div>
              <div>
                <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>CURRENT</label>
                <select className="tac-input" style={{ marginTop: 4 }} value={compCurId} onChange={e => setCompCurId(e.target.value)}>
                  <option value="">Select scan...</option>
                  {completedScans.map(s => (
                    <option key={s.id} value={s.id}>{s.name} — {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : 'N/A'}</option>
                  ))}
                </select>
              </div>
              <button
                onClick={runComparison}
                disabled={!compBaseId || !compCurId || compBaseId === compCurId || compLoading}
                style={{
                  background: 'var(--color-dast)', color: '#fff', border: 'none',
                  padding: '8px 20px', fontFamily: 'var(--font-mono)', fontSize: 10,
                  fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase',
                  cursor: (!compBaseId || !compCurId || compBaseId === compCurId) ? 'not-allowed' : 'pointer',
                  opacity: (!compBaseId || !compCurId || compBaseId === compCurId) ? 0.5 : 1,
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
              <div className="bracket-card bracket-dast" style={{ padding: '16px 20px', marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ flex: 1 }}>
                  <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)' }}>OVERALL TREND</div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginTop: 4, lineHeight: 1.6 }}>{compResult.summary}</div>
                </div>
                <div style={{ textAlign: 'right', marginLeft: 20 }}>
                  <div className="mono" style={{
                    fontSize: 28, fontWeight: 700,
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
              <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', marginBottom: 16 }}>
                <div className="mono" style={{
                  display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 80px',
                  padding: '8px 14px', borderBottom: '1px solid var(--color-border)',
                  fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', color: 'var(--color-text-dim)',
                }}>
                  <span>METRIC</span><span style={{ textAlign: 'right' }}>BASELINE</span><span style={{ textAlign: 'right' }}>CURRENT</span><span style={{ textAlign: 'right' }}>DELTA</span><span style={{ textAlign: 'right' }}>TREND</span>
                </div>
                {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                {compResult.deltas.map((d: any) => (
                  <div key={d.metric} style={{
                    display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 80px',
                    padding: '8px 14px', borderBottom: '1px solid var(--color-border)', alignItems: 'center',
                  }}>
                    <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{d.metric}</span>
                    <span className="mono" style={{ fontSize: 12, color: 'var(--color-text-dim)', textAlign: 'right' }}>{d.baseline}</span>
                    <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)', textAlign: 'right' }}>{d.current}</span>
                    <span className="mono" style={{ fontSize: 12, fontWeight: 600, textAlign: 'right', color: trendColor(d.direction) }}>
                      {d.delta > 0 ? '+' : ''}{d.delta}
                    </span>
                    <span className="mono" style={{ fontSize: 9, fontWeight: 700, textAlign: 'right', letterSpacing: '0.08em', color: trendColor(d.direction) }}>
                      {d.direction === 'unchanged' ? '—' : d.direction === 'improved' ? '▲ BETTER' : '▼ WORSE'}
                    </span>
                  </div>
                ))}
              </div>

              {/* Finding Changes Summary */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
                {[
                  { label: 'New', count: compResult.findingDiff.newFindings.length, color: 'var(--color-critical)' },
                  { label: 'Resolved', count: compResult.findingDiff.resolvedFindings.length, color: 'var(--color-scanner)' },
                  { label: 'Persistent', count: compResult.findingDiff.persistentFindings.length, color: 'var(--color-medium)' },
                  { label: 'Escalated', count: compResult.findingDiff.escalatedFindings.length, color: 'var(--color-high)' },
                ].map(m => (
                  <div key={m.label} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: '12px 14px', textAlign: 'center' }}>
                    <div className="mono" style={{ fontSize: 20, fontWeight: 700, color: m.color }}>{m.count}</div>
                    <div style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{m.label} Findings</div>
                  </div>
                ))}
              </div>

              {/* New Findings Detail */}
              {compResult.findingDiff.newFindings.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.14em', color: 'var(--color-critical)', marginBottom: 6 }}>
                    NEW FINDINGS ({compResult.findingDiff.newFindings.length})
                  </div>
                  {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                  {compResult.findingDiff.newFindings.map((f: any) => (
                    <div key={f.id} style={{ background: 'var(--color-bg-surface)', borderLeft: '3px solid var(--color-critical)', padding: '8px 14px', marginBottom: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 12, color: 'var(--color-text-primary)' }}>{f.title}</span>
                      <span className={`label-tag sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Resolved Findings Detail */}
              {compResult.findingDiff.resolvedFindings.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div className="mono" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.14em', color: 'var(--color-scanner)', marginBottom: 6 }}>
                    RESOLVED FINDINGS ({compResult.findingDiff.resolvedFindings.length})
                  </div>
                  {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                  {compResult.findingDiff.resolvedFindings.map((f: any) => (
                    <div key={f.id} style={{ background: 'var(--color-bg-surface)', borderLeft: '3px solid var(--color-scanner)', padding: '8px 14px', marginBottom: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 12, color: 'var(--color-text-primary)', textDecoration: 'line-through', opacity: 0.7 }}>{f.title}</span>
                      <span className="mono" style={{ fontSize: 9, fontWeight: 700, color: 'var(--color-scanner)' }}>RESOLVED</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {!compResult && !compLoading && (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 14, marginBottom: 8 }}>Select two scans to compare</div>
              <div className="mono" style={{ fontSize: 11 }}>See trends, new vulnerabilities, resolved issues, and metric changes between scan runs.</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
