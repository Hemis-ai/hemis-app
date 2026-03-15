'use client'

import { useState, useEffect, useRef } from 'react'
import { MOCK_SCAN, MOCK_FINDINGS } from '@/lib/mock-data/scanner'
import type { ScanFinding, Severity } from '@/lib/types'

type Phase = 'idle' | 'scanning' | 'done' | 'report'

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const SCAN_STAGES = [
  'Connecting to AWS account 482910...',
  'Enumerating IAM users, roles and policies...',
  'Scanning S3 buckets for public access...',
  'Checking EC2 security groups and network ACLs...',
  'Auditing RDS instances for encryption...',
  'Inspecting Lambda execution roles...',
  'Reviewing CloudTrail and VPC Flow Logs...',
  'Running KMS key rotation checks...',
  'Mapping findings to SOC2 / ISO27001 controls...',
  'Generating AI risk scores...',
  'Scan complete.',
]

function SevBadge({ sev }: { sev: Severity }) {
  const cls = `label-tag sev-${sev.toLowerCase()}`
  return <span className={cls}>{sev}</span>
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? 'var(--color-hemis)' : score >= 60 ? 'var(--color-hemis-orange)' : score >= 40 ? 'var(--color-medium)' : 'var(--color-scanner)'
  return (
    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
      <div className="tac-progress" style={{ flex:1 }}>
        <div className="tac-progress-fill" style={{ width:`${score}%`, background:color }} />
      </div>
      <span className="mono" style={{ fontSize:11, color, width:28 }}>{score}</span>
    </div>
  )
}

export default function ScannerPage() {
  const [phase, setPhase]           = useState<Phase>('idle')
  const [progress, setProgress]     = useState(0)
  const [stageIdx, setStageIdx]     = useState(0)
  const [findings, setFindings]     = useState<ScanFinding[]>([])
  const [remediating, setRemediating] = useState<Set<string>>(new Set())
  const [remediated, setRemediated] = useState<Set<string>>(new Set())
  const [expanded, setExpanded]     = useState<string | null>(null)
  const [filter, setFilter]         = useState<Severity | 'ALL'>('ALL')
  const [reportVisible, setReportVisible] = useState(false)
  const logRef = useRef<HTMLDivElement>(null)

  async function startScan() {
    setPhase('scanning')
    setProgress(0)
    setFindings([])
    setStageIdx(0)

    // Animate progress + stages
    for (let i = 0; i <= 100; i++) {
      await new Promise(r => setTimeout(r, 38))
      setProgress(i)
      const idx = Math.floor((i / 100) * (SCAN_STAGES.length - 1))
      setStageIdx(idx)
    }

    // Reveal findings one by one
    setPhase('done')
    const sorted = [...MOCK_FINDINGS].sort((a, b) => b.riskScore - a.riskScore)
    for (const f of sorted) {
      await new Promise(r => setTimeout(r, 90))
      setFindings(prev => [...prev, f])
    }
  }

  async function remediateFinding(id: string) {
    setRemediating(prev => new Set(prev).add(id))
    await new Promise(r => setTimeout(r, 1200))
    setRemediating(prev => { const n=new Set(prev); n.delete(id); return n })
    setRemediated(prev => new Set(prev).add(id))
  }

  async function remediateAll() {
    const openIds = findings.filter(f => f.status === 'OPEN' && !remediated.has(f.id)).map(f => f.id)
    for (const id of openIds) {
      setRemediating(prev => new Set(prev).add(id))
      await new Promise(r => setTimeout(r, 300))
    }
    await new Promise(r => setTimeout(r, 1500))
    setRemediating(new Set())
    setRemediated(new Set(openIds))
  }

  const critCount   = findings.filter(f => f.severity==='CRITICAL').length
  const highCount   = findings.filter(f => f.severity==='HIGH').length
  const medCount    = findings.filter(f => f.severity==='MEDIUM').length
  const lowCount    = findings.filter(f => f.severity==='LOW').length
  const remediatedCount = remediated.size

  const filtered = filter === 'ALL' ? findings : findings.filter(f => f.severity === filter)

  return (
    <div style={{ display:'flex', height:'100%', minHeight:0 }}>

      {/* Main content */}
      <div style={{ flex:1, overflow:'auto', padding:'24px 24px 40px' }} className="tac-grid">

        {/* Header */}
        <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:24 }}>
          <div>
            <div className="mono" style={{ fontSize:11, letterSpacing:'0.15em', color:'var(--color-scanner)', textTransform:'uppercase', marginBottom:5 }}>
              [ CLOUD SECURITY POSTURE MANAGEMENT ]
            </div>
            <h1 className="display" style={{ fontSize:22, fontWeight:700, color:'var(--color-text-primary)', margin:0 }}>
              Cloud Scanner
            </h1>
            <p style={{ color:'var(--color-text-secondary)', margin:'4px 0 0', fontSize:13 }}>
              AWS account 482910 · us-east-1, us-west-2 · 247 resources
            </p>
          </div>

          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            {phase === 'done' && (
              <button onClick={() => setReportVisible(true)} style={{
                background:'transparent', border:'1px solid var(--color-scanner)',
                color:'var(--color-scanner)', padding:'9px 16px', cursor:'pointer',
                fontFamily:'var(--font-mono)', fontSize:11, letterSpacing:'0.12em', textTransform:'uppercase',
              }}>
                GENERATE REPORT ▤
              </button>
            )}
            <button
              onClick={startScan}
              disabled={phase==='scanning'}
              style={{
                background: phase==='scanning' ? 'var(--color-bg-elevated)' : 'var(--color-scanner)',
                color: phase==='scanning' ? 'var(--color-text-secondary)' : '#050a06',
                border:'none', padding:'10px 18px', cursor: phase==='scanning' ? 'not-allowed' : 'pointer',
                fontFamily:'var(--font-mono)', fontSize:11, fontWeight:600, letterSpacing:'0.12em', textTransform:'uppercase',
                transition:'all 0.15s',
              }}
            >
              {phase==='scanning' ? (
                <span style={{ display:'flex', alignItems:'center', gap:7 }}>
                  <span className="dot-live" style={{ width:5, height:5 }} />
                  SCANNING...
                </span>
              ) : phase==='done' ? '▶ RESCAN' : '▶ RUN SCAN'}
            </button>
          </div>
        </div>

        {/* Scanning progress */}
        {phase === 'scanning' && (
          <div className="bracket-card bracket-scanner fade-in-up" style={{ padding:'20px', marginBottom:20, position:'relative', overflow:'hidden' }}>
            <div className="scan-line" />
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:10 }}>
              <span className="mono" style={{ fontSize:11, color:'var(--color-scanner)', letterSpacing:'0.1em' }}>
                SCANNING AWS ENVIRONMENT
              </span>
              <span className="mono" style={{ fontSize:13, fontWeight:600, color:'var(--color-scanner)' }}>
                {progress}%
              </span>
            </div>
            <div className="tac-progress" style={{ height:4, marginBottom:12 }}>
              <div className="tac-progress-fill" style={{ width:`${progress}%`, background:'var(--color-scanner)' }} />
            </div>
            <div className="mono terminal-success" style={{ fontSize:12 }}>
              {SCAN_STAGES[stageIdx]}
            </div>
          </div>
        )}

        {/* Score cards — show after scan */}
        {(phase === 'done') && findings.length > 0 && (
          <div style={{ display:'grid', gridTemplateColumns:'repeat(5, 1fr)', gap:12, marginBottom:20 }} className="fade-in-up">
            {/* Risk score */}
            <div className="bracket-card" style={{ padding:'14px 16px', borderColor:'var(--color-hemis)' }}>
              <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:4 }}>RISK SCORE</div>
              <div className="mono" style={{ fontSize:26, fontWeight:700, color:'var(--color-hemis)' }}>{MOCK_SCAN.riskScore}</div>
              <div style={{ fontSize:11, color:'var(--color-text-secondary)' }}>/100</div>
            </div>
            {/* Finding counts */}
            {[
              { label:'CRITICAL', count:critCount,   color:'var(--color-critical)' },
              { label:'HIGH',     count:highCount,   color:'var(--color-high)'     },
              { label:'MEDIUM',   count:medCount,    color:'var(--color-medium)'   },
              { label:'LOW',      count:lowCount,    color:'var(--color-low)'      },
            ].map(s => (
              <div key={s.label} className="bracket-card" style={{ padding:'14px 16px' }}>
                <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:4 }}>{s.label}</div>
                <div className="mono" style={{ fontSize:26, fontWeight:700, color:s.count>0 ? s.color : 'var(--color-text-secondary)' }}>{s.count}</div>
                <div style={{ fontSize:11, color:'var(--color-text-secondary)' }}>findings</div>
              </div>
            ))}
          </div>
        )}

        {/* Findings table */}
        {findings.length > 0 && (
          <div className="bracket-card bracket-scanner" style={{ overflow:'hidden' }}>
            {/* Table header */}
            <div style={{
              display:'flex', alignItems:'center', justifyContent:'space-between',
              padding:'14px 18px', borderBottom:'1px solid var(--color-border)',
              background:'var(--color-bg-elevated)',
            }}>
              <div style={{ display:'flex', alignItems:'center', gap:12 }}>
                <span className="mono" style={{ fontSize:11, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase' }}>
                  FINDINGS ({findings.length})
                </span>
                {remediatedCount > 0 && (
                  <span className="mono" style={{ fontSize:10, color:'var(--color-scanner)', letterSpacing:'0.08em' }}>
                    · {remediatedCount} REMEDIATED
                  </span>
                )}
              </div>
              <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                {/* Filter buttons */}
                {(['ALL', ...SEV_ORDER] as (Severity|'ALL')[]).map(f => (
                  <button key={f} onClick={() => setFilter(f)} style={{
                    background: filter===f ? 'var(--color-bg-hover)' : 'transparent',
                    border:`1px solid ${filter===f ? 'var(--color-border-bright)' : 'var(--color-border)'}`,
                    color: filter===f ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
                    padding:'4px 10px', cursor:'pointer',
                    fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:'0.1em', textTransform:'uppercase',
                  }}>
                    {f}
                  </button>
                ))}
                {/* Remediate all */}
                {phase==='done' && (
                  <button onClick={remediateAll} style={{
                    background:'var(--color-scanner-dim)', border:'1px solid var(--color-scanner)',
                    color:'var(--color-scanner)', padding:'4px 12px', cursor:'pointer', marginLeft:8,
                    fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:'0.1em', textTransform:'uppercase',
                  }}>
                    AUTO-REMEDIATE ALL ✓
                  </button>
                )}
              </div>
            </div>

            {/* Column headers */}
            <div style={{
              display:'grid', gridTemplateColumns:'90px 70px 1fr 80px 90px',
              padding:'8px 18px', borderBottom:'1px solid var(--color-border)',
              background:'var(--color-bg-base)',
            }}>
              {['SEVERITY','SERVICE','FINDING','RISK','ACTION'].map(h => (
                <span key={h} className="mono" style={{ fontSize:10, letterSpacing:'0.14em', color:'var(--color-text-secondary)', textTransform:'uppercase' }}>
                  {h}
                </span>
              ))}
            </div>

            {/* Rows */}
            <div>
              {filtered.map((f, i) => {
                const isRem   = remediated.has(f.id)
                const isRem_  = remediating.has(f.id)
                const isExp   = expanded === f.id
                return (
                  <div key={f.id} style={{ borderBottom: i < filtered.length-1 ? '1px solid var(--color-border)' : 'none' }}>
                    {/* Main row */}
                    <div
                      onClick={() => setExpanded(isExp ? null : f.id)}
                      style={{
                        display:'grid', gridTemplateColumns:'90px 70px 1fr 80px 90px',
                        padding:'11px 18px', cursor:'pointer',
                        background: isRem ? 'rgba(0,232,138,0.04)' : isExp ? 'var(--color-bg-elevated)' : 'transparent',
                        transition:'background 0.15s',
                        opacity: isRem ? 0.65 : 1,
                      }}
                    >
                      <div style={{ display:'flex', alignItems:'center' }}>
                        <SevBadge sev={f.severity} />
                      </div>
                      <span className="mono" style={{ fontSize:12, color:'var(--color-text-secondary)', alignSelf:'center' }}>{f.service}</span>
                      <div style={{ alignSelf:'center', minWidth:0 }}>
                        <div style={{ fontSize:13, color: isRem ? 'var(--color-scanner)' : 'var(--color-text-primary)', fontWeight:500 }}>
                          {isRem && '✓ '}{f.title}
                        </div>
                        <div className="mono" style={{ fontSize:11, color:'var(--color-text-secondary)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', marginTop:1 }}>
                          {f.resource}
                        </div>
                      </div>
                      <div style={{ alignSelf:'center' }}>
                        <RiskBar score={f.riskScore} />
                      </div>
                      <div style={{ alignSelf:'center', display:'flex', justifyContent:'flex-end' }}>
                        {!isRem ? (
                          <button
                            onClick={e => { e.stopPropagation(); remediateFinding(f.id) }}
                            disabled={isRem_}
                            style={{
                              background:'transparent',
                              border:`1px solid ${isRem_ ? 'var(--color-border)' : 'var(--color-scanner)'}`,
                              color: isRem_ ? 'var(--color-text-secondary)' : 'var(--color-scanner)',
                              padding:'4px 10px', cursor: isRem_ ? 'not-allowed' : 'pointer',
                              fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:'0.1em', textTransform:'uppercase',
                            }}
                          >
                            {isRem_ ? '...' : 'FIX'}
                          </button>
                        ) : (
                          <span className="mono" style={{ fontSize:10, color:'var(--color-scanner)', letterSpacing:'0.1em' }}>✓ FIXED</span>
                        )}
                      </div>
                    </div>

                    {/* Expanded detail */}
                    {isExp && (
                      <div style={{
                        padding:'0 18px 16px 18px',
                        background:'var(--color-bg-elevated)',
                        borderTop:'1px solid var(--color-border)',
                      }} className="fade-in-up">
                        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, paddingTop:14 }}>
                          <div>
                            <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:5 }}>DESCRIPTION</div>
                            <p style={{ fontSize:13, color:'var(--color-text-primary)', margin:0, lineHeight:1.6 }}>{f.description}</p>
                          </div>
                          <div>
                            <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-scanner)', textTransform:'uppercase', marginBottom:5 }}>REMEDIATION</div>
                            <p style={{ fontSize:13, color:'var(--color-text-primary)', margin:0, lineHeight:1.6 }}>{f.remediation}</p>
                          </div>
                        </div>
                        <div style={{ marginTop:12, display:'flex', gap:6, flexWrap:'wrap' }}>
                          {f.compliance.map(c => (
                            <span key={c} className="label-tag" style={{ fontSize:10, color:'var(--color-text-secondary)', borderColor:'var(--color-border)' }}>{c}</span>
                          ))}
                          <span className="mono" style={{ fontSize:11, color:'var(--color-text-secondary)', marginLeft:4, alignSelf:'center' }}>
                            · {f.region} · {new Date(f.detectedAt).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Idle state */}
        {phase === 'idle' && (
          <div className="bracket-card" style={{ padding:'48px', textAlign:'center' }}>
            <div style={{ fontSize:32, marginBottom:12, color:'var(--color-scanner)', opacity:0.5 }}>◈</div>
            <div className="display" style={{ fontSize:17, color:'var(--color-text-primary)', marginBottom:8 }}>Ready to scan your AWS environment</div>
            <div className="mono" style={{ fontSize:12, color:'var(--color-text-secondary)' }}>
              Click "RUN SCAN" to start — scans complete in under 60 seconds
            </div>
          </div>
        )}
      </div>

      {/* Compliance report panel */}
      {reportVisible && (
        <div style={{
          width:360, borderLeft:'1px solid var(--color-border)',
          background:'var(--color-bg-surface)', overflow:'auto',
          padding:'20px', flexShrink:0,
        }} className="fade-in-up">
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
            <span className="mono" style={{ fontSize:11, letterSpacing:'0.15em', color:'var(--color-scanner)', textTransform:'uppercase' }}>
              COMPLIANCE REPORT
            </span>
            <button onClick={() => setReportVisible(false)} style={{
              background:'transparent', border:'none', cursor:'pointer',
              color:'var(--color-text-secondary)', fontSize:14,
            }}>✕</button>
          </div>

          {/* SOC2 */}
          <div className="bracket-card bracket-scanner" style={{ padding:'16px', marginBottom:12 }}>
            <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:10 }}>SOC 2 TYPE II</div>
            <div className="mono" style={{ fontSize:28, fontWeight:700, color:'var(--color-hemis-orange)', marginBottom:4 }}>
              {MOCK_SCAN.complianceScore.soc2}%
            </div>
            <div className="tac-progress" style={{ marginBottom:10 }}>
              <div className="tac-progress-fill" style={{ width:`${MOCK_SCAN.complianceScore.soc2}%`, background:'var(--color-hemis-orange)' }} />
            </div>
            {['CC6.1 — Logical & Physical Access','CC6.3 — User Registration','CC6.6 — Network Security','CC7.2 — Monitoring','CC9.1 — Risk Mitigation'].map((ctrl, i) => {
              const pass = [false, true, false, false, true][i]
              return (
                <div key={ctrl} style={{ display:'flex', gap:8, alignItems:'flex-start', marginBottom:6 }}>
                  <span style={{ color: pass ? 'var(--color-scanner)' : 'var(--color-hemis)', fontSize:10, flexShrink:0 }}>
                    {pass ? '✓' : '✕'}
                  </span>
                  <span style={{ fontSize:12, color:'var(--color-text-primary)' }}>{ctrl}</span>
                </div>
              )
            })}
          </div>

          {/* ISO 27001 */}
          <div className="bracket-card bracket-scanner" style={{ padding:'16px', marginBottom:12 }}>
            <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:10 }}>ISO/IEC 27001:2022</div>
            <div className="mono" style={{ fontSize:28, fontWeight:700, color:'var(--color-hemis-orange)', marginBottom:4 }}>
              {MOCK_SCAN.complianceScore.iso27001}%
            </div>
            <div className="tac-progress" style={{ marginBottom:10 }}>
              <div className="tac-progress-fill" style={{ width:`${MOCK_SCAN.complianceScore.iso27001}%`, background:'var(--color-hemis-orange)' }} />
            </div>
            {['A.9.1 — Access Control Policy','A.9.2 — User Access Management','A.10.1 — Cryptographic Controls','A.12.4 — Logging & Monitoring','A.13.1 — Network Security Mgmt'].map((ctrl, i) => {
              const pass = [false, false, false, false, true][i]
              return (
                <div key={ctrl} style={{ display:'flex', gap:8, alignItems:'flex-start', marginBottom:6 }}>
                  <span style={{ color: pass ? 'var(--color-scanner)' : 'var(--color-hemis)', fontSize:10, flexShrink:0 }}>
                    {pass ? '✓' : '✕'}
                  </span>
                  <span style={{ fontSize:12, color:'var(--color-text-primary)' }}>{ctrl}</span>
                </div>
              )
            })}
          </div>

          {/* Export */}
          <button style={{
            width:'100%', background:'var(--color-scanner)', color:'#050a06',
            border:'none', padding:'11px 0', cursor:'pointer',
            fontFamily:'var(--font-mono)', fontSize:11, fontWeight:600, letterSpacing:'0.12em', textTransform:'uppercase',
          }}>
            EXPORT AUDIT PACKAGE ↓
          </button>
        </div>
      )}
    </div>
  )
}
