'use client'

import { useState, useEffect } from 'react'
import { INITIAL_ALERTS, KILL_CHAIN_EVENTS, HEALTH_SCORE, LIVE_ALERT_FEED } from '@/lib/mock-data/blueteam'
import type { ThreatAlert, Severity } from '@/lib/types'

function SevDot({ sev }: { sev: Severity }) {
  const color = {
    CRITICAL:'var(--color-critical)', HIGH:'var(--color-high)',
    MEDIUM:'var(--color-medium)',      LOW:'var(--color-low)', INFO:'var(--color-blueteam)',
  }[sev]
  return <span style={{ width:7, height:7, borderRadius:'50%', background:color, boxShadow:`0 0 5px ${color}`, display:'inline-block', flexShrink:0 }} />
}

function SevBadge({ sev }: { sev: Severity }) {
  const cls = `label-tag sev-${sev.toLowerCase()}`
  return <span className={cls}>{sev}</span>
}

function StatusBadge({ status }: { status: ThreatAlert['status'] }) {
  const map = {
    NEW:           { color:'var(--color-hemis)',     label:'NEW'          },
    INVESTIGATING: { color:'var(--color-hemis-orange)',label:'INVESTIGATING'},
    CONTAINED:     { color:'var(--color-medium)',    label:'CONTAINED'    },
    RESOLVED:      { color:'var(--color-scanner)',   label:'RESOLVED'     },
  }
  const m = map[status]
  return (
    <span className="label-tag" style={{ fontSize:8, color:m.color, borderColor:m.color, background:`${m.color}15` }}>
      {m.label}
    </span>
  )
}

export default function BlueTeamPage() {
  const [alerts, setAlerts]           = useState<ThreatAlert[]>(INITIAL_ALERTS)
  const [selected, setSelected]       = useState<ThreatAlert | null>(INITIAL_ALERTS[0])
  const [responding, setResponding]   = useState<Set<string>>(new Set())
  const [responded, setResponded]     = useState<Set<string>>(new Set(['alert-001','alert-002','alert-005','alert-006']))
  const [liveIdx, setLiveIdx]         = useState(0)
  const [alertCount, setAlertCount]   = useState(0)

  // Stream in live alerts for demo effect
  useEffect(() => {
    const timer = setInterval(() => {
      if (liveIdx < LIVE_ALERT_FEED.length) {
        const newAlert: ThreatAlert = {
          ...LIVE_ALERT_FEED[liveIdx],
          id: `live-${Date.now()}`,
          timestamp: new Date().toISOString(),
        }
        setAlerts(prev => [newAlert, ...prev])
        setAlertCount(c => c+1)
        setLiveIdx(i => i+1)
      }
    }, 12000)
    return () => clearInterval(timer)
  }, [liveIdx])

  async function autoRespond(alertId: string) {
    setResponding(prev => new Set(prev).add(alertId))
    await new Promise(r => setTimeout(r, 1500))
    setResponding(prev => { const n=new Set(prev); n.delete(alertId); return n })
    setResponded(prev => new Set(prev).add(alertId))
    setAlerts(prev => prev.map(a => a.id===alertId
      ? { ...a, status:'CONTAINED', autoResponded:true, responseActions:['AI playbook executed','Credentials revoked','Instance isolated'] }
      : a
    ))
    if (selected?.id === alertId) {
      setSelected(prev => prev ? { ...prev, status:'CONTAINED', autoResponded:true, responseActions:['AI playbook executed','Credentials revoked','Instance isolated'] } : prev)
    }
  }

  const critCount = alerts.filter(a=>a.severity==='CRITICAL' && a.status!=='RESOLVED').length
  const newCount  = alerts.filter(a=>a.status==='NEW').length

  return (
    <div style={{ display:'flex', height:'100%', minHeight:0, overflow:'hidden' }}>

      {/* Left: metrics + alert feed */}
      <div style={{ width:380, flexShrink:0, display:'flex', flexDirection:'column', borderRight:'1px solid var(--color-border)', overflow:'hidden' }}>

        {/* Header */}
        <div style={{ padding:'16px 16px 12px', borderBottom:'1px solid var(--color-border)', background:'var(--color-bg-surface)', flexShrink:0 }}>
          <div className="mono" style={{ fontSize:9, letterSpacing:'0.15em', color:'var(--color-blueteam)', textTransform:'uppercase', marginBottom:4 }}>
            [ AI BLUE TEAM · LIVE MONITORING ]
          </div>
          <h2 className="display" style={{ fontSize:16, fontWeight:700, color:'var(--color-text-primary)', margin:0 }}>
            Threat Detection
          </h2>
        </div>

        {/* Health score row */}
        <div style={{
          display:'grid', gridTemplateColumns:'repeat(4,1fr)',
          borderBottom:'1px solid var(--color-border)', flexShrink:0,
        }}>
          {[
            { label:'HEALTH',    val:HEALTH_SCORE.overall,    color:HEALTH_SCORE.overall<70?'var(--color-hemis-orange)':'var(--color-scanner)', suffix:'/100' },
            { label:'DETECTION', val:HEALTH_SCORE.detection,  color:'var(--color-blueteam)', suffix:'%' },
            { label:'COVERAGE',  val:HEALTH_SCORE.coverage,   color:'var(--color-medium)', suffix:'%' },
            { label:'MTTR',      val:HEALTH_SCORE.mttr,       color:'var(--color-text-secondary)', suffix:'' },
          ].map(m => (
            <div key={m.label} style={{
              padding:'10px 10px', borderRight:'1px solid var(--color-border)',
              background:'var(--color-bg-elevated)', textAlign:'center',
            }}>
              <div className="mono" style={{ fontSize:8, letterSpacing:'0.1em', color:'var(--color-text-dim)', textTransform:'uppercase', marginBottom:3 }}>{m.label}</div>
              <div className="mono" style={{ fontSize:13, fontWeight:700, color:m.color }}>{m.val}{m.suffix}</div>
            </div>
          ))}
        </div>

        {/* Alert feed header */}
        <div style={{
          display:'flex', alignItems:'center', justifyContent:'space-between',
          padding:'10px 14px', borderBottom:'1px solid var(--color-border)',
          background:'var(--color-bg-surface)', flexShrink:0,
        }}>
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <span className="dot-live blue" style={{ width:5, height:5 }} />
            <span className="mono" style={{ fontSize:9, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase' }}>
              ALERT FEED
            </span>
          </div>
          <div style={{ display:'flex', gap:8 }}>
            {critCount > 0 && (
              <span className="mono" style={{ fontSize:9, color:'var(--color-hemis)', letterSpacing:'0.08em' }}>
                {critCount} CRITICAL
              </span>
            )}
            {newCount > 0 && (
              <span className="label-tag sev-info" style={{ fontSize:7, padding:'1px 4px' }}>
                {newCount} NEW
              </span>
            )}
          </div>
        </div>

        {/* Alerts list */}
        <div style={{ flex:1, overflow:'auto' }}>
          {alerts.map((alert, i) => {
            const isSelected = selected?.id === alert.id
            const isLive = alert.id.startsWith('live-')
            return (
              <div
                key={alert.id}
                onClick={() => setSelected(alert)}
                className={isLive ? 'fade-in-up' : ''}
                style={{
                  padding:'11px 14px', cursor:'pointer',
                  borderBottom:'1px solid var(--color-border)',
                  background: isSelected ? 'var(--color-bg-hover)' : 'transparent',
                  borderLeft: isSelected ? `2px solid var(--color-blueteam)` : '2px solid transparent',
                  transition:'all 0.12s',
                }}
              >
                <div style={{ display:'flex', gap:8, alignItems:'flex-start', marginBottom:5 }}>
                  <SevDot sev={alert.severity} />
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:12, fontWeight:500, color:'var(--color-text-primary)', lineHeight:1.3, marginBottom:3 }}>
                      {isLive && <span className="mono" style={{ fontSize:8, color:'var(--color-blueteam)', marginRight:5, letterSpacing:'0.08em' }}>NEW</span>}
                      {alert.title}
                    </div>
                    <div style={{ display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' }}>
                      <SevBadge sev={alert.severity} />
                      <StatusBadge status={alert.status} />
                      <span className="mono" style={{ fontSize:9, color:'var(--color-text-dim)' }}>{alert.source}</span>
                    </div>
                  </div>
                </div>
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                  <span className="mono" style={{ fontSize:9, color:'var(--color-text-dim)' }}>
                    {new Date(alert.timestamp).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' })}
                  </span>
                  {alert.autoResponded && (
                    <span className="mono" style={{ fontSize:8, color:'var(--color-scanner)', letterSpacing:'0.08em' }}>
                      ✓ AUTO-RESPONDED
                    </span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Right: detail panel */}
      <div style={{ flex:1, overflow:'auto', display:'flex', flexDirection:'column' }}>
        {selected ? (
          <>
            {/* Alert detail header */}
            <div style={{
              padding:'18px 20px', borderBottom:'1px solid var(--color-border)',
              background:'var(--color-bg-surface)', flexShrink:0,
            }}>
              <div style={{ display:'flex', gap:10, alignItems:'center', marginBottom:8, flexWrap:'wrap' }}>
                <SevBadge sev={selected.severity} />
                <StatusBadge status={selected.status} />
                <span className="mono" style={{ fontSize:9, color:'var(--color-text-dim)', letterSpacing:'0.06em' }}>
                  {selected.id} · {selected.source} · {selected.region}
                </span>
              </div>
              <h2 className="display" style={{ fontSize:17, fontWeight:700, color:'var(--color-text-primary)', margin:'0 0 8px' }}>
                {selected.title}
              </h2>
              {/* AI summary */}
              <div style={{
                background:'var(--color-blueteam-dim)',
                border:'1px solid var(--color-blueteam)33',
                padding:'10px 14px', marginBottom:10,
              }}>
                <div className="mono" style={{ fontSize:8, letterSpacing:'0.12em', color:'var(--color-blueteam)', textTransform:'uppercase', marginBottom:5 }}>
                  ⚡ AI ANALYSIS
                </div>
                <p style={{ fontSize:12, color:'var(--color-text-secondary)', margin:0, lineHeight:1.65 }}>
                  {selected.summary}
                </p>
              </div>

              {/* Meta row */}
              <div style={{ display:'flex', gap:16, flexWrap:'wrap' }}>
                {[
                  { l:'RESOURCE', v:selected.resource },
                  { l:'SOURCE IP', v:selected.ip || '—' },
                  { l:'REGION', v:selected.region },
                  { l:'DETECTED', v:new Date(selected.timestamp).toLocaleTimeString() },
                ].map(m => (
                  <div key={m.l}>
                    <div className="mono" style={{ fontSize:8, letterSpacing:'0.1em', color:'var(--color-text-dim)', textTransform:'uppercase', marginBottom:2 }}>{m.l}</div>
                    <div className="mono" style={{ fontSize:11, color:'var(--color-text-primary)' }}>{m.v}</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ flex:1, overflow:'auto', padding:'18px 20px' }} className="tac-grid">

              {/* Response actions */}
              <div style={{ marginBottom:20 }}>
                <div className="mono" style={{ fontSize:9, letterSpacing:'0.13em', color:'var(--color-text-dim)', textTransform:'uppercase', marginBottom:10 }}>
                  RESPONSE ACTIONS
                </div>

                {selected.autoResponded || responded.has(selected.id) ? (
                  <div style={{
                    background:'rgba(0,232,138,0.05)', border:'1px solid var(--color-scanner)33',
                    padding:'12px 14px', marginBottom:12,
                  }}>
                    <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:8 }}>
                      <span style={{ color:'var(--color-scanner)', fontSize:12 }}>✓</span>
                      <span className="mono" style={{ fontSize:10, color:'var(--color-scanner)', letterSpacing:'0.1em' }}>
                        AI PLAYBOOK EXECUTED
                      </span>
                    </div>
                    {(selected.responseActions.length > 0 ? selected.responseActions : ['Automated response completed']).map((action, i) => (
                      <div key={i} style={{ display:'flex', gap:8, alignItems:'center', marginBottom:4 }}>
                        <span style={{ width:4, height:4, borderRadius:'50%', background:'var(--color-scanner)', display:'inline-block', flexShrink:0 }} />
                        <span style={{ fontSize:11, color:'var(--color-text-secondary)' }}>{action}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ display:'flex', gap:10, marginBottom:12 }}>
                    <button
                      onClick={() => autoRespond(selected.id)}
                      disabled={responding.has(selected.id)}
                      style={{
                        background: responding.has(selected.id) ? 'var(--color-bg-elevated)' : 'var(--color-blueteam)',
                        color: responding.has(selected.id) ? 'var(--color-text-dim)' : '#fff',
                        border:'none', padding:'9px 18px', cursor: responding.has(selected.id) ? 'not-allowed' : 'pointer',
                        fontFamily:'var(--font-mono)', fontSize:10, fontWeight:600, letterSpacing:'0.12em', textTransform:'uppercase',
                      }}
                    >
                      {responding.has(selected.id) ? (
                        <span style={{ display:'flex', alignItems:'center', gap:7 }}>
                          <span className="dot-live blue" style={{ width:5, height:5 }} />
                          EXECUTING PLAYBOOK...
                        </span>
                      ) : '◎ AUTO-RESPOND'}
                    </button>
                    <button style={{
                      background:'transparent', border:'1px solid var(--color-border)',
                      color:'var(--color-text-secondary)', padding:'9px 16px', cursor:'pointer',
                      fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:'0.12em', textTransform:'uppercase',
                    }}>
                      ASSIGN TO ANALYST
                    </button>
                  </div>
                )}

                {/* MITRE tactics */}
                {selected.tactics.length > 0 && (
                  <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
                    {selected.tactics.map(t => (
                      <span key={t} className="label-tag" style={{ fontSize:8, color:'var(--color-hemis-orange)', borderColor:'var(--color-hemis-orange)', background:'rgba(255,124,61,0.08)' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Kill chain timeline (show for first alert) */}
              {selected.id === 'alert-001' || selected.id === 'alert-002' ? (
                <div>
                  <div className="mono" style={{ fontSize:9, letterSpacing:'0.13em', color:'var(--color-text-dim)', textTransform:'uppercase', marginBottom:12 }}>
                    KILL CHAIN RECONSTRUCTION
                  </div>
                  <div style={{ position:'relative' }}>
                    {KILL_CHAIN_EVENTS.map((ev, i) => {
                      const sevColor = {
                        CRITICAL:'var(--color-hemis)', HIGH:'var(--color-high)',
                        MEDIUM:'var(--color-medium)', LOW:'var(--color-low)', INFO:'var(--color-blueteam)',
                      }[ev.severity]
                      return (
                        <div key={i} style={{ display:'flex', gap:12, marginBottom:0 }}>
                          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', flexShrink:0, width:16 }}>
                            <div style={{
                              width:8, height:8, borderRadius:'50%', flexShrink:0, marginTop:12,
                              background: sevColor, border:`1px solid ${sevColor}`,
                              boxShadow:`0 0 5px ${sevColor}66`,
                            }} />
                            {i < KILL_CHAIN_EVENTS.length-1 && (
                              <div style={{ width:1, flex:1, background:'var(--color-border)', minHeight:24 }} />
                            )}
                          </div>
                          <div style={{
                            flex:1, padding:'9px 12px', marginBottom:2,
                            background:'var(--color-bg-surface)',
                            border:`1px solid ${ev.severity==='CRITICAL'?'var(--color-hemis)22':'var(--color-border)'}`,
                          }}>
                            <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:3, flexWrap:'wrap' }}>
                              <span className="mono" style={{ fontSize:9, color:'var(--color-text-dim)' }}>{ev.timestamp}</span>
                              <span className="label-tag" style={{
                                fontSize:7, padding:'1px 5px',
                                color: sevColor, borderColor: sevColor, background:`${sevColor}15`,
                              }}>{ev.stage}</span>
                              <span style={{ fontSize:11, fontWeight:500, color:'var(--color-text-primary)' }}>{ev.action}</span>
                            </div>
                            <div style={{ display:'flex', gap:12 }}>
                              <span className="mono" style={{ fontSize:10, color:'var(--color-text-dim)' }}>
                                Actor: <span style={{ color:'var(--color-text-secondary)' }}>{ev.actor}</span>
                              </span>
                              <span className="mono" style={{ fontSize:10, color:'var(--color-text-dim)' }}>
                                Target: <span style={{ color:'var(--color-text-secondary)' }}>{ev.target}</span>
                              </span>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              ) : (
                <div className="bracket-card" style={{ padding:'24px', textAlign:'center' }}>
                  <div style={{ color:'var(--color-text-dim)', fontSize:10, marginBottom:6 }}>◎</div>
                  <div style={{ fontSize:12, color:'var(--color-text-dim)' }}>Kill chain data available for correlated attacks</div>
                </div>
              )}
            </div>
          </>
        ) : (
          <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center' }} className="tac-grid">
            <div style={{ textAlign:'center' }}>
              <div style={{ fontSize:28, color:'var(--color-text-dim)', marginBottom:10 }}>◎</div>
              <div className="display" style={{ fontSize:14, color:'var(--color-text-secondary)' }}>Select an alert to investigate</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
