'use client'

import { useState, useRef, useEffect } from 'react'
import { PRELOADED_SIMULATION, MITRE_TECHNIQUES, TACTICS_ORDER } from '@/lib/mock-data/hemis'
import type { AttackChainStep, MitreTechnique, TechniqueStatus } from '@/lib/types'

type SimPhase = 'idle' | 'running' | 'done'

const STATUS_COLORS: Record<TechniqueStatus, string> = {
  vulnerable: 'var(--color-hemis)',
  mitigated:  'var(--color-scanner)',
  tested:     'var(--color-blueteam)',
  untested:   'var(--color-bg-elevated)',
}
const STATUS_LABELS: Record<TechniqueStatus, string> = {
  vulnerable: 'VULN',
  mitigated:  'MITIGATED',
  tested:     'TESTED',
  untested:   'UNTESTED',
}

const ATTACK_TEMPLATES = [
  'Simulate an external attacker targeting our production API and AWS environment',
  'Test our login endpoint for SQL injection and authentication bypass',
  'Check for privilege escalation paths via IAM misconfigurations',
  'Test our LLM chatbot for prompt injection and data exfiltration',
  'Run a full red team simulation: recon → initial access → data exfiltration',
]

const NEW_SIM_LOG = [
  { t:300,  type:'dim',     text:'Initializing HEMIS simulation engine v2.4...' },
  { t:600,  type:'accent',  text:'Simulation authorized. Target scope confirmed.' },
  { t:900,  type:'default', text:'Phase 1 — Reconnaissance' },
  { t:1200, type:'success', text:'[T1595] Active scanning: 14 open ports identified' },
  { t:1600, type:'success', text:'[T1589] OSINT: AWS region identified from public GitHub repos' },
  { t:2000, type:'default', text:'Phase 2 — Initial Access' },
  { t:2400, type:'warn',    text:'[T1190] SQL injection in /v1/login — testing...' },
  { t:2900, type:'error',   text:'[T1190] VULNERABLE — admin credentials extracted via blind SQLi' },
  { t:3400, type:'error',   text:'[T1552] AWS keys found in public S3 .env file — CRITICAL' },
  { t:3900, type:'default', text:'Phase 3 — Privilege Escalation' },
  { t:4300, type:'error',   text:'[T1078] Full account compromise via stolen IAM credentials' },
  { t:4800, type:'default', text:'Phase 4 — Collection & Exfiltration' },
  { t:5200, type:'error',   text:'[T1530] 4.2 GB customer data staged from S3' },
  { t:5700, type:'error',   text:'[T1537] Data exfiltrated to external account — SIMULATION COMPLETE' },
  { t:6000, type:'accent',  text:'Attack chain complete. 8 findings. 3 critical vulnerabilities.' },
]

function LogLine({ text, type }: { text: string; type: string }) {
  const color = {
    success: 'var(--color-scanner)',
    warn:    'var(--color-hemis-orange)',
    error:   'var(--color-hemis)',
    dim:     'var(--color-text-dim)',
    accent:  'var(--color-yellow)',
    default: 'var(--color-text-secondary)',
  }[type] ?? 'var(--color-text-secondary)'

  return (
    <div style={{ display:'flex', gap:8, marginBottom:4 }}>
      <span style={{ color:'var(--color-text-secondary)', flexShrink:0 }}>›</span>
      <span style={{ color, fontFamily:'var(--font-mono)', fontSize:12, lineHeight:1.5 }}>{text}</span>
    </div>
  )
}

export default function HemisPage() {
  const [prompt, setPrompt]           = useState('')
  const [simPhase, setSimPhase]       = useState<SimPhase>('idle')
  const [logLines, setLogLines]       = useState<typeof NEW_SIM_LOG>([])
  const [simResult, setSimResult]     = useState(PRELOADED_SIMULATION)
  const [activeTab, setActiveTab]     = useState<'chain'|'heatmap'>('chain')
  const [showPreloaded, setShowPreloaded] = useState(true)
  const termRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight
    }
  }, [logLines])

  async function runSimulation(p: string) {
    if (!p.trim()) return
    setSimPhase('running')
    setShowPreloaded(false)
    setLogLines([])

    for (const line of NEW_SIM_LOG) {
      await new Promise(r => setTimeout(r, line.t / 4))
      setLogLines(prev => [...prev, line])
    }

    setSimPhase('done')
    setSimResult({ ...PRELOADED_SIMULATION, prompt: p })
    setShowPreloaded(true)
  }

  // Group techniques by tactic
  const byTactic: Record<string, MitreTechnique[]> = {}
  for (const t of MITRE_TECHNIQUES) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = []
    byTactic[t.tactic].push(t)
  }

  const vulnerableCount = MITRE_TECHNIQUES.filter(t=>t.status==='vulnerable').length
  const mitigatedCount  = MITRE_TECHNIQUES.filter(t=>t.status==='mitigated').length
  const testedCount     = MITRE_TECHNIQUES.filter(t=>t.status==='tested').length
  const untestedCount   = MITRE_TECHNIQUES.filter(t=>t.status==='untested').length

  return (
    <div style={{ display:'flex', height:'100%', minHeight:0, overflow:'hidden' }}>

      {/* Left — Terminal + controls */}
      <div style={{
        width:420, flexShrink:0, display:'flex', flexDirection:'column',
        borderRight:'1px solid var(--color-border)',
        background:'var(--color-bg-surface)',
      }}>
        {/* Header */}
        <div style={{ padding:'18px 18px 14px', borderBottom:'1px solid var(--color-border)' }}>
          <div className="mono" style={{ fontSize:11, letterSpacing:'0.15em', color:'var(--color-hemis)', textTransform:'uppercase', marginBottom:4 }}>
            [ HEMIS v2.4 · AI RED TEAM ENGINE ]
          </div>
          <h2 className="display" style={{ fontSize:18, fontWeight:700, color:'var(--color-text-primary)', margin:0 }}>
            Attack Console
          </h2>
          <p style={{ fontSize:12, color:'var(--color-text-secondary)', margin:'3px 0 0' }}>
            Describe an attack scenario in natural language
          </p>
        </div>

        {/* Terminal output */}
        <div
          ref={termRef}
          className="terminal"
          style={{ flex:1, padding:'14px', overflow:'auto', position:'relative' }}
        >
          {/* Scan line when running */}
          {simPhase === 'running' && <div className="scan-line red" />}

          {/* Initial state */}
          {logLines.length === 0 && simPhase === 'idle' && (
            <div>
              <LogLine type="accent"  text="HEMISX SIMULATION ENGINE READY" />
              <LogLine type="dim"     text="Authorization required before executing simulations." />
              <LogLine type="dim"     text="All attacks run in sandboxed environment with full audit trail." />
              <div style={{ margin:'12px 0', borderTop:'1px solid var(--color-border)' }} />
              <LogLine type="default" text="Enter a target scenario below and press EXECUTE." />
              <LogLine type="dim"     text="Or use a template from the quick-select menu." />
            </div>
          )}

          {/* Live log lines */}
          {logLines.map((l, i) => (
            <LogLine key={i} type={l.type} text={l.text} />
          ))}

          {/* Running indicator */}
          {simPhase === 'running' && (
            <div style={{ display:'flex', alignItems:'center', gap:6, marginTop:8 }}>
              <span className="dot-live red" />
              <span className="mono" style={{ fontSize:11, color:'var(--color-hemis)', letterSpacing:'0.1em' }}>
                EXECUTING SIMULATION...
              </span>
            </div>
          )}

          {simPhase === 'done' && (
            <div style={{ marginTop:8 }}>
              <div style={{ borderTop:'1px solid var(--color-border)', paddingTop:10 }}>
                <LogLine type="accent" text="▶ Scroll right panel for full results and MITRE heatmap" />
              </div>
            </div>
          )}
        </div>

        {/* Quick templates */}
        <div style={{ padding:'10px 14px', borderTop:'1px solid var(--color-border)' }}>
          <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:6 }}>
            QUICK TEMPLATES
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:3 }}>
            {ATTACK_TEMPLATES.slice(0,3).map((t,i) => (
              <button key={i} onClick={() => setPrompt(t)} style={{
                background:'transparent', border:'1px solid var(--color-border)',
                color:'var(--color-text-secondary)', padding:'5px 10px', cursor:'pointer', textAlign:'left',
                fontFamily:'var(--font-sans)', fontSize:11, lineHeight:1.4,
                transition:'all 0.12s',
              }}
              onMouseEnter={e=>(e.currentTarget.style.borderColor='var(--color-hemis)',e.currentTarget.style.color='var(--color-text-primary)')}
              onMouseLeave={e=>(e.currentTarget.style.borderColor='var(--color-border)',e.currentTarget.style.color='var(--color-text-secondary)')}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        {/* Input area */}
        <div style={{ padding:'12px 14px 14px', borderTop:'1px solid var(--color-border)' }}>
          <div className="mono" style={{ fontSize:10, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:6 }}>
            ATTACK SCENARIO
          </div>
          <textarea
            value={prompt}
            onChange={e => setPrompt(e.target.value)}
            placeholder="Describe an attack scenario in natural language..."
            className="tac-input"
            rows={3}
            style={{ resize:'none', display:'block', lineHeight:1.5 }}
          />
          <button
            onClick={() => runSimulation(prompt)}
            disabled={simPhase==='running' || !prompt.trim()}
            style={{
              marginTop:8, width:'100%',
              background: simPhase==='running' ? 'var(--color-bg-elevated)' : 'var(--color-hemis)',
              color: simPhase==='running' ? 'var(--color-text-secondary)' : '#ffffff',
              border:'none', padding:'10px 0', cursor: simPhase==='running'||!prompt.trim() ? 'not-allowed' : 'pointer',
              fontFamily:'var(--font-mono)', fontSize:10, fontWeight:600, letterSpacing:'0.14em', textTransform:'uppercase',
            }}
          >
            {simPhase==='running' ? '◉ SIMULATION RUNNING...' : '◉ EXECUTE SIMULATION'}
          </button>
        </div>
      </div>

      {/* Right — Results */}
      <div style={{ flex:1, overflow:'auto', display:'flex', flexDirection:'column' }}>

        {showPreloaded ? (
          <>
            {/* Results header */}
            <div style={{
              padding:'16px 20px', borderBottom:'1px solid var(--color-border)',
              background:'var(--color-bg-surface)', position:'sticky', top:0, zIndex:10,
              display:'flex', alignItems:'center', justifyContent:'space-between', flexShrink:0,
            }}>
              <div>
                <div className="mono" style={{ fontSize:10, color:'var(--color-text-secondary)', letterSpacing:'0.1em', textTransform:'uppercase', marginBottom:3 }}>
                  SIMULATION RESULTS · {simResult.id}
                </div>
                <div style={{ fontSize:14, color:'var(--color-text-primary)', fontStyle:'italic' }}>
                  "{simResult.prompt}"
                </div>
              </div>
              <div style={{ display:'flex', gap:10, flexShrink:0, marginLeft:16 }}>
                {[
                  { v:`${simResult.findings}`, l:'FINDINGS', c:'var(--color-hemis)' },
                  { v:`${simResult.criticals}`, l:'CRITICAL', c:'var(--color-hemis)' },
                  { v:simResult.duration, l:'DURATION', c:'var(--color-text-secondary)' },
                ].map(s => (
                  <div key={s.l} style={{ textAlign:'center', background:'var(--color-bg-elevated)', border:'1px solid var(--color-border)', padding:'6px 12px' }}>
                    <div className="mono" style={{ fontSize:16, fontWeight:700, color:s.c }}>{s.v}</div>
                    <div className="mono" style={{ fontSize:10, letterSpacing:'0.1em', color:'var(--color-text-secondary)', textTransform:'uppercase' }}>{s.l}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Tabs */}
            <div style={{
              display:'flex', gap:0, borderBottom:'1px solid var(--color-border)',
              background:'var(--color-bg-surface)', flexShrink:0,
            }}>
              {([['chain','ATTACK CHAIN'],['heatmap','MITRE ATT&CK HEATMAP']] as const).map(([id, label]) => (
                <button key={id} onClick={() => setActiveTab(id)} style={{
                  background: activeTab===id ? 'var(--color-bg-elevated)' : 'transparent',
                  border:'none',
                  borderBottom: activeTab===id ? `2px solid var(--color-hemis)` : '2px solid transparent',
                  borderRight:'1px solid var(--color-border)',
                  color: activeTab===id ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
                  padding:'10px 20px', cursor:'pointer',
                  fontFamily:'var(--font-mono)', fontSize:11, letterSpacing:'0.1em', textTransform:'uppercase',
                  transition:'all 0.12s',
                }}>
                  {label}
                </button>
              ))}
            </div>

            <div style={{ flex:1, overflow:'auto', padding:'20px' }} className="tac-grid">
              {activeTab === 'chain' && (
                <div>
                  {simResult.steps.map((step, i) => (
                    <div key={step.seq} className="fade-in-up" style={{
                      display:'flex', gap:14, marginBottom:0,
                      animationDelay:`${i * 0.04}s`,
                    }}>
                      {/* Timeline spine */}
                      <div style={{ display:'flex', flexDirection:'column', alignItems:'center', flexShrink:0, width:20 }}>
                        <div style={{
                          width:10, height:10, borderRadius:'50%', flexShrink:0,
                          background: step.result==='SUCCESS' ? 'var(--color-hemis)' : 'var(--color-scanner)',
                          border:`2px solid ${step.result==='SUCCESS' ? 'var(--color-hemis)' : 'var(--color-scanner)'}`,
                          boxShadow:`0 0 6px ${step.result==='SUCCESS' ? 'var(--color-hemis)' : 'var(--color-scanner)'}66`,
                          marginTop:14,
                        }} />
                        {i < simResult.steps.length-1 && (
                          <div style={{ width:1, flex:1, background:'var(--color-border)', minHeight:32 }} />
                        )}
                      </div>

                      {/* Content */}
                      <div style={{
                        flex:1, background:'var(--color-bg-surface)',
                        border:`1px solid ${step.result==='SUCCESS' ? 'var(--color-hemis)22' : 'var(--color-border)'}`,
                        padding:'11px 14px', marginBottom:2,
                      }}>
                        <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:6, flexWrap:'wrap' }}>
                          <span className="mono" style={{ fontSize:10, color:'var(--color-text-secondary)' }}>{step.timestamp}</span>
                          <span className="label-tag" style={{
                            fontSize:10, padding:'2px 6px',
                            color:'var(--color-hemis-orange)', borderColor:'var(--color-hemis-orange)',
                            background:'rgba(255,124,61,0.08)',
                          }}>{step.phase}</span>
                          <span className="mono" style={{ fontSize:10, color:'var(--color-text-secondary)' }}>{step.techniqueId}</span>
                          <span style={{ fontSize:12, fontWeight:500, color:'var(--color-text-primary)' }}>{step.technique}</span>
                          <span style={{
                            marginLeft:'auto', fontSize:9, fontFamily:'var(--font-mono)',
                            color: step.result==='SUCCESS' ? 'var(--color-hemis)' : 'var(--color-scanner)',
                            fontWeight:600, letterSpacing:'0.08em',
                          }}>
                            {step.result}
                          </span>
                        </div>
                        <div className="mono" style={{ fontSize:11, color:'var(--color-text-secondary)', marginBottom:4 }}>
                          Target: {step.target}
                        </div>
                        <div style={{ fontSize:12, color:'var(--color-text-primary)', lineHeight:1.5 }}>
                          {step.detail}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'heatmap' && (
                <div>
                  {/* Legend */}
                  <div style={{ display:'flex', gap:16, marginBottom:20, flexWrap:'wrap' }}>
                    {([['vulnerable','VULNERABLE',vulnerableCount],['tested','TESTED',testedCount],['mitigated','MITIGATED',mitigatedCount],['untested','UNTESTED',untestedCount]] as const).map(([s,l,c]) => (
                      <div key={s} style={{ display:'flex', alignItems:'center', gap:6 }}>
                        <div style={{ width:10, height:10, background:STATUS_COLORS[s], border:`1px solid ${STATUS_COLORS[s]}` }} />
                        <span className="mono" style={{ fontSize:11, color:'var(--color-text-primary)', letterSpacing:'0.08em' }}>{l} ({c})</span>
                      </div>
                    ))}
                  </div>

                  {/* Heatmap grid */}
                  {TACTICS_ORDER.filter(tac => byTactic[tac]).map(tac => (
                    <div key={tac} style={{ marginBottom:16 }}>
                      <div className="mono" style={{
                        fontSize:11, letterSpacing:'0.13em', color:'var(--color-hemis-orange)',
                        textTransform:'uppercase', marginBottom:6,
                      }}>
                        {tac}
                      </div>
                      <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
                        {(byTactic[tac] || []).map(t => (
                          <div key={t.id} title={`${t.id}: ${t.name} — ${t.status.toUpperCase()}`} style={{
                            background: STATUS_COLORS[t.status] + (t.status==='untested'?'' : '22'),
                            border:`1px solid ${STATUS_COLORS[t.status]}`,
                            padding:'5px 8px', cursor:'default',
                            minWidth:80, maxWidth:140,
                            transition:'all 0.1s',
                          }}>
                            <div className="mono" style={{ fontSize:10, color: t.status==='untested' ? 'var(--color-text-secondary)' : STATUS_COLORS[t.status], letterSpacing:'0.06em', marginBottom:2 }}>
                              {t.id}
                            </div>
                            <div style={{ fontSize:11, color: t.status==='untested' ? 'var(--color-text-secondary)' : 'var(--color-text-primary)', lineHeight:1.3 }}>
                              {t.name}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        ) : (
          /* Empty state while new sim running */
          <div style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }} className="tac-grid">
            {simPhase === 'running' ? (
              <div style={{ textAlign:'center' }}>
                <div style={{ marginBottom:16 }}>
                  <span className="dot-live red" style={{ width:10, height:10 }} />
                </div>
                <div className="display" style={{ fontSize:16, color:'var(--color-hemis)', marginBottom:6 }}>Simulation in progress</div>
                <div className="mono" style={{ fontSize:12, color:'var(--color-text-secondary)' }}>Results will appear here when complete</div>
              </div>
            ) : (
              <div style={{ textAlign:'center' }}>
                <div style={{ fontSize:28, color:'var(--color-text-secondary)', marginBottom:10 }}>◉</div>
                <div className="display" style={{ fontSize:15, color:'var(--color-text-primary)' }}>Ready to simulate</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
