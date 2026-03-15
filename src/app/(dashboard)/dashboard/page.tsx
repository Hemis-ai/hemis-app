'use client'

import Link from 'next/link'
import { MOCK_SCAN } from '@/lib/mock-data/scanner'
import { PRELOADED_SIMULATION } from '@/lib/mock-data/hemis'
import { INITIAL_ALERTS, HEALTH_SCORE } from '@/lib/mock-data/blueteam'

const criticals = INITIAL_ALERTS.filter(a => a.severity === 'CRITICAL').length
const openFindings = MOCK_SCAN.findings.filter(f => f.status === 'OPEN').length

const PRODUCTS = [
  {
    id: 'scanner',
    label: 'CLOUD SCANNER',
    desc: 'Cloud Security Posture Management',
    href: '/dashboard/scanner',
    color: 'var(--color-scanner)',
    bracketClass: 'bracket-scanner',
    icon: '◈',
    stats: [
      { label:'RISK SCORE',       value: `${MOCK_SCAN.riskScore}/100`,  alert: MOCK_SCAN.riskScore > 70 },
      { label:'OPEN FINDINGS',    value: `${openFindings}`,             alert: openFindings > 5 },
      { label:'SOC2 COMPLIANCE',  value: `${MOCK_SCAN.complianceScore.soc2}%`, alert: MOCK_SCAN.complianceScore.soc2 < 70 },
      { label:'RESOURCES',        value: `${MOCK_SCAN.resourcesScanned}`, alert: false },
    ],
    status: 'LAST SCAN 43s AGO',
    statusLive: true,
    cta: 'Open Scanner →',
  },
  {
    id: 'hemis',
    label: 'HEMIS',
    desc: 'AI Red Team Simulation Engine',
    href: '/dashboard/hemis',
    color: 'var(--color-hemis)',
    bracketClass: 'bracket-hemis',
    icon: '◉',
    stats: [
      { label:'LAST SIMULATION',   value: '3m 21s',          alert: false },
      { label:'CRITICAL FINDINGS', value: `${PRELOADED_SIMULATION.criticals}`, alert: true },
      { label:'TECHNIQUES TESTED', value: `${PRELOADED_SIMULATION.techniques.filter(t=>t.status!=='untested').length}/${PRELOADED_SIMULATION.techniques.length}`, alert: false },
      { label:'ATTACK STEPS',      value: `${PRELOADED_SIMULATION.steps.length}`, alert: false },
    ],
    status: 'SIMULATION READY',
    statusLive: false,
    cta: 'Open HEMIS →',
  },
  {
    id: 'blueteam',
    label: 'BLUE TEAM',
    desc: 'Autonomous Threat Detection & Response',
    href: '/dashboard/blueteam',
    color: 'var(--color-blueteam)',
    bracketClass: 'bracket-blueteam',
    icon: '◎',
    stats: [
      { label:'HEALTH SCORE',  value: `${HEALTH_SCORE.overall}/100`,  alert: HEALTH_SCORE.overall < 80 },
      { label:'ACTIVE ALERTS', value: `${criticals} CRITICAL`,        alert: criticals > 0 },
      { label:'AVG MTTR',      value: HEALTH_SCORE.mttr,              alert: false },
      { label:'COVERAGE',      value: `${HEALTH_SCORE.coverage}%`,    alert: HEALTH_SCORE.coverage < 70 },
    ],
    status: 'MONITORING LIVE',
    statusLive: true,
    cta: 'Open Blue Team →',
  },
]

const RECENT_EVENTS = [
  { time:'10:07:44', type:'ALERT',   product:'BLUE TEAM', color:'var(--color-hemis)',    msg:'IAM credentials used from anomalous geolocation [CRITICAL]' },
  { time:'10:07:33', type:'HEMIS',   product:'HEMIS',     color:'var(--color-hemis)',    msg:'Simulation: Data exfiltrated to external S3 bucket [T1537]' },
  { time:'10:06:02', type:'HEMIS',   product:'HEMIS',     color:'var(--color-hemis-orange)', msg:'Full AWS account compromise via valid accounts [T1078]' },
  { time:'10:05:44', type:'HEMIS',   product:'HEMIS',     color:'var(--color-hemis-orange)', msg:'AWS credentials found in public S3 .env file [T1552]' },
  { time:'10:22:41', type:'SCAN',    product:'SCANNER',   color:'var(--color-scanner)',  msg:'Scan complete — 12 findings across 247 resources' },
  { time:'10:22:00', type:'SCAN',    product:'SCANNER',   color:'var(--color-hemis)',    msg:'S3 bucket "prod-customer-backups" publicly accessible [CRITICAL]' },
]

export default function DashboardPage() {
  return (
    <div className="tac-grid" style={{ minHeight:'100%', padding:'28px 28px 40px' }}>

      {/* Page header */}
      <div style={{ marginBottom:28 }}>
        <div className="mono" style={{ fontSize:10, letterSpacing:'0.15em', color:'var(--color-yellow)', textTransform:'uppercase', marginBottom:6 }}>
          [ COMMAND CENTER ]
        </div>
        <h1 className="display" style={{ fontSize:22, fontWeight:700, color:'var(--color-text-primary)', margin:0, letterSpacing:'-0.02em' }}>
          Security Overview
        </h1>
        <p style={{ color:'var(--color-text-secondary)', margin:'4px 0 0', fontSize:13 }}>
          Acme Corp · AWS account 482910 · us-east-1, us-west-2
        </p>
      </div>

      {/* Global risk banner */}
      <div className="bracket-card" style={{
        marginBottom:24, padding:'16px 20px',
        borderColor:'var(--color-hemis)',
        background:'var(--color-hemis-dim)',
        display:'flex', alignItems:'center', gap:16,
      }}>
        <div className="dot-live red" />
        <div style={{ flex:1 }}>
          <span className="mono" style={{ fontSize:11, fontWeight:600, color:'var(--color-hemis)', letterSpacing:'0.1em', textTransform:'uppercase' }}>
            CRITICAL RISK DETECTED
          </span>
          <span style={{ fontSize:12, color:'var(--color-text-secondary)', marginLeft:12 }}>
            3 critical findings require immediate attention — unauthorized access attempt in progress
          </span>
        </div>
        <Link href="/dashboard/blueteam" style={{ textDecoration:'none' }}>
          <span className="mono" style={{ fontSize:10, color:'var(--color-hemis)', letterSpacing:'0.1em', border:'1px solid var(--color-hemis)', padding:'4px 10px', cursor:'pointer' }}>
            VIEW ALERTS →
          </span>
        </Link>
      </div>

      {/* Product cards grid */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(3, 1fr)', gap:16, marginBottom:24 }}>
        {PRODUCTS.map(p => (
          <Link key={p.id} href={p.href} style={{ textDecoration:'none' }}>
            <div
              className={`bracket-card ${p.bracketClass}`}
              style={{ padding:'20px', cursor:'pointer', height:'100%', transition:'border-color 0.15s' }}
            >
              {/* Card header */}
              <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:16 }}>
                <div>
                  <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:4 }}>
                    <span style={{ fontSize:14, color:p.color }}>{p.icon}</span>
                    <span className="mono" style={{ fontSize:10, fontWeight:600, letterSpacing:'0.14em', color:p.color, textTransform:'uppercase' }}>
                      {p.label}
                    </span>
                  </div>
                  <div style={{ fontSize:11, color:'var(--color-text-dim)' }}>{p.desc}</div>
                </div>
                <div style={{ display:'flex', alignItems:'center', gap:5, flexShrink:0 }}>
                  {p.statusLive
                    ? <span className="dot-live" style={{ width:5, height:5, background:p.color, boxShadow:`0 0 4px ${p.color}` }} />
                    : <span style={{ width:5, height:5, borderRadius:'50%', background:'var(--color-text-dim)', display:'inline-block' }} />
                  }
                  <span className="mono" style={{ fontSize:8, letterSpacing:'0.1em', color:'var(--color-text-dim)', textTransform:'uppercase' }}>
                    {p.status}
                  </span>
                </div>
              </div>

              {/* Stats grid */}
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, marginBottom:16 }}>
                {p.stats.map(s => (
                  <div key={s.label} style={{
                    background:'var(--color-bg-elevated)',
                    border:`1px solid ${s.alert ? p.color + '40' : 'var(--color-border)'}`,
                    padding:'8px 10px',
                  }}>
                    <div className="mono" style={{ fontSize:8, letterSpacing:'0.1em', color:'var(--color-text-dim)', textTransform:'uppercase', marginBottom:3 }}>
                      {s.label}
                    </div>
                    <div className="mono" style={{ fontSize:14, fontWeight:600, color: s.alert ? p.color : 'var(--color-text-primary)' }}>
                      {s.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* CTA */}
              <div style={{
                borderTop:'1px solid var(--color-border)',
                paddingTop:12,
                display:'flex', justifyContent:'flex-end',
              }}>
                <span className="mono" style={{ fontSize:10, letterSpacing:'0.1em', color:p.color, textTransform:'uppercase' }}>
                  {p.cta}
                </span>
              </div>
            </div>
          </Link>
        ))}
      </div>

      {/* Bottom row: recent activity + quick metrics */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 280px', gap:16 }}>

        {/* Recent Events */}
        <div className="bracket-card" style={{ padding:'20px' }}>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
            <div>
              <span className="mono" style={{ fontSize:9, letterSpacing:'0.15em', color:'var(--color-text-dim)', textTransform:'uppercase' }}>
                RECENT EVENTS
              </span>
            </div>
            <span className="dot-live" style={{ width:5, height:5 }} />
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:0 }}>
            {RECENT_EVENTS.map((ev, i) => (
              <div key={i} style={{
                display:'flex', alignItems:'flex-start', gap:12, padding:'9px 0',
                borderBottom: i < RECENT_EVENTS.length-1 ? '1px solid var(--color-border)' : 'none',
              }}>
                <span className="mono" style={{ fontSize:10, color:'var(--color-text-dim)', flexShrink:0, letterSpacing:'0.04em' }}>
                  {ev.time}
                </span>
                <span className="label-tag" style={{
                  fontSize:8, flexShrink:0, padding:'1px 5px',
                  color:ev.color, borderColor:ev.color, background:`${ev.color}15`,
                  letterSpacing:'0.1em',
                }}>
                  {ev.product}
                </span>
                <span style={{ fontSize:11, color:'var(--color-text-secondary)', lineHeight:1.4 }}>
                  {ev.msg}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Metrics */}
        <div style={{ display:'flex', flexDirection:'column', gap:12 }}>

          {/* Overall posture */}
          <div className="bracket-card" style={{ padding:'16px' }}>
            <div className="mono" style={{ fontSize:9, letterSpacing:'0.13em', color:'var(--color-text-dim)', textTransform:'uppercase', marginBottom:12 }}>
              SECURITY POSTURE
            </div>
            {[
              { label:'Risk Score',     val:74,  color:'var(--color-hemis)',   invert:true },
              { label:'SOC2 Coverage',  val:61,  color:'var(--color-scanner)', invert:false },
              { label:'Detection Rate', val:84,  color:'var(--color-blueteam)',invert:false },
            ].map(m => (
              <div key={m.label} style={{ marginBottom:10 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                  <span style={{ fontSize:11, color:'var(--color-text-secondary)' }}>{m.label}</span>
                  <span className="mono" style={{ fontSize:11, fontWeight:600, color:m.color }}>{m.val}%</span>
                </div>
                <div className="tac-progress">
                  <div className="tac-progress-fill" style={{
                    width:`${m.val}%`,
                    background: m.color,
                  }} />
                </div>
              </div>
            ))}
          </div>

          {/* Active product status */}
          <div className="bracket-card" style={{ padding:'16px' }}>
            <div className="mono" style={{ fontSize:9, letterSpacing:'0.13em', color:'var(--color-text-dim)', textTransform:'uppercase', marginBottom:12 }}>
              MODULE STATUS
            </div>
            {[
              { label:'Cloud Scanner', status:'ACTIVE', color:'var(--color-scanner)' },
              { label:'HEMIS Engine',  status:'STANDBY',color:'var(--color-text-dim)' },
              { label:'Blue Team',     status:'ACTIVE', color:'var(--color-blueteam)' },
            ].map(m => (
              <div key={m.label} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
                <span style={{ fontSize:11, color:'var(--color-text-secondary)' }}>{m.label}</span>
                <div style={{ display:'flex', alignItems:'center', gap:5 }}>
                  <span style={{
                    width:5, height:5, borderRadius:'50%',
                    background:m.color, display:'inline-block',
                    boxShadow: m.status === 'ACTIVE' ? `0 0 4px ${m.color}` : 'none',
                    animation: m.status === 'ACTIVE' ? 'pulse-dot 2s infinite' : 'none',
                  }} />
                  <span className="mono" style={{ fontSize:9, letterSpacing:'0.1em', color:m.color, textTransform:'uppercase' }}>
                    {m.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
