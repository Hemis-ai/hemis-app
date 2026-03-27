'use client'

import Link from 'next/link'
import { MOCK_SCAN } from '@/lib/mock-data/scanner'
import { PRELOADED_SIMULATION } from '@/lib/mock-data/hemis'
import { INITIAL_ALERTS, HEALTH_SCORE } from '@/lib/mock-data/blueteam'
import { Cloud, Shield, ShieldCheck, AlertTriangle, ArrowRight } from 'lucide-react'

const criticals = INITIAL_ALERTS.filter(a => a.severity === 'CRITICAL').length
const openFindings = MOCK_SCAN.findings.filter(f => f.status === 'OPEN').length

const PRODUCTS = [
  {
    id: 'scanner',
    label: 'Cloud Scanner',
    desc: 'Cloud Security Posture Management',
    href: '/dashboard/scanner',
    color: 'var(--color-scanner)',
    bracketClass: 'bracket-scanner',
    Icon: Cloud,
    stats: [
      { label: 'Risk Score',      value: `${MOCK_SCAN.riskScore}/100`,            alert: MOCK_SCAN.riskScore > 70 },
      { label: 'Open Findings',   value: `${openFindings}`,                        alert: openFindings > 5 },
      { label: 'SOC2 Compliance', value: `${MOCK_SCAN.complianceScore.soc2}%`,     alert: MOCK_SCAN.complianceScore.soc2 < 70 },
      { label: 'Resources',       value: `${MOCK_SCAN.resourcesScanned}`,          alert: false },
    ],
    status: 'Live',
    statusLive: true,
  },
  {
    id: 'hemis',
    label: 'HEMIS',
    desc: 'AI Red Team Simulation Engine',
    href: '/dashboard/hemis',
    color: 'var(--color-hemis)',
    bracketClass: 'bracket-hemis',
    Icon: Shield,
    stats: [
      { label: 'Last Simulation',   value: '3m 21s',                                                              alert: false },
      { label: 'Critical Findings', value: `${PRELOADED_SIMULATION.criticals}`,                                   alert: true },
      { label: 'Techniques Tested', value: `${PRELOADED_SIMULATION.techniques.filter(t => t.status !== 'untested').length}/${PRELOADED_SIMULATION.techniques.length}`, alert: false },
      { label: 'Attack Steps',      value: `${PRELOADED_SIMULATION.steps.length}`,                                alert: false },
    ],
    status: 'Standby',
    statusLive: false,
  },
  {
    id: 'blueteam',
    label: 'Blue Team',
    desc: 'Autonomous Threat Detection & Response',
    href: '/dashboard/blueteam',
    color: 'var(--color-blueteam)',
    bracketClass: 'bracket-blueteam',
    Icon: ShieldCheck,
    stats: [
      { label: 'Health Score',  value: `${HEALTH_SCORE.overall}/100`,   alert: HEALTH_SCORE.overall < 80 },
      { label: 'Active Alerts', value: `${criticals} Critical`,          alert: criticals > 0 },
      { label: 'Avg MTTR',      value: HEALTH_SCORE.mttr,                alert: false },
      { label: 'Coverage',      value: `${HEALTH_SCORE.coverage}%`,      alert: HEALTH_SCORE.coverage < 70 },
    ],
    status: 'Monitoring',
    statusLive: true,
  },
]

const RECENT_EVENTS = [
  { time: '10:07:44', type: 'ALERT',  product: 'Blue Team', color: 'var(--color-hemis)',       msg: 'IAM credentials used from anomalous geolocation' },
  { time: '10:07:33', type: 'HEMIS',  product: 'HEMIS',     color: 'var(--color-hemis)',       msg: 'Simulation: Data exfiltrated to external S3 bucket [T1537]' },
  { time: '10:06:02', type: 'HEMIS',  product: 'HEMIS',     color: 'var(--color-hemis-orange)', msg: 'Full AWS account compromise via valid accounts [T1078]' },
  { time: '10:05:44', type: 'HEMIS',  product: 'HEMIS',     color: 'var(--color-hemis-orange)', msg: 'AWS credentials found in public S3 .env file [T1552]' },
  { time: '10:22:41', type: 'SCAN',   product: 'Scanner',   color: 'var(--color-scanner)',     msg: 'Scan complete — 12 findings across 247 resources' },
  { time: '10:22:00', type: 'SCAN',   product: 'Scanner',   color: 'var(--color-hemis)',       msg: 'S3 bucket "prod-customer-backups" publicly accessible' },
]

export default function DashboardPage() {
  return (
    <div className="tac-grid" style={{ minHeight: '100%', padding: '28px 28px 40px' }}>

      {/* ── Page header ── */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span className="mono" style={{ fontSize: 10, letterSpacing: '0.14em', color: 'var(--color-yellow)', textTransform: 'uppercase' }}>
            Command Center
          </span>
        </div>
        <h1 className="display" style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0, letterSpacing: '-0.02em' }}>
          Security Overview
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', margin: '4px 0 0', fontSize: 13 }}>
          Acme Corp · AWS account 482910 · us-east-1, us-west-2
        </p>
      </div>

      {/* ── Critical alert banner ── */}
      <div style={{
        marginBottom: 20, padding: '13px 18px',
        background: 'var(--color-hemis-dim)',
        border: '1px solid var(--color-hemis)',
        borderRadius: 4,
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <AlertTriangle size={16} style={{ color: 'var(--color-hemis)', flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-hemis)' }}>Critical Risk Detected</span>
          <span style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginLeft: 10 }}>
            3 critical findings require immediate attention — unauthorized access attempt in progress
          </span>
        </div>
        <Link href="/dashboard/blueteam" className="btn btn-ghost" style={{ flexShrink: 0, borderColor: 'var(--color-hemis)', color: 'var(--color-hemis)', fontSize: 12 }}>
          View Alerts
          <ArrowRight size={12} />
        </Link>
      </div>

      {/* ── Product cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 20 }}>
        {PRODUCTS.map(p => (
          <Link key={p.id} href={p.href} style={{ textDecoration: 'none' }}>
            <div
              className={`bracket-card ${p.bracketClass} card-hover`}
              style={{ padding: '20px', cursor: 'pointer', height: '100%' }}
            >
              {/* Card header */}
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
                    <p.Icon size={15} style={{ color: p.color }} strokeWidth={1.75} />
                    <span style={{ fontSize: 14, fontWeight: 600, color: p.color }}>
                      {p.label}
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-dim)' }}>{p.desc}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
                  {p.statusLive
                    ? <span className="dot-live" style={{ width: 5, height: 5, background: p.color, boxShadow: `0 0 4px ${p.color}` }} />
                    : <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--color-text-dim)', display: 'inline-block' }} />
                  }
                  <span style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                    {p.status}
                  </span>
                </div>
              </div>

              {/* Stats grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
                {p.stats.map(s => (
                  <div key={s.label} style={{
                    background: 'var(--color-bg-elevated)',
                    border: `1px solid ${s.alert ? p.color + '40' : 'var(--color-border)'}`,
                    padding: '9px 11px',
                    borderRadius: 3,
                  }}>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 3 }}>
                      {s.label}
                    </div>
                    <div className="mono" style={{ fontSize: 14, fontWeight: 600, color: s.alert ? p.color : 'var(--color-text-primary)' }}>
                      {s.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* CTA */}
              <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: 12, display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 4 }}>
                <span style={{ fontSize: 12, color: p.color }}>Open {p.label}</span>
                <ArrowRight size={12} style={{ color: p.color }} />
              </div>
            </div>
          </Link>
        ))}
      </div>

      {/* ── Bottom row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16 }}>

        {/* Recent Events */}
        <div className="bracket-card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Recent Events
            </span>
            <span className="dot-live" style={{ width: 5, height: 5 }} />
          </div>
          <div>
            {RECENT_EVENTS.map((ev, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'flex-start', gap: 12, padding: '9px 0',
                borderBottom: i < RECENT_EVENTS.length - 1 ? '1px solid var(--color-border)' : 'none',
              }}>
                <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', flexShrink: 0, letterSpacing: '0.02em', paddingTop: 1 }}>
                  {ev.time}
                </span>
                <span style={{
                  fontSize: 10, flexShrink: 0, padding: '2px 6px',
                  color: ev.color, border: `1px solid ${ev.color}`, background: `${ev.color}15`,
                  borderRadius: 3, fontFamily: 'var(--font-mono)', letterSpacing: '0.06em',
                  lineHeight: '18px',
                }}>
                  {ev.product}
                </span>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                  {ev.msg}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Metrics */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

          {/* Security Posture */}
          <div className="bracket-card" style={{ padding: '16px 18px' }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 14 }}>
              Security Posture
            </div>
            {[
              { label: 'Risk Score',     val: 74, color: 'var(--color-hemis)' },
              { label: 'SOC2 Coverage',  val: 61, color: 'var(--color-scanner)' },
              { label: 'Detection Rate', val: 84, color: 'var(--color-blueteam)' },
            ].map(m => (
              <div key={m.label} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                  <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{m.label}</span>
                  <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: m.color }}>{m.val}%</span>
                </div>
                <div className="tac-progress">
                  <div className="tac-progress-fill" style={{ width: `${m.val}%`, background: m.color }} />
                </div>
              </div>
            ))}
          </div>

          {/* Module Status */}
          <div className="bracket-card" style={{ padding: '16px 18px' }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 14 }}>
              Module Status
            </div>
            {[
              { label: 'Cloud Scanner', status: 'Active',   color: 'var(--color-scanner)' },
              { label: 'HEMIS Engine',  status: 'Standby',  color: 'var(--color-text-dim)' },
              { label: 'Blue Team',     status: 'Active',   color: 'var(--color-blueteam)' },
            ].map(m => (
              <div key={m.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 9 }}>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{m.label}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{
                    width: 5, height: 5, borderRadius: '50%',
                    background: m.color, display: 'inline-block',
                    boxShadow: m.status === 'Active' ? `0 0 4px ${m.color}` : 'none',
                    animation: m.status === 'Active' ? 'pulse-dot 2s infinite' : 'none',
                  }} />
                  <span style={{ fontSize: 11, color: m.color }}>{m.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
