'use client'

import { Workflow, Zap, GitBranch, Bell, ShieldCheck, ChevronRight } from 'lucide-react'

const CAPABILITIES = [
  { icon: Zap,        label: 'Automated incident response playbooks', desc: 'Isolates hosts, revokes credentials, and creates tickets in seconds without human intervention' },
  { icon: GitBranch,  label: 'AI-driven adaptive playbooks',          desc: 'Next-gen SOAR reasons through novel attack scenarios — not just rule-based automation, but intelligent response chains' },
  { icon: Bell,       label: 'Threat intel enrichment pipeline',       desc: 'Auto-enriches IOCs against threat feeds, geoIP, WHOIS, and dark web sources on every alert' },
  { icon: ShieldCheck, label: 'Red team finding remediation loop',      desc: 'DAST and BBRT findings automatically trigger ticketing, SLA tracking, and developer notification workflows' },
]

export default function SoarPage() {
  return (
    <div style={{ display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden', alignItems: 'center', justifyContent: 'center', padding: '40px 24px' }}>
      <div style={{ maxWidth: 620, width: '100%' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
          <div style={{
            width: 44, height: 44,
            background: 'var(--color-soar-dim)',
            border: '1px solid var(--color-soar)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Workflow size={20} color="var(--color-soar)" strokeWidth={1.75} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="mono" style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-soar)', letterSpacing: '-0.02em' }}>SOAR</span>
              <span style={{
                fontSize: 10, fontWeight: 600, letterSpacing: '0.12em',
                color: 'var(--color-soar)', borderColor: 'var(--color-soar)',
                background: 'var(--color-soar-dim)', border: '1px solid',
                padding: '2px 8px', textTransform: 'uppercase',
              }}>
                Coming Soon
              </span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginTop: 2 }}>
              Security Orchestration, Automation &amp; Response
            </div>
          </div>
        </div>

        {/* Divider */}
        <div style={{ height: 1, background: 'var(--color-border)', margin: '20px 0' }} />

        {/* Description */}
        <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: '0 0 28px' }}>
          SOAR is the muscle memory of your security operations — automating the full response pipeline from detection to containment.
          When XDR raises an alert, SOAR executes playbooks that isolate hosts, revoke credentials, notify stakeholders, and enrich
          indicators of compromise across threat intel feeds, all without a human in the loop.
        </p>

        {/* Capabilities */}
        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: 12 }}>
          Key Capabilities
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {CAPABILITIES.map(({ icon: Icon, label, desc }) => (
            <div key={label} style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              padding: '12px 14px',
              background: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              opacity: 0.6,
            }}>
              <Icon size={15} color="var(--color-soar)" strokeWidth={1.75} style={{ marginTop: 1, flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 2 }}>{label}</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-dim)', lineHeight: 1.5 }}>{desc}</div>
              </div>
              <ChevronRight size={12} color="var(--color-text-dim)" style={{ marginLeft: 'auto', marginTop: 2, flexShrink: 0 }} />
            </div>
          ))}
        </div>

        {/* Industry note */}
        <div style={{ marginTop: 24, padding: '10px 14px', background: 'color-mix(in srgb, var(--color-soar) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--color-soar) 30%, transparent)' }}>
          <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
            INDUSTRY LEADERS · Palo Alto XSOAR · Splunk SOAR · IBM QRadar SOAR · Tines
          </span>
        </div>

      </div>
    </div>
  )
}
