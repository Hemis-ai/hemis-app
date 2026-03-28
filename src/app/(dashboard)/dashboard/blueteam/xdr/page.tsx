'use client'

import { Monitor, Lock, Cpu, Network, Radar, ChevronRight } from 'lucide-react'

const CAPABILITIES = [
  { icon: Network,  label: 'Cross-layer telemetry correlation', desc: 'Unifies endpoint, network, cloud, and identity signals into a single detection engine' },
  { icon: Cpu,      label: 'AI-powered behavioral analytics',   desc: 'ML models detect zero-days and novel TTPs without relying on signatures' },
  { icon: Radar,    label: 'Real-time MITRE ATT&CK mapping',    desc: 'Every alert automatically maps to tactics and techniques for analyst context' },
  { icon: Lock,     label: 'Automated threat containment',      desc: 'Isolates compromised endpoints and suspends accounts in seconds, not hours' },
]

export default function XdrPage() {
  return (
    <div style={{ display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden', alignItems: 'center', justifyContent: 'center', padding: '40px 24px' }}>
      <div style={{ maxWidth: 620, width: '100%' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
          <div style={{
            width: 44, height: 44,
            background: 'var(--color-xdr-dim)',
            border: '1px solid var(--color-xdr)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Monitor size={20} color="var(--color-xdr)" strokeWidth={1.75} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="mono" style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-xdr)', letterSpacing: '-0.02em' }}>XDR</span>
              <span style={{
                fontSize: 10, fontWeight: 600, letterSpacing: '0.12em',
                color: 'var(--color-xdr)', borderColor: 'var(--color-xdr)',
                background: 'var(--color-xdr-dim)', border: '1px solid',
                padding: '2px 8px', textTransform: 'uppercase',
              }}>
                Coming Soon
              </span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginTop: 2 }}>
              Extended Detection &amp; Response
            </div>
          </div>
        </div>

        {/* Divider */}
        <div style={{ height: 1, background: 'var(--color-border)', margin: '20px 0' }} />

        {/* Description */}
        <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: '0 0 28px' }}>
          XDR unifies telemetry across endpoints, network, cloud, and identity into a single correlated detection engine.
          AI-powered behavioral analytics surface zero-days and attacker TTPs in real time — mapping every alert to MITRE ATT&amp;CK
          automatically, replacing what used to take an entire SOC shift to reconstruct manually.
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
              <Icon size={15} color="var(--color-xdr)" strokeWidth={1.75} style={{ marginTop: 1, flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 2 }}>{label}</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-dim)', lineHeight: 1.5 }}>{desc}</div>
              </div>
              <ChevronRight size={12} color="var(--color-text-dim)" style={{ marginLeft: 'auto', marginTop: 2, flexShrink: 0 }} />
            </div>
          ))}
        </div>

        {/* Industry note */}
        <div style={{ marginTop: 24, padding: '10px 14px', background: 'color-mix(in srgb, var(--color-xdr) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--color-xdr) 30%, transparent)' }}>
          <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
            INDUSTRY LEADERS · CrowdStrike Falcon · SentinelOne Singularity · Palo Alto Cortex XDR · Vectra AI
          </span>
        </div>

      </div>
    </div>
  )
}
