'use client'

import { Layers, Key, Database, Globe, Server, ChevronRight } from 'lucide-react'

const CAPABILITIES = [
  { icon: Key,      label: 'Honey credential fabric',       desc: 'Fake API keys, AWS tokens, and AD accounts seeded throughout the environment — any use triggers instant breach confirmation' },
  { icon: Database, label: 'Decoy asset mesh',              desc: 'Ghost endpoints, fake databases, and shadow cloud buckets woven alongside real assets; legitimate users never touch them' },
  { icon: Globe,    label: 'OSINT canary tokens',           desc: 'Embedded tokens in documents, configs, and Kubernetes secrets — when exfiltrated and used anywhere globally, you are alerted instantly' },
  { icon: Server,   label: 'Adaptive deception positioning', desc: 'Decoys auto-positioned along attack paths discovered by White Box and Black Box red team simulations' },
]

export default function DectPage() {
  return (
    <div style={{ display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden', alignItems: 'center', justifyContent: 'center', padding: '40px 24px' }}>
      <div style={{ maxWidth: 620, width: '100%' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
          <div style={{
            width: 44, height: 44,
            background: 'var(--color-dect-dim)',
            border: '1px solid var(--color-dect)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Layers size={20} color="var(--color-dect)" strokeWidth={1.75} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="mono" style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-dect)', letterSpacing: '-0.02em' }}>DECT</span>
              <span style={{
                fontSize: 10, fontWeight: 600, letterSpacing: '0.12em',
                color: 'var(--color-dect)', borderColor: 'var(--color-dect)',
                background: 'var(--color-dect-dim)', border: '1px solid',
                padding: '2px 8px', textTransform: 'uppercase',
              }}>
                Coming Soon
              </span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginTop: 2 }}>
              Deception Technology
            </div>
          </div>
        </div>

        {/* Divider */}
        <div style={{ height: 1, background: 'var(--color-border)', margin: '20px 0' }} />

        {/* Description */}
        <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: '0 0 28px' }}>
          DECT deploys a fabric of fake assets — honey credentials, decoy APIs, ghost AD forests, and canary cloud buckets —
          woven throughout your real environment. Any interaction with a decoy is a guaranteed true-positive with zero false alerts.
          A single canary token embedded in a Kubernetes config has caught nation-state actors that million-dollar SIEM deployments missed entirely.
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
              <Icon size={15} color="var(--color-dect)" strokeWidth={1.75} style={{ marginTop: 1, flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 2 }}>{label}</div>
                <div style={{ fontSize: 11, color: 'var(--color-text-dim)', lineHeight: 1.5 }}>{desc}</div>
              </div>
              <ChevronRight size={12} color="var(--color-text-dim)" style={{ marginLeft: 'auto', marginTop: 2, flexShrink: 0 }} />
            </div>
          ))}
        </div>

        {/* Industry note */}
        <div style={{ marginTop: 24, padding: '10px 14px', background: 'color-mix(in srgb, var(--color-dect) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--color-dect) 30%, transparent)' }}>
          <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
            INDUSTRY LEADERS · Thinkst Canary · Attivo Networks (SentinelOne) · Illusive Networks (Proofpoint) · TrapX
          </span>
        </div>

      </div>
    </div>
  )
}
