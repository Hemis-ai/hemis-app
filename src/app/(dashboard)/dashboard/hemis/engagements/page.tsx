'use client'

import { useState } from 'react'

interface Engagement {
  id: string
  target: string
  status: 'ACTIVE' | 'COMPLETED' | 'PAUSED'
  findings: number
  createdAt: string
  authorized: boolean
  scope: string[]
}

const MOCK_ENGAGEMENTS: Engagement[] = [
  {
    id: 'eng_20260314_001',
    target: 'api.acme-corp.com',
    status: 'ACTIVE',
    findings: 8,
    createdAt: '2026-03-14T08:00:00Z',
    authorized: true,
    scope: ['10.0.0.0/8', 'api.acme-corp.com'],
  },
  {
    id: 'eng_20260313_042',
    target: 'internal.example.com',
    status: 'COMPLETED',
    findings: 12,
    createdAt: '2026-03-13T14:30:00Z',
    authorized: true,
    scope: ['192.168.0.0/16'],
  },
  {
    id: 'eng_20260312_015',
    target: 'staging-api.demo.io',
    status: 'PAUSED',
    findings: 5,
    createdAt: '2026-03-12T10:15:00Z',
    authorized: true,
    scope: ['staging-api.demo.io'],
  },
  {
    id: 'eng_20260311_088',
    target: 'prod-app.company.net',
    status: 'COMPLETED',
    findings: 23,
    createdAt: '2026-03-11T09:00:00Z',
    authorized: true,
    scope: ['prod-app.company.net', '172.16.0.0/12'],
  },
]

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, { bg: string; color: string }> = {
    ACTIVE: { bg: 'var(--color-scanner)22', color: 'var(--color-scanner)' },
    COMPLETED: { bg: 'var(--color-blueteam)22', color: 'var(--color-blueteam)' },
    PAUSED: { bg: 'var(--color-hemis-orange)22', color: 'var(--color-hemis-orange)' },
  }
  const style = colors[status] || colors.COMPLETED
  return (
    <div style={{
      display: 'inline-block',
      padding: '4px 10px',
      background: style.bg,
      border: `1px solid ${style.color}`,
      borderRadius: 0,
      fontSize: 9,
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      color: style.color,
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
    }}>
      {status}
    </div>
  )
}

function AuthBadge() {
  return (
    <div style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 5,
      padding: '4px 10px',
      background: 'var(--color-scanner)15',
      border: '1px solid var(--color-scanner)',
      borderRadius: 0,
      fontSize: 9,
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      color: 'var(--color-scanner)',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
    }}>
      <span>✓</span>
      <span>AUTHORIZED</span>
    </div>
  )
}

export default function EngagementsPage() {
  const [engagements] = useState<Engagement[]>(MOCK_ENGAGEMENTS)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  return (
    <div style={{ minHeight: '100vh', background: 'var(--color-bg-surface)' }}>
      {/* Header */}
      <div style={{
        padding: '20px 24px',
        borderBottom: '1px solid var(--color-border)',
        background: 'var(--color-bg-surface)',
        position: 'sticky',
        top: 0,
        zIndex: 10,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--color-hemis)', letterSpacing: '0.15em', marginBottom: 4, textTransform: 'uppercase' }}>
            [ HEMIS ENGAGEMENT MANAGER ]
          </div>
          <h1 className="display" style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
            Authorized Engagements
          </h1>
        </div>
        <button style={{
          padding: '10px 18px',
          background: 'var(--color-hemis)',
          color: '#ffffff',
          border: 'none',
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          cursor: 'pointer',
          transition: 'all 0.12s',
        }}
        onMouseEnter={e => {
          e.currentTarget.style.boxShadow = '0 0 12px var(--color-hemis)44'
        }}
        onMouseLeave={e => {
          e.currentTarget.style.boxShadow = 'none'
        }}
        >
          + NEW ENGAGEMENT
        </button>
      </div>

      <div style={{ padding: '20px 24px' }}>
        {/* Engagements List */}
        <div>
          {engagements.map((engagement, idx) => (
            <div key={engagement.id} style={{
              background: 'var(--color-bg-elevated)',
              border: '1px solid var(--color-border)',
              borderRadius: 0,
              marginBottom: idx < engagements.length - 1 ? 12 : 0,
            }}>
              {/* Header Row */}
              <div
                onClick={() => setExpandedId(expandedId === engagement.id ? null : engagement.id)}
                style={{
                  padding: '16px 18px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  cursor: 'pointer',
                  transition: 'all 0.12s',
                  background: expandedId === engagement.id ? 'var(--color-bg-surface)' : 'transparent',
                }}
              >
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 6 }}>
                    <div className="mono" style={{ fontSize: 9, color: 'var(--color-hemis-orange)', letterSpacing: '0.08em', fontWeight: 600, minWidth: 140 }}>
                      {engagement.id}
                    </div>
                    <AuthBadge />
                  </div>
                  <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', margin: 0, marginBottom: 4 }}>
                    {engagement.target}
                  </h3>
                  <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.06em' }}>
                    Created {new Date(engagement.createdAt).toLocaleDateString()} at {new Date(engagement.createdAt).toLocaleTimeString()}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexShrink: 0 }}>
                  <div style={{ textAlign: 'right' }}>
                    <div className="mono" style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-hemis)', marginBottom: 2 }}>
                      {engagement.findings}
                    </div>
                    <div className="mono" style={{ fontSize: 8, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      FINDINGS
                    </div>
                  </div>
                  <StatusBadge status={engagement.status} />
                  <span style={{ fontSize: 14, color: 'var(--color-text-dim)', transition: 'all 0.12s', transform: expandedId === engagement.id ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                    ▼
                  </span>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedId === engagement.id && (
                <div style={{
                  padding: '16px 18px',
                  borderTop: '1px solid var(--color-border)',
                  background: 'var(--color-bg-surface)',
                }}>
                  <div style={{ marginBottom: 16 }}>
                    <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', marginBottom: 8, textTransform: 'uppercase' }}>
                      Authorized Scope
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {engagement.scope.map(cidr => (
                        <div key={cidr} style={{
                          padding: '6px 10px',
                          background: 'var(--color-scanner)15',
                          border: '1px solid var(--color-scanner)44',
                          borderRadius: 0,
                          fontSize: 10,
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--color-scanner)',
                        }}>
                          {cidr}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                    <div>
                      <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', marginBottom: 6, textTransform: 'uppercase' }}>
                        Total Duration
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--color-text-primary)', fontWeight: 500 }}>
                        {engagement.status === 'ACTIVE' ? 'Ongoing' : '2 hours 45 minutes'}
                      </div>
                    </div>
                    <div>
                      <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', marginBottom: 6, textTransform: 'uppercase' }}>
                        Last Activity
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--color-text-primary)', fontWeight: 500 }}>
                        {new Date(engagement.createdAt).toLocaleString()}
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 8 }}>
                    {engagement.status === 'ACTIVE' && (
                      <>
                        <button style={{
                          padding: '8px 14px',
                          background: 'var(--color-bg-elevated)',
                          border: '1px solid var(--color-border)',
                          color: 'var(--color-text-secondary)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 9,
                          fontWeight: 600,
                          letterSpacing: '0.08em',
                          textTransform: 'uppercase',
                          cursor: 'pointer',
                        }}>
                          Pause
                        </button>
                        <button style={{
                          padding: '8px 14px',
                          background: 'var(--color-hemis)20',
                          border: '1px solid var(--color-hemis)',
                          color: 'var(--color-hemis)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 9,
                          fontWeight: 600,
                          letterSpacing: '0.08em',
                          textTransform: 'uppercase',
                          cursor: 'pointer',
                        }}>
                          Run Scan
                        </button>
                      </>
                    )}
                    {engagement.status === 'COMPLETED' && (
                      <button style={{
                        padding: '8px 14px',
                        background: 'var(--color-bg-elevated)',
                        border: '1px solid var(--color-border)',
                        color: 'var(--color-text-secondary)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: 9,
                        fontWeight: 600,
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase',
                        cursor: 'pointer',
                      }}>
                        View Report
                      </button>
                    )}
                    <button style={{
                      padding: '8px 14px',
                      background: 'var(--color-bg-elevated)',
                      border: '1px solid var(--color-border)',
                      color: 'var(--color-text-secondary)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 9,
                      fontWeight: 600,
                      letterSpacing: '0.08em',
                      textTransform: 'uppercase',
                      cursor: 'pointer',
                      marginLeft: 'auto',
                    }}>
                      Edit
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
