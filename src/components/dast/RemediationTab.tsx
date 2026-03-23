'use client'

import { useState } from 'react'
import type { DastFinding } from '@/lib/types'

interface RemediationTabProps {
  findings: DastFinding[]
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280',
}

export default function RemediationTab({ findings }: RemediationTabProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Sort by CVSS * confidence for priority
  const prioritized = [...findings]
    .filter(f => f.severity !== 'INFO')
    .sort((a, b) => {
      const scoreA = (a.cvssScore || 0) * (a.confidenceScore / 100)
      const scoreB = (b.cvssScore || 0) * (b.confidenceScore / 100)
      return scoreB - scoreA
    })

  // Calculate impact of fixing top N
  const totalRisk = findings.reduce((s, f) => s + f.riskScore, 0)
  const top3Risk = prioritized.slice(0, 3).reduce((s, f) => s + f.riskScore, 0)
  const top3Pct = totalRisk > 0 ? Math.round((top3Risk / totalRisk) * 100) : 0

  function parseRemediationCode(raw: string | null): { language: string; before?: string; after: string } | null {
    if (!raw) return null
    try {
      const parsed = JSON.parse(raw)
      return parsed
    } catch {
      return { language: 'text', after: raw }
    }
  }

  async function handleCopy(text: string, id: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch { /* clipboard not available */ }
  }

  return (
    <div style={{ marginTop: 20 }}>
      {/* Impact Summary */}
      <div className="bracket-card bracket-dast" style={{ padding: 20, marginBottom: 20, background: 'var(--color-bg-secondary)' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 20 }}>
          <div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)', letterSpacing: '0.1em' }}>
              ACTIONABLE FINDINGS
            </div>
            <div className="mono" style={{ fontSize: 28, fontWeight: 800, color: 'var(--color-dast)', marginTop: 4 }}>
              {prioritized.length}
            </div>
          </div>
          <div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)', letterSpacing: '0.1em' }}>
              FIX TOP 3 TO REDUCE RISK BY
            </div>
            <div className="mono" style={{ fontSize: 28, fontWeight: 800, color: '#22c55e', marginTop: 4 }}>
              {top3Pct}%
            </div>
          </div>
          <div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)', letterSpacing: '0.1em' }}>
              EST. REMEDIATION COST
            </div>
            <div className="mono" style={{ fontSize: 28, fontWeight: 800, color: 'var(--color-text-primary)', marginTop: 4 }}>
              ${(prioritized.length * 2.5).toFixed(0)}h
            </div>
            <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)' }}>
              ~2.5h avg per fix
            </div>
          </div>
        </div>
      </div>

      {/* Priority Queue */}
      <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 10 }}>
        FIX QUEUE &mdash; ORDERED BY RISK IMPACT
      </div>

      {prioritized.map((f, i) => {
        const code = parseRemediationCode(f.remediationCode)
        const isExpanded = expandedId === f.id
        const breachCost = (f.cvssScore || 0) * 52000

        return (
          <div
            key={f.id}
            className="bracket-card"
            style={{
              padding: 0, marginBottom: 8, overflow: 'hidden',
              borderLeft: `3px solid ${SEV_COLORS[f.severity]}`,
            }}
          >
            {/* Header */}
            <div
              onClick={() => setExpandedId(isExpanded ? null : f.id)}
              style={{
                padding: '12px 16px', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 12,
                background: i < 3 ? `${SEV_COLORS[f.severity]}08` : 'transparent',
              }}
            >
              <div className="mono" style={{
                fontSize: 12, fontWeight: 800, color: 'var(--color-text-secondary)',
                width: 28, flexShrink: 0,
              }}>
                #{i + 1}
              </div>
              <span className="mono" style={{
                fontSize: 9, padding: '2px 6px', borderRadius: 3,
                color: SEV_COLORS[f.severity],
                border: `1px solid ${SEV_COLORS[f.severity]}`,
                flexShrink: 0,
              }}>
                {f.severity}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  {f.title}
                </div>
                <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', marginTop: 2 }}>
                  {f.affectedUrl}
                </div>
              </div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)', flexShrink: 0 }}>
                CVSS {f.cvssScore ?? '—'}
              </div>
              <div className="mono" style={{
                fontSize: 10, flexShrink: 0,
                color: breachCost > 300000 ? '#ef4444' : '#f97316',
              }}>
                ${breachCost >= 1000000 ? `${(breachCost / 1000000).toFixed(1)}M` : `${(breachCost / 1000).toFixed(0)}K`}
              </div>
              <span style={{ fontSize: 12, color: 'var(--color-text-secondary)', flexShrink: 0 }}>
                {isExpanded ? '▾' : '▸'}
              </span>
            </div>

            {/* Expanded Detail */}
            {isExpanded && (
              <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--color-border)' }}>
                {/* Remediation text */}
                <div style={{ marginTop: 12 }}>
                  <div className="mono" style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-dast)', marginBottom: 6, letterSpacing: '0.08em' }}>
                    REMEDIATION
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
                    {f.remediation}
                  </div>
                </div>

                {/* Code Fix */}
                {code && (
                  <div style={{ marginTop: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <div className="mono" style={{ fontSize: 10, fontWeight: 700, color: '#22c55e', letterSpacing: '0.08em' }}>
                        FIX CODE ({code.language.toUpperCase()})
                      </div>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleCopy(code.after, f.id) }}
                        className="mono"
                        style={{
                          fontSize: 9, padding: '3px 8px', borderRadius: 3,
                          background: copiedId === f.id ? '#22c55e20' : 'var(--color-bg-secondary)',
                          border: `1px solid ${copiedId === f.id ? '#22c55e' : 'var(--color-border)'}`,
                          color: copiedId === f.id ? '#22c55e' : 'var(--color-text-secondary)',
                          cursor: 'pointer',
                        }}
                      >
                        {copiedId === f.id ? 'COPIED' : 'COPY'}
                      </button>
                    </div>
                    {code.before && (
                      <pre style={{
                        padding: 10, borderRadius: 4, fontSize: 11, lineHeight: 1.5,
                        background: '#ef444410', border: '1px solid #ef444430',
                        color: '#ef4444', overflow: 'auto', marginBottom: 6,
                        fontFamily: 'var(--font-mono)',
                      }}>
                        <span style={{ fontSize: 9, opacity: 0.6 }}>{'// BEFORE (vulnerable)\n'}</span>
                        {code.before}
                      </pre>
                    )}
                    <pre style={{
                      padding: 10, borderRadius: 4, fontSize: 11, lineHeight: 1.5,
                      background: '#22c55e10', border: '1px solid #22c55e30',
                      color: '#22c55e', overflow: 'auto',
                      fontFamily: 'var(--font-mono)',
                    }}>
                      <span style={{ fontSize: 9, opacity: 0.6 }}>{'// AFTER (secure)\n'}</span>
                      {code.after}
                    </pre>
                  </div>
                )}

                {/* Business Impact */}
                {f.businessImpact && (
                  <div style={{ marginTop: 12, padding: 10, borderRadius: 4, background: '#f9731610', border: '1px solid #f9731630' }}>
                    <div className="mono" style={{ fontSize: 9, fontWeight: 700, color: '#f97316', letterSpacing: '0.08em', marginBottom: 4 }}>
                      BUSINESS IMPACT
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                      {f.businessImpact}
                    </div>
                  </div>
                )}

                {/* References */}
                <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
                  {f.cweId && (
                    <span className="mono" style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {f.cweId}
                    </span>
                  )}
                  {f.owaspCategory && (
                    <span className="mono" style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {f.owaspCategory}
                    </span>
                  )}
                  {f.mitreAttackIds?.map(id => (
                    <span key={id} className="mono" style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: '#7c3aed15', border: '1px solid #7c3aed40', color: '#7c3aed' }}>
                      {id}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )
      })}

      {prioritized.length === 0 && (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--color-text-secondary)' }}>
          <div className="mono" style={{ fontSize: 12 }}>No actionable findings</div>
          <div className="mono" style={{ fontSize: 10, marginTop: 4 }}>Run a scan to see remediation priorities</div>
        </div>
      )}
    </div>
  )
}
