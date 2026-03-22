'use client'

import dynamic from 'next/dynamic'

const AttackGraph3D = dynamic(() => import('@/components/wbrt/AttackGraph3D'), { ssr: false })

import { useState, useCallback } from 'react'
import type {
  AttackGraph,
  AttackGraphNode,
  KillChain,
  WbrtFinding,
  WbrtReport,
} from '@/lib/types/wbrt'
import {
  MOCK_WBRT_ENGAGEMENT,
  MOCK_ATTACK_GRAPH,
  MOCK_KILL_CHAINS,
  MOCK_WBRT_FINDINGS,
  MOCK_WBRT_REPORT,
  MOCK_SAST_SCANS_FOR_IMPORT,
} from '@/lib/mock-data/wbrt'

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
  INFO:     'var(--color-text-dim)',
}

const SEV_BG: Record<string, string> = {
  CRITICAL: 'rgba(239,90,90,0.12)',
  HIGH:     'rgba(255,160,50,0.12)',
  MEDIUM:   'rgba(242,209,86,0.10)',
  LOW:      'rgba(90,176,255,0.10)',
  INFO:     'rgba(140,160,180,0.08)',
}

// ─── Attack graph node colors ─────────────────────────────────────────────────

const NODE_COLOR: Record<string, string> = {
  entry_point:  '#00d4aa',
  vulnerability: '#ef5a5a',
  privilege:    '#f2d156',
  asset:        '#5ab0ff',
  crown_jewel:  '#b06aff',
  data:         '#ff9a3c',
}

// ─── Kill chain likelihood / impact colors ───────────────────────────────────

const LIKELIHOOD_COLOR: Record<string, string> = {
  VERY_HIGH: 'var(--color-sev-critical)',
  HIGH:      'var(--color-sev-high)',
  MEDIUM:    'var(--color-sev-medium)',
  LOW:       'var(--color-sev-low)',
}

const IMPACT_COLOR: Record<string, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
}

const EFFORT_COLOR: Record<string, string> = {
  LOW:    'var(--color-sev-low)',
  MEDIUM: 'var(--color-sev-medium)',
  HIGH:   'var(--color-sev-high)',
}

// ─── MITRE tactics (14 standard) ─────────────────────────────────────────────

const MITRE_TACTICS = [
  { id: 'TA0001', short: 'InitAcc' },
  { id: 'TA0002', short: 'Exec' },
  { id: 'TA0003', short: 'Persist' },
  { id: 'TA0004', short: 'PrivEsc' },
  { id: 'TA0005', short: 'DefEvad' },
  { id: 'TA0006', short: 'CredAcc' },
  { id: 'TA0007', short: 'Discov' },
  { id: 'TA0008', short: 'LatMov' },
  { id: 'TA0009', short: 'Collect' },
  { id: 'TA0010', short: 'Exfil' },
  { id: 'TA0011', short: 'C2' },
  { id: 'TA0040', short: 'Impact' },
  { id: 'TA0042', short: 'RessDev' },
  { id: 'TA0043', short: 'Recon' },
]

// ─── Business impact score color ─────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 85) return 'var(--color-sev-critical)'
  if (score >= 65) return 'var(--color-sev-high)'
  if (score >= 40) return 'var(--color-sev-medium)'
  return 'var(--color-sev-low)'
}

// ─── Risk score color ─────────────────────────────────────────────────────────

function riskColor(score: number): string {
  if (score >= 75) return 'var(--color-sev-critical)'
  if (score >= 50) return 'var(--color-sev-high)'
  if (score >= 25) return 'var(--color-sev-medium)'
  return 'var(--color-sev-low)'
}

// ─── Markdown-like summary renderer ──────────────────────────────────────────

function renderSummaryMarkdown(md: string): React.ReactNode[] {
  const lines = md.split('\n')
  const elements: React.ReactNode[] = []

  lines.forEach((line, i) => {
    if (line.startsWith('## ')) {
      elements.push(
        <h2 key={i} style={{
          fontSize: 15, fontWeight: 700, color: 'var(--color-text-primary)',
          margin: '18px 0 8px', borderBottom: '1px solid var(--color-border)', paddingBottom: 6,
        }}>
          {line.replace('## ', '')}
        </h2>
      )
    } else if (line.startsWith('### ')) {
      elements.push(
        <h3 key={i} style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text-primary)', margin: '14px 0 6px' }}>
          {line.replace('### ', '')}
        </h3>
      )
    } else if (line === '---') {
      elements.push(<hr key={i} style={{ border: 'none', borderTop: '1px solid var(--color-border)', margin: '12px 0' }} />)
    } else if (line.startsWith('|') && !line.includes('---')) {
      const cells = line.split('|').filter(c => c.trim() !== '')
      const isHeader = lines[i + 1]?.includes('---')
      elements.push(
        <div key={i} style={{
          display: 'grid', gridTemplateColumns: `repeat(${cells.length}, 1fr)`,
          borderBottom: '1px solid var(--color-border)',
        }}>
          {cells.map((cell, j) => (
            <div key={j} style={{
              padding: '6px 10px', fontSize: 12,
              fontWeight: isHeader ? 700 : 400,
              color: isHeader ? 'var(--color-text-secondary)' : 'var(--color-text-primary)',
              background: isHeader ? 'var(--color-bg-surface)' : 'transparent',
              fontFamily: 'var(--font-mono)',
              borderRight: j < cells.length - 1 ? '1px solid var(--color-border)' : 'none',
            }}>
              {cell.trim()}
            </div>
          ))}
        </div>
      )
    } else if (line.startsWith('- ')) {
      const content = line.replace('- ', '')
      elements.push(
        <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 4, paddingLeft: 8 }}>
          <span style={{ color: 'var(--color-text-dim)', flexShrink: 0, marginTop: 2 }}>•</span>
          <span
            style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.6 }}
            dangerouslySetInnerHTML={{ __html: content.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>') }}
          />
        </div>
      )
    } else if (line.trim() === '') {
      elements.push(<div key={i} style={{ height: 6 }} />)
    } else {
      elements.push(
        <p
          key={i}
          style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: '4px 0' }}
          dangerouslySetInnerHTML={{ __html: line.replace(/\*\*(.+?)\*\*/g, '<strong style="color: var(--color-text-primary)">$1</strong>') }}
        />
      )
    }
  })

  return elements
}

// ─── Kill Chain card ──────────────────────────────────────────────────────────

function KillChainCard({
  chain,
  expanded,
  onToggle,
}: {
  chain: KillChain
  expanded: boolean
  onToggle: () => void
}) {
  const tacticIds = new Set(chain.steps.map(s => s.tacticId))
  const lColor = LIKELIHOOD_COLOR[chain.likelihood] ?? 'var(--color-border)'

  return (
    <div style={{
      border: `1px solid ${lColor}44`,
      background: 'var(--color-bg-elevated)',
      borderRadius: 2, marginBottom: 12, overflow: 'hidden',
    }}>
      {/* Header */}
      <div
        onClick={onToggle}
        style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '14px 18px', cursor: 'pointer', userSelect: 'none',
          borderBottom: expanded ? '1px solid var(--color-border)' : 'none',
        }}
      >
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
          padding: '3px 8px', letterSpacing: '0.1em',
          background: lColor + '20', color: lColor,
          border: `1px solid ${lColor}55`, borderRadius: 2, whiteSpace: 'nowrap',
        }}>
          {chain.likelihood.replace('_', ' ')}
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9,
          padding: '3px 8px',
          background: (IMPACT_COLOR[chain.impact] ?? '#888') + '15',
          color: IMPACT_COLOR[chain.impact] ?? '#888',
          border: `1px solid ${IMPACT_COLOR[chain.impact] ?? '#888'}44`,
          borderRadius: 2, whiteSpace: 'nowrap',
        }}>
          {chain.impact} IMPACT
        </span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>
          {chain.name}
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)', marginRight: 4 }}>
          {chain.steps.length} steps
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
          {expanded ? '▲' : '▼'}
        </span>
      </div>

      {/* Expanded body */}
      {expanded && (
        <div style={{ padding: '18px 20px' }}>
          {/* Narrative */}
          <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: '0 0 16px' }}>
            {chain.narrative}
          </p>

          {/* Meta */}
          <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
              Time to exploit: <span style={{ color: 'var(--color-text-primary)' }}>{chain.estimatedTimeToExploit}</span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
              Detection difficulty:{' '}
              <span style={{
                color: chain.detectionDifficulty === 'VERY_DIFFICULT' || chain.detectionDifficulty === 'DIFFICULT'
                  ? 'var(--color-sev-high)' : 'var(--color-sev-medium)',
              }}>
                {chain.detectionDifficulty}
              </span>
            </div>
          </div>

          {/* MITRE tactic bar */}
          <div style={{ marginBottom: 18 }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
              color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase',
            }}>
              MITRE ATT&amp;CK Coverage
            </div>
            <div style={{ display: 'flex', gap: 3 }}>
              {MITRE_TACTICS.map(t => {
                const active = tacticIds.has(t.id)
                return (
                  <div
                    key={t.id}
                    title={`${t.id}: ${t.short}`}
                    style={{
                      flex: 1, padding: '6px 2px', textAlign: 'center',
                      background: active ? 'rgba(0,212,170,0.18)' : 'var(--color-bg-surface)',
                      border: `1px solid ${active ? '#00d4aa55' : 'var(--color-border)'}`,
                      borderRadius: 2,
                    }}
                  >
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: 7,
                      color: active ? '#00d4aa' : 'var(--color-text-dim)',
                      letterSpacing: '0.03em', wordBreak: 'break-all',
                    }}>
                      {t.short}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Steps */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
            color: 'var(--color-text-dim)', marginBottom: 10, textTransform: 'uppercase',
          }}>
            Attack Steps
          </div>
          {chain.steps.map((step, i) => (
            <div key={step.seq} style={{
              display: 'flex', gap: 14, padding: '12px 0',
              borderBottom: i < chain.steps.length - 1 ? '1px solid var(--color-border)' : 'none',
            }}>
              {/* Sequence circle */}
              <div style={{
                width: 28, height: 28, borderRadius: '50%', flexShrink: 0, marginTop: 2,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: step.result === 'SUCCESS'
                  ? 'rgba(239,90,90,0.15)'
                  : step.result === 'PARTIAL'
                  ? 'rgba(242,209,86,0.15)'
                  : 'var(--color-bg-surface)',
                border: `2px solid ${step.result === 'SUCCESS'
                  ? 'var(--color-sev-critical)'
                  : step.result === 'PARTIAL'
                  ? 'var(--color-sev-medium)'
                  : 'var(--color-border)'}`,
              }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, color: 'var(--color-text-primary)' }}>
                  {step.seq}
                </span>
              </div>

              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {step.tactic}
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9, padding: '1px 6px',
                    background: 'var(--color-bg-surface)', color: '#00d4aa', border: '1px solid #00d4aa44',
                  }}>
                    {step.techniqueId}
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>
                    {step.technique}{step.subTechnique ? ` — ${step.subTechnique}` : ''}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 4 }}>
                  {step.action}
                </div>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)' }}>
                    Target: <span style={{ color: 'var(--color-text-secondary)' }}>{step.target}</span>
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9,
                    color: step.result === 'SUCCESS'
                      ? 'var(--color-sev-critical)'
                      : step.result === 'PARTIAL'
                      ? 'var(--color-sev-medium)'
                      : 'var(--color-text-dim)',
                  }}>
                    {step.result}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Finding card ─────────────────────────────────────────────────────────────

function FindingCard({
  finding,
  expanded,
  onToggle,
  onStatusChange,
}: {
  finding: WbrtFinding
  expanded: boolean
  onToggle: () => void
  onStatusChange: (id: string, status: string) => void
}) {
  const sev = finding.severity
  const impact = finding.businessImpact
  const nodeCount = finding.attackPathNodeIds.length

  return (
    <div style={{
      border: `1px solid ${SEV_COLOR[sev] ?? 'var(--color-border)'}44`,
      background: SEV_BG[sev] ?? 'var(--color-bg-elevated)',
      borderRadius: 2, marginBottom: 10, overflow: 'hidden',
    }}>
      {/* Header */}
      <div
        onClick={onToggle}
        style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '12px 16px', cursor: 'pointer', userSelect: 'none',
        }}
      >
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
          padding: '3px 8px', letterSpacing: '0.1em',
          background: (SEV_COLOR[sev] ?? '#888') + '22',
          color: SEV_COLOR[sev] ?? '#888',
          border: `1px solid ${SEV_COLOR[sev] ?? '#888'}55`,
          borderRadius: 2, whiteSpace: 'nowrap', minWidth: 68, textAlign: 'center',
        }}>
          {sev}
        </span>

        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>
          {finding.name}
        </span>

        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <div style={{ fontSize: 20, fontWeight: 800, color: scoreColor(impact.score), lineHeight: 1 }}>
            {impact.score}
            <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--color-text-dim)' }}>/100</span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--color-text-dim)', marginTop: 2 }}>
            IMPACT SCORE
          </div>
        </div>

        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
          {expanded ? '▲' : '▼'}
        </span>
      </div>

      {/* Quick info */}
      <div style={{ padding: '0 16px 12px', display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
          Est. financial impact: <span style={{ color: 'var(--color-sev-high)' }}>{impact.financialEstimate}</span>
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
          Records at risk: <span style={{ color: 'var(--color-text-secondary)' }}>{impact.dataRecordsAtRisk.toLocaleString()}</span>
        </span>
        {/* Attack path dots */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
          {Array.from({ length: nodeCount }).map((_, i) => (
            <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
              <span style={{
                width: 8, height: 8, borderRadius: '50%',
                background: i === 0 ? '#00d4aa' : i === nodeCount - 1 ? '#b06aff' : 'var(--color-text-secondary)',
                display: 'inline-block',
              }} />
              {i < nodeCount - 1 && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--color-text-dim)' }}>—</span>
              )}
            </span>
          ))}
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', marginLeft: 4 }}>
            {nodeCount} nodes
          </span>
        </div>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 8px',
          background: finding.status === 'OPEN'
            ? 'rgba(239,90,90,0.15)'
            : finding.status === 'REMEDIATED'
            ? 'rgba(0,212,170,0.15)'
            : 'var(--color-bg-surface)',
          color: finding.status === 'OPEN'
            ? 'var(--color-sev-critical)'
            : finding.status === 'REMEDIATED'
            ? '#00d4aa'
            : 'var(--color-text-secondary)',
          border: `1px solid ${finding.status === 'OPEN'
            ? 'var(--color-sev-critical)'
            : finding.status === 'REMEDIATED'
            ? '#00d4aa'
            : 'var(--color-border)'}44`,
          marginLeft: 'auto',
        }}>
          {finding.status}
        </span>
      </div>

      {/* Expanded body */}
      {expanded && (
        <div style={{ borderTop: '1px solid var(--color-border)', padding: '16px 18px' }}>
          <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, margin: '0 0 14px' }}>
            {finding.attackPathDescription}
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
                color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase',
              }}>
                Affected Data Types
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {impact.dataTypes.map(dt => (
                  <span key={dt} style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 8px',
                    background: 'rgba(239,90,90,0.1)', color: 'var(--color-sev-critical)',
                    border: '1px solid rgba(239,90,90,0.3)', borderRadius: 2,
                  }}>
                    {dt}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
                color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase',
              }}>
                Compliance Impact
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {impact.complianceFrameworksAffected.map(fw => (
                  <span key={fw} style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 8px',
                    background: 'rgba(255,160,50,0.1)', color: 'var(--color-sev-high)',
                    border: '1px solid rgba(255,160,50,0.3)', borderRadius: 2,
                  }}>
                    {fw}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Business impact detail */}
          <div style={{
            background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)',
            padding: 12, marginBottom: 14, borderRadius: 2,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
              color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase',
            }}>
              Business Impact Detail
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>
                <strong style={{ color: 'var(--color-text-primary)' }}>Operational:</strong>{' '}
                {impact.operationalImpact}
              </div>
              <div style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>
                <strong style={{ color: 'var(--color-text-primary)' }}>Legal Exposure:</strong>{' '}
                {impact.legalExposure}
              </div>
            </div>
          </div>

          {/* Remediation steps */}
          <div style={{ marginBottom: 14 }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
              color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase',
            }}>
              Remediation Steps
            </div>
            <ol style={{ margin: 0, paddingLeft: 18 }}>
              {finding.remediationSteps.map((step, i) => (
                <li key={i} style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 4 }}>
                  {step}
                </li>
              ))}
            </ol>
          </div>

          {/* MITRE table */}
          <div style={{ marginBottom: 14 }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
              color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase',
            }}>
              MITRE ATT&amp;CK Mapping
            </div>
            <div style={{ border: '1px solid var(--color-border)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{
                display: 'grid', gridTemplateColumns: '140px 100px 1fr',
                background: 'var(--color-bg-surface)', borderBottom: '1px solid var(--color-border)',
              }}>
                {['TACTIC', 'TECHNIQUE', 'SUB-TECHNIQUE'].map((h, j) => (
                  <div key={h} style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)',
                    padding: '6px 10px',
                    borderRight: j < 2 ? '1px solid var(--color-border)' : 'none',
                  }}>
                    {h}
                  </div>
                ))}
              </div>
              {finding.mitreMapping.map((m, i) => (
                <div key={i} style={{
                  display: 'grid', gridTemplateColumns: '140px 100px 1fr',
                  borderBottom: i < finding.mitreMapping.length - 1 ? '1px solid var(--color-border)' : 'none',
                }}>
                  <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', padding: '7px 10px', borderRight: '1px solid var(--color-border)' }}>
                    {m.tacticName}
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#00d4aa', padding: '7px 10px', borderRight: '1px solid var(--color-border)' }}>
                    {m.techniqueId}
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)', padding: '7px 10px' }}>
                    {m.subTechniqueId ?? '—'}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Status update */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>Update status:</span>
            <select
              value={finding.status}
              onChange={e => onStatusChange(finding.id, e.target.value)}
              style={{
                background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)',
                color: 'var(--color-text-primary)', padding: '4px 10px',
                fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer',
              }}
            >
              <option value="OPEN">OPEN</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="IN_PROGRESS">IN_PROGRESS</option>
              <option value="REMEDIATED">REMEDIATED</option>
              <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
            </select>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Risk gauge SVG ───────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const color = riskColor(score)
  const radius = 52
  const circ = 2 * Math.PI * radius
  const progress = (score / 100) * circ

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <svg width={130} height={130} viewBox="0 0 130 130">
        <circle cx={65} cy={65} r={radius} fill="none" stroke="var(--color-bg-surface)" strokeWidth={10} />
        <circle
          cx={65} cy={65} r={radius}
          fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${progress} ${circ - progress}`}
          strokeLinecap="round"
          style={{ transform: 'rotate(-90deg)', transformOrigin: '65px 65px' }}
        />
        <text x={65} y={60} textAnchor="middle" fontSize={24} fontWeight={800} fill={color} fontFamily="var(--font-display)">
          {score}
        </text>
        <text x={65} y={76} textAnchor="middle" fontSize={10} fill="var(--color-text-dim)" fontFamily="var(--font-mono)">
          /100
        </text>
      </svg>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color, letterSpacing: '0.1em', fontWeight: 700 }}>
        RISK SCORE
      </div>
    </div>
  )
}

// ─── Main WBRT Page ───────────────────────────────────────────────────────────

type TabId = 'engagement' | 'attack-graph' | 'kill-chains' | 'findings' | 'report'

export default function WbrtPage() {

  // ── Active tab ──────────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<TabId>('engagement')

  // ── Engagement form ─────────────────────────────────────────────────────
  const [inputMode, setInputMode] = useState<'import-sast' | 'upload-code'>('import-sast')
  const [selectedSastScanId, setSelectedSastScanId] = useState<string | null>(null)
  const [engagementForm, setEngagementForm] = useState({
    name: MOCK_WBRT_ENGAGEMENT.name,
    deployment: MOCK_WBRT_ENGAGEMENT.architectureContext.deployment,
    techStack: MOCK_WBRT_ENGAGEMENT.architectureContext.techStack.join(', '),
    cloudProviders: MOCK_WBRT_ENGAGEMENT.architectureContext.cloudProviders as string[],
    authMechanisms: ['JWT', 'OAuth2', 'API Keys'] as string[],
    dataClassifications: MOCK_WBRT_ENGAGEMENT.architectureContext.dataClassifications as string[],
    complianceRequirements: MOCK_WBRT_ENGAGEMENT.architectureContext.complianceRequirements as string[],
  })

  // ── Analysis run state ──────────────────────────────────────────────────
  const [isRunning, setIsRunning] = useState(false)
  const [progress, setProgress]   = useState<{ phase: string; percent: number } | null>(null)

  // ── Data (initialized from mock data) ───────────────────────────────────
  const [attackGraph, setAttackGraph] = useState<AttackGraph>(MOCK_ATTACK_GRAPH)
  const [killChains, setKillChains]   = useState<KillChain[]>(MOCK_KILL_CHAINS)
  const [findings, setFindings]       = useState<WbrtFinding[]>(MOCK_WBRT_FINDINGS)
  const [report]                      = useState<WbrtReport>(MOCK_WBRT_REPORT)

  // ── UI state ────────────────────────────────────────────────────────────
  const [selectedNodeId, setSelectedNodeId]       = useState<string | null>(null)
  const [expandedChainId, setExpandedChainId]     = useState<string | null>('kc-001')
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter]       = useState<string>('ALL')
  const [sortOrder, setSortOrder]                 = useState<string>('impact-desc')

  // ── Simulate analysis run ───────────────────────────────────────────────
  const runAnalysis = useCallback(() => {
    if (inputMode === 'import-sast' && !selectedSastScanId) return
    setIsRunning(true)
    setProgress({ phase: 'Ingesting SAST findings…', percent: 0 })

    const phases = [
      { phase: 'Ingesting SAST findings…',       percent: 10 },
      { phase: 'Mapping architecture context…',  percent: 22 },
      { phase: 'Building attack graph nodes…',   percent: 38 },
      { phase: 'Chaining kill chains…',          percent: 55 },
      { phase: 'Scoring business impact…',       percent: 72 },
      { phase: 'Generating compliance gaps…',    percent: 86 },
      { phase: 'Compiling executive report…',    percent: 94 },
      { phase: 'Complete',                        percent: 100 },
    ]

    let i = 0
    const tick = setInterval(() => {
      if (i < phases.length) {
        setProgress(phases[i])
        i++
      } else {
        clearInterval(tick)
        setIsRunning(false)
        setProgress(null)
        setAttackGraph(MOCK_ATTACK_GRAPH)
        setKillChains(MOCK_KILL_CHAINS)
        setFindings(MOCK_WBRT_FINDINGS)
        setActiveTab('attack-graph')
      }
    }, 700)
  }, [inputMode, selectedSastScanId])

  // ── Filtered / sorted findings ──────────────────────────────────────────
  const filteredFindings = findings
    .filter(f => severityFilter === 'ALL' || f.severity === severityFilter)
    .sort((a, b) => {
      if (sortOrder === 'impact-desc') return b.businessImpact.score - a.businessImpact.score
      if (sortOrder === 'impact-asc')  return a.businessImpact.score - b.businessImpact.score
      return 0
    })

  const handleStatusChange = useCallback((id: string, status: string) => {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status: status as WbrtFinding['status'] } : f))
  }, [])

  // ── Checkbox array toggle ───────────────────────────────────────────────
  function toggleArr(arr: string[], val: string): string[] {
    return arr.includes(val) ? arr.filter(x => x !== val) : [...arr, val]
  }

  // ── Tab definitions ─────────────────────────────────────────────────────
  const tabs: { id: TabId; label: string; count?: number }[] = [
    { id: 'engagement',   label: 'ENGAGEMENT' },
    { id: 'attack-graph', label: 'ATTACK GRAPH', count: attackGraph.nodes.length },
    { id: 'kill-chains',  label: 'KILL CHAINS',  count: killChains.length },
    { id: 'findings',     label: 'FINDINGS',     count: findings.length },
    { id: 'report',       label: 'REPORT' },
  ]

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div style={{ padding: 32, maxWidth: 1400, fontFamily: 'var(--font-sans)' }}>

      {/* Page header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.16em',
          color: '#b06aff', textTransform: 'uppercase', marginBottom: 8,
        }}>
          [ WHITE BOX RED TEAMING ]
        </div>
        <h1 style={{
          fontFamily: 'var(--font-display)', fontSize: 26, fontWeight: 700,
          color: 'var(--color-text-primary)', margin: '0 0 6px',
        }}>
          White Box Red Teaming
        </h1>
        <p style={{ fontSize: 14, color: 'var(--color-text-secondary)', margin: 0 }}>
          Source-code-aware attack graph analysis · MITRE ATT&amp;CK kill chains · Business impact scoring · Compliance gap mapping
        </p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--color-border)', marginBottom: 0 }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              padding: '10px 20px', fontSize: 11, letterSpacing: '0.12em',
              textTransform: 'uppercase', cursor: 'pointer',
              background: 'none', border: 'none',
              borderBottom: activeTab === t.id ? '2px solid #b06aff' : '2px solid transparent',
              color: activeTab === t.id ? '#b06aff' : 'var(--color-text-secondary)',
              fontFamily: 'var(--font-mono)', marginBottom: -1,
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            {t.label}
            {t.count !== undefined && (
              <span style={{
                fontSize: 9, padding: '1px 5px',
                background: activeTab === t.id ? '#b06aff22' : 'var(--color-bg-surface)',
                border: `1px solid ${activeTab === t.id ? '#b06aff44' : 'var(--color-border)'}`,
                color: activeTab === t.id ? '#b06aff' : 'var(--color-text-dim)',
                borderRadius: 2,
              }}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ════════════════════════════════════════════════════════════════════
          TAB 1: ENGAGEMENT
          ════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'engagement' && (
        <div style={{ marginTop: 24 }}>

          {/* Input mode toggle */}
          <div style={{
            border: '1px solid var(--color-border)', background: 'var(--color-bg-elevated)',
            borderRadius: 2, padding: 20, marginBottom: 20,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.14em',
              color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: 12,
            }}>
              Input Source
            </div>
            <div style={{ display: 'flex', gap: 8, marginBottom: inputMode === 'import-sast' || inputMode === 'upload-code' ? 16 : 0 }}>
              {([
                { id: 'import-sast', label: 'Import SAST Scan' },
                { id: 'upload-code', label: 'Upload Code' },
              ] as const).map(m => (
                <button
                  key={m.id}
                  onClick={() => setInputMode(m.id)}
                  style={{
                    padding: '8px 20px', fontSize: 11,
                    fontFamily: 'var(--font-mono)', letterSpacing: '0.1em', cursor: 'pointer',
                    background: inputMode === m.id ? '#b06aff22' : 'var(--color-bg-surface)',
                    border: `1px solid ${inputMode === m.id ? '#b06aff' : 'var(--color-border)'}`,
                    color: inputMode === m.id ? '#b06aff' : 'var(--color-text-secondary)',
                    borderRadius: 2,
                  }}
                >
                  {m.label}
                </button>
              ))}
            </div>

            {/* Import SAST mode: dropdown list */}
            {inputMode === 'import-sast' && (
              <div>
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
                  color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase',
                }}>
                  Select SAST Scan to Import
                </div>
                <div style={{ border: '1px solid var(--color-border)', borderRadius: 2, overflow: 'hidden' }}>
                  {MOCK_SAST_SCANS_FOR_IMPORT.map((scan, idx) => (
                    <div
                      key={scan.id}
                      onClick={() => setSelectedSastScanId(scan.id)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 14,
                        padding: '12px 16px', cursor: 'pointer',
                        background: selectedSastScanId === scan.id ? '#b06aff10' : 'transparent',
                        borderBottom: idx < MOCK_SAST_SCANS_FOR_IMPORT.length - 1 ? '1px solid var(--color-border)' : 'none',
                        borderLeft: selectedSastScanId === scan.id ? '3px solid #b06aff' : '3px solid transparent',
                        transition: 'background 0.12s',
                      }}
                      onMouseEnter={e => { if (selectedSastScanId !== scan.id) (e.currentTarget as HTMLElement).style.background = 'var(--color-bg-surface)' }}
                      onMouseLeave={e => { if (selectedSastScanId !== scan.id) (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                    >
                      <div style={{
                        width: 16, height: 16, borderRadius: '50%', flexShrink: 0,
                        border: `2px solid ${selectedSastScanId === scan.id ? '#b06aff' : 'var(--color-border)'}`,
                        background: selectedSastScanId === scan.id ? '#b06aff' : 'transparent',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                      }}>
                        {selectedSastScanId === scan.id && (
                          <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'white' }} />
                        )}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: 2 }}>
                          {scan.name}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
                          {new Date(scan.date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
                          {' · '}
                          {scan.findingsCount} findings
                        </div>
                      </div>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 8px',
                        background: 'rgba(239,90,90,0.1)', color: 'var(--color-sev-critical)',
                        border: '1px solid rgba(239,90,90,0.3)', borderRadius: 2,
                      }}>
                        {scan.findingsCount} findings
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Upload code mode */}
            {inputMode === 'upload-code' && (
              <div>
                <div style={{
                  border: '2px dashed var(--color-border)',
                  borderRadius: 2, padding: '32px 24px', textAlign: 'center',
                  background: 'var(--color-bg-base)',
                }}>
                  <div style={{ fontSize: 28, color: 'var(--color-text-dim)', marginBottom: 10 }}>⬆</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-secondary)', marginBottom: 6 }}>
                    Drag &amp; drop code files or click to upload
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)' }}>
                    Supports .ts, .tsx, .js, .py, .go, .java, .rs and more
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Architecture context form */}
          <div style={{
            border: '1px solid var(--color-border)', background: 'var(--color-bg-elevated)',
            borderRadius: 2, padding: 20, marginBottom: 20,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.14em',
              color: '#b06aff', textTransform: 'uppercase', marginBottom: 18,
            }}>
              [ ARCHITECTURE CONTEXT ]
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>

              {/* Engagement Name — full width */}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)',
                  display: 'block', marginBottom: 6, letterSpacing: '0.08em',
                }}>
                  ENGAGEMENT NAME
                </label>
                <input
                  type="text"
                  value={engagementForm.name}
                  onChange={e => setEngagementForm(prev => ({ ...prev, name: e.target.value }))}
                  style={{
                    width: '100%', boxSizing: 'border-box',
                    padding: '8px 12px', fontSize: 13,
                    background: 'var(--color-bg-surface)',
                    border: '1px solid var(--color-border)',
                    color: 'var(--color-text-primary)',
                    fontFamily: 'var(--font-sans)', borderRadius: 2,
                  }}
                />
              </div>

              {/* Deployment model */}
              <div>
                <label style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)',
                  display: 'block', marginBottom: 8, letterSpacing: '0.08em',
                }}>
                  DEPLOYMENT MODEL
                </label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                  {(['cloud', 'on_prem', 'hybrid', 'multi_cloud'] as const).map(d => (
                    <label key={d} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                      <input
                        type="radio" name="deployment" value={d}
                        checked={engagementForm.deployment === d}
                        onChange={() => setEngagementForm(prev => ({ ...prev, deployment: d }))}
                        style={{ accentColor: '#b06aff' }}
                      />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-secondary)' }}>
                        {d === 'on_prem' ? 'On-Premises'
                          : d === 'multi_cloud' ? 'Multi-Cloud'
                          : d.charAt(0).toUpperCase() + d.slice(1)}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Tech stack */}
              <div>
                <label style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)',
                  display: 'block', marginBottom: 6, letterSpacing: '0.08em',
                }}>
                  TECH STACK <span style={{ fontWeight: 400 }}>(comma-separated)</span>
                </label>
                <input
                  type="text"
                  value={engagementForm.techStack}
                  onChange={e => setEngagementForm(prev => ({ ...prev, techStack: e.target.value }))}
                  placeholder="Next.js, PostgreSQL, Redis, AWS…"
                  style={{
                    width: '100%', boxSizing: 'border-box',
                    padding: '8px 12px', fontSize: 12,
                    background: 'var(--color-bg-surface)',
                    border: '1px solid var(--color-border)',
                    color: 'var(--color-text-primary)',
                    fontFamily: 'var(--font-mono)', borderRadius: 2,
                  }}
                />
              </div>

              {/* Cloud providers */}
              <div>
                <label style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)',
                  display: 'block', marginBottom: 8, letterSpacing: '0.08em',
                }}>
                  CLOUD PROVIDERS
                </label>
                <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
                  {['AWS', 'GCP', 'Azure'].map(p => (
                    <label key={p} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={engagementForm.cloudProviders.includes(p)}
                        onChange={() => setEngagementForm(prev => ({ ...prev, cloudProviders: toggleArr(prev.cloudProviders, p) }))}
                        style={{ accentColor: '#b06aff' }}
                      />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-secondary)' }}>{p}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Auth mechanisms */}
              <div>
                <label style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)',
                  display: 'block', marginBottom: 8, letterSpacing: '0.08em',
                }}>
                  AUTH MECHANISMS
                </label>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  {['JWT', 'OAuth2', 'API Keys', 'Session Cookies', 'SAML'].map(a => (
                    <label key={a} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={engagementForm.authMechanisms.includes(a)}
                        onChange={() => setEngagementForm(prev => ({ ...prev, authMechanisms: toggleArr(prev.authMechanisms, a) }))}
                        style={{ accentColor: '#b06aff' }}
                      />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-secondary)' }}>{a}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Data classifications */}
              <div>
                <label style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)',
                  display: 'block', marginBottom: 8, letterSpacing: '0.08em',
                }}>
                  DATA CLASSIFICATIONS
                </label>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  {['PII', 'PCI', 'PHI', 'CONFIDENTIAL', 'RESTRICTED'].map(d => (
                    <label key={d} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={engagementForm.dataClassifications.includes(d)}
                        onChange={() => setEngagementForm(prev => ({ ...prev, dataClassifications: toggleArr(prev.dataClassifications, d) }))}
                        style={{ accentColor: '#b06aff' }}
                      />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-secondary)' }}>{d}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Compliance requirements */}
              <div>
                <label style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)',
                  display: 'block', marginBottom: 8, letterSpacing: '0.08em',
                }}>
                  COMPLIANCE REQUIREMENTS
                </label>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  {['PCI_DSS', 'SOC2', 'HIPAA', 'ISO27001', 'GDPR'].map(c => (
                    <label key={c} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={engagementForm.complianceRequirements.includes(c)}
                        onChange={() => setEngagementForm(prev => ({ ...prev, complianceRequirements: toggleArr(prev.complianceRequirements, c) }))}
                        style={{ accentColor: '#b06aff' }}
                      />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-secondary)' }}>{c}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Run Analysis + progress */}
          <div style={{
            border: '1px solid var(--color-border)', background: 'var(--color-bg-elevated)',
            borderRadius: 2, padding: 20,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
              <button
                onClick={runAnalysis}
                disabled={isRunning || (inputMode === 'import-sast' && !selectedSastScanId)}
                style={{
                  padding: '12px 32px', fontSize: 12,
                  fontFamily: 'var(--font-mono)', letterSpacing: '0.12em', fontWeight: 700,
                  cursor: isRunning || (inputMode === 'import-sast' && !selectedSastScanId) ? 'not-allowed' : 'pointer',
                  background: isRunning ? 'var(--color-bg-surface)' : '#b06aff',
                  color: isRunning ? 'var(--color-text-dim)' : '#0a0d0f',
                  border: 'none', borderRadius: 2,
                  opacity: inputMode === 'import-sast' && !selectedSastScanId && !isRunning ? 0.5 : 1,
                }}
              >
                {isRunning ? 'ANALYZING…' : 'RUN ANALYSIS'}
              </button>

              {inputMode === 'import-sast' && !selectedSastScanId && !isRunning && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
                  Select a SAST scan above to continue
                </span>
              )}
              {selectedSastScanId && !isRunning && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#b06aff' }}>
                  Ready · {MOCK_SAST_SCANS_FOR_IMPORT.find(s => s.id === selectedSastScanId)?.name}
                </span>
              )}
            </div>

            {/* Progress section */}
            {progress && (
              <div style={{ marginTop: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#b06aff' }}>
                    {progress.phase}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-dim)' }}>
                    {progress.percent}%
                  </span>
                </div>
                <div style={{ height: 6, background: 'var(--color-bg-surface)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', borderRadius: 3,
                    width: `${progress.percent}%`,
                    background: 'linear-gradient(90deg, #b06aff, #00d4aa)',
                    transition: 'width 0.6s ease',
                  }} />
                </div>
                <div style={{ display: 'flex', gap: 4, marginTop: 10, flexWrap: 'wrap' }}>
                  {['Ingest', 'Map', 'Graph', 'Chain', 'Score', 'Compliance', 'Report'].map((ph, i) => (
                    <span key={ph} style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 7px',
                      background: progress.percent > i * 14 ? '#b06aff22' : 'var(--color-bg-surface)',
                      border: `1px solid ${progress.percent > i * 14 ? '#b06aff55' : 'var(--color-border)'}`,
                      color: progress.percent > i * 14 ? '#b06aff' : 'var(--color-text-dim)',
                      borderRadius: 2,
                    }}>
                      {ph}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════
          TAB 2: ATTACK GRAPH
          ════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'attack-graph' && (
        <div style={{ marginTop: 24 }}>

          {/* Stats bar */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
            {[
              { label: 'TOTAL NODES',  value: attackGraph.nodes.length,       color: 'var(--color-text-primary)' },
              { label: 'ATTACK EDGES', value: attackGraph.edges.length,       color: '#5ab0ff' },
              { label: 'ENTRY POINTS', value: attackGraph.entryPoints.length, color: '#00d4aa' },
              { label: 'CROWN JEWELS', value: attackGraph.crownJewels.length, color: '#b06aff' },
            ].map(stat => (
              <div key={stat.label} style={{
                background: 'var(--color-bg-elevated)',
                border: '1px solid var(--color-border)',
                borderRadius: 2, padding: '14px 18px', textAlign: 'center',
              }}>
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.12em',
                  color: 'var(--color-text-dim)', marginBottom: 6, textTransform: 'uppercase',
                }}>
                  {stat.label}
                </div>
                <div style={{ fontSize: 28, fontWeight: 700, color: stat.color }}>
                  {stat.value}
                </div>
              </div>
            ))}
          </div>

          {/* Graph panel */}
          <div style={{
            background: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-border)',
            borderRadius: 2, padding: 20,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.14em',
              color: '#b06aff', textTransform: 'uppercase', marginBottom: 14,
            }}>
              [ ATTACK GRAPH — CLICK A NODE FOR DETAILS ]
            </div>

            <AttackGraph3D
              graph={attackGraph}
              killChains={killChains}
              selectedNodeId={selectedNodeId}
              onSelectNode={setSelectedNodeId}
              height={580}
            />

            {/* Node shape legend */}
            <div style={{ display: 'flex', gap: 16, marginTop: 14, flexWrap: 'wrap' }}>
              {Object.entries(NODE_COLOR).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, opacity: 0.85 }} />
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9,
                    color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>
                    {type.replace('_', ' ')}
                  </span>
                </div>
              ))}
            </div>

            {/* Inline node detail panel */}
            {selectedNodeId && (() => {
              const node = attackGraph.nodes.find(n => n.id === selectedNodeId)
              if (!node) return null
              const inbound  = attackGraph.edges.filter(e => e.target === selectedNodeId)
              const outbound = attackGraph.edges.filter(e => e.source === selectedNodeId)
              const color    = NODE_COLOR[node.type] ?? '#888'
              const inChains = killChains.filter(kc =>
                kc.steps.some(s => s.techniqueId && attackGraph.edges.some(
                  e => (e.source === selectedNodeId || e.target === selectedNodeId) && e.techniqueId === s.techniqueId
                ))
              )
              return (
                <div style={{
                  marginTop: 16,
                  background: 'var(--color-bg-surface)',
                  border: `1px solid ${color}44`,
                  borderRadius: 2, padding: 20,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{
                        background: color + '22', border: `1px solid ${color}`,
                        borderRadius: 2, padding: '3px 10px',
                        fontFamily: 'var(--font-mono)', fontSize: 9, color,
                        textTransform: 'uppercase', letterSpacing: '0.1em',
                      }}>
                        {node.type.replace('_', ' ')}
                      </div>
                      <span style={{ fontFamily: 'var(--font-display)', fontSize: 16, fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        {node.label}
                      </span>
                      {node.severity && (
                        <div style={{
                          background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)',
                          borderRadius: 2, padding: '2px 8px',
                          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-secondary)', fontWeight: 700,
                        }}>
                          {node.severity}
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => setSelectedNodeId(null)}
                      style={{
                        background: 'none', border: '1px solid var(--color-border)',
                        borderRadius: 2, padding: '4px 10px', cursor: 'pointer',
                        fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)',
                      }}
                    >
                      CLEAR ✕
                    </button>
                  </div>

                  {node.description && (
                    <p style={{ fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 14 }}>
                      {node.description}
                    </p>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 14 }}>
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8, textTransform: 'uppercase' }}>
                        Inbound ({inbound.length})
                      </div>
                      {inbound.length === 0
                        ? <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>—</div>
                        : inbound.map(e => (
                          <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#5ab0ff', background: 'rgba(90,176,255,0.1)', padding: '2px 6px', borderRadius: 2 }}>
                              {e.techniqueId}
                            </span>
                            <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-text-secondary)' }}>
                              {e.description?.slice(0, 40) ?? ''}
                            </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)' }}>
                              {Math.round((e.probability ?? 0) * 100)}%
                            </span>
                          </div>
                        ))
                      }
                    </div>
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8, textTransform: 'uppercase' }}>
                        Outbound ({outbound.length})
                      </div>
                      {outbound.length === 0
                        ? <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>—</div>
                        : outbound.map(e => (
                          <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ef5a5a', background: 'rgba(239,90,90,0.1)', padding: '2px 6px', borderRadius: 2 }}>
                              {e.techniqueId}
                            </span>
                            <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-text-secondary)' }}>
                              {e.description?.slice(0, 40) ?? ''}
                            </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)' }}>
                              {Math.round((e.probability ?? 0) * 100)}%
                            </span>
                          </div>
                        ))
                      }
                    </div>
                  </div>

                  {inChains.length > 0 && (
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8, textTransform: 'uppercase' }}>
                        Kill Chain Membership
                      </div>
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {inChains.map(kc => (
                          <div key={kc.id} style={{
                            background: 'rgba(239,90,90,0.1)', border: '1px solid rgba(239,90,90,0.3)',
                            borderRadius: 2, padding: '3px 10px',
                            fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ef5a5a',
                          }}>
                            {kc.name}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )
            })()}
          </div>
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════
          TAB 3: KILL CHAINS
          ════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'kill-chains' && (
        <div style={{ marginTop: 24 }}>
          {killChains.length === 0 ? (
            <div style={{
              border: '1px solid var(--color-border)',
              background: 'var(--color-bg-elevated)',
              borderRadius: 2, padding: 48, textAlign: 'center',
            }}>
              <div style={{ fontSize: 36, color: 'var(--color-text-dim)', marginBottom: 12 }}>◈</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-text-dim)', letterSpacing: '0.08em' }}>
                No engagements run yet.
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)', marginTop: 6, opacity: 0.6 }}>
                Configure and run an analysis on the Engagement tab to generate kill chains.
              </div>
            </div>
          ) : (
            <>
              {/* Quick stat row */}
              <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
                {killChains.map(chain => (
                  <div key={chain.id} style={{
                    padding: '8px 14px',
                    background: 'var(--color-bg-elevated)',
                    border: `1px solid ${LIKELIHOOD_COLOR[chain.likelihood] ?? 'var(--color-border)'}44`,
                    borderRadius: 2,
                    display: 'flex', alignItems: 'center', gap: 8,
                  }}>
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: LIKELIHOOD_COLOR[chain.likelihood] ?? '#888',
                      display: 'inline-block', flexShrink: 0,
                    }} />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-secondary)' }}>
                      {chain.estimatedTimeToExploit} to exploit
                    </span>
                  </div>
                ))}
              </div>

              {killChains.map(chain => (
                <KillChainCard
                  key={chain.id}
                  chain={chain}
                  expanded={expandedChainId === chain.id}
                  onToggle={() => setExpandedChainId(prev => prev === chain.id ? null : chain.id)}
                />
              ))}
            </>
          )}
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════
          TAB 4: FINDINGS
          ════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'findings' && (
        <div style={{ marginTop: 24 }}>

          {/* Filter bar */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16, flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>SEVERITY:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  padding: '4px 12px', fontSize: 9, fontFamily: 'var(--font-mono)',
                  letterSpacing: '0.08em', cursor: 'pointer',
                  background: severityFilter === sev
                    ? (sev === 'ALL' ? '#b06aff22' : (SEV_COLOR[sev] ?? '#888') + '22')
                    : 'var(--color-bg-surface)',
                  border: `1px solid ${severityFilter === sev
                    ? (sev === 'ALL' ? '#b06aff' : (SEV_COLOR[sev] ?? '#888'))
                    : 'var(--color-border)'}`,
                  color: severityFilter === sev
                    ? (sev === 'ALL' ? '#b06aff' : (SEV_COLOR[sev] ?? '#888'))
                    : 'var(--color-text-dim)',
                  borderRadius: 2,
                }}
              >
                {sev}
              </button>
            ))}

            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>SORT:</span>
              <select
                value={sortOrder}
                onChange={e => setSortOrder(e.target.value)}
                style={{
                  background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)',
                  color: 'var(--color-text-primary)', padding: '4px 10px',
                  fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer',
                }}
              >
                <option value="impact-desc">Impact Score ↓</option>
                <option value="impact-asc">Impact Score ↑</option>
              </select>
            </div>

            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>
              {filteredFindings.length} / {findings.length}
            </span>
          </div>

          {/* Cards */}
          {filteredFindings.length === 0 ? (
            <div style={{
              border: '1px solid var(--color-border)', background: 'var(--color-bg-elevated)',
              borderRadius: 2, padding: 40, textAlign: 'center',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-text-dim)' }}>
                No findings match the current filter.
              </div>
            </div>
          ) : filteredFindings.map(finding => (
            <FindingCard
              key={finding.id}
              finding={finding}
              expanded={expandedFindingId === finding.id}
              onToggle={() => setExpandedFindingId(prev => prev === finding.id ? null : finding.id)}
              onStatusChange={handleStatusChange}
            />
          ))}
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════
          TAB 5: REPORT
          ════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'report' && (
        <div style={{ marginTop: 24 }}>

          {/* Risk gauge + stats */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 24,
            marginBottom: 20, border: '1px solid var(--color-border)',
            background: 'var(--color-bg-elevated)', borderRadius: 2, padding: 24,
          }}>
            <RiskGauge score={report.overallRiskScore} />

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
                  Executive Risk Assessment
                </h2>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                  padding: '3px 10px',
                  background: riskColor(report.overallRiskScore) + '22',
                  color: riskColor(report.overallRiskScore),
                  border: `1px solid ${riskColor(report.overallRiskScore)}55`,
                  borderRadius: 2,
                }}>
                  {report.riskLevel}
                </span>
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 14 }}>
                Generated: {new Date(report.generatedAt).toLocaleString()} · Engagement: {report.engagementId}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                {[
                  { label: 'ATTACK PATHS', value: report.attackPathCount,                                           color: '#5ab0ff' },
                  { label: 'KILL CHAINS',  value: report.killChainCount,                                            color: 'var(--color-sev-high)' },
                  { label: 'CRITICAL',     value: MOCK_WBRT_FINDINGS.filter(f => f.severity === 'CRITICAL').length, color: 'var(--color-sev-critical)' },
                  { label: 'HIGH',         value: MOCK_WBRT_FINDINGS.filter(f => f.severity === 'HIGH').length,     color: 'var(--color-sev-high)' },
                ].map(stat => (
                  <div key={stat.label} style={{
                    padding: '10px 14px', textAlign: 'center',
                    background: 'var(--color-bg-surface)',
                    border: '1px solid var(--color-border)', borderRadius: 2,
                  }}>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: 8, letterSpacing: '0.12em',
                      color: 'var(--color-text-dim)', marginBottom: 4, textTransform: 'uppercase',
                    }}>
                      {stat.label}
                    </div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: stat.color }}>
                      {stat.value}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Executive summary */}
          <div style={{
            border: '1px solid var(--color-border)', background: 'var(--color-bg-elevated)',
            borderRadius: 2, padding: 24, marginBottom: 20,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.14em',
              color: '#b06aff', textTransform: 'uppercase', marginBottom: 16,
            }}>
              [ EXECUTIVE SUMMARY ]
            </div>
            <div>
              {renderSummaryMarkdown(report.executiveSummary)}
            </div>
          </div>

          {/* Compliance gaps table */}
          <div style={{
            border: '1px solid var(--color-border)', background: 'var(--color-bg-elevated)',
            borderRadius: 2, padding: 24, marginBottom: 20,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.14em',
              color: '#b06aff', textTransform: 'uppercase', marginBottom: 16,
            }}>
              [ COMPLIANCE GAPS ({report.complianceGaps.length}) ]
            </div>

            {/* Table header */}
            <div style={{
              display: 'grid', gridTemplateColumns: '110px 100px 1fr 80px',
              background: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              borderBottom: '2px solid var(--color-border)',
            }}>
              {['FRAMEWORK', 'CONTROL ID', 'CONTROL NAME', 'STATUS'].map((h, i) => (
                <div key={h} style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.1em',
                  color: 'var(--color-text-dim)', padding: '8px 12px',
                  borderRight: i < 3 ? '1px solid var(--color-border)' : 'none',
                }}>
                  {h}
                </div>
              ))}
            </div>

            {/* Table rows */}
            <div style={{ border: '1px solid var(--color-border)', borderTop: 'none' }}>
              {report.complianceGaps.map((gap, i) => {
                const stColor = gap.status === 'FAIL'
                  ? 'var(--color-sev-critical)'
                  : gap.status === 'PARTIAL'
                  ? 'var(--color-sev-medium)'
                  : '#00d4aa'
                const stBg = gap.status === 'FAIL'
                  ? 'rgba(239,90,90,0.15)'
                  : gap.status === 'PARTIAL'
                  ? 'rgba(242,209,86,0.12)'
                  : 'rgba(0,212,170,0.12)'
                return (
                  <div key={i} style={{
                    display: 'grid', gridTemplateColumns: '110px 100px 1fr 80px',
                    borderBottom: i < report.complianceGaps.length - 1 ? '1px solid var(--color-border)' : 'none',
                  }}>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600,
                      color: '#5ab0ff', padding: '10px 12px', borderRight: '1px solid var(--color-border)',
                    }}>
                      {gap.framework}
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: 10,
                      color: 'var(--color-text-secondary)', padding: '10px 12px',
                      borderRight: '1px solid var(--color-border)',
                    }}>
                      {gap.controlId}
                    </div>
                    <div style={{ padding: '10px 12px', borderRight: '1px solid var(--color-border)' }}>
                      <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: 4 }}>
                        {gap.controlName}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--color-text-dim)', lineHeight: 1.5 }}>
                        {gap.remediationNote}
                      </div>
                    </div>
                    <div style={{ padding: '10px 12px', display: 'flex', alignItems: 'flex-start' }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
                        padding: '3px 8px', background: stBg, color: stColor,
                        border: `1px solid ${stColor}55`, borderRadius: 2,
                      }}>
                        {gap.status}
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Remediation roadmap */}
          <div style={{
            border: '1px solid var(--color-border)', background: 'var(--color-bg-elevated)',
            borderRadius: 2, padding: 24, marginBottom: 20,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.14em',
              color: '#b06aff', textTransform: 'uppercase', marginBottom: 16,
            }}>
              [ REMEDIATION ROADMAP ]
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12 }}>
              {report.remediationRoadmap.map(item => {
                const pColor = item.priority === 1 ? 'var(--color-sev-critical)'
                  : item.priority === 2 ? 'var(--color-sev-high)'
                  : item.priority === 3 ? 'var(--color-sev-medium)'
                  : 'var(--color-text-secondary)'
                return (
                  <div key={item.priority} style={{
                    border: `1px solid ${pColor}33`,
                    background: 'var(--color-bg-surface)',
                    borderRadius: 2, padding: 16,
                    borderLeft: `3px solid ${pColor}`,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                      <div style={{
                        width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        background: pColor + '20', border: `2px solid ${pColor}`,
                      }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: pColor }}>
                          {item.priority}
                        </span>
                      </div>
                      <h4 style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', margin: 0, flex: 1 }}>
                        {item.title}
                      </h4>
                    </div>
                    <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, margin: '0 0 12px' }}>
                      {item.description}
                    </p>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 8px',
                        background: (EFFORT_COLOR[item.effort] ?? '#888') + '15',
                        color: EFFORT_COLOR[item.effort] ?? '#888',
                        border: `1px solid ${EFFORT_COLOR[item.effort] ?? '#888'}44`,
                        borderRadius: 2,
                      }}>
                        EFFORT: {item.effort}
                      </span>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 8px',
                        background: (IMPACT_COLOR[item.impact] ?? '#888') + '15',
                        color: IMPACT_COLOR[item.impact] ?? '#888',
                        border: `1px solid ${IMPACT_COLOR[item.impact] ?? '#888'}44`,
                        borderRadius: 2,
                      }}>
                        IMPACT: {item.impact}
                      </span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', marginLeft: 'auto' }}>
                        ~{item.estimatedHours}h
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Export buttons */}
          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginBottom: 8 }}>
            <button
              onClick={() => {
                const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>WBRT Report — ${MOCK_WBRT_ENGAGEMENT.name}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Arial, sans-serif; color: #111; background: #fff; padding: 40px; font-size: 13px; }
    h1 { font-size: 24px; margin-bottom: 4px; }
    h2 { font-size: 16px; margin: 28px 0 10px; border-bottom: 2px solid #333; padding-bottom: 4px; }
    h3 { font-size: 13px; margin: 16px 0 6px; }
    .meta { color: #666; font-size: 11px; margin-bottom: 24px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: bold; text-transform: uppercase; }
    .critical { background: #fee2e2; color: #b91c1c; }
    .high { background: #ffedd5; color: #c2410c; }
    .medium { background: #fef9c3; color: #a16207; }
    .low { background: #dbeafe; color: #1d4ed8; }
    .score { font-size: 48px; font-weight: bold; color: #b91c1c; }
    .stats { display: flex; gap: 24px; margin: 16px 0; }
    .stat { text-align: center; }
    .stat-val { font-size: 28px; font-weight: bold; }
    .stat-lbl { font-size: 10px; color: #666; text-transform: uppercase; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0; }
    th { background: #f3f4f6; padding: 8px 10px; text-align: left; font-size: 11px; text-transform: uppercase; }
    td { padding: 8px 10px; border-bottom: 1px solid #e5e7eb; font-size: 12px; }
    .fail { color: #b91c1c; font-weight: bold; }
    .partial { color: #c2410c; font-weight: bold; }
    .pass { color: #15803d; font-weight: bold; }
    .roadmap-item { border: 1px solid #e5e7eb; border-radius: 6px; padding: 14px; margin-bottom: 10px; }
    .roadmap-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
    .num { width: 28px; height: 28px; background: #111; color: #fff; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 12px; flex-shrink: 0; }
    p { line-height: 1.6; margin: 6px 0; }
    ul { padding-left: 20px; margin: 6px 0; }
    li { margin: 3px 0; }
    @media print { body { padding: 20px; } }
  </style>
</head>
<body>
  <h1>White Box Red Team Report</h1>
  <div class="meta">
    Engagement: ${MOCK_WBRT_ENGAGEMENT.name} &nbsp;·&nbsp;
    Generated: ${new Date(report.generatedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })} &nbsp;·&nbsp;
    Status: COMPLETED
  </div>

  <h2>Risk Score</h2>
  <div class="score">${report.overallRiskScore}<span style="font-size:20px;color:#666">/100</span></div>
  <div class="stats">
    <div class="stat"><div class="stat-val">${report.attackPathCount}</div><div class="stat-lbl">Attack Paths</div></div>
    <div class="stat"><div class="stat-val">${report.killChainCount}</div><div class="stat-lbl">Kill Chains</div></div>
    <div class="stat"><div class="stat-val">${findings.filter(f => f.severity === 'CRITICAL').length}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat"><div class="stat-val">${findings.filter(f => f.severity === 'HIGH').length}</div><div class="stat-lbl">High</div></div>
  </div>

  <h2>Executive Summary</h2>
  ${report.executiveSummary
    .split('\n')
    .map(line => {
      if (line.startsWith('## ')) return `<h3>${line.slice(3)}</h3>`
      if (line.startsWith('- ')) return `<li>${line.slice(2).replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')}</li>`
      if (line.trim() === '' || line.trim() === '---') return '<br/>'
      return `<p>${line.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')}</p>`
    })
    .join('\n')}

  <h2>Compliance Gaps</h2>
  <table>
    <thead><tr><th>Framework</th><th>Control ID</th><th>Control Name</th><th>Status</th></tr></thead>
    <tbody>
      ${report.complianceGaps.map(g => `
        <tr>
          <td>${g.framework}</td>
          <td style="font-family:monospace">${g.controlId}</td>
          <td>${g.controlName}</td>
          <td class="${g.status.toLowerCase()}">${g.status}</td>
        </tr>`).join('')}
    </tbody>
  </table>

  <h2>Remediation Roadmap</h2>
  ${report.remediationRoadmap.map(item => `
    <div class="roadmap-item">
      <div class="roadmap-header">
        <div class="num">${item.priority}</div>
        <strong>${item.title}</strong>
        <span class="badge">${item.effort} effort</span>
        <span class="badge">${item.impact} impact</span>
        <span style="font-size:11px;color:#666;margin-left:auto">${item.estimatedHours}h</span>
      </div>
      <p style="color:#444;font-size:12px">${item.description}</p>
    </div>`).join('')}
</body>
</html>`
                const win = window.open('', '_blank')
                if (win) {
                  win.document.write(html)
                  win.document.close()
                  win.focus()
                  setTimeout(() => win.print(), 500)
                }
              }}
              style={{
                padding: '10px 24px', fontSize: 11, fontFamily: 'var(--font-mono)',
                letterSpacing: '0.1em', cursor: 'pointer',
                background: '#b06aff22', border: '1px solid #b06aff66',
                color: '#b06aff', borderRadius: 2,
              }}
            >
              EXPORT PDF
            </button>
            <button
              onClick={() => {
                const payload = {
                  engagement: MOCK_WBRT_ENGAGEMENT,
                  report,
                  attackGraph,
                  killChains,
                  findings,
                  exportedAt: new Date().toISOString(),
                  version: '1.0',
                }
                const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `wbrt-report-${MOCK_WBRT_ENGAGEMENT.name.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().slice(0,10)}.json`
                a.click()
                URL.revokeObjectURL(url)
              }}
              style={{
                padding: '10px 24px', fontSize: 11, fontFamily: 'var(--font-mono)',
                letterSpacing: '0.1em', cursor: 'pointer',
                background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)',
                color: 'var(--color-text-secondary)', borderRadius: 2,
              }}
            >
              EXPORT JSON
            </button>
          </div>
        </div>
      )}

    </div>
  )
}
