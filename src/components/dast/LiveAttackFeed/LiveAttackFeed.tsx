'use client'

import { useState, useMemo, useCallback } from 'react'
import { useTelemetryPoll } from './useTelemetryPoll'
import RpsLatencyChart from './RpsLatencyChart'
import RequestStream from './RequestStream'
import SeverityFilters from './SeverityFilters'
import AttackTopology from './AttackTopology'
import type { DastScanProgress } from '@/lib/types'

interface LiveAttackFeedProps {
  scanId: string
  isScanning: boolean
  scanProgress: DastScanProgress | null
}

export default function LiveAttackFeed({ scanId, isScanning }: LiveAttackFeedProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [showTopology, setShowTopology] = useState(false)
  const [activeSeverities, setActiveSeverities] = useState<Set<string>>(new Set())
  const [activeVectors, setActiveVectors] = useState<Set<string>>(new Set())

  const { events, stats, rpsHistory, isLoading } = useTelemetryPoll(scanId, isScanning)

  const handleToggleSeverity = useCallback((sev: string) => {
    setActiveSeverities(prev => {
      const next = new Set(prev)
      if (next.has(sev)) next.delete(sev)
      else next.add(sev)
      if (next.size === 5) return new Set()
      return next
    })
  }, [])

  const handleToggleVector = useCallback((vec: string) => {
    setActiveVectors(prev => {
      const next = new Set(prev)
      if (next.has(vec)) next.delete(vec)
      else next.add(vec)
      return next
    })
  }, [])

  const filteredEvents = useMemo(() => {
    return events.filter(evt => {
      if (activeSeverities.size > 0 && evt.severity && !activeSeverities.has(evt.severity)) return false
      if (activeVectors.size > 0 && !activeVectors.has(evt.attackVector)) return false
      return true
    })
  }, [events, activeSeverities, activeVectors])

  return (
    <div
      className="bracket-card bracket-dast"
      style={{ padding: 0, marginBottom: 20, overflow: 'hidden', position: 'relative' }}
    >
      {/* Scan line effect */}
      {isScanning && <div className="scan-line purple" />}

      {/* Header */}
      <div
        onClick={() => setCollapsed(!collapsed)}
        style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '12px 16px', cursor: 'pointer',
          borderBottom: collapsed ? 'none' : '1px solid var(--color-border)',
          transition: 'border 0.15s ease',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%', background: '#22c55e',
            display: 'inline-block', animation: 'pulse 1.5s ease-in-out infinite',
            boxShadow: '0 0 6px rgba(34,197,94,0.5)',
          }} />
          <span className="mono" style={{
            fontSize: 10, fontWeight: 700, letterSpacing: '0.12em',
            color: 'var(--color-dast)',
          }}>
            LIVE ATTACK FEED
          </span>
          <span style={{
            fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)',
            padding: '1px 6px', background: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-border)',
          }}>
            {stats.totalRequests} requests
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-dast)' }}>
              {stats.rps} req/s
            </span>
            <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: '#f97316' }}>
              {stats.avgLatencyMs}ms avg
            </span>
            {stats.status4xx + stats.status5xx > 0 && (
              <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: '#ef4444' }}>
                {stats.status4xx + stats.status5xx} errors
              </span>
            )}
          </div>

          <span style={{
            fontSize: 14, color: 'var(--color-text-dim)',
            transform: collapsed ? 'rotate(0deg)' : 'rotate(180deg)',
            transition: 'transform 0.2s ease', display: 'inline-block',
          }}>
            ▾
          </span>
        </div>
      </div>

      {/* Body — CSS transition for collapse/expand */}
      <div style={{
        maxHeight: collapsed ? 0 : 1200,
        opacity: collapsed ? 0 : 1,
        overflow: 'hidden',
        transition: 'max-height 0.35s ease, opacity 0.25s ease',
      }}>
        <div style={{ padding: 16 }}>
          {isLoading ? (
            <div style={{
              padding: 40, textAlign: 'center', color: 'var(--color-text-dim)',
              fontFamily: 'var(--font-mono)', fontSize: 11,
            }}>
              Initializing telemetry feed...
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* RPS/Latency Chart */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <span className="mono" style={{
                    fontSize: 9, fontWeight: 600, letterSpacing: '0.12em',
                    color: 'var(--color-text-dim)',
                  }}>
                    TRAFFIC TIMELINE
                  </span>
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowTopology(!showTopology) }}
                    style={{
                      fontSize: 9, fontFamily: 'var(--font-mono)', cursor: 'pointer',
                      padding: '2px 8px',
                      background: showTopology ? 'var(--color-dast)' : 'var(--color-bg-elevated)',
                      color: showTopology ? '#fff' : 'var(--color-text-dim)',
                      border: `1px solid ${showTopology ? 'var(--color-dast)' : 'var(--color-border)'}`,
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {showTopology ? 'HIDE TOPOLOGY' : 'SHOW TOPOLOGY'}
                  </button>
                </div>

                <div style={{
                  display: 'grid',
                  gridTemplateColumns: showTopology ? '1fr 1fr' : '1fr',
                  gap: 16,
                }}>
                  <RpsLatencyChart data={rpsHistory} />
                  {showTopology && (
                    <AttackTopology events={events} activeEndpoints={stats.activeEndpoints} />
                  )}
                </div>
              </div>

              {/* Filters */}
              <SeverityFilters
                events={events}
                activeSeverities={activeSeverities}
                onToggleSeverity={handleToggleSeverity}
                activeVectors={activeVectors}
                onToggleVector={handleToggleVector}
              />

              {/* Request Stream */}
              <div>
                <div className="mono" style={{
                  fontSize: 9, fontWeight: 600, letterSpacing: '0.12em',
                  color: 'var(--color-text-dim)', marginBottom: 8,
                  display: 'flex', alignItems: 'center', gap: 6,
                }}>
                  <span style={{
                    width: 5, height: 5, borderRadius: '50%',
                    background: 'var(--color-dast)', display: 'inline-block',
                    animation: 'pulse 1.5s ease-in-out infinite',
                  }} />
                  ATTACK STREAM
                  <span style={{ color: 'var(--color-text-dim)', fontWeight: 400 }}>
                    ({filteredEvents.length}{filteredEvents.length !== events.length ? ` of ${events.length}` : ''})
                  </span>
                </div>
                <RequestStream events={filteredEvents} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
