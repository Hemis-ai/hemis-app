'use client'

import { useMemo } from 'react'
import type { AttackTelemetryEvent } from '@/lib/dast/telemetry-store'

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

interface SeverityFiltersProps {
  events: AttackTelemetryEvent[]
  activeSeverities: Set<string>
  onToggleSeverity: (sev: string) => void
  activeVectors: Set<string>
  onToggleVector: (vec: string) => void
}

export default function SeverityFilters({ events, activeSeverities, onToggleSeverity, activeVectors, onToggleVector }: SeverityFiltersProps) {
  const counts = useMemo(() => {
    const c: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    for (const e of events) {
      if (e.severity && c[e.severity] !== undefined) c[e.severity]++
    }
    return c
  }, [events])

  const vectors = useMemo(() => {
    const m = new Map<string, number>()
    for (const e of events) {
      if (e.attackVector) m.set(e.attackVector, (m.get(e.attackVector) || 0) + 1)
    }
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, 12)
  }, [events])

  const allSevActive = activeSeverities.size === 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {/* Severity row */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        <button
          onClick={() => {
            // Toggle all off (show all)
            if (allSevActive) return
            for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) onToggleSeverity(s)
          }}
          style={{
            padding: '4px 10px', fontSize: 10, fontFamily: 'var(--font-mono)',
            fontWeight: 600, letterSpacing: '0.08em', cursor: 'pointer',
            background: allSevActive ? 'var(--color-dast)' : 'var(--color-bg-elevated)',
            color: allSevActive ? '#fff' : 'var(--color-text-secondary)',
            border: `1px solid ${allSevActive ? 'var(--color-dast)' : 'var(--color-border)'}`,
            transition: 'all 0.15s ease',
          }}
        >
          ALL ({events.filter(e => e.severity).length})
        </button>
        {(Object.keys(SEV_COLORS) as Severity[]).map(sev => {
          const active = allSevActive || activeSeverities.has(sev)
          const color = SEV_COLORS[sev]
          return (
            <button
              key={sev}
              onClick={() => onToggleSeverity(sev)}
              style={{
                padding: '4px 10px', fontSize: 10, fontFamily: 'var(--font-mono)',
                fontWeight: 600, letterSpacing: '0.08em', cursor: 'pointer',
                background: active ? `${color}20` : 'var(--color-bg-elevated)',
                color: active ? color : 'var(--color-text-dim)',
                border: `1px solid ${active ? color : 'var(--color-border)'}`,
                transition: 'all 0.15s ease',
                opacity: counts[sev] === 0 ? 0.4 : 1,
              }}
            >
              {sev} ({counts[sev]})
            </button>
          )
        })}
      </div>

      {/* Attack vector row */}
      {vectors.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {vectors.map(([vec, count]) => {
            const active = activeVectors.size === 0 || activeVectors.has(vec)
            return (
              <button
                key={vec}
                onClick={() => onToggleVector(vec)}
                style={{
                  padding: '2px 8px', fontSize: 9, fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                  background: active ? 'var(--color-bg-elevated)' : 'transparent',
                  color: active ? 'var(--color-text-secondary)' : 'var(--color-text-dim)',
                  border: `1px solid ${active ? 'var(--color-border-bright, var(--color-border))' : 'transparent'}`,
                  transition: 'all 0.12s ease',
                }}
              >
                {vec} ({count})
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
