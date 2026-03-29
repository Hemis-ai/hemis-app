'use client'

import { useMemo } from 'react'
import type { TimeSeriesPoint } from './useTelemetryPoll'

interface RpsLatencyChartProps {
  data: TimeSeriesPoint[]
}

const W = 600
const H = 140
const PAD_L = 40
const PAD_R = 40
const PAD_T = 12
const PAD_B = 24
const PLOT_W = W - PAD_L - PAD_R
const PLOT_H = H - PAD_T - PAD_B

function buildPath(points: { x: number; y: number }[], close = false): string {
  if (points.length === 0) return ''
  let d = `M${points[0].x},${points[0].y}`
  for (let i = 1; i < points.length; i++) {
    d += ` L${points[i].x},${points[i].y}`
  }
  if (close && points.length > 0) {
    d += ` L${points[points.length - 1].x},${PAD_T + PLOT_H} L${points[0].x},${PAD_T + PLOT_H} Z`
  }
  return d
}

export default function RpsLatencyChart({ data }: RpsLatencyChartProps) {
  const { rpsPath, rpsAreaPath, latencyPath, errorBars, maxRps, maxLatency, ticks } = useMemo(() => {
    if (data.length === 0) return { rpsPath: '', rpsAreaPath: '', latencyPath: '', errorBars: [] as { x: number; intensity: number }[], maxRps: 10, maxLatency: 200, ticks: [] as { x: number; label: string }[] }

    const now = data[data.length - 1].time
    const windowMs = 60_000

    const maxR = Math.max(10, ...data.map(d => d.rps)) * 1.2
    const maxL = Math.max(200, ...data.map(d => d.avgLatencyMs)) * 1.2

    const rpsPoints: { x: number; y: number }[] = []
    const latPoints: { x: number; y: number }[] = []
    const errBars: { x: number; intensity: number }[] = []

    for (const pt of data) {
      const elapsed = pt.time - (now - windowMs)
      const x = PAD_L + (elapsed / windowMs) * PLOT_W
      if (x < PAD_L) continue

      const rpsY = PAD_T + PLOT_H - (pt.rps / maxR) * PLOT_H
      const latY = PAD_T + PLOT_H - (pt.avgLatencyMs / maxL) * PLOT_H

      rpsPoints.push({ x, y: rpsY })
      latPoints.push({ x, y: latY })

      if (pt.errorRate > 0.2) {
        errBars.push({ x, intensity: Math.min(1, pt.errorRate) })
      }
    }

    // Time ticks every 10s
    const tickArr: { x: number; label: string }[] = []
    for (let s = 0; s <= 60; s += 10) {
      const x = PAD_L + (s / 60) * PLOT_W
      tickArr.push({ x, label: s === 0 ? '-60s' : s === 60 ? 'now' : `-${60 - s}s` })
    }

    return {
      rpsPath: buildPath(rpsPoints),
      rpsAreaPath: buildPath(rpsPoints, true),
      latencyPath: buildPath(latPoints),
      errorBars: errBars,
      maxRps: maxR,
      maxLatency: maxL,
      ticks: tickArr,
    }
  }, [data])

  const hasData = data.length > 0

  return (
    <div style={{ position: 'relative' }}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto', display: 'block' }}>
        <defs>
          <linearGradient id="rps-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-dast)" stopOpacity={0.3} />
            <stop offset="100%" stopColor="var(--color-dast)" stopOpacity={0.02} />
          </linearGradient>
        </defs>

        {/* Grid lines */}
        {[0.25, 0.5, 0.75, 1].map(frac => (
          <line
            key={frac}
            x1={PAD_L} y1={PAD_T + PLOT_H * (1 - frac)}
            x2={PAD_L + PLOT_W} y2={PAD_T + PLOT_H * (1 - frac)}
            stroke="var(--color-border)" strokeWidth={0.5} strokeDasharray="3 3" opacity={0.4}
          />
        ))}

        {/* X-axis ticks */}
        {ticks.map(t => (
          <g key={t.label}>
            <line x1={t.x} y1={PAD_T} x2={t.x} y2={PAD_T + PLOT_H} stroke="var(--color-border)" strokeWidth={0.5} opacity={0.3} />
            <text x={t.x} y={H - 4} fill="var(--color-text-dim)" fontSize={8} fontFamily="var(--font-mono)" textAnchor="middle">{t.label}</text>
          </g>
        ))}

        {/* Y-axis labels */}
        <text x={PAD_L - 4} y={PAD_T + 4} fill="var(--color-dast)" fontSize={8} fontFamily="var(--font-mono)" textAnchor="end">{Math.round(maxRps)}</text>
        <text x={PAD_L - 4} y={PAD_T + PLOT_H} fill="var(--color-dast)" fontSize={8} fontFamily="var(--font-mono)" textAnchor="end">0</text>
        <text x={PAD_L + PLOT_W + 4} y={PAD_T + 4} fill="#f97316" fontSize={8} fontFamily="var(--font-mono)" textAnchor="start">{Math.round(maxLatency)}ms</text>
        <text x={PAD_L + PLOT_W + 4} y={PAD_T + PLOT_H} fill="#f97316" fontSize={8} fontFamily="var(--font-mono)" textAnchor="start">0</text>

        {/* Error spike bars */}
        {errorBars.map((bar, i) => (
          <rect
            key={i}
            x={bar.x - 2} y={PAD_T} width={4} height={PLOT_H}
            fill="#ef4444"
            opacity={bar.intensity * 0.25}
            style={{ transition: 'opacity 0.3s ease' }}
          />
        ))}

        {/* RPS area fill */}
        {hasData && <path d={rpsAreaPath} fill="url(#rps-grad)" style={{ transition: 'd 0.5s ease' }} />}

        {/* RPS line */}
        {hasData && <path d={rpsPath} fill="none" stroke="var(--color-dast)" strokeWidth={1.5} style={{ transition: 'd 0.5s ease' }} />}

        {/* Latency line (dashed) */}
        {hasData && <path d={latencyPath} fill="none" stroke="#f97316" strokeWidth={1} strokeDasharray="4 2" style={{ transition: 'd 0.5s ease' }} />}

        {/* No data placeholder */}
        {!hasData && (
          <text x={W / 2} y={H / 2} fill="var(--color-text-dim)" fontSize={11} fontFamily="var(--font-mono)" textAnchor="middle">
            Waiting for data...
          </text>
        )}
      </svg>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <div style={{ width: 12, height: 2, background: 'var(--color-dast)' }} />
          <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>RPS</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <div style={{ width: 12, height: 2, background: '#f97316', borderTop: '1px dashed #f97316' }} />
          <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>Latency</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <div style={{ width: 8, height: 8, background: 'rgba(239,68,68,0.25)' }} />
          <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>Error Spikes</span>
        </div>
      </div>
    </div>
  )
}
