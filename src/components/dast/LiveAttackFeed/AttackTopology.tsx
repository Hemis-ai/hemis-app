'use client'

import { useMemo, useRef, useEffect } from 'react'
import type { AttackTelemetryEvent } from '@/lib/dast/telemetry-store'

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }

interface AttackTopologyProps {
  events: AttackTelemetryEvent[]
  activeEndpoints: string[]
}

interface EndpointNode {
  endpoint: string
  count: number
  maxSeverity: string | null
  isActive: boolean
  x: number
  y: number
}

const W = 500
const H = 280
const CX = W / 2
const CY = H / 2

export default function AttackTopology({ events, activeEndpoints }: AttackTopologyProps) {
  const activeSet = useMemo(() => new Set(activeEndpoints), [activeEndpoints])

  const nodes = useMemo(() => {
    const endpointMap = new Map<string, { count: number; maxSev: string | null }>()

    for (const evt of events) {
      const existing = endpointMap.get(evt.endpoint)
      if (existing) {
        existing.count++
        if (evt.severity && (!existing.maxSev || SEV_RANK[evt.severity] > SEV_RANK[existing.maxSev])) {
          existing.maxSev = evt.severity
        }
      } else {
        endpointMap.set(evt.endpoint, { count: 1, maxSev: evt.severity })
      }
    }

    const entries = Array.from(endpointMap.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 24) // Max 24 nodes for readability

    const radius = Math.min(W, H) * 0.35
    return entries.map(([endpoint, data], i): EndpointNode => {
      const angle = (i / entries.length) * Math.PI * 2 - Math.PI / 2
      const r = radius + (i % 2 === 0 ? 0 : 20) // Stagger inner/outer ring
      return {
        endpoint,
        count: data.count,
        maxSeverity: data.maxSev,
        isActive: activeSet.has(endpoint),
        x: CX + Math.cos(angle) * r,
        y: CY + Math.sin(angle) * r,
      }
    })
  }, [events, activeSet])

  // Animated dash offset for active connections
  const dashRef = useRef(0)
  const rafRef = useRef<number | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    const animate = () => {
      dashRef.current = (dashRef.current + 0.5) % 20
      const svg = svgRef.current
      if (svg) {
        const activeLines = svg.querySelectorAll<SVGLineElement>('.active-edge')
        activeLines.forEach(line => {
          line.style.strokeDashoffset = String(dashRef.current)
        })
      }
      rafRef.current = requestAnimationFrame(animate)
    }
    rafRef.current = requestAnimationFrame(animate)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [])

  return (
    <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto', display: 'block' }}>
      {/* Edges from center to each endpoint */}
      {nodes.map(node => {
        const color = node.maxSeverity ? SEV_COLORS[node.maxSeverity] || 'var(--color-border)' : 'var(--color-border)'
        return (
          <line
            key={`edge-${node.endpoint}`}
            className={node.isActive ? 'active-edge' : ''}
            x1={CX} y1={CY}
            x2={node.x} y2={node.y}
            stroke={node.isActive ? color : 'var(--color-border)'}
            strokeWidth={node.isActive ? 1.5 : 0.5}
            strokeDasharray={node.isActive ? '6 4' : 'none'}
            opacity={node.isActive ? 0.8 : 0.3}
          />
        )
      })}

      {/* Scanner (center node) */}
      <circle cx={CX} cy={CY} r={14} fill="var(--color-dast)" opacity={0.2} />
      <circle cx={CX} cy={CY} r={10} fill="var(--color-dast)" opacity={0.4} />
      <circle cx={CX} cy={CY} r={6} fill="var(--color-dast)">
        <animate attributeName="r" values="6;8;6" dur="2s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="1;0.6;1" dur="2s" repeatCount="indefinite" />
      </circle>
      <text x={CX} y={CY + 22} fill="var(--color-dast)" fontSize={8} fontFamily="var(--font-mono)" fontWeight={700} textAnchor="middle" letterSpacing="0.1em">SCANNER</text>

      {/* Endpoint nodes */}
      {nodes.map(node => {
        const color = node.maxSeverity ? SEV_COLORS[node.maxSeverity] || 'var(--color-text-dim)' : 'var(--color-text-dim)'
        const r = Math.max(3, Math.min(8, 3 + (node.count / 10)))
        return (
          <g key={`node-${node.endpoint}`}>
            {node.isActive && (
              <circle cx={node.x} cy={node.y} r={r + 4} fill={color} opacity={0.15}>
                <animate attributeName="r" values={`${r + 4};${r + 7};${r + 4}`} dur="1.5s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.15;0.05;0.15" dur="1.5s" repeatCount="indefinite" />
              </circle>
            )}
            <circle cx={node.x} cy={node.y} r={r} fill={color} opacity={node.isActive ? 0.9 : 0.5} />
            <text
              x={node.x} y={node.y + r + 10}
              fill="var(--color-text-dim)" fontSize={7} fontFamily="var(--font-mono)"
              textAnchor="middle"
              opacity={node.isActive ? 1 : 0.5}
            >
              {node.endpoint.length > 20 ? '...' + node.endpoint.slice(-17) : node.endpoint}
            </text>
          </g>
        )
      })}

      {/* No data state */}
      {nodes.length === 0 && (
        <text x={CX} y={CY + 40} fill="var(--color-text-dim)" fontSize={10} fontFamily="var(--font-mono)" textAnchor="middle">
          Discovering endpoints...
        </text>
      )}
    </svg>
  )
}
