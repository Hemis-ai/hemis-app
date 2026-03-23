'use client'

import type { DastFinding } from '@/lib/types'

interface AttackSurfaceMapProps {
  findings: DastFinding[]
  onEndpointClick: (url: string) => void
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280',
}
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export default function AttackSurfaceMap({ findings, onEndpointClick }: AttackSurfaceMapProps) {
  // Group findings by endpoint
  const endpointMap = new Map<string, { count: number; highest: string; path: string }>()
  for (const f of findings) {
    let path: string
    try { path = new URL(f.affectedUrl).pathname } catch { path = f.affectedUrl }
    const existing = endpointMap.get(f.affectedUrl)
    if (existing) {
      existing.count++
      if (SEV_ORDER.indexOf(f.severity) < SEV_ORDER.indexOf(existing.highest)) {
        existing.highest = f.severity
      }
    } else {
      endpointMap.set(f.affectedUrl, { count: 1, highest: f.severity, path })
    }
  }

  const endpoints = Array.from(endpointMap.entries())
    .sort((a, b) => SEV_ORDER.indexOf(a[1].highest) - SEV_ORDER.indexOf(b[1].highest))

  if (endpoints.length === 0) return null

  return (
    <div style={{ marginBottom: 20 }}>
      <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 10 }}>
        ATTACK SURFACE MAP &mdash; {endpoints.length} ENDPOINTS
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {endpoints.map(([url, data]) => (
          <div
            key={url}
            onClick={() => onEndpointClick(url)}
            title={`${data.path}\n${data.count} finding${data.count > 1 ? 's' : ''} (${data.highest})`}
            style={{
              padding: '4px 8px', borderRadius: 4, cursor: 'pointer',
              background: `${SEV_COLORS[data.highest]}20`,
              border: `1px solid ${SEV_COLORS[data.highest]}60`,
              fontSize: 9, fontFamily: 'var(--font-mono)',
              color: SEV_COLORS[data.highest],
              transition: 'transform 0.1s',
              maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}
            onMouseEnter={e => { (e.target as HTMLElement).style.transform = 'scale(1.08)' }}
            onMouseLeave={e => { (e.target as HTMLElement).style.transform = 'scale(1)' }}
          >
            <span style={{ fontWeight: 700 }}>{data.count}</span>{' '}
            {data.path.length > 25 ? '...' + data.path.slice(-22) : data.path}
          </div>
        ))}
      </div>
    </div>
  )
}
