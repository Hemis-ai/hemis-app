'use client'

import type { DastFinding } from '@/lib/types'

interface OWASPHeatmapProps {
  findings: DastFinding[]
  onCategoryClick: (category: string) => void
}

const OWASP_CATEGORIES = [
  { id: 'A01:2021', name: 'Broken Access Control', short: 'A01' },
  { id: 'A02:2021', name: 'Cryptographic Failures', short: 'A02' },
  { id: 'A03:2021', name: 'Injection', short: 'A03' },
  { id: 'A04:2021', name: 'Insecure Design', short: 'A04' },
  { id: 'A05:2021', name: 'Security Misconfiguration', short: 'A05' },
  { id: 'A06:2021', name: 'Vulnerable Components', short: 'A06' },
  { id: 'A07:2021', name: 'Auth Failures', short: 'A07' },
  { id: 'A08:2021', name: 'Data Integrity Failures', short: 'A08' },
  { id: 'A09:2021', name: 'Logging Failures', short: 'A09' },
  { id: 'A10:2021', name: 'SSRF', short: 'A10' },
]

const SEV_WEIGHT: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0.5 }

export default function OWASPHeatmap({ findings, onCategoryClick }: OWASPHeatmapProps) {
  // Group findings by OWASP category
  const counts: Record<string, { total: number; weight: number; highest: string }> = {}
  for (const cat of OWASP_CATEGORIES) {
    counts[cat.id] = { total: 0, weight: 0, highest: 'INFO' }
  }

  for (const f of findings) {
    const cat = f.owaspCategory
    if (counts[cat]) {
      counts[cat].total++
      counts[cat].weight += SEV_WEIGHT[f.severity] || 0
      const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
      if (sevOrder.indexOf(f.severity) < sevOrder.indexOf(counts[cat].highest)) {
        counts[cat].highest = f.severity
      }
    }
  }

  const maxWeight = Math.max(...Object.values(counts).map(c => c.weight), 1)

  function heatColor(weight: number, highest: string): string {
    if (weight === 0) return 'var(--color-bg-secondary)'
    const intensity = Math.min(weight / maxWeight, 1)
    const base = highest === 'CRITICAL' ? [239, 68, 68] : highest === 'HIGH' ? [249, 115, 22] : highest === 'MEDIUM' ? [234, 179, 8] : [59, 130, 246]
    return `rgba(${base[0]}, ${base[1]}, ${base[2]}, ${0.15 + intensity * 0.55})`
  }

  return (
    <div style={{ marginBottom: 20 }}>
      <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 10 }}>
        OWASP TOP 10 COVERAGE
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
        {OWASP_CATEGORIES.map(cat => {
          const data = counts[cat.id]
          return (
            <div
              key={cat.id}
              onClick={() => onCategoryClick(cat.id)}
              style={{
                padding: '10px 8px', borderRadius: 6, cursor: 'pointer',
                background: heatColor(data.weight, data.highest),
                border: '1px solid var(--color-border)',
                transition: 'transform 0.15s, box-shadow 0.15s',
                textAlign: 'center',
              }}
              onMouseEnter={e => { (e.target as HTMLElement).style.transform = 'scale(1.04)' }}
              onMouseLeave={e => { (e.target as HTMLElement).style.transform = 'scale(1)' }}
            >
              <div className="mono" style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 2 }}>
                {cat.short}
              </div>
              <div className="mono" style={{ fontSize: 8, color: 'var(--color-text-secondary)', lineHeight: 1.2, marginBottom: 4 }}>
                {cat.name}
              </div>
              <div className="mono" style={{
                fontSize: 14, fontWeight: 800,
                color: data.total > 0 ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
              }}>
                {data.total}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
