'use client'

import type { DastFinding } from '@/lib/types'

interface CVSSDistributionProps {
  findings: DastFinding[]
}

const RANGES = [
  { label: '9.0–10.0', min: 9.0, max: 10.1, color: '#ef4444', severity: 'CRITICAL' },
  { label: '7.0–8.9', min: 7.0, max: 9.0, color: '#f97316', severity: 'HIGH' },
  { label: '4.0–6.9', min: 4.0, max: 7.0, color: '#eab308', severity: 'MEDIUM' },
  { label: '0.1–3.9', min: 0.1, max: 4.0, color: '#3b82f6', severity: 'LOW' },
  { label: 'N/A', min: -1, max: 0.1, color: '#6b7280', severity: 'INFO' },
]

export default function CVSSDistribution({ findings }: CVSSDistributionProps) {
  const rangeCounts = RANGES.map(r => ({
    ...r,
    count: findings.filter(f => {
      const score = f.cvssScore ?? 0
      return score >= r.min && score < r.max
    }).length,
  }))

  const maxCount = Math.max(...rangeCounts.map(r => r.count), 1)

  return (
    <div style={{ marginBottom: 20 }}>
      <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 10 }}>
        CVSS SCORE DISTRIBUTION
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {rangeCounts.map(r => (
          <div key={r.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', width: 55, textAlign: 'right', flexShrink: 0 }}>
              {r.label}
            </div>
            <div style={{ flex: 1, height: 16, background: 'var(--color-bg-secondary)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                width: `${(r.count / maxCount) * 100}%`,
                height: '100%', background: r.color, borderRadius: 3,
                transition: 'width 0.5s ease',
                minWidth: r.count > 0 ? 4 : 0,
              }} />
            </div>
            <div className="mono" style={{ fontSize: 10, fontWeight: 700, color: r.color, width: 24, textAlign: 'right', flexShrink: 0 }}>
              {r.count}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
