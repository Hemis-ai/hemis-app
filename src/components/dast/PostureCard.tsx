'use client'

import type { DastScan, DastFinding } from '@/lib/types'

interface PostureCardProps {
  scans: DastScan[]
  findings: DastFinding[]
}

const GRADE_THRESHOLDS = [
  { max: 20, grade: 'A', color: '#22c55e', label: 'Excellent' },
  { max: 40, grade: 'B', color: '#84cc16', label: 'Good' },
  { max: 60, grade: 'C', color: '#eab308', label: 'Fair' },
  { max: 80, grade: 'D', color: '#f97316', label: 'Poor' },
  { max: 101, grade: 'F', color: '#ef4444', label: 'Critical' },
]

function getGrade(risk: number) {
  return GRADE_THRESHOLDS.find(t => risk < t.max) || GRADE_THRESHOLDS[4]
}

function riskColor(risk: number): string {
  if (risk < 25) return '#22c55e'
  if (risk < 50) return '#eab308'
  if (risk < 75) return '#f97316'
  return '#ef4444'
}

export default function PostureCard({ scans, findings }: PostureCardProps) {
  const latestScan = scans[0]
  if (!latestScan) return null

  const risk = latestScan.riskScore || 0
  const grade = getGrade(risk)

  // Severity counts from latest scan
  const sevCounts = {
    CRITICAL: latestScan.criticalCount || 0,
    HIGH: latestScan.highCount || 0,
    MEDIUM: latestScan.mediumCount || 0,
    LOW: latestScan.lowCount || 0,
    INFO: latestScan.infoCount || 0,
  }
  const total = Object.values(sevCounts).reduce((a, b) => a + b, 0) || 1

  // Sparkline from last 10 scans
  const sparkScans = scans.slice(0, 10).reverse()
  const sparkMax = Math.max(...sparkScans.map(s => s.riskScore || 0), 1)

  // Breach cost estimate
  const breachCost = findings.reduce((sum, f) => sum + (f.cvssScore || 0) * 52000, 0)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 16, marginBottom: 20 }}>

      {/* Risk Score Gauge */}
      <div className="bracket-card bracket-dast" style={{ padding: 20, textAlign: 'center' }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 12 }}>
          RISK SCORE
        </div>
        <svg viewBox="0 0 120 80" width="120" height="80" style={{ margin: '0 auto', display: 'block' }}>
          {/* Background arc */}
          <path
            d="M 10 70 A 50 50 0 0 1 110 70"
            fill="none" stroke="var(--color-border)" strokeWidth="8" strokeLinecap="round"
          />
          {/* Filled arc */}
          <path
            d="M 10 70 A 50 50 0 0 1 110 70"
            fill="none" stroke={riskColor(risk)} strokeWidth="8" strokeLinecap="round"
            strokeDasharray={`${(risk / 100) * 157} 157`}
          />
          <text x="60" y="55" textAnchor="middle" fontSize="24" fontWeight="800" fill={riskColor(risk)} fontFamily="var(--font-mono)">
            {risk}
          </text>
          <text x="60" y="72" textAnchor="middle" fontSize="9" fill="var(--color-text-secondary)" fontFamily="var(--font-mono)">
            / 100
          </text>
        </svg>
      </div>

      {/* Grade Badge */}
      <div className="bracket-card bracket-dast" style={{ padding: 20, textAlign: 'center' }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 12 }}>
          SECURITY GRADE
        </div>
        <div style={{
          width: 64, height: 64, borderRadius: '50%', margin: '0 auto',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: `3px solid ${grade.color}`, background: `${grade.color}15`,
        }}>
          <span style={{ fontSize: 32, fontWeight: 900, color: grade.color, fontFamily: 'var(--font-mono)' }}>
            {grade.grade}
          </span>
        </div>
        <div className="mono" style={{ fontSize: 10, color: grade.color, marginTop: 8, letterSpacing: '0.1em' }}>
          {grade.label.toUpperCase()}
        </div>
      </div>

      {/* Severity Donut */}
      <div className="bracket-card bracket-dast" style={{ padding: 20, textAlign: 'center' }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 12 }}>
          SEVERITY BREAKDOWN
        </div>
        <svg viewBox="0 0 100 100" width="80" height="80" style={{ margin: '0 auto', display: 'block' }}>
          {(() => {
            const colors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280' }
            const r = 38, cx = 50, cy = 50, circumference = 2 * Math.PI * r
            let offset = 0
            return (Object.entries(sevCounts) as [string, number][]).map(([sev, count]) => {
              const pct = count / total
              const dash = pct * circumference
              const el = (
                <circle
                  key={sev} cx={cx} cy={cy} r={r}
                  fill="none" stroke={colors[sev as keyof typeof colors]}
                  strokeWidth="12" strokeDasharray={`${dash} ${circumference - dash}`}
                  strokeDashoffset={-offset}
                  transform="rotate(-90 50 50)"
                />
              )
              offset += dash
              return el
            })
          })()}
          <text x="50" y="48" textAnchor="middle" fontSize="18" fontWeight="800" fill="var(--color-text-primary)" fontFamily="var(--font-mono)">
            {total}
          </text>
          <text x="50" y="60" textAnchor="middle" fontSize="8" fill="var(--color-text-secondary)" fontFamily="var(--font-mono)">
            FINDINGS
          </text>
        </svg>
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
          {Object.entries(sevCounts).filter(([, c]) => c > 0).map(([sev, count]) => (
            <span key={sev} className="mono" style={{
              fontSize: 9, padding: '1px 5px', borderRadius: 3,
              color: { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280' }[sev],
              border: `1px solid ${({ CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280' } as Record<string, string>)[sev]}40`,
            }}>
              {count} {sev[0]}
            </span>
          ))}
        </div>
      </div>

      {/* Trend Sparkline + Breach Cost */}
      <div className="bracket-card bracket-dast" style={{ padding: 20, textAlign: 'center' }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 12 }}>
          RISK TREND
        </div>
        {sparkScans.length >= 2 ? (
          <svg viewBox="0 0 120 50" width="120" height="50" style={{ margin: '0 auto', display: 'block' }}>
            <polyline
              fill="none" stroke="var(--color-dast)" strokeWidth="2" strokeLinejoin="round"
              points={sparkScans.map((s, i) => {
                const x = (i / (sparkScans.length - 1)) * 110 + 5
                const y = 45 - ((s.riskScore || 0) / sparkMax) * 40
                return `${x},${y}`
              }).join(' ')}
            />
            {sparkScans.map((s, i) => (
              <circle
                key={i}
                cx={(i / (sparkScans.length - 1)) * 110 + 5}
                cy={45 - ((s.riskScore || 0) / sparkMax) * 40}
                r="3" fill="var(--color-dast)"
              />
            ))}
          </svg>
        ) : (
          <div style={{ height: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)' }}>
              Need 2+ scans
            </span>
          </div>
        )}
        <div style={{ marginTop: 12, borderTop: '1px solid var(--color-border)', paddingTop: 8 }}>
          <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', letterSpacing: '0.1em' }}>
            EST. BREACH EXPOSURE
          </div>
          <div className="mono" style={{
            fontSize: 16, fontWeight: 700, marginTop: 4,
            color: breachCost > 500000 ? '#ef4444' : breachCost > 100000 ? '#f97316' : '#22c55e',
          }}>
            ${breachCost >= 1000000 ? `${(breachCost / 1000000).toFixed(1)}M` : breachCost >= 1000 ? `${(breachCost / 1000).toFixed(0)}K` : breachCost.toFixed(0)}
          </div>
        </div>
      </div>
    </div>
  )
}
