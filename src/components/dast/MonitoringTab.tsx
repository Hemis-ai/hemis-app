'use client'

import { useState } from 'react'
import type { DastScan } from '@/lib/types'

interface MonitoringTabProps {
  scans: DastScan[]
}

interface ScheduleConfig {
  frequency: 'daily' | 'weekly' | 'monthly'
  targetUrl: string
  profile: string
  enabled: boolean
}

interface AlertRule {
  name: string
  condition: string
  enabled: boolean
}

const DEFAULT_ALERTS: AlertRule[] = [
  { name: 'New Critical Finding', condition: 'criticalCount > 0', enabled: true },
  { name: 'Risk Score Increase > 10', condition: 'riskScoreDelta > 10', enabled: true },
  { name: 'New HIGH Finding', condition: 'highCount > previousHighCount', enabled: false },
  { name: 'Scan Failure', condition: 'status === FAILED', enabled: true },
  { name: 'Certificate Expiring < 30 days', condition: 'certExpiry < 30d', enabled: false },
]

export default function MonitoringTab({ scans }: MonitoringTabProps) {
  const [schedules, setSchedules] = useState<ScheduleConfig[]>([])
  const [alerts, setAlerts] = useState(DEFAULT_ALERTS)
  const [showAddSchedule, setShowAddSchedule] = useState(false)
  const [newUrl, setNewUrl] = useState('')
  const [newFreq, setNewFreq] = useState<'daily' | 'weekly' | 'monthly'>('weekly')
  const [newProfile, setNewProfile] = useState('quick')

  // Risk trend from scans
  const completedScans = scans.filter(s => s.status === 'COMPLETED').slice(0, 12)

  function addSchedule() {
    if (!newUrl) return
    setSchedules(prev => [...prev, { frequency: newFreq, targetUrl: newUrl, profile: newProfile, enabled: true }])
    setNewUrl('')
    setShowAddSchedule(false)
  }

  function toggleAlert(idx: number) {
    setAlerts(prev => prev.map((a, i) => i === idx ? { ...a, enabled: !a.enabled } : a))
  }

  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>

        {/* Scheduled Scans */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-dast)', fontWeight: 700 }}>
              SCHEDULED SCANS
            </div>
            <button
              onClick={() => setShowAddSchedule(!showAddSchedule)}
              className="mono"
              style={{
                fontSize: 9, padding: '3px 10px', borderRadius: 3,
                background: 'var(--color-dast)', color: '#fff',
                border: 'none', cursor: 'pointer', letterSpacing: '0.08em',
              }}
            >
              + ADD
            </button>
          </div>

          {showAddSchedule && (
            <div className="bracket-card bracket-dast" style={{ padding: 14, marginBottom: 10 }}>
              <div style={{ marginBottom: 8 }}>
                <label className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 3 }}>
                  TARGET URL
                </label>
                <input
                  value={newUrl} onChange={e => setNewUrl(e.target.value)}
                  placeholder="https://example.com" className="mono"
                  style={{
                    width: '100%', padding: '6px 8px', fontSize: 11,
                    background: 'var(--color-bg-primary)', border: '1px solid var(--color-border)',
                    borderRadius: 4, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)',
                  }}
                />
              </div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                {(['daily', 'weekly', 'monthly'] as const).map(f => (
                  <button
                    key={f} onClick={() => setNewFreq(f)} className="mono"
                    style={{
                      fontSize: 9, padding: '4px 10px', borderRadius: 3, cursor: 'pointer',
                      background: newFreq === f ? 'var(--color-dast)' : 'transparent',
                      color: newFreq === f ? '#fff' : 'var(--color-text-secondary)',
                      border: `1px solid ${newFreq === f ? 'var(--color-dast)' : 'var(--color-border)'}`,
                    }}
                  >
                    {f.toUpperCase()}
                  </button>
                ))}
              </div>
              <button onClick={addSchedule} className="mono" style={{
                fontSize: 9, padding: '5px 14px', borderRadius: 3,
                background: 'var(--color-dast)', color: '#fff',
                border: 'none', cursor: 'pointer',
              }}>
                CREATE SCHEDULE
              </button>
            </div>
          )}

          {schedules.length === 0 && !showAddSchedule && (
            <div className="bracket-card" style={{ padding: 24, textAlign: 'center' }}>
              <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>
                No scheduled scans configured
              </div>
              <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', marginTop: 4 }}>
                Click + ADD to set up continuous monitoring
              </div>
            </div>
          )}

          {schedules.map((s, i) => (
            <div key={i} className="bracket-card" style={{
              padding: '10px 14px', marginBottom: 6,
              display: 'flex', alignItems: 'center', gap: 10,
              opacity: s.enabled ? 1 : 0.5,
            }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%',
                background: s.enabled ? '#22c55e' : '#6b7280',
              }} />
              <div style={{ flex: 1 }}>
                <div className="mono" style={{ fontSize: 10, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  {s.targetUrl}
                </div>
                <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)' }}>
                  {s.frequency.toUpperCase()} &middot; {s.profile.toUpperCase()} profile
                </div>
              </div>
              <button
                onClick={() => setSchedules(prev => prev.map((sc, j) => j === i ? { ...sc, enabled: !sc.enabled } : sc))}
                className="mono"
                style={{
                  fontSize: 9, padding: '2px 8px', borderRadius: 3,
                  background: 'none', cursor: 'pointer',
                  border: `1px solid ${s.enabled ? '#22c55e' : 'var(--color-border)'}`,
                  color: s.enabled ? '#22c55e' : 'var(--color-text-secondary)',
                }}
              >
                {s.enabled ? 'ON' : 'OFF'}
              </button>
            </div>
          ))}
        </div>

        {/* Alert Rules */}
        <div>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-dast)', marginBottom: 12, fontWeight: 700 }}>
            ALERT RULES
          </div>

          {alerts.map((alert, i) => (
            <div key={i} className="bracket-card" style={{
              padding: '10px 14px', marginBottom: 6,
              display: 'flex', alignItems: 'center', gap: 10,
              opacity: alert.enabled ? 1 : 0.5,
            }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%',
                background: alert.enabled ? '#22c55e' : '#6b7280',
              }} />
              <div style={{ flex: 1 }}>
                <div className="mono" style={{ fontSize: 10, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  {alert.name}
                </div>
                <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)' }}>
                  {alert.condition}
                </div>
              </div>
              <button
                onClick={() => toggleAlert(i)}
                className="mono"
                style={{
                  fontSize: 9, padding: '2px 8px', borderRadius: 3,
                  background: 'none', cursor: 'pointer',
                  border: `1px solid ${alert.enabled ? '#22c55e' : 'var(--color-border)'}`,
                  color: alert.enabled ? '#22c55e' : 'var(--color-text-secondary)',
                }}
              >
                {alert.enabled ? 'ON' : 'OFF'}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Baseline Drift Chart */}
      {completedScans.length >= 2 && (
        <div style={{ marginTop: 24 }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 10 }}>
            SECURITY POSTURE DRIFT
          </div>
          <div className="bracket-card" style={{ padding: 16 }}>
            <svg viewBox="0 0 600 120" width="100%" height="120" style={{ display: 'block' }}>
              {/* Grid lines */}
              {[0, 25, 50, 75, 100].map(v => (
                <g key={v}>
                  <line x1="40" y1={100 - v} x2="580" y2={100 - v} stroke="var(--color-border)" strokeWidth="0.5" />
                  <text x="35" y={104 - v} textAnchor="end" fontSize="8" fill="var(--color-text-secondary)" fontFamily="var(--font-mono)">
                    {v}
                  </text>
                </g>
              ))}
              {/* Risk score line */}
              <polyline
                fill="none" stroke="var(--color-dast)" strokeWidth="2" strokeLinejoin="round"
                points={completedScans.reverse().map((s, i) => {
                  const x = 40 + (i / (completedScans.length - 1)) * 540
                  const y = 100 - (s.riskScore || 0)
                  return `${x},${y}`
                }).join(' ')}
              />
              {completedScans.map((s, i) => (
                <circle
                  key={i}
                  cx={40 + (i / (completedScans.length - 1)) * 540}
                  cy={100 - (s.riskScore || 0)}
                  r="4" fill="var(--color-dast)" stroke="var(--color-bg-primary)" strokeWidth="2"
                />
              ))}
            </svg>
          </div>
        </div>
      )}
    </div>
  )
}
