'use client'

import { useState, useEffect, useCallback } from 'react'
import type { DastScan } from '@/lib/types'

interface MonitoringTabProps {
  scans: DastScan[]
}

interface ScheduleConfig {
  id: string
  frequency: 'daily' | 'weekly' | 'monthly'
  targetUrl: string
  profile: string
  enabled: boolean
  createdAt: string
  lastRun: string | null
  lastStatus: 'success' | 'failed' | null
}

interface AlertRule {
  id: string
  name: string
  condition: string
  enabled: boolean
  lastTriggered: string | null
  triggerCount: number
}

const STORAGE_KEY_SCHEDULES = 'hemisx-dast-schedules'
const STORAGE_KEY_ALERTS = 'hemisx-dast-alerts'

const DEFAULT_ALERTS: AlertRule[] = [
  { id: 'alert-1', name: 'New Critical Finding', condition: 'criticalCount > 0', enabled: true, lastTriggered: null, triggerCount: 0 },
  { id: 'alert-2', name: 'Risk Score Increase > 10', condition: 'riskScoreDelta > 10', enabled: true, lastTriggered: null, triggerCount: 0 },
  { id: 'alert-3', name: 'New HIGH Finding', condition: 'highCount > previousHighCount', enabled: false, lastTriggered: null, triggerCount: 0 },
  { id: 'alert-4', name: 'Scan Failure', condition: 'status === FAILED', enabled: true, lastTriggered: null, triggerCount: 0 },
  { id: 'alert-5', name: 'Certificate Expiring < 30 days', condition: 'certExpiry < 30d', enabled: false, lastTriggered: null, triggerCount: 0 },
]

function loadSchedules(): ScheduleConfig[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_SCHEDULES)
    return raw ? JSON.parse(raw) : []
  } catch { return [] }
}

function saveSchedules(schedules: ScheduleConfig[]) {
  try { localStorage.setItem(STORAGE_KEY_SCHEDULES, JSON.stringify(schedules)) } catch { /* noop */ }
}

function loadAlerts(): AlertRule[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_ALERTS)
    return raw ? JSON.parse(raw) : DEFAULT_ALERTS
  } catch { return DEFAULT_ALERTS }
}

function saveAlerts(alerts: AlertRule[]) {
  try { localStorage.setItem(STORAGE_KEY_ALERTS, JSON.stringify(alerts)) } catch { /* noop */ }
}

function getNextRunTime(schedule: ScheduleConfig): string {
  const base = schedule.lastRun ? new Date(schedule.lastRun) : new Date(schedule.createdAt)
  const next = new Date(base)
  if (schedule.frequency === 'daily') next.setDate(next.getDate() + 1)
  else if (schedule.frequency === 'weekly') next.setDate(next.getDate() + 7)
  else next.setMonth(next.getMonth() + 1)
  if (next <= new Date()) return 'Due now'
  const diffMs = next.getTime() - Date.now()
  const hours = Math.floor(diffMs / 3600000)
  if (hours < 1) return 'Less than 1h'
  if (hours < 24) return `${hours}h`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

export default function MonitoringTab({ scans }: MonitoringTabProps) {
  const [schedules, setSchedules] = useState<ScheduleConfig[]>([])
  const [alerts, setAlerts] = useState<AlertRule[]>(DEFAULT_ALERTS)
  const [showAddSchedule, setShowAddSchedule] = useState(false)
  const [newUrl, setNewUrl] = useState('')
  const [newFreq, setNewFreq] = useState<'daily' | 'weekly' | 'monthly'>('weekly')
  const [newProfile, setNewProfile] = useState('quick')
  const [runningId, setRunningId] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)

  // Load from localStorage on mount
  useEffect(() => {
    setSchedules(loadSchedules())
    setAlerts(loadAlerts())
  }, [])

  // Persist schedules
  const updateSchedules = useCallback((fn: (prev: ScheduleConfig[]) => ScheduleConfig[]) => {
    setSchedules(prev => {
      const next = fn(prev)
      saveSchedules(next)
      return next
    })
  }, [])

  // Persist alerts
  const updateAlerts = useCallback((fn: (prev: AlertRule[]) => AlertRule[]) => {
    setAlerts(prev => {
      const next = fn(prev)
      saveAlerts(next)
      return next
    })
  }, [])

  // Check alerts against latest scan data
  useEffect(() => {
    if (scans.length === 0) return
    const latest = scans.find(s => s.status === 'COMPLETED')
    const previous = scans.filter(s => s.status === 'COMPLETED')[1]
    if (!latest) return

    updateAlerts(prev => prev.map(alert => {
      if (!alert.enabled) return alert
      let triggered = false
      if (alert.condition === 'criticalCount > 0' && latest.criticalCount > 0) triggered = true
      if (alert.condition === 'riskScoreDelta > 10' && previous && (latest.riskScore - previous.riskScore) > 10) triggered = true
      if (alert.condition === 'highCount > previousHighCount' && previous && latest.highCount > previous.highCount) triggered = true
      if (alert.condition === 'status === FAILED' && scans[0]?.status === 'FAILED') triggered = true

      if (triggered && alert.lastTriggered !== latest.completedAt) {
        return { ...alert, lastTriggered: latest.completedAt ?? new Date().toISOString(), triggerCount: alert.triggerCount + 1 }
      }
      return alert
    }))
  }, [scans, updateAlerts])

  // Risk trend from scans
  const completedScans = scans.filter(s => s.status === 'COMPLETED').slice(0, 12)

  function addSchedule() {
    if (!newUrl) return
    try { new URL(newUrl) } catch {
      setToast('Invalid URL format')
      setTimeout(() => setToast(null), 3000)
      return
    }
    updateSchedules(prev => [...prev, {
      id: `sched-${Date.now()}`,
      frequency: newFreq,
      targetUrl: newUrl,
      profile: newProfile,
      enabled: true,
      createdAt: new Date().toISOString(),
      lastRun: null,
      lastStatus: null,
    }])
    setNewUrl('')
    setShowAddSchedule(false)
    setToast('Schedule created')
    setTimeout(() => setToast(null), 3000)
  }

  function deleteSchedule(id: string) {
    updateSchedules(prev => prev.filter(s => s.id !== id))
  }

  async function runNow(schedule: ScheduleConfig) {
    setRunningId(schedule.id)
    try {
      const res = await fetch('/api/dast/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `Scheduled: ${schedule.targetUrl}`,
          targetUrl: schedule.targetUrl,
          scanProfile: schedule.profile,
        }),
      })
      if (res.ok) {
        updateSchedules(prev => prev.map(s =>
          s.id === schedule.id ? { ...s, lastRun: new Date().toISOString(), lastStatus: 'success' as const } : s
        ))
        setToast('Scan started successfully')
      } else {
        updateSchedules(prev => prev.map(s =>
          s.id === schedule.id ? { ...s, lastRun: new Date().toISOString(), lastStatus: 'failed' as const } : s
        ))
        setToast('Failed to start scan')
      }
    } catch {
      updateSchedules(prev => prev.map(s =>
        s.id === schedule.id ? { ...s, lastRun: new Date().toISOString(), lastStatus: 'failed' as const } : s
      ))
      setToast('Network error — scan not started')
    }
    setRunningId(null)
    setTimeout(() => setToast(null), 3000)
  }

  return (
    <div style={{ marginTop: 20 }}>
      {/* Toast notification */}
      {toast && (
        <div style={{
          position: 'fixed', top: 20, right: 20, zIndex: 1000,
          padding: '10px 20px', borderRadius: 6,
          background: toast.includes('Failed') || toast.includes('error') || toast.includes('Invalid') ? '#ef444420' : '#22c55e20',
          border: `1px solid ${toast.includes('Failed') || toast.includes('error') || toast.includes('Invalid') ? '#ef4444' : '#22c55e'}`,
          color: toast.includes('Failed') || toast.includes('error') || toast.includes('Invalid') ? '#ef4444' : '#22c55e',
        }}>
          <span className="mono" style={{ fontSize: 11 }}>{toast}</span>
        </div>
      )}

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
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                {(['quick', 'full', 'api_only'] as const).map(p => (
                  <button
                    key={p} onClick={() => setNewProfile(p)} className="mono"
                    style={{
                      fontSize: 9, padding: '4px 10px', borderRadius: 3, cursor: 'pointer',
                      background: newProfile === p ? 'var(--color-dast)' : 'transparent',
                      color: newProfile === p ? '#fff' : 'var(--color-text-secondary)',
                      border: `1px solid ${newProfile === p ? 'var(--color-dast)' : 'var(--color-border)'}`,
                    }}
                  >
                    {p.toUpperCase().replace('_', ' ')}
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

          {schedules.map(s => (
            <div key={s.id} className="bracket-card" style={{
              padding: '10px 14px', marginBottom: 6,
              opacity: s.enabled ? 1 : 0.5,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: s.enabled ? (s.lastStatus === 'failed' ? '#ef4444' : '#22c55e') : '#6b7280',
                }} />
                <div style={{ flex: 1 }}>
                  <div className="mono" style={{ fontSize: 10, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {s.targetUrl}
                  </div>
                  <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)' }}>
                    {s.frequency.toUpperCase()} &middot; {s.profile.toUpperCase()} &middot; Next: {s.enabled ? getNextRunTime(s) : 'PAUSED'}
                  </div>
                </div>
                <button
                  onClick={() => runNow(s)}
                  disabled={runningId === s.id || !s.enabled}
                  className="mono"
                  style={{
                    fontSize: 9, padding: '2px 8px', borderRadius: 3,
                    background: runningId === s.id ? '#f9731620' : 'none', cursor: 'pointer',
                    border: '1px solid var(--color-dast)',
                    color: 'var(--color-dast)',
                    opacity: runningId === s.id || !s.enabled ? 0.5 : 1,
                  }}
                >
                  {runningId === s.id ? 'RUNNING...' : 'RUN NOW'}
                </button>
                <button
                  onClick={() => updateSchedules(prev => prev.map(sc => sc.id === s.id ? { ...sc, enabled: !sc.enabled } : sc))}
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
                <button
                  onClick={() => deleteSchedule(s.id)}
                  className="mono"
                  style={{
                    fontSize: 9, padding: '2px 6px', borderRadius: 3,
                    background: 'none', cursor: 'pointer',
                    border: '1px solid #ef444440', color: '#ef4444',
                  }}
                >
                  ✕
                </button>
              </div>
              {s.lastRun && (
                <div className="mono" style={{ fontSize: 8, color: 'var(--color-text-secondary)', marginTop: 4, marginLeft: 18 }}>
                  Last run: {new Date(s.lastRun).toLocaleString()} — {s.lastStatus === 'success' ? '✓ Success' : '✕ Failed'}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Alert Rules */}
        <div>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-dast)', marginBottom: 12, fontWeight: 700 }}>
            ALERT RULES
          </div>

          {alerts.map(alert => (
            <div key={alert.id} className="bracket-card" style={{
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
                  {alert.triggerCount > 0 && (
                    <span style={{ marginLeft: 8, color: '#f97316' }}>
                      Triggered {alert.triggerCount}x
                      {alert.lastTriggered && ` — last: ${new Date(alert.lastTriggered).toLocaleDateString()}`}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => updateAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, enabled: !a.enabled } : a))}
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
                points={[...completedScans].reverse().map((s, i, arr) => {
                  const x = 40 + (i / (arr.length - 1)) * 540
                  const y = 100 - (s.riskScore || 0)
                  return `${x},${y}`
                }).join(' ')}
              />
              {/* Finding count area */}
              <polyline
                fill="none" stroke="#7c3aed" strokeWidth="1" strokeDasharray="4 2"
                points={[...completedScans].reverse().map((s, i, arr) => {
                  const x = 40 + (i / (arr.length - 1)) * 540
                  const totalFindings = (s.criticalCount || 0) + (s.highCount || 0) + (s.mediumCount || 0) + (s.lowCount || 0) + (s.infoCount || 0)
                  const y = 100 - Math.min(100, totalFindings * 3)
                  return `${x},${y}`
                }).join(' ')}
              />
              {[...completedScans].reverse().map((s, i, arr) => (
                <g key={i}>
                  <circle
                    cx={40 + (i / (arr.length - 1)) * 540}
                    cy={100 - (s.riskScore || 0)}
                    r="4" fill="var(--color-dast)" stroke="var(--color-bg-primary)" strokeWidth="2"
                  />
                  {/* Date label for first and last */}
                  {(i === 0 || i === arr.length - 1) && s.completedAt && (
                    <text
                      x={40 + (i / (arr.length - 1)) * 540}
                      y={115} textAnchor={i === 0 ? 'start' : 'end'}
                      fontSize="7" fill="var(--color-text-secondary)" fontFamily="var(--font-mono)"
                    >
                      {new Date(s.completedAt).toLocaleDateString()}
                    </text>
                  )}
                </g>
              ))}
            </svg>
            <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 12, height: 2, background: 'var(--color-dast)' }} />
                <span className="mono" style={{ fontSize: 8, color: 'var(--color-text-secondary)' }}>Risk Score</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 12, height: 1, background: '#7c3aed', borderTop: '1px dashed #7c3aed' }} />
                <span className="mono" style={{ fontSize: 8, color: 'var(--color-text-secondary)' }}>Finding Count</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
