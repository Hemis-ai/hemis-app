'use client'

import { useState, useCallback, useEffect, useRef } from 'react'
import type {
  BbrtEngagement,
  BbrtFinding,
  BbrtKillChain,
  BbrtKillChainStep,
  BbrtReconResult,
  BbrtAttackSurface,
  BbrtReport,
  AttackSurfaceAsset,
  SubdomainRecord,
  PortRecord,
  TechStackDetection,
  OsintRecord,
  CertRecord,
  CloudAssetRecord,
  BbrtStatus,
  BbrtEngagementType,
  BbrtTargetConfig,
  BbrtProgressEvent,
} from '@/lib/types/bbrt'
import type { ComplianceGap, RemediationItem, MitreAttackMapping } from '@/lib/types/wbrt'
import {
  MOCK_BBRT_ENGAGEMENT,
} from '@/lib/mock-data/bbrt'

// ─── Color helpers ──────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
  INFO:     'var(--color-text-dim)',
}

const SEV_BG: Record<string, string> = {
  CRITICAL: 'rgba(239,90,90,0.12)',
  HIGH:     'rgba(255,160,50,0.12)',
  MEDIUM:   'rgba(242,209,86,0.10)',
  LOW:      'rgba(90,176,255,0.10)',
  INFO:     'rgba(140,160,180,0.08)',
}

const LIKELIHOOD_COLOR: Record<string, string> = {
  VERY_HIGH: 'var(--color-sev-critical)',
  HIGH:      'var(--color-sev-high)',
  MEDIUM:    'var(--color-sev-medium)',
  LOW:       'var(--color-sev-low)',
}

const IMPACT_COLOR: Record<string, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
}

const EFFORT_COLOR: Record<string, string> = {
  LOW:    'var(--color-sev-low)',
  MEDIUM: 'var(--color-sev-medium)',
  HIGH:   'var(--color-sev-high)',
}

const ASSET_TYPE_ICON: Record<string, string> = {
  domain: '🌐', subdomain: '🔗', ip: '📡', cloud_asset: '☁️',
  api_endpoint: '⚡', admin_panel: '🔐', database: '🗄️',
  cdn: '📦', email_server: '📧', load_balancer: '⚖️',
}

const EXPOSURE_COLOR: Record<string, string> = {
  PUBLIC: 'var(--color-sev-critical)',
  SEMI_PUBLIC: 'var(--color-sev-high)',
  INTERNAL_EXPOSED: 'var(--color-sev-medium)',
}

const BBRT_MITRE_TACTICS = [
  { id: 'TA0043', short: 'Recon' },
  { id: 'TA0042', short: 'ResDev' },
  { id: 'TA0001', short: 'InitAcc' },
  { id: 'TA0006', short: 'CredAcc' },
  { id: 'TA0007', short: 'Discov' },
  { id: 'TA0008', short: 'LatMov' },
  { id: 'TA0009', short: 'Collect' },
  { id: 'TA0010', short: 'Exfil' },
  { id: 'TA0040', short: 'Impact' },
]

const PHASE_LABELS: Record<string, string> = {
  CREATED: 'Created', INITIALIZING: 'Initializing', RECONNAISSANCE: 'Reconnaissance',
  SURFACE_MAPPING: 'Surface Mapping', VULN_DISCOVERY: 'Vulnerability Discovery',
  EXPLOIT_CHAINING: 'Exploit Chaining', IMPACT_SCORING: 'Impact Scoring',
  REPORTING: 'Reporting', COMPLETED: 'Complete', FAILED: 'Failed',
}
const PHASE_ORDER: BbrtStatus[] = [
  'INITIALIZING', 'RECONNAISSANCE', 'SURFACE_MAPPING', 'VULN_DISCOVERY',
  'EXPLOIT_CHAINING', 'IMPACT_SCORING', 'REPORTING',
]

function scoreColor(s: number) {
  if (s >= 85) return 'var(--color-sev-critical)'
  if (s >= 65) return 'var(--color-sev-high)'
  if (s >= 40) return 'var(--color-sev-medium)'
  return 'var(--color-sev-low)'
}

function riskColor(r: string) {
  return r === 'CRITICAL' ? 'var(--color-sev-critical)' : r === 'HIGH' ? 'var(--color-sev-high)' : r === 'MEDIUM' ? 'var(--color-sev-medium)' : 'var(--color-sev-low)'
}

// ─── Type filter tabs ───────────────────────────────────────────────────────────

type EngagementTab = 'attack-surface' | 'recon' | 'kill-chains' | 'findings' | 'mitre' | 'report'
type SevFilter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

// ─── Main Component ─────────────────────────────────────────────────────────────

export default function BlackBoxRedTeamingPage() {
  // State
  const [engagements, setEngagements] = useState<BbrtEngagement[]>([MOCK_BBRT_ENGAGEMENT])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [tab, setTab] = useState<EngagementTab>('attack-surface')
  const [sevFilter, setSevFilter] = useState<SevFilter>('ALL')
  const [expandedKillChain, setExpandedKillChain] = useState<string | null>(null)
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)
  const [showNewForm, setShowNewForm] = useState(false)
  const [newTarget, setNewTarget] = useState('')
  const [newName, setNewName] = useState('')
  const [newType, setNewType] = useState<BbrtEngagementType>('full')
  const [newIndustry, setNewIndustry] = useState('fintech')
  const [isCreating, setIsCreating] = useState(false)
  const [terminalLogs, setTerminalLogs] = useState<string[]>([])
  const terminalRef = useRef<HTMLDivElement>(null)

  const engagement = engagements.find(e => e.id === selectedId) ?? null
  const recon = engagement?.reconResult
  const surface = engagement?.attackSurface
  const findings = engagement?.findings ?? []
  const killChains = engagement?.killChains ?? []
  const report = engagement?.report

  // Progress polling
  useEffect(() => {
    if (!engagement || engagement.status === 'COMPLETED' || engagement.status === 'FAILED' || engagement.status === 'CREATED') return
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/bbrt/engagements/${engagement.id}/progress`)
        if (!res.ok) return
        const data = await res.json()
        const prog: BbrtProgressEvent = data.progress
        setEngagements(prev => prev.map(e => e.id === engagement.id ? {
          ...e,
          status: prog.status,
          progress: prog.progress,
          currentPhase: prog.currentPhase,
        } : e))
        setTerminalLogs(prev => [...prev, `[${new Date(prog.timestamp).toLocaleTimeString()}] ${prog.message}`])
        if (prog.status === 'COMPLETED' || prog.status === 'FAILED') {
          clearInterval(interval)
          // Fetch full engagement
          const fullRes = await fetch(`/api/bbrt/engagements/${engagement.id}`)
          if (fullRes.ok) {
            const fullData = await fullRes.json()
            setEngagements(prev => prev.map(e => e.id === engagement.id ? fullData.engagement : e))
          }
        }
      } catch { /* polling error — ignore */ }
    }, 1500)
    return () => clearInterval(interval)
  }, [engagement?.id, engagement?.status])

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight
  }, [terminalLogs])

  // Create engagement
  const handleCreate = useCallback(async () => {
    if (!newTarget.trim()) return
    setIsCreating(true)
    try {
      const body: { name: string; targetConfig: BbrtTargetConfig } = {
        name: newName.trim() || `BBRT — ${newTarget}`,
        targetConfig: {
          targetDomain: newTarget.trim(),
          targetScope: [`*.${newTarget.trim()}`],
          excludedPaths: [],
          engagementType: newType,
          complianceRequirements: ['SOC2'],
          businessContext: { industry: newIndustry as any, dataTypes: ['PII', 'CONFIDENTIAL'], userCount: '1K-10K', revenueRange: '$10M-100M', criticalSystems: [] },
        },
      }
      const res = await fetch('/api/bbrt/engagements', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (!res.ok) throw new Error('Failed to create')
      const data = await res.json()
      setEngagements(prev => [data.engagement, ...prev])
      setSelectedId(data.engagement.id)
      setShowNewForm(false)
      setTerminalLogs([`[${new Date().toLocaleTimeString()}] Engagement created: ${data.engagement.id}`])
      // Fire pipeline
      await fetch(`/api/bbrt/engagements/${data.engagement.id}/run`, { method: 'POST' })
      setTerminalLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Pipeline started — 7-phase analysis beginning...`])
    } catch { setTerminalLogs(prev => [...prev, `[ERROR] Failed to create engagement`]) }
    setIsCreating(false)
  }, [newTarget, newName, newType, newIndustry])

  // ─── Dashboard View ─────────────────────────────────────────────────────────

  if (!selectedId) {
    const totalFindings = engagements.reduce((s, e) => s + (e.summary?.totalFindings ?? 0), 0)
    const critFindings = engagements.reduce((s, e) => s + (e.summary?.criticalFindings ?? 0), 0)
    const avgRisk = engagements.length ? Math.round(engagements.reduce((s, e) => s + (e.summary?.overallRiskScore ?? 0), 0) / engagements.length) : 0

    return (
      <div style={{ padding: 32 }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
          <span style={{ fontSize: 28, width: 48, height: 48, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--color-bbrt-dim)', borderRadius: 10, border: '1px solid var(--color-bbrt)' }}>◌</span>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-bbrt)', letterSpacing: '-0.02em', margin: 0, fontFamily: 'var(--font-display)' }}>BLACK BOX RED TEAMING</h1>
            <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', margin: 0, marginTop: 2 }}>Zero-knowledge adversary simulation — attacking from the outside in</p>
          </div>
          <div style={{ flex: 1 }} />
          <button onClick={() => setShowNewForm(!showNewForm)} style={{ padding: '10px 20px', borderRadius: 8, border: 'none', background: 'var(--color-bbrt)', color: '#fff', fontWeight: 600, fontSize: 13, cursor: 'pointer', fontFamily: 'var(--font-display)' }}>
            + New Engagement
          </button>
        </div>

        <div style={{ borderBottom: '1px solid var(--color-border)', margin: '20px 0 24px' }} />

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
          {[
            { label: 'Active Engagements', value: engagements.length, color: 'var(--color-bbrt)' },
            { label: 'Total Findings', value: totalFindings, color: 'var(--color-text-primary)' },
            { label: 'Critical Findings', value: critFindings, color: 'var(--color-sev-critical)' },
            { label: 'Avg Risk Score', value: `${avgRisk}/100`, color: scoreColor(avgRisk) },
          ].map(s => (
            <div key={s.label} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, padding: '18px 20px' }}>
              <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', letterSpacing: '0.04em', marginBottom: 6, textTransform: 'uppercase' }}>{s.label}</div>
              <div style={{ fontSize: 26, fontWeight: 700, color: s.color, fontFamily: 'var(--font-display)' }}>{s.value}</div>
            </div>
          ))}
        </div>

        {/* New Engagement Form */}
        {showNewForm && (
          <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-bbrt)', borderRadius: 12, padding: 24, marginBottom: 24 }}>
            <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--color-bbrt)', margin: '0 0 16px', fontFamily: 'var(--font-display)' }}>New Black Box Assessment</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>TARGET DOMAIN *</label>
                <input value={newTarget} onChange={e => setNewTarget(e.target.value)} placeholder="example.com" style={{ width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid var(--color-border)', background: 'var(--color-bg-sunken)', color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', fontSize: 13, outline: 'none', boxSizing: 'border-box' }} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>ENGAGEMENT NAME</label>
                <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="Optional" style={{ width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid var(--color-border)', background: 'var(--color-bg-sunken)', color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', fontSize: 13, outline: 'none', boxSizing: 'border-box' }} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>TYPE</label>
                <select value={newType} onChange={e => setNewType(e.target.value as BbrtEngagementType)} style={{ width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid var(--color-border)', background: 'var(--color-bg-sunken)', color: 'var(--color-text-primary)', fontSize: 13, outline: 'none' }}>
                  {['full', 'web', 'api', 'network', 'cloud'].map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>INDUSTRY</label>
                <select value={newIndustry} onChange={e => setNewIndustry(e.target.value)} style={{ width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid var(--color-border)', background: 'var(--color-bg-sunken)', color: 'var(--color-text-primary)', fontSize: 13, outline: 'none' }}>
                  {['fintech', 'healthcare', 'saas', 'ecommerce', 'government', 'education', 'media', 'manufacturing'].map(i => <option key={i} value={i}>{i.charAt(0).toUpperCase() + i.slice(1)}</option>)}
                </select>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
              <button onClick={handleCreate} disabled={isCreating || !newTarget.trim()} style={{ padding: '10px 24px', borderRadius: 8, border: 'none', background: 'var(--color-bbrt)', color: '#fff', fontWeight: 600, fontSize: 13, cursor: 'pointer', opacity: isCreating || !newTarget.trim() ? 0.5 : 1 }}>
                {isCreating ? 'Creating...' : 'Launch Assessment'}
              </button>
              <button onClick={() => setShowNewForm(false)} style={{ padding: '10px 24px', borderRadius: 8, border: '1px solid var(--color-border)', background: 'transparent', color: 'var(--color-text-secondary)', fontSize: 13, cursor: 'pointer' }}>Cancel</button>
            </div>
          </div>
        )}

        {/* Engagement List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {engagements.map(e => (
            <div key={e.id} onClick={() => { setSelectedId(e.id); setTab('attack-surface'); setTerminalLogs([]) }} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 12, padding: '20px 24px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 20, transition: 'border-color 0.15s' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 4 }}>{e.name}</div>
                <div style={{ fontSize: 12, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>{e.targetConfig.targetDomain} &middot; {e.targetConfig.engagementType}</div>
              </div>
              <span style={{ padding: '4px 12px', borderRadius: 6, fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-mono)', background: e.status === 'COMPLETED' ? 'rgba(0,212,170,0.12)' : e.status === 'FAILED' ? SEV_BG.CRITICAL : 'rgba(255,107,157,0.12)', color: e.status === 'COMPLETED' ? '#00d4aa' : e.status === 'FAILED' ? SEV_COLOR.CRITICAL : 'var(--color-bbrt)' }}>
                {e.status}
              </span>
              {e.summary && (
                <>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: scoreColor(e.summary.overallRiskScore), fontFamily: 'var(--font-display)' }}>{e.summary.overallRiskScore}</div>
                    <div style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>RISK</div>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {e.summary.criticalFindings > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)', background: SEV_BG.CRITICAL, color: SEV_COLOR.CRITICAL }}>{e.summary.criticalFindings}C</span>}
                    {e.summary.highFindings > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)', background: SEV_BG.HIGH, color: SEV_COLOR.HIGH }}>{e.summary.highFindings}H</span>}
                    {e.summary.mediumFindings > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)', background: SEV_BG.MEDIUM, color: SEV_COLOR.MEDIUM }}>{e.summary.mediumFindings}M</span>}
                    {e.summary.lowFindings > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)', background: SEV_BG.LOW, color: SEV_COLOR.LOW }}>{e.summary.lowFindings}L</span>}
                  </div>
                </>
              )}
              <span style={{ fontSize: 18, color: 'var(--color-text-dim)' }}>&rsaquo;</span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  // ─── Engagement Detail View ───────────────────────────────────────────────────

  const filteredFindings = sevFilter === 'ALL' ? findings : findings.filter(f => f.severity === sevFilter)
  const isRunning = engagement && !['COMPLETED', 'FAILED', 'CREATED'].includes(engagement.status)
  const phaseIdx = engagement ? PHASE_ORDER.indexOf(engagement.status as BbrtStatus) : -1

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* ─── Left Panel: Attack Console ─────────────────────────────────────── */}
      <div style={{ width: 420, minWidth: 420, borderRight: '1px solid var(--color-border)', display: 'flex', flexDirection: 'column', background: 'var(--color-bg-base)' }}>
        {/* Back + Target info */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--color-border)' }}>
          <button onClick={() => setSelectedId(null)} style={{ fontSize: 12, color: 'var(--color-text-dim)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginBottom: 10, fontFamily: 'var(--font-mono)' }}>&larr; Back to Dashboard</button>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 22, width: 38, height: 38, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--color-bbrt-dim)', borderRadius: 8, border: '1px solid var(--color-bbrt)' }}>◌</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)' }}>{engagement?.name}</div>
              <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{engagement?.targetConfig.targetDomain} &middot; {engagement?.targetConfig.engagementType}</div>
            </div>
            <span style={{ padding: '4px 10px', borderRadius: 6, fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)', background: engagement?.status === 'COMPLETED' ? 'rgba(0,212,170,0.12)' : SEV_BG.HIGH, color: engagement?.status === 'COMPLETED' ? '#00d4aa' : 'var(--color-bbrt)' }}>
              {engagement?.status}
            </span>
          </div>
        </div>

        {/* Phase Progress */}
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--color-border)' }}>
          <div style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginBottom: 8, letterSpacing: '0.06em' }}>PIPELINE PROGRESS</div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 8 }}>
            {PHASE_ORDER.map((p, i) => {
              const done = phaseIdx > i || engagement?.status === 'COMPLETED'
              const active = phaseIdx === i && isRunning
              return (
                <div key={p} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
                  <div style={{
                    width: 10, height: 10, borderRadius: '50%',
                    background: done ? '#00d4aa' : active ? 'var(--color-bbrt)' : 'var(--color-border)',
                    boxShadow: active ? '0 0 8px var(--color-bbrt)' : 'none',
                    transition: 'all 0.3s',
                  }} />
                  <div style={{ fontSize: 8, color: done ? '#00d4aa' : active ? 'var(--color-bbrt)' : 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', textAlign: 'center', lineHeight: 1.2 }}>
                    {p.replace('_', '\n').slice(0, 6)}
                  </div>
                </div>
              )
            })}
          </div>
          {/* Progress bar */}
          <div style={{ width: '100%', height: 4, background: 'var(--color-border)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{ width: `${engagement?.progress ?? 0}%`, height: '100%', background: engagement?.status === 'COMPLETED' ? '#00d4aa' : 'var(--color-bbrt)', borderRadius: 2, transition: 'width 0.5s' }} />
          </div>
          <div style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>{engagement?.progress ?? 0}% &middot; {PHASE_LABELS[engagement?.status ?? 'CREATED'] ?? engagement?.status}</div>
        </div>

        {/* Summary Stats */}
        {engagement?.summary && (
          <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--color-border)', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
            {[
              { l: 'Assets', v: engagement.summary.totalAssets, c: 'var(--color-text-primary)' },
              { l: 'Findings', v: engagement.summary.totalFindings, c: 'var(--color-sev-high)' },
              { l: 'Kill Chains', v: engagement.summary.totalKillChains, c: 'var(--color-sev-critical)' },
              { l: 'Risk Score', v: `${engagement.summary.overallRiskScore}`, c: scoreColor(engagement.summary.overallRiskScore) },
              { l: 'Exposure', v: `${engagement.summary.exposureScore}`, c: scoreColor(engagement.summary.exposureScore) },
              { l: 'Critical', v: engagement.summary.criticalFindings, c: 'var(--color-sev-critical)' },
            ].map(s => (
              <div key={s.l} style={{ background: 'var(--color-bg-elevated)', borderRadius: 6, padding: '8px 10px', textAlign: 'center' }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: s.c, fontFamily: 'var(--font-display)' }}>{s.v}</div>
                <div style={{ fontSize: 8, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginTop: 2, letterSpacing: '0.04em' }}>{s.l.toUpperCase()}</div>
              </div>
            ))}
          </div>
        )}

        {/* Terminal */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '10px 20px 6px', fontSize: 10, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }}>ATTACK CONSOLE</div>
          <div ref={terminalRef} style={{ flex: 1, overflowY: 'auto', background: '#0a0a0a', margin: '0 12px 12px', borderRadius: 8, padding: 12, fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.7, color: '#4ade80' }}>
            {(terminalLogs.length > 0 ? terminalLogs : [
              `[SYS] HemisX BBRT Engine v2.0`,
              `[SYS] Target: ${engagement?.targetConfig.targetDomain}`,
              `[SYS] Type: ${engagement?.targetConfig.engagementType} assessment`,
              `[SYS] Status: ${engagement?.status}`,
              ...(engagement?.status === 'COMPLETED' ? [
                `[RECON] ${recon?.subdomains.length ?? 0} subdomains discovered`,
                `[RECON] ${recon?.openPorts.length ?? 0} open ports found`,
                `[RECON] ${recon?.techStack.length ?? 0} technologies fingerprinted`,
                `[RECON] ${recon?.osintFindings.length ?? 0} OSINT findings`,
                `[SURFACE] ${surface?.totalAssets ?? 0} assets mapped`,
                `[SURFACE] ${surface?.shadowAssets.length ?? 0} shadow assets detected`,
                `[SURFACE] Exposure score: ${surface?.exposureScore ?? 0}/100`,
                `[VULN] ${findings.length} vulnerabilities discovered`,
                `[CHAIN] ${killChains.length} kill chains constructed`,
                `[REPORT] Risk score: ${engagement?.summary?.overallRiskScore ?? 0}/100`,
                `[SYS] Analysis complete.`,
              ] : []),
            ]).map((line, i) => (
              <div key={i} style={{ color: line.includes('[ERROR]') ? '#ef5a5a' : line.includes('[SYS]') ? '#6b7280' : line.includes('[VULN]') || line.includes('[CHAIN]') ? '#f59e0b' : '#4ade80' }}>
                {line}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ─── Right Panel: Tabbed Results ───────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Tab bar */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--color-border)', padding: '0 24px', background: 'var(--color-bg-base)' }}>
          {([
            ['attack-surface', 'ATTACK SURFACE'],
            ['recon', 'RECON'],
            ['kill-chains', 'KILL CHAINS'],
            ['findings', 'FINDINGS'],
            ['mitre', 'MITRE HEATMAP'],
            ['report', 'REPORT'],
          ] as [EngagementTab, string][]).map(([t, label]) => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding: '12px 18px', fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-mono)',
              letterSpacing: '0.04em', border: 'none', borderBottom: tab === t ? '2px solid var(--color-bbrt)' : '2px solid transparent',
              background: 'transparent', color: tab === t ? 'var(--color-bbrt)' : 'var(--color-text-dim)', cursor: 'pointer',
            }}>{label}</button>
          ))}
        </div>

        {/* Tab content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>

          {/* ─── Tab: Attack Surface ───────────────────────────────────── */}
          {tab === 'attack-surface' && surface && (
            <div>
              {/* Stats row */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12, marginBottom: 24 }}>
                {[
                  { l: 'Total Assets', v: surface.totalAssets },
                  { l: 'Public', v: surface.publicAssets, c: 'var(--color-sev-critical)' },
                  { l: 'Int. Exposed', v: surface.internalExposedAssets, c: 'var(--color-sev-high)' },
                  { l: 'Shadow', v: surface.shadowAssets.length, c: 'var(--color-sev-critical)' },
                  { l: 'Entry Points', v: surface.entryPoints.length, c: '#00d4aa' },
                  { l: 'Crown Jewels', v: surface.crownJewels.length, c: '#b06aff' },
                ].map(s => (
                  <div key={s.l} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 8, padding: '14px 16px', textAlign: 'center' }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: s.c ?? 'var(--color-text-primary)', fontFamily: 'var(--font-display)' }}>{s.v}</div>
                    <div style={{ fontSize: 9, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginTop: 4, letterSpacing: '0.04em' }}>{s.l.toUpperCase()}</div>
                  </div>
                ))}
              </div>

              {/* Exposure Score */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24, background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, padding: 20 }}>
                <div style={{ width: 80, height: 80, borderRadius: '50%', border: `4px solid ${scoreColor(surface.exposureScore)}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column' }}>
                  <div style={{ fontSize: 24, fontWeight: 700, color: scoreColor(surface.exposureScore), fontFamily: 'var(--font-display)' }}>{surface.exposureScore}</div>
                  <div style={{ fontSize: 8, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>/ 100</div>
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)' }}>Exposure Score</div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginTop: 4 }}>Surface area visible to external attackers. Industry average for fintech: 45/100.</div>
                </div>
              </div>

              {/* Shadow Asset Warning */}
              {surface.shadowAssets.length > 0 && (
                <div style={{ background: 'rgba(239,90,90,0.08)', border: '1px solid rgba(239,90,90,0.3)', borderRadius: 10, padding: 16, marginBottom: 24 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-sev-critical)', marginBottom: 6 }}>Shadow Assets Detected ({surface.shadowAssets.length})</div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 10 }}>These assets were not expected to be publicly accessible:</div>
                  {surface.shadowAssets.map(a => (
                    <div key={a.id} style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-sev-critical)', padding: '4px 0' }}>
                      {ASSET_TYPE_ICON[a.type] ?? '?'} {a.label} — risk score: {a.riskScore}/100
                    </div>
                  ))}
                </div>
              )}

              {/* Asset Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
                {surface.assets.map(a => (
                  <div key={a.id} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, padding: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <span style={{ fontSize: 18 }}>{ASSET_TYPE_ICON[a.type] ?? '?'}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>{a.label}</div>
                        <div style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{a.type.replace('_', ' ')}</div>
                      </div>
                      <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600, fontFamily: 'var(--font-mono)', background: `${EXPOSURE_COLOR[a.exposureLevel]}20`, color: EXPOSURE_COLOR[a.exposureLevel] }}>{a.exposureLevel.replace('_', ' ')}</span>
                    </div>
                    {/* Risk bar */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                      <div style={{ flex: 1, height: 4, background: 'var(--color-border)', borderRadius: 2, overflow: 'hidden' }}>
                        <div style={{ width: `${a.riskScore}%`, height: '100%', background: scoreColor(a.riskScore), borderRadius: 2 }} />
                      </div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: scoreColor(a.riskScore), fontFamily: 'var(--font-mono)' }}>{a.riskScore}</span>
                    </div>
                    {/* Services */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 6 }}>
                      {a.services.map(s => (
                        <span key={s} style={{ fontSize: 9, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 3, background: 'var(--color-bg-sunken)', color: 'var(--color-text-dim)' }}>{s}</span>
                      ))}
                    </div>
                    {/* Badges */}
                    <div style={{ display: 'flex', gap: 6 }}>
                      {a.isEntryPoint && <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 3, background: 'rgba(0,212,170,0.12)', color: '#00d4aa' }}>ENTRY POINT</span>}
                      {a.isCrownJewel && <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 3, background: 'rgba(176,106,255,0.12)', color: '#b06aff' }}>CROWN JEWEL</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ─── Tab: Recon ────────────────────────────────────────────── */}
          {tab === 'recon' && recon && (
            <div>
              {/* Subdomains */}
              <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 12 }}>Subdomains ({recon.subdomains.length})</h3>
              <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden', marginBottom: 28 }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                  <thead>
                    <tr style={{ background: 'var(--color-bg-sunken)' }}>
                      {['Subdomain', 'IP', 'Status', 'HTTP', 'Risk', 'Shadow'].map(h => (
                        <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, color: 'var(--color-text-dim)', fontWeight: 500, letterSpacing: '0.04em' }}>{h.toUpperCase()}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {recon.subdomains.map(s => (
                      <tr key={s.subdomain} style={{ borderTop: '1px solid var(--color-border)' }}>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-primary)' }}>{s.subdomain}</td>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-dim)' }}>{s.ip}</td>
                        <td style={{ padding: '10px 14px' }}><span style={{ color: s.status === 'active' ? '#00d4aa' : 'var(--color-text-dim)' }}>{s.status}</span></td>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-dim)' }}>{s.httpStatus ?? '—'}</td>
                        <td style={{ padding: '10px 14px' }}><span style={{ color: scoreColor(s.riskScore), fontWeight: 600 }}>{s.riskScore}</span></td>
                        <td style={{ padding: '10px 14px' }}>{s.isShadowAsset && <span style={{ color: 'var(--color-sev-critical)', fontWeight: 600 }}>YES</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Open Ports */}
              <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 12 }}>Open Ports ({recon.openPorts.length})</h3>
              <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden', marginBottom: 28 }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                  <thead>
                    <tr style={{ background: 'var(--color-bg-sunken)' }}>
                      {['Host', 'Port', 'Service', 'Version', 'Risk', 'Notes'].map(h => (
                        <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, color: 'var(--color-text-dim)', fontWeight: 500, letterSpacing: '0.04em' }}>{h.toUpperCase()}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {recon.openPorts.map((p, i) => (
                      <tr key={`${p.host}-${p.port}-${i}`} style={{ borderTop: '1px solid var(--color-border)' }}>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-primary)' }}>{p.host}</td>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-dim)' }}>{p.port}/{p.protocol}</td>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-primary)' }}>{p.service}</td>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-dim)' }}>{p.version ?? '—'}</td>
                        <td style={{ padding: '10px 14px' }}><span style={{ padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600, background: SEV_BG[p.riskLevel] ?? SEV_BG.INFO, color: SEV_COLOR[p.riskLevel] ?? SEV_COLOR.INFO }}>{p.riskLevel}</span></td>
                        <td style={{ padding: '10px 14px', color: 'var(--color-text-dim)', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.notes ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Tech Stack */}
              <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 12 }}>Technology Stack ({recon.techStack.length})</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 28 }}>
                {recon.techStack.map(t => (
                  <div key={t.name} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 8, padding: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 3, background: 'var(--color-bbrt-dim)', color: 'var(--color-bbrt)' }}>{t.category}</span>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>{t.name}</div>
                    </div>
                    {t.version && <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>v{t.version}</div>}
                    <div style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>Confidence: {t.confidence}% &middot; via {t.detectedVia}</div>
                    {t.knownCVEs && t.knownCVEs.length > 0 && (
                      <div style={{ marginTop: 6, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {t.knownCVEs.map(c => <span key={c} style={{ fontSize: 9, fontFamily: 'var(--font-mono)', padding: '2px 5px', borderRadius: 3, background: SEV_BG.CRITICAL, color: SEV_COLOR.CRITICAL }}>{c}</span>)}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* OSINT */}
              <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 12 }}>OSINT Findings ({recon.osintFindings.length})</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 28 }}>
                {recon.osintFindings.map((o, i) => (
                  <div key={i} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, padding: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                      <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--font-mono)', background: SEV_BG[o.severity], color: SEV_COLOR[o.severity], fontWeight: 600 }}>{o.severity}</span>
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>{o.source}</span>
                      <div style={{ flex: 1 }} />
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>{o.type.replace('_', ' ')}</span>
                    </div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 4 }}>{o.title}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 8, lineHeight: 1.5 }}>{o.description}</div>
                    <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)', background: '#0a0a0a', padding: 10, borderRadius: 6, whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>{o.data}</div>
                  </div>
                ))}
              </div>

              {/* TLS Certs */}
              <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 12 }}>TLS Certificates ({recon.tlsCertificates.length})</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 28 }}>
                {recon.tlsCertificates.map(c => (
                  <div key={c.host} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, padding: 16 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', marginBottom: 6 }}>{c.host}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 4 }}>Issuer: {c.issuer} &middot; Algorithm: {c.signatureAlgorithm}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 8 }}>Valid: {new Date(c.validFrom).toLocaleDateString()} — {new Date(c.validTo).toLocaleDateString()}</div>
                    {c.issues.map((iss, i) => (
                      <div key={i} style={{ fontSize: 11, padding: '4px 8px', borderRadius: 4, background: SEV_BG[iss.severity], color: SEV_COLOR[iss.severity], marginBottom: 4 }}>
                        [{iss.type}] {iss.description}
                      </div>
                    ))}
                  </div>
                ))}
              </div>

              {/* Cloud Assets */}
              {recon.cloudAssets.length > 0 && (
                <>
                  <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 12 }}>Cloud Assets ({recon.cloudAssets.length})</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 28 }}>
                    {recon.cloudAssets.map((ca, i) => (
                      <div key={i} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, padding: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                          <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 3, background: 'var(--color-bbrt-dim)', color: 'var(--color-bbrt)' }}>{ca.provider.toUpperCase()}</span>
                          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>{ca.identifier}</span>
                          {ca.isPublic && <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 3, background: SEV_BG.CRITICAL, color: SEV_COLOR.CRITICAL, fontWeight: 600 }}>PUBLIC</span>}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 4 }}>{ca.type.replace('_', ' ')} {ca.region ? `(${ca.region})` : ''}</div>
                        {ca.issues.map((iss, j) => (
                          <div key={j} style={{ fontSize: 11, color: 'var(--color-sev-high)', padding: '2px 0' }}>- {iss}</div>
                        ))}
                      </div>
                    ))}
                  </div>
                </>
              )}

              {/* Emails */}
              {recon.emailAddresses.length > 0 && (
                <>
                  <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', marginBottom: 12 }}>Discovered Email Addresses ({recon.emailAddresses.length})</h3>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 28 }}>
                    {recon.emailAddresses.map(e => (
                      <span key={e} style={{ fontSize: 12, fontFamily: 'var(--font-mono)', padding: '6px 12px', borderRadius: 6, background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', color: 'var(--color-text-primary)' }}>{e}</span>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}

          {/* ─── Tab: Kill Chains ──────────────────────────────────────── */}
          {tab === 'kill-chains' && (
            <div>
              <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginBottom: 20 }}>
                {killChains.length} attack chains discovered — click to expand step-by-step timeline
              </div>
              {killChains.map(kc => (
                <div key={kc.id} style={{ marginBottom: 16 }}>
                  {/* Chain Header */}
                  <div onClick={() => setExpandedKillChain(expandedKillChain === kc.id ? null : kc.id)} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: expandedKillChain === kc.id ? '10px 10px 0 0' : 10, padding: 20, cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                      <span style={{ fontSize: 16, transform: expandedKillChain === kc.id ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }}>&#9654;</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)' }}>{kc.name}</div>
                        <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{kc.objective}</div>
                      </div>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <span style={{ padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)', background: `${LIKELIHOOD_COLOR[kc.likelihood]}20`, color: LIKELIHOOD_COLOR[kc.likelihood] }}>L:{kc.likelihood}</span>
                        <span style={{ padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)', background: `${IMPACT_COLOR[kc.impact]}20`, color: IMPACT_COLOR[kc.impact] }}>I:{kc.impact}</span>
                        <span style={{ fontSize: 16, fontWeight: 700, color: scoreColor(kc.riskScore), fontFamily: 'var(--font-display)', marginLeft: 4 }}>{kc.riskScore}</span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 12, fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>
                      <span>Time: {kc.estimatedTimeToExploit}</span>
                      <span>Detection: {kc.detectionDifficulty}</span>
                      <span>Steps: {kc.steps.length}</span>
                      <span>Data at risk: {kc.dataAtRisk.length} types</span>
                    </div>
                  </div>

                  {/* Expanded: Steps + Narrative */}
                  {expandedKillChain === kc.id && (
                    <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderTop: 'none', borderRadius: '0 0 10px 10px', padding: 20 }}>
                      {/* Narrative */}
                      <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 20, padding: 16, background: 'var(--color-bg-sunken)', borderRadius: 8, borderLeft: '3px solid var(--color-bbrt)' }}>
                        {kc.narrative}
                      </div>

                      {/* Steps Timeline */}
                      {kc.steps.map((step, i) => (
                        <div key={i} style={{ display: 'flex', gap: 16, marginBottom: i < kc.steps.length - 1 ? 0 : 0, position: 'relative', paddingLeft: 20, paddingBottom: 20 }}>
                          {/* Timeline line */}
                          {i < kc.steps.length - 1 && <div style={{ position: 'absolute', left: 5, top: 14, bottom: 0, width: 2, background: 'var(--color-border)' }} />}
                          {/* Dot */}
                          <div style={{ position: 'absolute', left: 0, top: 4, width: 12, height: 12, borderRadius: '50%', background: step.result === 'SUCCESS' ? '#00d4aa' : step.result === 'PARTIAL' ? 'var(--color-sev-medium)' : 'var(--color-sev-critical)', border: '2px solid var(--color-bg-elevated)', zIndex: 1 }} />
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                              <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 3, background: 'var(--color-bbrt-dim)', color: 'var(--color-bbrt)' }}>{step.tacticId}</span>
                              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)' }}>{step.tactic}</span>
                              <span style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>&rarr;</span>
                              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)' }}>{step.technique}</span>
                              <span style={{ marginLeft: 'auto', padding: '2px 6px', borderRadius: 3, fontSize: 9, fontWeight: 600, fontFamily: 'var(--font-mono)', background: step.result === 'SUCCESS' ? 'rgba(0,212,170,0.12)' : step.result === 'PARTIAL' ? SEV_BG.MEDIUM : SEV_BG.CRITICAL, color: step.result === 'SUCCESS' ? '#00d4aa' : step.result === 'PARTIAL' ? SEV_COLOR.MEDIUM : SEV_COLOR.CRITICAL }}>{step.result}</span>
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.5, marginBottom: 4 }}>{step.action}</div>
                            <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>Target: {step.target} &middot; Evidence: {step.evidence}</div>
                          </div>
                        </div>
                      ))}

                      {/* Data at Risk */}
                      <div style={{ marginTop: 12, padding: 12, background: 'rgba(239,90,90,0.06)', borderRadius: 8, border: '1px solid rgba(239,90,90,0.15)' }}>
                        <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-sev-critical)', marginBottom: 6, fontWeight: 600 }}>DATA AT RISK</div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          {kc.dataAtRisk.map(d => (
                            <span key={d} style={{ fontSize: 11, fontFamily: 'var(--font-mono)', padding: '3px 8px', borderRadius: 4, background: SEV_BG.CRITICAL, color: SEV_COLOR.CRITICAL }}>{d}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ─── Tab: Findings ─────────────────────────────────────────── */}
          {tab === 'findings' && (
            <div>
              {/* Severity filters */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as SevFilter[]).map(f => (
                  <button key={f} onClick={() => setSevFilter(f)} style={{
                    padding: '6px 14px', borderRadius: 6, border: sevFilter === f ? '1px solid var(--color-bbrt)' : '1px solid var(--color-border)',
                    background: sevFilter === f ? 'var(--color-bbrt-dim)' : 'transparent', color: sevFilter === f ? 'var(--color-bbrt)' : 'var(--color-text-dim)',
                    fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 600, cursor: 'pointer',
                  }}>
                    {f} {f !== 'ALL' && `(${findings.filter(ff => ff.severity === f).length})`}
                    {f === 'ALL' && `(${findings.length})`}
                  </button>
                ))}
              </div>

              {/* Finding cards */}
              {filteredFindings.map(f => (
                <div key={f.id} style={{ marginBottom: 12 }}>
                  <div onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)} style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: expandedFinding === f.id ? '10px 10px 0 0' : 10, padding: 16, cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)', background: SEV_BG[f.severity], color: SEV_COLOR[f.severity] }}>{f.severity}</span>
                      <span style={{ padding: '3px 8px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--font-mono)', background: 'var(--color-bbrt-dim)', color: 'var(--color-bbrt)' }}>{f.type.replace('_', ' ')}</span>
                      <div style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>{f.title}</div>
                      <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', color: scoreColor(f.cvssScore * 10) }}>CVSS {f.cvssScore}</span>
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>{f.exploitability}</span>
                    </div>
                    <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)', marginTop: 6 }}>
                      {f.affectedAssetLabel} {f.affectedUrl ? `— ${f.affectedUrl}` : ''}
                    </div>
                  </div>

                  {expandedFinding === f.id && (
                    <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderTop: 'none', borderRadius: '0 0 10px 10px', padding: 20 }}>
                      <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 16 }}>{f.description}</div>

                      {/* Evidence */}
                      {(f.evidence.httpRequest || f.evidence.httpResponse || f.evidence.pocPayload) && (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 8, fontFamily: 'var(--font-display)' }}>Evidence</div>
                          {f.evidence.httpRequest && (
                            <div style={{ marginBottom: 8 }}>
                              <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)', marginBottom: 4 }}>HTTP REQUEST</div>
                              <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: '#4ade80', background: '#0a0a0a', padding: 10, borderRadius: 6, overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap' }}>{f.evidence.httpRequest}</pre>
                            </div>
                          )}
                          {f.evidence.httpResponse && (
                            <div style={{ marginBottom: 8 }}>
                              <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)', marginBottom: 4 }}>HTTP RESPONSE</div>
                              <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: '#f59e0b', background: '#0a0a0a', padding: 10, borderRadius: 6, overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap' }}>{f.evidence.httpResponse}</pre>
                            </div>
                          )}
                          {f.evidence.pocPayload && (
                            <div style={{ marginBottom: 8 }}>
                              <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)', marginBottom: 4 }}>PROOF OF CONCEPT</div>
                              <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: '#ef5a5a', background: '#0a0a0a', padding: 10, borderRadius: 6, overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap' }}>{f.evidence.pocPayload}</pre>
                            </div>
                          )}
                        </div>
                      )}

                      {/* MITRE Mapping */}
                      {f.mitreMapping.length > 0 && (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 8, fontFamily: 'var(--font-display)' }}>MITRE ATT&CK Mapping</div>
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                            {f.mitreMapping.map((m, i) => (
                              <span key={i} style={{ fontSize: 10, fontFamily: 'var(--font-mono)', padding: '4px 8px', borderRadius: 4, background: 'var(--color-bbrt-dim)', color: 'var(--color-bbrt)', border: '1px solid var(--color-bbrt)' }}>
                                {m.techniqueId} {m.techniqueName} ({m.confidence}%)
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Business Impact */}
                      <div style={{ marginBottom: 16, padding: 14, background: 'var(--color-bg-sunken)', borderRadius: 8 }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 8, fontFamily: 'var(--font-display)' }}>Business Impact</div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, fontSize: 11 }}>
                          <div><span style={{ color: 'var(--color-text-dim)' }}>Financial:</span> <span style={{ color: 'var(--color-sev-critical)', fontWeight: 600 }}>{f.businessImpact.financialEstimate}</span></div>
                          <div><span style={{ color: 'var(--color-text-dim)' }}>Records at Risk:</span> <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{f.businessImpact.dataRecordsAtRisk.toLocaleString()}</span></div>
                          <div><span style={{ color: 'var(--color-text-dim)' }}>Reputation:</span> <span style={{ fontWeight: 600, color: scoreColor(f.businessImpact.reputationalScore) }}>{f.businessImpact.reputationalScore}/100</span></div>
                        </div>
                        {f.businessImpact.operationalImpact && <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginTop: 8 }}>Operational: {f.businessImpact.operationalImpact}</div>}
                      </div>

                      {/* Remediation */}
                      <div>
                        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 8, fontFamily: 'var(--font-display)' }}>Remediation Steps</div>
                        <ol style={{ margin: 0, paddingLeft: 20 }}>
                          {f.remediationSteps.map((s, i) => (
                            <li key={i} style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 4 }}>{s}</li>
                          ))}
                        </ol>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ─── Tab: MITRE Heatmap ────────────────────────────────────── */}
          {tab === 'mitre' && (
            <div>
              <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginBottom: 20 }}>
                MITRE ATT&CK coverage for external attacker tactics. Red = vulnerability maps to this technique.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(${BBRT_MITRE_TACTICS.length}, 1fr)`, gap: 2 }}>
                {/* Header row */}
                {BBRT_MITRE_TACTICS.map(t => (
                  <div key={t.id} style={{ padding: '10px 4px', textAlign: 'center', fontSize: 9, fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-bbrt)', background: 'var(--color-bbrt-dim)', borderRadius: '6px 6px 0 0' }}>
                    {t.short}<br /><span style={{ fontSize: 8, color: 'var(--color-text-dim)' }}>{t.id}</span>
                  </div>
                ))}
                {/* Technique cells */}
                {BBRT_MITRE_TACTICS.map(tac => {
                  const mappings = findings.flatMap(f => f.mitreMapping).filter(m => m.tacticId === tac.id)
                  const uniqueTechniques = [...new Map(mappings.map(m => [m.techniqueId, m])).values()]
                  return (
                    <div key={`cells-${tac.id}`} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      {uniqueTechniques.length > 0 ? uniqueTechniques.map(m => (
                        <div key={m.techniqueId} style={{ padding: '6px 4px', textAlign: 'center', fontSize: 8, fontFamily: 'var(--font-mono)', background: 'rgba(239,90,90,0.15)', color: 'var(--color-sev-critical)', borderRadius: 4, border: '1px solid rgba(239,90,90,0.3)' }}>
                          {m.techniqueId}<br />{m.techniqueName.slice(0, 18)}
                        </div>
                      )) : (
                        <div style={{ padding: '6px 4px', textAlign: 'center', fontSize: 8, fontFamily: 'var(--font-mono)', background: 'var(--color-bg-sunken)', color: 'var(--color-text-dim)', borderRadius: 4 }}>—</div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* ─── Tab: Report ───────────────────────────────────────────── */}
          {tab === 'report' && report && (
            <div>
              {/* Risk Score Gauge */}
              <div style={{ display: 'flex', gap: 24, marginBottom: 28 }}>
                <div style={{ width: 120, height: 120, borderRadius: '50%', border: `5px solid ${riskColor(report.riskLevel)}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', flexShrink: 0 }}>
                  <div style={{ fontSize: 36, fontWeight: 700, color: riskColor(report.riskLevel), fontFamily: 'var(--font-display)' }}>{report.overallRiskScore}</div>
                  <div style={{ fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-mono)', color: riskColor(report.riskLevel) }}>{report.riskLevel}</div>
                </div>
                <div>
                  <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', margin: '0 0 8px' }}>Overall Risk Assessment</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                    {[
                      { l: 'Critical', v: report.findingStats.critical, c: SEV_COLOR.CRITICAL },
                      { l: 'High', v: report.findingStats.high, c: SEV_COLOR.HIGH },
                      { l: 'Medium', v: report.findingStats.medium, c: SEV_COLOR.MEDIUM },
                      { l: 'Low', v: report.findingStats.low, c: SEV_COLOR.LOW },
                    ].map(s => (
                      <div key={s.l} style={{ padding: '8px 12px', borderRadius: 6, background: 'var(--color-bg-sunken)', textAlign: 'center' }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color: s.c, fontFamily: 'var(--font-display)' }}>{s.v}</div>
                        <div style={{ fontSize: 9, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>{s.l.toUpperCase()}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Executive Summary */}
              <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, padding: 24, marginBottom: 24 }}>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-bbrt)', fontFamily: 'var(--font-display)', margin: '0 0 16px' }}>Executive Summary</h3>
                <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                  {report.executiveSummary.replace(/#{1,3}\s/g, '').replace(/\*\*/g, '')}
                </div>
              </div>

              {/* Compliance Gaps */}
              {report.complianceGaps.length > 0 && (
                <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden', marginBottom: 24 }}>
                  <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--color-border)' }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', margin: 0 }}>Compliance Gaps ({report.complianceGaps.length})</h3>
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: 'var(--color-bg-sunken)' }}>
                        {['Framework', 'Control', 'Status', 'Note'].map(h => (
                          <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{h.toUpperCase()}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {report.complianceGaps.map((g, i) => (
                        <tr key={i} style={{ borderTop: '1px solid var(--color-border)' }}>
                          <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-bbrt)' }}>{g.framework}</td>
                          <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>{g.controlId} — {g.controlName}</td>
                          <td style={{ padding: '10px 14px' }}><span style={{ padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)', background: g.status === 'FAIL' ? SEV_BG.CRITICAL : SEV_BG.MEDIUM, color: g.status === 'FAIL' ? SEV_COLOR.CRITICAL : SEV_COLOR.MEDIUM }}>{g.status}</span></td>
                          <td style={{ padding: '10px 14px', color: 'var(--color-text-secondary)', fontSize: 11 }}>{g.remediationNote}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Remediation Roadmap */}
              <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden', marginBottom: 24 }}>
                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--color-border)' }}>
                  <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)', margin: 0 }}>Remediation Roadmap</h3>
                </div>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ background: 'var(--color-bg-sunken)' }}>
                      {['#', 'Action', 'Effort', 'Impact', 'Hours'].map(h => (
                        <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{h.toUpperCase()}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {report.remediationRoadmap.map(r => (
                      <tr key={r.priority} style={{ borderTop: '1px solid var(--color-border)' }}>
                        <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--color-bbrt)', fontFamily: 'var(--font-mono)' }}>P{r.priority}</td>
                        <td style={{ padding: '10px 14px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{r.title}</div>
                          <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>{r.description.slice(0, 120)}...</div>
                        </td>
                        <td style={{ padding: '10px 14px' }}><span style={{ padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)', background: `${EFFORT_COLOR[r.effort]}15`, color: EFFORT_COLOR[r.effort] }}>{r.effort}</span></td>
                        <td style={{ padding: '10px 14px' }}><span style={{ padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)', background: `${IMPACT_COLOR[r.impact]}20`, color: IMPACT_COLOR[r.impact] }}>{r.impact}</span></td>
                        <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>{r.estimatedHours}h</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* AI Insights */}
              <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-bbrt)', borderRadius: 10, padding: 24 }}>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-bbrt)', fontFamily: 'var(--font-display)', margin: '0 0 16px' }}>AI Threat Intelligence (Claude Opus 4.6)</h3>
                <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                  {report.aiInsights.replace(/#{1,3}\s/g, '').replace(/\*\*/g, '')}
                </div>
              </div>
            </div>
          )}

          {/* Empty state for tabs when no data */}
          {tab === 'attack-surface' && !surface && (
            <div style={{ textAlign: 'center', padding: 48, color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 36, marginBottom: 12, opacity: 0.4 }}>🔍</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--font-display)' }}>Attack surface data not yet available</div>
              <div style={{ fontSize: 12, marginTop: 4 }}>Start the engagement to begin reconnaissance</div>
            </div>
          )}
          {tab === 'recon' && !recon && (
            <div style={{ textAlign: 'center', padding: 48, color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 36, marginBottom: 12, opacity: 0.4 }}>📡</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--font-display)' }}>Reconnaissance data not yet available</div>
            </div>
          )}
          {tab === 'report' && !report && (
            <div style={{ textAlign: 'center', padding: 48, color: 'var(--color-text-dim)' }}>
              <div style={{ fontSize: 36, marginBottom: 12, opacity: 0.4 }}>📋</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--font-display)' }}>Report not yet generated</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
