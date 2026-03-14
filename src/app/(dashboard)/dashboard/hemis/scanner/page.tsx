'use client'

import { useState } from 'react'
import { PRELOADED_SIMULATION } from '@/lib/mock-data/hemis'
import type { Finding } from '@/lib/types'

// Mock findings for demo
const MOCK_FINDINGS: Finding[] = [
  {
    id: 'find_001',
    type: 'sql_injection',
    severity: 'CRITICAL',
    cvssScore: 9.2,
    affectedComponent: 'POST /api/v1/login',
    description: 'SQL injection vulnerability in login endpoint. User input not sanitized in SQL query.',
    remediation: 'Use parameterized queries or prepared statements. Implement input validation.',
    proof_of_concept: "' OR '1'='1",
    detectedAt: '2026-03-14T10:30:00Z',
    mitreId: 'T1190',
    status: 'OPEN',
  },
  {
    id: 'find_002',
    type: 'exposed_aws_key',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    affectedComponent: 'S3 bucket: prod-config',
    description: 'AWS credentials exposed in publicly readable S3 bucket.',
    remediation: 'Rotate AWS keys immediately. Enable S3 bucket encryption and restrict access via IAM policies.',
    proof_of_concept: 'AWS_ACCESS_KEY_ID found in .env file',
    detectedAt: '2026-03-14T10:28:00Z',
    mitreId: 'T1552',
    status: 'OPEN',
  },
  {
    id: 'find_003',
    type: 'privilege_escalation',
    severity: 'CRITICAL',
    cvssScore: 9.5,
    affectedComponent: 'IAM policy: deploy-bot',
    description: 'Service account has AdministratorAccess policy, enabling full AWS account compromise.',
    remediation: 'Apply principle of least privilege. Restrict IAM permissions to only required services and actions.',
    proof_of_concept: 'Assume role deploy-bot and execute destructive AWS API calls',
    detectedAt: '2026-03-14T10:25:00Z',
    mitreId: 'T1068',
    status: 'OPEN',
  },
  {
    id: 'find_004',
    type: 'xss_vulnerability',
    severity: 'HIGH',
    cvssScore: 7.1,
    affectedComponent: 'POST /api/v1/feedback',
    description: 'Reflected XSS vulnerability. User input echoed back in HTML response without sanitization.',
    remediation: 'Sanitize all user inputs. Use HTML entity encoding. Implement Content Security Policy headers.',
    proof_of_concept: '<script>alert("XSS")</script>',
    detectedAt: '2026-03-14T10:20:00Z',
    mitreId: 'T1059',
    status: 'OPEN',
  },
  {
    id: 'find_005',
    type: 'auth_bypass',
    severity: 'HIGH',
    cvssScore: 8.2,
    affectedComponent: 'JWT token validation',
    description: 'JWT token signature verification disabled in development mode not removed in production.',
    remediation: 'Ensure JWT signature verification is always enabled. Remove all debug flags before deployment.',
    proof_of_concept: 'Modified JWT payload without valid signature accepted by API',
    detectedAt: '2026-03-14T10:15:00Z',
    mitreId: 'T1078',
    status: 'OPEN',
  },
]

interface Finding {
  id: string
  type: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  cvssScore: number
  affectedComponent: string
  description: string
  remediation: string
  proof_of_concept: string
  detectedAt: string
  mitreId: string
  status: 'OPEN' | 'ACKNOWLEDGED' | 'REMEDIATED'
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, { bg: string; color: string }> = {
    CRITICAL: { bg: 'var(--color-hemis)22', color: 'var(--color-hemis)' },
    HIGH: { bg: 'var(--color-hemis-orange)22', color: 'var(--color-hemis-orange)' },
    MEDIUM: { bg: 'var(--color-yellow)22', color: 'var(--color-yellow)' },
    LOW: { bg: 'var(--color-scanner)22', color: 'var(--color-scanner)' },
  }
  const style = colors[severity] || colors.LOW
  return (
    <div style={{
      display: 'inline-block',
      padding: '3px 8px',
      background: style.bg,
      border: `1px solid ${style.color}`,
      borderRadius: 0,
      fontSize: 9,
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      color: style.color,
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
    }}>
      {severity}
    </div>
  )
}

function CVSSScoreCard({ score }: { score: number }) {
  let color = 'var(--color-scanner)'
  if (score >= 9.0) color = 'var(--color-hemis)'
  else if (score >= 7.0) color = 'var(--color-hemis-orange)'
  else if (score >= 4.0) color = 'var(--color-yellow)'

  return (
    <div style={{
      display: 'inline-flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      width: 60,
      height: 60,
      background: 'var(--color-bg-elevated)',
      border: `2px solid ${color}`,
      borderRadius: 0,
    }}>
      <div className="mono" style={{ fontSize: 18, fontWeight: 700, color }}>{score.toFixed(1)}</div>
      <div className="mono" style={{ fontSize: 7, color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>CVSS</div>
    </div>
  )
}

export default function ScannerPage() {
  const [findings, setFindings] = useState<Finding[]>(MOCK_FINDINGS)
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState('')

  async function startScan() {
    if (!target.trim()) return
    setScanning(true)
    setScanProgress(0)

    for (let i = 0; i <= 100; i += 5) {
      setScanProgress(i)
      await new Promise(r => setTimeout(r, 100))
    }

    setScanning(false)
    setScanProgress(0)
  }

  const critical = findings.filter(f => f.severity === 'CRITICAL').length
  const high = findings.filter(f => f.severity === 'HIGH').length
  const medium = findings.filter(f => f.severity === 'MEDIUM').length
  const low = findings.filter(f => f.severity === 'LOW').length

  return (
    <div style={{ minHeight: '100vh', background: 'var(--color-bg-surface)' }}>
      {/* Header */}
      <div style={{
        padding: '20px 24px',
        borderBottom: '1px solid var(--color-border)',
        background: 'var(--color-bg-surface)',
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}>
        <div className="mono" style={{ fontSize: 10, color: 'var(--color-hemis)', letterSpacing: '0.15em', marginBottom: 4, textTransform: 'uppercase' }}>
          [ HEMIS VULNERABILITY SCANNER ]
        </div>
        <h1 className="display" style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
          Network Vulnerability Scan
        </h1>
        <p style={{ fontSize: 12, color: 'var(--color-text-dim)', margin: '6px 0 0' }}>
          Discover and analyze vulnerabilities in target systems
        </p>
      </div>

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 100px)' }}>
        {/* Left — Launcher */}
        <div style={{
          width: 320,
          flexShrink: 0,
          borderRight: '1px solid var(--color-border)',
          padding: '20px 18px',
          overflow: 'auto',
          background: 'var(--color-bg-surface)',
        }}>
          <div className="mono" style={{ fontSize: 9, letterSpacing: '0.15em', color: 'var(--color-hemis)', textTransform: 'uppercase', marginBottom: 12 }}>
            SCAN CONFIGURATION
          </div>

          <div style={{ marginBottom: 16 }}>
            <label className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 6, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Target URL
            </label>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="https://api.example.com"
              style={{
                width: '100%',
                padding: '8px 10px',
                background: 'var(--color-bg-elevated)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 6, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Scope (CIDR/domain list)
            </label>
            <textarea
              value={scope}
              onChange={e => setScope(e.target.value)}
              placeholder="10.0.0.0/8&#10;example.com"
              style={{
                width: '100%',
                padding: '8px 10px',
                background: 'var(--color-bg-elevated)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                boxSizing: 'border-box',
                resize: 'vertical',
                minHeight: 60,
              }}
            />
          </div>

          <button
            onClick={startScan}
            disabled={scanning || !target.trim()}
            style={{
              width: '100%',
              padding: '10px',
              background: scanning || !target.trim() ? 'var(--color-bg-elevated)' : 'var(--color-hemis)',
              color: scanning || !target.trim() ? 'var(--color-text-dim)' : '#ffffff',
              border: 'none',
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              cursor: scanning || !target.trim() ? 'not-allowed' : 'pointer',
              transition: 'all 0.12s',
            }}
          >
            {scanning ? `⊙ SCANNING ${scanProgress}%` : '▶ START SCAN'}
          </button>

          {scanning && (
            <div style={{ marginTop: 12, background: 'var(--color-hemis)15', border: '1px solid var(--color-hemis)33', padding: 10 }}>
              <div style={{ height: 4, background: 'var(--color-bg-elevated)', borderRadius: 2, overflow: 'hidden', marginBottom: 6 }}>
                <div style={{ height: '100%', background: 'var(--color-hemis)', width: `${scanProgress}%`, transition: 'width 0.1s' }} />
              </div>
              <div className="mono" style={{ fontSize: 9, color: 'var(--color-hemis)', letterSpacing: '0.08em' }}>
                Scanning in progress...
              </div>
            </div>
          )}
        </div>

        {/* Right — Results */}
        <div style={{ flex: 1, padding: '20px 24px', overflow: 'auto' }}>
          {/* Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
            {[
              { label: 'CRITICAL', count: critical, color: 'var(--color-hemis)' },
              { label: 'HIGH', count: high, color: 'var(--color-hemis-orange)' },
              { label: 'MEDIUM', count: medium, color: 'var(--color-yellow)' },
              { label: 'LOW', count: low, color: 'var(--color-scanner)' },
            ].map(stat => (
              <div key={stat.label} style={{
                padding: 12,
                background: `${stat.color}15`,
                border: `1px solid ${stat.color}33`,
                borderRadius: 0,
              }}>
                <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: stat.color, marginBottom: 4 }}>
                  {stat.count}
                </div>
                <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  {stat.label}
                </div>
              </div>
            ))}
          </div>

          {/* Findings Table */}
          <div style={{ marginBottom: 24 }}>
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 12, textTransform: 'uppercase' }}>
              FINDINGS ({findings.length})
            </div>
            {findings.map((finding, idx) => (
              <div key={finding.id} style={{
                background: 'var(--color-bg-elevated)',
                border: '1px solid var(--color-border)',
                padding: 14,
                marginBottom: 10,
                borderRadius: 0,
              }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', marginBottom: 10 }}>
                  <SeverityBadge severity={finding.severity} />
                  <div style={{ flex: 1 }}>
                    <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', margin: 0, marginBottom: 4 }}>
                      {finding.type.replace(/_/g, ' ').toUpperCase()}
                    </h3>
                    <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', marginBottom: 2 }}>
                      {finding.affectedComponent}
                    </div>
                    <div className="mono" style={{ fontSize: 9, color: 'var(--color-hemis-orange)', letterSpacing: '0.08em' }}>
                      {finding.mitreId}
                    </div>
                  </div>
                  <CVSSScoreCard score={finding.cvssScore} />
                </div>

                <p style={{ fontSize: 11, color: 'var(--color-text-secondary)', margin: '0 0 10px 0', lineHeight: 1.5 }}>
                  {finding.description}
                </p>

                <div style={{ marginBottom: 10 }}>
                  <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', marginBottom: 4, textTransform: 'uppercase' }}>
                    REMEDIATION
                  </div>
                  <p style={{ fontSize: 10, color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.5 }}>
                    {finding.remediation}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
