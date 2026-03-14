'use client'

import { useState } from 'react'

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
    status: 'ACKNOWLEDGED',
  },
  {
    id: 'find_006',
    type: 'weak_encryption',
    severity: 'MEDIUM',
    cvssScore: 5.3,
    affectedComponent: 'Database encryption',
    description: 'Database uses deprecated MD5 hashing for passwords instead of bcrypt.',
    remediation: 'Migrate to bcrypt or Argon2. Use salt with appropriate work factor.',
    proof_of_concept: 'Rainbow table attack on extracted password hashes',
    detectedAt: '2026-03-14T10:10:00Z',
    mitreId: 'T1110',
    status: 'IN_PROGRESS',
  },
]

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

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    OPEN: 'var(--color-hemis)',
    ACKNOWLEDGED: 'var(--color-hemis-orange)',
    IN_PROGRESS: 'var(--color-yellow)',
    REMEDIATED: 'var(--color-scanner)',
  }
  const color = colors[status] || 'var(--color-text-dim)'
  return (
    <div style={{
      display: 'inline-block',
      padding: '2px 6px',
      background: `${color}15`,
      border: `1px solid ${color}44`,
      fontSize: 8,
      fontFamily: 'var(--font-mono)',
      fontWeight: 500,
      color,
      textTransform: 'uppercase',
      letterSpacing: '0.06em',
    }}>
      {status}
    </div>
  )
}

export default function FindingsPage() {
  const [findings] = useState<Finding[]>(MOCK_FINDINGS)
  const [filter, setFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL')

  const filtered = filter === 'ALL' ? findings : findings.filter(f => f.severity === filter)

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
          [ HEMIS FINDINGS DATABASE ]
        </div>
        <h1 className="display" style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
          All Findings
        </h1>
        <p style={{ fontSize: 12, color: 'var(--color-text-dim)', margin: '6px 0 0' }}>
          Discovered vulnerabilities across all scans and assessments
        </p>
      </div>

      {/* Filter Bar */}
      <div style={{
        padding: '16px 24px',
        background: 'var(--color-bg-surface)',
        borderBottom: '1px solid var(--color-border)',
        display: 'flex',
        gap: 8,
        alignItems: 'center',
        flexWrap: 'wrap',
        position: 'sticky',
        top: 100,
        zIndex: 9,
      }}>
        <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginRight: 8 }}>
          Filter by Severity:
        </div>
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => {
          const colors: Record<string, string> = {
            ALL: 'var(--color-text-secondary)',
            CRITICAL: 'var(--color-hemis)',
            HIGH: 'var(--color-hemis-orange)',
            MEDIUM: 'var(--color-yellow)',
            LOW: 'var(--color-scanner)',
          }
          const isActive = filter === sev
          return (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              style={{
                padding: '6px 12px',
                background: isActive ? `${colors[sev]}22` : 'transparent',
                border: isActive ? `1px solid ${colors[sev]}` : '1px solid var(--color-border)',
                color: isActive ? colors[sev] : 'var(--color-text-secondary)',
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                fontWeight: 600,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                cursor: 'pointer',
                transition: 'all 0.12s',
              }}
            >
              {sev}
            </button>
          )
        })}
      </div>

      <div style={{ padding: '20px 24px' }}>
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
        <div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 12, textTransform: 'uppercase' }}>
            FINDINGS ({filtered.length})
          </div>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse',
            background: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-border)',
            borderRadius: 0,
          }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-bg-surface)' }}>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: 9, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Severity</th>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: 9, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Type</th>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: 9, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Component</th>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: 9, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>CVSS</th>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: 9, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>MITRE</th>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: 9, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((finding, idx) => (
                <tr key={finding.id} style={{
                  borderBottom: idx < filtered.length - 1 ? '1px solid var(--color-border)' : 'none',
                  background: finding.severity === 'CRITICAL' ? 'var(--color-hemis)08' : 'transparent',
                }}>
                  <td style={{ padding: '12px 14px' }}>
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 11, color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {finding.type.replace(/_/g, ' ')}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 11, color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {finding.affectedComponent}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 11, color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                    {finding.cvssScore.toFixed(1)}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 11, color: 'var(--color-hemis-orange)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                    {finding.mitreId}
                  </td>
                  <td style={{ padding: '12px 14px' }}>
                    <StatusBadge status={finding.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Export Section */}
        <div style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--color-border)' }}>
          <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em', marginBottom: 12, textTransform: 'uppercase' }}>
            Export Options
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button style={{
              padding: '8px 14px',
              background: 'var(--color-bg-elevated)',
              border: '1px solid var(--color-border)',
              color: 'var(--color-text-secondary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              fontWeight: 600,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              transition: 'all 0.12s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--color-hemis)'
              e.currentTarget.style.color = 'var(--color-hemis)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--color-border)'
              e.currentTarget.style.color = 'var(--color-text-secondary)'
            }}
            >
              ▼ Export CSV
            </button>
            <button style={{
              padding: '8px 14px',
              background: 'var(--color-bg-elevated)',
              border: '1px solid var(--color-border)',
              color: 'var(--color-text-secondary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              fontWeight: 600,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              transition: 'all 0.12s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--color-hemis)'
              e.currentTarget.style.color = 'var(--color-hemis)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--color-border)'
              e.currentTarget.style.color = 'var(--color-text-secondary)'
            }}
            >
              ▼ Export JSON
            </button>
            <button style={{
              padding: '8px 14px',
              background: 'var(--color-bg-elevated)',
              border: '1px solid var(--color-border)',
              color: 'var(--color-text-secondary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              fontWeight: 600,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              transition: 'all 0.12s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--color-hemis)'
              e.currentTarget.style.color = 'var(--color-hemis)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--color-border)'
              e.currentTarget.style.color = 'var(--color-text-secondary)'
            }}
            >
              📄 Export PDF
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
