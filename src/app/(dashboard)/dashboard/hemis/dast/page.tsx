'use client'

export default function DastPage() {
  return (
    <div style={{ padding: '40px 32px', maxWidth: 900 }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <span style={{ fontSize: 24 }}>◆</span>
          <h1 className="display" style={{
            fontSize: 24, fontWeight: 700, color: 'var(--color-hemis)',
            letterSpacing: '-0.02em', margin: 0,
          }}>
            DAST
          </h1>
          <span className="mono" style={{
            fontSize: 10, padding: '2px 8px',
            border: '1px solid var(--color-hemis)',
            color: 'var(--color-hemis)',
            letterSpacing: '0.1em', fontWeight: 600,
          }}>
            COMING SOON
          </span>
        </div>
        <p style={{ fontSize: 14, color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.6 }}>
          Dynamic Application Security Testing — actively probe running web applications
          for vulnerabilities including XSS, SQL injection, CORS misconfigurations, broken
          authentication, and more.
        </p>
      </div>

      {/* Feature preview cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 32 }}>
        {[
          { title: 'URL Crawler', desc: 'Discover endpoints, forms, and API routes automatically by crawling your target application.', icon: '🔗' },
          { title: 'Active Scanning', desc: 'Probe endpoints with XSS, SQLi, command injection, and SSRF payloads in a controlled environment.', icon: '⚡' },
          { title: 'Auth Testing', desc: 'Detect broken authentication, session fixation, privilege escalation, and insecure password policies.', icon: '🔐' },
          { title: 'Security Headers', desc: 'Audit HTTP headers — CSP, HSTS, X-Frame-Options, CORS, cookie flags, and more.', icon: '🛡' },
          { title: 'API Fuzzing', desc: 'Fuzz REST and GraphQL APIs with malformed inputs to find crashes, leaks, and logic bugs.', icon: '🧪' },
          { title: 'Unified Reports', desc: 'Findings merge with SAST results into a single report with OWASP mapping and remediation guides.', icon: '📊' },
        ].map(card => (
          <div key={card.title} style={{
            padding: '20px', border: '1px solid var(--color-border)',
            background: 'var(--color-bg-surface)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: 16 }}>{card.icon}</span>
              <span className="mono" style={{
                fontSize: 11, fontWeight: 600, color: 'var(--color-text-primary)',
                letterSpacing: '0.06em',
              }}>
                {card.title}
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--color-text-dim)', margin: 0, lineHeight: 1.5 }}>
              {card.desc}
            </p>
          </div>
        ))}
      </div>

      {/* Placeholder box */}
      <div style={{
        border: '2px dashed var(--color-border)',
        padding: '48px 32px',
        textAlign: 'center',
        background: 'var(--color-bg-base)',
      }}>
        <div style={{ fontSize: 40, marginBottom: 12, opacity: 0.3 }}>◆</div>
        <div className="mono" style={{
          fontSize: 13, color: 'var(--color-text-secondary)',
          letterSpacing: '0.1em', marginBottom: 8,
        }}>
          DAST MODULE IN DEVELOPMENT
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-dim)', maxWidth: 400, margin: '0 auto', lineHeight: 1.5 }}>
          This module will allow you to scan live web applications for security vulnerabilities.
          Enter a target URL, configure scan scope, and receive findings mapped to OWASP Top 10.
        </div>
      </div>
    </div>
  )
}
