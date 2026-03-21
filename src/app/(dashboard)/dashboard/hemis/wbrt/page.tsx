'use client'

export default function WhiteBoxRedTeamingPage() {
  return (
    <div style={{ padding: 32 }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        marginBottom: 8,
      }}>
        <span style={{
          fontSize: 28,
          width: 48,
          height: 48,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--color-wbrt-dim)',
          borderRadius: 10,
          border: '1px solid var(--color-wbrt)',
        }}>◉</span>
        <div>
          <h1 style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--color-wbrt)',
            letterSpacing: '-0.02em',
            margin: 0,
            fontFamily: 'var(--font-display)',
          }}>WHITE BOX RED TEAMING</h1>
          <p style={{
            fontSize: 13,
            color: 'var(--color-text-secondary)',
            margin: 0,
            marginTop: 2,
          }}>Source-aware adversary simulation with full code &amp; architecture access</p>
        </div>
      </div>

      <div style={{
        borderBottom: '1px solid var(--color-border)',
        margin: '20px 0 28px',
      }} />

      {/* Coming Soon Card */}
      <div style={{
        background: 'var(--color-bg-elevated)',
        border: '1px solid var(--color-border)',
        borderRadius: 12,
        padding: '48px 32px',
        textAlign: 'center',
        maxWidth: 620,
      }}>
        <div style={{
          fontSize: 48,
          marginBottom: 16,
          opacity: 0.6,
        }}>🔬</div>
        <h2 style={{
          fontSize: 18,
          fontWeight: 600,
          color: 'var(--color-text-primary)',
          margin: '0 0 8px',
          fontFamily: 'var(--font-display)',
        }}>Coming Soon</h2>
        <p style={{
          fontSize: 14,
          color: 'var(--color-text-secondary)',
          margin: '0 0 24px',
          lineHeight: 1.6,
          maxWidth: 460,
          marginLeft: 'auto',
          marginRight: 'auto',
        }}>
          White Box Red Teaming performs adversary simulation with full access to source code,
          architecture diagrams, and internal documentation — mimicking an insider threat or
          a compromised developer account.
        </p>
        <div style={{
          display: 'flex',
          gap: 12,
          justifyContent: 'center',
          flexWrap: 'wrap',
        }}>
          {['Source Code Analysis', 'Architecture Review', 'Logic Flaw Discovery', 'Insider Threat Sim'].map(tag => (
            <span key={tag} style={{
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              padding: '5px 12px',
              borderRadius: 6,
              background: 'var(--color-wbrt-dim)',
              color: 'var(--color-wbrt)',
              border: '1px solid var(--color-wbrt)',
              opacity: 0.7,
              letterSpacing: '0.03em',
            }}>{tag}</span>
          ))}
        </div>
      </div>
    </div>
  )
}
