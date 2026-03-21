'use client'

export default function BlackBoxRedTeamingPage() {
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
          background: 'var(--color-bbrt-dim)',
          borderRadius: 10,
          border: '1px solid var(--color-bbrt)',
        }}>◌</span>
        <div>
          <h1 style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--color-bbrt)',
            letterSpacing: '-0.02em',
            margin: 0,
            fontFamily: 'var(--font-display)',
          }}>BLACK BOX RED TEAMING</h1>
          <p style={{
            fontSize: 13,
            color: 'var(--color-text-secondary)',
            margin: 0,
            marginTop: 2,
          }}>Zero-knowledge adversary simulation — attacking from the outside in</p>
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
        }}>🎯</div>
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
          Black Box Red Teaming simulates a real-world external attacker with zero prior knowledge
          of your systems — probing exposed surfaces, discovering attack paths, and chaining
          vulnerabilities just like a threat actor would.
        </p>
        <div style={{
          display: 'flex',
          gap: 12,
          justifyContent: 'center',
          flexWrap: 'wrap',
        }}>
          {['External Recon', 'Attack Surface Mapping', 'Exploit Chaining', 'Zero-Knowledge Testing'].map(tag => (
            <span key={tag} style={{
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              padding: '5px 12px',
              borderRadius: 6,
              background: 'var(--color-bbrt-dim)',
              color: 'var(--color-bbrt)',
              border: '1px solid var(--color-bbrt)',
              opacity: 0.7,
              letterSpacing: '0.03em',
            }}>{tag}</span>
          ))}
        </div>
      </div>
    </div>
  )
}
