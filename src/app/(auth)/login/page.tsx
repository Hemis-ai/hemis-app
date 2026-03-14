'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const [scanLine, setScanLine] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!email || !password) { setError('CREDENTIALS REQUIRED'); return }
    setError('')
    setLoading(true)
    setScanLine(true)
    // Simulate auth delay
    await new Promise(r => setTimeout(r, 1400))
    router.push('/dashboard')
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center tac-grid"
      style={{ background: 'var(--color-bg-base)' }}
    >
      {/* Ambient glow */}
      <div style={{
        position: 'fixed', inset: 0, pointerEvents: 'none',
        background: 'radial-gradient(ellipse 800px 500px at 50% 40%, rgba(255,225,124,0.04) 0%, transparent 70%)',
      }} />

      <div style={{ width: '100%', maxWidth: 460, padding: '0 24px' }}>

        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <div style={{ display:'inline-flex', alignItems:'center', gap:10, marginBottom:8 }}>
            <span style={{ fontSize:30 }}>⚡</span>
            <span className="display" style={{ fontSize:24, fontWeight:700, color:'var(--color-text-primary)', letterSpacing:'-0.03em' }}>
              HemisX
            </span>
          </div>
          <div className="mono" style={{ fontSize:11, letterSpacing:'0.18em', color:'var(--color-text-secondary)', textTransform:'uppercase' }}>
            Security Console · console.hemisx.com
          </div>
        </div>

        {/* Card */}
        <div className="bracket-card" style={{ padding: '36px 30px', position:'relative', overflow:'hidden' }}>
          {/* Scan line animation during auth */}
          {scanLine && <div className="scan-line" style={{ animationDuration:'1.2s' }} />}

          {/* Header */}
          <div style={{ marginBottom:30 }}>
            <div className="mono" style={{ fontSize:11, letterSpacing:'0.16em', color:'var(--color-yellow)', textTransform:'uppercase', marginBottom:8 }}>
              [ AUTHENTICATE ]
            </div>
            <h1 className="display" style={{ fontSize:22, fontWeight:700, color:'var(--color-text-primary)', margin:0 }}>
              Sign in to your workspace
            </h1>
          </div>

          <form onSubmit={handleSubmit} style={{ display:'flex', flexDirection:'column', gap:16 }}>
            {/* Email */}
            <div>
              <label className="mono" style={{ display:'block', fontSize:11, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:6 }}>
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="tac-input"
                style={{ display:'block' }}
                autoComplete="email"
              />
            </div>

            {/* Password */}
            <div>
              <label className="mono" style={{ display:'block', fontSize:11, letterSpacing:'0.12em', color:'var(--color-text-secondary)', textTransform:'uppercase', marginBottom:6 }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="tac-input"
                style={{ display:'block' }}
                autoComplete="current-password"
              />
            </div>

            {/* Error */}
            {error && (
              <div className="mono" style={{ fontSize:12, color:'var(--color-hemis)', letterSpacing:'0.08em' }}>
                ✕ {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              style={{
                marginTop:8,
                background: loading ? 'var(--color-bg-elevated)' : 'var(--color-yellow)',
                color: loading ? 'var(--color-text-dim)' : '#0a0d0f',
                border: 'none',
                padding: '13px 0',
                width: '100%',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                fontWeight: 600,
                letterSpacing: '0.12em',
                textTransform: 'uppercase',
                transition: 'all 0.15s',
                position: 'relative',
                overflow: 'hidden',
              }}
            >
              {loading ? (
                <span style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:8 }}>
                  <span className="dot-live yellow" />
                  AUTHENTICATING...
                </span>
              ) : (
                'AUTHENTICATE →'
              )}
            </button>
          </form>

          {/* Divider */}
          <div style={{ margin:'26px 0', borderTop:'1px solid var(--color-border)' }} />

          {/* Demo hint */}
          <div className="mono" style={{ fontSize:12, color:'var(--color-text-secondary)', textAlign:'center', lineHeight:1.8 }}>
            Demo mode — any credentials will work<br/>
          <span style={{ color:'var(--color-text-primary)' }}>demo@hemisx.com</span>
          </div>
        </div>

        {/* Footer */}
        <div className="mono" style={{ textAlign:'center', marginTop:28, fontSize:12, color:'var(--color-text-secondary)', letterSpacing:'0.1em' }}>
          © 2026 HemisX · console.hemisx.com · TLS 1.3 ENCRYPTED
        </div>
      </div>
    </div>
  )
}
