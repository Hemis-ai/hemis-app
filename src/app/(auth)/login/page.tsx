'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Zap, Loader2 } from 'lucide-react'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!email || !password) { setError('Email and password are required'); return }
    setError('')
    setLoading(true)
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

      <div style={{ width: '100%', maxWidth: 440, padding: '0 24px' }}>

        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            <div style={{
              width: 36, height: 36, background: 'var(--color-yellow)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Zap size={18} color="#0a0d0f" strokeWidth={2.5} />
            </div>
            <span className="display" style={{ fontSize: 24, fontWeight: 700, color: 'var(--color-text-primary)', letterSpacing: '-0.03em' }}>
              HemisX
            </span>
          </div>
          <div style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>
            Security Console · console.hemisx.com
          </div>
        </div>

        {/* Card */}
        <div className="bracket-card" style={{ padding: '32px 28px', position: 'relative', overflow: 'hidden' }}>
          {/* Scan line animation during auth */}
          {loading && <div className="scan-line" style={{ animationDuration: '1.2s' }} />}

          {/* Header */}
          <div style={{ marginBottom: 24 }}>
            <div className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', color: 'var(--color-yellow)', textTransform: 'uppercase', marginBottom: 8 }}>
              Authenticate
            </div>
            <h1 className="display" style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
              Sign in to your workspace
            </h1>
          </div>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* Email */}
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--color-text-secondary)', marginBottom: 6 }}>
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="tac-input"
                style={{ display: 'block', borderRadius: 4 }}
                autoComplete="email"
              />
            </div>

            {/* Password */}
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--color-text-secondary)', marginBottom: 6 }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="tac-input"
                style={{ display: 'block', borderRadius: 4 }}
                autoComplete="current-password"
              />
            </div>

            {/* Error */}
            {error && (
              <div style={{ fontSize: 12, color: 'var(--color-hemis)', padding: '8px 12px', background: 'var(--color-hemis-dim)', border: '1px solid var(--color-hemis)', borderRadius: 4 }}>
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              style={{
                marginTop: 4,
                background: loading ? 'var(--color-bg-elevated)' : 'var(--color-yellow)',
                color: loading ? 'var(--color-text-dim)' : '#0a0d0f',
                border: '1px solid transparent',
                borderColor: loading ? 'var(--color-border)' : 'var(--color-yellow)',
                padding: '12px 0',
                width: '100%',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-sans)',
                fontSize: 14,
                fontWeight: 600,
                letterSpacing: '0.02em',
                borderRadius: 4,
                transition: 'all 0.15s',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 8,
              }}
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="spin" />
                  Authenticating…
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Divider */}
          <div style={{ margin: '22px 0', borderTop: '1px solid var(--color-border)' }} />

          {/* Demo hint */}
          <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', textAlign: 'center', lineHeight: 1.8 }}>
            Demo mode — any credentials will work<br />
            <span style={{ color: 'var(--color-text-primary)', fontWeight: 500 }}>demo@hemisx.com</span>
          </div>
        </div>

        {/* Footer */}
        <div style={{ textAlign: 'center', marginTop: 24, fontSize: 11, color: 'var(--color-text-dim)' }}>
          © 2026 HemisX · console.hemisx.com · TLS 1.3
        </div>
      </div>
    </div>
  )
}
