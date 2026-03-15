'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState } from 'react'

// ── Feature flags (set via env vars, default ON in dev) ──────────────────────
const FF = {
  sast:      process.env.NEXT_PUBLIC_FEATURE_SAST      !== 'false',
  dast:      process.env.NEXT_PUBLIC_FEATURE_DAST      !== 'false',
  blueteam:  process.env.NEXT_PUBLIC_FEATURE_BLUETEAM  !== 'false',
  scanner:   process.env.NEXT_PUBLIC_FEATURE_SCANNER   !== 'false',
}

const PRODUCTS = [
  ...(FF.scanner ? [{
    id: 'scanner',
    label: 'CLOUD SCANNER',
    href: '/dashboard/scanner',
    color: 'var(--color-scanner)',
    icon: '◈',
  }] : []),
  {
    id: 'hemis',
    label: 'HEMIS',
    href: '/dashboard/hemis',
    color: 'var(--color-hemis)',
    icon: '◉',
    children: [
      ...(FF.sast ? [{ id: 'sast', label: 'SAST', href: '/dashboard/hemis/sast', icon: '⬡', color: 'var(--color-hemis)' }] : []),
      ...(FF.dast ? [{ id: 'dast', label: 'DAST', href: '/dashboard/hemis/dast', icon: '◇', color: 'var(--color-dast)' }] : []),
    ],
  },
  ...(FF.blueteam ? [{
    id: 'blueteam',
    label: 'BLUE TEAM',
    href: '/dashboard/blueteam',
    color: 'var(--color-blueteam)',
    icon: '◎',
  }] : []),
]

const NAV_ITEMS = [
  { label: 'OVERVIEW',   href: '/dashboard',          icon: '▦' },
  { label: 'REPORTS',    href: '/dashboard/reports',   icon: '▤' },
  { label: 'SETTINGS',   href: '/dashboard/settings',  icon: '◌' },
]

export default function Sidebar() {
  const path = usePathname()
  const [hemisExpanded, setHemisExpanded] = useState(
    path.startsWith('/dashboard/hemis')
  )

  const activeProduct = PRODUCTS.find(p => path.startsWith(p.href))

  return (
    <aside style={{
      width: 236,
      minWidth: 236,
      background: 'var(--color-bg-surface)',
      borderRight: '1px solid var(--color-border)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: 'sticky',
      top: 0,
      flexShrink: 0,
    }}>

      {/* Logo */}
      <div style={{
        padding: '22px 18px 18px',
        borderBottom: '1px solid var(--color-border)',
      }}>
        <Link href="/dashboard" style={{ textDecoration:'none', display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ fontSize:20 }}>⚡</span>
          <span className="display" style={{ fontSize:16, fontWeight:700, color:'var(--color-text-primary)', letterSpacing:'-0.02em' }}>
            HemisX
          </span>
          <span className="mono" style={{ fontSize:10, color:'var(--color-text-secondary)', letterSpacing:'0.12em', marginLeft:2 }}>
            CONSOLE
          </span>
        </Link>
        {/* Uptime indicator */}
        <div style={{ marginTop:10, display:'flex', alignItems:'center', gap:6 }}>
          <span className="dot-live" style={{ width:5, height:5 }} />
          <span className="mono" style={{ fontSize:10, color:'var(--color-text-dim)', letterSpacing:'0.08em' }}>
            ALL SYSTEMS OPERATIONAL
          </span>
        </div>
      </div>

      {/* Products */}
      <div style={{ padding:'18px 12px 10px', overflowY:'auto', flex:1 }}>
        <div className="mono" style={{ fontSize:10, letterSpacing:'0.15em', color:'var(--color-text-dim)', textTransform:'uppercase', padding:'0 6px', marginBottom:8 }}>
          Products
        </div>
        {PRODUCTS.map(p => {
          const isActive = path.startsWith(p.href) ||
            (p.children?.some(c => path.startsWith(c.href)) ?? false)
          const hasChildren = p.children && p.children.length > 0

          return (
            <div key={p.id}>
              {/* Parent item */}
              <div
                style={{ display:'flex', alignItems:'center', marginBottom:2, cursor:'pointer' }}
              >
                <Link
                  href={p.href}
                  style={{ textDecoration:'none', display:'flex', alignItems:'center', gap:8, flex:1, padding:'8px 8px' }}
                  onClick={() => { if (hasChildren) setHemisExpanded(true) }}
                >
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    flex: 1,
                    position: 'relative',
                  }}>
                    {isActive && (
                      <div style={{
                        position:'absolute', left:-8, top:-8, bottom:-8, width:2,
                        background: p.color,
                      }} />
                    )}
                    <span style={{ fontSize:13, color: isActive ? p.color : 'var(--color-text-dim)', lineHeight:1, flexShrink:0 }}>
                      {p.icon}
                    </span>
                    <div className="mono" style={{
                      fontSize:9, fontWeight:700,
                      letterSpacing:'0.08em',
                      color: isActive ? p.color : 'var(--color-text-secondary)',
                      textTransform:'uppercase',
                      flex: 1,
                    }}>
                      {p.label}
                    </div>
                    {hasChildren && (
                      <span
                        className="mono"
                        onClick={e => { e.preventDefault(); e.stopPropagation(); setHemisExpanded(!hemisExpanded) }}
                        style={{ fontSize:8, color:'var(--color-text-dim)', transition:'transform 0.15s', transform: hemisExpanded ? 'rotate(90deg)' : 'rotate(0deg)', padding:'2px 4px', cursor:'pointer' }}
                      >
                        ▸
                      </span>
                    )}
                  </div>
                </Link>
              </div>

              {/* Children (sub-products) */}
              {hasChildren && hemisExpanded && (
                <div style={{ paddingLeft:20, marginBottom:4 }}>
                  {p.children!.map(child => {
                    const childActive = path.startsWith(child.href)
                    return (
                      <Link key={child.id} href={child.href} style={{ textDecoration:'none', display:'block', marginBottom:1 }}>
                        <div style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          padding: '5px 8px',
                          background: childActive ? `${child.color}10` : 'transparent',
                          border: childActive ? `1px solid ${child.color}22` : '1px solid transparent',
                          transition: 'all 0.12s',
                          position: 'relative',
                        }}>
                          {childActive && (
                            <div style={{
                              position:'absolute', left:0, top:0, bottom:0, width:2,
                              background: child.color,
                            }} />
                          )}
                          <span style={{ fontSize:10, color: childActive ? child.color : 'var(--color-text-dim)', lineHeight:1 }}>
                            {child.icon}
                          </span>
                          <span className="mono" style={{
                            fontSize:8, fontWeight:600,
                            letterSpacing:'0.08em',
                            color: childActive ? child.color : 'var(--color-text-dim)',
                            textTransform:'uppercase',
                          }}>
                            {child.label}
                          </span>
                        </div>
                      </Link>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}

        {/* Divider */}
        <div style={{ margin:'12px 4px 8px', borderTop:'1px solid var(--color-border)' }} />

        {/* Nav */}
        <div className="mono" style={{ fontSize:10, letterSpacing:'0.15em', color:'var(--color-text-dim)', textTransform:'uppercase', padding:'0 6px', marginBottom:8 }}>
          Navigation
        </div>
        {NAV_ITEMS.map(item => {
          const isActive = path === item.href
          return (
            <Link key={item.href} href={item.href} style={{ textDecoration:'none', display:'block', marginBottom:2 }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 10px',
                background: isActive ? 'var(--color-bg-elevated)' : 'transparent',
                border: isActive ? '1px solid var(--color-border-bright)' : '1px solid transparent',
                transition: 'all 0.12s',
              }}>
                <span style={{ fontSize:12, color: isActive ? 'var(--color-yellow)' : 'var(--color-text-dim)' }}>
                  {item.icon}
                </span>
                <span className="mono" style={{
                  fontSize:11,
                  fontWeight: 600,
                  letterSpacing:'0.1em',
                  textTransform:'uppercase',
                  color: isActive ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
                }}>
                  {item.label}
                </span>
              </div>
            </Link>
          )
        })}
      </div>

      {/* Bottom — user */}
      <div style={{
        padding:'14px 18px',
        borderTop:'1px solid var(--color-border)',
        display:'flex',
        alignItems:'center',
        gap:10,
      }}>
        <div style={{
          width:30, height:30, borderRadius:'50%',
          background:'var(--color-yellow-dim)',
          border:'1px solid var(--color-yellow)',
          display:'flex', alignItems:'center', justifyContent:'center',
          flexShrink:0,
        }}>
          <span style={{ fontSize:12, color:'var(--color-yellow)', fontWeight:700 }}>A</span>
        </div>
        <div style={{ minWidth:0, flex:1 }}>
          <div style={{ fontSize:13, fontWeight:500, color:'var(--color-text-primary)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
            Alex M.
          </div>
          <div className="mono" style={{ fontSize:10, color:'var(--color-text-dim)', letterSpacing:'0.06em' }}>
            Security Engineer
          </div>
        </div>
        <Link href="/login" style={{ textDecoration:'none' }}>
          <span className="mono" style={{ fontSize:10, color:'var(--color-text-dim)', letterSpacing:'0.08em', cursor:'pointer' }}>
            ⎋
          </span>
        </Link>
      </div>
    </aside>
  )
}
