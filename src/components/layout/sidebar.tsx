'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'

const PRODUCTS = [
  {
    id: 'scanner',
    label: 'CLOUD SCANNER',
    short: 'SCN',
    href: '/dashboard/scanner',
    color: 'var(--color-scanner)',
    dimColor: 'var(--color-scanner-dim)',
    icon: '◈',
    desc: 'Cloud Security Posture',
  },
  {
    id: 'hemis',
    label: 'HEMIS',
    short: 'RED',
    href: '/dashboard/hemis',
    color: 'var(--color-hemis)',
    dimColor: 'var(--color-hemis-dim)',
    icon: '◉',
    desc: 'AI Red Team Engine',
    tools: [
      { label: 'SAST', href: '/dashboard/hemis/sast', icon: '◇', desc: 'Static Code Analysis' },
      { label: 'DAST', href: '/dashboard/hemis/dast', icon: '◆', desc: 'Dynamic App Testing' },
    ],
  },
  {
    id: 'blueteam',
    label: 'BLUE TEAM',
    short: 'BLU',
    href: '/dashboard/blueteam',
    color: 'var(--color-blueteam)',
    dimColor: 'var(--color-blueteam-dim)',
    icon: '◎',
    desc: 'Threat Detection & Response',
  },
]

const NAV_ITEMS = [
  { label: 'OVERVIEW',   href: '/dashboard',          icon: '▦' },
  { label: 'REPORTS',    href: '/dashboard/reports',   icon: '▤' },
  { label: 'SETTINGS',   href: '/dashboard/settings',  icon: '◌' },
]

export default function Sidebar() {
  const path = usePathname()

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
          const isActive = path.startsWith(p.href)
          const isExactActive = path === p.href
          return (
            <div key={p.id}>
              <Link href={p.href} style={{ textDecoration:'none', display:'block', marginBottom:2 }}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '9px 10px',
                  borderRadius: 0,
                  border: isActive ? `1px solid ${p.color}22` : '1px solid transparent',
                  background: isActive ? `${p.color}10` : 'transparent',
                  transition: 'all 0.12s',
                  cursor: 'pointer',
                  position: 'relative',
                }}>
                  {/* Active stripe */}
                  {isActive && (
                    <div style={{
                      position:'absolute', left:0, top:0, bottom:0, width:2,
                      background: p.color,
                    }} />
                  )}
                  <span style={{ fontSize:14, color: isActive ? p.color : 'var(--color-text-dim)', lineHeight:1, flexShrink:0 }}>
                    {p.icon}
                  </span>
                  <div style={{ minWidth:0, flex:1 }}>
                    <div className="mono" style={{
                      fontSize:11, fontWeight:600,
                      letterSpacing:'0.1em',
                      color: isActive ? p.color : 'var(--color-text-secondary)',
                      textTransform:'uppercase',
                    }}>
                      {p.label}
                    </div>
                    <div style={{
                      fontSize:11,
                      color: isActive ? 'var(--color-text-secondary)' : 'var(--color-text-dim)',
                      marginTop:1,
                    }}>
                      {p.desc}
                    </div>
                  </div>
                  {isActive && (
                    <span className="dot-live" style={{
                      width:5, height:5, flexShrink:0,
                      background: p.color, boxShadow:`0 0 4px ${p.color}`,
                    }} />
                  )}
                </div>
              </Link>

              {/* Sub-tools (nested under product when active) */}
              {'tools' in p && p.tools && isActive && (
                <div style={{ paddingLeft: 20, marginBottom: 4 }}>
                  {p.tools.map(tool => {
                    const isToolActive = path === tool.href
                    return (
                      <Link key={tool.href} href={tool.href} style={{ textDecoration:'none', display:'block' }}>
                        <div style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          padding: '6px 10px',
                          borderLeft: isToolActive ? `2px solid ${p.color}` : '2px solid transparent',
                          background: isToolActive ? `${p.color}12` : 'transparent',
                          transition: 'all 0.12s',
                          cursor: 'pointer',
                          marginTop: 2,
                        }}>
                          <span style={{ fontSize:11, color: isToolActive ? p.color : 'var(--color-text-dim)', lineHeight:1, flexShrink:0 }}>
                            {tool.icon}
                          </span>
                          <div style={{ minWidth:0, flex:1 }}>
                            <div className="mono" style={{
                              fontSize:10, fontWeight:600,
                              letterSpacing:'0.08em',
                              color: isToolActive ? p.color : 'var(--color-text-secondary)',
                              textTransform:'uppercase',
                            }}>
                              {tool.label}
                            </div>
                            <div style={{
                              fontSize:10,
                              color: isToolActive ? 'var(--color-text-secondary)' : 'var(--color-text-dim)',
                              marginTop:1,
                            }}>
                              {tool.desc}
                            </div>
                          </div>
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
