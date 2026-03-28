'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState } from 'react'
import {
  Cloud, Shield, Code2, Globe, Eye, Scan, ShieldCheck,
  LayoutDashboard, FileText, Settings, ChevronRight,
  Zap, LogOut, Monitor, Workflow, Layers,
} from 'lucide-react'

// ── Feature flags ─────────────────────────────────────────────────────────────
const FF = {
  sast:     process.env.NEXT_PUBLIC_FEATURE_SAST     !== 'false',
  dast:     process.env.NEXT_PUBLIC_FEATURE_DAST     !== 'false',
  wbrt:     process.env.NEXT_PUBLIC_FEATURE_WBRT     !== 'false',
  bbrt:     process.env.NEXT_PUBLIC_FEATURE_BBRT     !== 'false',
  blueteam: process.env.NEXT_PUBLIC_FEATURE_BLUETEAM !== 'false',
  scanner:  process.env.NEXT_PUBLIC_FEATURE_SCANNER  !== 'false',
  xdr:      process.env.NEXT_PUBLIC_FEATURE_XDR      !== 'false',
  soar:     process.env.NEXT_PUBLIC_FEATURE_SOAR     !== 'false',
  dect:     process.env.NEXT_PUBLIC_FEATURE_DECT     !== 'false',
}

const PRODUCTS = [
  ...(FF.scanner ? [{
    id: 'scanner',
    label: 'Cloud Scanner',
    href: '/dashboard/scanner',
    color: 'var(--color-scanner)',
    Icon: Cloud,
    children: undefined as undefined,
  }] : []),
  {
    id: 'hemis',
    label: 'HEMIS',
    href: '/dashboard/hemis',
    color: 'var(--color-hemis)',
    Icon: Shield,
    children: [
      ...(FF.sast ? [{ id: 'sast', label: 'SAST',         href: '/dashboard/hemis/sast', Icon: Code2,  color: 'var(--color-sast)' }] : []),
      ...(FF.dast ? [{ id: 'dast', label: 'DAST',         href: '/dashboard/hemis/dast', Icon: Globe,  color: 'var(--color-dast)' }] : []),
      ...(FF.wbrt ? [{ id: 'wbrt', label: 'White Box RT', href: '/dashboard/hemis/wbrt', Icon: Eye,    color: 'var(--color-wbrt)' }] : []),
      ...(FF.bbrt ? [{ id: 'bbrt', label: 'Black Box RT', href: '/dashboard/hemis/bbrt', Icon: Scan,   color: 'var(--color-bbrt)' }] : []),
    ],
  },
  ...(FF.blueteam ? [{
    id: 'blueteam',
    label: 'Blue Team',
    href: '/dashboard/blueteam',
    color: 'var(--color-blueteam)',
    Icon: ShieldCheck,
    children: [
      ...(FF.xdr  ? [{ id: 'xdr',  label: 'XDR',  href: '/dashboard/blueteam/xdr',  Icon: Monitor,  color: 'var(--color-xdr)'  }] : []),
      ...(FF.soar ? [{ id: 'soar', label: 'SOAR', href: '/dashboard/blueteam/soar', Icon: Workflow, color: 'var(--color-soar)' }] : []),
      ...(FF.dect ? [{ id: 'dect', label: 'DECT', href: '/dashboard/blueteam/dect', Icon: Layers,   color: 'var(--color-dect)' }] : []),
    ],
  }] : []),
]

const NAV_ITEMS = [
  { label: 'Overview',  href: '/dashboard',          Icon: LayoutDashboard },
  { label: 'Reports',   href: '/dashboard/reports',  Icon: FileText },
  { label: 'Settings',  href: '/dashboard/settings', Icon: Settings },
]

export default function Sidebar() {
  const path = usePathname()
  const [hemisExpanded, setHemisExpanded] = useState(
    path.startsWith('/dashboard/hemis')
  )
  const [blueteamExpanded, setBlueteamExpanded] = useState(
    path.startsWith('/dashboard/blueteam')
  )

  return (
    <aside style={{
      width: 240,
      minWidth: 240,
      background: 'var(--color-bg-surface)',
      borderRight: '1px solid var(--color-border)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: 'sticky',
      top: 0,
      flexShrink: 0,
    }}>

      {/* ── Logo ── */}
      <div style={{ padding: '18px 16px 16px', borderBottom: '1px solid var(--color-border)' }}>
        <Link href="/dashboard" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32, height: 32,
            background: '#0a0d0f',
            borderRadius: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Zap size={16} color="#ffffff" strokeWidth={2.5} />
          </div>
          <div>
            <div className="display" style={{ fontSize: 15, fontWeight: 700, color: 'var(--color-text-primary)', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
              HemisX
            </div>
            <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.14em', textTransform: 'uppercase' }}>
              Console
            </div>
          </div>
        </Link>
      </div>

      {/* ── Navigation ── */}
      <div style={{ padding: '10px 8px', overflowY: 'auto', flex: 1 }}>

        {/* Products */}
        <SectionLabel>Products</SectionLabel>
        {PRODUCTS.map(p => {
          const isActive = path.startsWith(p.href) ||
            (p.children?.some(c => path.startsWith(c.href)) ?? false)
          const hasChildren = p.children && p.children.length > 0

          return (
            <div key={p.id} style={{ marginBottom: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <Link
                  href={p.href}
                  style={{ textDecoration: 'none', flex: 1 }}
                  onClick={() => {
                    if (hasChildren) {
                      if (p.id === 'hemis') setHemisExpanded(true)
                      if (p.id === 'blueteam') setBlueteamExpanded(true)
                    }
                  }}
                >
                  <NavItem active={isActive} accentColor={p.color}>
                    <p.Icon size={15} strokeWidth={1.75} style={{ flexShrink: 0, color: isActive ? p.color : 'var(--color-text-dim)' }} />
                    <span style={{ flex: 1, fontSize: 13, fontWeight: isActive ? 600 : 400, color: isActive ? 'var(--color-text-primary)' : 'var(--color-text-secondary)' }}>
                      {p.label}
                    </span>
                    {isActive && !hasChildren && (
                      <div style={{ width: 4, height: 4, borderRadius: '50%', background: p.color, flexShrink: 0 }} />
                    )}
                  </NavItem>
                </Link>
                {hasChildren && (
                  <button
                    onClick={() => {
                      if (p.id === 'hemis') setHemisExpanded(!hemisExpanded)
                      if (p.id === 'blueteam') setBlueteamExpanded(!blueteamExpanded)
                    }}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px 6px', display: 'flex', alignItems: 'center', color: 'var(--color-text-dim)' }}
                  >
                    <ChevronRight size={13} style={{
                      transition: 'transform 0.15s',
                      transform: (p.id === 'hemis' ? hemisExpanded : blueteamExpanded) ? 'rotate(90deg)' : 'rotate(0deg)',
                    }} />
                  </button>
                )}
              </div>

              {/* Sub-items */}
              {hasChildren && (p.id === 'hemis' ? hemisExpanded : blueteamExpanded) && (
                <div style={{ paddingLeft: 12, marginTop: 1, marginBottom: 2 }}>
                  {p.children!.map(child => {
                    const childActive = path.startsWith(child.href)
                    return (
                      <Link key={child.id} href={child.href} style={{ textDecoration: 'none', display: 'block', marginBottom: 1 }}>
                        <div style={{
                          display: 'flex', alignItems: 'center', gap: 8,
                          padding: '6px 8px',
                          borderRadius: 4,
                          background: childActive ? `color-mix(in srgb, ${child.color} 10%, transparent)` : 'transparent',
                          transition: 'background 0.12s',
                        }}>
                          <div style={{ width: 2, height: 14, background: childActive ? child.color : 'var(--color-border)', borderRadius: 1, flexShrink: 0 }} />
                          <child.Icon size={12} strokeWidth={1.75} style={{ color: childActive ? child.color : 'var(--color-text-dim)', flexShrink: 0 }} />
                          <span style={{ fontSize: 12, color: childActive ? 'var(--color-text-primary)' : 'var(--color-text-secondary)', fontWeight: childActive ? 500 : 400 }}>
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
        <div style={{ margin: '10px 4px', borderTop: '1px solid var(--color-border)' }} />

        {/* General nav */}
        <SectionLabel>Navigation</SectionLabel>
        {NAV_ITEMS.map(item => {
          const isActive = path === item.href
          return (
            <Link key={item.href} href={item.href} style={{ textDecoration: 'none', display: 'block', marginBottom: 1 }}>
              <NavItem active={isActive} accentColor="var(--color-yellow)">
                <item.Icon size={15} strokeWidth={1.75} style={{ flexShrink: 0, color: isActive ? 'var(--color-yellow)' : 'var(--color-text-dim)' }} />
                <span style={{ fontSize: 13, fontWeight: isActive ? 600 : 400, color: isActive ? 'var(--color-text-primary)' : 'var(--color-text-secondary)' }}>
                  {item.label}
                </span>
              </NavItem>
            </Link>
          )
        })}
      </div>

      {/* ── User ── */}
      <div style={{ padding: '12px 14px', borderTop: '1px solid var(--color-border)', display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{
          width: 32, height: 32, borderRadius: '50%',
          background: 'var(--color-yellow-dim)',
          border: '1px solid var(--color-yellow)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
          fontSize: 13, fontWeight: 600, color: 'var(--color-yellow)',
        }}>
          A
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--color-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            Alex M.
          </div>
          <div style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
            Security Engineer
          </div>
        </div>
        <Link href="/login" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', padding: 4, color: 'var(--color-text-dim)' }}>
          <LogOut size={14} strokeWidth={1.75} />
        </Link>
      </div>
    </aside>
  )
}

// ── Small helpers ─────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-dim)', textTransform: 'uppercase', padding: '4px 8px 6px' }}>
      {children}
    </div>
  )
}

function NavItem({ children, active, accentColor }: { children: React.ReactNode; active: boolean; accentColor: string }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '7px 8px',
      borderRadius: 4,
      background: active ? 'var(--color-bg-elevated)' : 'transparent',
      border: active ? `1px solid var(--color-border)` : '1px solid transparent',
      transition: 'background 0.12s',
      cursor: 'pointer',
    }}>
      {children}
    </div>
  )
}
