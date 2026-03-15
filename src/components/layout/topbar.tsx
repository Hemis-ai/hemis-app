'use client'

import { usePathname } from 'next/navigation'
import { useTheme } from '@/components/layout/theme-provider'

const PAGE_META: Record<string, { title: string; product: string; color: string; breadcrumb: string }> = {
  '/dashboard':           { title:'OVERVIEW',      product:'HemisX Console',  color:'var(--color-yellow)',   breadcrumb:'/ overview'      },
  '/dashboard/scanner':   { title:'CLOUD SCANNER', product:'Cloud Security',  color:'var(--color-scanner)',  breadcrumb:'/ scanner'        },
  '/dashboard/hemis':     { title:'HEMIS',         product:'AI Red Team',     color:'var(--color-hemis)',    breadcrumb:'/ hemis'          },
  '/dashboard/blueteam':  { title:'BLUE TEAM',     product:'Threat Response', color:'var(--color-blueteam)', breadcrumb:'/ blue-team'      },
  '/dashboard/hemis/sast': { title:'SAST',           product:'Static Analysis', color:'var(--color-hemis)',    breadcrumb:'/ hemis / sast'    },
  '/dashboard/hemis/dast': { title:'DAST',           product:'Dynamic Testing', color:'var(--color-hemis)',    breadcrumb:'/ hemis / dast'    },
}

export default function Topbar() {
  const path = usePathname()
  const { theme, toggle } = useTheme()
  const meta = PAGE_META[path] ?? PAGE_META['/dashboard']

  return (
    <header style={{
      height: 60,
      background: 'var(--color-bg-surface)',
      borderBottom: '1px solid var(--color-border)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 26px',
      gap: 18,
      flexShrink: 0,
      position: 'sticky',
      top: 0,
      zIndex: 20,
    }}>
      {/* Page identity */}
      <div style={{ flex:1, display:'flex', alignItems:'center', gap:10 }}>
        <span className="mono" style={{ fontSize:12, color:'var(--color-text-secondary)', letterSpacing:'0.08em' }}>
          console.hemisx.com
        </span>
        <span style={{ color:'var(--color-border-bright)', fontSize:12 }}>›</span>
        <span className="mono" style={{ fontSize:11, color:'var(--color-text-secondary)', letterSpacing:'0.08em' }}>
          {meta.breadcrumb}
        </span>
      </div>

      {/* Center title */}
      <div style={{ display:'flex', alignItems:'center', gap:10 }}>
        <span className="mono" style={{
          fontSize:12, fontWeight:600, letterSpacing:'0.14em',
          textTransform:'uppercase', color: meta.color,
        }}>
          {meta.title}
        </span>
      </div>

      {/* Right cluster */}
      <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'flex-end', gap:16, position:'relative' }}>
        {/* Theme toggle */}
        <button
          onClick={toggle}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          style={{
            background: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text-secondary)',
            width: 30, height: 30,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer',
            fontSize: 14,
            transition: 'all 0.15s',
            flexShrink: 0,
          }}
          onMouseEnter={e => {
            e.currentTarget.style.borderColor = 'var(--color-border-bright)'
            e.currentTarget.style.color = 'var(--color-text-primary)'
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = 'var(--color-border)'
            e.currentTarget.style.color = 'var(--color-text-secondary)'
          }}
        >
          {theme === 'dark' ? '☀' : '☾'}
        </button>

        {/* Divider */}
        <div style={{ width:1, height:16, background:'var(--color-border)' }} />

        {/* Org */}
        <div style={{ display:'flex', alignItems:'center', gap:6 }}>
          <div style={{
            width:24, height:24, borderRadius:'50%',
            background:'var(--color-yellow-dim)',
            border:'1px solid var(--color-yellow)',
            display:'flex', alignItems:'center', justifyContent:'center',
          }}>
            <span style={{ fontSize:10, color:'var(--color-yellow)', fontWeight:700 }}>H</span>
          </div>
          <span style={{ fontSize:13, color:'var(--color-text-secondary)' }}>Acme Corp</span>
          <span className="mono" style={{ fontSize:11, color:'var(--color-text-secondary)' }}>▾</span>
        </div>
      </div>
    </header>
  )
}
