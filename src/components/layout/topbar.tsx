'use client'

import { usePathname } from 'next/navigation'

const PAGE_META: Record<string, { title: string; product: string; color: string; breadcrumb: string }> = {
  '/dashboard':           { title:'OVERVIEW',      product:'HemisX Console',  color:'var(--color-yellow)',   breadcrumb:'/ overview'      },
  '/dashboard/scanner':   { title:'CLOUD SCANNER', product:'Cloud Security',  color:'var(--color-scanner)',  breadcrumb:'/ scanner'        },
  '/dashboard/hemis':     { title:'HEMIS',         product:'AI Red Team',     color:'var(--color-hemis)',    breadcrumb:'/ hemis'          },
  '/dashboard/blueteam':  { title:'BLUE TEAM',     product:'Threat Response', color:'var(--color-blueteam)', breadcrumb:'/ blue-team'      },
}

export default function Topbar() {
  const path = usePathname()
  const meta = PAGE_META[path] ?? PAGE_META['/dashboard']
  const now  = new Date().toLocaleString('en-US', { hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit' })

  return (
    <header style={{
      height: 52,
      background: 'var(--color-bg-surface)',
      borderBottom: '1px solid var(--color-border)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 24px',
      gap: 16,
      flexShrink: 0,
      position: 'sticky',
      top: 0,
      zIndex: 20,
    }}>
      {/* Page identity */}
      <div style={{ flex:1, display:'flex', alignItems:'center', gap:10 }}>
        <span className="mono" style={{ fontSize:10, color:'var(--color-text-dim)', letterSpacing:'0.08em' }}>
          console.hemisx.com
        </span>
        <span style={{ color:'var(--color-border-bright)', fontSize:10 }}>›</span>
        <span className="mono" style={{ fontSize:10, color:'var(--color-text-secondary)', letterSpacing:'0.08em' }}>
          {meta.breadcrumb}
        </span>
      </div>

      {/* Center title */}
      <div style={{ display:'flex', alignItems:'center', gap:8 }}>
        <span className="mono" style={{
          fontSize:11, fontWeight:600, letterSpacing:'0.14em',
          textTransform:'uppercase', color: meta.color,
        }}>
          {meta.title}
        </span>
      </div>

      {/* Right cluster */}
      <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'flex-end', gap:16 }}>
        {/* Live time */}
        <div className="mono" style={{ fontSize:10, color:'var(--color-text-dim)', letterSpacing:'0.08em' }}>
          {new Date().toLocaleDateString('en-US', { month:'short', day:'2-digit', year:'numeric' })}
        </div>

        {/* Alert badge */}
        <div style={{ display:'flex', alignItems:'center', gap:5, cursor:'pointer' }}>
          <span className="dot-live red" style={{ width:5, height:5 }} />
          <span className="mono" style={{ fontSize:10, color:'var(--color-hemis)', letterSpacing:'0.08em' }}>
            3 CRITICAL
          </span>
        </div>

        {/* Divider */}
        <div style={{ width:1, height:16, background:'var(--color-border)' }} />

        {/* Org */}
        <div style={{ display:'flex', alignItems:'center', gap:6 }}>
          <div style={{
            width:22, height:22, borderRadius:'50%',
            background:'var(--color-yellow-dim)',
            border:'1px solid var(--color-yellow)',
            display:'flex', alignItems:'center', justifyContent:'center',
          }}>
            <span style={{ fontSize:9, color:'var(--color-yellow)', fontWeight:700 }}>H</span>
          </div>
          <span style={{ fontSize:12, color:'var(--color-text-secondary)' }}>Acme Corp</span>
          <span className="mono" style={{ fontSize:9, color:'var(--color-text-dim)' }}>▾</span>
        </div>
      </div>
    </header>
  )
}
