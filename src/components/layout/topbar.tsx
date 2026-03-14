'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useTheme } from '@/components/layout/theme-provider'

const PAGE_META: Record<string, { title: string; product: string; color: string; breadcrumb: string }> = {
  '/dashboard':           { title:'OVERVIEW',      product:'HemisX Console',  color:'var(--color-yellow)',   breadcrumb:'/ overview'      },
  '/dashboard/scanner':   { title:'CLOUD SCANNER', product:'Cloud Security',  color:'var(--color-scanner)',  breadcrumb:'/ scanner'        },
  '/dashboard/hemis':     { title:'HEMIS',         product:'AI Red Team',     color:'var(--color-hemis)',    breadcrumb:'/ hemis'          },
  '/dashboard/blueteam':  { title:'BLUE TEAM',     product:'Threat Response', color:'var(--color-blueteam)', breadcrumb:'/ blue-team'      },
}

const PRODUCT_TOOLS = {
  hemis: [
    { href:'/dashboard/hemis', label:'SAST', icon:'⬡' },
    { href:'/dashboard/hemis/scanner', label:'DAST', icon:'◈' },
    { href:'/dashboard/hemis/payloads', label:'WHITE BOX RED TEAMING', icon:'◉' },
    { href:'/dashboard/hemis/findings', label:'BLACK BOX RED TEAMING', icon:'◌' },
    { href:'/dashboard/hemis/engagements', label:'FINDINGS ENGINE', icon:'▦' },
    { href:'/dashboard/hemis/reports', label:'REPORT GENERATOR', icon:'▤' },
  ],
  scanner: [
    { href:'/dashboard/scanner', label:'CLOUD SCAN', icon:'◈' },
    { href:'/dashboard/scanner', label:'COMPLIANCE', icon:'▤' },
    { href:'/dashboard/scanner', label:'INVENTORY', icon:'◌' },
  ],
  blueteam: [
    { href:'/dashboard/blueteam', label:'ALERTS', icon:'◎' },
    { href:'/dashboard/blueteam', label:'DETECTION RULES', icon:'▦' },
    { href:'/dashboard/blueteam', label:'PLAYBOOKS', icon:'◌' },
  ],
}

const PRODUCTS = [
  { id: 'scanner', label: 'CLOUD SCANNER', color: 'var(--color-scanner)' },
  { id: 'hemis', label: 'HEMIS', color: 'var(--color-hemis)' },
  { id: 'blueteam', label: 'BLUE TEAM', color: 'var(--color-blueteam)' },
]

export default function Topbar() {
  const path = usePathname()
  const { theme, toggle } = useTheme()
  const meta = PAGE_META[path] ?? PAGE_META['/dashboard']
  const [showToolsDropdown, setShowToolsDropdown] = useState(false)

  // Determine active product
  const activeProduct = PRODUCTS.find(p => path.startsWith(`/dashboard/${p.id}`))
  const tools = activeProduct ? PRODUCT_TOOLS[activeProduct.id as keyof typeof PRODUCT_TOOLS] : []

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
        {/* Tools Dropdown — only show if product is active */}
        {activeProduct && tools.length > 0 && (
          <div style={{ position:'relative' }}>
            <button
              onClick={() => setShowToolsDropdown(!showToolsDropdown)}
              style={{
                display:'flex', alignItems:'center', gap:6,
                background:'transparent', border:`1px solid ${activeProduct.color}`,
                padding:'6px 10px', cursor:'pointer',
                transition:'all 0.12s',
                borderColor: showToolsDropdown ? activeProduct.color : `${activeProduct.color}66`,
              }}
              onMouseEnter={e => !showToolsDropdown && (e.currentTarget.style.borderColor = activeProduct.color)}
              onMouseLeave={e => !showToolsDropdown && (e.currentTarget.style.borderColor = `${activeProduct.color}66`)}
            >
              <span className="mono" style={{ fontSize:11, color: activeProduct.color, letterSpacing:'0.08em', fontWeight:600 }}>
                TOOLS
              </span>
              <span className="mono" style={{ fontSize:9, color: activeProduct.color }}>▾</span>
            </button>

            {/* Dropdown Menu */}
            {showToolsDropdown && (
              <div style={{
                position:'absolute', top:'100%', right:0, marginTop:4,
                background:'var(--color-bg-elevated)', border:`1px solid ${activeProduct.color}44`,
                minWidth:200, zIndex:1000,
                boxShadow:'0 8px 24px rgba(0,0,0,0.4)',
              }}>
                {tools.map(tool => {
                  const isActive = path === tool.href
                  return (
                    <Link
                      key={tool.label}
                      href={tool.href}
                      onClick={() => setShowToolsDropdown(false)}
                      style={{ textDecoration:'none', display:'block' }}
                    >
                      <div style={{
                        display:'flex', alignItems:'center', gap:8,
                        background: isActive ? `${activeProduct.color}15` : 'transparent',
                        border: isActive ? `1px solid ${activeProduct.color}44` : '1px solid transparent',
                        borderBottom: '1px solid var(--color-border)',
                        padding:'10px 12px', cursor:'pointer',
                        transition:'all 0.1s',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = `${activeProduct.color}10`)}
                      onMouseLeave={e => {
                        e.currentTarget.style.background = isActive ? `${activeProduct.color}15` : 'transparent'
                      }}
                      >
                        <span style={{ fontSize:11, color: activeProduct.color, flexShrink:0 }}>{tool.icon}</span>
                        <span className="mono" style={{
                          fontSize:9, fontWeight:600, color: isActive ? activeProduct.color : 'var(--color-text-secondary)',
                          letterSpacing:'0.08em', textTransform:'uppercase',
                        }}>
                          {tool.label}
                        </span>
                      </div>
                    </Link>
                  )
                })}
              </div>
            )}
          </div>
        )}

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
