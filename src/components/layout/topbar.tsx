'use client'

import { useState } from 'react'
import { usePathname } from 'next/navigation'
import { useTheme } from '@/components/layout/theme-provider'
import { Sun, Moon, ChevronDown } from 'lucide-react'

const PAGE_META: Record<string, { title: string; product: string; color: string; crumbs: string[] }> = {
  '/dashboard':            { title: 'Overview',        product: 'HemisX Console',         color: 'var(--color-yellow)',   crumbs: ['Dashboard'] },
  '/dashboard/scanner':    { title: 'Cloud Scanner',   product: 'Cloud Security',          color: 'var(--color-scanner)', crumbs: ['Dashboard', 'Cloud Scanner'] },
  '/dashboard/hemis':      { title: 'HEMIS',           product: 'AI Red Team',             color: 'var(--color-hemis)',   crumbs: ['Dashboard', 'HEMIS'] },
  '/dashboard/hemis/sast': { title: 'SAST',            product: 'Static Analysis',         color: 'var(--color-sast)',    crumbs: ['Dashboard', 'HEMIS', 'SAST'] },
  '/dashboard/hemis/dast': { title: 'DAST',            product: 'Web App Security',        color: 'var(--color-dast)',    crumbs: ['Dashboard', 'HEMIS', 'DAST'] },
  '/dashboard/hemis/wbrt': { title: 'White Box RT',    product: 'White Box Red Teaming',   color: 'var(--color-wbrt)',    crumbs: ['Dashboard', 'HEMIS', 'White Box RT'] },
  '/dashboard/hemis/bbrt': { title: 'Black Box RT',    product: 'Black Box Red Teaming',   color: 'var(--color-bbrt)',    crumbs: ['Dashboard', 'HEMIS', 'Black Box RT'] },
  '/dashboard/blueteam':   { title: 'Blue Team',       product: 'Threat Response',         color: 'var(--color-blueteam)', crumbs: ['Dashboard', 'Blue Team'] },
  '/dashboard/reports':    { title: 'Reports',         product: 'HemisX Console',          color: 'var(--color-yellow)',  crumbs: ['Dashboard', 'Reports'] },
  '/dashboard/settings':   { title: 'Settings',        product: 'HemisX Console',          color: 'var(--color-yellow)',  crumbs: ['Dashboard', 'Settings'] },
}

export default function Topbar() {
  const path = usePathname()
  const { theme, toggle } = useTheme()
  const meta = PAGE_META[path] ?? PAGE_META['/dashboard']

  return (
    <header style={{
      height: 56,
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

      {/* Breadcrumbs */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 6 }}>
        {meta.crumbs.map((crumb, i) => (
          <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {i > 0 && (
              <span style={{ color: 'var(--color-border-bright)', fontSize: 13, lineHeight: 1 }}>/</span>
            )}
            <span style={{
              fontSize: 13,
              color: i === meta.crumbs.length - 1 ? 'var(--color-text-primary)' : 'var(--color-text-dim)',
              fontWeight: i === meta.crumbs.length - 1 ? 500 : 400,
            }}>
              {crumb}
            </span>
          </span>
        ))}
      </div>

      {/* Center: product label */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: meta.color, boxShadow: `0 0 6px ${meta.color}` }} />
        <span className="mono" style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: meta.color }}>
          {meta.product}
        </span>
      </div>

      {/* Right cluster */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 12 }}>

        {/* Theme toggle */}
        <button
          onClick={toggle}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          style={{
            background: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text-secondary)',
            width: 32, height: 32,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer',
            borderRadius: 4,
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
          {theme === 'dark'
            ? <Sun size={14} strokeWidth={1.75} />
            : <Moon size={14} strokeWidth={1.75} />
          }
        </button>

        {/* Separator */}
        <div style={{ width: 1, height: 20, background: 'var(--color-border)' }} />

        {/* Org */}
        <button style={{
          display: 'flex', alignItems: 'center', gap: 7,
          background: 'none', border: 'none', cursor: 'pointer', padding: '4px 6px',
          borderRadius: 4,
          transition: 'background 0.12s',
        }}
          onMouseEnter={e => { e.currentTarget.style.background = 'var(--color-bg-elevated)' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'none' }}
        >
          <div style={{
            width: 24, height: 24, borderRadius: '50%',
            background: 'var(--color-yellow-dim)',
            border: '1px solid var(--color-yellow)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 10, fontWeight: 700, color: 'var(--color-yellow)',
            flexShrink: 0,
          }}>
            H
          </div>
          <span style={{ fontSize: 13, color: 'var(--color-text-secondary)', fontWeight: 400 }}>Acme Corp</span>
          <ChevronDown size={12} style={{ color: 'var(--color-text-dim)' }} />
        </button>
      </div>
    </header>
  )
}
