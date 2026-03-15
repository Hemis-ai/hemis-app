'use client'

import { useState } from 'react'

export default function ReportGeneratorPage() {
  const [reports] = useState([
    {
      id: 'report_001',
      title: 'Q1 2026 Security Assessment',
      type: 'FULL PENETRATION TEST',
      date: '2026-03-14',
      status: 'COMPLETED',
      findings: 8,
      criticals: 3,
      format: 'PDF',
    },
    {
      id: 'report_002',
      title: 'SAST Code Review Results',
      type: 'STATIC ANALYSIS',
      date: '2026-03-10',
      status: 'COMPLETED',
      findings: 12,
      criticals: 2,
      format: 'PDF',
    },
    {
      id: 'report_003',
      title: 'API Security Assessment',
      type: 'DYNAMIC ANALYSIS',
      date: '2026-03-08',
      status: 'COMPLETED',
      findings: 5,
      criticals: 1,
      format: 'PDF',
    },
  ])

  return (
    <div style={{ minHeight: '100vh', background: 'var(--color-bg-surface)', padding: '20px 24px' }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div className="mono" style={{ fontSize: 10, color: 'var(--color-hemis)', letterSpacing: '0.15em', marginBottom: 4, textTransform: 'uppercase' }}>
          [ HEMIS REPORT GENERATOR ]
        </div>
        <h1 className="display" style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0, marginBottom: 8 }}>
          Security Assessment Reports
        </h1>
        <p style={{ fontSize: 12, color: 'var(--color-text-dim)', margin: 0 }}>
          Generate, manage, and export comprehensive security findings reports
        </p>
      </div>

      {/* Generate New Report Button */}
      <div style={{ marginBottom: 24 }}>
        <button style={{
          padding: '10px 16px',
          background: 'var(--color-hemis)',
          color: '#ffffff',
          border: 'none',
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          cursor: 'pointer',
          transition: 'all 0.12s',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--color-hemis-orange)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'var(--color-hemis)')}
        >
          ◉ GENERATE NEW REPORT
        </button>
      </div>

      {/* Reports Table */}
      <div style={{ background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)' }}>
        <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--color-border)' }}>
          <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            AVAILABLE REPORTS ({reports.length})
          </div>
        </div>

        {reports.map((report, idx) => (
          <div key={report.id} style={{
            padding: '14px 16px',
            borderBottom: idx < reports.length - 1 ? '1px solid var(--color-border)' : 'none',
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            justifyContent: 'space-between',
            transition: 'all 0.12s',
          }}
          onMouseEnter={e => (e.currentTarget.style.background = 'var(--color-bg-surface)')}
          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
          >
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 4 }}>
                {report.title}
              </div>
              <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--color-text-secondary)' }}>
                <span className="mono">{report.type}</span>
                <span className="mono">•</span>
                <span className="mono">{report.date}</span>
                <span className="mono">•</span>
                <span className="mono">{report.findings} findings</span>
                <span className="mono" style={{ color: 'var(--color-hemis)', fontWeight: 600 }}>
                  {report.criticals} CRITICAL
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button style={{
                padding: '6px 12px',
                background: 'transparent',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-secondary)',
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                fontWeight: 600,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                cursor: 'pointer',
                transition: 'all 0.12s',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = 'var(--color-hemis)'
                e.currentTarget.style.color = 'var(--color-hemis)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'var(--color-border)'
                e.currentTarget.style.color = 'var(--color-text-secondary)'
              }}
              >
                ▼ DOWNLOAD
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Report Options */}
      <div style={{ marginTop: 24, padding: '16px', background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)' }}>
        <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 12 }}>
          EXPORT OPTIONS
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          {['PDF', 'JSON', 'CSV'].map(fmt => (
            <button key={fmt} style={{
              padding: '8px 12px',
              background: 'transparent',
              border: '1px solid var(--color-border)',
              color: 'var(--color-text-secondary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              fontWeight: 600,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              transition: 'all 0.12s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--color-hemis)'
              e.currentTarget.style.color = 'var(--color-hemis)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--color-border)'
              e.currentTarget.style.color = 'var(--color-text-secondary)'
            }}
            >
              {fmt}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
