'use client'

import React, { useRef, useEffect, useState, useCallback } from 'react'
import type { AttackTelemetryEvent } from '@/lib/dast/telemetry-store'

const METHOD_COLORS: Record<string, string> = {
  GET: '#22c55e',
  POST: '#3b82f6',
  PUT: '#f97316',
  DELETE: '#ef4444',
  PATCH: '#a855f7',
  OPTIONS: '#6b7280',
  HEAD: '#6b7280',
}

const STATUS_COLORS: Record<string, string> = {
  '2': '#22c55e',
  '3': '#3b82f6',
  '4': '#eab308',
  '5': '#ef4444',
  '0': '#6b7280',
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

function highlightPayload(payload: string): React.ReactNode[] {
  const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND|WHERE|FROM|TABLE|JOIN|INTO|VALUES|SET|ALTER|CREATE|EXEC|EXECUTE|DECLARE|CAST|CONVERT|CHAR|NCHAR|VARCHAR)\b/gi
  const htmlTags = /(<\/?[a-zA-Z][^>]*>)/g
  const specialChars = /(--|;|'|"|`|\$\{|\}\))/g

  const parts: React.ReactNode[] = []
  let key = 0
  const tokens = payload.split(/(\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND|WHERE|FROM|TABLE)\b|<\/?[a-zA-Z][^>]*>|--|;|'|"|`)/gi)

  for (const token of tokens) {
    if (!token) continue
    if (sqlKeywords.test(token)) {
      parts.push(<span key={key++} style={{ color: '#ef4444', fontWeight: 600 }}>{token}</span>)
    } else if (htmlTags.test(token)) {
      parts.push(<span key={key++} style={{ color: '#f97316' }}>{token}</span>)
    } else if (specialChars.test(token)) {
      parts.push(<span key={key++} style={{ color: '#eab308' }}>{token}</span>)
    } else {
      parts.push(<span key={key++}>{token}</span>)
    }
    sqlKeywords.lastIndex = 0
    htmlTags.lastIndex = 0
    specialChars.lastIndex = 0
  }

  return parts
}

interface RequestStreamProps {
  events: AttackTelemetryEvent[]
}

const MAX_VISIBLE = 50

export default function RequestStream({ events }: RequestStreamProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const prevLengthRef = useRef(0)

  const handleScroll = useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60
    setAutoScroll(atBottom)
  }, [])

  useEffect(() => {
    if (autoScroll && scrollRef.current && events.length > prevLengthRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
    prevLengthRef.current = events.length
  }, [events.length, autoScroll])

  const visible = events.slice(-MAX_VISIBLE)

  return (
    <div style={{ position: 'relative' }}>
      <style>{`
        @keyframes feed-card-in {
          from { opacity: 0; transform: translateY(12px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .feed-card { animation: feed-card-in 0.25s ease-out both; }
        @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
      `}</style>

      <div
        ref={scrollRef}
        onScroll={handleScroll}
        style={{
          maxHeight: 380, overflowY: 'auto',
          display: 'flex', flexDirection: 'column', gap: 4, paddingRight: 4,
        }}
      >
        {visible.map(evt => {
          const statusGroup = evt.httpStatus > 0 ? String(evt.httpStatus)[0] : '0'
          const statusColor = STATUS_COLORS[statusGroup] || '#6b7280'
          const methodColor = METHOD_COLORS[evt.method] || '#6b7280'
          const is5xx = statusGroup === '5'

          return (
            <div
              key={evt.id}
              className="feed-card"
              style={{
                background: is5xx ? 'rgba(239,68,68,0.06)' : 'var(--color-bg-elevated)',
                border: `1px solid ${is5xx ? 'rgba(239,68,68,0.2)' : 'var(--color-border)'}`,
                padding: '8px 12px',
                transition: 'background 0.3s ease',
              }}
            >
              {/* Top row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{
                  fontSize: 9, fontFamily: 'var(--font-mono)', fontWeight: 700,
                  padding: '1px 6px', background: `${methodColor}20`, color: methodColor,
                  border: `1px solid ${methodColor}40`, letterSpacing: '0.05em',
                }}>
                  {evt.method}
                </span>
                <span style={{
                  fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)',
                  flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0,
                }}>
                  {evt.endpoint}
                </span>
                {evt.httpStatus > 0 && (
                  <span style={{
                    fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 600,
                    padding: '1px 6px', background: `${statusColor}15`, color: statusColor,
                    border: `1px solid ${statusColor}30`,
                  }}>
                    {evt.httpStatus}
                  </span>
                )}
                <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>
                  {evt.latencyMs}ms
                </span>
                {evt.severity && (
                  <span style={{
                    fontSize: 8, fontFamily: 'var(--font-mono)', fontWeight: 700,
                    padding: '1px 6px', letterSpacing: '0.08em',
                    background: `${SEV_COLORS[evt.severity]}20`,
                    color: SEV_COLORS[evt.severity],
                    border: `1px solid ${SEV_COLORS[evt.severity]}40`,
                  }}>
                    {evt.severity}
                  </span>
                )}
              </div>

              {/* Bottom row: payload + vector */}
              {(evt.payload || evt.attackVector) && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                  {evt.attackVector && (
                    <span style={{
                      fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--color-dast)', opacity: 0.8, flexShrink: 0,
                    }}>
                      {evt.attackVector}
                    </span>
                  )}
                  {evt.payload && (
                    <span style={{
                      fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0,
                    }}>
                      {highlightPayload(evt.payload)}
                    </span>
                  )}
                </div>
              )}

              {/* Finding title */}
              {evt.findingTitle && (
                <div style={{
                  marginTop: 4, fontSize: 10, fontFamily: 'var(--font-mono)',
                  color: SEV_COLORS[evt.severity || 'INFO'], fontWeight: 600,
                }}>
                  Finding: {evt.findingTitle}
                </div>
              )}
            </div>
          )
        })}

        {events.length === 0 && (
          <div style={{
            padding: 40, textAlign: 'center', color: 'var(--color-text-dim)',
            fontFamily: 'var(--font-mono)', fontSize: 11,
          }}>
            Waiting for first request...
          </div>
        )}
      </div>

      {/* Jump to latest button */}
      {!autoScroll && events.length > 0 && (
        <button
          onClick={() => {
            setAutoScroll(true)
            scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
          }}
          style={{
            position: 'absolute', bottom: 8, left: '50%', transform: 'translateX(-50%)',
            padding: '4px 14px', fontSize: 10, fontFamily: 'var(--font-mono)',
            fontWeight: 600, letterSpacing: '0.06em', cursor: 'pointer',
            background: 'var(--color-dast)', color: '#fff', border: 'none',
            boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
            animation: 'fade-in 0.2s ease-out',
          }}
        >
          Jump to latest
        </button>
      )}
    </div>
  )
}
