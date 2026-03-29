'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import type { AttackTelemetryEvent, TelemetryStats } from '@/lib/dast/telemetry-store'

export interface TimeSeriesPoint {
  time: number
  rps: number
  avgLatencyMs: number
  errorRate: number // (4xx + 5xx) / total in this window
}

export interface TelemetryState {
  events: AttackTelemetryEvent[]
  stats: TelemetryStats
  rpsHistory: TimeSeriesPoint[]
  isLoading: boolean
}

const MAX_EVENTS = 500
const MAX_HISTORY = 60
const POLL_INTERVAL = 1000

const EMPTY_STATS: TelemetryStats = {
  totalRequests: 0, rps: 0, avgLatencyMs: 0,
  status2xx: 0, status3xx: 0, status4xx: 0, status5xx: 0,
  activeEndpoints: [],
}

export function useTelemetryPoll(scanId: string | null, enabled: boolean): TelemetryState {
  const [events, setEvents] = useState<AttackTelemetryEvent[]>([])
  const [stats, setStats] = useState<TelemetryStats>(EMPTY_STATS)
  const [rpsHistory, setRpsHistory] = useState<TimeSeriesPoint[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const cursorRef = useRef(0)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const poll = useCallback(async () => {
    if (!scanId) return
    try {
      const res = await fetch(`/api/dast/scans/${scanId}/telemetry?since=${cursorRef.current}&limit=100`)
      if (!res.ok) return
      const data = await res.json()

      if (data.events?.length > 0) {
        setEvents(prev => {
          const merged = [...prev, ...data.events]
          return merged.length > MAX_EVENTS ? merged.slice(-MAX_EVENTS) : merged
        })
        cursorRef.current = data.nextCursor
      }

      if (data.stats) {
        setStats(data.stats)
        const total = data.stats.status2xx + data.stats.status3xx + data.stats.status4xx + data.stats.status5xx
        setRpsHistory(prev => {
          const point: TimeSeriesPoint = {
            time: Date.now(),
            rps: data.stats.rps,
            avgLatencyMs: data.stats.avgLatencyMs,
            errorRate: total > 0 ? (data.stats.status4xx + data.stats.status5xx) / total : 0,
          }
          const next = [...prev, point]
          return next.length > MAX_HISTORY ? next.slice(-MAX_HISTORY) : next
        })
      }

      setIsLoading(false)
    } catch {
      // Silently fail — next poll will retry
    }
  }, [scanId])

  useEffect(() => {
    if (!enabled || !scanId) {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
      return
    }

    // Reset state for new scan
    setEvents([])
    setStats(EMPTY_STATS)
    setRpsHistory([])
    setIsLoading(true)
    cursorRef.current = 0

    // Immediate first poll
    poll()
    intervalRef.current = setInterval(poll, POLL_INTERVAL)

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [scanId, enabled, poll])

  return { events, stats, rpsHistory, isLoading }
}
