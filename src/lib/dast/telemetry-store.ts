/**
 * In-memory telemetry store for live attack feed.
 * Ring buffer of recent HTTP requests made during a DAST scan,
 * with computed stats (RPS, latency, status code distribution).
 */

export interface AttackTelemetryEvent {
  id: string
  scanId: string
  timestamp: string
  method: string
  targetUrl: string
  endpoint: string
  attackVector: string
  payload: string | null
  httpStatus: number
  latencyMs: number
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | null
  findingTitle: string | null
  phase: string
}

export interface TelemetryStats {
  totalRequests: number
  rps: number
  avgLatencyMs: number
  status2xx: number
  status3xx: number
  status4xx: number
  status5xx: number
  activeEndpoints: string[]
}

export type TelemetryCallback = (event: Omit<AttackTelemetryEvent, 'id' | 'scanId' | 'timestamp'>) => void

interface TelemetryState {
  events: AttackTelemetryEvent[]
  totalRequests: number
}

const MAX_EVENTS = 500
const RPS_WINDOW_MS = 5000

const telemetryStore = new Map<string, TelemetryState>()

export function pushTelemetryEvent(scanId: string, partial: Omit<AttackTelemetryEvent, 'id' | 'scanId' | 'timestamp'>): void {
  const event: AttackTelemetryEvent = {
    ...partial,
    id: crypto.randomUUID(),
    scanId,
    timestamp: new Date().toISOString(),
  }

  let state = telemetryStore.get(scanId)
  if (!state) {
    state = { events: [], totalRequests: 0 }
    telemetryStore.set(scanId, state)
  }

  state.events.push(event)
  state.totalRequests++

  // Ring buffer: keep only the last MAX_EVENTS
  if (state.events.length > MAX_EVENTS) {
    state.events = state.events.slice(-MAX_EVENTS)
  }
}

export function getTelemetryEventsSince(scanId: string, sinceIndex: number, limit = 50): { events: AttackTelemetryEvent[]; nextCursor: number } {
  const state = telemetryStore.get(scanId)
  if (!state) return { events: [], nextCursor: 0 }

  // sinceIndex is based on totalRequests (absolute index)
  // Map it to the ring buffer position
  const bufferStart = state.totalRequests - state.events.length
  const startIdx = Math.max(0, sinceIndex - bufferStart)
  const events = state.events.slice(startIdx, startIdx + limit)
  const nextCursor = sinceIndex + events.length

  return { events, nextCursor }
}

export function getTelemetryStats(scanId: string): TelemetryStats {
  const state = telemetryStore.get(scanId)
  if (!state) {
    return { totalRequests: 0, rps: 0, avgLatencyMs: 0, status2xx: 0, status3xx: 0, status4xx: 0, status5xx: 0, activeEndpoints: [] }
  }

  const now = Date.now()
  const windowStart = now - RPS_WINDOW_MS

  // Compute RPS from events in the sliding window
  let windowCount = 0
  let totalLatency = 0
  let latencyCount = 0
  let s2xx = 0, s3xx = 0, s4xx = 0, s5xx = 0
  const recentEndpoints = new Set<string>()

  for (const evt of state.events) {
    const evtTime = new Date(evt.timestamp).getTime()

    // Stats across all buffered events
    if (evt.httpStatus >= 200 && evt.httpStatus < 300) s2xx++
    else if (evt.httpStatus >= 300 && evt.httpStatus < 400) s3xx++
    else if (evt.httpStatus >= 400 && evt.httpStatus < 500) s4xx++
    else if (evt.httpStatus >= 500) s5xx++

    totalLatency += evt.latencyMs
    latencyCount++

    // RPS window
    if (evtTime >= windowStart) {
      windowCount++
      recentEndpoints.add(evt.endpoint)
    }
  }

  return {
    totalRequests: state.totalRequests,
    rps: Math.round((windowCount / (RPS_WINDOW_MS / 1000)) * 10) / 10,
    avgLatencyMs: latencyCount > 0 ? Math.round(totalLatency / latencyCount) : 0,
    status2xx: s2xx,
    status3xx: s3xx,
    status4xx: s4xx,
    status5xx: s5xx,
    activeEndpoints: Array.from(recentEndpoints).slice(0, 20),
  }
}

export function clearTelemetry(scanId: string): void {
  telemetryStore.delete(scanId)
}
