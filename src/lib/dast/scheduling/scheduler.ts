/**
 * DAST Scan Scheduling — Manage recurring scan schedules.
 * In production, this would integrate with a cron service or task queue.
 * For now, we store schedules in-memory and provide the data model.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type ScheduleFrequency = 'daily' | 'weekly' | 'biweekly' | 'monthly' | 'quarterly'
export type ScheduleStatus = 'active' | 'paused' | 'disabled'

export interface ScanSchedule {
  id: string
  name: string
  targetUrl: string
  scanProfile: string
  frequency: ScheduleFrequency
  status: ScheduleStatus
  authConfigJson: string | null
  scopeInclude: string[]
  scopeExclude: string[]
  nextRunAt: string
  lastRunAt: string | null
  lastScanId: string | null
  totalRuns: number
  createdAt: string
  updatedAt: string
}

export interface CreateScheduleInput {
  name: string
  targetUrl: string
  scanProfile: string
  frequency: ScheduleFrequency
  authConfigJson?: string | null
  scopeInclude?: string[]
  scopeExclude?: string[]
}

// ─── Frequency Helpers ──────────────────────────────────────────────────────

const FREQ_MS: Record<ScheduleFrequency, number> = {
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
  biweekly: 14 * 24 * 60 * 60 * 1000,
  monthly: 30 * 24 * 60 * 60 * 1000,
  quarterly: 90 * 24 * 60 * 60 * 1000,
}

export function getNextRunDate(frequency: ScheduleFrequency, from?: Date): Date {
  const base = from ?? new Date()
  return new Date(base.getTime() + FREQ_MS[frequency])
}

export const FREQUENCY_LABELS: Record<ScheduleFrequency, string> = {
  daily: 'Every Day',
  weekly: 'Every Week',
  biweekly: 'Every 2 Weeks',
  monthly: 'Every Month',
  quarterly: 'Every Quarter',
}

// ─── In-Memory Store (would be Prisma in production) ────────────────────────

let schedules: ScanSchedule[] = []
let nextId = 1

export function listSchedules(): ScanSchedule[] {
  return [...schedules].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
}

export function getSchedule(id: string): ScanSchedule | null {
  return schedules.find(s => s.id === id) ?? null
}

export function createSchedule(input: CreateScheduleInput): ScanSchedule {
  const now = new Date().toISOString()
  const schedule: ScanSchedule = {
    id: `sched-${String(nextId++).padStart(3, '0')}`,
    name: input.name,
    targetUrl: input.targetUrl,
    scanProfile: input.scanProfile,
    frequency: input.frequency,
    status: 'active',
    authConfigJson: input.authConfigJson ?? null,
    scopeInclude: input.scopeInclude ?? [],
    scopeExclude: input.scopeExclude ?? [],
    nextRunAt: getNextRunDate(input.frequency).toISOString(),
    lastRunAt: null,
    lastScanId: null,
    totalRuns: 0,
    createdAt: now,
    updatedAt: now,
  }
  schedules.push(schedule)
  return schedule
}

export function updateScheduleStatus(id: string, status: ScheduleStatus): ScanSchedule | null {
  const schedule = schedules.find(s => s.id === id)
  if (!schedule) return null
  schedule.status = status
  schedule.updatedAt = new Date().toISOString()
  return schedule
}

export function deleteSchedule(id: string): boolean {
  const idx = schedules.findIndex(s => s.id === id)
  if (idx === -1) return false
  schedules.splice(idx, 1)
  return true
}

export function markScheduleRun(id: string, scanId: string): ScanSchedule | null {
  const schedule = schedules.find(s => s.id === id)
  if (!schedule) return null
  schedule.lastRunAt = new Date().toISOString()
  schedule.lastScanId = scanId
  schedule.totalRuns += 1
  schedule.nextRunAt = getNextRunDate(schedule.frequency).toISOString()
  schedule.updatedAt = new Date().toISOString()
  return schedule
}

// ─── Seed Demo Schedules ────────────────────────────────────────────────────

export function seedDemoSchedules(): void {
  if (schedules.length > 0) return
  schedules = [
    {
      id: 'sched-001',
      name: 'Production Web App — Weekly',
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      frequency: 'weekly',
      status: 'active',
      authConfigJson: null,
      scopeInclude: [],
      scopeExclude: ['/logout', '/static/*'],
      nextRunAt: '2026-03-19T08:00:00Z',
      lastRunAt: '2026-03-12T08:00:00Z',
      lastScanId: 'dast-scan-001',
      totalRuns: 8,
      createdAt: '2026-01-15T10:00:00Z',
      updatedAt: '2026-03-12T09:23:00Z',
    },
    {
      id: 'sched-002',
      name: 'Staging API — Daily',
      targetUrl: 'https://api-staging.example.com',
      scanProfile: 'api_only',
      frequency: 'daily',
      status: 'active',
      authConfigJson: JSON.stringify({ type: 'bearer', token: 'staging-token-xxx' }),
      scopeInclude: ['/api/*'],
      scopeExclude: [],
      nextRunAt: '2026-03-16T14:00:00Z',
      lastRunAt: '2026-03-15T14:00:00Z',
      lastScanId: 'dast-scan-002',
      totalRuns: 42,
      createdAt: '2026-02-01T09:00:00Z',
      updatedAt: '2026-03-15T14:42:00Z',
    },
    {
      id: 'sched-003',
      name: 'Payment Portal — Monthly Deep',
      targetUrl: 'https://payments.example.com',
      scanProfile: 'deep',
      frequency: 'monthly',
      status: 'active',
      authConfigJson: null,
      scopeInclude: [],
      scopeExclude: [],
      nextRunAt: '2026-04-14T02:00:00Z',
      lastRunAt: '2026-03-14T02:00:00Z',
      lastScanId: 'dast-scan-003',
      totalRuns: 3,
      createdAt: '2026-01-14T01:00:00Z',
      updatedAt: '2026-03-14T04:47:00Z',
    },
    {
      id: 'sched-004',
      name: 'Internal Admin Panel — Biweekly',
      targetUrl: 'https://admin.internal.example.com',
      scanProfile: 'full',
      frequency: 'biweekly',
      status: 'paused',
      authConfigJson: JSON.stringify({ type: 'form', loginUrl: 'https://admin.internal.example.com/login', usernameField: 'email', passwordField: 'password', username: 'admin@example.com', password: '••••••••' }),
      scopeInclude: [],
      scopeExclude: [],
      nextRunAt: '2026-03-28T06:00:00Z',
      lastRunAt: '2026-03-01T06:00:00Z',
      lastScanId: null,
      totalRuns: 2,
      createdAt: '2026-02-15T06:00:00Z',
      updatedAt: '2026-03-01T07:15:00Z',
    },
  ]
  nextId = 5
}
