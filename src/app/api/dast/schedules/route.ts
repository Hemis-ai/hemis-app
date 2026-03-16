import { NextRequest, NextResponse } from 'next/server'
import {
  listSchedules,
  createSchedule,
  updateScheduleStatus,
  deleteSchedule,
  seedDemoSchedules,
  type CreateScheduleInput,
  type ScheduleFrequency,
  type ScheduleStatus,
} from '@/lib/dast/scheduling/scheduler'

const VALID_FREQUENCIES: ScheduleFrequency[] = ['daily', 'weekly', 'biweekly', 'monthly', 'quarterly']
const VALID_STATUSES: ScheduleStatus[] = ['active', 'paused', 'disabled']

/**
 * GET /api/dast/schedules — List all scan schedules
 */
export async function GET() {
  seedDemoSchedules()
  const schedules = listSchedules()
  return NextResponse.json({ schedules })
}

/**
 * POST /api/dast/schedules — Create a new schedule, update status, or delete
 * Body for create: { action: 'create', name, targetUrl, scanProfile, frequency, authConfigJson?, scopeInclude?, scopeExclude? }
 * Body for update: { action: 'update', id, status }
 * Body for delete: { action: 'delete', id }
 */
export async function POST(req: NextRequest) {
  try {
    seedDemoSchedules()
    const body = await req.json()
    const { action } = body

    if (action === 'create') {
      const { name, targetUrl, scanProfile, frequency, authConfigJson, scopeInclude, scopeExclude } = body
      if (!name?.trim() || !targetUrl?.trim()) {
        return NextResponse.json({ error: 'Name and target URL are required' }, { status: 400 })
      }
      if (!VALID_FREQUENCIES.includes(frequency)) {
        return NextResponse.json({ error: `Invalid frequency. Use: ${VALID_FREQUENCIES.join(', ')}` }, { status: 400 })
      }
      const input: CreateScheduleInput = {
        name: name.trim(),
        targetUrl: targetUrl.trim(),
        scanProfile: scanProfile || 'full',
        frequency,
        authConfigJson: authConfigJson || null,
        scopeInclude: scopeInclude || [],
        scopeExclude: scopeExclude || [],
      }
      const schedule = createSchedule(input)
      return NextResponse.json({ schedule }, { status: 201 })
    }

    if (action === 'update') {
      const { id, status } = body
      if (!id) return NextResponse.json({ error: 'Schedule ID is required' }, { status: 400 })
      if (!VALID_STATUSES.includes(status)) {
        return NextResponse.json({ error: `Invalid status. Use: ${VALID_STATUSES.join(', ')}` }, { status: 400 })
      }
      const schedule = updateScheduleStatus(id, status)
      if (!schedule) return NextResponse.json({ error: 'Schedule not found' }, { status: 404 })
      return NextResponse.json({ schedule })
    }

    if (action === 'delete') {
      const { id } = body
      if (!id) return NextResponse.json({ error: 'Schedule ID is required' }, { status: 400 })
      const deleted = deleteSchedule(id)
      if (!deleted) return NextResponse.json({ error: 'Schedule not found' }, { status: 404 })
      return NextResponse.json({ success: true })
    }

    return NextResponse.json({ error: 'Invalid action. Use: create, update, delete' }, { status: 400 })
  } catch (error) {
    console.error('POST /api/dast/schedules error:', error)
    return NextResponse.json({ error: 'Failed to process schedule request' }, { status: 500 })
  }
}
