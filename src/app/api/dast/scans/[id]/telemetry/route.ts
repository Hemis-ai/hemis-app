import { NextRequest, NextResponse } from 'next/server'
import { getTelemetryEventsSince, getTelemetryStats } from '@/lib/dast/telemetry-store'

/**
 * GET /api/dast/scans/:id/telemetry — Live attack telemetry for the feed
 * Query: ?since=<cursor>&limit=<50>
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const since = parseInt(req.nextUrl.searchParams.get('since') || '0', 10)
    const limit = Math.min(parseInt(req.nextUrl.searchParams.get('limit') || '50', 10), 100)

    const { events, nextCursor } = getTelemetryEventsSince(id, since, limit)
    const stats = getTelemetryStats(id)

    return NextResponse.json({ events, stats, nextCursor })
  } catch (error) {
    console.error('GET /api/dast/scans/:id/telemetry error:', error)
    return NextResponse.json({ error: 'Failed to fetch telemetry' }, { status: 500 })
  }
}
