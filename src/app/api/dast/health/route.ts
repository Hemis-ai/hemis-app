import { NextResponse } from 'next/server'
import { isDatabaseReachable } from '@/lib/db'

export async function GET() {
  const dbOk = await isDatabaseReachable()

  let zapOk = false
  try {
    const zapUrl = process.env.ZAP_URL || 'http://localhost:8090'
    const res = await fetch(`${zapUrl}/JSON/core/view/version/`, { signal: AbortSignal.timeout(5000) })
    zapOk = res.ok
  } catch { /* ZAP not running */ }

  const status = dbOk ? 'healthy' : 'degraded'

  return NextResponse.json({
    status,
    services: { database: dbOk ? 'connected' : 'disconnected', zap: zapOk ? 'connected' : 'disconnected' },
    timestamp: new Date().toISOString(),
  }, { status: status === 'healthy' ? 200 : 503 })
}
