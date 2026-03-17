import { NextResponse } from 'next/server'
import { isDatabaseReachable } from '@/lib/db'
import { isDastEngineRunning, DAST_ENGINE_URL } from '@/lib/dast/engine-proxy'

export async function GET() {
  const [dbOk, engineOk] = await Promise.all([
    isDatabaseReachable(),
    isDastEngineRunning(),
  ])

  const status = engineOk || dbOk ? 'healthy' : 'degraded'

  return NextResponse.json({
    status,
    services: {
      database: dbOk ? 'connected' : 'disconnected',
      dastEngine: engineOk ? 'connected' : 'disconnected',
      dastEngineUrl: DAST_ENGINE_URL,
    },
    timestamp: new Date().toISOString(),
  }, { status: status === 'healthy' ? 200 : 503 })
}
