// src/app/api/cloud/scans/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { createScan, listScans } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function POST(req: NextRequest) {
  try {
    const { connectionId, accountId, accountAlias } = await req.json()
    const scan = createScan(connectionId ?? 'conn-demo', accountId ?? '123456789012', accountAlias ?? 'acme-production')
    console.log(`[Cloud] Scan created: ${scan.id}`)
    return NextResponse.json({ scan }, { status: 201 })
  } catch (err) {
    console.error('[Cloud] POST /api/cloud/scans error:', err)
    return NextResponse.json({ error: 'Failed to create scan' }, { status: 500 })
  }
}

export async function GET() {
  try {
    const scans = listScans()
    // In demo mode with no scans, return mock
    if (scans.length === 0) return NextResponse.json({ scans: [MOCK_CLOUD_SCAN] })
    return NextResponse.json({ scans })
  } catch (err) {
    console.error('[Cloud] GET /api/cloud/scans error:', err)
    return NextResponse.json({ scans: [MOCK_CLOUD_SCAN] })
  }
}
