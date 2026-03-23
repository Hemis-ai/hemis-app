// src/app/api/cloud/scans/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    if (id === 'demo' || id === MOCK_CLOUD_SCAN.id) return NextResponse.json({ scan: MOCK_CLOUD_SCAN })
    const scan = getScan(id)
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
    return NextResponse.json({ scan })
  } catch (err) {
    console.error('[Cloud] GET /api/cloud/scans/[id] error:', err)
    return NextResponse.json({ scan: MOCK_CLOUD_SCAN })
  }
}
