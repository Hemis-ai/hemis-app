// src/app/api/cloud/scans/[id]/run/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan, runScan, progressStore } from '@/lib/cloud-scanner/scan-orchestrator'

export async function POST(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const scan = getScan(id)
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
    const progress = progressStore.get(id)
    if (progress && !['COMPLETED', 'FAILED', 'CREATED'].includes(progress.status)) {
      return NextResponse.json({ error: 'Scan already running' }, { status: 409 })
    }
    // Fire and forget
    runScan(id).catch(err => console.error('[Cloud] runScan error:', err))
    return NextResponse.json({ message: 'Scan started', scanId: id }, { status: 202 })
  } catch (err) {
    console.error('[Cloud] POST /api/cloud/scans/[id]/run error:', err)
    return NextResponse.json({ error: 'Failed to start scan' }, { status: 500 })
  }
}
