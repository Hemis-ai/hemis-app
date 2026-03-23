// src/app/api/cloud/findings/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const scan = (id === 'demo' || id === MOCK_CLOUD_SCAN.id) ? MOCK_CLOUD_SCAN : getScan(id)
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  return NextResponse.json({ findings: scan.findings })
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const { findingId, status } = await req.json()
    const validStatuses = ['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE']
    if (!validStatuses.includes(status)) return NextResponse.json({ error: 'Invalid status' }, { status: 400 })
    // In demo: just return success (in-memory update would go here)
    console.log(`[Cloud] Finding ${findingId} in scan ${id} status → ${status}`)
    return NextResponse.json({ success: true, findingId, status })
  } catch (err) {
    console.error('[Cloud] PATCH /api/cloud/findings/[id] error:', err)
    return NextResponse.json({ error: 'Failed to update finding' }, { status: 500 })
  }
}
