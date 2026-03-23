// src/app/api/cloud/remediation/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const scan = (id === 'demo' || id === MOCK_CLOUD_SCAN.id) ? MOCK_CLOUD_SCAN : getScan(id)
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  return NextResponse.json({ remediationQueue: scan.remediationQueue })
}
