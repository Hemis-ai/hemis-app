// src/app/api/cloud/scans/[id]/progress/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { progressStore } from '@/lib/cloud-scanner/scan-orchestrator'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const progress = progressStore.get(id) ?? { scanId: id, status: 'CREATED', progress: 0, currentPhase: 'created', message: 'Scan created', timestamp: new Date().toISOString() }
  return NextResponse.json({ progress })
}
