import { NextRequest, NextResponse } from 'next/server'
import { mockScan } from '@/lib/redteam/scanner'
import type { Finding } from '@/lib/types'

/**
 * GET /api/redteam/scan/:id
 * Poll scan status and retrieve findings
 */

interface ScanStatusResponse {
  scanId: string
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
  progress: number
  findings?: Finding[]
  error?: string
}

// Mock in-memory scan cache (in production, use database)
const scanCache = new Map<string, { status: string; findings: Finding[]; progress: number; target: string }>()

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
): Promise<NextResponse<ScanStatusResponse>> {
  try {
    const scanId = params.id

    // Validate scan ID format
    if (!scanId || !scanId.startsWith('scan_')) {
      return NextResponse.json(
        {
          scanId,
          status: 'FAILED',
          progress: 0,
          error: 'Invalid scan ID format',
        },
        { status: 400 }
      )
    }

    // Check cache
    let cached = scanCache.get(scanId)

    if (!cached) {
      // First poll — initialize scan
      cached = {
        status: 'RUNNING',
        findings: [],
        progress: 0,
        target: 'api.example.com', // Mock target
      }
      scanCache.set(scanId, cached)

      // Simulate async scan in background
      simulateScan(scanId)
    }

    const response: ScanStatusResponse = {
      scanId,
      status: cached.status as any,
      progress: cached.progress,
      ...(cached.status === 'COMPLETED' && { findings: cached.findings }),
    }

    return NextResponse.json(response)
  } catch (error) {
    console.error('[REDTEAM] Scan poll error:', error)
    return NextResponse.json(
      {
        scanId: params.id,
        status: 'FAILED',
        progress: 0,
        error: 'Internal server error',
      },
      { status: 500 }
    )
  }
}

/**
 * Simulate async scan execution
 * Updates cache as scan progresses
 */
async function simulateScan(scanId: string) {
  const cached = scanCache.get(scanId)
  if (!cached) return

  try {
    // Simulate scan progress
    for (let i = 0; i < 100; i += 25) {
      if (cached) {
        cached.progress = i
      }
      await new Promise(r => setTimeout(r, 800))
    }

    // Run actual mock scan
    const findings = await mockScan('api.example.com', ['10.0.0.0/8'])

    if (cached) {
      cached.findings = findings
      cached.progress = 100
      cached.status = 'COMPLETED'
    }

    console.log(`[REDTEAM] Scan completed: ${scanId}`, {
      findingsCount: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
    })
  } catch (error) {
    if (cached) {
      cached.status = 'FAILED'
    }
    console.error(`[REDTEAM] Scan failed: ${scanId}`, error)
  }
}
