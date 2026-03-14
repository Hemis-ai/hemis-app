import { NextRequest, NextResponse } from 'next/server'

/**
 * POST /api/redteam/scan
 * Start a new vulnerability scan
 * Requires authorization verification before execution
 */

interface ScanRequest {
  target: string
  scope: string[]
  engagementId: string
}

interface ScanResponse {
  scanId: string
  status: string
  target: string
  createdAt: string
  error?: string
}

export async function POST(request: NextRequest): Promise<NextResponse<ScanResponse>> {
  try {
    const body: ScanRequest = await request.json()

    // Validate required fields
    if (!body.target || !Array.isArray(body.scope) || !body.engagementId) {
      return NextResponse.json(
        {
          error: 'Missing required fields: target, scope, engagementId',
          scanId: '',
          status: 'FAILED',
          target: '',
          createdAt: '',
        },
        { status: 400 }
      )
    }

    // Authorization verification
    // In production, this would query database for authorization record
    if (!body.engagementId.trim()) {
      return NextResponse.json(
        {
          error: 'Engagement must be authorized before running scans',
          scanId: '',
          status: 'FAILED',
          target: '',
          createdAt: '',
        },
        { status: 403 }
      )
    }

    // Validate target format
    const urlPattern = /^(https?:\/\/)?[\w.-]+(\.\w+)+$/
    if (!urlPattern.test(body.target)) {
      return NextResponse.json(
        {
          error: 'Invalid target URL format',
          scanId: '',
          status: 'FAILED',
          target: '',
          createdAt: '',
        },
        { status: 400 }
      )
    }

    // Generate scan ID
    const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    const createdAt = new Date().toISOString()

    // Audit log
    console.log(`[REDTEAM] Scan initiated: ${scanId}`, {
      target: body.target,
      scope: body.scope,
      engagementId: body.engagementId,
      timestamp: createdAt,
    })

    return NextResponse.json({
      scanId,
      status: 'PENDING',
      target: body.target,
      createdAt,
    })
  } catch (error) {
    console.error('[REDTEAM] Scan error:', error)
    return NextResponse.json(
      {
        error: 'Internal server error',
        scanId: '',
        status: 'FAILED',
        target: '',
        createdAt: '',
      },
      { status: 500 }
    )
  }
}

// GET /api/redteam/scan — Not typically used, but can return info about active scans
export async function GET(): Promise<NextResponse> {
  return NextResponse.json({
    message: 'Use POST to start a new scan, or GET /api/redteam/scan/:id to poll results',
  })
}
