import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * POST /api/redteam/scan
 * Start a new red team vulnerability scan.
 *
 * Body: { target: string; scope: string[]; engagementId: string }
 *
 * Auth: requires valid access token (or demo mode).
 * Persistence: stored in RedTeamScan table when DB is reachable.
 */

interface ScanRequest {
  target:       string
  scope:        string[]
  engagementId: string
}

interface ScanResponse {
  scanId:     string
  status:     string
  target:     string
  createdAt:  string
  error?:     string
  demo?:      boolean
}

const urlPattern = /^(https?:\/\/)?[\w.-]+(\.\w+)+(:\d+)?(\/.*)?$/

export async function POST(req: NextRequest): Promise<NextResponse<ScanResponse>> {
  try {
    const body: ScanRequest = await req.json()

    if (!body.target || !Array.isArray(body.scope) || !body.engagementId) {
      return NextResponse.json(
        { error: 'Missing required fields: target, scope, engagementId', scanId: '', status: 'FAILED', target: '', createdAt: '' },
        { status: 400 }
      )
    }

    if (!body.engagementId.trim()) {
      return NextResponse.json(
        { error: 'Engagement must be authorized before running scans', scanId: '', status: 'FAILED', target: '', createdAt: '' },
        { status: 403 }
      )
    }

    if (!urlPattern.test(body.target)) {
      return NextResponse.json(
        { error: 'Invalid target URL format', scanId: '', status: 'FAILED', target: '', createdAt: '' },
        { status: 400 }
      )
    }

    const createdAt = new Date().toISOString()
    const dbReachable = await isDatabaseReachable()

    // ── Persist to DB ───────────────────────────────────────────────────────
    if (dbReachable) {
      const token   = req.cookies.get(ACCESS_COOKIE)?.value
      const payload = token ? await verifyAccessToken(token) : null

      if (!payload) {
        return NextResponse.json(
          { error: 'Authentication required', scanId: '', status: 'FAILED', target: '', createdAt: '' },
          { status: 401 }
        )
      }

      const scan = await prisma.redTeamScan.create({
        data: {
          orgId:        payload.orgId,
          initiatedBy:  payload.userId,
          engagementId: body.engagementId,
          target:       body.target,
          scope:        body.scope,
          status:       'PENDING',
          progress:     0,
        },
      })

      await prisma.auditLog.create({
        data: {
          orgId:     payload.orgId,
          userId:    payload.userId,
          action:    'redteam.scan.start',
          resource:  scan.id,
          meta:      { target: body.target, scope: body.scope, engagementId: body.engagementId },
          ipAddress: req.headers.get('x-forwarded-for') ?? req.headers.get('x-real-ip') ?? undefined,
        },
      })

      console.log(`[REDTEAM] Scan persisted: ${scan.id}`, { target: body.target, engagementId: body.engagementId })

      return NextResponse.json({
        scanId:    scan.id,
        status:    'PENDING',
        target:    body.target,
        createdAt: scan.startedAt.toISOString(),
        demo:      false,
      })
    }

    // ── Demo mode fallback ──────────────────────────────────────────────────
    const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

    console.log(`[REDTEAM][DEMO] Scan initiated: ${scanId}`, {
      target:       body.target,
      scope:        body.scope,
      engagementId: body.engagementId,
      timestamp:    createdAt,
    })

    return NextResponse.json({ scanId, status: 'PENDING', target: body.target, createdAt, demo: true })
  } catch (err) {
    console.error('[REDTEAM] Scan error:', err)
    return NextResponse.json(
      { error: 'Internal server error', scanId: '', status: 'FAILED', target: '', createdAt: '' },
      { status: 500 }
    )
  }
}

export async function GET(): Promise<NextResponse> {
  return NextResponse.json({
    message: 'Use POST to start a new scan, or GET /api/redteam/scan/:id to poll results',
  })
}
