import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /api/github/status
 * Check if GitHub App is connected for the current org.
 */
export async function GET(req: NextRequest) {
  try {
    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null

    if (!payload) {
      return NextResponse.json({ connected: false, reason: 'Not authenticated' })
    }

    const dbReachable = await isDatabaseReachable()
    if (!dbReachable) {
      return NextResponse.json({
        connected: false,
        reason: 'Database not available',
        demoMode: true,
      })
    }

    const installation = await prisma.gitHubInstallation.findFirst({
      where: { orgId: payload.orgId },
    })

    if (installation) {
      return NextResponse.json({
        connected:      true,
        installationId: installation.installationId,
        accountLogin:   installation.accountLogin,
        connectedAt:    installation.createdAt,
      })
    }

    return NextResponse.json({ connected: false })
  } catch (err) {
    console.error('[GitHub] Status check error:', err)
    return NextResponse.json({ connected: false, error: 'Internal error' })
  }
}
