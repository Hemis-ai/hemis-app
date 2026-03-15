import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /api/github/install
 * Handles the post-installation redirect from GitHub.
 * Stores the installation ID linked to the user's organization.
 */
export async function GET(req: NextRequest) {
  try {
    const installationId = req.nextUrl.searchParams.get('installation_id')
    const setupAction    = req.nextUrl.searchParams.get('setup_action')

    if (!installationId) {
      return NextResponse.redirect(new URL('/dashboard/sast?github=error&reason=no_installation_id', req.url))
    }

    // Get authenticated user
    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null

    if (!payload) {
      // Store installation_id in a cookie so we can link after login
      const response = NextResponse.redirect(new URL('/login?redirect=/api/github/install&installation_id=' + installationId, req.url))
      return response
    }

    // Store installation in database
    const dbReachable = await isDatabaseReachable()
    if (dbReachable) {
      await prisma.gitHubInstallation.upsert({
        where: { installationId: parseInt(installationId) },
        create: {
          orgId:          payload.orgId,
          installationId: parseInt(installationId),
          accountLogin:   '', // Will be populated on first webhook
          accountType:    'Organization',
        },
        update: {
          orgId: payload.orgId,
        },
      })

      await prisma.auditLog.create({
        data: {
          orgId:    payload.orgId,
          userId:   payload.userId,
          action:   'github.app.installed',
          resource: installationId,
          meta:     { setupAction },
        },
      }).catch(() => null)
    }

    console.log(`[GitHub] App installed: installation=${installationId}, org=${payload.orgId}, action=${setupAction}`)

    return NextResponse.redirect(new URL('/dashboard/sast?github=connected', req.url))
  } catch (err) {
    console.error('[GitHub] Install callback error:', err)
    return NextResponse.redirect(new URL('/dashboard/sast?github=error', req.url))
  }
}
