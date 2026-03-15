import { NextRequest, NextResponse } from 'next/server'
import {
  verifyRefreshToken,
  REFRESH_COOKIE,
  ACCESS_COOKIE,
} from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * POST /api/auth/logout
 * Clears auth cookies and revokes the refresh token in the DB.
 */
export async function POST(req: NextRequest) {
  const refreshToken = req.cookies.get(REFRESH_COOKIE)?.value

  if (refreshToken) {
    const payload = await verifyRefreshToken(refreshToken)
    if (payload) {
      const dbReachable = await isDatabaseReachable()
      if (dbReachable) {
        await prisma.refreshToken
          .updateMany({
            where: { token: payload.tokenId, userId: payload.userId, revokedAt: null },
            data:  { revokedAt: new Date() },
          })
          .catch(() => null) // non-critical
      }
    }
  }

  const res = NextResponse.json({ ok: true })
  res.cookies.set(ACCESS_COOKIE,  '', { maxAge: 0, path: '/' })
  res.cookies.set(REFRESH_COOKIE, '', { maxAge: 0, path: '/' })
  return res
}
