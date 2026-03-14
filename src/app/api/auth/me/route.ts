import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /api/auth/me
 * Returns the currently authenticated user from the access token.
 */
export async function GET(req: NextRequest) {
  const token = req.cookies.get(ACCESS_COOKIE)?.value

  if (!token) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })
  }

  const payload = await verifyAccessToken(token)
  if (!payload) {
    return NextResponse.json({ error: 'Token invalid or expired' }, { status: 401 })
  }

  // Lightweight response from the token itself (no DB needed for most requests)
  const baseUser = {
    id:    payload.userId,
    email: payload.email,
    name:  payload.name,
    role:  payload.role,
    orgId: payload.orgId,
  }

  // Optionally enrich with live DB data
  const dbReachable = await isDatabaseReachable()
  if (dbReachable) {
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: {
        id: true, email: true, name: true, role: true, orgId: true, lastLoginAt: true,
        organization: { select: { name: true, plan: true, slug: true } },
      },
    })
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }
    return NextResponse.json({ user })
  }

  return NextResponse.json({ user: baseUser, demo: true })
}
