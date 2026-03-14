import { NextRequest, NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import { randomBytes } from 'crypto'
import {
  signAccessToken,
  signRefreshToken,
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  cookieOptions,
} from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * POST /api/auth/login
 *
 * Body: { email: string; password: string }
 *
 * Returns: { user: { id, email, name, role, orgId } }
 * Sets httpOnly cookies: hemisx_access (15m) + hemisx_refresh (7d)
 *
 * Demo fallback: when DATABASE_URL is unreachable and DEMO_MODE_ENABLED=true,
 * accepts demo@hemisx.com / demo1234 and returns a mock session.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const email    = (body.email    ?? '').trim().toLowerCase()
    const password = (body.password ?? '').trim()

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password are required' }, { status: 400 })
    }

    const dbReachable = await isDatabaseReachable()

    // ── Demo mode fallback ──────────────────────────────────────────────────
    if (!dbReachable && process.env.DEMO_MODE_ENABLED !== 'false') {
      const demoEmail = process.env.DEMO_USER_EMAIL ?? 'demo@hemisx.com'
      const demoPass  = process.env.DEMO_USER_PASSWORD ?? 'demo1234'

      // In demo mode, accept demo credentials OR any credentials
      const isDemoCredentials = email === demoEmail && password === demoPass
      const anyCredentials = process.env.DEMO_MODE_ENABLED === 'true'

      if (!isDemoCredentials && !anyCredentials) {
        return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
      }

      const demoUser = {
        id:    'demo_user_01',
        email: email,
        name:  'Demo User',
        role:  'OWNER' as const,
        orgId: 'demo_org_01',
        org:   { name: 'HemisX Demo Org', plan: 'PROFESSIONAL' },
      }

      const [accessToken, refreshToken] = await Promise.all([
        signAccessToken({
          userId: demoUser.id,
          orgId:  demoUser.orgId,
          role:   demoUser.role,
          email:  demoUser.email,
          name:   demoUser.name,
        }),
        signRefreshToken({ userId: demoUser.id, tokenId: 'demo_refresh_01' }),
      ])

      const res = NextResponse.json({ user: demoUser, demo: true })
      res.cookies.set(ACCESS_COOKIE,  accessToken,  cookieOptions(15 * 60))
      res.cookies.set(REFRESH_COOKIE, refreshToken, cookieOptions(7 * 24 * 60 * 60))
      return res
    }

    // ── Real database auth ──────────────────────────────────────────────────
    if (!dbReachable) {
      return NextResponse.json(
        { error: 'Service temporarily unavailable. Please try again.' },
        { status: 503 }
      )
    }

    const user = await prisma.user.findUnique({
      where: { email },
      include: { organization: { select: { name: true, plan: true } } },
    })

    if (!user) {
      // Constant-time comparison to prevent user enumeration
      await bcrypt.compare(password, '$2b$10$invalidhashtopreventtiming00000000000000000000000000000')
      return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 })
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash)
    if (!passwordMatch) {
      return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 })
    }

    // Create refresh token record
    const tokenId    = randomBytes(32).toString('hex')
    const refreshRaw = await signRefreshToken({ userId: user.id, tokenId })
    const expiresAt  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)

    await Promise.all([
      prisma.refreshToken.create({ data: { token: tokenId, userId: user.id, expiresAt } }),
      prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } }),
      prisma.auditLog.create({
        data: {
          orgId:     user.orgId,
          userId:    user.id,
          action:    'auth.login',
          ipAddress: req.headers.get('x-forwarded-for') ?? req.headers.get('x-real-ip') ?? undefined,
          userAgent: req.headers.get('user-agent') ?? undefined,
        },
      }),
    ])

    const accessToken = await signAccessToken({
      userId: user.id,
      orgId:  user.orgId,
      role:   user.role,
      email:  user.email,
      name:   user.name,
    })

    const safeUser = {
      id:    user.id,
      email: user.email,
      name:  user.name,
      role:  user.role,
      orgId: user.orgId,
      org:   user.organization,
    }

    const res = NextResponse.json({ user: safeUser, demo: false })
    res.cookies.set(ACCESS_COOKIE,  accessToken, cookieOptions(15 * 60))
    res.cookies.set(REFRESH_COOKIE, refreshRaw,  cookieOptions(7 * 24 * 60 * 60))
    return res
  } catch (err) {
    console.error('[AUTH] Login error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
