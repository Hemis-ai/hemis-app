import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE, REFRESH_COOKIE } from '@/lib/auth/jwt'

/**
 * HemisX route protection middleware.
 *
 * Public routes (no auth required):
 *   /login, /api/auth/*
 *
 * Protected routes (require valid access token):
 *   /dashboard/*, /api/* (except /api/auth/*)
 *
 * Demo mode: if no token is present but DEMO_MODE_ENABLED=true,
 * dashboard routes are allowed through (token verified client-side).
 */

const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/logout']

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '/'))
}

function isDashboardPath(pathname: string): boolean {
  return pathname.startsWith('/dashboard') || pathname.startsWith('/api/')
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl

  // Always allow public paths
  if (isPublic(pathname)) return NextResponse.next()

  // Only guard dashboard & API paths
  if (!isDashboardPath(pathname)) return NextResponse.next()

  const accessToken  = req.cookies.get(ACCESS_COOKIE)?.value
  const refreshToken = req.cookies.get(REFRESH_COOKIE)?.value

  // Valid access token — allow through
  if (accessToken) {
    const payload = await verifyAccessToken(accessToken)
    if (payload) return NextResponse.next()
  }

  // No or expired access token — check demo mode
  const demoMode = process.env.DEMO_MODE_ENABLED !== 'false'

  if (demoMode && refreshToken) {
    // Allow through in demo mode; client will handle re-auth
    return NextResponse.next()
  }

  if (demoMode && !accessToken && !refreshToken) {
    // Demo: no tokens at all — redirect to login (but don't block API calls)
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })
    }
    return NextResponse.redirect(new URL('/login', req.url))
  }

  // Production: no valid token → redirect to login
  if (pathname.startsWith('/api/')) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })
  }
  return NextResponse.redirect(new URL('/login', req.url))
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/api/((?!auth).+)',
  ],
}
