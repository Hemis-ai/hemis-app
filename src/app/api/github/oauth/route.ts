import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'

/**
 * GET /api/github/oauth
 * Initiates the GitHub OAuth flow by redirecting to GitHub's authorize URL.
 */
export async function GET(req: NextRequest) {
  const clientId = process.env.GITHUB_CLIENT_ID

  if (!clientId) {
    return NextResponse.json(
      { error: 'GITHUB_CLIENT_ID not configured' },
      { status: 500 },
    )
  }

  // Generate a random state parameter for CSRF protection
  const state = crypto.randomBytes(20).toString('hex')

  // Build the callback URL relative to the current origin
  const origin = req.nextUrl.origin
  const redirectUri = `${origin}/api/github/oauth/callback`

  // Scopes: read repos (public + private), read user profile
  const scopes = 'repo read:user'

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize')
  authorizeUrl.searchParams.set('client_id', clientId)
  authorizeUrl.searchParams.set('redirect_uri', redirectUri)
  authorizeUrl.searchParams.set('scope', scopes)
  authorizeUrl.searchParams.set('state', state)

  // Store state in a short-lived cookie for CSRF verification
  const response = NextResponse.redirect(authorizeUrl.toString())
  response.cookies.set('github_oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 600, // 10 minutes
    path: '/',
  })

  return response
}
