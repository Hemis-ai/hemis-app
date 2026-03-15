import { NextResponse } from 'next/server'
import crypto from 'crypto'

/**
 * GET /api/auth/github/init
 * Initiates the GitHub OAuth flow.
 * Redirects the user to GitHub's authorization endpoint with a CSRF state token.
 */
export async function GET() {
  const clientId = process.env.GITHUB_CLIENT_ID
  
  if (!clientId) {
    return NextResponse.json({ error: 'GITHUB_CLIENT_ID is not configured' }, { status: 500 })
  }

  // 1. Generate a random state string for CSRF protection
  const state = crypto.randomBytes(16).toString('hex')
  
  // 2. Determine the application URL to build the redirect URI
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:7777'
  const redirectUri = `${appUrl}/auth/github/callback`

  // 3. Construct the GitHub Authorization URL
  const githubAuthUrl = new URL('https://github.com/login/oauth/authorize')
  githubAuthUrl.searchParams.append('client_id', clientId)
  githubAuthUrl.searchParams.append('redirect_uri', redirectUri)
  githubAuthUrl.searchParams.append('scope', 'user repo')
  githubAuthUrl.searchParams.append('state', state)

  // 4. Return the redirect response
  const response = NextResponse.redirect(githubAuthUrl.toString())
  
  // 5. Store the state securely in an HTTP-only cookie
  response.cookies.set('github_oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 10 // 10 minutes valid
  })

  return response
}
