import { NextRequest, NextResponse } from 'next/server'
import { prisma, isDatabaseReachable } from '@/lib/db'

/**
 * GET /auth/github/callback
 * Handles the OAuth callback from GitHub.
 * Validates the state parameter, exchanges the code for an access token,
 * fetches the user profile, and stores the connection.
 */
export async function GET(req: NextRequest) {
  try {
    const searchParams = req.nextUrl.searchParams
    const code = searchParams.get('code')
    const state = searchParams.get('state')

    // 1. Validate the state parameter to prevent CSRF attacks
    const savedState = req.cookies.get('github_oauth_state')?.value

    if (!state || !savedState || state !== savedState) {
      console.error('[GitHub OAuth] CSRF validation failed. State mismatch.')
      return NextResponse.redirect(new URL('/dashboard/sast?github=error&reason=csrf_failed', req.url))
    }

    if (!code) {
      console.error('[GitHub OAuth] Authorization code missing.')
      return NextResponse.redirect(new URL('/dashboard/sast?github=error&reason=no_code', req.url))
    }

    const clientId = process.env.GITHUB_CLIENT_ID
    const clientSecret = process.env.GITHUB_CLIENT_SECRET
    const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:7777'
    const redirectUri = `${appUrl}/auth/github/callback`

    if (!clientId || !clientSecret) {
      console.error('[GitHub OAuth] Missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET.')
      return NextResponse.redirect(new URL('/dashboard/sast?github=error&reason=missing_config', req.url))
    }

    // 2. Exchange the authorization code for an access token
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
      }),
    })

    if (!tokenRes.ok) {
      console.error(`[GitHub OAuth] Token exchange failed. Status: ${tokenRes.status}`)
      return NextResponse.redirect(new URL('/dashboard/sast?github=error&reason=token_failed', req.url))
    }

    const tokenData = await tokenRes.json()
    const accessToken = tokenData.access_token

    if (!accessToken) {
      console.error('[GitHub OAuth] No access token received from GitHub.', tokenData)
      return NextResponse.redirect(new URL('/dashboard/sast?github=error&reason=no_token', req.url))
    }

    // 3. Fetch the authenticated user's profile from GitHub
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
      },
    })

    if (!userRes.ok) {
      console.error(`[GitHub OAuth] User fetch failed. Status: ${userRes.status}`)
      return NextResponse.redirect(new URL('/dashboard/sast?github=error&reason=user_fetch_failed', req.url))
    }

    const githubUser = await userRes.json()
    
    // We now have the GitHub user profile:
    // { id: githubUser.id, login: githubUser.login, avatar_url: githubUser.avatar_url, email: githubUser.email }
    console.log(`[GitHub OAuth] Successfully authenticated user: ${githubUser.login}`)

    // 4. Securely store the access token as an HttpOnly cookie
    // In a production app, you might encrypt this token before storing it in the database and linking it to the Hemis user model, 
    // or keep it in an encrypted session cookie.
    
    const response = NextResponse.redirect(new URL('/dashboard/sast?github=connected', req.url))
    
    // Clear the CSRF state cookie
    response.cookies.delete('github_oauth_state')

    // Store the access token securely. Do NOT expose to JS.
    response.cookies.set('github_access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60 * 24 * 7 // 7 days
    })
    
    // Optionally expose public data to the frontend (NO TOKENS)
    response.cookies.set('github_user', JSON.stringify({
      login: githubUser.login,
      avatar_url: githubUser.avatar_url
    }), {
      httpOnly: false, // Frontend can read this for UI
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60 * 24 * 7
    })

    return response
    
  } catch (err) {
    console.error('[GitHub OAuth] Callback error:', err)
    return NextResponse.redirect(new URL('/dashboard/sast?github=error', req.url))
  }
}
