import { NextRequest, NextResponse } from 'next/server'

/**
 * GET /api/github/oauth/callback
 * Handles the OAuth callback from GitHub.
 * Exchanges the authorization code for an access token,
 * fetches the user profile, and stores both in httpOnly cookies.
 */
export async function GET(req: NextRequest) {
  const code  = req.nextUrl.searchParams.get('code')
  const state = req.nextUrl.searchParams.get('state')
  const error = req.nextUrl.searchParams.get('error')

  // Handle denied / cancelled authorization
  if (error) {
    console.error('[GitHub OAuth] Authorization error:', error)
    return NextResponse.redirect(
      new URL('/dashboard/hemis/sast?github=error&reason=' + encodeURIComponent(error), req.url),
    )
  }

  if (!code) {
    return NextResponse.redirect(
      new URL('/dashboard/hemis/sast?github=error&reason=no_code', req.url),
    )
  }

  // Verify CSRF state
  const savedState = req.cookies.get('github_oauth_state')?.value
  if (!savedState || savedState !== state) {
    console.error('[GitHub OAuth] State mismatch — possible CSRF')
    return NextResponse.redirect(
      new URL('/dashboard/hemis/sast?github=error&reason=state_mismatch', req.url),
    )
  }

  const clientId     = process.env.GITHUB_CLIENT_ID
  const clientSecret = process.env.GITHUB_CLIENT_SECRET

  if (!clientId || !clientSecret) {
    return NextResponse.redirect(
      new URL('/dashboard/hemis/sast?github=error&reason=missing_config', req.url),
    )
  }

  try {
    // ── Step 1: Exchange code for access token ──────────────────────────────
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id:     clientId,
        client_secret: clientSecret,
        code,
        redirect_uri:  `${process.env.NEXT_PUBLIC_APP_URL?.replace(/\/$/, '') || req.nextUrl.origin}/api/github/oauth/callback`,
      }),
    })

    if (!tokenRes.ok) {
      console.error('[GitHub OAuth] Token exchange failed:', tokenRes.status)
      return NextResponse.redirect(
        new URL('/dashboard/hemis/sast?github=error&reason=token_exchange_failed', req.url),
      )
    }

    const tokenData = await tokenRes.json()

    if (tokenData.error) {
      console.error('[GitHub OAuth] Token error:', tokenData.error, tokenData.error_description)
      return NextResponse.redirect(
        new URL('/dashboard/hemis/sast?github=error&reason=' + encodeURIComponent(tokenData.error), req.url),
      )
    }

    const accessToken = tokenData.access_token
    if (!accessToken) {
      return NextResponse.redirect(
        new URL('/dashboard/hemis/sast?github=error&reason=no_access_token', req.url),
      )
    }

    // ── Step 2: Fetch user profile ──────────────────────────────────────────
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    })

    let userData = { login: 'unknown', avatar_url: '' }
    if (userRes.ok) {
      const u = await userRes.json()
      userData = { login: u.login, avatar_url: u.avatar_url }
    }

    // ── Step 3: Set cookies and redirect to SAST page ───────────────────────
    const response = NextResponse.redirect(
      new URL('/dashboard/hemis/sast?github=connected', req.url),
    )

    // Store access token in httpOnly cookie (not accessible from JS)
    response.cookies.set('github_access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 8, // 8 hours
      path: '/',
    })

    // Store minimal user info (readable from client for display)
    response.cookies.set('github_user', JSON.stringify(userData), {
      httpOnly: false, // client needs to read this for avatar/name
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 8,
      path: '/',
    })

    // Clear the CSRF state cookie
    response.cookies.delete('github_oauth_state')

    console.log(`[GitHub OAuth] Authenticated: ${userData.login}`)

    return response
  } catch (err) {
    console.error('[GitHub OAuth] Callback error:', err)
    return NextResponse.redirect(
      new URL('/dashboard/hemis/sast?github=error&reason=internal_error', req.url),
    )
  }
}
