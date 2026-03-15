import { NextRequest, NextResponse } from 'next/server'

/**
 * GET /api/github/status
 * Check if the user has a valid GitHub OAuth access token.
 */
export async function GET(req: NextRequest) {
  try {
    const accessToken = req.cookies.get('github_access_token')?.value
    const githubUser = req.cookies.get('github_user')?.value

    if (!accessToken) {
      return NextResponse.json({ connected: false, reason: 'No access token' })
    }

    try {
      const user = githubUser ? JSON.parse(githubUser) : null
      
      return NextResponse.json({
        connected: true,
        accountLogin: user?.login || 'Authenticated User',
        avatarUrl: user?.avatar_url
      })
    } catch {
      return NextResponse.json({
        connected: false,
        reason: 'Invalid user data cookie'
      })
    }

  } catch (err) {
    console.error('[GitHub] Status check error:', err)
    return NextResponse.json({ connected: false, error: 'Internal error' })
  }
}
