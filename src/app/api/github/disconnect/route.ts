import { NextResponse } from 'next/server'

/**
 * POST /api/github/disconnect
 * Clears GitHub OAuth cookies, effectively disconnecting the account.
 */
export async function POST() {
  const response = NextResponse.json({ disconnected: true })

  response.cookies.delete('github_access_token')
  response.cookies.delete('github_user')

  return response
}
