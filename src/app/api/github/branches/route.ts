import { NextRequest, NextResponse } from 'next/server'

const GITHUB_API = 'https://api.github.com'

function ghHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  }
}

/**
 * GET /api/github/branches?owner=xxx&repo=yyy
 * List all branches for a given repository.
 */
export async function GET(req: NextRequest) {
  const accessToken = req.cookies.get('github_access_token')?.value
  if (!accessToken) {
    return NextResponse.json({ error: 'GitHub not connected' }, { status: 401 })
  }

  const owner = req.nextUrl.searchParams.get('owner')
  const repo  = req.nextUrl.searchParams.get('repo')

  if (!owner || !repo) {
    return NextResponse.json({ error: 'owner and repo are required' }, { status: 400 })
  }

  try {
    // Fetch up to 100 branches (covers most repos)
    const res = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/branches?per_page=100`,
      { headers: ghHeaders(accessToken) },
    )

    if (!res.ok) {
      const body = await res.text()
      return NextResponse.json({ error: `GitHub API error: ${res.status}`, detail: body }, { status: 502 })
    }

    const data = await res.json()

    // Also get the default branch from the repo
    const repoRes = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}`,
      { headers: ghHeaders(accessToken) },
    )
    const repoData = repoRes.ok ? await repoRes.json() : null
    const defaultBranch = repoData?.default_branch ?? null

    const branches: string[] = (Array.isArray(data) ? data : []).map(
      (b: { name: string }) => b.name,
    )

    // Sort: default branch first, then alphabetically
    branches.sort((a, b) => {
      if (a === defaultBranch) return -1
      if (b === defaultBranch) return 1
      return a.localeCompare(b)
    })

    return NextResponse.json({ branches, defaultBranch })
  } catch (err) {
    console.error('[GitHub] Branches error:', err)
    return NextResponse.json({ error: 'Failed to fetch branches' }, { status: 500 })
  }
}
