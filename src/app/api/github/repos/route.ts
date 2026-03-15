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
 * GET /api/github/repos
 * List repositories accessible through the GitHub OAuth token.
 */
export async function GET(req: NextRequest) {
  try {
    const accessToken = req.cookies.get('github_access_token')?.value

    if (!accessToken) {
      return NextResponse.json({ error: 'GitHub not connected', connected: false }, { status: 401 })
    }

    // List repos accessible to this user
    // We request user's repos. Including affiliations to get org repos too.
    const res = await fetch(
      `${GITHUB_API}/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member`,
      { headers: ghHeaders(accessToken) },
    )

    if (!res.ok) {
      const body = await res.text()
      return NextResponse.json({ error: `GitHub API error: ${res.status}`, detail: body }, { status: 502 })
    }

    const data = await res.json()
    const repos = (Array.isArray(data) ? data : []).map((r: any) => ({
      id:           r.id,
      name:         r.name,
      full_name:    r.full_name,
      private:      r.private,
      language:     r.language,
      default_branch: r.default_branch,
      updated_at:   r.updated_at,
      html_url:     r.html_url,
    }))

    return NextResponse.json({
      repos,
      total: repos.length,
    })
  } catch (err) {
    console.error('[GitHub] Repos list error:', err)
    return NextResponse.json({ error: 'Failed to list repos' }, { status: 500 })
  }
}

/**
 * POST /api/github/repos
 * Fetch files from a specific repo+branch for SAST scanning using OAuth Token.
 * Body: { owner, repo, branch?, path? }
 */
export async function POST(req: NextRequest) {
  try {
    const accessToken = req.cookies.get('github_access_token')?.value

    if (!accessToken) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 401 })
    }

    const body = await req.json()
    const { owner, repo, branch, path: treePath } = body as {
      owner: string
      repo: string
      branch?: string
      path?: string
    }

    if (!owner || !repo) {
      return NextResponse.json({ error: 'owner and repo are required' }, { status: 400 })
    }

    // Resolve the branch (default if not specified)
    const ref = branch || 'HEAD'

    // Get the repo tree recursively
    const treeUrl = treePath
      ? `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`
      : `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`

    const treeRes = await fetch(treeUrl, { headers: ghHeaders(accessToken) })
    
    if (!treeRes.ok) {
      // Sometimes HEAD requires branch resolution. If tree fails, try getting default branch
      if (ref === 'HEAD') {
        const repoRes = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers: ghHeaders(accessToken) })
        if (repoRes.ok) {
          const repoData = await repoRes.json()
          const defaultBranch = repoData.default_branch
          const fallbackTreeRes = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`, { headers: ghHeaders(accessToken) })
          if (!fallbackTreeRes.ok) {
            return NextResponse.json({ error: `Failed to fetch tree: ${fallbackTreeRes.status}` }, { status: 502 })
          }
          return await processTreeResponse(fallbackTreeRes, owner, repo, defaultBranch, treePath, accessToken)
        }
      }
      return NextResponse.json({ error: `Failed to fetch tree: ${treeRes.status}` }, { status: 502 })
    }

    return await processTreeResponse(treeRes, owner, repo, ref, treePath, accessToken)

  } catch (err) {
    console.error('[GitHub] Repo files error:', err)
    return NextResponse.json({ error: 'Failed to fetch repo files' }, { status: 500 })
  }
}

async function processTreeResponse(treeRes: Response, owner: string, repo: string, ref: string, treePath: string | undefined, token: string) {
  const treeData = await treeRes.json()

  // Filter to scannable source files
  const SCANNABLE_EXTENSIONS = [
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.py', '.php', '.java', '.go', '.rb', '.cs',
    '.json', '.yaml', '.yml', '.toml', '.mod',
  ]
  const MANIFEST_FILES = [
    'package.json', 'package-lock.json', 'yarn.lock',
    'requirements.txt', 'Pipfile', 'Pipfile.lock',
    'go.mod', 'go.sum', 'Gemfile', 'Gemfile.lock',
    'composer.json', 'composer.lock', 'pom.xml', 'build.gradle',
  ]

  const SKIP_DIRS = ['node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__', '.next', 'coverage']

  const candidateFiles = (treeData.tree ?? [])
    .filter((item: { type: string; path: string; size?: number }) => {
      if (item.type !== 'blob') return false
      // Skip large files (> 500KB)
      if (item.size && item.size > 500_000) return false
      // Skip directories we don't want
      if (SKIP_DIRS.some(d => item.path.startsWith(d + '/') || item.path.includes('/' + d + '/'))) return false
      // Filter by subpath if specified
      if (treePath && !item.path.startsWith(treePath)) return false
      // Check if it's a scannable file
      const basename = item.path.split('/').pop() ?? ''
      const ext = '.' + basename.split('.').pop()
      return SCANNABLE_EXTENSIONS.includes(ext) || MANIFEST_FILES.includes(basename)
    })
    .slice(0, 50) // Limit to 50 files per scan

  // Fetch content for each file in parallel (batches of 10)
  const files: { path: string; content: string }[] = []
  const batchSize = 10
  for (let i = 0; i < candidateFiles.length; i += batchSize) {
    const batch = candidateFiles.slice(i, i + batchSize)
    const results = await Promise.allSettled(
      batch.map(async (item: { path: string }) => {
        const contentRes = await fetch(
          `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(item.path)}?ref=${ref}`,
          { 
            headers: { 
              Authorization: `Bearer ${token}`,
              Accept: 'application/vnd.github.raw',
              'X-GitHub-Api-Version': '2022-11-28'
            } 
          },
        )
        if (!contentRes.ok) return null
        const content = await contentRes.text()
        return { path: item.path, content }
      }),
    )
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        files.push(r.value)
      }
    }
  }

  return NextResponse.json({
    files,
    repo: `${owner}/${repo}`,
    branch: ref,
    totalInTree: candidateFiles.length,
    fetched: files.length,
  })
}
