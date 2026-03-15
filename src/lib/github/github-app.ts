// HemisX — GitHub App Integration
// Handles GitHub App authentication (JWT + installation tokens) and provides
// typed helpers for the GitHub REST API. Uses plain fetch (no Octokit) to
// keep the bundle small for Vercel serverless.

import { SignJWT } from 'jose'
import type { SastFindingResult, SastSeverity } from '@/lib/types/sast'

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GitHubInstallation {
  id:       number
  account:  { login: string; type: string }
}

export interface GitHubCheckRun {
  id:          number
  status:      string
  conclusion:  string | null
  html_url:    string
}

export interface GitHubPRFile {
  filename:  string
  status:    string
  raw_url:   string
  patch?:    string
  additions: number
  deletions: number
}

interface CheckAnnotation {
  path:             string
  start_line:       number
  end_line:         number
  annotation_level: 'failure' | 'warning' | 'notice'
  message:          string
  title:            string
}

// ─── Config ─────────────────────────────────────────────────────────────────

const GITHUB_API = 'https://api.github.com'

function getAppConfig() {
  const appId      = process.env.GITHUB_APP_ID
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY
  const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET
  return { appId, privateKey, webhookSecret }
}

// ─── JWT Generation ─────────────────────────────────────────────────────────

/**
 * Generate a JWT for GitHub App authentication.
 * Valid for 10 minutes as per GitHub's requirements.
 */
export async function generateAppJWT(): Promise<string> {
  const { appId, privateKey } = getAppConfig()
  if (!appId || !privateKey) {
    throw new Error('GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set')
  }

  // The private key may come as a base64-encoded string in env vars
  const key = privateKey.includes('BEGIN') ? privateKey : Buffer.from(privateKey, 'base64').toString('utf8')

  const now = Math.floor(Date.now() / 1000)
  const jwt = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt(now - 60) // 60 seconds in the past to account for clock drift
    .setExpirationTime(now + 600) // 10 minutes
    .setIssuer(appId)
    .sign(await importPKCS8Key(key))

  return jwt
}

async function importPKCS8Key(pem: string): Promise<CryptoKey> {
  const pemContents = pem
    .replace(/-----BEGIN RSA PRIVATE KEY-----/, '')
    .replace(/-----END RSA PRIVATE KEY-----/, '')
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\n/g, '')
    .replace(/\r/g, '')
  const binaryDer = Buffer.from(pemContents, 'base64')

  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )
}

// ─── Installation Token ─────────────────────────────────────────────────────

/**
 * Get an installation access token for a specific installation.
 * This token has the permissions granted by the app and is valid for 1 hour.
 */
export async function getInstallationToken(installationId: number): Promise<string> {
  const jwt = await generateAppJWT()

  const res = await fetch(`${GITHUB_API}/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  })

  if (!res.ok) {
    const body = await res.text()
    throw new Error(`Failed to get installation token: ${res.status} ${body}`)
  }

  const data = await res.json()
  return data.token
}

// ─── GitHub REST API Helpers ────────────────────────────────────────────────

function ghHeaders(token: string) {
  return {
    Authorization: `token ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json',
  }
}

/** Get the list of files changed in a PR */
export async function getPullRequestFiles(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<GitHubPRFile[]> {
  const res = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100`,
    { headers: ghHeaders(token) },
  )
  if (!res.ok) throw new Error(`Failed to get PR files: ${res.status}`)
  return res.json()
}

/** Download a single file's content from a raw URL */
export async function getFileContent(token: string, rawUrl: string): Promise<string> {
  const res = await fetch(rawUrl, {
    headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.raw' },
  })
  if (!res.ok) return ''
  return res.text()
}

/** Get file content from a specific ref (branch/SHA) */
export async function getFileFromRef(
  token: string,
  owner: string,
  repo: string,
  path: string,
  ref: string,
): Promise<string | null> {
  const res = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${ref}`,
    { headers: { ...ghHeaders(token), Accept: 'application/vnd.github.raw' } },
  )
  if (!res.ok) return null
  return res.text()
}

// ─── Check Runs ─────────────────────────────────────────────────────────────

/** Create a new check run (in_progress) */
export async function createCheckRun(
  token: string,
  owner: string,
  repo: string,
  headSha: string,
  name: string = 'HemisX SAST',
): Promise<GitHubCheckRun> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/check-runs`, {
    method: 'POST',
    headers: ghHeaders(token),
    body: JSON.stringify({
      name,
      head_sha: headSha,
      status: 'in_progress',
      started_at: new Date().toISOString(),
    }),
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`Failed to create check run: ${res.status} ${body}`)
  }
  return res.json()
}

/** Update a check run with results */
export async function updateCheckRun(
  token: string,
  owner: string,
  repo: string,
  checkRunId: number,
  conclusion: 'success' | 'failure' | 'neutral' | 'action_required',
  title: string,
  summary: string,
  annotations: CheckAnnotation[],
): Promise<void> {
  // GitHub limits annotations to 50 per request
  const batchSize = 50
  for (let i = 0; i < annotations.length; i += batchSize) {
    const batch = annotations.slice(i, i + batchSize)
    const isLast = i + batchSize >= annotations.length

    const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/check-runs/${checkRunId}`, {
      method: 'PATCH',
      headers: ghHeaders(token),
      body: JSON.stringify({
        status: isLast ? 'completed' : 'in_progress',
        conclusion: isLast ? conclusion : undefined,
        completed_at: isLast ? new Date().toISOString() : undefined,
        output: {
          title,
          summary,
          annotations: batch,
        },
      }),
    })
    if (!res.ok) {
      const body = await res.text()
      console.error(`[GitHub] Failed to update check run: ${res.status} ${body}`)
    }
  }

  // If no annotations, still complete the check run
  if (annotations.length === 0) {
    await fetch(`${GITHUB_API}/repos/${owner}/${repo}/check-runs/${checkRunId}`, {
      method: 'PATCH',
      headers: ghHeaders(token),
      body: JSON.stringify({
        status: 'completed',
        conclusion,
        completed_at: new Date().toISOString(),
        output: { title, summary },
      }),
    })
  }
}

// ─── SARIF Upload ───────────────────────────────────────────────────────────

/** Upload SARIF results to GitHub Code Scanning */
export async function uploadSarif(
  token: string,
  owner: string,
  repo: string,
  ref: string,
  commitSha: string,
  sarifJson: string,
): Promise<void> {
  // SARIF must be gzip+base64 encoded
  const { gzipSync } = await import('zlib')
  const compressed = gzipSync(Buffer.from(sarifJson, 'utf8'))
  const encoded = compressed.toString('base64')

  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/code-scanning/sarifs`, {
    method: 'POST',
    headers: ghHeaders(token),
    body: JSON.stringify({
      commit_sha: commitSha,
      ref,
      sarif: encoded,
      tool_name: 'HemisX SAST',
    }),
  })

  if (!res.ok) {
    const body = await res.text()
    console.error(`[GitHub] SARIF upload failed: ${res.status} ${body}`)
  }
}

// ─── Finding → Annotation Conversion ────────────────────────────────────────

export function findingsToAnnotations(findings: SastFindingResult[]): CheckAnnotation[] {
  return findings.map(f => ({
    path:             f.filePath,
    start_line:       f.lineStart,
    end_line:         f.lineEnd,
    annotation_level: severityToAnnotationLevel(f.severity),
    message:          `${f.description}\n\nRemediation: ${f.remediation}\n\n[${f.owasp}] [${f.cwe}]`,
    title:            `[${f.severity}] ${f.ruleName}`,
  }))
}

function severityToAnnotationLevel(severity: SastSeverity): CheckAnnotation['annotation_level'] {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'failure'
    case 'MEDIUM':
      return 'warning'
    default:
      return 'notice'
  }
}

/** Generate a check run summary from findings */
export function generateCheckSummary(findings: SastFindingResult[]): {
  conclusion: 'success' | 'failure' | 'neutral'
  title: string
  summary: string
} {
  const critical = findings.filter(f => f.severity === 'CRITICAL').length
  const high     = findings.filter(f => f.severity === 'HIGH').length
  const medium   = findings.filter(f => f.severity === 'MEDIUM').length
  const low      = findings.filter(f => f.severity === 'LOW').length
  const total    = findings.length

  const conclusion = critical > 0 || high > 0 ? 'failure'
    : medium > 0 ? 'neutral'
    : 'success'

  const title = total === 0
    ? 'HemisX SAST: No issues found'
    : `HemisX SAST: ${total} issue${total !== 1 ? 's' : ''} (${critical}C/${high}H/${medium}M/${low}L)`

  const summary = [
    '## HemisX SAST Scan Results\n',
    `| Severity | Count |`,
    `|----------|-------|`,
    `| Critical | ${critical} |`,
    `| High | ${high} |`,
    `| Medium | ${medium} |`,
    `| Low | ${low} |`,
    `| **Total** | **${total}** |`,
    '',
    total > 0
      ? '> Review annotations on changed files for details and remediation guidance.'
      : '> No security issues detected in the changed files.',
  ].join('\n')

  return { conclusion, title, summary }
}
