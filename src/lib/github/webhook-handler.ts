// HemisX — GitHub Webhook Handler
// Processes webhook events from GitHub (pull_request, push, check_suite)
// and triggers SAST scans on changed files.

import { createHmac, timingSafeEqual } from 'crypto'
import {
  getInstallationToken,
  getPullRequestFiles,
  getFileContent,
  getFileFromRef,
  createCheckRun,
  updateCheckRun,
  findingsToAnnotations,
  generateCheckSummary,
  uploadSarif,
} from '@/lib/github/github-app'
import { runSastScan } from '@/lib/sast/scanner'
import { scanWithAST } from '@/lib/sast/ast-engine'
import { runDeepTaintAnalysis } from '@/lib/sast/taint-engine'
import { SECRET_PATTERNS } from '@/lib/sast/secret-detector'
import { scanForHighEntropy } from '@/lib/sast/entropy-scanner'
import { scanDependencies, isDependencyManifest } from '@/lib/sast/dependency-scanner'
import { detectLanguage } from '@/lib/sast/language-detector'
import { toSarif } from '@/lib/sast/sarif-export'
import { randomUUID } from 'crypto'
import type { SastFindingResult, SastScanResult } from '@/lib/types/sast'

// ─── Webhook signature verification ─────────────────────────────────────────

export function verifyWebhookSignature(
  payload: string,
  signature: string | null,
): boolean {
  const secret = process.env.GITHUB_WEBHOOK_SECRET
  if (!secret) {
    console.warn('[GitHub] GITHUB_WEBHOOK_SECRET not set — skipping signature verification')
    return true // Allow in dev mode
  }

  if (!signature) return false

  const expected = 'sha256=' + createHmac('sha256', secret).update(payload).digest('hex')

  try {
    return timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  } catch {
    return false
  }
}

// ─── Event routing ──────────────────────────────────────────────────────────

export interface WebhookResult {
  action:  'scanned' | 'skipped' | 'error'
  message: string
  findings?: number
}

export async function handleWebhookEvent(
  event: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload: any,
): Promise<WebhookResult> {
  switch (event) {
    case 'pull_request':
      return handlePullRequest(payload)

    case 'push':
      return handlePush(payload)

    case 'check_suite':
      if (payload.action === 'rerequested') {
        return handleCheckSuiteRerun(payload)
      }
      return { action: 'skipped', message: `check_suite action "${payload.action}" not handled` }

    default:
      return { action: 'skipped', message: `Event "${event}" not handled` }
  }
}

// ─── Pull Request Handler ───────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function handlePullRequest(payload: any): Promise<WebhookResult> {
  const action = payload.action
  if (action !== 'opened' && action !== 'synchronize' && action !== 'reopened') {
    return { action: 'skipped', message: `PR action "${action}" not scanned` }
  }

  const installationId = payload.installation?.id
  if (!installationId) {
    return { action: 'error', message: 'No installation ID in webhook payload' }
  }

  const owner    = payload.repository.owner.login
  const repo     = payload.repository.name
  const prNumber = payload.pull_request.number
  const headSha  = payload.pull_request.head.sha
  const ref      = payload.pull_request.head.ref

  console.log(`[GitHub] PR #${prNumber} scan triggered (${owner}/${repo} @ ${headSha.slice(0, 7)})`)

  try {
    const token = await getInstallationToken(installationId)

    // Create a check run (in_progress)
    const checkRun = await createCheckRun(token, owner, repo, headSha)

    // Get changed files
    const prFiles = await getPullRequestFiles(token, owner, repo, prNumber)

    // Filter to scannable files
    const scannableFiles = prFiles.filter(f =>
      f.status !== 'removed' &&
      /\.(js|jsx|ts|tsx|mjs|cjs|py|php|java|go|rb|json|yaml|yml)$/.test(f.filename)
    )

    if (scannableFiles.length === 0) {
      await updateCheckRun(token, owner, repo, checkRun.id,
        'success', 'HemisX SAST: No scannable files', 'No JS/TS/Python/PHP files were changed.', [])
      return { action: 'scanned', message: 'No scannable files in PR', findings: 0 }
    }

    // Download file contents
    const files: Array<{ path: string; content: string }> = []
    for (const pf of scannableFiles.slice(0, 50)) { // Limit to 50 files
      const content = pf.raw_url
        ? await getFileContent(token, pf.raw_url)
        : await getFileFromRef(token, owner, repo, pf.filename, ref) || ''

      if (content) {
        files.push({ path: pf.filename, content })
      }
    }

    // Run the full scan pipeline
    const scanResult = await runFullScan(files, `PR #${prNumber}`)

    // Generate check run annotations
    const annotations = findingsToAnnotations(scanResult.findings)
    const checkSummary = generateCheckSummary(scanResult.findings)

    // Update check run with results
    await updateCheckRun(
      token, owner, repo, checkRun.id,
      checkSummary.conclusion, checkSummary.title, checkSummary.summary,
      annotations,
    )

    // Upload SARIF to GitHub Code Scanning (best-effort)
    try {
      const sarif = toSarif(scanResult)
      await uploadSarif(token, owner, repo, `refs/heads/${ref}`, headSha, JSON.stringify(sarif))
    } catch (e) {
      console.warn('[GitHub] SARIF upload failed (non-fatal):', e)
    }

    console.log(`[GitHub] PR #${prNumber} scan complete: ${scanResult.findings.length} findings`)
    return { action: 'scanned', message: `Scanned ${files.length} files`, findings: scanResult.findings.length }

  } catch (err) {
    console.error('[GitHub] PR scan error:', err)
    return { action: 'error', message: err instanceof Error ? err.message : 'Unknown error' }
  }
}

// ─── Push Handler ───────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function handlePush(payload: any): Promise<WebhookResult> {
  // Only scan pushes to default branch
  const defaultRef = `refs/heads/${payload.repository.default_branch}`
  if (payload.ref !== defaultRef) {
    return { action: 'skipped', message: 'Push to non-default branch' }
  }

  const installationId = payload.installation?.id
  if (!installationId) {
    return { action: 'error', message: 'No installation ID in webhook payload' }
  }

  const owner   = payload.repository.owner.login || payload.repository.owner.name
  const repo    = payload.repository.name
  const headSha = payload.after

  // Get the list of changed files from the push commits
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const changedFiles = new Set<string>()
  for (const commit of (payload.commits || [])) {
    for (const f of [...(commit.added || []), ...(commit.modified || [])]) {
      if (/\.(js|jsx|ts|tsx|mjs|cjs|py|php|java|go|rb|json|yaml|yml)$/.test(f)) {
        changedFiles.add(f)
      }
    }
  }

  if (changedFiles.size === 0) {
    return { action: 'skipped', message: 'No scannable files in push' }
  }

  console.log(`[GitHub] Push scan triggered (${owner}/${repo} @ ${headSha.slice(0, 7)}, ${changedFiles.size} files)`)

  try {
    const token = await getInstallationToken(installationId)
    const checkRun = await createCheckRun(token, owner, repo, headSha)
    const ref = payload.repository.default_branch

    const files: Array<{ path: string; content: string }> = []
    for (const filePath of Array.from(changedFiles).slice(0, 50)) {
      const content = await getFileFromRef(token, owner, repo, filePath, ref)
      if (content) files.push({ path: filePath, content })
    }

    const scanResult = await runFullScan(files, `Push to ${ref}`)
    const annotations = findingsToAnnotations(scanResult.findings)
    const checkSummary = generateCheckSummary(scanResult.findings)

    await updateCheckRun(
      token, owner, repo, checkRun.id,
      checkSummary.conclusion, checkSummary.title, checkSummary.summary,
      annotations,
    )

    return { action: 'scanned', message: `Scanned ${files.length} files`, findings: scanResult.findings.length }
  } catch (err) {
    console.error('[GitHub] Push scan error:', err)
    return { action: 'error', message: err instanceof Error ? err.message : 'Unknown error' }
  }
}

// ─── Check Suite Re-run ─────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function handleCheckSuiteRerun(payload: any): Promise<WebhookResult> {
  // Re-run all associated PRs
  const prs = payload.check_suite?.pull_requests || []
  if (prs.length === 0) {
    return { action: 'skipped', message: 'No PRs associated with check suite' }
  }

  // Re-trigger as a PR scan for the first PR
  const syntheticPayload = {
    action: 'synchronize',
    installation: payload.installation,
    repository: payload.repository,
    pull_request: {
      number: prs[0].number,
      head: { sha: payload.check_suite.head_sha, ref: payload.check_suite.head_branch },
    },
  }

  return handlePullRequest(syntheticPayload)
}

// ─── Full Scan Pipeline ─────────────────────────────────────────────────────

async function runFullScan(
  files: Array<{ path: string; content: string }>,
  name: string,
): Promise<SastScanResult> {
  const scanId = randomUUID()
  const start  = Date.now()

  // Run secret detection
  const secretFindings: SastFindingResult[] = []
  for (const file of files) {
    const lang = detectLanguage(file.path, file.content)
    for (const sp of SECRET_PATTERNS) {
      sp.pattern.lastIndex = 0
      const lines = file.content.split('\n')
      let m: RegExpExecArray | null
      const seen = new Set<number>()

      while ((m = sp.pattern.exec(file.content)) !== null) {
        const lineIdx = file.content.slice(0, m.index).split('\n').length - 1
        if (seen.has(lineIdx)) continue
        seen.add(lineIdx)

        const s2 = Math.max(0, lineIdx - 2)
        const e2 = Math.min(lines.length - 1, lineIdx + 2)
        const snippet = lines.slice(s2, e2 + 1).map((l, i) => `${s2 + i + 1} | ${l}`).join('\n')

        secretFindings.push({
          id: randomUUID(), scanId, ruleId: sp.id, ruleName: sp.name,
          severity: 'CRITICAL', confidence: 'HIGH', language: lang,
          filePath: file.path, lineStart: lineIdx + 1, lineEnd: lineIdx + 1,
          codeSnippet: snippet,
          description: `${sp.name} detected in source file.`,
          remediation: sp.remediation,
          owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-798',
          category: 'Secrets', status: 'OPEN', falsePositive: false,
          detectedAt: new Date().toISOString(),
        })
      }
      sp.pattern.lastIndex = 0
    }
  }

  // Run SCA
  const depFindings: SastFindingResult[] = []
  for (const file of files) {
    if (isDependencyManifest(file.path)) {
      depFindings.push(...scanDependencies(scanId, file.path, file.content).findings)
    }
  }

  // Run entropy detection
  const entropyFindings: SastFindingResult[] = []
  for (const file of files) {
    if (!isDependencyManifest(file.path)) {
      entropyFindings.push(...scanForHighEntropy(scanId, file.path, file.content))
    }
  }

  // Run AST analysis
  const astFindings: SastFindingResult[] = []
  for (const file of files) {
    if (!isDependencyManifest(file.path)) {
      try { astFindings.push(...scanWithAST(scanId, file.path, file.content)) } catch { /* skip */ }
    }
  }

  // Run deep taint analysis
  const taintFindings: SastFindingResult[] = []
  for (const file of files) {
    if (!isDependencyManifest(file.path)) {
      try { taintFindings.push(...runDeepTaintAnalysis(scanId, file.path, file.content)) } catch { /* skip */ }
    }
  }

  // Run regex scanner
  const scanResult = runSastScan(scanId, name, files)

  // Deduplicate
  const regexKeys = new Set(scanResult.findings.map(f => `${f.filePath}:${f.lineStart}:${f.cwe}`))
  const uniqueAst   = astFindings.filter(f => !regexKeys.has(`${f.filePath}:${f.lineStart}:${f.cwe}`))
  const allKeys     = new Set([...regexKeys, ...uniqueAst.map(f => `${f.filePath}:${f.lineStart}:${f.cwe}`)])
  const uniqueTaint = taintFindings.filter(f => !allKeys.has(`${f.filePath}:${f.lineStart}:${f.cwe}`))

  const mergedFindings = [
    ...secretFindings, ...entropyFindings, ...depFindings,
    ...uniqueAst, ...uniqueTaint, ...scanResult.findings,
  ]

  const summary = {
    critical: mergedFindings.filter(f => f.severity === 'CRITICAL').length,
    high:     mergedFindings.filter(f => f.severity === 'HIGH').length,
    medium:   mergedFindings.filter(f => f.severity === 'MEDIUM').length,
    low:      mergedFindings.filter(f => f.severity === 'LOW').length,
    info:     mergedFindings.filter(f => f.severity === 'INFO').length,
    total:    mergedFindings.length,
  }

  return { ...scanResult, findings: mergedFindings, summary, duration: Date.now() - start }
}
