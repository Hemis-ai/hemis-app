import { NextRequest, NextResponse } from 'next/server'
import { randomUUID } from 'crypto'
import { runSastScan } from '@/lib/sast/scanner'
import { SECRET_PATTERNS } from '@/lib/sast/secret-detector'
import { detectLanguage } from '@/lib/sast/language-detector'
import { scanDependencies, isDependencyManifest } from '@/lib/sast/dependency-scanner'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'
import type { SastScanRequest, SastFindingResult } from '@/lib/types/sast'

const MAX_FILE_SIZE  = 500_000  // 500 KB per file
const MAX_TOTAL_SIZE = 2_000_000 // 2 MB total
const MAX_FILES      = 50

/**
 * POST /api/sast/scan
 * Submit source code for SAST analysis.
 *
 * Body: SastScanRequest { name, language?, files: [{ path, content }] }
 * Returns: full SastScanResult (synchronous — scanned inline)
 */
export async function POST(req: NextRequest) {
  try {
    const body: SastScanRequest = await req.json()

    // ── Validation ──────────────────────────────────────────────────────────
    if (!body.name?.trim()) {
      return NextResponse.json({ error: 'Scan name is required' }, { status: 400 })
    }
    if (!Array.isArray(body.files) || body.files.length === 0) {
      return NextResponse.json({ error: 'At least one file is required' }, { status: 400 })
    }
    if (body.files.length > MAX_FILES) {
      return NextResponse.json({ error: `Maximum ${MAX_FILES} files per scan` }, { status: 400 })
    }

    let totalSize = 0
    for (const f of body.files) {
      if (!f.path || !f.content) {
        return NextResponse.json({ error: 'Each file must have a path and content' }, { status: 400 })
      }
      const size = Buffer.byteLength(f.content, 'utf8')
      if (size > MAX_FILE_SIZE) {
        return NextResponse.json({ error: `File "${f.path}" exceeds 500 KB limit` }, { status: 400 })
      }
      totalSize += size
    }
    if (totalSize > MAX_TOTAL_SIZE) {
      return NextResponse.json({ error: 'Total upload size exceeds 2 MB limit' }, { status: 400 })
    }

    // ── Auth ─────────────────────────────────────────────────────────────────
    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null

    const scanId = randomUUID()
    const start  = Date.now()

    // ── Run secret detector first (augment files array) ────────────────────
    const secretFindings: SastFindingResult[] = []
    for (const file of body.files) {
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

          const start2 = Math.max(0, lineIdx - 2)
          const end2   = Math.min(lines.length - 1, lineIdx + 2)
          const snippet = lines
            .slice(start2, end2 + 1)
            .map((l, i) => `${start2 + i + 1} | ${l}`)
            .join('\n')

          secretFindings.push({
            id:           randomUUID(),
            scanId,
            ruleId:       sp.id,
            ruleName:     sp.name,
            severity:     'CRITICAL',
            confidence:   'HIGH',
            language:     lang,
            filePath:     file.path,
            lineStart:    lineIdx + 1,
            lineEnd:      lineIdx + 1,
            codeSnippet:  snippet,
            description:  `${sp.name} detected in source file. Exposed credentials allow unauthorized access.`,
            remediation:  sp.remediation,
            owasp:        'A02:2021 – Cryptographic Failures',
            cwe:          'CWE-798',
            category:     'Secrets',
            status:       'OPEN',
            falsePositive: false,
            detectedAt:   new Date().toISOString(),
          })
        }
        sp.pattern.lastIndex = 0
      }
    }

    // ── Run dependency scanner (SCA) on manifest files ──────────────────────
    const depFindings: SastFindingResult[] = []
    for (const file of body.files) {
      if (isDependencyManifest(file.path)) {
        const depResult = scanDependencies(scanId, file.path, file.content)
        depFindings.push(...depResult.findings)
      }
    }

    // ── Run SAST rule scanner ───────────────────────────────────────────────
    const scanResult = runSastScan(scanId, body.name, body.files)

    // Merge all findings: secrets + SCA + SAST rules
    const mergedFindings = [...secretFindings, ...depFindings, ...scanResult.findings]
    const summary = {
      critical: mergedFindings.filter(f => f.severity === 'CRITICAL').length,
      high:     mergedFindings.filter(f => f.severity === 'HIGH').length,
      medium:   mergedFindings.filter(f => f.severity === 'MEDIUM').length,
      low:      mergedFindings.filter(f => f.severity === 'LOW').length,
      info:     mergedFindings.filter(f => f.severity === 'INFO').length,
      total:    mergedFindings.length,
    }

    const finalResult = { ...scanResult, findings: mergedFindings, summary, duration: Date.now() - start }

    // ── Persist to DB ───────────────────────────────────────────────────────
    const dbReachable = await isDatabaseReachable()
    if (dbReachable && payload) {
      await prisma.sastScan.create({
        data: {
          id:           scanId,
          orgId:        payload.orgId,
          initiatedBy:  payload.userId,
          name:         body.name,
          language:     finalResult.language,
          linesOfCode:  finalResult.linesOfCode,
          filesScanned: finalResult.filesScanned,
          status:       'COMPLETED',
          duration:     finalResult.duration,
          completedAt:  new Date(),
          criticalCount: summary.critical,
          highCount:     summary.high,
          mediumCount:   summary.medium,
          lowCount:      summary.low,
          infoCount:     summary.info,
          findings: {
            create: mergedFindings.map(f => ({
              id:                f.id,
              ruleId:            f.ruleId,
              ruleName:          f.ruleName,
              severity:          f.severity,
              confidence:        f.confidence,
              language:          f.language,
              filePath:          f.filePath,
              lineStart:         f.lineStart,
              lineEnd:           f.lineEnd,
              codeSnippet:       f.codeSnippet,
              description:       f.description,
              remediation:       f.remediation,
              owasp:             f.owasp,
              cwe:               f.cwe,
              category:          f.category,
              status:            'OPEN' as const,
            })),
          },
        },
      })

      await prisma.auditLog.create({
        data: {
          orgId:    payload.orgId,
          userId:   payload.userId,
          action:   'sast.scan.complete',
          resource: scanId,
          meta:     { name: body.name, totalFindings: summary.total, critical: summary.critical },
          ipAddress: req.headers.get('x-forwarded-for') ?? undefined,
        },
      }).catch(() => null)
    }

    console.log(`[SAST] Scan complete: ${scanId}`, {
      name: body.name, files: body.files.length, findings: summary.total, duration: `${finalResult.duration}ms`,
    })

    return NextResponse.json(finalResult)
  } catch (err) {
    console.error('[SAST] Scan error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
