import { NextRequest, NextResponse } from 'next/server'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'
import { prisma, isDatabaseReachable } from '@/lib/db'
import { toSarif } from '@/lib/sast/sarif-export'
import type { SastScanResult, SastFindingResult, OwaspCategory } from '@/lib/types/sast'
import { OWASP_CATEGORIES } from '@/lib/sast/rules'

/**
 * GET /api/sast/export/:id?format=sarif|json|csv
 * Export scan results in various formats.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const format = req.nextUrl.searchParams.get('format') ?? 'sarif'

    if (!['sarif', 'json', 'csv'].includes(format)) {
      return NextResponse.json({ error: 'Format must be sarif, json, or csv' }, { status: 400 })
    }

    const dbReachable = await isDatabaseReachable()
    if (!dbReachable) {
      return NextResponse.json({ error: 'Database unavailable' }, { status: 503 })
    }

    const token   = req.cookies.get(ACCESS_COOKIE)?.value
    const payload = token ? await verifyAccessToken(token) : null
    if (!payload) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })

    const scan = await prisma.sastScan.findFirst({
      where:   { id, orgId: payload.orgId },
      include: { findings: { orderBy: [{ severity: 'asc' }, { detectedAt: 'desc' }] } },
    })

    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })

    // Build SastScanResult shape for SARIF export
    const findings: SastFindingResult[] = scan.findings.map((f: any) => ({
      id:           f.id,
      scanId:       f.scanId,
      ruleId:       f.ruleId,
      ruleName:     f.ruleName,
      severity:     f.severity as SastFindingResult['severity'],
      confidence:   f.confidence as SastFindingResult['confidence'],
      language:     f.language,
      filePath:     f.filePath,
      lineStart:    f.lineStart,
      lineEnd:      f.lineEnd,
      codeSnippet:  f.codeSnippet,
      description:  f.description,
      remediation:  f.remediation,
      owasp:        f.owasp,
      cwe:          f.cwe,
      category:     f.category as SastFindingResult['category'],
      status:       f.status as SastFindingResult['status'],
      falsePositive: f.falsePositive,
      detectedAt:   f.detectedAt.toISOString(),
    }))

    // Build OWASP coverage
    const owaspCoverage: OwaspCategory[] = OWASP_CATEGORIES.map(cat => {
      const catFindings = findings.filter(f => f.owasp.startsWith(cat.id))
      const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
      const highest = catFindings.length > 0
        ? catFindings.reduce((a, b) =>
            sevOrder.indexOf(a.severity) < sevOrder.indexOf(b.severity) ? a : b
          ).severity as OwaspCategory['highest']
        : null
      return { id: cat.id, name: cat.name, count: catFindings.length, highest }
    })

    const scanResult: SastScanResult = {
      id:           scan.id,
      name:         scan.name,
      language:     scan.language,
      linesOfCode:  scan.linesOfCode,
      filesScanned: scan.filesScanned,
      status:       scan.status as SastScanResult['status'],
      duration:     scan.duration ?? undefined,
      startedAt:    scan.startedAt.toISOString(),
      completedAt:  scan.completedAt?.toISOString(),
      summary: {
        critical: scan.criticalCount,
        high:     scan.highCount,
        medium:   scan.mediumCount,
        low:      scan.lowCount,
        info:     scan.infoCount,
        total:    findings.length,
      },
      findings,
      owaspCoverage,
    }

    if (format === 'sarif') {
      const sarif = toSarif(scanResult)
      return new NextResponse(JSON.stringify(sarif, null, 2), {
        headers: {
          'Content-Type':        'application/json',
          'Content-Disposition': `attachment; filename="hemisx-sast-${id.slice(0, 8)}.sarif"`,
        },
      })
    }

    if (format === 'csv') {
      const header = 'Rule ID,Rule Name,Severity,Confidence,File,Line,CWE,OWASP,Category,Status,False Positive'
      const rows = findings.map(f =>
        [f.ruleId, `"${f.ruleName}"`, f.severity, f.confidence, f.filePath, f.lineStart, f.cwe, f.owasp.split('–')[0]?.trim(), f.category, f.status, f.falsePositive].join(',')
      )
      return new NextResponse([header, ...rows].join('\n'), {
        headers: {
          'Content-Type':        'text/csv',
          'Content-Disposition': `attachment; filename="hemisx-sast-${id.slice(0, 8)}.csv"`,
        },
      })
    }

    // format === 'json'
    return new NextResponse(JSON.stringify(scanResult, null, 2), {
      headers: {
        'Content-Type':        'application/json',
        'Content-Disposition': `attachment; filename="hemisx-sast-${id.slice(0, 8)}.json"`,
      },
    })
  } catch (err) {
    console.error('[SAST] Export error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
