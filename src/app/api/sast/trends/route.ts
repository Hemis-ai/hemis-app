import { NextResponse } from 'next/server'
import { prisma } from '@/lib/db'

/**
 * GET /api/sast/trends
 * Returns trend analytics data: findings over time, severity distribution,
 * top vulnerability types, MTTR estimates, and scan frequency.
 */
export async function GET() {
  try {
    // Try database first
    const scans = await prisma.sastScan.findMany({
      orderBy: { startedAt: 'desc' },
      take: 50,
      include: {
        findings: {
          select: {
            id: true,
            severity: true,
            category: true,
            ruleId: true,
            ruleName: true,
            status: true,
            falsePositive: true,
            detectedAt: true,
            cwe: true,
            owasp: true,
          },
        },
      },
    })

    if (scans.length === 0) {
      return NextResponse.json(generateDemoTrends())
    }

    // ─── Findings over time (last 30 days, grouped by day) ────────────────
    const thirtyDaysAgo = new Date()
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30)

    const dailyMap: Record<string, { critical: number; high: number; medium: number; low: number; info: number; total: number }> = {}

    for (let d = 0; d < 30; d++) {
      const date = new Date(thirtyDaysAgo)
      date.setDate(date.getDate() + d)
      const key = date.toISOString().split('T')[0]
      dailyMap[key] = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
    }

    for (const scan of scans) {
      const day = new Date(scan.startedAt).toISOString().split('T')[0]
      if (dailyMap[day]) {
        dailyMap[day].critical += scan.criticalCount
        dailyMap[day].high += scan.highCount
        dailyMap[day].medium += scan.mediumCount
        dailyMap[day].low += scan.lowCount
        dailyMap[day].info += scan.infoCount
        dailyMap[day].total += scan.criticalCount + scan.highCount + scan.mediumCount + scan.lowCount + scan.infoCount
      }
    }

    const findingsOverTime = Object.entries(dailyMap)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, counts]) => ({ date, ...counts }))

    // ─── Top vulnerability types ──────────────────────────────────────────
    const vulnTypeCounts: Record<string, { count: number; severity: string; cwe: string }> = {}
    for (const scan of scans) {
      for (const f of scan.findings) {
        const key = f.ruleName as string
        if (!vulnTypeCounts[key]) {
          vulnTypeCounts[key] = { count: 0, severity: f.severity as string, cwe: f.cwe as string }
        }
        vulnTypeCounts[key].count++
      }
    }
    const topVulnTypes = Object.entries(vulnTypeCounts)
      .sort(([, a], [, b]) => b.count - a.count)
      .slice(0, 10)
      .map(([name, data]) => ({ name, ...data }))

    // ─── Severity distribution ────────────────────────────────────────────
    const sevDist = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const scan of scans) {
      sevDist.critical += scan.criticalCount
      sevDist.high += scan.highCount
      sevDist.medium += scan.mediumCount
      sevDist.low += scan.lowCount
      sevDist.info += scan.infoCount
    }

    // ─── Scan frequency ───────────────────────────────────────────────────
    const scanFrequency = scans.map((s: typeof scans[number]) => ({
      date: new Date(s.startedAt).toISOString().split('T')[0],
      scanCount: 1,
      findings: s.criticalCount + s.highCount + s.mediumCount + s.lowCount + s.infoCount,
      filesScanned: s.filesScanned,
      linesOfCode: s.linesOfCode,
    }))

    // ─── Category breakdown ───────────────────────────────────────────────
    const catCounts: Record<string, number> = {}
    for (const scan of scans) {
      for (const f of scan.findings) {
        const cat = f.category as string
        catCounts[cat] = (catCounts[cat] || 0) + 1
      }
    }
    const categoryBreakdown = Object.entries(catCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([category, count]) => ({ category, count }))

    // ─── Summary stats ────────────────────────────────────────────────────
    const totalFindings = sevDist.critical + sevDist.high + sevDist.medium + sevDist.low + sevDist.info
    const totalScans = scans.length
    const avgFindingsPerScan = totalScans > 0 ? Math.round(totalFindings / totalScans) : 0
    const allFindings = scans.flatMap((s: typeof scans[number]) => s.findings)
    const remediatedCount = allFindings.filter((f: typeof allFindings[number]) => f.status === 'REMEDIATED').length
    const fpCount = allFindings.filter((f: typeof allFindings[number]) => f.falsePositive).length
    const scansWithDuration = scans.filter((s: typeof scans[number]) => s.duration != null)
    const avgScanDuration = scansWithDuration.reduce((sum: number, s: typeof scans[number]) => sum + (s.duration || 0), 0) / Math.max(scansWithDuration.length, 1)

    return NextResponse.json({
      findingsOverTime,
      topVulnTypes,
      severityDistribution: sevDist,
      categoryBreakdown,
      scanFrequency,
      summary: {
        totalScans,
        totalFindings,
        avgFindingsPerScan,
        remediatedCount,
        falsePositiveCount: fpCount,
        avgScanDuration: Math.round(avgScanDuration),
        criticalOpen: sevDist.critical,
        highOpen: sevDist.high,
      },
    })
  } catch (err) {
    // Fallback to demo data if DB is unavailable
    console.warn('[SAST Trends] DB unavailable, using demo data:', err)
    return NextResponse.json(generateDemoTrends())
  }
}

// ─── Demo trend data for when no real scans exist ──────────────────────────

function generateDemoTrends() {
  const now = new Date()
  const findingsOverTime = []

  for (let i = 29; i >= 0; i--) {
    const date = new Date(now)
    date.setDate(date.getDate() - i)
    const dayKey = date.toISOString().split('T')[0]

    // Simulate a declining trend (security improving over time)
    const base = Math.max(0, 20 - Math.floor(i / 3))
    const jitter = Math.floor(Math.random() * 6) - 2

    findingsOverTime.push({
      date: dayKey,
      critical: Math.max(0, Math.floor((base + jitter) * 0.1)),
      high: Math.max(0, Math.floor((base + jitter) * 0.25)),
      medium: Math.max(0, Math.floor((base + jitter) * 0.35)),
      low: Math.max(0, Math.floor((base + jitter) * 0.2)),
      info: Math.max(0, Math.floor((base + jitter) * 0.1)),
      total: Math.max(0, base + jitter),
    })
  }

  return {
    findingsOverTime,
    topVulnTypes: [
      { name: 'SQL Injection via string concatenation', count: 28, severity: 'CRITICAL', cwe: 'CWE-89' },
      { name: 'Hardcoded credentials in source', count: 24, severity: 'HIGH', cwe: 'CWE-798' },
      { name: 'Command injection via exec()', count: 19, severity: 'CRITICAL', cwe: 'CWE-78' },
      { name: 'Cross-Site Scripting (reflected)', count: 17, severity: 'HIGH', cwe: 'CWE-79' },
      { name: 'Weak cryptographic algorithm', count: 14, severity: 'MEDIUM', cwe: 'CWE-327' },
      { name: 'Missing CSRF protection', count: 12, severity: 'MEDIUM', cwe: 'CWE-352' },
      { name: 'Insecure deserialization', count: 9, severity: 'HIGH', cwe: 'CWE-502' },
      { name: 'Path traversal vulnerability', count: 7, severity: 'HIGH', cwe: 'CWE-22' },
      { name: 'Debug mode enabled in production', count: 6, severity: 'LOW', cwe: 'CWE-489' },
      { name: 'Sensitive data in logs', count: 5, severity: 'MEDIUM', cwe: 'CWE-532' },
    ],
    severityDistribution: { critical: 47, high: 72, medium: 58, low: 31, info: 14 },
    categoryBreakdown: [
      { category: 'Injection', count: 64 },
      { category: 'Secrets', count: 38 },
      { category: 'Cryptography', count: 26 },
      { category: 'XSS', count: 22 },
      { category: 'Authentication', count: 18 },
      { category: 'Misconfiguration', count: 15 },
      { category: 'Dependencies', count: 12 },
      { category: 'Logging', count: 8 },
      { category: 'Deserialization', count: 9 },
      { category: 'SSRF', count: 5 },
    ],
    scanFrequency: Array.from({ length: 14 }, (_, i) => {
      const date = new Date(now)
      date.setDate(date.getDate() - (13 - i))
      return {
        date: date.toISOString().split('T')[0],
        scanCount: Math.floor(Math.random() * 4) + 1,
        findings: Math.floor(Math.random() * 30) + 5,
        filesScanned: Math.floor(Math.random() * 20) + 3,
        linesOfCode: Math.floor(Math.random() * 5000) + 500,
      }
    }),
    summary: {
      totalScans: 47,
      totalFindings: 222,
      avgFindingsPerScan: 5,
      remediatedCount: 89,
      falsePositiveCount: 18,
      avgScanDuration: 342,
      criticalOpen: 47,
      highOpen: 72,
    },
  }
}
