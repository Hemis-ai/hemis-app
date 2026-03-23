import { NextRequest, NextResponse } from 'next/server'
import { isDatabaseReachable, prisma } from '@/lib/db'
import { compareScans, type ScanComparisonInput } from '@/lib/dast/comparison/scan-comparator'
import { isDastEngineRunning, proxyToEngine } from '@/lib/dast/engine-proxy'
import { directScanStore } from '@/app/api/dast/scans/route'
import { verifyAccessToken, ACCESS_COOKIE } from '@/lib/auth/jwt'

/**
 * POST /api/dast/compare — Compare two DAST scans
 * Body: { baselineScanId: string, currentScanId: string }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { baselineScanId, currentScanId } = body

    if (!baselineScanId || !currentScanId) {
      return NextResponse.json({ error: 'Both baselineScanId and currentScanId are required' }, { status: 400 })
    }

    if (baselineScanId === currentScanId) {
      return NextResponse.json({ error: 'Cannot compare a scan with itself' }, { status: 400 })
    }

    // Try Python engine first
    const engineOk = await isDastEngineRunning()
    if (engineOk) {
      const engineRes = await proxyToEngine('/api/dast/compare', {
        method: 'POST',
        body: JSON.stringify({ baselineScanId, currentScanId }),
      })
      if (engineRes?.ok) {
        const data = await engineRes.json()
        return NextResponse.json(data)
      }
    }

    const dbOk = await isDatabaseReachable()

    if (!dbOk) {
      // Check in-memory direct scan store
      const baseEntry = directScanStore.get(baselineScanId)
      const curEntry = directScanStore.get(currentScanId)

      if (!baseEntry || !curEntry) {
        return NextResponse.json({ error: 'One or both scans not found. Database is not available.' }, { status: 404 })
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      function entryToInput(entry: { scan: any; findings: any[] }): ScanComparisonInput {
        return {
          id: entry.scan.id, name: entry.scan.name, targetUrl: entry.scan.targetUrl,
          riskScore: entry.scan.riskScore ?? 0, criticalCount: entry.scan.criticalCount ?? 0,
          highCount: entry.scan.highCount ?? 0, mediumCount: entry.scan.mediumCount ?? 0,
          lowCount: entry.scan.lowCount ?? 0, infoCount: entry.scan.infoCount ?? 0,
          endpointsDiscovered: entry.scan.endpointsDiscovered ?? 0,
          endpointsTested: entry.scan.endpointsTested ?? 0, payloadsSent: entry.scan.payloadsSent ?? 0,
          completedAt: entry.scan.completedAt ?? null,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          findings: entry.findings.map((f: any) => ({
            id: f.id, type: f.type, severity: f.severity, title: f.title,
            affectedUrl: f.affectedUrl, affectedParameter: f.affectedParameter,
            cvssScore: f.cvssScore, owaspCategory: f.owaspCategory, cweId: f.cweId, riskScore: f.riskScore ?? 0,
          })),
        }
      }

      const result = compareScans(entryToInput(baseEntry), entryToInput(curEntry))
      return NextResponse.json({ comparison: result })
    }

    // Verify org ownership of both scans
    const token = req.cookies.get(ACCESS_COOKIE)?.value
    const jwtPayload = token ? await verifyAccessToken(token) : null
    const orgId = jwtPayload?.orgId || 'org-demo'

    // Real DB comparison
    const [baselineScan, currentScan] = await Promise.all([
      prisma.dastScan.findUnique({ where: { id: baselineScanId }, include: { dastFindings: true } }),
      prisma.dastScan.findUnique({ where: { id: currentScanId }, include: { dastFindings: true } }),
    ])

    if (!baselineScan || !currentScan) {
      return NextResponse.json({ error: 'One or both scans not found' }, { status: 404 })
    }

    // Ensure both scans belong to the requesting org
    if (baselineScan.orgId !== orgId || currentScan.orgId !== orgId) {
      return NextResponse.json({ error: 'One or both scans not found' }, { status: 404 })
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    function toInput(scan: any): ScanComparisonInput {
      return {
        id: scan.id,
        name: scan.name,
        targetUrl: scan.targetUrl,
        riskScore: scan.riskScore ?? 0,
        criticalCount: scan.criticalCount ?? 0,
        highCount: scan.highCount ?? 0,
        mediumCount: scan.mediumCount ?? 0,
        lowCount: scan.lowCount ?? 0,
        infoCount: scan.infoCount ?? 0,
        endpointsDiscovered: scan.endpointsDiscovered ?? 0,
        endpointsTested: scan.endpointsTested ?? 0,
        payloadsSent: scan.payloadsSent ?? 0,
        completedAt: scan.completedAt?.toISOString() ?? null,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        findings: scan.dastFindings.map((f: any) => ({
          id: f.id,
          type: f.type,
          severity: f.severity,
          title: f.title,
          affectedUrl: f.affectedUrl,
          affectedParameter: f.affectedParameter,
          cvssScore: f.cvssScore,
          owaspCategory: f.owaspCategory,
          cweId: f.cweId,
          riskScore: f.riskScore ?? 0,
        })),
      }
    }

    const result = compareScans(toInput(baselineScan), toInput(currentScan))
    return NextResponse.json({ comparison: result })
  } catch (error) {
    console.error('POST /api/dast/compare error:', error)
    return NextResponse.json({ error: 'Failed to compare scans' }, { status: 500 })
  }
}
