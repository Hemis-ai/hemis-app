import { NextRequest, NextResponse } from 'next/server'
import { mapToCompliance, getFrameworks } from '@/lib/sast/compliance-mapper'
import type { ComplianceFramework } from '@/lib/sast/compliance-mapper'
import type { SastFindingResult } from '@/lib/types/sast'

/**
 * POST /api/sast/compliance
 * Generate compliance mapping from scan findings.
 * Body: { findings: SastFindingResult[], framework?: ComplianceFramework }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { findings, framework } = body as {
      findings: SastFindingResult[]
      framework?: ComplianceFramework
    }

    if (!Array.isArray(findings)) {
      return NextResponse.json({ error: 'findings array is required' }, { status: 400 })
    }

    const results = mapToCompliance(findings, framework)

    return NextResponse.json({ results, frameworks: getFrameworks() })
  } catch (err) {
    console.error('[SAST] Compliance mapping error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
