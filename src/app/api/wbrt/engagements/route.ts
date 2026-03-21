import { NextRequest, NextResponse } from 'next/server'
import {
  createEngagement,
  listEngagements,
} from '@/lib/wbrt/engagement-orchestrator'
import type { ArchitectureContext, WbrtInputSource } from '@/lib/types/wbrt'

/**
 * POST /api/wbrt/engagements — Create a new WBRT engagement
 *
 * Body: { name, inputSource, architectureContext, sastScanId? }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { name, inputSource, architectureContext, sastScanId } = body

    // ── Validation ──
    if (!name?.trim()) {
      return NextResponse.json({ error: 'Engagement name is required' }, { status: 400 })
    }
    if (!inputSource || !['sast_import', 'code_upload', 'hybrid'].includes(inputSource)) {
      return NextResponse.json({ error: 'Valid inputSource is required (sast_import, code_upload, hybrid)' }, { status: 400 })
    }
    if (!architectureContext) {
      return NextResponse.json({ error: 'Architecture context is required' }, { status: 400 })
    }

    // Provide sensible defaults for missing architecture fields
    const arch: ArchitectureContext = {
      techStack: architectureContext.techStack || [],
      deployment: architectureContext.deployment || 'cloud',
      cloudProviders: architectureContext.cloudProviders || [],
      networkSegments: architectureContext.networkSegments || [],
      authMechanisms: architectureContext.authMechanisms || [],
      dataClassifications: architectureContext.dataClassifications || [],
      complianceRequirements: architectureContext.complianceRequirements || [],
      externalIntegrations: architectureContext.externalIntegrations || [],
      userCount: architectureContext.userCount || '1-100',
      description: architectureContext.description || '',
    }

    const engagement = createEngagement(
      name.trim(),
      inputSource as WbrtInputSource,
      arch,
      sastScanId,
    )

    console.log(`[WBRT] Engagement created: ${engagement.id}`, { name: engagement.name, inputSource })

    return NextResponse.json({ engagement }, { status: 201 })
  } catch (err) {
    console.error('[WBRT] POST /api/wbrt/engagements error:', err)
    return NextResponse.json({ error: 'Failed to create engagement' }, { status: 500 })
  }
}

/**
 * GET /api/wbrt/engagements — List all engagements
 */
export async function GET() {
  try {
    const engagements = listEngagements()
    return NextResponse.json({ engagements })
  } catch (err) {
    console.error('[WBRT] GET /api/wbrt/engagements error:', err)
    return NextResponse.json({ engagements: [], demo: true })
  }
}
