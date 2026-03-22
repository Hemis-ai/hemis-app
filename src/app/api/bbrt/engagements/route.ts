import { NextRequest, NextResponse } from 'next/server'
import {
  createEngagement,
  listEngagements,
  ensureMockSeeded,
} from '@/lib/bbrt/engagement-orchestrator'
import type { BbrtTargetConfig } from '@/lib/types/bbrt'

/**
 * POST /api/bbrt/engagements — Create a new BBRT engagement
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { name, targetConfig } = body

    if (!name?.trim()) {
      return NextResponse.json({ error: 'Engagement name is required' }, { status: 400 })
    }
    if (!targetConfig?.targetDomain?.trim()) {
      return NextResponse.json({ error: 'Target domain is required' }, { status: 400 })
    }

    const config: BbrtTargetConfig = {
      targetDomain: targetConfig.targetDomain.trim(),
      targetIPs: targetConfig.targetIPs || [],
      targetScope: targetConfig.targetScope || [targetConfig.targetDomain.trim()],
      excludedPaths: targetConfig.excludedPaths || [],
      engagementType: targetConfig.engagementType || 'full',
      complianceRequirements: targetConfig.complianceRequirements || [],
      businessContext: {
        industry: targetConfig.businessContext?.industry || 'other',
        dataTypes: targetConfig.businessContext?.dataTypes || [],
        userCount: targetConfig.businessContext?.userCount || '1-100',
        revenueRange: targetConfig.businessContext?.revenueRange || '$0-1M',
        criticalSystems: targetConfig.businessContext?.criticalSystems || [],
      },
    }

    const engagement = createEngagement(name.trim(), config)
    console.log(`[BBRT] Engagement created: ${engagement.id}`, { name: engagement.name, target: config.targetDomain })

    return NextResponse.json({ engagement }, { status: 201 })
  } catch (err) {
    console.error('[BBRT] POST /api/bbrt/engagements error:', err)
    return NextResponse.json({ error: 'Failed to create engagement' }, { status: 500 })
  }
}

/**
 * GET /api/bbrt/engagements — List all engagements
 */
export async function GET() {
  try {
    ensureMockSeeded()
    const engagements = listEngagements()
    return NextResponse.json({ engagements })
  } catch (err) {
    console.error('[BBRT] GET /api/bbrt/engagements error:', err)
    return NextResponse.json({ engagements: [], demo: true })
  }
}
