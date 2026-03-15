import { NextRequest, NextResponse } from 'next/server'
import { generatePayload, isAuthorizedEngagement } from '@/lib/redteam/payload-engine'
import type { Payload } from '@/lib/types'

/**
 * POST /api/redteam/payloads
 * Generate attack payloads for authorized testing
 * All payloads require valid engagement ID for authorization
 */

interface PayloadRequest {
  vulnType: string
  targetComponent: string
  engagementId: string
}

interface PayloadResponse {
  payload?: Payload
  error?: string
}

export async function POST(request: NextRequest): Promise<NextResponse<PayloadResponse>> {
  try {
    const body: PayloadRequest = await request.json()

    // Validate required fields
    if (!body.vulnType || !body.targetComponent || !body.engagementId) {
      return NextResponse.json(
        {
          error: 'Missing required fields: vulnType, targetComponent, engagementId',
        },
        { status: 400 }
      )
    }

    // Authorization verification
    if (!isAuthorizedEngagement(body.engagementId)) {
      console.warn('[REDTEAM] Unauthorized payload request:', {
        engagementId: body.engagementId,
        vulnType: body.vulnType,
      })
      return NextResponse.json(
        {
          error: 'Invalid or missing authorization. Payloads require valid engagement ID.',
        },
        { status: 403 }
      )
    }

    // Generate payload
    const generated = generatePayload(body.vulnType, body.targetComponent, body.engagementId)

    const payload: Payload = {
      id: generated.id,
      vulnType: generated.vulnType,
      payload: generated.payload,
      mitreId: generated.mitreId,
      cvssScore: generated.cvssScore,
      remediation: generated.remediation,
      engagementId: body.engagementId,
      generatedAt: new Date().toISOString(),
    }

    // Audit log
    console.log('[REDTEAM] Payload generated:', {
      id: payload.id,
      vulnType: body.vulnType,
      mitreId: payload.mitreId,
      engagementId: body.engagementId,
      timestamp: payload.generatedAt,
    })

    return NextResponse.json({ payload })
  } catch (error) {
    console.error('[REDTEAM] Payload generation error:', error)
    return NextResponse.json(
      {
        error: 'Internal server error',
      },
      { status: 500 }
    )
  }
}

// GET — Return list of supported vulnerability types
export async function GET(): Promise<NextResponse> {
  return NextResponse.json({
    supportedTypes: [
      'sql_injection',
      'xss',
      'command_injection',
      'path_traversal',
      'ssrf',
      'auth_bypass',
      'privilege_escalation',
    ],
    message: 'POST with vulnType, targetComponent, and engagementId to generate payload',
  })
}
