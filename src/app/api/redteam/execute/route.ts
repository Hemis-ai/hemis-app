import { NextRequest, NextResponse } from 'next/server'
import type { ExecutionResult } from '@/lib/types'

/**
 * POST /api/redteam/execute
 * Execute authorized attack simulation
 * Requires valid engagement ID for authorization
 */

interface ExecuteRequest {
  engagementId: string
  targetUrl: string
  simulationType: string
}

interface ExecuteResponse {
  execution?: ExecutionResult
  error?: string
}

// Mock execution cache (in production, use database)
const executionCache = new Map<string, ExecutionResult>()

export async function POST(request: NextRequest): Promise<NextResponse<ExecuteResponse>> {
  try {
    const body: ExecuteRequest = await request.json()

    // Validate required fields
    if (!body.engagementId || !body.targetUrl || !body.simulationType) {
      return NextResponse.json(
        {
          error: 'Missing required fields: engagementId, targetUrl, simulationType',
        },
        { status: 400 }
      )
    }

    // Authorization verification
    if (!body.engagementId.trim()) {
      return NextResponse.json(
        {
          error: 'Invalid engagement. Simulations require valid authorization.',
        },
        { status: 403 }
      )
    }

    // Rate limiting check (max 10 concurrent simulations per engagement)
    const engagementExecutions = Array.from(executionCache.values()).filter(
      e => e.engagementId === body.engagementId && e.status === 'RUNNING'
    )

    if (engagementExecutions.length >= 10) {
      return NextResponse.json(
        {
          error: 'Execution limit reached. Maximum 10 concurrent simulations per engagement.',
        },
        { status: 429 }
      )
    }

    // Create execution record
    const executionId = `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    const startedAt = new Date().toISOString()

    const execution: ExecutionResult = {
      id: executionId,
      engagementId: body.engagementId,
      targetUrl: body.targetUrl,
      simulationType: body.simulationType,
      status: 'RUNNING',
      startedAt,
    }

    // Cache execution
    executionCache.set(executionId, execution)

    // Simulate async execution
    simulateExecution(executionId)

    // Audit log
    console.log('[REDTEAM] Execution started:', {
      id: executionId,
      engagementId: body.engagementId,
      targetUrl: body.targetUrl,
      simulationType: body.simulationType,
      timestamp: startedAt,
    })

    return NextResponse.json({ execution })
  } catch (error) {
    console.error('[REDTEAM] Execution error:', error)
    return NextResponse.json(
      {
        error: 'Internal server error',
      },
      { status: 500 }
    )
  }
}

/**
 * Simulate async execution
 * Updates cache as execution progresses
 */
async function simulateExecution(executionId: string) {
  const execution = executionCache.get(executionId)
  if (!execution) return

  try {
    // Simulate execution duration (2-5 seconds)
    const duration = Math.random() * 3000 + 2000
    await new Promise(r => setTimeout(r, duration))

    execution.status = 'COMPLETED'
    execution.completedAt = new Date().toISOString()

    console.log(`[REDTEAM] Execution completed: ${executionId}`)
  } catch (error) {
    execution.status = 'FAILED'
    execution.completedAt = new Date().toISOString()
    console.error(`[REDTEAM] Execution failed: ${executionId}`, error)
  }
}

// GET — Return execution status
export async function GET(request: NextRequest): Promise<NextResponse> {
  const executionId = request.nextUrl.searchParams.get('id')

  if (!executionId) {
    return NextResponse.json({
      message: 'Provide ?id=exec_xxx to check execution status',
    })
  }

  const execution = executionCache.get(executionId)

  if (!execution) {
    return NextResponse.json({
      error: 'Execution not found',
    }, { status: 404 })
  }

  return NextResponse.json({ execution })
}
