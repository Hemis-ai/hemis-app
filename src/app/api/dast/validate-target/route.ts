import { NextRequest, NextResponse } from 'next/server'
import { validateTarget } from '@/lib/dast/target-validator'

/**
 * POST /api/dast/validate-target — Validate target URL reachability and detect tech stack
 *
 * Returns expanded validation including:
 * - detectedTech: string[] — fingerprinted technologies
 * - apiSpecUrl / apiSpecFormat — detected OpenAPI/Swagger spec
 * - hasGraphql / graphqlEndpoint — detected GraphQL endpoint
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { url } = body

    if (!url?.trim()) {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 })
    }

    // Validate URL format first
    try {
      new URL(url)
    } catch {
      return NextResponse.json({
        reachable: false,
        url,
        detectedTech: [],
        apiSpecUrl: null,
        apiSpecFormat: null,
        hasGraphql: false,
        graphqlEndpoint: null,
        error: 'Invalid URL format',
      })
    }

    const result = await validateTarget(url)
    return NextResponse.json(result)
  } catch (error) {
    console.error('POST /api/dast/validate-target error:', error)
    return NextResponse.json({ error: 'Validation failed' }, { status: 500 })
  }
}
