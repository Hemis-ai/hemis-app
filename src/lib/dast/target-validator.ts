/**
 * Target URL validation — adapted from hemisx-dast/src/services/target-validator.service.ts
 * Validates that a target URL is reachable before starting a scan.
 */

export interface TargetValidationResult {
  reachable: boolean
  url: string
  statusCode?: number
  responseTimeMs?: number
  serverHeader?: string
  error?: string
}

export async function validateTarget(url: string): Promise<TargetValidationResult> {
  const startTime = Date.now()

  try {
    // Validate URL format
    const parsed = new URL(url)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return {
        reachable: false,
        url,
        error: `Unsupported protocol: ${parsed.protocol}. Only http and https are supported.`,
      }
    }

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000) // 10s timeout

    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'HemisX-DAST-Validator/1.0',
      },
    })

    clearTimeout(timeout)
    const responseTimeMs = Date.now() - startTime

    return {
      reachable: true,
      url,
      statusCode: response.status,
      responseTimeMs,
      serverHeader: response.headers.get('server') ?? undefined,
    }
  } catch (error) {
    const responseTimeMs = Date.now() - startTime
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'

    return {
      reachable: false,
      url,
      responseTimeMs,
      error: errorMessage,
    }
  }
}
