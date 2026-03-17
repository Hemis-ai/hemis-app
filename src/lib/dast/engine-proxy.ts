/**
 * Proxy helper for forwarding requests to the Python DAST engine.
 * Falls back to existing Prisma/mock behavior when engine is unavailable.
 */

const DAST_ENGINE_URL = process.env.DAST_ENGINE_URL || 'http://localhost:8000'

/**
 * Check if the Python DAST engine is running.
 */
export async function isDastEngineRunning(): Promise<boolean> {
  try {
    const res = await fetch(`${DAST_ENGINE_URL}/api/dast/health`, {
      signal: AbortSignal.timeout(2000),
    })
    return res.ok
  } catch {
    return false
  }
}

/**
 * Proxy a request to the Python DAST engine.
 * Returns the Response or null if the engine is unreachable.
 */
export async function proxyToEngine(
  path: string,
  options: {
    method?: string
    body?: string | null
    headers?: Record<string, string>
    timeout?: number
  } = {}
): Promise<Response | null> {
  try {
    const url = `${DAST_ENGINE_URL}${path}`
    const res = await fetch(url, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      body: options.body || undefined,
      signal: AbortSignal.timeout(options.timeout || 30000),
    })
    return res
  } catch {
    return null
  }
}

export { DAST_ENGINE_URL }
