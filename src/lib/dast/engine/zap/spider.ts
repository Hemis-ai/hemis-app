import { ZapClient } from './zap-client'
import type { SpiderResult } from '../../types'

const DEFAULT_POLL_INTERVAL_MS = 2000
const MAX_POLL_ITERATIONS = 1800

export interface SpiderOptions {
  targetUrl: string
  contextName?: string
  maxChildren?: number
  includeAjaxSpider?: boolean
  pollIntervalMs?: number
  onProgress?: (percent: number, phase: string) => void
}

export async function runSpider(client: ZapClient, options: SpiderOptions): Promise<SpiderResult> {
  const { targetUrl, contextName, maxChildren, includeAjaxSpider = false, pollIntervalMs = DEFAULT_POLL_INTERVAL_MS, onProgress } = options
  const startTime = Date.now()

  const scanId = await client.startSpider(targetUrl, contextName, maxChildren)

  let iterations = 0
  while (iterations < MAX_POLL_ITERATIONS) {
    const status = await client.getSpiderStatus(scanId)
    onProgress?.(status, 'traditional_spider')
    if (status >= 100) break
    await sleep(pollIntervalMs)
    iterations++
  }
  if (iterations >= MAX_POLL_ITERATIONS) await client.stopSpider(scanId)

  if (includeAjaxSpider) {
    await client.startAjaxSpider(targetUrl, contextName)
    let ajaxIterations = 0
    while (ajaxIterations < MAX_POLL_ITERATIONS) {
      const ajaxStatus = await client.getAjaxSpiderStatus()
      onProgress?.(ajaxStatus === 'stopped' ? 100 : 50, 'ajax_spider')
      if (ajaxStatus === 'stopped') break
      await sleep(pollIntervalMs)
      ajaxIterations++
    }
    if (ajaxIterations >= MAX_POLL_ITERATIONS) await client.stopAjaxSpider()
  }

  const urls = await client.getSpiderResults(scanId)
  return { scanId, urlsDiscovered: urls.length, urls, durationMs: Date.now() - startTime }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
