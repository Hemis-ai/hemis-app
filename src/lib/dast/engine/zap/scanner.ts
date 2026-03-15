import { ZapClient } from './zap-client'
import type { ActiveScanResult } from '../../types'

const DEFAULT_POLL_INTERVAL_MS = 3000
const MAX_POLL_ITERATIONS = 1200

export interface ActiveScanOptions {
  targetUrl: string
  contextId?: string
  recurse?: boolean
  scanPolicyName?: string
  pollIntervalMs?: number
  onProgress?: (percent: number, phase: string) => void
}

export async function runActiveScan(client: ZapClient, options: ActiveScanOptions): Promise<ActiveScanResult> {
  const { targetUrl, contextId, recurse = true, scanPolicyName, pollIntervalMs = DEFAULT_POLL_INTERVAL_MS, onProgress } = options
  const startTime = Date.now()

  const scanId = await client.startActiveScan(targetUrl, contextId, recurse, scanPolicyName)

  let iterations = 0
  let lastProgress = 0
  while (iterations < MAX_POLL_ITERATIONS) {
    const progress = await client.getActiveScanStatus(scanId)
    lastProgress = progress
    onProgress?.(progress, 'active_scan')
    if (progress >= 100) break
    await sleep(pollIntervalMs)
    iterations++
  }

  const durationMs = Date.now() - startTime
  if (iterations >= MAX_POLL_ITERATIONS) {
    await client.stopActiveScan(scanId)
    return { scanId, progress: lastProgress, durationMs, status: 'stopped' }
  }

  return { scanId, progress: 100, durationMs, status: 'completed' }
}

export async function pauseScan(client: ZapClient, scanId: string): Promise<void> {
  await client.pauseActiveScan(scanId)
}

export async function resumeScan(client: ZapClient, scanId: string): Promise<void> {
  await client.resumeActiveScan(scanId)
}

export async function cancelScan(client: ZapClient, scanId: string): Promise<void> {
  await client.stopActiveScan(scanId)
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
