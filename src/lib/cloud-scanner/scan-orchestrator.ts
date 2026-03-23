// src/lib/cloud-scanner/scan-orchestrator.ts
import type { CloudScan, CloudScanProgress, CloudScanStatus } from '@/lib/types/cloud-scanner'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'
import { randomUUID } from 'crypto'

// In-memory stores
export const progressStore = new Map<string, CloudScanProgress>()
const scanStore = new Map<string, CloudScan>()

function updateProgress(scanId: string, status: CloudScanStatus, progress: number, phase: string, message: string) {
  progressStore.set(scanId, { scanId, status, progress, currentPhase: phase, message, timestamp: new Date().toISOString() })
}

export function getScan(id: string): CloudScan | null {
  return scanStore.get(id) ?? null
}

export function listScans(): CloudScan[] {
  return Array.from(scanStore.values()).sort(
    (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
  )
}

export function createScan(connectionId: string, accountId: string, accountAlias?: string): CloudScan {
  const scan: CloudScan = {
    ...MOCK_CLOUD_SCAN,
    id: randomUUID(),
    connectionId,
    accountId,
    accountAlias,
    status: 'CREATED',
    progress: 0,
    currentPhase: 'created',
    startedAt: new Date().toISOString(),
    completedAt: undefined,
  }
  scanStore.set(scan.id, scan)
  return scan
}

export async function runScan(scanId: string): Promise<void> {
  const scan = scanStore.get(scanId)
  if (!scan) return

  const phases: Array<{ status: CloudScanStatus; progress: number; phase: string; message: string; delay: number }> = [
    { status: 'CONNECTING',       progress: 10, phase: 'connecting',       message: 'Assuming IAM role via STS…',               delay: 800  },
    { status: 'DISCOVERING',      progress: 25, phase: 'discovering',      message: 'Discovering resources across 3 regions…',  delay: 1200 },
    { status: 'SCANNING_IAM',     progress: 45, phase: 'scanning_iam',     message: 'Auditing IAM users, roles, and policies…', delay: 1500 },
    { status: 'SCANNING_DATA',    progress: 62, phase: 'scanning_data',    message: 'Scanning S3 buckets and RDS instances…',   delay: 1200 },
    { status: 'SCANNING_NETWORK', progress: 78, phase: 'scanning_network', message: 'Checking security groups and VPCs…',       delay: 1000 },
    { status: 'ANALYZING',        progress: 90, phase: 'analyzing',        message: 'Chaining risks and mapping compliance…',   delay: 1200 },
    { status: 'COMPLETED',        progress: 100, phase: 'completed',       message: 'Scan complete. 9 findings detected.',      delay: 0    },
  ]

  for (const p of phases) {
    await new Promise(r => setTimeout(r, p.delay))
    updateProgress(scanId, p.status, p.progress, p.phase, p.message)
    const updated: CloudScan = { ...scan, status: p.status, progress: p.progress, currentPhase: p.phase }
    if (p.status === 'COMPLETED') {
      updated.completedAt = new Date().toISOString()
      // Merge mock findings/results into this scan
      Object.assign(updated, {
        findings: MOCK_CLOUD_SCAN.findings,
        inventory: MOCK_CLOUD_SCAN.inventory,
        complianceScores: MOCK_CLOUD_SCAN.complianceScores,
        attackScenarios: MOCK_CLOUD_SCAN.attackScenarios,
        remediationQueue: MOCK_CLOUD_SCAN.remediationQueue,
        summary: MOCK_CLOUD_SCAN.summary,
        riskScore: MOCK_CLOUD_SCAN.riskScore,
        riskLevel: MOCK_CLOUD_SCAN.riskLevel,
      })
    }
    scanStore.set(scanId, updated)
  }
}
