import { ZapClient } from './zap-client'
import type { ZapRawAlert, ZapAlert } from '../../types'

const DEFAULT_BATCH_SIZE = 100

export async function fetchAlerts(client: ZapClient, baseUrl?: string, batchSize: number = DEFAULT_BATCH_SIZE): Promise<ZapAlert[]> {
  const allRaw: ZapRawAlert[] = []
  let offset = 0

  while (true) {
    const response = await client.getAlerts(baseUrl, offset, batchSize)
    const batch = response.alerts
    if (!batch || batch.length === 0) break
    allRaw.push(...batch)
    offset += batch.length
    if (batch.length < batchSize) break
  }

  const normalized = allRaw.map(normalizeAlert)
  return deduplicateAlerts(normalized)
}

function normalizeAlert(raw: ZapRawAlert): ZapAlert {
  return {
    id: raw.id, pluginId: raw.pluginId,
    name: (raw.name || raw.alert || '').trim(),
    description: (raw.description || '').trim(),
    risk: normalizeRisk(raw.risk),
    confidence: (raw.confidence || '').trim(),
    cweId: raw.cweid === '-1' ? '' : (raw.cweid || '').trim(),
    wascId: raw.wascid === '-1' ? '' : (raw.wascid || '').trim(),
    url: (raw.url || '').trim(), method: (raw.method || '').trim(),
    param: (raw.param || '').trim(), attack: (raw.attack || '').trim(),
    evidence: (raw.evidence || '').trim(), solution: (raw.solution || '').trim(),
    reference: (raw.reference || '').trim(), tags: raw.tags || {},
  }
}

function normalizeRisk(risk: string): string {
  const trimmed = (risk || '').trim()
  return trimmed === 'Informational' ? 'Info' : trimmed
}

function deduplicateAlerts(alerts: ZapAlert[]): ZapAlert[] {
  const seen = new Set<string>()
  const result: ZapAlert[] = []
  for (const alert of alerts) {
    const key = `${alert.pluginId}|${alert.url}|${alert.param}|${alert.attack}`
    if (!seen.has(key)) { seen.add(key); result.push(alert) }
  }
  return result
}
