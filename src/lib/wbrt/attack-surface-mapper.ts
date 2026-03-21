// src/lib/wbrt/attack-surface-mapper.ts
import type { SastFindingResult } from '@/lib/types/sast'
import type { ArchitectureContext, AttackGraphNode } from '@/lib/types/wbrt'
import { randomUUID } from 'crypto'

export interface AttackSurface {
  entryPoints: AttackGraphNode[]
  assets: AttackGraphNode[]
  crownJewels: AttackGraphNode[]
  trustBoundaries: { name: string; fromNodes: string[]; toNodes: string[] }[]
}

export function mapAttackSurface(
  findings: SastFindingResult[],
  arch: ArchitectureContext
): AttackSurface {
  const entryPoints: AttackGraphNode[] = []
  const assets: AttackGraphNode[] = []
  const crownJewels: AttackGraphNode[] = []

  // Derive entry points from findings that affect public-facing code
  const publicFacingCategories = ['Injection', 'XSS', 'SSRF', 'Authentication', 'Path Traversal', 'XXE']
  const entryFindings = findings.filter(f => publicFacingCategories.includes(f.category))

  // Group by file to create entry point nodes
  const fileGroups = new Map<string, SastFindingResult[]>()
  for (const f of entryFindings) {
    const existing = fileGroups.get(f.filePath) || []
    existing.push(f)
    fileGroups.set(f.filePath, existing)
  }

  for (const [filePath, fileFindings] of fileGroups) {
    const highest = fileFindings.reduce((max, f) => {
      const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
      return order.indexOf(f.severity) < order.indexOf(max) ? f.severity : max
    }, 'INFO' as string)

    entryPoints.push({
      id: randomUUID(),
      type: 'entry_point',
      label: filePath.split('/').pop() || filePath,
      description: `Public-facing endpoint with ${fileFindings.length} vulnerabilities`,
      severity: highest as any,
      metadata: {
        filePath,
        findingCount: String(fileFindings.length),
        categories: [...new Set(fileFindings.map(f => f.category))].join(', '),
      },
    })
  }

  // Derive assets from architecture context
  for (const tech of arch.techStack) {
    assets.push({
      id: randomUUID(),
      type: 'asset',
      label: tech,
      description: `Technology component: ${tech}`,
      metadata: { component: tech },
    })
  }

  // Add network segment assets
  for (const seg of arch.networkSegments) {
    assets.push({
      id: randomUUID(),
      type: 'asset',
      label: seg.name,
      description: `Network segment (${seg.exposure}): ${seg.services.join(', ')}`,
      metadata: {
        exposure: seg.exposure,
        services: seg.services.join(', '),
      },
    })
  }

  // Derive crown jewels from data classification
  const sensitiveData = arch.dataClassifications.filter(d =>
    ['RESTRICTED', 'PII', 'PHI', 'PCI', 'CONFIDENTIAL'].includes(d)
  )
  for (const dataType of sensitiveData) {
    crownJewels.push({
      id: randomUUID(),
      type: 'crown_jewel',
      label: `${dataType} Data Store`,
      description: `Contains ${dataType} classified data requiring protection`,
      metadata: { classification: dataType },
    })
  }

  // Add external integrations as assets
  for (const integration of arch.externalIntegrations) {
    assets.push({
      id: randomUUID(),
      type: 'asset',
      label: integration,
      description: `External integration: ${integration}`,
      metadata: { type: 'external_integration' },
    })
  }

  // Build trust boundaries from network segments
  const trustBoundaries = arch.networkSegments
    .filter(s => s.exposure !== 'public')
    .map(seg => ({
      name: `${seg.name} boundary`,
      fromNodes: entryPoints.map(e => e.id),
      toNodes: assets.filter(a => seg.services.some(s =>
        a.label.toLowerCase().includes(s.toLowerCase())
      )).map(a => a.id),
    }))

  return { entryPoints, assets, crownJewels, trustBoundaries }
}
