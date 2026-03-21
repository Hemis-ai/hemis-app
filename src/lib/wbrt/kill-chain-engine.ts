// src/lib/wbrt/kill-chain-engine.ts
import type { AttackGraph, AttackGraphNode, AttackGraphEdge, KillChain, KillChainStep, MitreAttackMapping } from '@/lib/types/wbrt'
import { MITRE_TACTICS, findTechnique } from './mitre-attack-data'
import { randomUUID } from 'crypto'

/**
 * Build kill chains by finding all paths from entry points to crown jewels in the attack graph.
 */
export function constructKillChains(graph: AttackGraph, engagementId: string): KillChain[] {
  const killChains: KillChain[] = []
  const nodeMap = new Map(graph.nodes.map(n => [n.id, n]))
  const adjList = new Map<string, AttackGraphEdge[]>()

  for (const edge of graph.edges) {
    const existing = adjList.get(edge.source) || []
    existing.push(edge)
    adjList.set(edge.source, existing)
  }

  // Find all paths from entry points to crown jewels (BFS, max depth 8)
  for (const entryId of graph.entryPoints) {
    for (const jewelId of graph.crownJewels) {
      const paths = findPaths(entryId, jewelId, adjList, 8)
      for (const path of paths) {
        const chain = buildKillChain(path, nodeMap, adjList, engagementId)
        if (chain) killChains.push(chain)
      }
    }
  }

  // Sort by impact severity, then likelihood
  const impactOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
  const likelihoodOrder = { VERY_HIGH: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
  killChains.sort((a, b) =>
    (impactOrder[a.impact] - impactOrder[b.impact]) ||
    (likelihoodOrder[a.likelihood] - likelihoodOrder[b.likelihood])
  )

  // Limit to top 10 most impactful chains
  return killChains.slice(0, 10)
}

function findPaths(
  start: string,
  end: string,
  adjList: Map<string, AttackGraphEdge[]>,
  maxDepth: number
): string[][] {
  const paths: string[][] = []
  const queue: { node: string; path: string[] }[] = [{ node: start, path: [start] }]

  while (queue.length > 0) {
    const { node, path } = queue.shift()!
    if (path.length > maxDepth) continue

    if (node === end && path.length > 1) {
      paths.push(path)
      continue
    }

    const edges = adjList.get(node) || []
    for (const edge of edges) {
      if (!path.includes(edge.target)) {
        queue.push({ node: edge.target, path: [...path, edge.target] })
      }
    }
  }

  return paths.slice(0, 5) // Max 5 paths per entry->jewel pair
}

function buildKillChain(
  path: string[],
  nodeMap: Map<string, AttackGraphNode>,
  adjList: Map<string, AttackGraphEdge[]>,
  engagementId: string
): KillChain | null {
  const steps: KillChainStep[] = []
  const mitreMapping: MitreAttackMapping[] = []
  const affectedAssets: string[] = []
  let totalProb = 1

  for (let i = 0; i < path.length - 1; i++) {
    const sourceNode = nodeMap.get(path[i])
    const targetNode = nodeMap.get(path[i + 1])
    if (!sourceNode || !targetNode) continue

    const edges = adjList.get(path[i]) || []
    const edge = edges.find(e => e.target === path[i + 1])
    if (!edge) continue

    totalProb *= edge.probability

    // Determine MITRE tactic based on node types and position
    const tactic = inferTactic(sourceNode, targetNode, i, path.length)
    const technique = findTechnique(edge.subTechniqueId || edge.techniqueId)

    steps.push({
      seq: i + 1,
      tactic: tactic.name,
      tacticId: tactic.id,
      technique: edge.technique,
      techniqueId: edge.techniqueId,
      subTechnique: technique?.subTechniqueName,
      subTechniqueId: edge.subTechniqueId,
      action: generateActionNarrative(sourceNode, targetNode, edge),
      target: targetNode.label,
      result: 'SUCCESS',
      evidence: `Source: ${sourceNode.label} (${sourceNode.metadata.cwe || sourceNode.type})`,
      nodeIds: [sourceNode.id, targetNode.id],
    })

    mitreMapping.push({
      tacticId: tactic.id,
      tacticName: tactic.name,
      techniqueId: edge.techniqueId,
      techniqueName: edge.technique,
      subTechniqueId: edge.subTechniqueId,
      subTechniqueName: technique?.subTechniqueName,
      confidence: Math.round(edge.probability * 100),
      evidence: edge.description,
    })

    if (targetNode.type === 'asset' || targetNode.type === 'crown_jewel') {
      affectedAssets.push(targetNode.label)
    }
  }

  if (steps.length < 2) return null

  // Build chain name from first and last step
  const firstName = nodeMap.get(path[0])?.label || 'Entry'
  const lastName = nodeMap.get(path[path.length - 1])?.label || 'Target'
  const middleNames = path.slice(1, -1).map(id => nodeMap.get(id)?.label || '').filter(Boolean)

  const name = middleNames.length > 0
    ? `${firstName} \u2192 ${middleNames.join(' \u2192 ')} \u2192 ${lastName}`
    : `${firstName} \u2192 ${lastName}`

  const likelihood = totalProb > 0.5 ? 'VERY_HIGH' : totalProb > 0.3 ? 'HIGH' : totalProb > 0.15 ? 'MEDIUM' : 'LOW'
  const hasCritical = steps.some(s => {
    const node = nodeMap.get(s.nodeIds[1])
    return node?.severity === 'CRITICAL'
  })
  const impact = hasCritical ? 'CRITICAL' : totalProb > 0.3 ? 'HIGH' : 'MEDIUM'

  const narrative = generateNarrative(steps, nodeMap, path)

  return {
    id: randomUUID(),
    engagementId,
    name,
    narrative,
    likelihood,
    impact,
    steps,
    mitreMapping,
    affectedAssets: [...new Set(affectedAssets)],
    estimatedTimeToExploit: estimateTime(steps.length, totalProb),
    detectionDifficulty: totalProb > 0.5 ? 'MODERATE' : 'DIFFICULT',
  }
}

function inferTactic(
  source: AttackGraphNode,
  target: AttackGraphNode,
  stepIndex: number,
  totalSteps: number
): { id: string; name: string } {
  if (stepIndex === 0 && source.type === 'entry_point') return { id: 'TA0001', name: 'Initial Access' }
  if (target.type === 'vulnerability') return { id: 'TA0002', name: 'Execution' }
  if (target.type === 'privilege') return { id: 'TA0004', name: 'Privilege Escalation' }
  if (source.type === 'privilege' && target.type === 'asset') return { id: 'TA0008', name: 'Lateral Movement' }
  if (target.type === 'crown_jewel') return { id: 'TA0010', name: 'Exfiltration' }
  if (target.type === 'asset') return { id: 'TA0007', name: 'Discovery' }
  if (stepIndex === totalSteps - 2) return { id: 'TA0009', name: 'Collection' }
  return { id: 'TA0002', name: 'Execution' }
}

function generateActionNarrative(
  source: AttackGraphNode,
  target: AttackGraphNode,
  edge: AttackGraphEdge
): string {
  const actions: Record<string, string> = {
    entry_point: `The attacker identifies and targets ${source.label}, probing for exploitable weaknesses.`,
    vulnerability: `Exploiting ${source.label}, the attacker leverages ${edge.technique} to reach ${target.label}.`,
    privilege: `With ${source.label}, the attacker escalates access toward ${target.label}.`,
    asset: `Moving laterally through ${source.label}, the attacker discovers and accesses ${target.label}.`,
    crown_jewel: `The attacker reaches the crown jewel: ${target.label}, completing the attack chain.`,
  }
  return actions[source.type] || edge.description
}

function generateNarrative(
  steps: KillChainStep[],
  nodeMap: Map<string, AttackGraphNode>,
  path: string[]
): string {
  const firstNode = nodeMap.get(path[0])
  const lastNode = nodeMap.get(path[path.length - 1])
  const tactics = [...new Set(steps.map(s => s.tactic))].join(', ')

  return `An attacker begins by targeting ${firstNode?.label || 'the application'}, ` +
    `progressing through ${steps.length} attack stages spanning ${tactics}. ` +
    steps.map((s, i) => `Step ${i + 1}: ${s.action}`).join(' ') +
    ` Ultimately reaching ${lastNode?.label || 'the target'}, ` +
    `this attack path poses a significant risk to business operations and data integrity.`
}

function estimateTime(stepCount: number, probability: number): string {
  const baseHours = stepCount * 2
  const adjustedHours = Math.round(baseHours / Math.max(probability, 0.1))
  if (adjustedHours <= 4) return '2-4 hours'
  if (adjustedHours <= 12) return '4-12 hours'
  if (adjustedHours <= 24) return '12-24 hours'
  return '1-3 days'
}
