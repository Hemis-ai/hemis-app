// src/lib/wbrt/attack-graph-engine.ts
import type { SastFindingResult } from '@/lib/types/sast'
import type { AttackGraph, AttackGraphNode, AttackGraphEdge } from '@/lib/types/wbrt'
import type { AttackSurface } from './attack-surface-mapper'
import { CWE_TO_MITRE, findTechnique } from './mitre-attack-data'
import { randomUUID } from 'crypto'

let Anthropic: any
try { Anthropic = require('@anthropic-ai/sdk').default } catch { Anthropic = null }

interface GraphGenInput {
  engagementId: string
  findings: SastFindingResult[]
  surface: AttackSurface
}

/**
 * Generate attack graph using Claude for intelligent path chaining,
 * with deterministic fallback when API is unavailable.
 */
export async function generateAttackGraph(input: GraphGenInput): Promise<AttackGraph> {
  const { engagementId, findings, surface } = input

  // Build vulnerability nodes from SAST findings
  const vulnNodes: AttackGraphNode[] = findings.map(f => ({
    id: `vuln-${f.id}`,
    type: 'vulnerability' as const,
    label: f.ruleName,
    description: f.description,
    severity: f.severity,
    metadata: {
      findingId: f.id,
      cwe: f.cwe,
      owasp: f.owasp,
      filePath: f.filePath,
      line: String(f.lineStart),
      category: f.category,
    },
  }))

  // Combine all nodes
  const allNodes: AttackGraphNode[] = [
    ...surface.entryPoints,
    ...vulnNodes,
    ...surface.assets,
    ...surface.crownJewels,
  ]

  // Privilege escalation nodes (synthetic)
  const privNodes: AttackGraphNode[] = []
  const hasAuthFindings = findings.some(f => ['Authentication', 'Authorization'].includes(f.category))
  if (hasAuthFindings) {
    const privNode: AttackGraphNode = {
      id: `priv-${randomUUID()}`,
      type: 'privilege',
      label: 'Elevated Privileges',
      description: 'Attacker gains elevated access through auth/authz bypass',
      metadata: { level: 'admin' },
    }
    privNodes.push(privNode)
    allNodes.push(privNode)
  }

  const hasCredentialFindings = findings.some(f => f.category === 'Secrets')
  if (hasCredentialFindings) {
    const credNode: AttackGraphNode = {
      id: `priv-${randomUUID()}`,
      type: 'privilege',
      label: 'Stolen Credentials',
      description: 'Attacker obtains valid credentials from hardcoded secrets',
      metadata: { level: 'service_account' },
    }
    privNodes.push(credNode)
    allNodes.push(credNode)
  }

  let edges: AttackGraphEdge[]

  // Try Claude-powered edge generation
  if (Anthropic && process.env.ANTHROPIC_API_KEY) {
    try {
      edges = await generateEdgesWithClaude(allNodes, findings)
    } catch (err) {
      console.warn('[WBRT] Claude API failed, using deterministic fallback:', err)
      edges = generateEdgesDeterministic(allNodes, findings, surface, privNodes)
    }
  } else {
    edges = generateEdgesDeterministic(allNodes, findings, surface, privNodes)
  }

  return {
    id: randomUUID(),
    engagementId,
    nodes: allNodes,
    edges,
    entryPoints: surface.entryPoints.map(n => n.id),
    crownJewels: surface.crownJewels.map(n => n.id),
    generatedAt: new Date().toISOString(),
  }
}

async function generateEdgesWithClaude(
  nodes: AttackGraphNode[],
  findings: SastFindingResult[]
): Promise<AttackGraphEdge[]> {
  const client = new Anthropic()

  const nodesSummary = nodes.map(n => ({
    id: n.id, type: n.type, label: n.label, severity: n.severity,
    cwe: n.metadata.cwe, category: n.metadata.category,
  }))

  const prompt = `You are a senior penetration tester analyzing an attack graph for a white box red team assessment.

Given these nodes (vulnerabilities, assets, entry points, privileges, crown jewels):
${JSON.stringify(nodesSummary, null, 2)}

Generate attack path edges that chain these nodes into realistic multi-step attack scenarios. Each edge represents an attacker moving from one node to the next using a specific MITRE ATT&CK technique.

Rules:
- Edges must flow logically: entry_point \u2192 vulnerability \u2192 privilege/asset \u2192 crown_jewel
- Each edge needs a MITRE technique ID (e.g., T1190, T1078.004)
- Probability should be 0.0-1.0 based on exploitation difficulty
- Generate 10-25 edges creating 2-5 distinct attack paths
- Focus on realistic SMB attack scenarios

Return ONLY valid JSON array of edges:
[{"source":"node_id","target":"node_id","technique":"name","techniqueId":"T1xxx","subTechniqueId":"T1xxx.yyy","probability":0.8,"description":"how attacker moves","prerequisites":["what they need"]}]`

  const response = await client.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 4096,
    messages: [{ role: 'user', content: prompt }],
  })

  const text = response.content[0].type === 'text' ? response.content[0].text : ''
  const jsonMatch = text.match(/\[[\s\S]*\]/)
  if (!jsonMatch) throw new Error('No JSON array in Claude response')

  const rawEdges = JSON.parse(jsonMatch[0])
  return rawEdges.map((e: any) => ({
    id: randomUUID(),
    source: e.source,
    target: e.target,
    technique: e.technique || 'Unknown',
    techniqueId: e.techniqueId || 'T1190',
    subTechniqueId: e.subTechniqueId,
    probability: Math.min(1, Math.max(0, e.probability || 0.5)),
    description: e.description || '',
    prerequisites: e.prerequisites || [],
  }))
}

function generateEdgesDeterministic(
  allNodes: AttackGraphNode[],
  findings: SastFindingResult[],
  surface: AttackSurface,
  privNodes: AttackGraphNode[]
): AttackGraphEdge[] {
  const edges: AttackGraphEdge[] = []
  const vulnNodes = allNodes.filter(n => n.type === 'vulnerability')

  // Entry point \u2192 vulnerability edges
  for (const entry of surface.entryPoints) {
    const entryFile = entry.metadata.filePath
    const relatedVulns = vulnNodes.filter(v => v.metadata.filePath === entryFile)
    for (const vuln of relatedVulns) {
      const cwe = vuln.metadata.cwe
      const mitreIds = CWE_TO_MITRE[cwe] || ['T1190']
      const technique = findTechnique(mitreIds[0])

      edges.push({
        id: randomUUID(),
        source: entry.id,
        target: vuln.id,
        technique: technique?.techniqueName || 'Exploit Public-Facing Application',
        techniqueId: mitreIds[0].split('.')[0],
        subTechniqueId: mitreIds[0].includes('.') ? mitreIds[0] : undefined,
        probability: vuln.severity === 'CRITICAL' ? 0.9 : vuln.severity === 'HIGH' ? 0.7 : 0.5,
        description: `Exploit ${vuln.label} in ${entry.label}`,
        prerequisites: ['Network access to target'],
      })
    }
  }

  // Vulnerability \u2192 privilege edges (for auth/secret findings)
  for (const vuln of vulnNodes) {
    const category = vuln.metadata.category
    if (['Authentication', 'Authorization', 'Secrets'].includes(category)) {
      for (const priv of privNodes) {
        const mitreIds = CWE_TO_MITRE[vuln.metadata.cwe] || ['T1078']
        edges.push({
          id: randomUUID(),
          source: vuln.id,
          target: priv.id,
          technique: 'Exploit for Privilege Escalation',
          techniqueId: mitreIds[0].split('.')[0],
          subTechniqueId: mitreIds[0].includes('.') ? mitreIds[0] : undefined,
          probability: 0.7,
          description: `Leverage ${vuln.label} to obtain ${priv.label}`,
          prerequisites: ['Successful exploitation of vulnerability'],
        })
      }
    }
  }

  // Privilege \u2192 crown jewel edges
  for (const priv of privNodes) {
    for (const jewel of surface.crownJewels) {
      edges.push({
        id: randomUUID(),
        source: priv.id,
        target: jewel.id,
        technique: 'Data from Cloud Storage',
        techniqueId: 'T1530',
        probability: 0.8,
        description: `Access ${jewel.label} using ${priv.label}`,
        prerequisites: ['Elevated privileges obtained'],
      })
    }
  }

  // Vulnerability \u2192 asset edges (lateral movement)
  const injectionVulns = vulnNodes.filter(v =>
    ['Injection', 'SSRF', 'Deserialization'].includes(v.metadata.category)
  )
  for (const vuln of injectionVulns) {
    for (const asset of surface.assets.slice(0, 3)) {
      edges.push({
        id: randomUUID(),
        source: vuln.id,
        target: asset.id,
        technique: 'Exploitation of Remote Services',
        techniqueId: 'T1210',
        probability: 0.5,
        description: `Pivot from ${vuln.label} to ${asset.label}`,
        prerequisites: ['Successful exploitation of entry vulnerability'],
      })
    }
  }

  // Asset \u2192 crown jewel edges
  for (const asset of surface.assets.filter(a => a.metadata.exposure === 'restricted' || a.metadata.type === 'external_integration').slice(0, 2)) {
    for (const jewel of surface.crownJewels) {
      edges.push({
        id: randomUUID(),
        source: asset.id,
        target: jewel.id,
        technique: 'Data from Information Repositories',
        techniqueId: 'T1213',
        probability: 0.4,
        description: `Access ${jewel.label} through ${asset.label}`,
        prerequisites: ['Lateral access to internal systems'],
      })
    }
  }

  return edges
}
