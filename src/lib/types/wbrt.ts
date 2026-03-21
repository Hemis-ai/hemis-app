// src/lib/types/wbrt.ts
// HemisX WBRT — White Box Red Teaming Type Definitions

import type { SastScanResult, SastFindingResult, SastSeverity } from './sast'

// ─── Engagement Status ──────────────────────────────────────────────────────
export type WbrtStatus = 'CREATED' | 'INGESTING' | 'MAPPING' | 'GRAPHING' | 'CHAINING' | 'SCORING' | 'REPORTING' | 'COMPLETED' | 'FAILED'
export type WbrtInputSource = 'sast_import' | 'code_upload' | 'hybrid'
export type WbrtFindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'REMEDIATED' | 'ACCEPTED_RISK' | 'IN_PROGRESS'
export type DeploymentModel = 'cloud' | 'on_prem' | 'hybrid' | 'multi_cloud'
export type DataClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | 'PII' | 'PHI' | 'PCI'
export type ComplianceFramework = 'PCI_DSS' | 'SOC2' | 'HIPAA' | 'ISO27001' | 'GDPR' | 'CIS' | 'NIST'

// ─── Architecture Context (questionnaire output) ───────────────────────────
export interface ArchitectureContext {
  techStack: string[]                    // ['Next.js', 'PostgreSQL', 'Redis', 'AWS']
  deployment: DeploymentModel
  cloudProviders: string[]               // ['AWS', 'GCP']
  networkSegments: NetworkSegment[]
  authMechanisms: string[]               // ['JWT', 'OAuth2', 'API Keys']
  dataClassifications: DataClassification[]
  complianceRequirements: ComplianceFramework[]
  externalIntegrations: string[]         // ['Stripe', 'SendGrid', 'Twilio']
  userCount: string                      // '1-100', '100-1K', '1K-10K', '10K+'
  description: string                    // freeform architecture description
}

export interface NetworkSegment {
  name: string                           // 'DMZ', 'Internal', 'Database Tier'
  cidr?: string
  services: string[]
  exposure: 'public' | 'internal' | 'restricted'
}

// ─── MITRE ATT&CK Mapping (full depth: tactic → technique → sub-technique) ─
export interface MitreAttackMapping {
  tacticId: string                       // 'TA0001'
  tacticName: string                     // 'Initial Access'
  techniqueId: string                    // 'T1190'
  techniqueName: string                  // 'Exploit Public-Facing Application'
  subTechniqueId?: string                // 'T1190.001'
  subTechniqueName?: string
  confidence: number                     // 0-100
  evidence: string                       // why this mapping applies
}

// ─── Attack Graph ───────────────────────────────────────────────────────────
export type AttackNodeType = 'vulnerability' | 'asset' | 'privilege' | 'data' | 'entry_point' | 'crown_jewel'

export interface AttackGraphNode {
  id: string
  type: AttackNodeType
  label: string
  description: string
  severity?: SastSeverity
  metadata: Record<string, string>       // flexible: cwe, file, line, service, etc.
  x?: number                             // layout position (computed client-side)
  y?: number
}

export interface AttackGraphEdge {
  id: string
  source: string                         // node id
  target: string                         // node id
  technique: string                      // MITRE technique name
  techniqueId: string                    // T1190
  subTechniqueId?: string                // T1190.001
  probability: number                    // 0-1 likelihood
  description: string                    // "Exploiting SQLi to extract credentials"
  prerequisites: string[]                // what attacker needs first
}

export interface AttackGraph {
  id: string
  engagementId: string
  nodes: AttackGraphNode[]
  edges: AttackGraphEdge[]
  entryPoints: string[]                  // node IDs
  crownJewels: string[]                  // node IDs
  generatedAt: string
}

// ─── Kill Chain ─────────────────────────────────────────────────────────────
export interface KillChainStep {
  seq: number
  tactic: string                         // 'Initial Access'
  tacticId: string                       // 'TA0001'
  technique: string                      // 'Exploit Public-Facing Application'
  techniqueId: string                    // 'T1190'
  subTechnique?: string
  subTechniqueId?: string
  action: string                         // "Attacker exploits the exposed login API..."
  target: string                         // what is being attacked
  result: 'SUCCESS' | 'PARTIAL' | 'FAILED'
  evidence: string                       // supporting data (finding ID, code ref)
  nodeIds: string[]                      // attack graph node IDs involved
}

export interface KillChain {
  id: string
  engagementId: string
  name: string                           // "SQLi → Credential Theft → Cloud Takeover"
  narrative: string                      // prose paragraph an exec can read
  likelihood: 'VERY_HIGH' | 'HIGH' | 'MEDIUM' | 'LOW'
  impact: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  steps: KillChainStep[]
  mitreMapping: MitreAttackMapping[]
  affectedAssets: string[]
  estimatedTimeToExploit: string         // "2-4 hours"
  detectionDifficulty: 'EASY' | 'MODERATE' | 'DIFFICULT' | 'VERY_DIFFICULT'
}

// ─── Chained Finding (attack path with business impact) ─────────────────────
export interface BusinessImpact {
  score: number                          // 1-100
  financialEstimate: string              // "$1.2M - $3.5M"
  dataRecordsAtRisk: number
  dataTypes: DataClassification[]
  complianceFrameworksAffected: ComplianceFramework[]
  reputationalScore: number              // 1-100
  operationalImpact: string              // "48hr service disruption"
  legalExposure: string                  // "Class-action risk, regulatory fines"
}

export interface WbrtFinding {
  id: string
  engagementId: string
  name: string                           // "API SQLi → DB Exfil → Cloud Pivot"
  attackPathNodeIds: string[]            // ordered node IDs through graph
  attackPathDescription: string          // human-readable path description
  sourceFindingIds: string[]             // original SAST finding IDs that contribute
  severity: SastSeverity
  businessImpact: BusinessImpact
  killChainId: string                    // associated kill chain
  mitreMapping: MitreAttackMapping[]
  remediationPriority: number            // 1 = fix first
  remediationSteps: string[]
  status: WbrtFindingStatus
}

// ─── WBRT Report ────────────────────────────────────────────────────────────
export interface WbrtReport {
  id: string
  engagementId: string
  executiveSummary: string               // markdown
  overallRiskScore: number               // 0-100
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  attackPathCount: number
  killChainCount: number
  topFindings: WbrtFinding[]
  complianceGaps: ComplianceGap[]
  remediationRoadmap: RemediationItem[]
  generatedAt: string
}

export interface ComplianceGap {
  framework: ComplianceFramework
  controlId: string
  controlName: string
  status: 'FAIL' | 'PARTIAL'
  affectedFindingIds: string[]
  remediationNote: string
}

export interface RemediationItem {
  priority: number
  title: string
  description: string
  effort: 'LOW' | 'MEDIUM' | 'HIGH'
  impact: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  affectedFindingIds: string[]
  estimatedHours: number
}

// ─── Engagement (top-level entity) ──────────────────────────────────────────
export interface WbrtEngagement {
  id: string
  orgId: string
  name: string
  inputSource: WbrtInputSource
  status: WbrtStatus
  progress: number                       // 0-100
  currentPhase: string
  architectureContext: ArchitectureContext
  sastScanId?: string                    // if imported from SAST
  codeFiles?: { path: string; content: string }[]
  attackGraph?: AttackGraph
  killChains: KillChain[]
  findings: WbrtFinding[]
  report?: WbrtReport
  summary?: {
    totalAttackPaths: number
    totalKillChains: number
    criticalFindings: number
    highFindings: number
    mediumFindings: number
    lowFindings: number
    overallRiskScore: number
  }
  createdAt: string
  startedAt?: string
  completedAt?: string
}

// ─── Progress Event (for polling) ───────────────────────────────────────────
export interface WbrtProgressEvent {
  engagementId: string
  status: WbrtStatus
  progress: number
  currentPhase: string
  message: string
  timestamp: string
}
