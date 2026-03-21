# White Box Red Teaming (WBRT) Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a full White Box Red Teaming product that ingests SAST findings + source code + architecture context, chains vulnerabilities into attack graphs, maps kill chains to full MITRE ATT&CK (with sub-techniques), scores business impact, and generates executive red team reports.

**Architecture:** Hybrid input (import SAST results OR upload code) + architecture questionnaire. Claude-powered attack graph generation chains individual vulns into multi-step attack paths. 6-phase engagement pipeline (ingest, surface mapping, graph generation, kill chain construction, impact scoring, report synthesis). Five UI tabs: Engagement, Attack Graph, Kill Chains, Findings, Report.

**Tech Stack:** Next.js 15 (App Router), React 19, TypeScript, Prisma (optional DB), Claude API (claude-sonnet-4-20250514), inline CSS (matching existing SAST/DAST pattern — no Tailwind in page components).

---

## File Structure

### Types
- **Create:** `src/lib/types/wbrt.ts` — All WBRT type definitions (engagement, attack graph, kill chain, findings, business impact, MITRE mapping)

### MITRE ATT&CK Data
- **Create:** `src/lib/wbrt/mitre-attack-data.ts` — Full ATT&CK matrix: 14 tactics, techniques, sub-techniques with IDs and descriptions

### Engine Library
- **Create:** `src/lib/wbrt/engagement-orchestrator.ts` — 6-phase pipeline orchestrator with in-memory progress tracking
- **Create:** `src/lib/wbrt/attack-surface-mapper.ts` — Identify entry points, trust boundaries, data flows from code + arch context
- **Create:** `src/lib/wbrt/attack-graph-engine.ts` — Claude-powered: chains individual vulns into multi-step attack paths, produces nodes + edges
- **Create:** `src/lib/wbrt/kill-chain-engine.ts` — Maps attack paths to MITRE ATT&CK tactics/techniques/sub-techniques, generates narrative prose
- **Create:** `src/lib/wbrt/impact-scorer.ts` — Business impact scoring: financial, data, compliance, reputational
- **Create:** `src/lib/wbrt/report-generator.ts` — Executive report synthesis (JSON structure for PDF rendering)

### Mock Data
- **Create:** `src/lib/mock-data/wbrt.ts` — Pre-built engagement with 3 kill chains, 8 chained findings, 15 attack graph nodes

### API Routes
- **Create:** `src/app/api/wbrt/engagements/route.ts` — POST (create) + GET (list)
- **Create:** `src/app/api/wbrt/engagements/[id]/route.ts` — GET (detail)
- **Create:** `src/app/api/wbrt/engagements/[id]/run/route.ts` — POST (trigger analysis)
- **Create:** `src/app/api/wbrt/engagements/[id]/progress/route.ts` — GET (poll progress)
- **Create:** `src/app/api/wbrt/attack-graph/[id]/route.ts` — GET attack graph data
- **Create:** `src/app/api/wbrt/kill-chains/[id]/route.ts` — GET kill chains
- **Create:** `src/app/api/wbrt/findings/[id]/route.ts` — GET chained findings + PATCH update status
- **Create:** `src/app/api/wbrt/report/[id]/route.ts` — POST generate report
- **Create:** `src/app/api/wbrt/import-sast/[scanId]/route.ts` — POST import SAST results

### UI
- **Modify:** `src/app/(dashboard)/dashboard/hemis/wbrt/page.tsx` — Full rewrite: 5-tab UI (Engagement, Attack Graph, Kill Chains, Findings, Report)

---

## Task 1: WBRT Type Definitions

**Files:**
- Create: `src/lib/types/wbrt.ts`

- [ ] **Step 1: Create the WBRT type definitions file**

```typescript
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
```

- [ ] **Step 2: Verify types compile**

Run: `cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit src/lib/types/wbrt.ts 2>&1 | head -20`
Expected: No errors (or only unrelated project-wide errors)

- [ ] **Step 3: Commit**

```bash
git add src/lib/types/wbrt.ts
git commit -m "feat(wbrt): add type definitions for White Box Red Teaming"
```

---

## Task 2: MITRE ATT&CK Data Matrix

**Files:**
- Create: `src/lib/wbrt/mitre-attack-data.ts`

- [ ] **Step 1: Create the MITRE ATT&CK data file with all 14 tactics, key techniques, and sub-techniques**

This file exports the full MITRE ATT&CK Enterprise matrix as structured data. Include the 14 tactics, the most relevant ~60 techniques for web/cloud/code-level attacks, and their sub-techniques (~150 total entries). Each entry has: tacticId, tacticName, techniqueId, techniqueName, subTechniqueId?, subTechniqueName?, description, platforms, dataSources.

```typescript
// src/lib/wbrt/mitre-attack-data.ts

export interface MitreAttackEntry {
  tacticId: string
  tacticName: string
  techniqueId: string
  techniqueName: string
  subTechniqueId?: string
  subTechniqueName?: string
  description: string
  platforms: string[]
  dataSources: string[]
}

export const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
] as const

// Full ATT&CK matrix — techniques + sub-techniques relevant to web/cloud/code
// Organized by tactic for lookup efficiency
export const MITRE_ATTACK_MATRIX: MitreAttackEntry[] = [
  // ── TA0043: Reconnaissance ──
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', description: 'Actively scan target infrastructure to gather information', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.001', subTechniqueName: 'Scanning IP Blocks', description: 'Scan IP blocks to identify live hosts and services', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.002', subTechniqueName: 'Vulnerability Scanning', description: 'Scan for vulnerabilities in target systems', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.003', subTechniqueName: 'Wordlist Scanning', description: 'Use wordlists to discover hidden endpoints', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', description: 'Gather information about victim hosts', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', subTechniqueId: 'T1592.002', subTechniqueName: 'Software', description: 'Identify software and versions on targets', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1589', techniqueName: 'Gather Victim Identity Information', description: 'Gather identity details about victims', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1589', techniqueName: 'Gather Victim Identity Information', subTechniqueId: 'T1589.001', subTechniqueName: 'Credentials', description: 'Gather leaked or exposed credentials', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information', description: 'Gather network topology and configuration details', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information', subTechniqueId: 'T1590.005', subTechniqueName: 'IP Addresses', description: 'Discover IP addresses of target infrastructure', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  // ── TA0042: Resource Development ──
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', description: 'Acquire tools, exploits, or infrastructure', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.005', subTechniqueName: 'Exploits', description: 'Obtain exploits for identified vulnerabilities', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.006', subTechniqueName: 'Vulnerabilities', description: 'Research and identify zero-day or known vulnerabilities', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1587', techniqueName: 'Develop Capabilities', description: 'Develop custom attack tools and exploits', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1587', techniqueName: 'Develop Capabilities', subTechniqueId: 'T1587.001', subTechniqueName: 'Malware', description: 'Develop custom malware payloads', platforms: ['PRE'], dataSources: [] },

  // ── TA0001: Initial Access ──
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', description: 'Exploit vulnerabilities in internet-facing applications (SQLi, RCE, SSRF)', platforms: ['Linux', 'Windows', 'Containers', 'IaaS'], dataSources: ['Application Log', 'Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', description: 'Use compromised credentials for initial access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session', 'User Account'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.001', subTechniqueName: 'Default Accounts', description: 'Use default credentials left in production', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.004', subTechniqueName: 'Cloud Accounts', description: 'Use compromised cloud service credentials', platforms: ['IaaS', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1133', techniqueName: 'External Remote Services', description: 'Access via exposed remote services (SSH, RDP, VPN)', platforms: ['Linux', 'Windows'], dataSources: ['Logon Session', 'Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566', techniqueName: 'Phishing', description: 'Social engineering via phishing', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Application Log', 'Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566', techniqueName: 'Phishing', subTechniqueId: 'T1566.002', subTechniqueName: 'Spearphishing Link', description: 'Targeted phishing with malicious links', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', description: 'Compromise via trusted third-party software', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', subTechniqueId: 'T1195.001', subTechniqueName: 'Compromise Software Dependencies', description: 'Inject malicious code into package dependencies', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', subTechniqueId: 'T1195.002', subTechniqueName: 'Compromise Software Supply Chain', description: 'Compromise build or distribution pipeline', platforms: ['Linux', 'Windows'], dataSources: ['File'] },

  // ── TA0002: Execution ──
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', description: 'Execute commands via scripting interpreters', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', subTechniqueId: 'T1059.004', subTechniqueName: 'Unix Shell', description: 'Execute commands via bash/sh', platforms: ['Linux'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', subTechniqueId: 'T1059.006', subTechniqueName: 'Python', description: 'Execute Python scripts for post-exploitation', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', subTechniqueId: 'T1059.007', subTechniqueName: 'JavaScript', description: 'Execute JavaScript (Node.js, browser-based)', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1203', techniqueName: 'Exploitation for Client Execution', description: 'Exploit client-side vulnerabilities for code execution', platforms: ['Linux', 'Windows'], dataSources: ['Application Log', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1610', techniqueName: 'Deploy Container', description: 'Deploy malicious container for execution', platforms: ['Containers'], dataSources: ['Container', 'Pod'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1648', techniqueName: 'Serverless Execution', description: 'Execute code via serverless functions (Lambda, Cloud Functions)', platforms: ['IaaS', 'SaaS'], dataSources: ['Application Log', 'Cloud Service'] },

  // ── TA0003: Persistence ──
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1505', techniqueName: 'Server Software Component', description: 'Install persistent backdoor via server components', platforms: ['Linux', 'Windows'], dataSources: ['Application Log', 'File'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1505', techniqueName: 'Server Software Component', subTechniqueId: 'T1505.003', subTechniqueName: 'Web Shell', description: 'Deploy web shell for persistent access', platforms: ['Linux', 'Windows'], dataSources: ['Application Log', 'File'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098', techniqueName: 'Account Manipulation', description: 'Modify accounts to maintain access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098', techniqueName: 'Account Manipulation', subTechniqueId: 'T1098.001', subTechniqueName: 'Additional Cloud Credentials', description: 'Add cloud credentials for persistent access', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098', techniqueName: 'Account Manipulation', subTechniqueId: 'T1098.003', subTechniqueName: 'Additional Cloud Roles', description: 'Assign additional cloud roles', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1136', techniqueName: 'Create Account', description: 'Create new accounts for persistent access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1136', techniqueName: 'Create Account', subTechniqueId: 'T1136.003', subTechniqueName: 'Cloud Account', description: 'Create cloud IAM user or service account', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1078', techniqueName: 'Valid Accounts', description: 'Maintain access through valid credentials', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session'] },

  // ── TA0004: Privilege Escalation ──
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1068', techniqueName: 'Exploitation for Privilege Escalation', description: 'Exploit software vulnerability to escalate privileges', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['Process'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1078', techniqueName: 'Valid Accounts', description: 'Use valid accounts with elevated privileges', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.004', subTechniqueName: 'Cloud Accounts', description: 'Escalate via misconfigured cloud IAM', platforms: ['IaaS', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1611', techniqueName: 'Escape to Host', description: 'Escape container to access host system', platforms: ['Containers'], dataSources: ['Container', 'Process'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1548', techniqueName: 'Abuse Elevation Control Mechanism', description: 'Bypass OS privilege escalation controls', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1548', techniqueName: 'Abuse Elevation Control Mechanism', subTechniqueId: 'T1548.003', subTechniqueName: 'Sudo and Sudo Caching', description: 'Abuse sudo misconfigurations', platforms: ['Linux'], dataSources: ['Command'] },

  // ── TA0005: Defense Evasion ──
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal', description: 'Remove evidence of intrusion', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File', 'Process'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal', subTechniqueId: 'T1070.001', subTechniqueName: 'Clear Windows Event Logs', description: 'Clear event logs to hide activity', platforms: ['Windows'], dataSources: ['Process', 'Windows Registry'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal', subTechniqueId: 'T1070.002', subTechniqueName: 'Clear Linux or Mac System Logs', description: 'Clear syslog and auth logs', platforms: ['Linux'], dataSources: ['File', 'Process'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562', techniqueName: 'Impair Defenses', description: 'Disable or modify security tools', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Process', 'Cloud Service'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562', techniqueName: 'Impair Defenses', subTechniqueId: 'T1562.001', subTechniqueName: 'Disable or Modify Tools', description: 'Disable security monitoring tools', platforms: ['Linux', 'Windows'], dataSources: ['Process'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562', techniqueName: 'Impair Defenses', subTechniqueId: 'T1562.008', subTechniqueName: 'Disable Cloud Logs', description: 'Disable CloudTrail, GCP audit logs', platforms: ['IaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', description: 'Use non-password authentication tokens', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', subTechniqueId: 'T1550.001', subTechniqueName: 'Application Access Token', description: 'Use stolen OAuth/API tokens to bypass auth', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },

  // ── TA0006: Credential Access ──
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', description: 'Find credentials stored insecurely', platforms: ['Linux', 'Windows', 'IaaS', 'SaaS', 'Containers'], dataSources: ['Command', 'File'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.001', subTechniqueName: 'Credentials In Files', description: 'Hardcoded credentials in source code, configs', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['File'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.005', subTechniqueName: 'Cloud Instance Metadata API', description: 'Access cloud metadata service for credentials (SSRF → IMDS)', platforms: ['IaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.007', subTechniqueName: 'Container API', description: 'Extract secrets from container orchestration APIs', platforms: ['Containers'], dataSources: ['Container'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', description: 'Attempt to discover credentials through brute force', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session', 'User Account'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.001', subTechniqueName: 'Password Guessing', description: 'Guess passwords using common patterns', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.004', subTechniqueName: 'Credential Stuffing', description: 'Use breached credentials against target', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1212', techniqueName: 'Exploitation for Credential Access', description: 'Exploit software vulnerability to access credentials', platforms: ['Linux', 'Windows'], dataSources: ['Process'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1528', techniqueName: 'Steal Application Access Token', description: 'Steal OAuth tokens or API keys', platforms: ['SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1606', techniqueName: 'Forge Web Credentials', description: 'Forge authentication tokens or cookies', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session', 'Web Credential'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1606', techniqueName: 'Forge Web Credentials', subTechniqueId: 'T1606.001', subTechniqueName: 'Web Cookies', description: 'Forge session cookies for unauthorized access', platforms: ['SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1606', techniqueName: 'Forge Web Credentials', subTechniqueId: 'T1606.002', subTechniqueName: 'SAML Tokens', description: 'Forge SAML tokens (Golden SAML)', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },

  // ── TA0007: Discovery ──
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1046', techniqueName: 'Network Service Discovery', description: 'Discover services running on network hosts', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1580', techniqueName: 'Cloud Infrastructure Discovery', description: 'Discover cloud resources, VPCs, subnets', platforms: ['IaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1526', techniqueName: 'Cloud Service Discovery', description: 'Enumerate cloud services and configurations', platforms: ['IaaS', 'SaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1087', techniqueName: 'Account Discovery', description: 'Enumerate user and service accounts', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1087', techniqueName: 'Account Discovery', subTechniqueId: 'T1087.004', subTechniqueName: 'Cloud Account', description: 'Enumerate cloud IAM users and roles', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1613', techniqueName: 'Container and Resource Discovery', description: 'Discover containers, pods, and orchestration details', platforms: ['Containers'], dataSources: ['Container'] },

  // ── TA0008: Lateral Movement ──
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1021', techniqueName: 'Remote Services', description: 'Move laterally using remote services', platforms: ['Linux', 'Windows'], dataSources: ['Logon Session', 'Network Traffic'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1021', techniqueName: 'Remote Services', subTechniqueId: 'T1021.004', subTechniqueName: 'SSH', description: 'Lateral movement via SSH with stolen keys', platforms: ['Linux'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', description: 'Lateral movement using stolen tokens', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', subTechniqueId: 'T1550.001', subTechniqueName: 'Application Access Token', description: 'Use stolen app tokens to access other services', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1210', techniqueName: 'Exploitation of Remote Services', description: 'Exploit internal services for lateral movement', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },

  // ── TA0009: Collection ──
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage', description: 'Access data from cloud storage (S3, Blob, GCS)', platforms: ['IaaS', 'SaaS'], dataSources: ['Cloud Storage'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories', description: 'Access data from wikis, SharePoint, databases', platforms: ['SaaS'], dataSources: ['Application Log'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories', subTechniqueId: 'T1213.003', subTechniqueName: 'Code Repositories', description: 'Access source code repositories for secrets and IP', platforms: ['SaaS'], dataSources: ['Application Log'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1119', techniqueName: 'Automated Collection', description: 'Automate data collection from multiple sources', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Command', 'File'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1005', techniqueName: 'Data from Local System', description: 'Collect sensitive data from local filesystems', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'File'] },

  // ── TA0011: Command and Control ──
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', description: 'Use application protocols for C2 communication', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', subTechniqueId: 'T1071.001', subTechniqueName: 'Web Protocols', description: 'Use HTTP/HTTPS for C2 traffic', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', subTechniqueId: 'T1071.004', subTechniqueName: 'DNS', description: 'Use DNS for covert C2 communication', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1102', techniqueName: 'Web Service', description: 'Use legitimate web services for C2', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1102', techniqueName: 'Web Service', subTechniqueId: 'T1102.002', subTechniqueName: 'Bidirectional Communication', description: 'Use web service for bidirectional C2', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },

  // ── TA0010: Exfiltration ──
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', description: 'Exfiltrate data via cloud storage or web services', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Network Traffic', 'Cloud Storage'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', subTechniqueId: 'T1567.002', subTechniqueName: 'Exfiltration to Cloud Storage', description: 'Upload stolen data to attacker-controlled cloud storage', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', description: 'Exfiltrate data using non-standard protocols', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', subTechniqueId: 'T1048.003', subTechniqueName: 'Exfiltration Over Unencrypted Non-C2 Protocol', description: 'Use DNS, ICMP or other protocols for data exfil', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1537', techniqueName: 'Transfer Data to Cloud Account', description: 'Transfer data to attacker-controlled cloud account', platforms: ['IaaS'], dataSources: ['Cloud Storage'] },

  // ── TA0040: Impact ──
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1485', techniqueName: 'Data Destruction', description: 'Destroy data to disrupt business operations', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File', 'Cloud Storage'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact', description: 'Encrypt data for ransomware or disruption', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery', description: 'Delete backups and recovery mechanisms', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Cloud Storage', 'File'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1498', techniqueName: 'Network Denial of Service', description: 'Perform DDoS to disrupt services', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1498', techniqueName: 'Network Denial of Service', subTechniqueId: 'T1498.001', subTechniqueName: 'Direct Network Flood', description: 'Volumetric attack against network infrastructure', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1496', techniqueName: 'Resource Hijacking', description: 'Hijack compute resources for cryptomining', platforms: ['Linux', 'Windows', 'IaaS', 'Containers'], dataSources: ['Process', 'Cloud Service'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1565', techniqueName: 'Data Manipulation', description: 'Manipulate data to affect business processes', platforms: ['Linux', 'Windows'], dataSources: ['File', 'Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1565', techniqueName: 'Data Manipulation', subTechniqueId: 'T1565.001', subTechniqueName: 'Stored Data Manipulation', description: 'Modify stored data in databases', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
]

// ── Helper functions ──
export function getTacticById(id: string) {
  return MITRE_TACTICS.find(t => t.id === id)
}

export function getTechniquesByTactic(tacticId: string): MitreAttackEntry[] {
  return MITRE_ATTACK_MATRIX.filter(e => e.tacticId === tacticId)
}

export function getSubTechniques(techniqueId: string): MitreAttackEntry[] {
  return MITRE_ATTACK_MATRIX.filter(e => e.subTechniqueId?.startsWith(techniqueId))
}

export function findTechnique(techniqueId: string): MitreAttackEntry | undefined {
  return MITRE_ATTACK_MATRIX.find(e =>
    (e.subTechniqueId === techniqueId) || (!e.subTechniqueId && e.techniqueId === techniqueId)
  )
}

// Map CWE to likely MITRE techniques (used by attack-graph-engine)
export const CWE_TO_MITRE: Record<string, string[]> = {
  'CWE-89':   ['T1190'],                    // SQL Injection → Exploit Public App
  'CWE-78':   ['T1190', 'T1059.004'],       // OS Command Injection
  'CWE-79':   ['T1190', 'T1059.007'],       // XSS
  'CWE-22':   ['T1190', 'T1005'],           // Path Traversal
  'CWE-918':  ['T1190', 'T1552.005'],       // SSRF → Cloud Metadata
  'CWE-502':  ['T1190', 'T1059'],           // Deserialization → RCE
  'CWE-798':  ['T1552.001', 'T1078'],       // Hardcoded Credentials
  'CWE-327':  ['T1552.001'],                // Weak Crypto
  'CWE-611':  ['T1190', 'T1005'],           // XXE
  'CWE-287':  ['T1078', 'T1110'],           // Improper Auth
  'CWE-862':  ['T1078', 'T1068'],           // Missing Authorization
  'CWE-863':  ['T1068'],                    // Incorrect Authorization
  'CWE-352':  ['T1190'],                    // CSRF
  'CWE-434':  ['T1190', 'T1505.003'],       // Unrestricted Upload → Web Shell
  'CWE-94':   ['T1059.007'],                // Code Injection
  'CWE-116':  ['T1190'],                    // Improper Output Encoding
  'CWE-200':  ['T1005', 'T1530'],           // Information Exposure
  'CWE-269':  ['T1068', 'T1548'],           // Improper Privilege Mgmt
  'CWE-306':  ['T1078.001'],                // Missing Auth for Critical Function
  'CWE-732':  ['T1068', 'T1222'],           // Incorrect Permission Assignment
}
```

- [ ] **Step 2: Verify file compiles**

Run: `cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit src/lib/wbrt/mitre-attack-data.ts 2>&1 | head -10`

- [ ] **Step 3: Commit**

```bash
git add src/lib/wbrt/mitre-attack-data.ts
git commit -m "feat(wbrt): add full MITRE ATT&CK matrix with sub-techniques and CWE mapping"
```

---

## Task 3: Mock Data

**Files:**
- Create: `src/lib/mock-data/wbrt.ts`

- [ ] **Step 1: Create mock data file with a realistic SMB engagement scenario**

Create a pre-built engagement demonstrating: web app (Next.js + PostgreSQL on AWS) with SAST findings chained into 3 kill chains, 8 chained findings, and a 15-node attack graph. Scenario: SQL injection in login → credential extraction → IAM role assumption → S3 data exfiltration.

The mock data should include:
- `MOCK_WBRT_ENGAGEMENT`: Full engagement object with all fields populated
- `MOCK_ATTACK_GRAPH`: 15 nodes (mix of vulnerability, asset, privilege, entry_point, crown_jewel) + 18 edges
- `MOCK_KILL_CHAINS`: 3 kill chains with full MITRE mapping and narrative prose
- `MOCK_WBRT_FINDINGS`: 8 chained findings with business impact scores
- `MOCK_WBRT_REPORT`: Executive report with summary, compliance gaps, remediation roadmap
- `MOCK_SAST_SCANS_FOR_IMPORT`: Lightweight list of past SAST scans (id + name + date + finding count) for the import dropdown

Follow the exact structure from `src/lib/types/wbrt.ts`. Use realistic data that demonstrates value to SMBs. Include timestamps from March 2026.

- [ ] **Step 2: Verify import works**

Run: `cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit src/lib/mock-data/wbrt.ts 2>&1 | head -10`

- [ ] **Step 3: Commit**

```bash
git add src/lib/mock-data/wbrt.ts
git commit -m "feat(wbrt): add realistic mock data for demo engagement"
```

---

## Task 4: Engine — Attack Surface Mapper

**Files:**
- Create: `src/lib/wbrt/attack-surface-mapper.ts`

- [ ] **Step 1: Create the attack surface mapper**

This module takes SAST findings + architecture context and identifies:
- Entry points (public APIs, login forms, file upload endpoints)
- Trust boundaries (DMZ → app tier → DB tier → cloud services)
- Data flows (user input → processing → storage → external)
- Crown jewels (databases, key stores, PII repositories)

It returns `AttackGraphNode[]` for the asset/entry_point/crown_jewel nodes.

```typescript
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
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/wbrt/attack-surface-mapper.ts
git commit -m "feat(wbrt): add attack surface mapper for entry points, assets, crown jewels"
```

---

## Task 5: Engine — Attack Graph Engine (Claude-Powered)

**Files:**
- Create: `src/lib/wbrt/attack-graph-engine.ts`

- [ ] **Step 1: Create the Claude-powered attack graph engine**

This is the core differentiator. It takes SAST findings + attack surface nodes and uses Claude to:
1. Create vulnerability nodes from SAST findings
2. Generate edges that chain vulnerabilities into attack paths
3. Map each edge to a MITRE technique/sub-technique
4. Calculate probability scores for each edge

When Claude API is unavailable, falls back to a deterministic algorithm using `CWE_TO_MITRE` mapping.

```typescript
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
- Edges must flow logically: entry_point → vulnerability → privilege/asset → crown_jewel
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

  // Entry point → vulnerability edges
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

  // Vulnerability → privilege edges (for auth/secret findings)
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

  // Privilege → crown jewel edges
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

  // Vulnerability → asset edges (lateral movement)
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

  // Asset → crown jewel edges
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
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/wbrt/attack-graph-engine.ts
git commit -m "feat(wbrt): add Claude-powered attack graph engine with deterministic fallback"
```

---

## Task 6: Engine — Kill Chain Engine

**Files:**
- Create: `src/lib/wbrt/kill-chain-engine.ts`

- [ ] **Step 1: Create the kill chain engine**

Takes an attack graph and constructs kill chains by finding paths from entry points to crown jewels. Each path becomes a kill chain with MITRE ATT&CK mapping at tactic/technique/sub-technique level, prose narrative, likelihood, and impact assessment.

```typescript
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

  return paths.slice(0, 5) // Max 5 paths per entry→jewel pair
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
    ? `${firstName} → ${middleNames.join(' → ')} → ${lastName}`
    : `${firstName} → ${lastName}`

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
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/wbrt/kill-chain-engine.ts
git commit -m "feat(wbrt): add kill chain engine with MITRE ATT&CK tactic inference and narrative generation"
```

---

## Task 7: Engine — Impact Scorer

**Files:**
- Create: `src/lib/wbrt/impact-scorer.ts`

- [ ] **Step 1: Create the business impact scorer**

Scores each attack path by financial impact, data records at risk, compliance framework impact, reputational damage, and operational disruption. Outputs `WbrtFinding[]` with `BusinessImpact` attached.

```typescript
// src/lib/wbrt/impact-scorer.ts
import type { AttackGraph, KillChain, WbrtFinding, BusinessImpact, ArchitectureContext, DataClassification, ComplianceFramework } from '@/lib/types/wbrt'
import type { SastFindingResult, SastSeverity } from '@/lib/types/sast'
import { randomUUID } from 'crypto'

const SEVERITY_WEIGHT: Record<SastSeverity, number> = {
  CRITICAL: 1.0, HIGH: 0.75, MEDIUM: 0.5, LOW: 0.25, INFO: 0.1,
}

const DATA_CLASS_WEIGHT: Record<DataClassification, number> = {
  RESTRICTED: 1.0, PHI: 0.95, PCI: 0.9, PII: 0.85, CONFIDENTIAL: 0.7, INTERNAL: 0.3, PUBLIC: 0.05,
}

const RECORDS_BY_USER_COUNT: Record<string, number> = {
  '1-100': 5_000, '100-1K': 50_000, '1K-10K': 500_000, '10K+': 5_000_000,
}

const COST_PER_RECORD = 164 // IBM Cost of a Data Breach 2025 average

export function scoreFindings(
  graph: AttackGraph,
  killChains: KillChain[],
  findings: SastFindingResult[],
  arch: ArchitectureContext,
  engagementId: string,
): WbrtFinding[] {
  const wbrtFindings: WbrtFinding[] = []
  const findingMap = new Map(findings.map(f => [`vuln-${f.id}`, f]))
  let priority = 0

  for (const chain of killChains) {
    priority++

    // Collect source SAST findings in this chain
    const sourceIds: string[] = []
    const severities: SastSeverity[] = []
    for (const step of chain.steps) {
      for (const nodeId of step.nodeIds) {
        const finding = findingMap.get(nodeId)
        if (finding) {
          sourceIds.push(finding.id)
          severities.push(finding.severity)
        }
      }
    }

    // Calculate composite severity
    const maxSeverityWeight = Math.max(...severities.map(s => SEVERITY_WEIGHT[s] || 0), 0.25)
    const chainLengthMultiplier = Math.min(chain.steps.length / 3, 2) // longer chains = more impactful

    // Data classification impact
    const dataWeights = arch.dataClassifications.map(d => DATA_CLASS_WEIGHT[d] || 0.1)
    const maxDataWeight = Math.max(...dataWeights, 0.1)

    // Business impact score (1-100)
    const rawScore = (maxSeverityWeight * 40) + (maxDataWeight * 30) + (chainLengthMultiplier * 15) +
      (chain.likelihood === 'VERY_HIGH' ? 15 : chain.likelihood === 'HIGH' ? 10 : chain.likelihood === 'MEDIUM' ? 5 : 2)
    const score = Math.min(100, Math.round(rawScore))

    // Financial estimate
    const estimatedRecords = RECORDS_BY_USER_COUNT[arch.userCount] || 50_000
    const recordsAtRisk = Math.round(estimatedRecords * maxDataWeight * maxSeverityWeight)
    const minCost = recordsAtRisk * COST_PER_RECORD * 0.5
    const maxCost = recordsAtRisk * COST_PER_RECORD * 1.5

    const formatCost = (n: number) => {
      if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`
      if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`
      return `$${n}`
    }

    // Compliance frameworks affected
    const affectedFrameworks = determineAffectedFrameworks(severities, arch.complianceRequirements)

    // Reputational score
    const reputationalScore = Math.round(score * 0.8 + (arch.dataClassifications.includes('PII') ? 15 : 0))

    const businessImpact: BusinessImpact = {
      score,
      financialEstimate: `${formatCost(minCost)} - ${formatCost(maxCost)}`,
      dataRecordsAtRisk: recordsAtRisk,
      dataTypes: arch.dataClassifications.filter(d => DATA_CLASS_WEIGHT[d] >= 0.7),
      complianceFrameworksAffected: affectedFrameworks,
      reputationalScore: Math.min(100, reputationalScore),
      operationalImpact: score >= 80 ? 'Extended service disruption (48-72 hrs)' :
        score >= 60 ? 'Significant service degradation (12-24 hrs)' :
        score >= 40 ? 'Partial service impact (4-8 hrs)' : 'Minimal operational impact',
      legalExposure: affectedFrameworks.length >= 2
        ? 'Class-action risk, regulatory fines, mandatory breach notification'
        : affectedFrameworks.length === 1
        ? 'Regulatory fines possible, breach notification required'
        : 'Limited legal exposure',
    }

    const severity: SastSeverity = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'

    // Remediation steps
    const remediationSteps = generateRemediationSteps(chain, findingMap)

    wbrtFindings.push({
      id: randomUUID(),
      engagementId,
      name: chain.name,
      attackPathNodeIds: chain.steps.flatMap(s => s.nodeIds),
      attackPathDescription: chain.narrative,
      sourceFindingIds: [...new Set(sourceIds)],
      severity,
      businessImpact,
      killChainId: chain.id,
      mitreMapping: chain.mitreMapping,
      remediationPriority: priority,
      remediationSteps,
      status: 'OPEN',
    })
  }

  return wbrtFindings
}

function determineAffectedFrameworks(
  severities: SastSeverity[],
  required: ComplianceFramework[]
): ComplianceFramework[] {
  const hasCritical = severities.includes('CRITICAL')
  const hasHigh = severities.includes('HIGH')

  // All required frameworks are affected if critical/high vulns exist
  if (hasCritical) return required
  if (hasHigh) return required.filter(f => ['PCI_DSS', 'HIPAA', 'SOC2'].includes(f))
  return required.filter(f => f === 'PCI_DSS')
}

function generateRemediationSteps(
  chain: KillChain,
  findingMap: Map<string, SastFindingResult>
): string[] {
  const steps: string[] = []
  const seen = new Set<string>()

  for (const step of chain.steps) {
    for (const nodeId of step.nodeIds) {
      const finding = findingMap.get(nodeId)
      if (finding && !seen.has(finding.remediation)) {
        seen.add(finding.remediation)
        steps.push(`[${finding.severity}] ${finding.ruleName}: ${finding.remediation}`)
      }
    }
  }

  if (steps.length === 0) {
    steps.push('Review and remediate all vulnerabilities in this attack chain')
    steps.push('Implement network segmentation to limit lateral movement')
    steps.push('Add monitoring for the MITRE techniques identified in this kill chain')
  }

  return steps
}
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/wbrt/impact-scorer.ts
git commit -m "feat(wbrt): add business impact scorer with financial, compliance, and reputational scoring"
```

---

## Task 8: Engine — Report Generator

**Files:**
- Create: `src/lib/wbrt/report-generator.ts`

- [ ] **Step 1: Create the report generator**

Synthesizes all WBRT analysis into an executive report structure: summary markdown, risk matrix, compliance gaps, remediation roadmap.

```typescript
// src/lib/wbrt/report-generator.ts
import type { WbrtReport, WbrtFinding, KillChain, AttackGraph, ArchitectureContext, ComplianceGap, RemediationItem } from '@/lib/types/wbrt'
import type { SastSeverity } from '@/lib/types/sast'
import { randomUUID } from 'crypto'

export function generateReport(
  engagementId: string,
  findings: WbrtFinding[],
  killChains: KillChain[],
  graph: AttackGraph,
  arch: ArchitectureContext,
): WbrtReport {
  // Overall risk score = weighted average of finding impact scores
  const totalScore = findings.reduce((sum, f) => sum + f.businessImpact.score, 0)
  const overallRiskScore = findings.length > 0 ? Math.round(totalScore / findings.length) : 0
  const riskLevel: SastSeverity = overallRiskScore >= 80 ? 'CRITICAL' : overallRiskScore >= 60 ? 'HIGH' : overallRiskScore >= 40 ? 'MEDIUM' : 'LOW'

  // Compliance gaps
  const complianceGaps = buildComplianceGaps(findings, arch)

  // Remediation roadmap
  const remediationRoadmap = buildRemediationRoadmap(findings)

  // Executive summary
  const executiveSummary = buildExecutiveSummary(findings, killChains, graph, overallRiskScore, riskLevel, arch)

  return {
    id: randomUUID(),
    engagementId,
    executiveSummary,
    overallRiskScore,
    riskLevel: riskLevel as any,
    attackPathCount: graph.edges.length,
    killChainCount: killChains.length,
    topFindings: findings.slice(0, 5),
    complianceGaps,
    remediationRoadmap,
    generatedAt: new Date().toISOString(),
  }
}

function buildExecutiveSummary(
  findings: WbrtFinding[],
  killChains: KillChain[],
  graph: AttackGraph,
  riskScore: number,
  riskLevel: string,
  arch: ArchitectureContext,
): string {
  const critCount = findings.filter(f => f.severity === 'CRITICAL').length
  const highCount = findings.filter(f => f.severity === 'HIGH').length
  const totalFinancial = findings.reduce((max, f) => {
    const match = f.businessImpact.financialEstimate.match(/\$[\d.]+[MK]/g)
    return match ? f.businessImpact.financialEstimate : max
  }, '$0')

  return `## White Box Red Team Assessment — Executive Summary

### Overall Risk Posture: **${riskLevel}** (${riskScore}/100)

This white box red team assessment analyzed the application architecture (${arch.techStack.join(', ')}) with full source code access, simulating an insider threat with complete knowledge of the system.

### Key Findings

- **${findings.length} exploitable attack paths** identified across ${graph.nodes.length} system components
- **${killChains.length} complete kill chains** from initial access to data exfiltration
- **${critCount} critical** and **${highCount} high** severity attack paths require immediate remediation
- **${graph.entryPoints.length} entry points** identified with exploitable vulnerabilities
- **${graph.crownJewels.length} crown jewels** (sensitive data stores) are reachable through chained attacks

### Risk Categories

${critCount > 0 ? `- **CRITICAL**: ${critCount} attack paths enable full system compromise or data exfiltration` : ''}
${highCount > 0 ? `- **HIGH**: ${highCount} attack paths enable significant unauthorized access` : ''}
${findings.filter(f => f.severity === 'MEDIUM').length > 0 ? `- **MEDIUM**: ${findings.filter(f => f.severity === 'MEDIUM').length} attack paths with moderate business impact` : ''}

### Compliance Impact

${arch.complianceRequirements.map(f => `- **${f}**: Gaps identified — remediation required before audit`).join('\n')}

### Recommended Actions

1. **Immediate (0-48 hrs)**: Remediate all CRITICAL attack paths — focus on breaking the kill chains at their weakest links
2. **Short-term (1-2 weeks)**: Address HIGH severity paths, implement network segmentation
3. **Medium-term (1-3 months)**: Full remediation roadmap, detection rule deployment for identified MITRE techniques
4. **Ongoing**: Re-run WBRT assessment quarterly to track remediation progress`
}

function buildComplianceGaps(
  findings: WbrtFinding[],
  arch: ArchitectureContext,
): ComplianceGap[] {
  const gaps: ComplianceGap[] = []

  const frameworkControls: Record<string, { controlId: string; controlName: string }[]> = {
    PCI_DSS: [
      { controlId: 'PCI-6.2.4', controlName: 'Injection prevention' },
      { controlId: 'PCI-6.3.1', controlName: 'Vulnerability identification' },
      { controlId: 'PCI-1.3.1', controlName: 'Network segmentation' },
      { controlId: 'PCI-8.3.1', controlName: 'Strong authentication' },
    ],
    SOC2: [
      { controlId: 'CC6.1', controlName: 'Logical access controls' },
      { controlId: 'CC6.6', controlName: 'Boundary protection' },
      { controlId: 'CC7.1', controlName: 'Vulnerability management' },
      { controlId: 'CC7.2', controlName: 'Anomaly monitoring' },
    ],
    HIPAA: [
      { controlId: '164.312(a)(1)', controlName: 'Access control' },
      { controlId: '164.312(e)(1)', controlName: 'Transmission security' },
      { controlId: '164.308(a)(1)', controlName: 'Security management' },
    ],
    ISO27001: [
      { controlId: 'A.14.2.1', controlName: 'Secure development policy' },
      { controlId: 'A.12.6.1', controlName: 'Technical vulnerability management' },
    ],
    GDPR: [
      { controlId: 'Art.32', controlName: 'Security of processing' },
      { controlId: 'Art.25', controlName: 'Data protection by design' },
    ],
    CIS: [
      { controlId: 'CIS-7', controlName: 'Continuous vulnerability management' },
      { controlId: 'CIS-16', controlName: 'Application software security' },
    ],
    NIST: [
      { controlId: 'SI-10', controlName: 'Information input validation' },
      { controlId: 'AC-6', controlName: 'Least privilege' },
    ],
  }

  for (const framework of arch.complianceRequirements) {
    const controls = frameworkControls[framework] || []
    const affectedFindings = findings.filter(f =>
      f.businessImpact.complianceFrameworksAffected.includes(framework)
    )

    if (affectedFindings.length > 0) {
      for (const control of controls) {
        gaps.push({
          framework,
          controlId: control.controlId,
          controlName: control.controlName,
          status: affectedFindings.some(f => f.severity === 'CRITICAL') ? 'FAIL' : 'PARTIAL',
          affectedFindingIds: affectedFindings.map(f => f.id),
          remediationNote: `Address attack paths affecting ${control.controlName} — ${affectedFindings.length} findings impact this control`,
        })
      }
    }
  }

  return gaps
}

function buildRemediationRoadmap(findings: WbrtFinding[]): RemediationItem[] {
  return findings.map((f, i) => ({
    priority: i + 1,
    title: `Break kill chain: ${f.name}`,
    description: f.remediationSteps.join('; '),
    effort: f.severity === 'CRITICAL' ? 'HIGH' as const : f.severity === 'HIGH' ? 'MEDIUM' as const : 'LOW' as const,
    impact: f.severity as any,
    affectedFindingIds: [f.id],
    estimatedHours: f.severity === 'CRITICAL' ? 16 : f.severity === 'HIGH' ? 8 : 4,
  }))
}
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/wbrt/report-generator.ts
git commit -m "feat(wbrt): add executive report generator with compliance gaps and remediation roadmap"
```

---

## Task 9: Engine — Engagement Orchestrator

**Files:**
- Create: `src/lib/wbrt/engagement-orchestrator.ts`

- [ ] **Step 1: Create the 6-phase engagement orchestrator**

Follows the DAST `scan-orchestrator.ts` pattern: runs phases sequentially, tracks progress in-memory via a Map, updates status at each phase. Falls back to mock data in demo mode.

```typescript
// src/lib/wbrt/engagement-orchestrator.ts
import type { WbrtEngagement, WbrtProgressEvent, ArchitectureContext } from '@/lib/types/wbrt'
import type { SastFindingResult } from '@/lib/types/sast'
import { mapAttackSurface } from './attack-surface-mapper'
import { generateAttackGraph } from './attack-graph-engine'
import { constructKillChains } from './kill-chain-engine'
import { scoreFindings } from './impact-scorer'
import { generateReport } from './report-generator'
import { MOCK_WBRT_ENGAGEMENT } from '@/lib/mock-data/wbrt'
import { randomUUID } from 'crypto'

// In-memory progress store (same pattern as DAST)
export const progressStore = new Map<string, WbrtProgressEvent>()

// In-memory engagement store (demo mode)
const engagementStore = new Map<string, WbrtEngagement>()

function updateProgress(
  engagementId: string,
  status: WbrtProgressEvent['status'],
  progress: number,
  phase: string,
  message: string,
) {
  progressStore.set(engagementId, {
    engagementId,
    status,
    progress,
    currentPhase: phase,
    message,
    timestamp: new Date().toISOString(),
  })
}

export function getEngagement(id: string): WbrtEngagement | null {
  return engagementStore.get(id) || null
}

export function listEngagements(): WbrtEngagement[] {
  return Array.from(engagementStore.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  )
}

export function createEngagement(
  name: string,
  inputSource: WbrtEngagement['inputSource'],
  arch: ArchitectureContext,
  sastScanId?: string,
): WbrtEngagement {
  const engagement: WbrtEngagement = {
    id: randomUUID(),
    orgId: 'org-demo',
    name,
    inputSource,
    status: 'CREATED',
    progress: 0,
    currentPhase: 'created',
    architectureContext: arch,
    sastScanId,
    killChains: [],
    findings: [],
    createdAt: new Date().toISOString(),
  }

  engagementStore.set(engagement.id, engagement)
  return engagement
}

/**
 * Run the full 6-phase WBRT analysis pipeline.
 * Fire-and-forget from the API route (same as DAST pattern).
 */
export async function runEngagement(
  engagementId: string,
  findings: SastFindingResult[],
): Promise<void> {
  const engagement = engagementStore.get(engagementId)
  if (!engagement) throw new Error(`Engagement ${engagementId} not found`)

  try {
    engagement.status = 'INGESTING'
    engagement.startedAt = new Date().toISOString()
    engagementStore.set(engagementId, engagement)

    // ── Phase 1: Ingest & Normalize (0-15%) ──
    updateProgress(engagementId, 'INGESTING', 5, 'Ingesting', 'Normalizing SAST findings and source context...')
    await sleep(800) // Simulate processing time

    if (findings.length === 0) {
      // Demo mode: use mock data
      const mock = MOCK_WBRT_ENGAGEMENT
      Object.assign(engagement, {
        ...mock,
        id: engagementId,
        name: engagement.name,
        architectureContext: engagement.architectureContext,
        status: 'COMPLETED',
        progress: 100,
        currentPhase: 'complete',
        completedAt: new Date().toISOString(),
      })
      engagementStore.set(engagementId, engagement)
      updateProgress(engagementId, 'COMPLETED', 100, 'Complete', 'Analysis complete (demo mode)')
      return
    }

    updateProgress(engagementId, 'INGESTING', 15, 'Ingesting', `Ingested ${findings.length} findings from SAST scan`)

    // ── Phase 2: Attack Surface Mapping (15-30%) ──
    updateProgress(engagementId, 'MAPPING', 20, 'Mapping Attack Surface', 'Identifying entry points, assets, and crown jewels...')
    const surface = mapAttackSurface(findings, engagement.architectureContext)
    updateProgress(engagementId, 'MAPPING', 30, 'Mapping Attack Surface',
      `Mapped ${surface.entryPoints.length} entry points, ${surface.assets.length} assets, ${surface.crownJewels.length} crown jewels`)

    // ── Phase 3: Attack Graph Generation (30-55%) ──
    updateProgress(engagementId, 'GRAPHING', 35, 'Generating Attack Graph', 'Claude is analyzing vulnerability chains...')
    const attackGraph = await generateAttackGraph({ engagementId, findings, surface })
    engagement.attackGraph = attackGraph
    updateProgress(engagementId, 'GRAPHING', 55, 'Generating Attack Graph',
      `Generated graph with ${attackGraph.nodes.length} nodes and ${attackGraph.edges.length} edges`)

    // ── Phase 4: Kill Chain Construction (55-75%) ──
    updateProgress(engagementId, 'CHAINING', 60, 'Constructing Kill Chains', 'Mapping attack paths to MITRE ATT&CK framework...')
    const killChains = constructKillChains(attackGraph, engagementId)
    engagement.killChains = killChains
    updateProgress(engagementId, 'CHAINING', 75, 'Constructing Kill Chains',
      `Constructed ${killChains.length} kill chains with full MITRE mapping`)

    // ── Phase 5: Business Impact Scoring (75-90%) ──
    updateProgress(engagementId, 'SCORING', 80, 'Scoring Business Impact', 'Calculating financial, compliance, and reputational impact...')
    const wbrtFindings = scoreFindings(attackGraph, killChains, findings, engagement.architectureContext, engagementId)
    engagement.findings = wbrtFindings
    updateProgress(engagementId, 'SCORING', 90, 'Scoring Business Impact',
      `Scored ${wbrtFindings.length} chained findings with business impact`)

    // ── Phase 6: Report Synthesis (90-100%) ──
    updateProgress(engagementId, 'REPORTING', 92, 'Generating Report', 'Synthesizing executive red team report...')
    const report = generateReport(engagementId, wbrtFindings, killChains, attackGraph, engagement.architectureContext)
    engagement.report = report

    // Build summary
    engagement.summary = {
      totalAttackPaths: attackGraph.edges.length,
      totalKillChains: killChains.length,
      criticalFindings: wbrtFindings.filter(f => f.severity === 'CRITICAL').length,
      highFindings: wbrtFindings.filter(f => f.severity === 'HIGH').length,
      mediumFindings: wbrtFindings.filter(f => f.severity === 'MEDIUM').length,
      lowFindings: wbrtFindings.filter(f => f.severity === 'LOW').length,
      overallRiskScore: report.overallRiskScore,
    }

    engagement.status = 'COMPLETED'
    engagement.progress = 100
    engagement.currentPhase = 'complete'
    engagement.completedAt = new Date().toISOString()
    engagementStore.set(engagementId, engagement)

    updateProgress(engagementId, 'COMPLETED', 100, 'Complete',
      `Analysis complete: ${wbrtFindings.length} findings, ${killChains.length} kill chains, risk score ${report.overallRiskScore}/100`)

    console.log(`[WBRT] Engagement complete: ${engagementId}`, {
      findings: wbrtFindings.length,
      killChains: killChains.length,
      riskScore: report.overallRiskScore,
    })

  } catch (err) {
    console.error(`[WBRT] Engagement failed: ${engagementId}`, err)
    engagement.status = 'FAILED'
    engagement.currentPhase = 'failed'
    engagementStore.set(engagementId, engagement)
    updateProgress(engagementId, 'FAILED', engagement.progress, 'Failed', `Analysis failed: ${(err as Error).message}`)
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/wbrt/engagement-orchestrator.ts
git commit -m "feat(wbrt): add 6-phase engagement orchestrator with progress tracking"
```

---

## Task 10: API Routes

**Files:**
- Create: `src/app/api/wbrt/engagements/route.ts`
- Create: `src/app/api/wbrt/engagements/[id]/route.ts`
- Create: `src/app/api/wbrt/engagements/[id]/run/route.ts`
- Create: `src/app/api/wbrt/engagements/[id]/progress/route.ts`
- Create: `src/app/api/wbrt/attack-graph/[id]/route.ts`
- Create: `src/app/api/wbrt/kill-chains/[id]/route.ts`
- Create: `src/app/api/wbrt/findings/[id]/route.ts`
- Create: `src/app/api/wbrt/report/[id]/route.ts`
- Create: `src/app/api/wbrt/import-sast/[scanId]/route.ts`

- [ ] **Step 1: Create all API route files**

Follow the SAST/DAST route patterns: validate input, check auth (gracefully), call engine, return JSON. All routes should work in demo mode without database.

Each route file follows this pattern:
```typescript
import { NextRequest, NextResponse } from 'next/server'
// ... imports from engine/orchestrator
```

**`src/app/api/wbrt/engagements/route.ts`** — POST creates engagement, GET lists all.
**`src/app/api/wbrt/engagements/[id]/route.ts`** — GET returns engagement detail.
**`src/app/api/wbrt/engagements/[id]/run/route.ts`** — POST triggers analysis (fire-and-forget).
**`src/app/api/wbrt/engagements/[id]/progress/route.ts`** — GET returns current progress.
**`src/app/api/wbrt/attack-graph/[id]/route.ts`** — GET returns attack graph.
**`src/app/api/wbrt/kill-chains/[id]/route.ts`** — GET returns kill chains.
**`src/app/api/wbrt/findings/[id]/route.ts`** — GET returns chained findings, PATCH updates status.
**`src/app/api/wbrt/report/[id]/route.ts`** — POST generates report, GET returns existing.
**`src/app/api/wbrt/import-sast/[scanId]/route.ts`** — POST imports SAST scan results for WBRT analysis.

- [ ] **Step 2: Verify routes compile**

Run: `cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit 2>&1 | grep wbrt | head -20`

- [ ] **Step 3: Test API endpoint manually**

Run: `curl -s http://localhost:7777/api/wbrt/engagements | head -5`
Expected: `[]` (empty array) or JSON response

- [ ] **Step 4: Commit**

```bash
git add src/app/api/wbrt/
git commit -m "feat(wbrt): add all API routes for engagements, attack graph, kill chains, findings, report"
```

---

## Task 11: Full UI Page — 5-Tab WBRT Interface

**Files:**
- Modify: `src/app/(dashboard)/dashboard/hemis/wbrt/page.tsx`

- [ ] **Step 1: Rewrite the WBRT page with all 5 tabs**

This is the largest file. Follow SAST/DAST patterns exactly:
- `'use client'` at top
- All state via `useState`
- Inline styles using CSS variables (`var(--color-wbrt)`, `var(--color-bg-elevated)`, etc.)
- Fetch from `/api/wbrt/*` endpoints
- Severity color mapping using existing CSS variables

**Tab 1: ENGAGEMENT** — Setup form:
- Toggle: "Import SAST Scan" vs "Upload Code"
- If import: dropdown of past SAST scans (fetched from `/api/sast/scans`), preview findings count
- If upload: drag-drop code upload (same pattern as SAST multifile)
- Architecture questionnaire form below: tech stack (multi-select chips), deployment model (radio), cloud providers (checkboxes), network segments (dynamic add/remove), auth mechanisms (multi-select), data classification (checkboxes), compliance requirements (checkboxes), external integrations (tag input), user count (dropdown), description (textarea)
- "Run Analysis" button at bottom

**Tab 2: ATTACK GRAPH** — Canvas visualization:
- Render nodes as colored circles/squares based on type (entry=green, vuln=red, privilege=gold, asset=blue, crown_jewel=purple)
- Edges as lines with technique labels
- Click node for detail sidebar
- Legend showing node types
- Stats bar: total nodes, edges, entry points, crown jewels

**Tab 3: KILL CHAINS** — Accordion list:
- Each chain: header with name, likelihood badge, impact badge
- MITRE tactic progression bar (14 colored steps, filled = present in chain)
- Expandable steps: each step shows tactic → technique → sub-technique, action narrative, target, MITRE ID badge
- Estimated time to exploit, detection difficulty badges

**Tab 4: FINDINGS** — Card list:
- Each finding card: name, severity badge, business impact score (large number), financial estimate
- Mini attack path visualization (horizontal node chain)
- Expandable: full remediation steps, compliance frameworks affected, MITRE mapping
- Filter by severity, sort by impact score or priority
- Status toggle (OPEN/ACKNOWLEDGED/REMEDIATED/ACCEPTED_RISK)

**Tab 5: REPORT** — Executive report view:
- Rendered markdown executive summary
- Risk score gauge (circular)
- Stats: attack paths, kill chains, critical/high/medium/low counts
- Compliance gaps table
- Remediation roadmap (priority ordered cards with effort/impact badges)
- Export buttons: PDF, JSON

- [ ] **Step 2: Verify page loads**

Open: `http://localhost:7777/dashboard/hemis/wbrt`
Expected: ENGAGEMENT tab visible with form, no console errors

- [ ] **Step 3: Test demo mode**

Click "Run Analysis" with default/demo data. Should show progress, then results across all tabs.

- [ ] **Step 4: Commit**

```bash
git add src/app/\(dashboard\)/dashboard/hemis/wbrt/page.tsx
git commit -m "feat(wbrt): add full 5-tab UI with engagement, attack graph, kill chains, findings, report"
```

---

## Task 12: Integration Testing

- [ ] **Step 1: Test the full WBRT flow end-to-end**

1. Navigate to `/dashboard/hemis/wbrt`
2. Fill in the architecture questionnaire with demo values
3. Click "Run Analysis" (demo mode)
4. Verify progress updates in real time
5. Switch to Attack Graph tab — verify nodes and edges render
6. Switch to Kill Chains tab — verify MITRE mapping and narratives
7. Switch to Findings tab — verify business impact scores
8. Switch to Report tab — verify executive summary and compliance gaps

- [ ] **Step 2: Test SAST import flow**

1. First run a SAST scan (paste demo code)
2. Navigate to WBRT, select "Import SAST Scan"
3. Select the scan from dropdown
4. Fill architecture context
5. Run analysis
6. Verify findings are chained from SAST results

- [ ] **Step 3: Verify sidebar navigation**

1. Click "WHITE BOX RT" in sidebar — page loads
2. Breadcrumb shows "/ hemis / wbrt"
3. Topbar shows "WHITE BOX RT" title

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix(wbrt): integration test fixes and polish"
```
