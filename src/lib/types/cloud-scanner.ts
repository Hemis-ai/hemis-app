// src/lib/types/cloud-scanner.ts
// HemisX Cloud Misconfiguration Scanner — Type Definitions

// ─── Enums ──────────────────────────────────────────────────────────────────
export type CloudScanStatus =
  | 'CREATED'
  | 'CONNECTING'
  | 'DISCOVERING'
  | 'SCANNING_IAM'
  | 'SCANNING_DATA'
  | 'SCANNING_NETWORK'
  | 'ANALYZING'
  | 'COMPLETED'
  | 'FAILED'

export type CloudProvider = 'AWS' | 'GCP' | 'AZURE'
export type CloudFindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type CloudFindingStatus = 'OPEN' | 'IN_PROGRESS' | 'REMEDIATED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE'
export type CloudCheckCategory = 'IAM' | 'DATA' | 'NETWORK'
export type ComplianceFramework = 'CIS' | 'PCI_DSS' | 'SOC2' | 'HIPAA'
export type FixEffort = '5min' | '1hr' | '1day' | '1week'

// ─── Connection ──────────────────────────────────────────────────────────────
export interface CloudConnection {
  id: string
  orgId: string
  provider: CloudProvider
  accountId: string           // AWS Account ID (12 digits)
  accountAlias?: string       // Human-readable alias
  roleArn: string             // arn:aws:iam::ACCOUNT:role/HemisXScannerRole
  externalId: string          // Confused-deputy protection
  regions: string[]           // Discovered active regions
  connectedAt: string
  lastScannedAt?: string
  status: 'CONNECTED' | 'ERROR' | 'PENDING'
  errorMessage?: string
}

// ─── Scan ────────────────────────────────────────────────────────────────────
export interface CloudScan {
  id: string
  connectionId: string
  accountId: string
  accountAlias?: string
  status: CloudScanStatus
  progress: number            // 0-100
  currentPhase: string
  startedAt: string
  completedAt?: string
  duration?: number           // ms
  riskScore: number           // 0-100 (100 = worst)
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  summary: CloudScanSummary
  findings: CloudFinding[]
  inventory: CloudInventory
  complianceScores: ComplianceScore[]
  attackScenarios: AttackScenario[]
  remediationQueue: RemediationItem[]
}

export interface CloudScanSummary {
  totalFindings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  byCategory: Record<CloudCheckCategory, number>
  estimatedBreachCost: number   // USD
  resourcesScanned: number
  checksRun: number
  checksPassed: number
  checksFailed: number
}

// ─── Progress ────────────────────────────────────────────────────────────────
export interface CloudScanProgress {
  scanId: string
  status: CloudScanStatus
  progress: number
  currentPhase: string
  message: string
  timestamp: string
}

// ─── Finding ─────────────────────────────────────────────────────────────────
export interface CloudFinding {
  id: string
  checkId: string             // e.g. 'IAM-001'
  category: CloudCheckCategory
  severity: CloudFindingSeverity
  status: CloudFindingStatus
  title: string
  resourceId: string          // ARN or resource identifier
  resourceType: string        // 'AWS::S3::Bucket', 'AWS::IAM::User', etc.
  resourceName: string        // Human-readable name
  region: string
  // Risk narrative (the differentiator)
  riskNarrative: string       // Business-context explanation
  attackVector: string        // How an attacker exploits this
  estimatedImpact: string     // Financial/data impact
  // Compliance
  complianceMappings: ComplianceMapping[]
  // Remediation
  fixEffort: FixEffort
  remediation: RemediationDetail
  // Chaining
  chainIds?: string[]         // IDs of attack scenarios this feeds into
  detectedAt: string
  lastSeenAt: string
}

export interface ComplianceMapping {
  framework: ComplianceFramework
  controlId: string           // 'CIS 1.4', 'PCI-DSS 8.3.1'
  controlName: string
  status: 'FAIL' | 'PARTIAL'
}

export interface RemediationDetail {
  summary: string
  console: string             // Step-by-step AWS Console instructions
  cli: string                 // AWS CLI command(s)
  terraform: string           // Terraform HCL snippet
  cloudformation: string      // CloudFormation YAML snippet
  estimatedMinutes: number
}

// ─── Attack Scenarios (Risk Chaining) ────────────────────────────────────────
export interface AttackScenario {
  id: string
  title: string
  severity: CloudFindingSeverity
  likelihood: 'HIGH' | 'MEDIUM' | 'LOW'
  narrative: string           // Full attacker story
  steps: AttackScenarioStep[]
  findingIds: string[]        // Which findings chain together
  estimatedBreachCost: number // USD
  affectedDataTypes: string[]
  complianceImpact: ComplianceFramework[]
}

export interface AttackScenarioStep {
  seq: number
  action: string
  findingId?: string
  technique: string           // e.g. 'Credential Theft via IMDSv1'
}

// ─── Inventory ───────────────────────────────────────────────────────────────
export interface CloudInventory {
  ec2Instances: CloudResource[]
  s3Buckets: CloudResource[]
  rdsInstances: CloudResource[]
  iamUsers: CloudResource[]
  iamRoles: CloudResource[]
  lambdaFunctions: CloudResource[]
  securityGroups: CloudResource[]
  vpcs: CloudResource[]
  totalResources: number
}

export interface CloudResource {
  id: string
  arn: string
  name: string
  type: string
  region: string
  tags: Record<string, string>
  securityStatus: 'CLEAN' | 'WARNING' | 'CRITICAL'
  findingIds: string[]
}

// ─── Compliance ───────────────────────────────────────────────────────────────
export interface ComplianceScore {
  framework: ComplianceFramework
  score: number               // 0-100 (100 = fully compliant)
  passed: number
  failed: number
  total: number
  gaps: ComplianceGap[]
}

export interface ComplianceGap {
  controlId: string
  controlName: string
  status: 'FAIL' | 'PARTIAL'
  findingIds: string[]
  severity: CloudFindingSeverity
}

// ─── Remediation Queue ────────────────────────────────────────────────────────
export interface RemediationItem {
  priority: number
  findingId: string
  title: string
  severity: CloudFindingSeverity
  effort: FixEffort
  estimatedMinutes: number
  impactScore: number         // 0-100 (100 = fix this first)
  category: CloudCheckCategory
  status: CloudFindingStatus
}

// ─── Check Definition ─────────────────────────────────────────────────────────
export interface CloudCheck {
  id: string                  // 'IAM-001'
  category: CloudCheckCategory
  title: string
  description: string
  severity: CloudFindingSeverity
  resourceType: string
  complianceMappings: Omit<ComplianceMapping, 'status'>[]
  fixEffort: FixEffort
  estimatedMinutes: number
}
