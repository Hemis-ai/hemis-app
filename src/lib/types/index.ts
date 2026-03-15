// ─── Shared ───────────────────────────────────────────────────────────────
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type Status   = 'OPEN' | 'REMEDIATED' | 'ACKNOWLEDGED'

// ─── Scanner ──────────────────────────────────────────────────────────────
export interface ScanFinding {
  id:          string
  severity:    Severity
  service:     string        // IAM, S3, EC2, RDS…
  resource:    string        // resource ARN / name
  title:       string
  description: string
  remediation: string
  compliance:  string[]      // ['SOC2-CC6.1', 'ISO27001-A.9.1']
  riskScore:   number        // 0–100
  status:      Status
  region:      string
  detectedAt:  string
}

export interface ScanResult {
  id:          string
  startedAt:   string
  completedAt: string
  resourcesScanned: number
  riskScore:   number
  findings:    ScanFinding[]
  complianceScore: { soc2: number; iso27001: number }
}

// ─── HEMIS ────────────────────────────────────────────────────────────────
export type MitreTactic =
  | 'Reconnaissance' | 'Resource Development' | 'Initial Access'
  | 'Execution' | 'Persistence' | 'Privilege Escalation'
  | 'Defense Evasion' | 'Credential Access' | 'Discovery'
  | 'Lateral Movement' | 'Collection' | 'Command and Control'
  | 'Exfiltration' | 'Impact'

export type TechniqueStatus = 'vulnerable' | 'mitigated' | 'tested' | 'untested'

export interface MitreTechnique {
  id:     string   // T1190
  name:   string
  tactic: MitreTactic
  status: TechniqueStatus
}

export interface AttackChainStep {
  seq:       number
  timestamp: string
  phase:     string
  technique: string
  techniqueId: string
  target:    string
  result:    'SUCCESS' | 'FAILED' | 'PARTIAL'
  detail:    string
}

export interface SimulationResult {
  id:         string
  prompt:     string
  startedAt:  string
  duration:   string
  steps:      AttackChainStep[]
  findings:   number
  criticals:  number
  techniques: MitreTechnique[]
}

// ─── Blue Team ────────────────────────────────────────────────────────────
export interface ThreatAlert {
  id:        string
  severity:  Severity
  title:     string
  summary:   string        // AI plain-English summary
  source:    string        // CloudTrail, GuardDuty, VPC Flow Logs…
  resource:  string
  ip?:       string
  region:    string
  timestamp: string
  status:    'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED'
  tactics:   string[]      // MITRE tactics
  autoResponded: boolean
  responseActions: string[]
}

export interface KillChainEvent {
  timestamp: string
  stage:     string
  action:    string
  actor:     string
  target:    string
  severity:  Severity
}

export interface HealthScore {
  overall:    number
  detection:  number
  response:   number
  coverage:   number
  mttr:       string        // Mean time to respond
}

// ─── Red Team ─────────────────────────────────────────────────────────────
export interface Finding {
  id:                 string
  type:               string        // sql_injection, xss, command_injection, etc.
  severity:           Severity
  cvssScore:          number        // 0-10
  affectedComponent:  string        // endpoint, service, or resource affected
  description:        string
  remediation:        string
  proof_of_concept:   string
  detectedAt:         string        // ISO timestamp
  mitreId:            string        // T1190, etc.
  status:             Status        // OPEN, ACKNOWLEDGED, REMEDIATED
}

export interface ScanJob {
  id:           string
  target:       string
  scope:        string[]
  engagementId: string
  status:       'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
  progress:     number        // 0-100
  findings?:    Finding[]
  startedAt:    string
  completedAt?: string
}

export interface Payload {
  id:           string
  vulnType:     string
  payload:      string
  mitreId:      string
  cvssScore:    number
  remediation:  string
  engagementId: string
  generatedAt:  string
}

export interface ExecutionResult {
  id:             string
  engagementId:   string
  targetUrl:      string
  simulationType: string
  status:         'RUNNING' | 'COMPLETED' | 'FAILED'
  startedAt:      string
  completedAt?:   string
}

// ─── DAST ──────────────────────────────────────────────────────────────────
export type DastScanStatus = 'CREATED' | 'QUEUED' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
export type DastFindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'REMEDIATED' | 'FALSE_POSITIVE' | 'IN_PROGRESS'

export interface DastScan {
  id:               string
  orgId?:           string
  name:             string
  targetUrl:        string
  status:           DastScanStatus
  scanProfile:      'full' | 'quick' | 'api_only'
  progress:         number
  currentPhase:     string
  endpointsDiscovered: number
  endpointsTested:  number
  payloadsSent:     number
  findingsCount?:   number
  criticalCount:    number
  highCount:        number
  mediumCount:      number
  lowCount:         number
  infoCount:        number
  riskScore:        number
  executiveSummary: string | null
  reportUrl:        string | null
  startedAt:        string
  completedAt:      string | null
  createdAt?:       string
}

export interface DastFinding {
  id:                string
  scanId:            string
  type?:             string
  title:             string
  description:       string
  severity:          Severity
  riskScore?:        number
  cvssScore:         number | null
  cvssVector:        string | null
  owaspCategory:     string
  cweId:             string | null
  affectedUrl:       string
  affectedParameter: string | null
  payload:           string | null
  evidence?:         string | null
  confidenceScore:   number
  status:            DastFindingStatus
  isConfirmed?:      boolean
  businessImpact:    string | null
  remediation:       string
  remediationCode:   string | null
  pciDssRefs:        string[]
  soc2Refs:          string[]
  mitreAttackIds:    string[]
  detectedAt?:       string
}

export interface DastScanProgress {
  scanId:             string
  status:             DastScanStatus
  progress:           number
  currentPhase:       string
  endpointsDiscovered: number
  endpointsTested:    number
  payloadsSent:       number
  findingsCount:      number
  message:            string
  timestamp:          string
}
