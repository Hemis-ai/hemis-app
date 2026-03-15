// HemisX SAST — Type Definitions

export type SastSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type SastConfidence = 'HIGH' | 'MEDIUM' | 'LOW'
export type SastStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
export type FindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'REMEDIATED' | 'IN_PROGRESS'

export type SupportedLanguage =
  | 'javascript' | 'typescript' | 'python' | 'php'
  | 'java' | 'go' | 'ruby' | 'csharp' | 'unknown'

// ─── Rule definition (used by the scanner engine) ──────────────────────────
export interface SastRule {
  id:          string          // "SAST-INJ-001"
  name:        string
  description: string
  pattern:     RegExp
  languages:   SupportedLanguage[] | ['all']
  severity:    SastSeverity
  confidence:  SastConfidence
  owasp:       string          // "A03:2021 – Injection"
  cwe:         string          // "CWE-89"
  category:    SastCategory
  remediation: string
}

export type SastCategory =
  | 'Injection'
  | 'Cryptography'
  | 'Authentication'
  | 'Authorization'
  | 'Secrets'
  | 'Deserialization'
  | 'Path Traversal'
  | 'SSRF'
  | 'XSS'
  | 'Misconfiguration'
  | 'Logging'
  | 'Race Condition'
  | 'XXE'
  | 'Dependencies'

// ─── A single scanner finding ───────────────────────────────────────────────
export interface SastFindingResult {
  id:           string
  scanId:       string
  ruleId:       string
  ruleName:     string
  severity:     SastSeverity
  confidence:   SastConfidence
  language:     string
  filePath:     string
  lineStart:    number
  lineEnd:      number
  codeSnippet:  string
  description:  string
  remediation:  string
  owasp:        string
  cwe:          string
  category:     SastCategory
  status:       FindingStatus
  falsePositive: boolean
  detectedAt:   string
}

// ─── Scan summary returned by API ───────────────────────────────────────────
export interface SastScanResult {
  id:            string
  name:          string
  language:      string
  linesOfCode:   number
  filesScanned:  number
  status:        SastStatus
  duration?:     number       // ms
  startedAt:     string
  completedAt?:  string
  summary: {
    critical: number
    high:     number
    medium:   number
    low:      number
    info:     number
    total:    number
  }
  findings:      SastFindingResult[]
  owaspCoverage: OwaspCategory[]
}

export interface OwaspCategory {
  id:      string    // "A01"
  name:    string    // "Broken Access Control"
  count:   number
  highest: SastSeverity | null
}

// ─── Scan request payload ────────────────────────────────────────────────────
export interface SastScanRequest {
  name:     string
  language?: SupportedLanguage
  files:    SastFile[]
}

export interface SastFile {
  path:    string
  content: string
}
