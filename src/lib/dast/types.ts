// ─── DAST Types (adapted from hemisx-dast) ─────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export type DastScanStatus =
  | 'CREATED' | 'QUEUED' | 'RUNNING' | 'PAUSED'
  | 'COMPLETED' | 'FAILED' | 'CANCELLED'

export type DastFindingStatus =
  | 'OPEN' | 'ACKNOWLEDGED' | 'REMEDIATED' | 'FALSE_POSITIVE' | 'IN_PROGRESS'

export type AuthConfig =
  | { type: 'none' }
  | {
      type: 'form'
      loginUrl: string
      usernameField: string
      passwordField: string
      username: string
      password: string
      loggedInPattern: string
    }
  | { type: 'bearer'; token: string }
  | { type: 'apikey'; headerName: string; value: string }
  | {
      type: 'oauth2'
      tokenUrl: string
      clientId: string
      clientSecret: string
      scope?: string
      grantType?: 'client_credentials' | 'password'
      username?: string
      password?: string
    }
  | { type: 'cookie'; cookieName: string; cookieValue: string; domain?: string; path?: string }
  | { type: 'header'; headers: Record<string, string> }

export interface CreateDastScanInput {
  orgId: string
  name: string
  targetUrl: string
  scope?: string[]
  excludedPaths?: string[]
  authConfig?: AuthConfig
  scanProfile?: ScanProfile
}

export type ScanProfile = 'full' | 'quick' | 'api_only' | 'deep'

// ─── Scan Policy Configuration ──────────────────────────────────────────────

export type AttackStrength = 'LOW' | 'MEDIUM' | 'HIGH' | 'INSANE'
export type AlertThreshold = 'OFF' | 'DEFAULT' | 'LOW' | 'MEDIUM' | 'HIGH'

export interface ScanPolicyConfig {
  name: string
  defaultStrength: AttackStrength
  defaultThreshold: AlertThreshold
  maxRuleDurationMins: number
  threadPerHost: number
  enabledScannerIds?: string[]
  disabledScannerIds?: string[]
}

export interface ScanProgressEvent {
  scanId: string
  status: DastScanStatus
  progress: number
  currentPhase: string
  endpointsDiscovered: number
  endpointsTested: number
  payloadsSent: number
  findingsCount: number
  timestamp: string
  message?: string
}

// ─── ZAP Types ────────────────────────────────────────────────────────────

export interface ZapVersionResponse { version: string }
export interface ZapResultResponse { Result: string }
export interface ZapSpiderStartResponse { scan: string }
export interface ZapSpiderStatusResponse { status: string }
export interface ZapSpiderResultsResponse { results: string[] }
export interface ZapAjaxSpiderStatusResponse { status: string }
export interface ZapActiveScanStartResponse { scan: string }
export interface ZapActiveScanStatusResponse { status: string }
export interface ZapContextCreateResponse { contextId: string }
export interface ZapNewUserResponse { userId: string }
export interface ZapHttpSessionsResponse { sessions: string[][] }

export interface ZapRawAlert {
  sourceid: string; other: string; method: string; evidence: string
  pluginId: string; cweid: string; confidence: string; wascid: string
  description: string; messageId: string; inputVector: string
  url: string; tags: Record<string, string>; reference: string
  solution: string; alert: string; param: string; attack: string
  name: string; risk: string; id: string; alertRef: string
}

export interface ZapAlertsResponse { alerts: ZapRawAlert[] }

export interface ZapAlert {
  id: string; pluginId: string; name: string; description: string
  risk: string; confidence: string; cweId: string; wascId: string
  url: string; method: string; param: string; attack: string
  evidence: string; solution: string; reference: string
  tags: Record<string, string>
}

export interface SpiderResult {
  scanId: string; urlsDiscovered: number; urls: string[]; durationMs: number
}

export interface ActiveScanResult {
  scanId: string; progress: number; durationMs: number
  status: 'completed' | 'stopped' | 'failed'
}

// ─── CVSS Types ──────────────────────────────────────────────────────────

export type AttackVector = 'N' | 'A' | 'L' | 'P'
export type AttackComplexity = 'L' | 'H'
export type PrivilegesRequired = 'N' | 'L' | 'H'
export type UserInteraction = 'N' | 'R'
export type Scope = 'U' | 'C'
export type ImpactMetric = 'N' | 'L' | 'H'

export interface CvssInput {
  AV: AttackVector; AC: AttackComplexity; PR: PrivilegesRequired
  UI: UserInteraction; S: Scope; C: ImpactMetric; I: ImpactMetric; A: ImpactMetric
}

export interface CvssResult {
  score: number; vector: string; severity: Severity
}

export interface OwaspMapping {
  owaspCategory: string; cweId: string; type: string
  mitreAttackIds: string[]; pciDssRefs: string[]; soc2Refs: string[]
}

export interface CreateFindingInput {
  scanId: string; zapAlertId?: string; pluginId?: string; type: string
  owaspCategory: string; cweId?: string; severity: Severity
  cvssScore?: number; cvssVector?: string; riskScore: number
  title: string; description: string; businessImpact?: string
  affectedUrl: string; affectedParameter?: string; injectionPoint?: string
  payload?: string; requestEvidence?: string; responseEvidence?: string
  remediation: string; remediationCode?: string
  pciDssRefs?: string[]; soc2Refs?: string[]; mitreAttackIds?: string[]
  confidenceScore: number
}
