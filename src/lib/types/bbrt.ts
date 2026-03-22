// src/lib/types/bbrt.ts
// HemisX BBRT — Black Box Red Teaming Type Definitions

import type { SastSeverity } from './sast'
import type { DataClassification, ComplianceFramework, BusinessImpact, ComplianceGap, RemediationItem, MitreAttackMapping } from './wbrt'

// ─── Engagement Status ──────────────────────────────────────────────────────
export type BbrtStatus =
  | 'CREATED'
  | 'INITIALIZING'
  | 'RECONNAISSANCE'
  | 'SURFACE_MAPPING'
  | 'VULN_DISCOVERY'
  | 'EXPLOIT_CHAINING'
  | 'IMPACT_SCORING'
  | 'REPORTING'
  | 'COMPLETED'
  | 'FAILED'

export type BbrtEngagementType = 'web' | 'api' | 'network' | 'cloud' | 'full'

export type BbrtFindingType =
  | 'RECON_EXPOSURE'
  | 'MISCONFIG'
  | 'VULN'
  | 'CREDENTIAL_LEAK'
  | 'CLOUD_EXPOSURE'
  | 'SUPPLY_CHAIN'
  | 'LLM_VULN'
  | 'INFO_DISCLOSURE'
  | 'CERT_ISSUE'
  | 'AUTH_WEAKNESS'

export type BbrtFindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'IN_PROGRESS' | 'REMEDIATED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE'

export type BbrtExploitability = 'TRIVIAL' | 'EASY' | 'MODERATE' | 'HARD'

export type ExposureLevel = 'PUBLIC' | 'SEMI_PUBLIC' | 'INTERNAL_EXPOSED'

export type AssetType = 'domain' | 'subdomain' | 'ip' | 'cloud_asset' | 'api_endpoint' | 'admin_panel' | 'database' | 'cdn' | 'email_server' | 'load_balancer'

// ─── Industry Vertical ──────────────────────────────────────────────────────
export type IndustryVertical =
  | 'fintech'
  | 'healthcare'
  | 'saas'
  | 'ecommerce'
  | 'government'
  | 'education'
  | 'media'
  | 'manufacturing'
  | 'energy'
  | 'telecom'
  | 'other'

// ─── Business Context ───────────────────────────────────────────────────────
export interface BbrtBusinessContext {
  industry: IndustryVertical
  dataTypes: DataClassification[]
  userCount: string                    // '1-100', '100-1K', '1K-10K', '10K-100K', '100K+'
  revenueRange: string                 // '$0-1M', '$1M-10M', '$10M-100M', '$100M+'
  criticalSystems: string[]            // ['payment API', 'user database', 'auth service']
}

// ─── Target Configuration ───────────────────────────────────────────────────
export interface BbrtTargetConfig {
  targetDomain: string                 // "example.com"
  targetIPs?: string[]                 // optional specific IPs
  targetScope: string[]                // included subdomains/CIDRs
  excludedPaths: string[]              // paths to skip
  engagementType: BbrtEngagementType
  complianceRequirements: ComplianceFramework[]
  businessContext: BbrtBusinessContext
}

// ─── Reconnaissance Results ─────────────────────────────────────────────────
export interface SubdomainRecord {
  subdomain: string                    // "api.example.com"
  ip: string
  status: 'active' | 'inactive' | 'unknown'
  httpStatus?: number                  // 200, 301, 403, etc.
  title?: string                       // page title if accessible
  isShadowAsset: boolean               // not in DNS baseline
  riskScore: number                    // 0-100
}

export interface DnsRecord {
  type: 'A' | 'AAAA' | 'MX' | 'TXT' | 'CNAME' | 'NS' | 'SOA' | 'SRV'
  name: string
  value: string
  ttl: number
  securityNotes?: string               // e.g. "SPF record missing", "DMARC not enforced"
}

export interface PortRecord {
  host: string
  port: number
  protocol: 'tcp' | 'udp'
  state: 'open' | 'filtered' | 'closed'
  service: string                      // "http", "ssh", "mysql"
  version?: string                     // "OpenSSH 8.9", "nginx/1.18.0"
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  notes?: string                       // "Database port exposed to internet"
}

export interface TechStackDetection {
  category: 'framework' | 'server' | 'cms' | 'cdn' | 'analytics' | 'cloud' | 'language' | 'database' | 'waf' | 'os' | 'container'
  name: string                         // "React", "nginx", "WordPress"
  version?: string                     // "18.2.0"
  confidence: number                   // 0-100
  detectedVia: string                  // "HTTP header", "meta tag", "cookie", "error page"
  knownCVEs?: string[]                 // CVE IDs for this version
}

export interface CertRecord {
  host: string
  issuer: string
  subject: string
  validFrom: string
  validTo: string
  serialNumber: string
  signatureAlgorithm: string
  sans: string[]                       // Subject Alternative Names
  issues: CertIssue[]
}

export interface CertIssue {
  type: 'expired' | 'expiring_soon' | 'self_signed' | 'weak_cipher' | 'wildcard' | 'mismatch' | 'revoked' | 'sha1'
  description: string
  severity: SastSeverity
}

export interface OsintRecord {
  source: 'github' | 'pastebin' | 'cert_transparency' | 'breach_db' | 'social_media' | 'dns_history' | 'wayback_machine' | 'shodan'
  type: 'credential_leak' | 'api_key' | 'internal_url' | 'email_address' | 'source_code' | 'config_file' | 'employee_info'
  title: string
  description: string
  url?: string
  severity: SastSeverity
  data: string                         // sanitized excerpt
  discoveredAt: string
}

export interface CloudAssetRecord {
  provider: 'aws' | 'gcp' | 'azure' | 'cloudflare' | 'digital_ocean'
  type: 's3_bucket' | 'blob_storage' | 'gcs_bucket' | 'ec2_instance' | 'lambda' | 'cloud_function' | 'cdn_distribution'
  identifier: string                   // bucket name, instance ID, etc.
  isPublic: boolean
  region?: string
  issues: string[]                     // "public read access", "no encryption"
}

export interface BbrtReconResult {
  subdomains: SubdomainRecord[]
  dnsRecords: DnsRecord[]
  openPorts: PortRecord[]
  techStack: TechStackDetection[]
  tlsCertificates: CertRecord[]
  osintFindings: OsintRecord[]
  cloudAssets: CloudAssetRecord[]
  emailAddresses: string[]
  whoisInfo?: {
    registrar: string
    createdDate: string
    expiryDate: string
    nameServers: string[]
  }
  discoveredAt: string
}

// ─── Attack Surface ─────────────────────────────────────────────────────────
export interface AttackSurfaceAsset {
  id: string
  type: AssetType
  label: string                        // "api.example.com"
  url?: string
  ip?: string
  domain?: string
  exposureLevel: ExposureLevel
  services: string[]                   // ["http/443", "ssh/22"]
  techStack: string[]                  // ["nginx/1.18", "Node.js"]
  knownVulnerabilities: string[]       // finding IDs or CVE references
  riskScore: number                    // 0-100
  isEntryPoint: boolean
  isCrownJewel: boolean
  metadata: Record<string, string>
}

export interface SurfaceChange {
  assetId: string
  changeType: 'added' | 'removed' | 'modified'
  description: string
  detectedAt: string
}

export interface BbrtAttackSurface {
  assets: AttackSurfaceAsset[]
  entryPoints: string[]                // asset IDs
  crownJewels: string[]                // asset IDs
  exposureScore: number                // 0-100 overall
  shadowAssets: AttackSurfaceAsset[]   // unexpected/rogue assets
  totalAssets: number
  publicAssets: number
  internalExposedAssets: number
  changesSinceLastScan?: SurfaceChange[]
  mappedAt: string
}

// ─── Evidence ───────────────────────────────────────────────────────────────
export interface BbrtEvidence {
  httpRequest?: string                 // raw HTTP request
  httpResponse?: string                // raw HTTP response (truncated)
  screenshot?: string                  // base64 or URL
  pocPayload?: string                  // proof-of-concept payload
  codeSnippet?: string                 // relevant code if disclosed
  commandOutput?: string               // tool output
  notes: string                        // human-readable explanation
}

// ─── Findings ───────────────────────────────────────────────────────────────
export interface BbrtFinding {
  id: string
  engagementId: string
  type: BbrtFindingType
  severity: SastSeverity
  cvssScore: number                    // 0-10
  cvssVector?: string                  // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  title: string
  description: string
  affectedAsset: string                // asset ID
  affectedAssetLabel: string           // "api.example.com"
  affectedUrl?: string                 // specific URL
  evidence: BbrtEvidence
  mitreMapping: MitreAttackMapping[]
  exploitability: BbrtExploitability
  businessImpact: BusinessImpact
  status: BbrtFindingStatus
  remediationSteps: string[]
  references: string[]                 // CWE, CVE, OWASP links
  discoveredInPhase: BbrtStatus        // which phase found this
  cweId?: string                       // "CWE-89"
  cveId?: string                       // "CVE-2024-1234"
}

// ─── Kill Chain ─────────────────────────────────────────────────────────────
export interface BbrtKillChainStep {
  seq: number
  tactic: string                       // 'Reconnaissance'
  tacticId: string                     // 'TA0043'
  technique: string                    // 'Active Scanning'
  techniqueId: string                  // 'T1595'
  subTechnique?: string
  subTechniqueId?: string
  action: string                       // "Attacker discovers exposed admin panel..."
  target: string                       // what is being attacked
  result: 'SUCCESS' | 'PARTIAL' | 'FAILED'
  evidence: string                     // supporting data
  findingIds: string[]                 // related finding IDs
  assetIds: string[]                   // asset IDs involved
}

export interface BbrtKillChain {
  id: string
  engagementId: string
  name: string                         // "Credential Leak → Admin Takeover → DB Exfiltration"
  objective: string                    // "Full database exfiltration via credential reuse"
  narrative: string                    // prose paragraph an exec can read
  likelihood: 'VERY_HIGH' | 'HIGH' | 'MEDIUM' | 'LOW'
  impact: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  steps: BbrtKillChainStep[]
  mitreMapping: MitreAttackMapping[]
  affectedAssets: string[]             // asset IDs
  dataAtRisk: string[]                 // "2M user records", "payment card data"
  estimatedTimeToExploit: string       // "2-4 hours"
  detectionDifficulty: 'EASY' | 'MODERATE' | 'DIFFICULT' | 'VERY_DIFFICULT'
  riskScore: number                    // 0-100
}

// ─── Report ─────────────────────────────────────────────────────────────────
export interface BbrtAttackSurfaceStats {
  totalAssets: number
  publicAssets: number
  shadowAssets: number
  entryPoints: number
  crownJewels: number
  exposureScore: number
  openPorts: number
  subdomains: number
}

export interface BbrtFindingStats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  byType: Record<BbrtFindingType, number>
}

export interface BbrtReport {
  id: string
  engagementId: string
  executiveSummary: string             // markdown
  overallRiskScore: number             // 0-100
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  attackSurfaceStats: BbrtAttackSurfaceStats
  findingStats: BbrtFindingStats
  killChainCount: number
  topKillChains: BbrtKillChain[]
  criticalFindings: BbrtFinding[]
  complianceGaps: ComplianceGap[]
  remediationRoadmap: RemediationItem[]
  aiInsights: string                   // Claude-generated strategic threat narrative
  generatedAt: string
}

// ─── Engagement (top-level entity) ──────────────────────────────────────────
export interface BbrtEngagement {
  id: string
  orgId: string
  name: string
  targetConfig: BbrtTargetConfig
  status: BbrtStatus
  progress: number                     // 0-100
  currentPhase: string
  reconResult?: BbrtReconResult
  attackSurface?: BbrtAttackSurface
  findings: BbrtFinding[]
  killChains: BbrtKillChain[]
  report?: BbrtReport
  summary?: {
    totalAssets: number
    totalFindings: number
    criticalFindings: number
    highFindings: number
    mediumFindings: number
    lowFindings: number
    totalKillChains: number
    overallRiskScore: number
    exposureScore: number
  }
  createdAt: string
  startedAt?: string
  completedAt?: string
}

// ─── Progress Event (for polling) ───────────────────────────────────────────
export interface BbrtProgressEvent {
  engagementId: string
  status: BbrtStatus
  progress: number
  currentPhase: string
  message: string
  timestamp: string
  details?: Record<string, number | string>  // phase-specific stats
}

// ─── Terminal Log Entry ─────────────────────────────────────────────────────
export interface BbrtTerminalEntry {
  timestamp: string
  phase: BbrtStatus
  level: 'info' | 'warn' | 'error' | 'success' | 'debug'
  message: string
  data?: string                        // optional detail payload
}
