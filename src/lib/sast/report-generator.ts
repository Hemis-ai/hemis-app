// HemisX SAST — Executive Report Generator
// Generates structured report data for PDF/HTML export with executive summaries,
// risk scoring, and remediation prioritization.

import type { SastScanResult, SastFindingResult, SastSeverity } from '@/lib/types/sast'
import type { ComplianceResult } from '@/lib/sast/compliance-mapper'

export interface ExecutiveReport {
  title:          string
  generatedAt:    string
  scanInfo:       ScanInfo
  riskScore:      RiskScore
  executiveSummary: string
  topRisks:       TopRisk[]
  remediationPlan: RemediationItem[]
  compliance?:    ComplianceSummary[]
  trends?:        TrendSummary
}

interface ScanInfo {
  scanId:       string
  scanName:     string
  language:     string
  filesScanned: number
  linesOfCode:  number
  duration:     number
  completedAt:  string
}

interface RiskScore {
  overall:   number  // 0-100 (100 = max risk)
  grade:     'A' | 'B' | 'C' | 'D' | 'F'
  trend:     'IMPROVING' | 'STABLE' | 'DECLINING'
  breakdown: {
    injection:       number
    cryptography:    number
    authentication:  number
    secrets:         number
    dependencies:    number
    configuration:   number
  }
}

interface TopRisk {
  rank:        number
  finding:     string
  severity:    SastSeverity
  category:    string
  cwe:         string
  impact:      string
  remediation: string
  effort:      'LOW' | 'MEDIUM' | 'HIGH'
}

interface RemediationItem {
  priority:    number
  category:    string
  action:      string
  findingCount: number
  effort:      'LOW' | 'MEDIUM' | 'HIGH'
  impact:      'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}

interface ComplianceSummary {
  framework:   string
  score:       number
  status:      'PASS' | 'FAIL' | 'PARTIAL'
  failedControls: number
}

interface TrendSummary {
  direction:    'IMPROVING' | 'STABLE' | 'DECLINING'
  changePercent: number
  period:       string
}

// ─── Severity weights for risk calculation ──────────────────────────────────

const SEV_WEIGHTS: Record<SastSeverity, number> = {
  CRITICAL: 10,
  HIGH:     7,
  MEDIUM:   4,
  LOW:      1,
  INFO:     0,
}

// ─── Effort estimation based on category ────────────────────────────────────

const CATEGORY_EFFORT: Record<string, 'LOW' | 'MEDIUM' | 'HIGH'> = {
  'Secrets':          'LOW',
  'Misconfiguration': 'LOW',
  'Logging':          'LOW',
  'XSS':              'MEDIUM',
  'Injection':        'MEDIUM',
  'Cryptography':     'MEDIUM',
  'Authentication':   'MEDIUM',
  'Authorization':    'MEDIUM',
  'Dependencies':     'MEDIUM',
  'Path Traversal':   'MEDIUM',
  'SSRF':             'HIGH',
  'Deserialization':  'HIGH',
  'Race Condition':   'HIGH',
  'XXE':              'MEDIUM',
}

// ─── Generate Executive Report ──────────────────────────────────────────────

export function generateExecutiveReport(
  scan: SastScanResult,
  compliance?: ComplianceResult[],
): ExecutiveReport {
  const activeFindings = scan.findings.filter(f => !f.falsePositive)
  const riskScore = calculateRiskScore(activeFindings)
  const topRisks = getTopRisks(activeFindings)
  const remediationPlan = buildRemediationPlan(activeFindings)

  const complianceSummary: ComplianceSummary[] | undefined = compliance?.map(c => ({
    framework:      c.fullName,
    score:          c.score,
    status:         c.score >= 80 ? 'PASS' : c.score >= 50 ? 'PARTIAL' : 'FAIL',
    failedControls: c.failedControls,
  }))

  return {
    title: `Security Assessment Report — ${scan.name}`,
    generatedAt: new Date().toISOString(),
    scanInfo: {
      scanId:       scan.id,
      scanName:     scan.name,
      language:     scan.language,
      filesScanned: scan.filesScanned,
      linesOfCode:  scan.linesOfCode,
      duration:     scan.duration ?? 0,
      completedAt:  scan.completedAt ?? new Date().toISOString(),
    },
    riskScore,
    executiveSummary: generateSummaryText(scan, riskScore, activeFindings),
    topRisks,
    remediationPlan,
    compliance: complianceSummary,
  }
}

function calculateRiskScore(findings: SastFindingResult[]): RiskScore {
  // Weighted severity score (max ~100)
  const rawScore = findings.reduce((sum, f) => sum + SEV_WEIGHTS[f.severity], 0)
  const maxScore = findings.length * 10 || 1
  const normalized = Math.min(100, Math.round((rawScore / maxScore) * 100))

  // Grade
  const grade: RiskScore['grade'] = normalized <= 20 ? 'A'
    : normalized <= 40 ? 'B'
    : normalized <= 60 ? 'C'
    : normalized <= 80 ? 'D' : 'F'

  // Category breakdown
  const catScores: Record<string, number[]> = {}
  for (const f of findings) {
    const bucket = mapCategoryToBucket(f.category)
    if (!catScores[bucket]) catScores[bucket] = []
    catScores[bucket].push(SEV_WEIGHTS[f.severity])
  }

  const avgFor = (key: string) => {
    const scores = catScores[key]
    if (!scores || scores.length === 0) return 0
    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length * 10)
  }

  return {
    overall: normalized,
    grade,
    trend: 'STABLE',
    breakdown: {
      injection:      avgFor('injection'),
      cryptography:   avgFor('cryptography'),
      authentication: avgFor('authentication'),
      secrets:        avgFor('secrets'),
      dependencies:   avgFor('dependencies'),
      configuration:  avgFor('configuration'),
    },
  }
}

function mapCategoryToBucket(cat: string): string {
  switch (cat) {
    case 'Injection': case 'XSS': case 'XXE': case 'SSRF': return 'injection'
    case 'Cryptography': return 'cryptography'
    case 'Authentication': case 'Authorization': return 'authentication'
    case 'Secrets': return 'secrets'
    case 'Dependencies': return 'dependencies'
    default: return 'configuration'
  }
}

function getTopRisks(findings: SastFindingResult[]): TopRisk[] {
  const sorted = [...findings].sort((a, b) => {
    const order: SastSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    return order.indexOf(a.severity) - order.indexOf(b.severity)
  })

  return sorted.slice(0, 5).map((f, i) => ({
    rank:        i + 1,
    finding:     f.ruleName,
    severity:    f.severity,
    category:    f.category,
    cwe:         f.cwe,
    impact:      getImpactDescription(f),
    remediation: f.remediation,
    effort:      CATEGORY_EFFORT[f.category] || 'MEDIUM',
  }))
}

function getImpactDescription(f: SastFindingResult): string {
  const impacts: Record<string, string> = {
    'Injection':       'Could allow attackers to execute arbitrary commands or queries, leading to data breach or system compromise.',
    'XSS':             'Could allow attackers to inject malicious scripts, steal session tokens, or redirect users.',
    'Secrets':         'Exposed credentials could grant unauthorized access to systems, databases, or third-party services.',
    'Cryptography':    'Weak cryptography could allow attackers to decrypt sensitive data or forge authentication tokens.',
    'Authentication':  'Could allow attackers to bypass authentication or escalate privileges.',
    'Dependencies':    'Known vulnerabilities in third-party libraries could be exploited for remote code execution.',
    'Deserialization': 'Could allow remote code execution through crafted serialized objects.',
    'SSRF':            'Could allow attackers to access internal services, cloud metadata, or exfiltrate data.',
    'Path Traversal':  'Could allow attackers to read or write arbitrary files on the server.',
  }
  return impacts[f.category] || 'Could lead to security compromise if exploited.'
}

function buildRemediationPlan(findings: SastFindingResult[]): RemediationItem[] {
  const categoryGroups: Record<string, SastFindingResult[]> = {}
  for (const f of findings) {
    if (!categoryGroups[f.category]) categoryGroups[f.category] = []
    categoryGroups[f.category].push(f)
  }

  return Object.entries(categoryGroups)
    .map(([category, items]) => {
      const hasCritical = items.some(i => i.severity === 'CRITICAL')
      const hasHigh = items.some(i => i.severity === 'HIGH')
      return {
        priority:     hasCritical ? 1 : hasHigh ? 2 : 3,
        category,
        action:       getRemediationAction(category),
        findingCount: items.length,
        effort:       CATEGORY_EFFORT[category] || 'MEDIUM' as const,
        impact:       (hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : 'MEDIUM') as RemediationItem['impact'],
      }
    })
    .sort((a, b) => a.priority - b.priority)
}

function getRemediationAction(category: string): string {
  const actions: Record<string, string> = {
    'Injection':        'Implement parameterized queries and input validation across all data entry points.',
    'XSS':              'Apply output encoding and Content Security Policy headers.',
    'Secrets':          'Rotate all exposed credentials and migrate to a secrets manager (Vault, AWS SM).',
    'Cryptography':     'Upgrade to approved cryptographic algorithms (AES-256, SHA-256+, ECDSA).',
    'Authentication':   'Implement MFA, strong password policies, and secure session management.',
    'Dependencies':     'Update vulnerable dependencies and establish automated dependency scanning in CI/CD.',
    'Deserialization':  'Replace native deserialization with safe alternatives (JSON, protobuf).',
    'Misconfiguration': 'Review and harden configuration files, disable debug modes in production.',
    'Logging':          'Implement structured logging with PII/secret masking.',
    'SSRF':             'Implement URL allowlisting and disable unnecessary outbound network access.',
    'Path Traversal':   'Validate and sanitize file paths, use chroot or path canonicalization.',
  }
  return actions[category] || `Address all ${category} findings following OWASP guidelines.`
}

function generateSummaryText(
  scan: SastScanResult,
  risk: RiskScore,
  findings: SastFindingResult[],
): string {
  const critical = findings.filter(f => f.severity === 'CRITICAL').length
  const high = findings.filter(f => f.severity === 'HIGH').length
  const total = findings.length

  const urgency = critical > 0
    ? `Immediate attention is required. ${critical} critical vulnerability${critical > 1 ? 'ies' : 'y'} ${critical > 1 ? 'were' : 'was'} identified that could lead to complete system compromise.`
    : high > 0
    ? `Priority attention is recommended. ${high} high-severity issue${high > 1 ? 's' : ''} could be exploited under certain conditions.`
    : 'No critical or high-severity issues were found. The codebase demonstrates reasonable security hygiene.'

  return `HemisX SAST scanned ${scan.filesScanned} file${scan.filesScanned > 1 ? 's' : ''} (${scan.linesOfCode.toLocaleString()} lines of ${scan.language} code) and identified ${total} security finding${total !== 1 ? 's' : ''}. The overall risk score is ${risk.overall}/100 (Grade: ${risk.grade}). ${urgency}`
}
