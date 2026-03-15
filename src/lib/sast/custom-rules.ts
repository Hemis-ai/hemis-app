// HemisX SAST — Custom Rule Engine
// Allows users to define, test, and manage custom SAST rules beyond the built-in 55.

import type { SastRule, SastSeverity, SastConfidence, SastCategory, SupportedLanguage } from '@/lib/types/sast'

export interface CustomRuleDefinition {
  id:          string
  name:        string
  description: string
  pattern:     string            // regex pattern as string (not compiled)
  languages:   SupportedLanguage[] | ['all']
  severity:    SastSeverity
  confidence:  SastConfidence
  owasp:       string
  cwe:         string
  category:    SastCategory
  remediation: string
  enabled:     boolean
  createdAt:   string
  updatedAt:   string
  testCases:   RuleTestCase[]
}

export interface RuleTestCase {
  code:      string
  shouldMatch: boolean
  label:     string
}

// ─── Built-in rule catalog (metadata only, for the rules panel) ─────────────

export interface RuleCatalogEntry {
  id:          string
  name:        string
  category:    SastCategory
  severity:    SastSeverity
  confidence:  SastConfidence
  owasp:       string
  cwe:         string
  languages:   string[]
  description: string
  enabled:     boolean
}

// ─── Default custom rules (pre-populated for new users) ─────────────────────

export const DEFAULT_CUSTOM_RULES: CustomRuleDefinition[] = [
  {
    id: 'CUSTOM-001',
    name: 'React dangerouslySetInnerHTML usage',
    description: 'Detects use of dangerouslySetInnerHTML in React components, which can lead to XSS if the HTML is not properly sanitized.',
    pattern: 'dangerouslySetInnerHTML\\s*=\\s*\\{',
    languages: ['javascript', 'typescript'],
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-79',
    category: 'XSS',
    remediation: 'Use a sanitization library like DOMPurify before passing HTML to dangerouslySetInnerHTML, or avoid it entirely by using React\'s built-in text rendering.',
    enabled: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    testCases: [
      { code: '<div dangerouslySetInnerHTML={{ __html: userInput }} />', shouldMatch: true, label: 'Direct usage' },
      { code: '<div>{sanitizedContent}</div>', shouldMatch: false, label: 'Safe rendering' },
    ],
  },
  {
    id: 'CUSTOM-002',
    name: 'Hardcoded localhost/127.0.0.1 in production code',
    description: 'Detects hardcoded localhost references that may indicate development-only configurations left in production.',
    pattern: '(?:https?://)?(?:localhost|127\\.0\\.0\\.1)(?::\\d+)?(?:/\\S*)?',
    languages: ['all'],
    severity: 'LOW',
    confidence: 'MEDIUM',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-489',
    category: 'Misconfiguration',
    remediation: 'Use environment variables for service URLs. Replace hardcoded localhost references with configurable endpoints.',
    enabled: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    testCases: [
      { code: 'const API_URL = "http://localhost:3000/api"', shouldMatch: true, label: 'localhost URL' },
      { code: 'const API_URL = process.env.API_URL', shouldMatch: false, label: 'Env var usage' },
    ],
  },
  {
    id: 'CUSTOM-003',
    name: 'Console.log with sensitive variable names',
    description: 'Detects console.log statements that may leak sensitive data like passwords, tokens, or keys.',
    pattern: 'console\\.(?:log|debug|info|warn)\\s*\\([^)]*(?:password|token|secret|key|credential|auth|session)[^)]*\\)',
    languages: ['javascript', 'typescript'],
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    owasp: 'A09:2021 – Security Logging and Monitoring Failures',
    cwe: 'CWE-532',
    category: 'Logging',
    remediation: 'Remove console.log statements that output sensitive data. Use a structured logger with sensitive field masking.',
    enabled: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    testCases: [
      { code: 'console.log("User password:", password)', shouldMatch: true, label: 'Logging password' },
      { code: 'console.log("User logged in:", username)', shouldMatch: false, label: 'Safe logging' },
    ],
  },
]

// ─── Test a regex pattern against code ──────────────────────────────────────

export function testPattern(pattern: string, code: string): { matches: boolean; matchCount: number; matchPositions: { start: number; end: number; text: string }[] } {
  try {
    const regex = new RegExp(pattern, 'gi')
    const positions: { start: number; end: number; text: string }[] = []
    let match: RegExpExecArray | null
    let count = 0

    while ((match = regex.exec(code)) !== null && count < 50) {
      positions.push({
        start: match.index,
        end: match.index + match[0].length,
        text: match[0],
      })
      count++
      // Prevent infinite loops on zero-length matches
      if (match[0].length === 0) regex.lastIndex++
    }

    return { matches: positions.length > 0, matchCount: positions.length, matchPositions: positions }
  } catch {
    return { matches: false, matchCount: 0, matchPositions: [] }
  }
}

// ─── Validate regex pattern ─────────────────────────────────────────────────

export function validatePattern(pattern: string): { valid: boolean; error?: string } {
  try {
    new RegExp(pattern, 'gi')
    return { valid: true }
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : 'Invalid regex' }
  }
}

// ─── Convert custom rule to SastRule ────────────────────────────────────────

export function toSastRule(custom: CustomRuleDefinition): SastRule {
  return {
    id:          custom.id,
    name:        custom.name,
    description: custom.description,
    pattern:     new RegExp(custom.pattern, 'gi'),
    languages:   custom.languages,
    severity:    custom.severity,
    confidence:  custom.confidence,
    owasp:       custom.owasp,
    cwe:         custom.cwe,
    category:    custom.category,
    remediation: custom.remediation,
  }
}

// ─── OWASP Categories for dropdown ──────────────────────────────────────────

export const OWASP_CATEGORIES = [
  { id: 'A01:2021', name: 'A01:2021 – Broken Access Control' },
  { id: 'A02:2021', name: 'A02:2021 – Cryptographic Failures' },
  { id: 'A03:2021', name: 'A03:2021 – Injection' },
  { id: 'A04:2021', name: 'A04:2021 – Insecure Design' },
  { id: 'A05:2021', name: 'A05:2021 – Security Misconfiguration' },
  { id: 'A06:2021', name: 'A06:2021 – Vulnerable Components' },
  { id: 'A07:2021', name: 'A07:2021 – Auth Failures' },
  { id: 'A08:2021', name: 'A08:2021 – Software & Data Integrity' },
  { id: 'A09:2021', name: 'A09:2021 – Logging & Monitoring Failures' },
  { id: 'A10:2021', name: 'A10:2021 – SSRF' },
]

export const CWE_COMMON = [
  'CWE-79', 'CWE-89', 'CWE-78', 'CWE-94', 'CWE-95', 'CWE-22',
  'CWE-327', 'CWE-798', 'CWE-256', 'CWE-502', 'CWE-918', 'CWE-611',
  'CWE-862', 'CWE-532', 'CWE-209', 'CWE-319', 'CWE-521', 'CWE-489',
  'CWE-1035', 'CWE-352', 'CWE-338', 'CWE-295', 'CWE-347', 'CWE-915',
]

export const SAST_CATEGORIES: SastCategory[] = [
  'Injection', 'Cryptography', 'Authentication', 'Authorization',
  'Secrets', 'Deserialization', 'Path Traversal', 'SSRF',
  'XSS', 'Misconfiguration', 'Logging', 'Race Condition', 'XXE', 'Dependencies',
]
