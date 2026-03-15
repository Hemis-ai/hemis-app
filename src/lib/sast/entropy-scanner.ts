// HemisX SAST — Shannon Entropy Scanner
// Detects high-entropy strings that may be secrets not caught by pattern matching.
// Uses Shannon entropy calculation to identify random-looking strings like API keys,
// tokens, and passwords that don't match known patterns.

import type { SastFindingResult } from '@/lib/types/sast'
import { randomUUID } from 'crypto'

// ─── Shannon Entropy ──────────────────────────────────────────────────────────

function shannonEntropy(str: string): number {
  if (str.length === 0) return 0
  const freq: Record<string, number> = {}
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1
  let entropy = 0
  const len = str.length
  for (const count of Object.values(freq)) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }
  return entropy
}

// ─── Constants ────────────────────────────────────────────────────────────────

// Minimum entropy thresholds for different charsets
const HEX_ENTROPY_THRESHOLD     = 3.0   // hex strings (a-f0-9)
const BASE64_ENTROPY_THRESHOLD  = 4.2   // base64 strings
const GENERAL_ENTROPY_THRESHOLD = 4.5   // general high-entropy

const MIN_LENGTH = 16   // ignore short strings
const MAX_LENGTH = 256  // ignore very long strings (likely not secrets)

// Common false positives to skip
const SAFE_PATTERNS = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^[0-9]+$/,                    // pure numbers
  /^[a-z]+$/i,                   // pure letters
  /^(true|false|null|undefined|none|yes|no)$/i, // boolean-like
  /^(https?|ftp|ssh|git):\/\//i, // URLs
  /^localhost/i,
  /^[\w.-]+@[\w.-]+$/,           // emails
  /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/, // IP addresses
  /^sha[0-9]+-/i,                // hash references (sha256-xxx)
  /^v?[0-9]+\.[0-9]+/,           // version strings
]

// Variable name patterns that suggest secrets
const SECRET_VAR_PATTERNS = [
  /(?:password|passwd|pass|pwd)/i,
  /(?:secret|token|key|credential|auth)/i,
  /(?:api_key|apikey|api-key|access_key)/i,
  /(?:private|signing|encryption)/i,
  /(?:connection_string|conn_str|dsn)/i,
]

// ─── High-entropy string extractor ────────────────────────────────────────────

interface HighEntropyMatch {
  value:    string
  line:     number
  entropy:  number
  varName?: string
  charset:  'hex' | 'base64' | 'general'
}

function extractHighEntropyStrings(content: string): HighEntropyMatch[] {
  const results: HighEntropyMatch[] = []
  const lines = content.split('\n')

  // Patterns to find potential secret values in assignments
  const assignmentPatterns = [
    // key = "value" or key: "value"
    /(?:^|[\s{(,])(\w+)\s*[:=]\s*["'`]([^"'`\n]{16,256})["'`]/g,
    // env.VARIABLE or process.env.VARIABLE
    /["'`]([A-Za-z0-9+/=_\-]{20,256})["'`]/g,
  ]

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    // Skip comments
    if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('*')) continue

    for (const pattern of assignmentPatterns) {
      pattern.lastIndex = 0
      let match: RegExpExecArray | null

      while ((match = pattern.exec(line)) !== null) {
        const varName = match[1]
        const value = match[2] ?? match[1]

        if (!value || value.length < MIN_LENGTH || value.length > MAX_LENGTH) continue

        // Skip safe patterns
        if (SAFE_PATTERNS.some(p => p.test(value))) continue

        // Skip if it looks like code (contains spaces, common keywords)
        if (value.includes(' ') && value.split(' ').length > 3) continue

        const entropy = shannonEntropy(value)

        // Determine charset
        let charset: HighEntropyMatch['charset'] = 'general'
        if (/^[0-9a-fA-F]+$/.test(value)) charset = 'hex'
        else if (/^[A-Za-z0-9+/=_\-]+$/.test(value)) charset = 'base64'

        const threshold = charset === 'hex' ? HEX_ENTROPY_THRESHOLD
          : charset === 'base64' ? BASE64_ENTROPY_THRESHOLD
          : GENERAL_ENTROPY_THRESHOLD

        if (entropy >= threshold) {
          // Boost score if variable name suggests it's a secret
          const isSecretVar = varName && SECRET_VAR_PATTERNS.some(p => p.test(varName))

          // Only report if variable name is suspicious OR entropy is very high
          if (isSecretVar || entropy >= threshold + 0.5) {
            results.push({
              value: value.slice(0, 8) + '...' + value.slice(-4), // mask
              line: i + 1,
              entropy: Math.round(entropy * 100) / 100,
              varName,
              charset,
            })
          }
        }
      }
    }
  }

  return results
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function scanForHighEntropy(
  scanId: string,
  filePath: string,
  content: string,
): SastFindingResult[] {
  const matches = extractHighEntropyStrings(content)
  const lines = content.split('\n')
  const findings: SastFindingResult[] = []

  for (const match of matches) {
    const start = Math.max(0, match.line - 2)
    const end   = Math.min(lines.length - 1, match.line + 1)
    const snippet = lines
      .slice(start, end + 1)
      .map((l, i) => `${start + i + 1} | ${l}`)
      .join('\n')

    findings.push({
      id:           randomUUID(),
      scanId,
      ruleId:       'ENTROPY-001',
      ruleName:     'High-entropy string detected (potential secret)',
      severity:     match.varName && SECRET_VAR_PATTERNS.some(p => p.test(match.varName!)) ? 'HIGH' : 'MEDIUM',
      confidence:   'MEDIUM',
      language:     'unknown',
      filePath,
      lineStart:    match.line,
      lineEnd:      match.line,
      codeSnippet:  snippet,
      description:  `High-entropy ${match.charset} string detected${match.varName ? ` in variable "${match.varName}"` : ''}. Shannon entropy: ${match.entropy} bits/char. This may be a hardcoded secret, API key, or credential.`,
      remediation:  'Move secrets to environment variables or a secrets manager. Never hardcode credentials in source code. Use tools like AWS Secrets Manager, HashiCorp Vault, or .env files (excluded from VCS).',
      owasp:        'A02:2021 – Cryptographic Failures',
      cwe:          'CWE-798',
      category:     'Secrets',
      status:       'OPEN',
      falsePositive: false,
      detectedAt:   new Date().toISOString(),
    })
  }

  return findings
}

/** Exported for testing */
export { shannonEntropy }
