import { randomUUID } from 'crypto'
import { SAST_RULES, OWASP_CATEGORIES } from './rules'
import { detectLanguage, languageMatches } from './language-detector'
import type {
  SastFile,
  SastFindingResult,
  SastScanResult,
  OwaspCategory,
  SastSeverity,
} from '@/lib/types/sast'

const CONTEXT_LINES = 3   // lines to include above/below match for snippet

/**
 * Extract a code snippet centered on `lineIndex` (0-based) with context.
 * Returns the snippet string and 1-based line numbers.
 */
function extractSnippet(
  lines: string[],
  lineIndex: number
): { snippet: string; lineStart: number; lineEnd: number } {
  const start = Math.max(0, lineIndex - CONTEXT_LINES)
  const end   = Math.min(lines.length - 1, lineIndex + CONTEXT_LINES)
  const snippet = lines
    .slice(start, end + 1)
    .map((l, i) => `${start + i + 1} | ${l}`)
    .join('\n')
  return { snippet, lineStart: start + 1, lineEnd: end + 1 }
}

/**
 * Scan a single file's content and return an array of raw findings.
 */
function scanFile(
  scanId: string,
  file: SastFile,
): SastFindingResult[] {
  const lang    = detectLanguage(file.path, file.content)
  const lines   = file.content.split('\n')
  const results: SastFindingResult[] = []

  for (const rule of SAST_RULES) {
    if (!languageMatches(rule.languages as string[], lang)) continue

    // Reset regex state between files (global flag)
    rule.pattern.lastIndex = 0

    let match: RegExpExecArray | null
    const seen = new Set<number>()  // deduplicate multiple matches on same line

    while ((match = rule.pattern.exec(file.content)) !== null) {
      // Calculate 0-based line index
      const linesBefore = file.content.slice(0, match.index).split('\n')
      const lineIdx     = linesBefore.length - 1

      if (seen.has(lineIdx)) continue
      seen.add(lineIdx)

      const { snippet, lineStart, lineEnd } = extractSnippet(lines, lineIdx)

      results.push({
        id:           randomUUID(),
        scanId,
        ruleId:       rule.id,
        ruleName:     rule.name,
        severity:     rule.severity,
        confidence:   rule.confidence,
        language:     lang,
        filePath:     file.path,
        lineStart,
        lineEnd,
        codeSnippet:  snippet,
        description:  rule.description,
        remediation:  rule.remediation,
        owasp:        rule.owasp,
        cwe:          rule.cwe,
        category:     rule.category,
        status:       'OPEN',
        falsePositive:false,
        detectedAt:   new Date().toISOString(),
      })
    }

    // Reset regex for next file
    rule.pattern.lastIndex = 0
  }

  return results
}

/**
 * Build the OWASP coverage breakdown from findings.
 */
function buildOwaspCoverage(findings: SastFindingResult[]): OwaspCategory[] {
  const SEVERITY_ORDER: SastSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

  return OWASP_CATEGORIES.map(cat => {
    const relevant = findings.filter(f => f.owasp.startsWith(cat.id))
    const highest = relevant.length
      ? SEVERITY_ORDER.find(s => relevant.some(f => f.severity === s)) ?? null
      : null
    return { id: cat.id, name: cat.name, count: relevant.length, highest }
  })
}

/**
 * Main entry point — scans all provided files and returns a complete SastScanResult.
 */
export function runSastScan(
  scanId: string,
  name:   string,
  files:  SastFile[],
): SastScanResult {
  const startedAt = new Date()
  const allFindings: SastFindingResult[] = []

  let totalLines = 0
  for (const file of files) {
    totalLines += file.content.split('\n').length
    allFindings.push(...scanFile(scanId, file))
  }

  const completedAt = new Date()
  const duration    = completedAt.getTime() - startedAt.getTime()

  // Determine primary language (most common among files)
  const langCounts: Record<string, number> = {}
  for (const file of files) {
    const l = detectLanguage(file.path, file.content)
    langCounts[l] = (langCounts[l] ?? 0) + 1
  }
  const primaryLang = Object.entries(langCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown'

  const summary = {
    critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
    high:     allFindings.filter(f => f.severity === 'HIGH').length,
    medium:   allFindings.filter(f => f.severity === 'MEDIUM').length,
    low:      allFindings.filter(f => f.severity === 'LOW').length,
    info:     allFindings.filter(f => f.severity === 'INFO').length,
    total:    allFindings.length,
  }

  return {
    id:            scanId,
    name,
    language:      primaryLang,
    linesOfCode:   totalLines,
    filesScanned:  files.length,
    status:        'COMPLETED',
    duration,
    startedAt:     startedAt.toISOString(),
    completedAt:   completedAt.toISOString(),
    summary,
    findings:      allFindings,
    owaspCoverage: buildOwaspCoverage(allFindings),
  }
}
