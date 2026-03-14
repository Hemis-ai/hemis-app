// HemisX SAST — SARIF v2.1.0 Export
// Generates SARIF-compliant JSON for integration with GitHub Code Scanning,
// Azure DevOps, VS Code SARIF Viewer, and other standard tools.

import type { SastScanResult, SastFindingResult } from '@/lib/types/sast'

interface SarifResult {
  ruleId: string
  level: 'error' | 'warning' | 'note' | 'none'
  message: { text: string }
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string }
      region: { startLine: number; endLine: number }
    }
  }>
  properties?: Record<string, unknown>
}

interface SarifReport {
  $schema: string
  version: string
  runs: Array<{
    tool: {
      driver: {
        name: string
        version: string
        informationUri: string
        rules: Array<{
          id: string
          name: string
          shortDescription: { text: string }
          helpUri?: string
          properties?: Record<string, unknown>
        }>
      }
    }
    results: SarifResult[]
  }>
}

function severityToLevel(severity: string): SarifResult['level'] {
  switch (severity) {
    case 'CRITICAL': return 'error'
    case 'HIGH':     return 'error'
    case 'MEDIUM':   return 'warning'
    case 'LOW':      return 'note'
    case 'INFO':     return 'none'
    default:         return 'warning'
  }
}

export function toSarif(scan: SastScanResult): SarifReport {
  // Deduplicate rules
  const rulesMap = new Map<string, SastFindingResult>()
  for (const f of scan.findings) {
    if (!rulesMap.has(f.ruleId)) rulesMap.set(f.ruleId, f)
  }

  const rules = Array.from(rulesMap.values()).map(f => ({
    id:               f.ruleId,
    name:             f.ruleName,
    shortDescription: { text: f.description.slice(0, 200) },
    helpUri:          `https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html`,
    properties: {
      tags:     [f.owasp, f.cwe, f.category],
      security: f.severity,
    },
  }))

  const results: SarifResult[] = scan.findings.map(f => ({
    ruleId:  f.ruleId,
    level:   severityToLevel(f.severity),
    message: { text: `${f.ruleName}: ${f.description}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.filePath },
        region: { startLine: f.lineStart, endLine: f.lineEnd },
      },
    }],
    properties: {
      severity:   f.severity,
      confidence: f.confidence,
      owasp:      f.owasp,
      cwe:        f.cwe,
      category:   f.category,
      remediation: f.remediation,
    },
  }))

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name:           'HemisX SAST',
          version:        '1.0.0',
          informationUri: 'https://hemisx.io/sast',
          rules,
        },
      },
      results,
    }],
  }
}
