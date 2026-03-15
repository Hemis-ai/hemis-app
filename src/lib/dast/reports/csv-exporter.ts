import type { ReportData } from './html-template'

const CSV_HEADERS = [
  'Finding #',
  'Title',
  'Severity',
  'CVSS Score',
  'CVSS Vector',
  'OWASP Category',
  'CWE',
  'Affected URL',
  'Affected Parameter',
  'Description',
  'Business Impact',
  'Remediation',
  'Confidence',
  'PCI-DSS',
  'SOC 2',
  'MITRE ATT&CK',
]

function escapeCsv(value: string): string {
  if (value.includes('"') || value.includes(',') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

/**
 * Export findings as CSV.
 * Returns CSV string with BOM for Excel compatibility.
 */
export function generateCsvReport(data: ReportData): string {
  const rows = data.findings.map((f, i) => [
    String(i + 1),
    f.title,
    f.severity,
    f.cvssScore?.toString() ?? '',
    f.cvssVector ?? '',
    f.owaspCategory,
    f.cweId ?? '',
    f.affectedUrl,
    f.affectedParameter ?? '',
    f.description.substring(0, 500),
    f.businessImpact?.substring(0, 500) ?? '',
    f.remediation.substring(0, 500),
    String(f.confidenceScore),
    f.pciDssRefs.join('; '),
    f.soc2Refs.join('; '),
    f.mitreAttackIds.join('; '),
  ])

  const lines = [
    CSV_HEADERS.map(escapeCsv).join(','),
    ...rows.map((row) => row.map(escapeCsv).join(',')),
  ]

  // BOM + content
  return '\uFEFF' + lines.join('\r\n')
}
