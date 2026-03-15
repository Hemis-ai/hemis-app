// HemisX SAST — Compliance Framework Mapper
// Maps SAST findings to compliance requirements for PCI-DSS 4.0, SOC2 Type II,
// OWASP ASVS 4.0, ISO 27001, HIPAA, and GDPR.

import type { SastFindingResult, SastSeverity } from '@/lib/types/sast'

// ─── Compliance Framework Definitions ─────────────────────────────────────────

export interface ComplianceControl {
  id:          string
  name:        string
  description: string
  framework:   ComplianceFramework
  cweMapping:  string[]       // CWE IDs that map to this control
  owaspMapping: string[]      // OWASP categories that map to this control
  criticality: 'REQUIRED' | 'RECOMMENDED' | 'OPTIONAL'
}

export type ComplianceFramework = 'PCI-DSS' | 'SOC2' | 'OWASP-ASVS' | 'ISO-27001' | 'HIPAA' | 'GDPR'

export interface ComplianceResult {
  framework:    ComplianceFramework
  fullName:     string
  totalControls: number
  passedControls: number
  failedControls: number
  notApplicable:  number
  score:          number   // 0-100
  controls:       ControlAssessment[]
}

export interface ControlAssessment {
  control:    ComplianceControl
  status:     'PASS' | 'FAIL' | 'PARTIAL' | 'N/A'
  findings:   SastFindingResult[]
  highest:    SastSeverity | null
}

// ─── Compliance Controls Database ─────────────────────────────────────────────

const CONTROLS: ComplianceControl[] = [
  // PCI-DSS 4.0
  { id: 'PCI-6.2.4', name: 'Prevent common software attacks', description: 'Software engineering techniques prevent or mitigate common software attacks and related vulnerabilities (SQL injection, XSS, CSRF, etc.)',
    framework: 'PCI-DSS', cweMapping: ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-352', 'CWE-94', 'CWE-95', 'CWE-611', 'CWE-90', 'CWE-918'], owaspMapping: ['A03'], criticality: 'REQUIRED' },
  { id: 'PCI-6.2.3', name: 'Review custom code before release', description: 'Custom application code is reviewed before release to identify and correct potential coding vulnerabilities.',
    framework: 'PCI-DSS', cweMapping: ['CWE-89', 'CWE-79', 'CWE-78'], owaspMapping: ['A03', 'A04'], criticality: 'REQUIRED' },
  { id: 'PCI-6.3.1', name: 'Identify security vulnerabilities', description: 'Security vulnerabilities are identified and managed through industry-recognized vulnerability databases.',
    framework: 'PCI-DSS', cweMapping: ['CWE-1035'], owaspMapping: ['A06'], criticality: 'REQUIRED' },
  { id: 'PCI-6.3.2', name: 'Inventory software components', description: 'An inventory of bespoke and custom software components is maintained to facilitate vulnerability and patch management.',
    framework: 'PCI-DSS', cweMapping: ['CWE-1035'], owaspMapping: ['A06'], criticality: 'REQUIRED' },
  { id: 'PCI-2.2.7', name: 'Encrypt non-console admin access', description: 'All non-console administrative access is encrypted using strong cryptography.',
    framework: 'PCI-DSS', cweMapping: ['CWE-319', 'CWE-327', 'CWE-295'], owaspMapping: ['A02'], criticality: 'REQUIRED' },
  { id: 'PCI-3.4.1', name: 'Protect stored cardholder data', description: 'PAN is secured wherever it is stored.',
    framework: 'PCI-DSS', cweMapping: ['CWE-798', 'CWE-321', 'CWE-256'], owaspMapping: ['A02', 'A07'], criticality: 'REQUIRED' },
  { id: 'PCI-8.3.6', name: 'Strong authentication credentials', description: 'Strong authentication credentials are enforced with minimum complexity and not reused.',
    framework: 'PCI-DSS', cweMapping: ['CWE-521', 'CWE-256', 'CWE-798'], owaspMapping: ['A07'], criticality: 'REQUIRED' },
  { id: 'PCI-10.2.1', name: 'Audit log coverage', description: 'Audit logs capture all individual user access to cardholder data.',
    framework: 'PCI-DSS', cweMapping: ['CWE-532', 'CWE-209'], owaspMapping: ['A09'], criticality: 'REQUIRED' },

  // SOC2 Type II
  { id: 'SOC2-CC6.1', name: 'Logical and physical access controls', description: 'The entity implements logical access security software and infrastructure to protect information assets.',
    framework: 'SOC2', cweMapping: ['CWE-862', 'CWE-22', 'CWE-798', 'CWE-256', 'CWE-521'], owaspMapping: ['A01', 'A07'], criticality: 'REQUIRED' },
  { id: 'SOC2-CC6.6', name: 'Restrict unauthorized access', description: 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.',
    framework: 'SOC2', cweMapping: ['CWE-502', 'CWE-94', 'CWE-78', 'CWE-89'], owaspMapping: ['A03', 'A08'], criticality: 'REQUIRED' },
  { id: 'SOC2-CC6.7', name: 'Restrict data transmission', description: 'The entity restricts the transmission, movement, and removal of information to authorized internal/external users.',
    framework: 'SOC2', cweMapping: ['CWE-319', 'CWE-598', 'CWE-614'], owaspMapping: ['A02', 'A05'], criticality: 'REQUIRED' },
  { id: 'SOC2-CC7.1', name: 'Detect unauthorized changes', description: 'To meet its objectives, the entity monitors system components for anomalies and evaluates anomalies to identify errors.',
    framework: 'SOC2', cweMapping: ['CWE-532', 'CWE-209', 'CWE-367'], owaspMapping: ['A09', 'A04'], criticality: 'REQUIRED' },
  { id: 'SOC2-CC8.1', name: 'Change management', description: 'Changes to infrastructure, data, software are authorized, designed, developed, configured, documented, tested and approved.',
    framework: 'SOC2', cweMapping: ['CWE-489', 'CWE-547', 'CWE-942'], owaspMapping: ['A05'], criticality: 'REQUIRED' },

  // OWASP ASVS 4.0
  { id: 'ASVS-5.3.4', name: 'Output encoding for XSS prevention', description: 'Verify that data selection or database queries use parameterized queries.',
    framework: 'OWASP-ASVS', cweMapping: ['CWE-89', 'CWE-79', 'CWE-95'], owaspMapping: ['A03'], criticality: 'REQUIRED' },
  { id: 'ASVS-5.2.4', name: 'Injection prevention', description: 'Verify that the application avoids the use of eval() or other dynamic code execution features.',
    framework: 'OWASP-ASVS', cweMapping: ['CWE-94', 'CWE-95', 'CWE-78'], owaspMapping: ['A03'], criticality: 'REQUIRED' },
  { id: 'ASVS-2.1.1', name: 'Password storage', description: 'Verify that user passwords are stored using an approved one-way key derivation or hashing function.',
    framework: 'OWASP-ASVS', cweMapping: ['CWE-256', 'CWE-327', 'CWE-916'], owaspMapping: ['A02', 'A07'], criticality: 'REQUIRED' },
  { id: 'ASVS-6.2.1', name: 'Strong cryptography', description: 'Verify that all cryptographic modules fail securely and errors are handled properly.',
    framework: 'OWASP-ASVS', cweMapping: ['CWE-327', 'CWE-338', 'CWE-329', 'CWE-295'], owaspMapping: ['A02'], criticality: 'REQUIRED' },
  { id: 'ASVS-10.3.2', name: 'Dependency security', description: 'Verify that the application does not use deprecated or insecure third-party libraries.',
    framework: 'OWASP-ASVS', cweMapping: ['CWE-1035'], owaspMapping: ['A06'], criticality: 'REQUIRED' },
  { id: 'ASVS-12.3.1', name: 'File upload restrictions', description: 'Verify that file handling is done securely to prevent path traversal attacks.',
    framework: 'OWASP-ASVS', cweMapping: ['CWE-22', 'CWE-367'], owaspMapping: ['A01', 'A04'], criticality: 'REQUIRED' },
  { id: 'ASVS-13.1.1', name: 'SSRF protection', description: 'Verify that server-side request forgery protections are in place.',
    framework: 'OWASP-ASVS', cweMapping: ['CWE-918'], owaspMapping: ['A10'], criticality: 'REQUIRED' },

  // ISO 27001
  { id: 'ISO-A.14.2.1', name: 'Secure development policy', description: 'Rules for the development of software and systems shall be established and applied.',
    framework: 'ISO-27001', cweMapping: ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-502'], owaspMapping: ['A03', 'A08'], criticality: 'REQUIRED' },
  { id: 'ISO-A.14.2.5', name: 'Secure system engineering', description: 'Principles for engineering secure systems shall be applied to the full development lifecycle.',
    framework: 'ISO-27001', cweMapping: ['CWE-798', 'CWE-489', 'CWE-547'], owaspMapping: ['A05', 'A07'], criticality: 'REQUIRED' },
  { id: 'ISO-A.10.1.1', name: 'Cryptographic controls', description: 'A policy on the use of cryptographic controls for protection of information shall be developed and implemented.',
    framework: 'ISO-27001', cweMapping: ['CWE-327', 'CWE-338', 'CWE-329', 'CWE-295', 'CWE-319'], owaspMapping: ['A02'], criticality: 'REQUIRED' },
  { id: 'ISO-A.9.4.2', name: 'Secure log-on procedures', description: 'Where required by the access control policy, access to systems shall be controlled by a secure log-on procedure.',
    framework: 'ISO-27001', cweMapping: ['CWE-256', 'CWE-347', 'CWE-521', 'CWE-598'], owaspMapping: ['A07'], criticality: 'REQUIRED' },

  // HIPAA
  { id: 'HIPAA-164.312(a)', name: 'Access control', description: 'Implement technical policies and procedures for electronic information systems that maintain ePHI.',
    framework: 'HIPAA', cweMapping: ['CWE-862', 'CWE-22', 'CWE-798', 'CWE-256'], owaspMapping: ['A01', 'A07'], criticality: 'REQUIRED' },
  { id: 'HIPAA-164.312(c)', name: 'Integrity controls', description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction.',
    framework: 'HIPAA', cweMapping: ['CWE-89', 'CWE-502', 'CWE-915'], owaspMapping: ['A03', 'A08', 'A04'], criticality: 'REQUIRED' },
  { id: 'HIPAA-164.312(e)', name: 'Transmission security', description: 'Implement technical security measures to guard against unauthorized access to ePHI transmitted over networks.',
    framework: 'HIPAA', cweMapping: ['CWE-319', 'CWE-295', 'CWE-614'], owaspMapping: ['A02', 'A05'], criticality: 'REQUIRED' },
  { id: 'HIPAA-164.312(b)', name: 'Audit controls', description: 'Implement hardware, software, and/or procedural mechanisms to record and examine activity in systems containing ePHI.',
    framework: 'HIPAA', cweMapping: ['CWE-532', 'CWE-209'], owaspMapping: ['A09'], criticality: 'REQUIRED' },

  // GDPR
  { id: 'GDPR-Art.25', name: 'Data protection by design', description: 'The controller shall implement appropriate technical and organisational measures for data protection.',
    framework: 'GDPR', cweMapping: ['CWE-798', 'CWE-321', 'CWE-256', 'CWE-327'], owaspMapping: ['A02', 'A07'], criticality: 'REQUIRED' },
  { id: 'GDPR-Art.32', name: 'Security of processing', description: 'Implement appropriate technical measures to ensure security appropriate to the risk.',
    framework: 'GDPR', cweMapping: ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-319', 'CWE-502'], owaspMapping: ['A02', 'A03', 'A08'], criticality: 'REQUIRED' },
]

// ─── Mapper ───────────────────────────────────────────────────────────────────

export function mapToCompliance(
  findings: SastFindingResult[],
  framework?: ComplianceFramework
): ComplianceResult[] {
  const frameworks: ComplianceFramework[] = framework
    ? [framework]
    : ['PCI-DSS', 'SOC2', 'OWASP-ASVS', 'ISO-27001', 'HIPAA', 'GDPR']

  const frameworkNames: Record<ComplianceFramework, string> = {
    'PCI-DSS':    'PCI DSS v4.0',
    'SOC2':       'SOC 2 Type II',
    'OWASP-ASVS': 'OWASP ASVS v4.0',
    'ISO-27001':  'ISO/IEC 27001:2022',
    'HIPAA':      'HIPAA Security Rule',
    'GDPR':       'GDPR (EU 2016/679)',
  }

  // Active (non-FP) findings only
  const activeFindings = findings.filter(f => !f.falsePositive)

  return frameworks.map(fw => {
    const controls = CONTROLS.filter(c => c.framework === fw)
    const assessments: ControlAssessment[] = controls.map(control => {
      // Find matching findings by CWE or OWASP mapping
      const matchedFindings = activeFindings.filter(f => {
        const cweMatch = control.cweMapping.includes(f.cwe)
        const owaspMatch = control.owaspMapping.some(o => f.owasp.startsWith(o))
        return cweMatch || owaspMatch
      })

      const sevOrder: SastSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
      const highest = matchedFindings.length > 0
        ? matchedFindings.reduce((a, b) =>
            sevOrder.indexOf(a.severity) < sevOrder.indexOf(b.severity) ? a : b
          ).severity
        : null

      let status: ControlAssessment['status'] = 'PASS'
      if (matchedFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
        status = 'FAIL'
      } else if (matchedFindings.some(f => f.severity === 'MEDIUM')) {
        status = 'PARTIAL'
      }

      return { control, status, findings: matchedFindings, highest }
    })

    const passed = assessments.filter(a => a.status === 'PASS').length
    const failed = assessments.filter(a => a.status === 'FAIL').length
    const partial = assessments.filter(a => a.status === 'PARTIAL').length
    const total = controls.length
    const score = total > 0 ? Math.round(((passed + partial * 0.5) / total) * 100) : 100

    return {
      framework:     fw,
      fullName:      frameworkNames[fw],
      totalControls: total,
      passedControls: passed,
      failedControls: failed + partial,
      notApplicable:  0,
      score,
      controls:      assessments,
    }
  })
}

/** Get all supported frameworks */
export function getFrameworks(): { id: ComplianceFramework; name: string }[] {
  return [
    { id: 'PCI-DSS', name: 'PCI DSS v4.0' },
    { id: 'SOC2', name: 'SOC 2 Type II' },
    { id: 'OWASP-ASVS', name: 'OWASP ASVS v4.0' },
    { id: 'ISO-27001', name: 'ISO/IEC 27001:2022' },
    { id: 'HIPAA', name: 'HIPAA Security Rule' },
    { id: 'GDPR', name: 'GDPR (EU 2016/679)' },
  ]
}
