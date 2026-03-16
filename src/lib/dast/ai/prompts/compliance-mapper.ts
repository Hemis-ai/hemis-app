import { z } from 'zod'
import { claudeClient } from '../claude-client'

const ComplianceControlSchema = z.object({
  framework: z.string(),
  controlId: z.string(),
  controlName: z.string().max(200),
  status: z.enum(['FAIL', 'AT_RISK', 'NEEDS_REVIEW']),
  findingIndices: z.array(z.number()),
  remediationNote: z.string().max(300),
})

const ComplianceReportSchema = z.object({
  frameworks: z.array(z.object({
    name: z.string(),
    overallStatus: z.enum(['CRITICAL_GAPS', 'SIGNIFICANT_GAPS', 'MINOR_GAPS', 'PASSING']),
    controlsAffected: z.number(),
    totalControlsChecked: z.number(),
    affectedControls: z.array(ComplianceControlSchema).max(20),
  })).max(5),
  highestRiskFramework: z.string(),
  complianceScore: z.number().min(0).max(100),
  auditReadiness: z.enum(['NOT_READY', 'NEEDS_WORK', 'MOSTLY_READY', 'READY']),
  keyGaps: z.array(z.string().max(200)).max(10),
})

export type ComplianceReport = z.infer<typeof ComplianceReportSchema>

interface FindingSummary {
  index: number
  type: string
  severity: string
  owaspCategory: string
  pciDssRefs: string[]
  soc2Refs: string[]
  cweId?: string
}

export async function generateComplianceReport(
  findings: FindingSummary[],
  targetUrl: string,
): Promise<ComplianceReport | null> {
  if (findings.length === 0) return null

  const systemPrompt = `You are a GRC (Governance, Risk, and Compliance) specialist with deep expertise in PCI DSS 4.0, SOC 2 Type II, HIPAA, GDPR, and ISO 27001.

Given DAST scan findings, map them to specific compliance control failures across these frameworks:

1. **PCI DSS 4.0** — Focus on Requirements 6 (Secure Systems), 4 (Encryption), 8 (Authentication), 10 (Logging)
2. **SOC 2 Type II** — Map to Trust Service Criteria: CC6 (Logical Access), CC7 (System Operations), CC8 (Change Management)
3. **HIPAA** — Map to Technical Safeguards §164.312 (Access Control, Audit, Integrity, Transmission)
4. **GDPR** — Map to Articles 25 (Data Protection by Design), 32 (Security of Processing), 33 (Breach Notification)

Output ONLY valid JSON matching this structure:
{
  "frameworks": [{
    "name": "PCI DSS 4.0",
    "overallStatus": "CRITICAL_GAPS|SIGNIFICANT_GAPS|MINOR_GAPS|PASSING",
    "controlsAffected": number,
    "totalControlsChecked": number,
    "affectedControls": [{ "framework": "PCI DSS 4.0", "controlId": "6.2.4", "controlName": "string", "status": "FAIL|AT_RISK|NEEDS_REVIEW", "findingIndices": [0, 2], "remediationNote": "string" }]
  }],
  "highestRiskFramework": "string — which framework is most impacted",
  "complianceScore": number (0-100) — overall compliance posture,
  "auditReadiness": "NOT_READY|NEEDS_WORK|MOSTLY_READY|READY",
  "keyGaps": ["string", ...] — top compliance gaps across all frameworks
}

Be precise with control IDs. Only map findings to controls where there is a clear, defensible connection.`

  const findingsList = findings
    .map((f) => `[${f.index}] ${f.severity} | ${f.type} | ${f.owaspCategory}${f.cweId ? ` | ${f.cweId}` : ''}${f.pciDssRefs.length ? ` | PCI: ${f.pciDssRefs.join(',')}` : ''}${f.soc2Refs.length ? ` | SOC2: ${f.soc2Refs.join(',')}` : ''}`)
    .join('\n')

  const userPrompt = `Map these ${findings.length} DAST findings to compliance framework controls:

Target Application: ${targetUrl}

Findings:
${findingsList}

Generate a compliance report covering PCI DSS 4.0, SOC 2 Type II, HIPAA, and GDPR. Be specific about which controls are affected and why.`

  return claudeClient.callClaude<ComplianceReport>(systemPrompt, userPrompt, (response: string) => {
    try {
      let text = response.trim()
      if (text.startsWith('```')) {
        text = text.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '')
      }
      const parsed = JSON.parse(text)
      const validated = ComplianceReportSchema.parse(parsed)
      return { valid: true, data: validated }
    } catch (err) {
      return { valid: false, error: `Parse/validation failed: ${err instanceof Error ? err.message : String(err)}` }
    }
  }, { maxTokens: 4000 })
}
