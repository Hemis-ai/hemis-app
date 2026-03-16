import { claudeClient } from '../claude-client'

interface ScanContext {
  scanName: string; targetUrl: string; scanProfileName: string
  scanDurationMs: number; endpointsDiscovered: number; endpointsTested: number
  payloadsSent: number; techStackDetected: string[]
  criticalCount: number; highCount: number; mediumCount: number
  lowCount: number; infoCount: number
  topCriticalFindings: Array<{ title: string; url: string }>
  topHighFindings: Array<{ title: string; url: string }>
  // ─── Phase 4: Enhanced context ───
  owaspCategoryCounts?: Record<string, number>
  authType?: string
  riskScore?: number
  previousScanFindingsCount?: number
}

export async function generateExecutiveSummary(context: ScanContext): Promise<string | null> {
  const totalFindings = context.criticalCount + context.highCount + context.mediumCount + context.lowCount + context.infoCount
  const scanDurationMin = Math.round(context.scanDurationMs / 60000)

  const systemPrompt = `You are a senior security executive preparing an assessment report for a CISO, CTO, or board of directors.

Write a comprehensive yet concise executive summary of a web application security assessment.

Structure your summary with these sections (use markdown headers):

## Security Posture Overview
Overall security rating and key findings summary.

## Critical Risk Areas
Top 3 risks with business impact (revenue, reputation, regulatory).

## OWASP Top 10 Coverage
Which OWASP categories had findings and what that means.

## Compliance Impact
How findings affect PCI DSS 4.0, SOC 2, GDPR, and HIPAA compliance posture.

## Recommended Actions
Prioritized remediation roadmap:
- Immediate (0-48 hours): Critical items
- Short-term (1-2 weeks): High-priority items
- Medium-term (1-3 months): Systematic improvements

## Risk Trend
${context.previousScanFindingsCount !== undefined ? `Compare with previous scan (${context.previousScanFindingsCount} findings) and note improvement or regression.` : 'Note this is a baseline assessment.'}

Requirements:
- Target audience: C-suite executives with limited technical knowledge
- Length: 500-900 words
- Tone: Professional, confident, actionable
- Use specific numbers from the data provided
- Do NOT use the word "comprehensive"
- Output ONLY the summary text in markdown format`

  const owaspBreakdown = context.owaspCategoryCounts
    ? Object.entries(context.owaspCategoryCounts)
        .sort(([, a], [, b]) => b - a)
        .map(([cat, count]) => `  - ${cat}: ${count} findings`)
        .join('\n')
    : ''

  const userPrompt = `Generate an executive summary for this security assessment:

Assessment Details:
- Application: ${context.targetUrl}
- Assessment Name: ${context.scanName}
- Assessment Type: ${context.scanProfileName} DAST (Dynamic Application Security Testing)
- Duration: ${scanDurationMin} minutes
- Endpoints Discovered: ${context.endpointsDiscovered}
- Endpoints Tested: ${context.endpointsTested}
- Test Payloads Sent: ${context.payloadsSent}
- Detected Technology: ${context.techStackDetected.join(', ') || 'Unidentified'}
${context.authType ? `- Authentication: ${context.authType}` : ''}
${context.riskScore !== undefined ? `- Computed Risk Score: ${context.riskScore}/100` : ''}

Findings Summary:
- CRITICAL: ${context.criticalCount}
- HIGH: ${context.highCount}
- MEDIUM: ${context.mediumCount}
- LOW: ${context.lowCount}
- INFO: ${context.infoCount}
- Total: ${totalFindings}

${owaspBreakdown ? `OWASP Top 10 Breakdown:\n${owaspBreakdown}` : ''}

${context.topCriticalFindings.length > 0 ? `Top Critical Issues:\n${context.topCriticalFindings.map((f) => `- ${f.title} (${f.url})`).join('\n')}` : ''}
${context.topHighFindings.length > 0 ? `\nTop High Issues:\n${context.topHighFindings.map((f) => `- ${f.title} (${f.url})`).join('\n')}` : ''}

${context.previousScanFindingsCount !== undefined ? `Previous scan had ${context.previousScanFindingsCount} total findings.` : 'This is the first scan for this target.'}

Write the executive summary with all sections: posture overview, critical risks, OWASP coverage, compliance impact, recommended actions, and risk trend.`

  return claudeClient.callClaude<string>(systemPrompt, userPrompt, (response: string) => {
    const text = response.trim()
    if (text.length < 400 || text.length > 4000) return { valid: false, error: `Summary length ${text.length} outside bounds` }
    return { valid: true, data: text }
  }, { maxTokens: 3000 })
}
