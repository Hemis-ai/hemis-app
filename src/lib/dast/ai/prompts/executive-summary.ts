import { claudeClient } from '../claude-client'

interface ScanContext {
  scanName: string; targetUrl: string; scanProfileName: string
  scanDurationMs: number; endpointsDiscovered: number; endpointsTested: number
  payloadsSent: number; techStackDetected: string[]
  criticalCount: number; highCount: number; mediumCount: number
  lowCount: number; infoCount: number
  topCriticalFindings: Array<{ title: string; url: string }>
  topHighFindings: Array<{ title: string; url: string }>
}

export async function generateExecutiveSummary(context: ScanContext): Promise<string | null> {
  const systemPrompt = `You are a security executive preparing a report for a CISO or CEO.
Write a compelling, concise executive summary of a web application security assessment.
Focus on business impact, top 3 priorities, remediation timeline, and overall posture.
Target audience: C-suite executives with limited technical knowledge.
Length: 400-600 words. Tone: Professional, confident, actionable.
Output ONLY the summary text, no JSON or formatting.`

  const totalFindings = context.criticalCount + context.highCount + context.mediumCount + context.lowCount + context.infoCount
  const scanDurationMin = Math.round(context.scanDurationMs / 60000)

  const userPrompt = `Generate an executive summary for this security assessment:

Assessment Details:
- Application: ${context.targetUrl}
- Assessment Type: ${context.scanProfileName} (DAST - Dynamic Application Security Testing)
- Duration: ${scanDurationMin} minutes
- Endpoints Discovered: ${context.endpointsDiscovered}
- Endpoints Tested: ${context.endpointsTested}
- Test Payloads Sent: ${context.payloadsSent}
- Detected Technology: ${context.techStackDetected.join(', ') || 'Unidentified'}

Findings Summary:
- CRITICAL: ${context.criticalCount}, HIGH: ${context.highCount}, MEDIUM: ${context.mediumCount}, LOW: ${context.lowCount}, INFO: ${context.infoCount}
- Total: ${totalFindings}

${context.topCriticalFindings.length > 0 ? `Top Critical Issues:\n${context.topCriticalFindings.map((f) => `- ${f.title} (${f.url})`).join('\n')}` : ''}
${context.topHighFindings.length > 0 ? `\nTop High Issues:\n${context.topHighFindings.map((f) => `- ${f.title} (${f.url})`).join('\n')}` : ''}

Write an executive summary covering: overall posture, top 3 risks + business impact, remediation timeline, immediate actions (30 days), confidence + next steps.`

  return claudeClient.callClaude<string>(systemPrompt, userPrompt, (response: string) => {
    const text = response.trim()
    if (text.length < 300 || text.length > 2000) return { valid: false, error: `Summary length ${text.length} outside bounds` }
    return { valid: true, data: text }
  })
}
