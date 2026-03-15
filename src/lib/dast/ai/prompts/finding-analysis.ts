import { z } from 'zod'
import { claudeClient } from '../claude-client'

const FindingAnalysisSchema = z.object({
  businessImpact: z.string().min(50).max(1000),
  technicalDetail: z.string().min(50).max(500),
  exploitDifficulty: z.enum(['LOW', 'MEDIUM', 'HIGH']),
  dataAtRisk: z.array(z.string()).max(10),
  complianceImplications: z.array(z.string()).max(8),
})

export type FindingAnalysis = z.infer<typeof FindingAnalysisSchema>

interface FindingContext {
  type: string; owaspCategory: string; severity: string; cvssScore?: number
  title: string; description: string; affectedUrl: string
  affectedParameter?: string; payload?: string
  requestEvidence?: string; responseEvidence?: string; techStack: string[]
}

export async function analyzeFinding(context: FindingContext): Promise<FindingAnalysis | null> {
  const systemPrompt = `You are a senior security consultant analyzing a vulnerability finding.
Provide a concise, business-focused explanation of the risk and its implications.
Output ONLY valid JSON matching this structure:
{
  "businessImpact": "string (50-1000 chars)",
  "technicalDetail": "string (50-500 chars)",
  "exploitDifficulty": "LOW|MEDIUM|HIGH",
  "dataAtRisk": ["string", ...],
  "complianceImplications": ["string", ...]
}`

  const userPrompt = `Analyze this security finding:

Vulnerability Type: ${context.type}
OWASP Category: ${context.owaspCategory}
Severity: ${context.severity}
${context.cvssScore ? `CVSS Score: ${context.cvssScore}` : ''}

Title: ${context.title}
Description: ${context.description}

Affected URL: ${context.affectedUrl}
${context.affectedParameter ? `Affected Parameter: ${context.affectedParameter}` : ''}
${context.payload ? `Example Payload: ${context.payload}` : ''}

Detected Tech Stack: ${context.techStack.join(', ') || 'Unknown'}

${context.requestEvidence ? `Request Evidence (first 200 chars): ${context.requestEvidence.substring(0, 200)}` : ''}
${context.responseEvidence ? `Response Evidence (first 200 chars): ${context.responseEvidence.substring(0, 200)}` : ''}

Provide business impact, technical detail, exploitation difficulty, data at risk, and compliance implications.`

  return claudeClient.callClaude<FindingAnalysis>(systemPrompt, userPrompt, (response: string) => {
    try {
      const parsed = JSON.parse(response)
      const validated = FindingAnalysisSchema.parse(parsed)
      return { valid: true, data: validated }
    } catch (err) {
      return { valid: false, error: `Parse/validation failed: ${err instanceof Error ? err.message : String(err)}` }
    }
  })
}
