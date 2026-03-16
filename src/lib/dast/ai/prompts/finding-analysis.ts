import { z } from 'zod'
import { claudeClient } from '../claude-client'

const FindingAnalysisSchema = z.object({
  businessImpact: z.string().min(50).max(1000),
  technicalDetail: z.string().min(50).max(500),
  exploitDifficulty: z.enum(['LOW', 'MEDIUM', 'HIGH']),
  dataAtRisk: z.array(z.string()).max(10),
  complianceImplications: z.array(z.string()).max(8),
  // ─── Enhanced Phase 4 fields ───
  attackScenario: z.string().min(30).max(600).optional(),
  falsePositiveLikelihood: z.enum(['LOW', 'MEDIUM', 'HIGH']).optional(),
  falsePositiveReason: z.string().max(300).optional(),
  priorityScore: z.number().min(1).max(100).optional(),
  priorityReason: z.string().max(300).optional(),
  relatedCwes: z.array(z.string()).max(5).optional(),
  mitigationUrgency: z.enum(['IMMEDIATE', 'SHORT_TERM', 'MEDIUM_TERM', 'LOW_PRIORITY']).optional(),
})

export type FindingAnalysis = z.infer<typeof FindingAnalysisSchema>

interface FindingContext {
  type: string; owaspCategory: string; severity: string; cvssScore?: number
  title: string; description: string; affectedUrl: string
  affectedParameter?: string; payload?: string
  requestEvidence?: string; responseEvidence?: string; techStack: string[]
  // Phase 4: additional context for deeper analysis
  scanProfile?: string
  authType?: string
  otherFindingTypes?: string[]
}

export async function analyzeFinding(context: FindingContext): Promise<FindingAnalysis | null> {
  const systemPrompt = `You are a senior application security consultant with 15+ years of experience performing DAST assessments for Fortune 500 companies. You are analyzing vulnerability findings from a ZAP-based scanner.

Your analysis must be:
1. Business-focused: explain impact in terms executives understand (revenue, reputation, legal)
2. Technically precise: reference specific CWEs, attack techniques, and exploitation paths
3. Pragmatic about false positives: assess likelihood based on evidence quality and context
4. Prioritized: assign a 1-100 priority score considering exploitability, data sensitivity, and blast radius

Output ONLY valid JSON matching this structure:
{
  "businessImpact": "string (50-1000 chars) — explain the real-world business consequences",
  "technicalDetail": "string (50-500 chars) — precise technical explanation",
  "exploitDifficulty": "LOW|MEDIUM|HIGH",
  "dataAtRisk": ["string", ...] — specific data types at risk (PII, credentials, financial, health, etc.),
  "complianceImplications": ["string", ...] — specific regulations affected (PCI DSS 4.0 Req X, SOC 2 CC6.x, HIPAA §X, GDPR Art X, etc.),
  "attackScenario": "string (30-600 chars) — step-by-step realistic exploitation scenario",
  "falsePositiveLikelihood": "LOW|MEDIUM|HIGH" — based on evidence quality,
  "falsePositiveReason": "string — why this might or might not be a false positive",
  "priorityScore": number (1-100) — overall remediation priority,
  "priorityReason": "string — justification for the priority score",
  "relatedCwes": ["CWE-XXX", ...] — related weakness identifiers beyond the primary one,
  "mitigationUrgency": "IMMEDIATE|SHORT_TERM|MEDIUM_TERM|LOW_PRIORITY"
}`

  const otherContext = context.otherFindingTypes?.length
    ? `\nOther findings in this scan: ${context.otherFindingTypes.slice(0, 10).join(', ')}`
    : ''

  const userPrompt = `Analyze this security finding from a ${context.scanProfile || 'full'} DAST scan:

Vulnerability Type: ${context.type}
OWASP Category: ${context.owaspCategory}
Severity: ${context.severity}
${context.cvssScore ? `CVSS 3.1 Score: ${context.cvssScore}` : ''}

Title: ${context.title}
Description: ${context.description}

Affected URL: ${context.affectedUrl}
${context.affectedParameter ? `Affected Parameter: ${context.affectedParameter}` : ''}
${context.payload ? `Example Payload: ${context.payload}` : ''}

Detected Tech Stack: ${context.techStack.join(', ') || 'Unknown'}
${context.authType ? `Authentication Type: ${context.authType}` : ''}
${otherContext}

${context.requestEvidence ? `Request Evidence (first 300 chars): ${context.requestEvidence.substring(0, 300)}` : ''}
${context.responseEvidence ? `Response Evidence (first 300 chars): ${context.responseEvidence.substring(0, 300)}` : ''}

Provide comprehensive analysis including: business impact, technical detail, exploitation difficulty, attack scenario, false positive assessment, priority score, data at risk, compliance implications, related CWEs, and mitigation urgency.`

  return claudeClient.callClaude<FindingAnalysis>(systemPrompt, userPrompt, (response: string) => {
    try {
      // Handle potential markdown code block wrapping
      let text = response.trim()
      if (text.startsWith('```')) {
        text = text.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '')
      }
      const parsed = JSON.parse(text)
      const validated = FindingAnalysisSchema.parse(parsed)
      return { valid: true, data: validated }
    } catch (err) {
      return { valid: false, error: `Parse/validation failed: ${err instanceof Error ? err.message : String(err)}` }
    }
  }, { maxTokens: 2500 })
}
