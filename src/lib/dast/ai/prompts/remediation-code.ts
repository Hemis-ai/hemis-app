import { z } from 'zod'
import { claudeClient } from '../claude-client'

const RemediationCodeSchema = z.object({
  vulnerableCode: z.string().min(20).max(1000),
  remediatedCode: z.string().min(20).max(1000),
  explanation: z.string().min(50).max(500),
  dependencies: z.array(z.string()).max(5),
  testingGuidance: z.string().min(30).max(300),
})

export type RemediationCode = z.infer<typeof RemediationCodeSchema>

interface RemediationContext {
  type: string; title: string; description: string; affectedUrl: string
  affectedParameter?: string; techStack: string[]; payload?: string; severity: string
}

export async function generateRemediationCode(context: RemediationContext): Promise<RemediationCode | null> {
  const applicableTypes = ['sql_injection', 'command_injection', 'xss_reflected', 'xss_stored', 'path_traversal', 'broken_access_control']
  if (!applicableTypes.includes(context.type)) return null

  const techStack = context.techStack.join(', ') || 'Unknown'
  const systemPrompt = `You are a senior software engineer reviewing security vulnerabilities.
Generate practical code fixes for the reported vulnerability.
Output ONLY valid JSON matching this structure:
{
  "vulnerableCode": "string (code snippet with vulnerability)",
  "remediatedCode": "string (fixed code snippet)",
  "explanation": "string (why the fix works)",
  "dependencies": ["string", ...],
  "testingGuidance": "string (how to verify the fix)"
}
Code snippets should be concise (5-15 lines), syntactically correct, and directly address the vulnerability.`

  const userPrompt = `Generate remediation code for this vulnerability:

Type: ${context.type}
Title: ${context.title}
Severity: ${context.severity}
Description: ${context.description}
Affected URL: ${context.affectedUrl}
${context.affectedParameter ? `Affected Parameter: ${context.affectedParameter}` : ''}
Technology Stack: ${techStack}
${context.payload ? `Example Payload: ${context.payload}` : ''}

Provide before/after code, explanation, dependencies, and testing guidance.`

  return claudeClient.callClaude<RemediationCode>(systemPrompt, userPrompt, (response: string) => {
    try {
      const parsed = JSON.parse(response)
      const validated = RemediationCodeSchema.parse(parsed)
      return { valid: true, data: validated }
    } catch (err) {
      return { valid: false, error: `Parse/validation failed: ${err instanceof Error ? err.message : String(err)}` }
    }
  })
}
