import { z } from 'zod'
import { claudeClient } from '../claude-client'

const RemediationCodeSchema = z.object({
  vulnerableCode: z.string().min(20).max(1500),
  remediatedCode: z.string().min(20).max(1500),
  explanation: z.string().min(50).max(800),
  dependencies: z.array(z.string()).max(8),
  testingGuidance: z.string().min(30).max(500),
  // ─── Enhanced Phase 4 fields ───
  language: z.string().max(30).optional(),
  framework: z.string().max(50).optional(),
  configurationFix: z.string().max(800).optional(),
  securityHeaders: z.array(z.string()).max(10).optional(),
  wafRule: z.string().max(500).optional(),
})

export type RemediationCode = z.infer<typeof RemediationCodeSchema>

interface RemediationContext {
  type: string; title: string; description: string; affectedUrl: string
  affectedParameter?: string; techStack: string[]; payload?: string; severity: string
}

/** Vulnerability types that can receive code-level remediation */
const REMEDIABLE_TYPES = new Set([
  // Critical: Injection
  'sql_injection', 'sql_injection_mysql', 'sql_injection_postgres', 'sql_injection_oracle',
  'sql_injection_mssql', 'sql_injection_sqlite', 'sql_injection_hypersonic', 'sql_injection_advanced',
  'command_injection', 'server_side_code_injection', 'ssti', 'expression_language_injection',
  'xpath_injection', 'xslt_injection', 'log4shell',
  // High: XSS
  'xss_reflected', 'xss_stored', 'xss_dom', 'xss_persistent',
  // High: Access Control
  'directory_traversal', 'broken_access_control', 'idor', 'bypassing_403',
  'csrf', 'csrf_on_auth', 'ssrf',
  // High: Auth / Session
  'session_fixation', 'auth_bypass', 'oauth2_misconfiguration', 'jwt_vulnerability',
  'weak_authentication', 'brute_force',
  // Medium: Headers & Config
  'open_redirect', 'crlf_injection', 'server_side_include',
  'missing_csp', 'missing_hsts', 'missing_anti_clickjacking', 'missing_x_content_type_options',
  'insecure_cookie', 'missing_httponly', 'missing_secure_flag', 'missing_samesite',
  'insecure_session_cookie', 'cookie_without_expiry',
  // Low: Info Disclosure
  'source_code_disclosure', 'backup_file_disclosure', 'information_disclosure',
  'cloud_metadata', 'spring_actuator', 'hidden_file',
])

export async function generateRemediationCode(context: RemediationContext): Promise<RemediationCode | null> {
  if (!REMEDIABLE_TYPES.has(context.type)) return null

  const techStack = context.techStack.join(', ') || 'Unknown'
  const isHeaderOrConfigIssue = context.type.startsWith('missing_') || context.type.startsWith('insecure_') || context.type === 'cookie_without_expiry'

  const systemPrompt = `You are a senior software engineer and security architect with deep expertise in secure coding practices across multiple frameworks and languages.

Generate practical, production-ready remediation for the reported vulnerability.

${isHeaderOrConfigIssue ? `This is a configuration/header issue. Focus on server configuration and middleware changes.` : `This is a code-level vulnerability. Provide before/after code snippets that directly fix the issue.`}

Output ONLY valid JSON matching this structure:
{
  "vulnerableCode": "string — code snippet demonstrating the vulnerability (or current insecure config)",
  "remediatedCode": "string — fixed code snippet (or secure configuration)",
  "explanation": "string — clear explanation of why the fix works and what attack vectors it blocks",
  "dependencies": ["string", ...] — required packages or libraries for the fix,
  "testingGuidance": "string — how to verify the fix works (include specific test cases)",
  "language": "string — primary language used (e.g., JavaScript, Python, Java)",
  "framework": "string — framework if applicable (e.g., Express, Django, Spring Boot)",
  "configurationFix": "string (optional) — server/infrastructure configuration changes if applicable (e.g., nginx config, .htaccess, web.xml)",
  "securityHeaders": ["string", ...] (optional) — recommended HTTP security headers to add,
  "wafRule": "string (optional) — WAF rule suggestion if applicable (ModSecurity/CloudFlare format)"
}

Rules:
- Code must be syntactically correct and production-ready
- Infer the most likely language/framework from the tech stack
- If multiple frameworks detected, use the most relevant one
- Include input validation, output encoding, and defense-in-depth where applicable
- For header issues, provide middleware/config snippets for the detected stack`

  const userPrompt = `Generate remediation code for this vulnerability:

Type: ${context.type}
Title: ${context.title}
Severity: ${context.severity}
Description: ${context.description}
Affected URL: ${context.affectedUrl}
${context.affectedParameter ? `Affected Parameter: ${context.affectedParameter}` : ''}
Technology Stack: ${techStack}
${context.payload ? `Example Payload: ${context.payload}` : ''}

Provide comprehensive remediation: before/after code, explanation, dependencies, testing guidance, and any applicable configuration or WAF rules.`

  return claudeClient.callClaude<RemediationCode>(systemPrompt, userPrompt, (response: string) => {
    try {
      let text = response.trim()
      if (text.startsWith('```')) {
        text = text.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '')
      }
      const parsed = JSON.parse(text)
      const validated = RemediationCodeSchema.parse(parsed)
      return { valid: true, data: validated }
    } catch (err) {
      return { valid: false, error: `Parse/validation failed: ${err instanceof Error ? err.message : String(err)}` }
    }
  }, { maxTokens: 3000 })
}
