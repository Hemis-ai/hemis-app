// HemisX SAST — Claude AI Enrichment Engine
// Uses the Anthropic Claude API to provide intelligent analysis of SAST findings:
// - Detailed remediation with code examples
// - False positive assessment with confidence scoring
// - Business impact analysis
// - Fix code generation
// - Executive-friendly explanations

import Anthropic from '@anthropic-ai/sdk'
import type { SastFindingResult, SastScanResult } from '@/lib/types/sast'

// ─── Types ──────────────────────────────────────────────────────────────────

export interface EnrichedFinding extends SastFindingResult {
  aiEnrichment?: AiEnrichment
}

export interface AiEnrichment {
  analysisId:       string
  // AI-assessed false positive probability (0-100)
  falsePositiveProbability: number
  fpReasoning:      string
  // Business impact analysis
  businessImpact:   string
  impactLevel:      'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'
  // Detailed remediation with code
  detailedRemediation: string
  fixCode:          string
  fixLanguage:      string
  // Executive-friendly explanation
  executiveExplanation: string
  // Related CVEs/attack techniques
  relatedCVEs:      string[]
  attackTechniques:  string[]
  // Confidence in the analysis
  aiConfidence:     number  // 0-100
  model:            string
  analyzedAt:       string
}

export interface ScanSummaryEnrichment {
  overallAssessment:  string
  prioritizedActions: string[]
  riskNarrative:      string
  complianceNotes:    string
  estimatedEffort:    string
}

// ─── Client ─────────────────────────────────────────────────────────────────

function getClient(): Anthropic | null {
  const apiKey = process.env.ANTHROPIC_API_KEY
  if (!apiKey) return null
  return new Anthropic({ apiKey })
}

// ─── Enrich a single finding ────────────────────────────────────────────────

export async function enrichFinding(
  finding: SastFindingResult,
  fileContext?: string,
): Promise<AiEnrichment | null> {
  const client = getClient()
  if (!client) {
    console.warn('[AI Enrichment] No ANTHROPIC_API_KEY set — returning mock enrichment')
    return generateMockEnrichment(finding)
  }

  try {
    const prompt = buildFindingPrompt(finding, fileContext)

    const message = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
      system: `You are a senior application security engineer analyzing SAST (Static Application Security Testing) findings. Provide precise, actionable analysis. Always respond with valid JSON matching the requested schema. Be concise but thorough.`,
    })

    const text = message.content[0].type === 'text' ? message.content[0].text : ''

    // Parse JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/)
    if (!jsonMatch) return generateMockEnrichment(finding)

    const parsed = JSON.parse(jsonMatch[0])

    return {
      analysisId:              `ai-${Date.now()}`,
      falsePositiveProbability: parsed.falsePositiveProbability ?? 10,
      fpReasoning:             parsed.fpReasoning ?? '',
      businessImpact:          parsed.businessImpact ?? '',
      impactLevel:             parsed.impactLevel ?? finding.severity,
      detailedRemediation:     parsed.detailedRemediation ?? finding.remediation,
      fixCode:                 parsed.fixCode ?? '',
      fixLanguage:             parsed.fixLanguage ?? finding.language,
      executiveExplanation:    parsed.executiveExplanation ?? '',
      relatedCVEs:             parsed.relatedCVEs ?? [],
      attackTechniques:        parsed.attackTechniques ?? [],
      aiConfidence:            parsed.aiConfidence ?? 80,
      model:                   'claude-sonnet-4-20250514',
      analyzedAt:              new Date().toISOString(),
    }
  } catch (err) {
    console.error('[AI Enrichment] Error:', err)
    return generateMockEnrichment(finding)
  }
}

// ─── Enrich multiple findings (batch) ───────────────────────────────────────

export async function enrichFindings(
  findings: SastFindingResult[],
  maxConcurrent: number = 3,
): Promise<Map<string, AiEnrichment>> {
  const results = new Map<string, AiEnrichment>()

  // Process in batches to respect rate limits
  for (let i = 0; i < findings.length; i += maxConcurrent) {
    const batch = findings.slice(i, i + maxConcurrent)
    const enrichments = await Promise.all(
      batch.map(f => enrichFinding(f).then(e => ({ id: f.id, enrichment: e })))
    )
    for (const { id, enrichment } of enrichments) {
      if (enrichment) results.set(id, enrichment)
    }
  }

  return results
}

// ─── Enrich scan summary ────────────────────────────────────────────────────

export async function enrichScanSummary(
  scan: SastScanResult,
): Promise<ScanSummaryEnrichment | null> {
  const client = getClient()
  if (!client) return generateMockScanSummary(scan)

  try {
    const findingSummary = scan.findings
      .filter(f => !f.falsePositive)
      .slice(0, 20)
      .map(f => `- [${f.severity}] ${f.ruleName} in ${f.filePath}:${f.lineStart} (${f.cwe})`)
      .join('\n')

    const message = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1500,
      messages: [{
        role: 'user',
        content: `Analyze this SAST scan and provide a security assessment.

Scan: "${scan.name}" | ${scan.language} | ${scan.filesScanned} files | ${scan.linesOfCode} LOC
Summary: ${scan.summary.critical} critical, ${scan.summary.high} high, ${scan.summary.medium} medium, ${scan.summary.low} low

Findings:
${findingSummary}

Respond with JSON:
{
  "overallAssessment": "2-3 sentence overall security assessment",
  "prioritizedActions": ["top 3-5 prioritized remediation actions"],
  "riskNarrative": "Business-friendly risk narrative (2-3 sentences)",
  "complianceNotes": "Relevant compliance implications (PCI-DSS, SOC2, etc.)",
  "estimatedEffort": "Estimated remediation effort (e.g., '2-3 developer-days')"
}`,
      }],
      system: 'You are a CISO-level security advisor. Provide clear, actionable assessments. Respond with valid JSON only.',
    })

    const text = message.content[0].type === 'text' ? message.content[0].text : ''
    const jsonMatch = text.match(/\{[\s\S]*\}/)
    if (!jsonMatch) return generateMockScanSummary(scan)

    return JSON.parse(jsonMatch[0]) as ScanSummaryEnrichment
  } catch (err) {
    console.error('[AI Enrichment] Scan summary error:', err)
    return generateMockScanSummary(scan)
  }
}

// ─── Prompt Builder ─────────────────────────────────────────────────────────

function buildFindingPrompt(finding: SastFindingResult, fileContext?: string): string {
  return `Analyze this SAST finding and provide security assessment.

**Finding:**
- Rule: ${finding.ruleId} — ${finding.ruleName}
- Severity: ${finding.severity} | Confidence: ${finding.confidence}
- File: ${finding.filePath}:${finding.lineStart}
- CWE: ${finding.cwe} | OWASP: ${finding.owasp}
- Category: ${finding.category}

**Code:**
\`\`\`${finding.language}
${finding.codeSnippet}
\`\`\`

${fileContext ? `**Surrounding context:**\n\`\`\`\n${fileContext.slice(0, 1000)}\n\`\`\`\n` : ''}

**Current remediation suggestion:** ${finding.remediation}

Respond with JSON:
{
  "falsePositiveProbability": <0-100, probability this is a false positive>,
  "fpReasoning": "<why this might or might not be a false positive>",
  "businessImpact": "<specific business impact if exploited>",
  "impactLevel": "<CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL>",
  "detailedRemediation": "<step-by-step remediation guide>",
  "fixCode": "<corrected code snippet>",
  "fixLanguage": "${finding.language}",
  "executiveExplanation": "<non-technical explanation for executives, 1-2 sentences>",
  "relatedCVEs": ["<relevant CVE IDs if any>"],
  "attackTechniques": ["<MITRE ATT&CK technique IDs if applicable>"],
  "aiConfidence": <0-100, your confidence in this analysis>
}`
}

// ─── Mock Enrichment (when no API key) ──────────────────────────────────────

function generateMockEnrichment(finding: SastFindingResult): AiEnrichment {
  const mockData: Record<string, Partial<AiEnrichment>> = {
    'Injection': {
      falsePositiveProbability: 8,
      fpReasoning: 'The code clearly shows dynamic string construction in a security-sensitive context. Pattern matches known injection vectors with high confidence.',
      businessImpact: 'An attacker could manipulate the query to bypass authentication, extract sensitive data from the database, or modify/delete records. This could lead to a full data breach.',
      impactLevel: 'CRITICAL',
      detailedRemediation: '1. Replace string concatenation with parameterized queries\n2. Use an ORM (Prisma, Sequelize) which auto-parameterizes\n3. Add input validation with allowlisting\n4. Implement WAF rules as defense-in-depth',
      fixCode: `// Before (vulnerable):\nconst query = "SELECT * FROM users WHERE id = " + userId;\n\n// After (safe):\nconst query = "SELECT * FROM users WHERE id = $1";\nconst result = await db.query(query, [userId]);`,
      executiveExplanation: 'This vulnerability could allow an attacker to access or modify any data in the database, including customer records and credentials.',
      relatedCVEs: ['CVE-2023-36844', 'CVE-2022-36067'],
      attackTechniques: ['T1190', 'T1059'],
    },
    'Secrets': {
      falsePositiveProbability: 5,
      fpReasoning: 'The detected string has characteristics of a real credential (high entropy, matches known credential patterns). It is hardcoded directly in source code.',
      businessImpact: 'Exposed credentials could grant unauthorized access to production systems, databases, or third-party services. If the repository is public, credentials may already be compromised.',
      impactLevel: 'HIGH',
      detailedRemediation: '1. Immediately rotate the exposed credential\n2. Move to environment variables or a secrets manager\n3. Add .env to .gitignore\n4. Scan git history for other exposed secrets\n5. Set up pre-commit hooks to prevent future leaks',
      fixCode: `// Before (vulnerable):\nconst API_KEY = "sk-live_abc123...";\n\n// After (safe):\nconst API_KEY = process.env.API_KEY;\nif (!API_KEY) throw new Error("API_KEY not configured");`,
      executiveExplanation: 'A password or API key was found hardcoded in the source code. If exposed, an attacker could use it to access company systems.',
      relatedCVEs: [],
      attackTechniques: ['T1552.001', 'T1078'],
    },
    'Cryptography': {
      falsePositiveProbability: 12,
      fpReasoning: 'Weak algorithm usage is confirmed. However, context matters — MD5 used for non-security checksums (e.g., ETags) is acceptable, but for password hashing or data integrity it is not.',
      businessImpact: 'Weak cryptography could allow attackers to forge signatures, crack password hashes, or decrypt sensitive data. This undermines the security of the entire authentication system.',
      impactLevel: 'MEDIUM',
      detailedRemediation: '1. Replace MD5/SHA1 with SHA-256 or SHA-3\n2. For passwords, use bcrypt (cost ≥ 12) or argon2id\n3. For HMAC, use HMAC-SHA-256 minimum\n4. Update all dependent systems that verify these hashes',
      fixCode: `// Before (weak):\nconst hash = crypto.createHash('md5').update(data).digest('hex');\n\n// After (strong):\nconst hash = crypto.createHash('sha256').update(data).digest('hex');`,
      executiveExplanation: 'The application uses outdated encryption methods that could be broken by modern computers, putting user data at risk.',
      relatedCVEs: ['CVE-2004-2761'],
      attackTechniques: ['T1557', 'T1040'],
    },
  }

  const categoryMock = mockData[finding.category] || mockData['Injection']!

  return {
    analysisId:              `mock-${Date.now()}`,
    falsePositiveProbability: categoryMock.falsePositiveProbability ?? 15,
    fpReasoning:             categoryMock.fpReasoning ?? 'Analysis based on code pattern matching and context evaluation.',
    businessImpact:          categoryMock.businessImpact ?? 'Could lead to security compromise if exploited by an attacker.',
    impactLevel:             (categoryMock.impactLevel as AiEnrichment['impactLevel']) ?? finding.severity,
    detailedRemediation:     categoryMock.detailedRemediation ?? finding.remediation,
    fixCode:                 categoryMock.fixCode ?? '',
    fixLanguage:             finding.language,
    executiveExplanation:    categoryMock.executiveExplanation ?? 'A security vulnerability was detected that should be addressed.',
    relatedCVEs:             categoryMock.relatedCVEs ?? [],
    attackTechniques:        categoryMock.attackTechniques ?? [],
    aiConfidence:            78,
    model:                   'mock-enrichment (set ANTHROPIC_API_KEY for real analysis)',
    analyzedAt:              new Date().toISOString(),
  }
}

function generateMockScanSummary(scan: SastScanResult): ScanSummaryEnrichment {
  const activeFindings = scan.findings.filter(f => !f.falsePositive)
  const critical = activeFindings.filter(f => f.severity === 'CRITICAL').length
  const high = activeFindings.filter(f => f.severity === 'HIGH').length

  return {
    overallAssessment: `The ${scan.language} codebase shows ${critical > 0 ? 'significant' : 'moderate'} security concerns with ${activeFindings.length} findings across ${scan.filesScanned} files. ${critical > 0 ? `${critical} critical vulnerabilities require immediate remediation before deployment.` : 'No critical issues detected, but high-severity findings should be addressed promptly.'}`,
    prioritizedActions: [
      ...(critical > 0 ? ['Immediately address all CRITICAL findings — these represent active exploitation risk'] : []),
      ...(high > 0 ? ['Remediate HIGH-severity injection and authentication issues within this sprint'] : []),
      'Rotate any exposed credentials and move to environment variables',
      'Implement parameterized queries across all database interactions',
      'Add SAST scanning to CI/CD pipeline to prevent regression',
    ].slice(0, 5),
    riskNarrative: `This codebase has a ${critical > 0 ? 'high' : 'moderate'} risk profile. The primary concerns are ${Array.from(new Set(activeFindings.map(f => f.category))).slice(0, 3).join(', ')} vulnerabilities. ${critical > 0 ? 'Without remediation, the application is vulnerable to automated attacks that could lead to data breach.' : 'The identified issues should be addressed as part of normal development workflow.'}`,
    complianceNotes: `Findings impact PCI-DSS 6.2 (secure development), SOC2 CC6.1 (access controls), and OWASP ASVS requirements. ${critical > 0 ? 'Current state would not pass a compliance audit.' : 'Most compliance frameworks would require documented remediation plans for the identified issues.'}`,
    estimatedEffort: `${critical + high > 10 ? '5-8' : critical + high > 5 ? '3-5' : '1-3'} developer-days for full remediation. Critical items can be addressed in ${critical > 5 ? '2-3 days' : '1 day'}.`,
  }
}
