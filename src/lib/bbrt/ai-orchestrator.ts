// src/lib/bbrt/ai-orchestrator.ts
// Claude Opus 4.6 AI Orchestrator for BBRT
// Handles: attack plan generation, kill chain narratives, vulnerability correlation, business impact assessment
import { ClaudeClient } from '@/lib/dast/ai/claude-client'
import type {
  BbrtReconResult,
  BbrtAttackSurface,
  BbrtFinding,
  BbrtKillChain,
  BbrtKillChainStep,
  BbrtTargetConfig,
} from '@/lib/types/bbrt'
import type { MitreAttackMapping } from '@/lib/types/wbrt'

// Use Claude Opus 4.6 for the orchestrator (most capable model for attack reasoning)
const orchestratorClient = new ClaudeClient('claude-opus-4-6')
// Use Claude Sonnet for lighter tasks (report writing, impact assessment)
const sonnetClient = new ClaudeClient(process.env.CLAUDE_MODEL || 'claude-sonnet-4-6')

// ─── JSON Validator Helper ──────────────────────────────────────────────────
function jsonValidator<T>(response: string): { valid: boolean; data?: T; error?: string } {
  try {
    // Extract JSON from markdown code blocks if present
    const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)```/) || [null, response]
    const cleaned = (jsonMatch[1] || response).trim()
    const data = JSON.parse(cleaned) as T
    return { valid: true, data }
  } catch (e) {
    return { valid: false, error: `JSON parse failed: ${(e as Error).message}` }
  }
}

// ─── Attack Plan Generation ─────────────────────────────────────────────────

export interface AttackPlan {
  phases: Array<{
    name: string
    priority: number
    techniques: string[]
    targets: string[]
    rationale: string
  }>
  highValueTargets: string[]
  estimatedComplexity: 'LOW' | 'MEDIUM' | 'HIGH'
}

export async function generateAttackPlan(
  config: BbrtTargetConfig,
  recon: BbrtReconResult,
): Promise<AttackPlan | null> {
  const systemPrompt = `You are an expert penetration tester and red team operator. You are conducting an authorized black-box red team engagement. Given reconnaissance data about a target, generate a structured attack plan.

Your response must be valid JSON matching this schema:
{
  "phases": [{ "name": string, "priority": number, "techniques": string[], "targets": string[], "rationale": string }],
  "highValueTargets": string[],
  "estimatedComplexity": "LOW" | "MEDIUM" | "HIGH"
}

Focus on realistic attack paths. Prioritize by impact and exploitability. Include MITRE ATT&CK technique names where relevant.`

  const userPrompt = `Target: ${config.targetDomain}
Engagement Type: ${config.engagementType}
Industry: ${config.businessContext.industry}

Reconnaissance Summary:
- Subdomains discovered: ${recon.subdomains.length} (${recon.subdomains.filter(s => s.isShadowAsset).length} shadow assets)
- Open ports: ${recon.openPorts.length} across ${new Set(recon.openPorts.map(p => p.host)).size} hosts
- Technology stack: ${recon.techStack.map(t => t.name).join(', ')}
- OSINT findings: ${recon.osintFindings.length} (types: ${recon.osintFindings.map(o => o.type).join(', ')})
- Cloud assets: ${recon.cloudAssets.length} (${recon.cloudAssets.filter(c => c.isPublic).length} public)
- TLS issues: ${recon.tlsCertificates.flatMap(c => c.issues).length}
- Email addresses: ${recon.emailAddresses.length}

High-risk subdomains: ${recon.subdomains.filter(s => s.riskScore > 60).map(s => `${s.subdomain} (risk: ${s.riskScore})`).join(', ')}

Generate an attack plan with 4-6 phases, prioritized by likelihood of success and impact.`

  return orchestratorClient.callClaude<AttackPlan>(
    systemPrompt,
    userPrompt,
    jsonValidator,
    { maxTokens: 3000, temperature: 0.3 },
  )
}

// ─── Kill Chain Narrative Generation ────────────────────────────────────────

export async function generateKillChainNarrative(
  chain: BbrtKillChain,
  config: BbrtTargetConfig,
): Promise<string> {
  const systemPrompt = `You are a senior red team operator writing a report for executive leadership. Given a kill chain (sequence of attack steps), write a compelling 2-3 paragraph narrative that explains:
1. How an attacker would discover and exploit this path
2. What data/systems would be compromised
3. The business impact in concrete terms

Write in professional prose, not bullet points. Use specific technical details from the steps but make it accessible to non-technical executives. Do NOT use markdown formatting — write plain text paragraphs.`

  const userPrompt = `Target: ${config.targetDomain}
Industry: ${config.businessContext.industry}
Kill Chain: ${chain.name}
Objective: ${chain.objective}

Steps:
${chain.steps.map(s => `${s.seq}. [${s.tactic}] ${s.technique}: ${s.action} → ${s.result}`).join('\n')}

Affected assets: ${chain.affectedAssets.join(', ')}
Data at risk: ${chain.dataAtRisk.join(', ')}
Estimated time to exploit: ${chain.estimatedTimeToExploit}
Detection difficulty: ${chain.detectionDifficulty}`

  const result = await sonnetClient.callClaude<string>(
    systemPrompt,
    userPrompt,
    (response) => ({ valid: true, data: response.trim() }),
    { maxTokens: 1000, temperature: 0.5 },
  )

  return result || chain.objective // Fallback to objective if AI fails
}

// ─── Vulnerability Correlation ──────────────────────────────────────────────

export interface VulnCorrelation {
  chainableFindings: Array<{
    findingIds: string[]
    chainDescription: string
    combinedImpact: string
    likelihood: 'VERY_HIGH' | 'HIGH' | 'MEDIUM' | 'LOW'
  }>
}

export async function correlateVulnerabilities(
  findings: BbrtFinding[],
  surface: BbrtAttackSurface,
): Promise<VulnCorrelation | null> {
  if (findings.length < 2) return null

  const systemPrompt = `You are an expert penetration tester. Given a list of discovered vulnerabilities and an attack surface, identify which vulnerabilities can be chained together for greater impact.

Return valid JSON:
{
  "chainableFindings": [{
    "findingIds": string[],
    "chainDescription": string,
    "combinedImpact": string,
    "likelihood": "VERY_HIGH" | "HIGH" | "MEDIUM" | "LOW"
  }]
}`

  const userPrompt = `Findings:
${findings.map(f => `- [${f.id}] ${f.title} (${f.severity}, affects: ${f.affectedAssetLabel})`).join('\n')}

Attack Surface:
- Entry points: ${surface.entryPoints.length}
- Crown jewels: ${surface.crownJewels.length}
- Total assets: ${surface.totalAssets}

Which findings can be chained together? Focus on realistic attack paths from entry points to crown jewels.`

  return orchestratorClient.callClaude<VulnCorrelation>(
    systemPrompt,
    userPrompt,
    jsonValidator,
    { maxTokens: 2000, temperature: 0.3 },
  )
}

// ─── Executive Summary Generation ───────────────────────────────────────────

export async function generateExecutiveSummary(
  config: BbrtTargetConfig,
  findings: BbrtFinding[],
  killChains: BbrtKillChain[],
  riskScore: number,
): Promise<string> {
  const systemPrompt = `You are a senior cybersecurity consultant writing an executive summary for a black-box red team engagement report. Write 3-4 paragraphs in markdown format that:
1. Summarize the engagement scope and methodology
2. Highlight the most critical findings and their business impact
3. Describe the most dangerous attack chains discovered
4. Provide a strategic recommendation

Be specific with numbers and severity levels. Write for a CISO audience.`

  const userPrompt = `Target: ${config.targetDomain}
Industry: ${config.businessContext.industry}
Overall Risk Score: ${riskScore}/100

Findings: ${findings.length} total
- Critical: ${findings.filter(f => f.severity === 'CRITICAL').length}
- High: ${findings.filter(f => f.severity === 'HIGH').length}
- Medium: ${findings.filter(f => f.severity === 'MEDIUM').length}
- Low: ${findings.filter(f => f.severity === 'LOW').length}

Top findings:
${findings.slice(0, 5).map(f => `- [${f.severity}] ${f.title}: ${f.description.slice(0, 150)}...`).join('\n')}

Kill Chains: ${killChains.length} discovered
${killChains.map(kc => `- [${kc.impact}] ${kc.name}: ${kc.objective}`).join('\n')}

Compliance requirements: ${config.complianceRequirements.join(', ')}`

  const result = await sonnetClient.callClaude<string>(
    systemPrompt,
    userPrompt,
    (response) => ({ valid: true, data: response.trim() }),
    { maxTokens: 1500, temperature: 0.5 },
  )

  return result || buildFallbackSummary(config, findings, killChains, riskScore)
}

// ─── AI Insights Generation ─────────────────────────────────────────────────

export async function generateAiInsights(
  config: BbrtTargetConfig,
  findings: BbrtFinding[],
  killChains: BbrtKillChain[],
  surface: BbrtAttackSurface,
): Promise<string> {
  const systemPrompt = `You are a threat intelligence analyst. Based on the results of a black-box red team engagement, provide strategic threat intelligence insights in 2-3 paragraphs. Focus on:
1. What this attack surface tells you about the organization's security maturity
2. How a real APT group would likely approach this target
3. What the organization should prioritize in the next 90 days

Write in professional prose for a CISO audience. Do not use bullet points.`

  const userPrompt = `Target: ${config.targetDomain} (${config.businessContext.industry})
Exposure Score: ${surface.exposureScore}/100
Shadow Assets: ${surface.shadowAssets.length}
Critical Findings: ${findings.filter(f => f.severity === 'CRITICAL').length}
Kill Chains: ${killChains.length}
Top vulnerability types: ${[...new Set(findings.map(f => f.type))].join(', ')}
OSINT exposure: credential leaks, API keys, internal URLs`

  const result = await sonnetClient.callClaude<string>(
    systemPrompt,
    userPrompt,
    (response) => ({ valid: true, data: response.trim() }),
    { maxTokens: 1000, temperature: 0.5 },
  )

  return result || 'AI insights generation was not available for this engagement. Review findings and kill chains for strategic threat assessment.'
}

// ─── Fallback Summary (when AI is unavailable) ─────────────────────────────

function buildFallbackSummary(
  config: BbrtTargetConfig,
  findings: BbrtFinding[],
  killChains: BbrtKillChain[],
  riskScore: number,
): string {
  const critical = findings.filter(f => f.severity === 'CRITICAL').length
  const high = findings.filter(f => f.severity === 'HIGH').length
  const riskLevel = riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High' : riskScore >= 40 ? 'Medium' : 'Low'

  return `## Executive Summary

A black-box red team engagement was conducted against **${config.targetDomain}** simulating an external adversary with zero prior knowledge of the target infrastructure. The assessment identified **${findings.length} vulnerabilities** (${critical} critical, ${high} high) and mapped **${killChains.length} viable attack chains** from initial reconnaissance to potential data exfiltration.

The overall risk score of **${riskScore}/100 (${riskLevel})** reflects significant external exposure. ${critical > 0 ? `Critical findings include exposed CI/CD infrastructure with default credentials and leaked cloud API keys in public repositories, either of which could grant an attacker full access to production systems.` : 'High-severity findings indicate gaps in access control and configuration management that could be exploited in a targeted attack.'}

${killChains.length > 0 ? `The most concerning attack chain — "${killChains[0].name}" — demonstrates how an attacker could move from public OSINT discovery to full infrastructure compromise in an estimated ${killChains[0].estimatedTimeToExploit}.` : ''} Immediate remediation of critical findings is strongly recommended, followed by a structured hardening program addressing the ${config.complianceRequirements.length > 0 ? `${config.complianceRequirements.join(', ')} compliance gaps` : 'identified security gaps'} identified in this engagement.`
}
