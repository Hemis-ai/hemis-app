import type { CvssInput, CvssResult, Severity, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, ImpactMetric } from '../../types'

const AV_WEIGHTS: Record<AttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 }
const AC_WEIGHTS: Record<AttackComplexity, number> = { L: 0.77, H: 0.44 }
const PR_WEIGHTS_UNCHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 }
const PR_WEIGHTS_CHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.50 }
const UI_WEIGHTS: Record<UserInteraction, number> = { N: 0.85, R: 0.62 }
const IMPACT_WEIGHTS: Record<ImpactMetric, number> = { H: 0.56, L: 0.22, N: 0.00 }

export function calculateCvss(input: CvssInput): CvssResult {
  const { AV, AC, PR, UI, S, C, I, A } = input
  const iss = 1 - (1 - IMPACT_WEIGHTS[C]) * (1 - IMPACT_WEIGHTS[I]) * (1 - IMPACT_WEIGHTS[A])
  let impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  if (impact <= 0) return { score: 0.0, vector: formatVector(input), severity: 'INFO' }
  const prWeight = S === 'U' ? PR_WEIGHTS_UNCHANGED[PR] : PR_WEIGHTS_CHANGED[PR]
  const exploitability = 8.22 * AV_WEIGHTS[AV] * AC_WEIGHTS[AC] * prWeight * UI_WEIGHTS[UI]
  const score = S === 'U'
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10))
  return { score, vector: formatVector(input), severity: cvssToSeverity(score) }
}

function roundUp(value: number): number { return Math.ceil(value * 10) / 10 }

export function cvssToSeverity(score: number): Severity {
  if (score === 0.0) return 'INFO'
  if (score <= 3.9) return 'LOW'
  if (score <= 6.9) return 'MEDIUM'
  if (score <= 8.9) return 'HIGH'
  return 'CRITICAL'
}

function formatVector(input: CvssInput): string {
  return `CVSS:3.1/AV:${input.AV}/AC:${input.AC}/PR:${input.PR}/UI:${input.UI}/S:${input.S}/C:${input.C}/I:${input.I}/A:${input.A}`
}

export const PRESET_VECTORS: Record<string, CvssInput> = {
  sql_injection:          { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  command_injection:      { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  xxe:                    { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  ssrf:                   { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'N', A: 'N' },
  directory_traversal:    { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  xss_reflected:          { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  csrf:                   { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'H', A: 'N' },
  open_redirect:          { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  weak_tls:               { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  xss_stored:             { AV: 'N', AC: 'L', PR: 'L', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  information_disclosure: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  insecure_cookie:        { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  missing_csp:            { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'L', A: 'N' },
}
