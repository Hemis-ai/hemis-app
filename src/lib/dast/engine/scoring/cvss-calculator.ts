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
  // ─── Critical: Remote Code Execution / Full Compromise ─────────────────
  sql_injection:              { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  sql_injection_mysql:        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  sql_injection_postgres:     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  sql_injection_oracle:       { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  sql_injection_mssql:        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  sql_injection_sqlite:       { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  sql_injection_hypersonic:   { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  sql_injection_advanced:     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  command_injection:          { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  server_side_code_injection: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  ssti:                       { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  expression_language_injection: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  log4shell:                  { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' },
  shellshock:                 { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },

  // ─── High: Data Exfiltration / Significant Impact ──────────────────────
  xxe:                        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  ssrf:                       { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'N', A: 'N' },
  directory_traversal:        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  xpath_injection:            { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  xslt_injection:             { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  server_side_include:        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  session_fixation:           { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'H', A: 'N' },
  csrf:                       { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'H', A: 'N' },
  idor:                       { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  broken_access_control:      { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  bypassing_403:              { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  source_code_disclosure:     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  backup_file_disclosure:     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  spring_actuator:            { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  cloud_metadata:             { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'N', A: 'N' },
  jwt_vulnerability:          { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },

  // ─── Medium: Client-Side / Conditional Impact ──────────────────────────
  xss_reflected:              { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  xss_stored:                 { AV: 'N', AC: 'L', PR: 'L', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  xss_dom:                    { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  xss_persistent:             { AV: 'N', AC: 'L', PR: 'L', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  open_redirect:              { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  crlf_injection:             { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'N', I: 'L', A: 'N' },
  parameter_tampering:        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'N' },
  cross_site_method_tampering:{ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'L', A: 'N' },
  http_parameter_override:    { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'N' },
  weak_tls:                   { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  weak_authentication:        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
  get_for_post:               { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  vulnerable_js_library:      { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
  http_only_site:             { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'N', A: 'N' },
  https_content_via_http:     { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },

  // ─── Low: Informational / Hardening ────────────────────────────────────
  information_disclosure:     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  pii_disclosure:             { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  insecure_cookie:            { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  missing_httponly:            { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  missing_secure_flag:        { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  missing_samesite:           { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  missing_csp:                { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'L', A: 'N' },
  missing_hsts:               { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  missing_anti_clickjacking:  { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'L', A: 'N' },
  missing_x_content_type_options: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'L', A: 'N' },
  content_cacheability:       { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  hidden_file:                { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  trace_method:               { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  insecure_http_method:       { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'N' },

  // ─── Authentication & Session Security ────────────────────────────────
  session_timeout:            { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
  token_reuse:                { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  oauth2_misconfiguration:    { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  insecure_session_cookie:    { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'N', A: 'N' },
  csrf_on_auth:               { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'H', A: 'N' },
  auth_bypass:                { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  credential_stuffing:        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  brute_force:                { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  insufficient_session_expiry:{ AV: 'N', AC: 'H', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  cookie_without_expiry:      { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
}
