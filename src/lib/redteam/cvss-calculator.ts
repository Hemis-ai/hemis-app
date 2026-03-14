/**
 * CVSS v3.1 Score Calculator
 * Simplified calculator for base score estimation
 */

export interface CVSSParams {
  attackVector: 'NETWORK' | 'ADJACENT_NETWORK' | 'LOCAL' | 'PHYSICAL'
  complexity: 'LOW' | 'HIGH'
  privileges: 'NONE' | 'LOW' | 'HIGH'
  interaction: 'NONE' | 'REQUIRED'
  confidentiality: 'NONE' | 'LOW' | 'HIGH'
  integrity: 'NONE' | 'LOW' | 'HIGH'
  availability: 'NONE' | 'LOW' | 'HIGH'
}

export interface CVSSScore {
  score: number
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  vector: string
}

/**
 * Calculate CVSS v3.1 Base Score
 * Implements simplified CVSS v3.1 scoring
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 */
export function calculateCVSS(params: Partial<CVSSParams>): CVSSScore {
  // Default to moderate severity if incomplete params
  const p: CVSSParams = {
    attackVector: params.attackVector || 'NETWORK',
    complexity: params.complexity || 'LOW',
    privileges: params.privileges || 'NONE',
    interaction: params.interaction || 'NONE',
    confidentiality: params.confidentiality || 'NONE',
    integrity: params.integrity || 'NONE',
    availability: params.availability || 'NONE',
  }

  // Assign metric values
  const av = { NETWORK: 0.85, ADJACENT_NETWORK: 0.62, LOCAL: 0.55, PHYSICAL: 0.2 }[p.attackVector]
  const ac = { LOW: 0.77, HIGH: 0.44 }[p.complexity]
  const au = { NONE: 0.85, LOW: 0.62, HIGH: 0.27 }[p.privileges]
  const ui = { NONE: 0.85, REQUIRED: 0.62 }[p.interaction]

  // Impact metrics
  const c = { NONE: 0, LOW: 0.22, HIGH: 0.56 }[p.confidentiality]
  const i = { NONE: 0, LOW: 0.22, HIGH: 0.56 }[p.integrity]
  const a = { NONE: 0, LOW: 0.22, HIGH: 0.56 }[p.availability]

  // Calculate impact
  const impact = 1 - (1 - c) * (1 - i) * (1 - a)

  // Calculate exploitability
  const exploitability = 8.22 * av * ac * au * ui

  // Calculate base score
  const baseScore = impact === 0 ? 0 : Math.min(10, (impact + exploitability) * 1.08)

  // Round to single decimal
  const score = Math.round(baseScore * 10) / 10

  // Determine severity
  const severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' =
    score >= 9.0 ? 'CRITICAL'
    : score >= 7.0 ? 'HIGH'
    : score >= 4.0 ? 'MEDIUM'
    : score > 0 ? 'LOW'
    : 'NONE'

  // Build vector string
  const vector = `CVSS:3.1/AV:${p.attackVector[0]}/AC:${p.complexity[0]}/PR:${p.privileges[0]}/UI:${p.interaction[0]}/S:U/C:${p.confidentiality[0]}/I:${p.integrity[0]}/A:${p.availability[0]}`

  return { score, severity, vector }
}

/**
 * Quick CVSS score estimation based on vulnerability type
 * Used for mock data generation
 */
export function estimateCVSSByType(vulnType: string): CVSSScore {
  const typeScores: Record<string, Partial<CVSSParams>> = {
    sql_injection: {
      attackVector: 'NETWORK',
      complexity: 'LOW',
      privileges: 'NONE',
      interaction: 'NONE',
      confidentiality: 'HIGH',
      integrity: 'HIGH',
      availability: 'HIGH',
    },
    xss: {
      attackVector: 'NETWORK',
      complexity: 'LOW',
      privileges: 'NONE',
      interaction: 'REQUIRED',
      confidentiality: 'LOW',
      integrity: 'LOW',
      availability: 'NONE',
    },
    command_injection: {
      attackVector: 'NETWORK',
      complexity: 'LOW',
      privileges: 'NONE',
      interaction: 'NONE',
      confidentiality: 'HIGH',
      integrity: 'HIGH',
      availability: 'HIGH',
    },
    path_traversal: {
      attackVector: 'NETWORK',
      complexity: 'LOW',
      privileges: 'NONE',
      interaction: 'NONE',
      confidentiality: 'HIGH',
      integrity: 'NONE',
      availability: 'NONE',
    },
    ssrf: {
      attackVector: 'NETWORK',
      complexity: 'LOW',
      privileges: 'NONE',
      interaction: 'NONE',
      confidentiality: 'HIGH',
      integrity: 'LOW',
      availability: 'LOW',
    },
    auth_bypass: {
      attackVector: 'NETWORK',
      complexity: 'LOW',
      privileges: 'NONE',
      interaction: 'NONE',
      confidentiality: 'HIGH',
      integrity: 'HIGH',
      availability: 'NONE',
    },
    privilege_escalation: {
      attackVector: 'NETWORK',
      complexity: 'LOW',
      privileges: 'LOW',
      interaction: 'NONE',
      confidentiality: 'HIGH',
      integrity: 'HIGH',
      availability: 'HIGH',
    },
    weak_encryption: {
      attackVector: 'NETWORK',
      complexity: 'HIGH',
      privileges: 'NONE',
      interaction: 'NONE',
      confidentiality: 'HIGH',
      integrity: 'NONE',
      availability: 'NONE',
    },
  }

  const params = typeScores[vulnType.toLowerCase()] || typeScores.sql_injection
  return calculateCVSS(params)
}
