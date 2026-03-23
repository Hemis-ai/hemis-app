'use client'

import type { DastFinding } from '@/lib/types'

interface MitreAttackMatrixProps {
  findings: DastFinding[]
}

const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', techniques: ['T1595', 'T1592', 'T1589'] },
  { id: 'TA0042', name: 'Resource Dev', techniques: ['T1583', 'T1584', 'T1587'] },
  { id: 'TA0001', name: 'Initial Access', techniques: ['T1190', 'T1189', 'T1566'] },
  { id: 'TA0002', name: 'Execution', techniques: ['T1059', 'T1203', 'T1047'] },
  { id: 'TA0003', name: 'Persistence', techniques: ['T1505', 'T1136', 'T1098'] },
  { id: 'TA0004', name: 'Priv Escalation', techniques: ['T1068', 'T1548', 'T1134'] },
  { id: 'TA0005', name: 'Defense Evasion', techniques: ['T1027', 'T1070', 'T1562'] },
  { id: 'TA0006', name: 'Credential Access', techniques: ['T1110', 'T1003', 'T1558'] },
  { id: 'TA0007', name: 'Discovery', techniques: ['T1046', 'T1087', 'T1518'] },
  { id: 'TA0008', name: 'Lateral Movement', techniques: ['T1021', 'T1563', 'T1080'] },
  { id: 'TA0009', name: 'Collection', techniques: ['T1005', 'T1039', 'T1114'] },
  { id: 'TA0011', name: 'C2', techniques: ['T1071', 'T1105', 'T1573'] },
  { id: 'TA0010', name: 'Exfiltration', techniques: ['T1041', 'T1048', 'T1567'] },
  { id: 'TA0040', name: 'Impact', techniques: ['T1486', 'T1490', 'T1499'] },
]

const TECHNIQUE_NAMES: Record<string, string> = {
  T1595: 'Active Scanning', T1592: 'Gather Info', T1589: 'Gather Creds',
  T1583: 'Acquire Infra', T1584: 'Compromise Infra', T1587: 'Develop Capabilities',
  T1190: 'Exploit Public App', T1189: 'Drive-by', T1566: 'Phishing',
  T1059: 'Script Execution', T1203: 'Exploit for Exec', T1047: 'WMI',
  T1505: 'Server Software', T1136: 'Create Account', T1098: 'Account Manip',
  T1068: 'Exploitation', T1548: 'Abuse Elevation', T1134: 'Access Token',
  T1027: 'Obfuscation', T1070: 'Indicator Removal', T1562: 'Impair Defenses',
  T1110: 'Brute Force', T1003: 'Credential Dumping', T1558: 'Kerberoast',
  T1046: 'Network Scan', T1087: 'Account Discovery', T1518: 'Software Discovery',
  T1021: 'Remote Services', T1563: 'Remote Session', T1080: 'Taint Content',
  T1005: 'Local Data', T1039: 'Network Data', T1114: 'Email Collection',
  T1071: 'App Layer Proto', T1105: 'Ingress Tool', T1573: 'Encrypted Channel',
  T1041: 'Exfil via C2', T1048: 'Exfil via Alt Proto', T1567: 'Exfil to Cloud',
  T1486: 'Data Encrypted', T1490: 'Inhibit Recovery', T1499: 'Endpoint DoS',
}

export default function MitreAttackMatrix({ findings }: MitreAttackMatrixProps) {
  // Collect all MITRE ATT&CK IDs from findings
  const foundTechniques = new Set<string>()
  const techniqueFindings = new Map<string, { count: number; highest: string }>()

  for (const f of findings) {
    if (f.mitreAttackIds) {
      for (const id of f.mitreAttackIds) {
        foundTechniques.add(id)
        const existing = techniqueFindings.get(id)
        if (existing) {
          existing.count++
          const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
          if (sevOrder.indexOf(f.severity) < sevOrder.indexOf(existing.highest)) {
            existing.highest = f.severity
          }
        } else {
          techniqueFindings.set(id, { count: 1, highest: f.severity })
        }
      }
    }
  }

  const sevColors: Record<string, string> = {
    CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280',
  }

  return (
    <div style={{ marginBottom: 20 }}>
      <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', marginBottom: 10 }}>
        MITRE ATT&CK MATRIX &mdash; {foundTechniques.size} TECHNIQUES DETECTED
      </div>
      <div style={{ overflowX: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: `repeat(${TACTICS.length}, minmax(75px, 1fr))`, gap: 3, minWidth: 900 }}>
          {/* Header row */}
          {TACTICS.map(tactic => (
            <div key={tactic.id} style={{
              padding: '6px 4px', textAlign: 'center',
              background: 'var(--color-bg-secondary)', borderRadius: 4,
              borderBottom: '2px solid var(--color-dast)',
            }}>
              <div className="mono" style={{ fontSize: 7, fontWeight: 700, color: 'var(--color-dast)', letterSpacing: '0.08em' }}>
                {tactic.name.toUpperCase()}
              </div>
            </div>
          ))}
          {/* Technique cells — 3 rows */}
          {[0, 1, 2].map(row => (
            TACTICS.map(tactic => {
              const techId = tactic.techniques[row]
              const match = techniqueFindings.get(techId)
              const isFound = foundTechniques.has(techId)
              return (
                <div key={`${tactic.id}-${row}`} style={{
                  padding: '4px 3px', textAlign: 'center', borderRadius: 3,
                  background: isFound ? `${sevColors[match?.highest || 'INFO']}25` : 'transparent',
                  border: isFound ? `1px solid ${sevColors[match?.highest || 'INFO']}50` : '1px solid var(--color-border)',
                  minHeight: 32, display: 'flex', flexDirection: 'column', justifyContent: 'center',
                }}>
                  <div className="mono" style={{
                    fontSize: 7, color: isFound ? sevColors[match?.highest || 'INFO'] : 'var(--color-text-secondary)',
                    fontWeight: isFound ? 700 : 400, lineHeight: 1.2,
                  }}>
                    {TECHNIQUE_NAMES[techId] || techId}
                  </div>
                  {match && (
                    <div className="mono" style={{ fontSize: 8, fontWeight: 800, color: sevColors[match.highest], marginTop: 2 }}>
                      {match.count}
                    </div>
                  )}
                </div>
              )
            })
          ))}
        </div>
      </div>
    </div>
  )
}
