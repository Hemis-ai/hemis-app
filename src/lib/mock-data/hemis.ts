import type { MitreTechnique, AttackChainStep, SimulationResult, MitreTactic } from '@/lib/types'

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  // Reconnaissance
  { id:'T1595', name:'Active Scanning',            tactic:'Reconnaissance',          status:'tested'     },
  { id:'T1590', name:'Gather Victim Network Info', tactic:'Reconnaissance',          status:'mitigated'  },
  { id:'T1589', name:'Gather Victim Identity Info',tactic:'Reconnaissance',          status:'tested'     },
  // Initial Access
  { id:'T1190', name:'Exploit Public-Facing App',  tactic:'Initial Access',          status:'vulnerable' },
  { id:'T1078', name:'Valid Accounts',             tactic:'Initial Access',          status:'vulnerable' },
  { id:'T1566', name:'Phishing',                   tactic:'Initial Access',          status:'mitigated'  },
  { id:'T1133', name:'External Remote Services',   tactic:'Initial Access',          status:'tested'     },
  // Execution
  { id:'T1059', name:'Command & Scripting Interpreter', tactic:'Execution',          status:'tested'     },
  { id:'T1203', name:'Exploitation for Execution', tactic:'Execution',               status:'untested'   },
  { id:'T1072', name:'Software Deployment Tools',  tactic:'Execution',               status:'mitigated'  },
  // Persistence
  { id:'T1136', name:'Create Account',             tactic:'Persistence',             status:'tested'     },
  { id:'T1098', name:'Account Manipulation',       tactic:'Persistence',             status:'vulnerable' },
  { id:'T1053', name:'Scheduled Task/Job',         tactic:'Persistence',             status:'mitigated'  },
  // Privilege Escalation
  { id:'T1068', name:'Exploitation for Privilege Escalation', tactic:'Privilege Escalation', status:'vulnerable' },
  { id:'T1078', name:'Valid Accounts (Priv Esc)',  tactic:'Privilege Escalation',    status:'vulnerable' },
  { id:'T1548', name:'Abuse Elevation Control',    tactic:'Privilege Escalation',    status:'untested'   },
  // Defense Evasion
  { id:'T1562', name:'Impair Defenses',            tactic:'Defense Evasion',         status:'tested'     },
  { id:'T1070', name:'Indicator Removal',          tactic:'Defense Evasion',         status:'mitigated'  },
  { id:'T1036', name:'Masquerading',               tactic:'Defense Evasion',         status:'untested'   },
  // Credential Access
  { id:'T1552', name:'Unsecured Credentials',      tactic:'Credential Access',       status:'vulnerable' },
  { id:'T1110', name:'Brute Force',                tactic:'Credential Access',       status:'mitigated'  },
  { id:'T1555', name:'Credentials from Password Stores', tactic:'Credential Access', status:'untested'  },
  // Discovery
  { id:'T1069', name:'Permission Groups Discovery',tactic:'Discovery',               status:'tested'     },
  { id:'T1082', name:'System Information Discovery',tactic:'Discovery',              status:'tested'     },
  { id:'T1083', name:'File and Directory Discovery',tactic:'Discovery',              status:'mitigated'  },
  // Lateral Movement
  { id:'T1021', name:'Remote Services',            tactic:'Lateral Movement',        status:'tested'     },
  { id:'T1534', name:'Internal Spearphishing',     tactic:'Lateral Movement',        status:'untested'   },
  // Collection
  { id:'T1530', name:'Data from Cloud Storage',    tactic:'Collection',              status:'vulnerable' },
  { id:'T1213', name:'Data from Info Repositories',tactic:'Collection',              status:'untested'   },
  // Command and Control
  { id:'T1071', name:'App Layer Protocol',         tactic:'Command and Control',     status:'mitigated'  },
  { id:'T1572', name:'Protocol Tunneling',         tactic:'Command and Control',     status:'untested'   },
  // Exfiltration
  { id:'T1041', name:'Exfil Over C2 Channel',      tactic:'Exfiltration',            status:'tested'     },
  { id:'T1537', name:'Transfer to Cloud Account',  tactic:'Exfiltration',            status:'vulnerable' },
  // Impact
  { id:'T1485', name:'Data Destruction',           tactic:'Impact',                  status:'mitigated'  },
  { id:'T1486', name:'Data Encrypted for Impact',  tactic:'Impact',                  status:'untested'   },
]

export const PRELOADED_CHAIN: AttackChainStep[] = [
  { seq:1,  timestamp:'10:04:12', phase:'Reconnaissance',      techniqueId:'T1595', technique:'Active Scanning',              target:'api.acme-corp.com',               result:'SUCCESS', detail:'Identified 14 open ports. Services: nginx/1.22, PostgreSQL, Redis (unauthenticated).' },
  { seq:2,  timestamp:'10:04:31', phase:'Reconnaissance',      techniqueId:'T1589', technique:'Gather Victim Identity Info',  target:'LinkedIn / GitHub OSINT',         result:'SUCCESS', detail:'Found 3 developer GitHub accounts. Identified AWS region "us-east-1" from public S3 URLs in codebase.' },
  { seq:3,  timestamp:'10:05:08', phase:'Initial Access',      techniqueId:'T1190', technique:'Exploit Public-Facing App',    target:'api.acme-corp.com/v1/login',       result:'SUCCESS', detail:'SQL injection in /v1/login email parameter. Extracted 2 admin password hashes.' },
  { seq:4,  timestamp:'10:05:44', phase:'Credential Access',   techniqueId:'T1552', technique:'Unsecured Credentials',        target:'.env file in S3 bucket',          result:'SUCCESS', detail:'Public S3 bucket contained .env file with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.' },
  { seq:5,  timestamp:'10:06:02', phase:'Privilege Escalation',techniqueId:'T1078', technique:'Valid Accounts (Priv Esc)',    target:'IAM user deploy-bot',             result:'SUCCESS', detail:'Credential pair valid. User has AdministratorAccess policy. Full AWS account compromise.' },
  { seq:6,  timestamp:'10:06:18', phase:'Discovery',           techniqueId:'T1069', technique:'Permission Groups Discovery',  target:'AWS IAM',                         result:'SUCCESS', detail:'Enumerated 47 IAM users, 12 roles, 8 groups. Identified 3 other high-privilege accounts.' },
  { seq:7,  timestamp:'10:06:55', phase:'Collection',          techniqueId:'T1530', technique:'Data from Cloud Storage',      target:'S3 prod-customer-backups',        result:'SUCCESS', detail:'Accessed and staged 4.2 GB of customer PII data across 847 files.' },
  { seq:8,  timestamp:'10:07:33', phase:'Exfiltration',        techniqueId:'T1537', technique:'Transfer to Cloud Account',    target:'External S3 bucket (attacker)',   result:'SUCCESS', detail:'Exfiltrated 4.2 GB. Total attack duration: 3m 21s from initial access to data exfil.' },
]

export const PRELOADED_SIMULATION: SimulationResult = {
  id:        'sim-20260313-042',
  prompt:    'Simulate an external attacker targeting our production API and AWS environment',
  startedAt: '2026-03-13T10:04:10Z',
  duration:  '3m 21s',
  steps:     PRELOADED_CHAIN,
  findings:  8,
  criticals: 3,
  techniques: MITRE_TECHNIQUES,
}

export const TACTICS_ORDER: MitreTactic[] = [
  'Reconnaissance','Resource Development','Initial Access','Execution',
  'Persistence','Privilege Escalation','Defense Evasion','Credential Access',
  'Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact',
]
