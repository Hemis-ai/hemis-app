/**
 * MITRE ATT&CK Mapping for Common Vulnerability Types
 * Maps vulnerability types discovered by red team scans to MITRE ATT&CK techniques
 */

export interface MitreMapping {
  techniqueId: string
  tactic: string
  technique: string
  description: string
}

const MITRE_MAPPINGS: Record<string, MitreMapping> = {
  sql_injection: {
    techniqueId: 'T1190',
    tactic: 'Initial Access',
    technique: 'Exploit Public-Facing Application',
    description: 'SQL injection allows attackers to execute arbitrary database queries, often leading to unauthorized data access or authentication bypass.',
  },
  xss: {
    techniqueId: 'T1059',
    tactic: 'Execution',
    technique: 'Command & Scripting Interpreter',
    description: 'Cross-site scripting (XSS) enables execution of arbitrary JavaScript in victim browsers, potentially leading to credential theft or malware delivery.',
  },
  xss_reflected: {
    techniqueId: 'T1059',
    tactic: 'Execution',
    technique: 'Command & Scripting Interpreter',
    description: 'Reflected XSS vulnerability where user input is directly echoed in HTTP responses.',
  },
  xss_stored: {
    techniqueId: 'T1190',
    tactic: 'Initial Access',
    technique: 'Exploit Public-Facing Application',
    description: 'Stored XSS where malicious scripts persist in application data and execute for all users.',
  },
  command_injection: {
    techniqueId: 'T1059',
    tactic: 'Execution',
    technique: 'Command & Scripting Interpreter',
    description: 'Command injection allows execution of arbitrary system commands, enabling full system compromise.',
  },
  path_traversal: {
    techniqueId: 'T1083',
    tactic: 'Discovery',
    technique: 'File and Directory Discovery',
    description: 'Path traversal vulnerabilities enable unauthorized access to arbitrary files and directories on the target system.',
  },
  ssrf: {
    techniqueId: 'T1090',
    tactic: 'Lateral Movement',
    technique: 'Proxy',
    description: 'Server-side request forgery allows attackers to make requests from the target server to internal systems or cloud metadata services.',
  },
  auth_bypass: {
    techniqueId: 'T1078',
    tactic: 'Privilege Escalation',
    technique: 'Valid Accounts',
    description: 'Authentication bypass vulnerabilities allow unauthorized access without valid credentials.',
  },
  privilege_escalation: {
    techniqueId: 'T1068',
    tactic: 'Privilege Escalation',
    technique: 'Exploitation for Privilege Escalation',
    description: 'Privilege escalation vulnerabilities enable attackers to gain higher-level access and system control.',
  },
  weak_encryption: {
    techniqueId: 'T1110',
    tactic: 'Credential Access',
    technique: 'Brute Force',
    description: 'Weak encryption or hashing allows attackers to crack passwords and obtain credentials.',
  },
  exposed_aws_key: {
    techniqueId: 'T1552',
    tactic: 'Credential Access',
    technique: 'Unsecured Credentials',
    description: 'Exposed cloud credentials in public repositories or accessible storage enable full account compromise.',
  },
  insecure_deserialization: {
    techniqueId: 'T1190',
    tactic: 'Initial Access',
    technique: 'Exploit Public-Facing Application',
    description: 'Insecure deserialization vulnerabilities allow remote code execution through malicious serialized objects.',
  },
  default_credentials: {
    techniqueId: 'T1078',
    tactic: 'Initial Access',
    technique: 'Valid Accounts',
    description: 'Default credentials enable unauthorized access to applications and services without modification.',
  },
  information_disclosure: {
    techniqueId: 'T1590',
    tactic: 'Reconnaissance',
    technique: 'Gather Victim Network Information',
    description: 'Information disclosure vulnerabilities leak sensitive data that can be used for further attacks.',
  },
  missing_authentication: {
    techniqueId: 'T1078',
    tactic: 'Initial Access',
    technique: 'Valid Accounts',
    description: 'Missing authentication controls allow unauthenticated access to sensitive endpoints.',
  },
}

/**
 * Get MITRE ATT&CK mapping for a vulnerability type
 * @param vulnType - The vulnerability type (e.g., 'sql_injection', 'xss')
 * @returns MITRE mapping with technique ID, tactic, and description
 */
export function getMitreMapping(vulnType: string): MitreMapping {
  const normalized = vulnType.toLowerCase().replace(/[_-\s]+/g, '_')
  return (
    MITRE_MAPPINGS[normalized] || {
      techniqueId: 'T1190',
      tactic: 'Initial Access',
      technique: 'Exploit Public-Facing Application',
      description: 'Vulnerability allows unauthorized access or system compromise.',
    }
  )
}

/**
 * Get all available MITRE mappings
 */
export function getAllMitreMappings(): Record<string, MitreMapping> {
  return MITRE_MAPPINGS
}
