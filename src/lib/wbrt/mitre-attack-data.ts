// src/lib/wbrt/mitre-attack-data.ts

export interface MitreAttackEntry {
  tacticId: string
  tacticName: string
  techniqueId: string
  techniqueName: string
  subTechniqueId?: string
  subTechniqueName?: string
  description: string
  platforms: string[]
  dataSources: string[]
}

export const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
] as const

// Full ATT&CK matrix — techniques + sub-techniques relevant to web/cloud/code
// Organized by tactic for lookup efficiency
export const MITRE_ATTACK_MATRIX: MitreAttackEntry[] = [
  // ── TA0043: Reconnaissance ──
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', description: 'Actively scan target infrastructure to gather information', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.001', subTechniqueName: 'Scanning IP Blocks', description: 'Scan IP blocks to identify live hosts and services', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.002', subTechniqueName: 'Vulnerability Scanning', description: 'Scan for vulnerabilities in target systems', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.003', subTechniqueName: 'Wordlist Scanning', description: 'Use wordlists to discover hidden endpoints', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', description: 'Gather information about victim hosts', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', subTechniqueId: 'T1592.002', subTechniqueName: 'Software', description: 'Identify software and versions on targets', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1589', techniqueName: 'Gather Victim Identity Information', description: 'Gather identity details about victims', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1589', techniqueName: 'Gather Victim Identity Information', subTechniqueId: 'T1589.001', subTechniqueName: 'Credentials', description: 'Gather leaked or exposed credentials', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information', description: 'Gather network topology and configuration details', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information', subTechniqueId: 'T1590.005', subTechniqueName: 'IP Addresses', description: 'Discover IP addresses of target infrastructure', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  // ── TA0042: Resource Development ──
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', description: 'Acquire tools, exploits, or infrastructure', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.005', subTechniqueName: 'Exploits', description: 'Obtain exploits for identified vulnerabilities', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.006', subTechniqueName: 'Vulnerabilities', description: 'Research and identify zero-day or known vulnerabilities', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1587', techniqueName: 'Develop Capabilities', description: 'Develop custom attack tools and exploits', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1587', techniqueName: 'Develop Capabilities', subTechniqueId: 'T1587.001', subTechniqueName: 'Malware', description: 'Develop custom malware payloads', platforms: ['PRE'], dataSources: [] },

  // ── TA0001: Initial Access ──
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', description: 'Exploit vulnerabilities in internet-facing applications (SQLi, RCE, SSRF)', platforms: ['Linux', 'Windows', 'Containers', 'IaaS'], dataSources: ['Application Log', 'Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', description: 'Use compromised credentials for initial access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session', 'User Account'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.001', subTechniqueName: 'Default Accounts', description: 'Use default credentials left in production', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.004', subTechniqueName: 'Cloud Accounts', description: 'Use compromised cloud service credentials', platforms: ['IaaS', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1133', techniqueName: 'External Remote Services', description: 'Access via exposed remote services (SSH, RDP, VPN)', platforms: ['Linux', 'Windows'], dataSources: ['Logon Session', 'Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566', techniqueName: 'Phishing', description: 'Social engineering via phishing', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Application Log', 'Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566', techniqueName: 'Phishing', subTechniqueId: 'T1566.002', subTechniqueName: 'Spearphishing Link', description: 'Targeted phishing with malicious links', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', description: 'Compromise via trusted third-party software', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', subTechniqueId: 'T1195.001', subTechniqueName: 'Compromise Software Dependencies', description: 'Inject malicious code into package dependencies', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', subTechniqueId: 'T1195.002', subTechniqueName: 'Compromise Software Supply Chain', description: 'Compromise build or distribution pipeline', platforms: ['Linux', 'Windows'], dataSources: ['File'] },

  // ── TA0002: Execution ──
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', description: 'Execute commands via scripting interpreters', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', subTechniqueId: 'T1059.004', subTechniqueName: 'Unix Shell', description: 'Execute commands via bash/sh', platforms: ['Linux'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', subTechniqueId: 'T1059.006', subTechniqueName: 'Python', description: 'Execute Python scripts for post-exploitation', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', subTechniqueId: 'T1059.007', subTechniqueName: 'JavaScript', description: 'Execute JavaScript (Node.js, browser-based)', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1203', techniqueName: 'Exploitation for Client Execution', description: 'Exploit client-side vulnerabilities for code execution', platforms: ['Linux', 'Windows'], dataSources: ['Application Log', 'Process'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1610', techniqueName: 'Deploy Container', description: 'Deploy malicious container for execution', platforms: ['Containers'], dataSources: ['Container', 'Pod'] },
  { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1648', techniqueName: 'Serverless Execution', description: 'Execute code via serverless functions (Lambda, Cloud Functions)', platforms: ['IaaS', 'SaaS'], dataSources: ['Application Log', 'Cloud Service'] },

  // ── TA0003: Persistence ──
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1505', techniqueName: 'Server Software Component', description: 'Install persistent backdoor via server components', platforms: ['Linux', 'Windows'], dataSources: ['Application Log', 'File'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1505', techniqueName: 'Server Software Component', subTechniqueId: 'T1505.003', subTechniqueName: 'Web Shell', description: 'Deploy web shell for persistent access', platforms: ['Linux', 'Windows'], dataSources: ['Application Log', 'File'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098', techniqueName: 'Account Manipulation', description: 'Modify accounts to maintain access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098', techniqueName: 'Account Manipulation', subTechniqueId: 'T1098.001', subTechniqueName: 'Additional Cloud Credentials', description: 'Add cloud credentials for persistent access', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098', techniqueName: 'Account Manipulation', subTechniqueId: 'T1098.003', subTechniqueName: 'Additional Cloud Roles', description: 'Assign additional cloud roles', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1136', techniqueName: 'Create Account', description: 'Create new accounts for persistent access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1136', techniqueName: 'Create Account', subTechniqueId: 'T1136.003', subTechniqueName: 'Cloud Account', description: 'Create cloud IAM user or service account', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1078', techniqueName: 'Valid Accounts', description: 'Maintain access through valid credentials', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session'] },

  // ── TA0004: Privilege Escalation ──
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1068', techniqueName: 'Exploitation for Privilege Escalation', description: 'Exploit software vulnerability to escalate privileges', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['Process'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1078', techniqueName: 'Valid Accounts', description: 'Use valid accounts with elevated privileges', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.004', subTechniqueName: 'Cloud Accounts', description: 'Escalate via misconfigured cloud IAM', platforms: ['IaaS', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1611', techniqueName: 'Escape to Host', description: 'Escape container to access host system', platforms: ['Containers'], dataSources: ['Container', 'Process'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1548', techniqueName: 'Abuse Elevation Control Mechanism', description: 'Bypass OS privilege escalation controls', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'Process'] },
  { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1548', techniqueName: 'Abuse Elevation Control Mechanism', subTechniqueId: 'T1548.003', subTechniqueName: 'Sudo and Sudo Caching', description: 'Abuse sudo misconfigurations', platforms: ['Linux'], dataSources: ['Command'] },

  // ── TA0005: Defense Evasion ──
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal', description: 'Remove evidence of intrusion', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File', 'Process'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal', subTechniqueId: 'T1070.001', subTechniqueName: 'Clear Windows Event Logs', description: 'Clear event logs to hide activity', platforms: ['Windows'], dataSources: ['Process', 'Windows Registry'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal', subTechniqueId: 'T1070.002', subTechniqueName: 'Clear Linux or Mac System Logs', description: 'Clear syslog and auth logs', platforms: ['Linux'], dataSources: ['File', 'Process'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562', techniqueName: 'Impair Defenses', description: 'Disable or modify security tools', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Process', 'Cloud Service'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562', techniqueName: 'Impair Defenses', subTechniqueId: 'T1562.001', subTechniqueName: 'Disable or Modify Tools', description: 'Disable security monitoring tools', platforms: ['Linux', 'Windows'], dataSources: ['Process'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562', techniqueName: 'Impair Defenses', subTechniqueId: 'T1562.008', subTechniqueName: 'Disable Cloud Logs', description: 'Disable CloudTrail, GCP audit logs', platforms: ['IaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', description: 'Use non-password authentication tokens', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', subTechniqueId: 'T1550.001', subTechniqueName: 'Application Access Token', description: 'Use stolen OAuth/API tokens to bypass auth', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },

  // ── TA0006: Credential Access ──
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', description: 'Find credentials stored insecurely', platforms: ['Linux', 'Windows', 'IaaS', 'SaaS', 'Containers'], dataSources: ['Command', 'File'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.001', subTechniqueName: 'Credentials In Files', description: 'Hardcoded credentials in source code, configs', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['File'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.005', subTechniqueName: 'Cloud Instance Metadata API', description: 'Access cloud metadata service for credentials (SSRF → IMDS)', platforms: ['IaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.007', subTechniqueName: 'Container API', description: 'Extract secrets from container orchestration APIs', platforms: ['Containers'], dataSources: ['Container'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', description: 'Attempt to discover credentials through brute force', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session', 'User Account'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.001', subTechniqueName: 'Password Guessing', description: 'Guess passwords using common patterns', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.004', subTechniqueName: 'Credential Stuffing', description: 'Use breached credentials against target', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1212', techniqueName: 'Exploitation for Credential Access', description: 'Exploit software vulnerability to access credentials', platforms: ['Linux', 'Windows'], dataSources: ['Process'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1528', techniqueName: 'Steal Application Access Token', description: 'Steal OAuth tokens or API keys', platforms: ['SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1606', techniqueName: 'Forge Web Credentials', description: 'Forge authentication tokens or cookies', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session', 'Web Credential'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1606', techniqueName: 'Forge Web Credentials', subTechniqueId: 'T1606.001', subTechniqueName: 'Web Cookies', description: 'Forge session cookies for unauthorized access', platforms: ['SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1606', techniqueName: 'Forge Web Credentials', subTechniqueId: 'T1606.002', subTechniqueName: 'SAML Tokens', description: 'Forge SAML tokens (Golden SAML)', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },

  // ── TA0007: Discovery ──
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1046', techniqueName: 'Network Service Discovery', description: 'Discover services running on network hosts', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1580', techniqueName: 'Cloud Infrastructure Discovery', description: 'Discover cloud resources, VPCs, subnets', platforms: ['IaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1526', techniqueName: 'Cloud Service Discovery', description: 'Enumerate cloud services and configurations', platforms: ['IaaS', 'SaaS'], dataSources: ['Cloud Service'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1087', techniqueName: 'Account Discovery', description: 'Enumerate user and service accounts', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1087', techniqueName: 'Account Discovery', subTechniqueId: 'T1087.004', subTechniqueName: 'Cloud Account', description: 'Enumerate cloud IAM users and roles', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1613', techniqueName: 'Container and Resource Discovery', description: 'Discover containers, pods, and orchestration details', platforms: ['Containers'], dataSources: ['Container'] },

  // ── TA0008: Lateral Movement ──
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1021', techniqueName: 'Remote Services', description: 'Move laterally using remote services', platforms: ['Linux', 'Windows'], dataSources: ['Logon Session', 'Network Traffic'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1021', techniqueName: 'Remote Services', subTechniqueId: 'T1021.004', subTechniqueName: 'SSH', description: 'Lateral movement via SSH with stolen keys', platforms: ['Linux'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', description: 'Lateral movement using stolen tokens', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', subTechniqueId: 'T1550.001', subTechniqueName: 'Application Access Token', description: 'Use stolen app tokens to access other services', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1210', techniqueName: 'Exploitation of Remote Services', description: 'Exploit internal services for lateral movement', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },

  // ── TA0009: Collection ──
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage', description: 'Access data from cloud storage (S3, Blob, GCS)', platforms: ['IaaS', 'SaaS'], dataSources: ['Cloud Storage'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories', description: 'Access data from wikis, SharePoint, databases', platforms: ['SaaS'], dataSources: ['Application Log'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories', subTechniqueId: 'T1213.003', subTechniqueName: 'Code Repositories', description: 'Access source code repositories for secrets and IP', platforms: ['SaaS'], dataSources: ['Application Log'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1119', techniqueName: 'Automated Collection', description: 'Automate data collection from multiple sources', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Command', 'File'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1005', techniqueName: 'Data from Local System', description: 'Collect sensitive data from local filesystems', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'File'] },

  // ── TA0011: Command and Control ──
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', description: 'Use application protocols for C2 communication', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', subTechniqueId: 'T1071.001', subTechniqueName: 'Web Protocols', description: 'Use HTTP/HTTPS for C2 traffic', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', subTechniqueId: 'T1071.004', subTechniqueName: 'DNS', description: 'Use DNS for covert C2 communication', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1102', techniqueName: 'Web Service', description: 'Use legitimate web services for C2', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1102', techniqueName: 'Web Service', subTechniqueId: 'T1102.002', subTechniqueName: 'Bidirectional Communication', description: 'Use web service for bidirectional C2', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },

  // ── TA0010: Exfiltration ──
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', description: 'Exfiltrate data via cloud storage or web services', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Network Traffic', 'Cloud Storage'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', subTechniqueId: 'T1567.002', subTechniqueName: 'Exfiltration to Cloud Storage', description: 'Upload stolen data to attacker-controlled cloud storage', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', description: 'Exfiltrate data using non-standard protocols', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', subTechniqueId: 'T1048.003', subTechniqueName: 'Exfiltration Over Unencrypted Non-C2 Protocol', description: 'Use DNS, ICMP or other protocols for data exfil', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1537', techniqueName: 'Transfer Data to Cloud Account', description: 'Transfer data to attacker-controlled cloud account', platforms: ['IaaS'], dataSources: ['Cloud Storage'] },

  // ── TA0040: Impact ──
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1485', techniqueName: 'Data Destruction', description: 'Destroy data to disrupt business operations', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File', 'Cloud Storage'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact', description: 'Encrypt data for ransomware or disruption', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery', description: 'Delete backups and recovery mechanisms', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Cloud Storage', 'File'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1498', techniqueName: 'Network Denial of Service', description: 'Perform DDoS to disrupt services', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1498', techniqueName: 'Network Denial of Service', subTechniqueId: 'T1498.001', subTechniqueName: 'Direct Network Flood', description: 'Volumetric attack against network infrastructure', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1496', techniqueName: 'Resource Hijacking', description: 'Hijack compute resources for cryptomining', platforms: ['Linux', 'Windows', 'IaaS', 'Containers'], dataSources: ['Process', 'Cloud Service'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1565', techniqueName: 'Data Manipulation', description: 'Manipulate data to affect business processes', platforms: ['Linux', 'Windows'], dataSources: ['File', 'Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1565', techniqueName: 'Data Manipulation', subTechniqueId: 'T1565.001', subTechniqueName: 'Stored Data Manipulation', description: 'Modify stored data in databases', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
]

// ── Helper functions ──
export function getTacticById(id: string) {
  return MITRE_TACTICS.find(t => t.id === id)
}

export function getTechniquesByTactic(tacticId: string): MitreAttackEntry[] {
  return MITRE_ATTACK_MATRIX.filter(e => e.tacticId === tacticId)
}

export function getSubTechniques(techniqueId: string): MitreAttackEntry[] {
  return MITRE_ATTACK_MATRIX.filter(e => e.subTechniqueId?.startsWith(techniqueId))
}

export function findTechnique(techniqueId: string): MitreAttackEntry | undefined {
  return MITRE_ATTACK_MATRIX.find(e =>
    (e.subTechniqueId === techniqueId) || (!e.subTechniqueId && e.techniqueId === techniqueId)
  )
}

// Map CWE to likely MITRE techniques (used by attack-graph-engine)
export const CWE_TO_MITRE: Record<string, string[]> = {
  'CWE-89':   ['T1190'],                    // SQL Injection → Exploit Public App
  'CWE-78':   ['T1190', 'T1059.004'],       // OS Command Injection
  'CWE-79':   ['T1190', 'T1059.007'],       // XSS
  'CWE-22':   ['T1190', 'T1005'],           // Path Traversal
  'CWE-918':  ['T1190', 'T1552.005'],       // SSRF → Cloud Metadata
  'CWE-502':  ['T1190', 'T1059'],           // Deserialization → RCE
  'CWE-798':  ['T1552.001', 'T1078'],       // Hardcoded Credentials
  'CWE-327':  ['T1552.001'],                // Weak Crypto
  'CWE-611':  ['T1190', 'T1005'],           // XXE
  'CWE-287':  ['T1078', 'T1110'],           // Improper Auth
  'CWE-862':  ['T1078', 'T1068'],           // Missing Authorization
  'CWE-863':  ['T1068'],                    // Incorrect Authorization
  'CWE-352':  ['T1190'],                    // CSRF
  'CWE-434':  ['T1190', 'T1505.003'],       // Unrestricted Upload → Web Shell
  'CWE-94':   ['T1059.007'],                // Code Injection
  'CWE-116':  ['T1190'],                    // Improper Output Encoding
  'CWE-200':  ['T1005', 'T1530'],           // Information Exposure
  'CWE-269':  ['T1068', 'T1548'],           // Improper Privilege Mgmt
  'CWE-306':  ['T1078.001'],                // Missing Auth for Critical Function
  'CWE-732':  ['T1068', 'T1222'],           // Incorrect Permission Assignment
}
