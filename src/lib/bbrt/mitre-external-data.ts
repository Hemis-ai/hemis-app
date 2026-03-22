// src/lib/bbrt/mitre-external-data.ts
// HemisX BBRT — Black Box Red Teaming MITRE ATT&CK Data
// Focused on EXTERNAL ATTACKER techniques relevant to black-box red teaming

import type { MitreAttackMapping } from '@/lib/types/wbrt'

// Re-export the MitreAttackEntry interface from WBRT
export type { MitreAttackEntry } from '@/lib/wbrt/mitre-attack-data'
import type { MitreAttackEntry } from '@/lib/wbrt/mitre-attack-data'

// ── Tactics subset most relevant to external black-box testing ──
export const BBRT_MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
] as const

// ── Full BBRT ATT&CK matrix — external attacker techniques + sub-techniques ──
export const BBRT_MITRE_MATRIX: MitreAttackEntry[] = [

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0043: Reconnaissance
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', description: 'Actively probe target infrastructure to identify live hosts, open ports, and running services', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.001', subTechniqueName: 'Scanning IP Blocks', description: 'Scan IP address ranges to identify live hosts and exposed services', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.002', subTechniqueName: 'Vulnerability Scanning', description: 'Run automated vulnerability scanners against target infrastructure', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1595', techniqueName: 'Active Scanning', subTechniqueId: 'T1595.003', subTechniqueName: 'Wordlist Scanning', description: 'Brute-force discover hidden directories, endpoints, and subdomains', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', description: 'Collect information about victim host configurations and software', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', subTechniqueId: 'T1592.002', subTechniqueName: 'Software', description: 'Fingerprint web servers, frameworks, and application versions via headers and responses', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', subTechniqueId: 'T1592.004', subTechniqueName: 'Client Configurations', description: 'Identify client-side technologies, JavaScript frameworks, and browser requirements', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1589', techniqueName: 'Gather Victim Identity Information', description: 'Collect employee names, emails, roles, and organizational structure', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1589', techniqueName: 'Gather Victim Identity Information', subTechniqueId: 'T1589.001', subTechniqueName: 'Credentials', description: 'Search breach databases and paste sites for leaked credentials', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1589', techniqueName: 'Gather Victim Identity Information', subTechniqueId: 'T1589.002', subTechniqueName: 'Email Addresses', description: 'Harvest email addresses from public sources for credential attacks', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information', description: 'Map external network topology, DNS records, and CDN configurations', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information', subTechniqueId: 'T1590.002', subTechniqueName: 'DNS', description: 'Enumerate DNS records, zone transfers, and subdomain takeover opportunities', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information', subTechniqueId: 'T1590.005', subTechniqueName: 'IP Addresses', description: 'Discover origin IP addresses behind WAFs and CDNs', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1591', techniqueName: 'Gather Victim Org Information', description: 'Research organizational structure, business relationships, and tech stack', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1591', techniqueName: 'Gather Victim Org Information', subTechniqueId: 'T1591.002', subTechniqueName: 'Business Relationships', description: 'Identify third-party vendors, partners, and supply chain connections', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1591', techniqueName: 'Gather Victim Org Information', subTechniqueId: 'T1591.004', subTechniqueName: 'Identify Roles', description: 'Discover key personnel roles for targeted social engineering', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1596', techniqueName: 'Search Open Technical Databases', description: 'Query Shodan, Censys, and other technical databases for exposed assets', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1596', techniqueName: 'Search Open Technical Databases', subTechniqueId: 'T1596.001', subTechniqueName: 'DNS/Passive DNS', description: 'Use passive DNS databases to discover historical and current DNS records', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1596', techniqueName: 'Search Open Technical Databases', subTechniqueId: 'T1596.005', subTechniqueName: 'Scan Databases', description: 'Query internet-wide scan databases (Shodan, Censys) for exposed services', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1593', techniqueName: 'Search Open Websites/Domains', description: 'Search public websites, social media, and code repositories for intel', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1593', techniqueName: 'Search Open Websites/Domains', subTechniqueId: 'T1593.001', subTechniqueName: 'Social Media', description: 'Mine social media for employee info, tech stack hints, and attack surface intel', platforms: ['PRE'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1593', techniqueName: 'Search Open Websites/Domains', subTechniqueId: 'T1593.003', subTechniqueName: 'Code Repositories', description: 'Search GitHub/GitLab for exposed secrets, API keys, and internal documentation', platforms: ['PRE'], dataSources: ['Network Traffic'] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0042: Resource Development
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', description: 'Acquire tools, exploits, and infrastructure for the engagement', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.001', subTechniqueName: 'Malware', description: 'Obtain off-the-shelf malware or RATs for post-exploitation', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.002', subTechniqueName: 'Tool', description: 'Acquire penetration testing tools and exploitation frameworks', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.005', subTechniqueName: 'Exploits', description: 'Obtain public or private exploits for identified vulnerabilities', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1588', techniqueName: 'Obtain Capabilities', subTechniqueId: 'T1588.006', subTechniqueName: 'Vulnerabilities', description: 'Research and catalog zero-day or known vulnerabilities in target stack', platforms: ['PRE'], dataSources: [] },

  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1587', techniqueName: 'Develop Capabilities', description: 'Build custom attack tools, exploits, and payloads', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1587', techniqueName: 'Develop Capabilities', subTechniqueId: 'T1587.001', subTechniqueName: 'Malware', description: 'Develop custom malware tailored to the target environment', platforms: ['PRE'], dataSources: [] },
  { tacticId: 'TA0042', tacticName: 'Resource Development', techniqueId: 'T1587', techniqueName: 'Develop Capabilities', subTechniqueId: 'T1587.004', subTechniqueName: 'Exploits', description: 'Develop custom exploits for discovered vulnerabilities', platforms: ['PRE'], dataSources: [] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0001: Initial Access
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', description: 'Exploit vulnerabilities in internet-facing applications (SQLi, XSS, RCE, SSRF, IDOR)', platforms: ['Linux', 'Windows', 'Containers', 'IaaS'], dataSources: ['Application Log', 'Network Traffic'] },

  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', description: 'Use compromised or guessed credentials for initial access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session', 'User Account'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.001', subTechniqueName: 'Default Accounts', description: 'Exploit default credentials left on production systems and admin panels', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.004', subTechniqueName: 'Cloud Accounts', description: 'Use compromised cloud credentials (AWS keys, GCP service accounts)', platforms: ['IaaS', 'SaaS'], dataSources: ['Logon Session'] },

  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1133', techniqueName: 'External Remote Services', description: 'Access exposed remote services (SSH, RDP, VPN, admin panels)', platforms: ['Linux', 'Windows'], dataSources: ['Logon Session', 'Network Traffic'] },

  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', description: 'Compromise via third-party software or service dependencies', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', subTechniqueId: 'T1195.001', subTechniqueName: 'Compromise Software Dependencies', description: 'Exploit vulnerable or malicious package dependencies (npm, PyPI)', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise', subTechniqueId: 'T1195.002', subTechniqueName: 'Compromise Software Supply Chain', description: 'Target CI/CD pipeline or build infrastructure', platforms: ['Linux', 'Windows'], dataSources: ['File'] },

  { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1199', techniqueName: 'Trusted Relationship', description: 'Abuse trusted third-party relationships (SSO federation, API integrations) for access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Application Log', 'Logon Session', 'Network Traffic'] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0006: Credential Access
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', description: 'Attempt to discover credentials through systematic guessing', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session', 'User Account'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.001', subTechniqueName: 'Password Guessing', description: 'Guess passwords using common patterns and dictionaries', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.003', subTechniqueName: 'Password Spraying', description: 'Try a small set of common passwords against many accounts', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.004', subTechniqueName: 'Credential Stuffing', description: 'Use breached credential pairs against target authentication endpoints', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session'] },

  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1555', techniqueName: 'Credentials from Password Stores', description: 'Extract credentials from browser stores, vaults, or key managers', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['File', 'Process'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1555', techniqueName: 'Credentials from Password Stores', subTechniqueId: 'T1555.003', subTechniqueName: 'Credentials from Web Browsers', description: 'Extract saved passwords and tokens from web browser storage', platforms: ['Linux', 'Windows'], dataSources: ['File', 'Process'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1555', techniqueName: 'Credentials from Password Stores', subTechniqueId: 'T1555.005', subTechniqueName: 'Password Managers', description: 'Target password manager vaults or master passwords', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['File', 'Process'] },

  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', description: 'Find credentials stored insecurely in files, environment variables, or metadata', platforms: ['Linux', 'Windows', 'IaaS', 'SaaS', 'Containers'], dataSources: ['Command', 'File'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.001', subTechniqueName: 'Credentials In Files', description: 'Discover hardcoded credentials in exposed configuration files and source code', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['File'] },
  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.005', subTechniqueName: 'Cloud Instance Metadata API', description: 'Exploit SSRF to access cloud metadata service for temporary credentials', platforms: ['IaaS'], dataSources: ['Cloud Service'] },

  { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1539', techniqueName: 'Steal Web Session Cookie', description: 'Steal session cookies via XSS, network interception, or browser exploitation', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Logon Session', 'Web Credential'] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0007: Discovery
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1046', techniqueName: 'Network Service Discovery', description: 'Discover services running on network hosts via port scanning and service fingerprinting', platforms: ['Linux', 'Windows', 'Containers'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1082', techniqueName: 'System Information Discovery', description: 'Gather OS version, architecture, and configuration details from exposed endpoints', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Command', 'Process'] },

  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1526', techniqueName: 'Cloud Service Discovery', description: 'Enumerate cloud services, storage buckets, and serverless functions', platforms: ['IaaS', 'SaaS'], dataSources: ['Cloud Service'] },

  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1580', techniqueName: 'Cloud Infrastructure Discovery', description: 'Discover cloud VPCs, subnets, security groups, and resource configurations', platforms: ['IaaS'], dataSources: ['Cloud Service'] },

  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1087', techniqueName: 'Account Discovery', description: 'Enumerate user accounts via login responses, API endpoints, and error messages', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },
  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1087', techniqueName: 'Account Discovery', subTechniqueId: 'T1087.004', subTechniqueName: 'Cloud Account', description: 'Enumerate cloud IAM users, roles, and service accounts', platforms: ['IaaS', 'SaaS'], dataSources: ['User Account'] },

  { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1018', techniqueName: 'Remote System Discovery', description: 'Discover additional systems and services accessible from initial foothold', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Network Traffic', 'Process'] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0008: Lateral Movement
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1210', techniqueName: 'Exploitation of Remote Services', description: 'Exploit vulnerabilities in internal services to move laterally across the environment', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', description: 'Move laterally using stolen tokens, cookies, or API keys', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', subTechniqueId: 'T1550.001', subTechniqueName: 'Application Access Token', description: 'Use stolen OAuth/JWT tokens to access connected services', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material', subTechniqueId: 'T1550.004', subTechniqueName: 'Web Session Cookie', description: 'Reuse stolen session cookies to impersonate authenticated users', platforms: ['SaaS', 'IaaS'], dataSources: ['Logon Session'] },

  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1021', techniqueName: 'Remote Services', description: 'Move laterally using exposed remote services', platforms: ['Linux', 'Windows'], dataSources: ['Logon Session', 'Network Traffic'] },
  { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1021', techniqueName: 'Remote Services', subTechniqueId: 'T1021.004', subTechniqueName: 'SSH', description: 'Lateral movement via SSH with stolen keys or credentials', platforms: ['Linux'], dataSources: ['Logon Session'] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0009: Collection
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage', description: 'Access misconfigured or exposed cloud storage (S3 buckets, Azure Blobs, GCS)', platforms: ['IaaS', 'SaaS'], dataSources: ['Cloud Storage'] },

  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories', description: 'Access sensitive data from wikis, Confluence, SharePoint, and databases', platforms: ['SaaS'], dataSources: ['Application Log'] },
  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1213', techniqueName: 'Data from Information Repositories', subTechniqueId: 'T1213.003', subTechniqueName: 'Code Repositories', description: 'Access source code repositories for secrets, API keys, and intellectual property', platforms: ['SaaS'], dataSources: ['Application Log'] },

  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1119', techniqueName: 'Automated Collection', description: 'Automate data collection across discovered endpoints and services', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Command', 'File'] },

  { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1005', techniqueName: 'Data from Local System', description: 'Collect sensitive data from accessible filesystems after gaining access', platforms: ['Linux', 'Windows'], dataSources: ['Command', 'File'] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0010: Exfiltration
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', description: 'Exfiltrate data via cloud storage services or web APIs', platforms: ['Linux', 'Windows', 'SaaS'], dataSources: ['Network Traffic', 'Cloud Storage'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', subTechniqueId: 'T1567.002', subTechniqueName: 'Exfiltration to Cloud Storage', description: 'Upload stolen data to attacker-controlled cloud storage buckets', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', description: 'Exfiltrate data using non-standard protocols to bypass monitoring', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', subTechniqueId: 'T1048.003', subTechniqueName: 'Exfiltration Over Unencrypted Non-C2 Protocol', description: 'Use DNS, ICMP, or other protocols for covert data exfiltration', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1537', techniqueName: 'Transfer Data to Cloud Account', description: 'Transfer data to attacker-controlled cloud accounts or regions', platforms: ['IaaS'], dataSources: ['Cloud Storage'] },

  // ══════════════════════════════════════════════════════════════════════════════
  // TA0040: Impact
  // ══════════════════════════════════════════════════════════════════════════════
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact', description: 'Encrypt data to disrupt operations or demand ransom', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File'] },

  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1531', techniqueName: 'Account Access Removal', description: 'Delete or lock accounts to deny legitimate users access', platforms: ['Linux', 'Windows', 'SaaS', 'IaaS'], dataSources: ['User Account'] },

  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1489', techniqueName: 'Service Stop', description: 'Stop critical services to disrupt business operations', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Process', 'Cloud Service'] },

  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1485', techniqueName: 'Data Destruction', description: 'Destroy data in databases, storage, and backups', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['File', 'Cloud Storage'] },

  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1498', techniqueName: 'Network Denial of Service', description: 'Perform denial-of-service attacks against externally facing services', platforms: ['Linux', 'Windows', 'IaaS'], dataSources: ['Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1498', techniqueName: 'Network Denial of Service', subTechniqueId: 'T1498.001', subTechniqueName: 'Direct Network Flood', description: 'Volumetric flood attack against network infrastructure', platforms: ['Linux', 'Windows'], dataSources: ['Network Traffic'] },

  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1496', techniqueName: 'Resource Hijacking', description: 'Hijack compute resources for cryptomining or other attacker purposes', platforms: ['Linux', 'Windows', 'IaaS', 'Containers'], dataSources: ['Process', 'Cloud Service'] },

  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1565', techniqueName: 'Data Manipulation', description: 'Manipulate data to undermine integrity of business processes', platforms: ['Linux', 'Windows'], dataSources: ['File', 'Network Traffic'] },
  { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1565', techniqueName: 'Data Manipulation', subTechniqueId: 'T1565.001', subTechniqueName: 'Stored Data Manipulation', description: 'Modify stored data in databases and application storage', platforms: ['Linux', 'Windows'], dataSources: ['File'] },
]

// ── Helper functions ──

export function getTechniquesByTactic(tacticId: string): MitreAttackEntry[] {
  return BBRT_MITRE_MATRIX.filter(e => e.tacticId === tacticId)
}

export function getTechniqueById(techniqueId: string): MitreAttackEntry | undefined {
  return BBRT_MITRE_MATRIX.find(e =>
    (e.subTechniqueId === techniqueId) || (!e.subTechniqueId && e.techniqueId === techniqueId)
  )
}

/**
 * Maps a BBRT finding to relevant MITRE ATT&CK techniques.
 * Returns an array of MitreAttackMapping with confidence scores and evidence.
 */
export function mapFindingToMitre(findingType: string, description: string): MitreAttackMapping[] {
  const mappings: MitreAttackMapping[] = []
  const descLower = description.toLowerCase()
  const typeLower = findingType.toLowerCase()

  // ── Reconnaissance findings ──
  if (typeLower.includes('recon') || typeLower.includes('osint') || typeLower.includes('information_disclosure')) {
    const reconTechniques = getTechniquesByTactic('TA0043')
    for (const tech of reconTechniques) {
      if (!tech.subTechniqueId) {
        mappings.push({
          tacticId: tech.tacticId,
          tacticName: tech.tacticName,
          techniqueId: tech.techniqueId,
          techniqueName: tech.techniqueName,
          confidence: 60,
          evidence: `Finding type "${findingType}" relates to reconnaissance activity`,
        })
      }
    }
  }

  // ── Subdomain / DNS related ──
  if (descLower.includes('subdomain') || descLower.includes('dns') || descLower.includes('zone transfer')) {
    mappings.push({
      tacticId: 'TA0043', tacticName: 'Reconnaissance',
      techniqueId: 'T1590', techniqueName: 'Gather Victim Network Information',
      subTechniqueId: 'T1590.002', subTechniqueName: 'DNS',
      confidence: 85,
      evidence: `Description references DNS/subdomain: "${description.slice(0, 120)}"`,
    })
  }

  // ── Exposed credentials / secrets ──
  if (typeLower.includes('credential') || typeLower.includes('secret') || typeLower.includes('api_key') || descLower.includes('hardcoded') || descLower.includes('leaked credential')) {
    mappings.push({
      tacticId: 'TA0006', tacticName: 'Credential Access',
      techniqueId: 'T1552', techniqueName: 'Unsecured Credentials',
      subTechniqueId: 'T1552.001', subTechniqueName: 'Credentials In Files',
      confidence: 90,
      evidence: `Finding indicates exposed credentials: "${findingType}"`,
    })
    mappings.push({
      tacticId: 'TA0001', tacticName: 'Initial Access',
      techniqueId: 'T1078', techniqueName: 'Valid Accounts',
      confidence: 75,
      evidence: `Exposed credentials could enable initial access via valid accounts`,
    })
  }

  // ── Brute force / authentication weakness ──
  if (typeLower.includes('brute_force') || typeLower.includes('weak_password') || typeLower.includes('rate_limit') || descLower.includes('no lockout') || descLower.includes('rate limit')) {
    mappings.push({
      tacticId: 'TA0006', tacticName: 'Credential Access',
      techniqueId: 'T1110', techniqueName: 'Brute Force',
      confidence: 85,
      evidence: `Finding suggests brute force vulnerability: "${findingType}"`,
    })
  }

  // ── Password spraying opportunity ──
  if (descLower.includes('password spray') || descLower.includes('common password')) {
    mappings.push({
      tacticId: 'TA0006', tacticName: 'Credential Access',
      techniqueId: 'T1110', techniqueName: 'Brute Force',
      subTechniqueId: 'T1110.003', subTechniqueName: 'Password Spraying',
      confidence: 80,
      evidence: `Description references password spraying: "${description.slice(0, 120)}"`,
    })
  }

  // ── Web application vulnerabilities (SQLi, XSS, RCE, SSRF) ──
  if (typeLower.includes('sqli') || typeLower.includes('injection') || typeLower.includes('xss') || typeLower.includes('rce') || typeLower.includes('ssrf') || typeLower.includes('idor')) {
    mappings.push({
      tacticId: 'TA0001', tacticName: 'Initial Access',
      techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application',
      confidence: 90,
      evidence: `Web vulnerability "${findingType}" maps to exploitation of public-facing application`,
    })
  }

  // ── SSRF specifically → cloud metadata ──
  if (typeLower.includes('ssrf') || descLower.includes('metadata') || descLower.includes('imds')) {
    mappings.push({
      tacticId: 'TA0006', tacticName: 'Credential Access',
      techniqueId: 'T1552', techniqueName: 'Unsecured Credentials',
      subTechniqueId: 'T1552.005', subTechniqueName: 'Cloud Instance Metadata API',
      confidence: 85,
      evidence: `SSRF/metadata finding enables cloud credential theft via IMDS`,
    })
  }

  // ── Session / cookie theft ──
  if (typeLower.includes('session') || typeLower.includes('cookie') || descLower.includes('session fixation') || descLower.includes('session hijack')) {
    mappings.push({
      tacticId: 'TA0006', tacticName: 'Credential Access',
      techniqueId: 'T1539', techniqueName: 'Steal Web Session Cookie',
      confidence: 85,
      evidence: `Finding relates to session/cookie security: "${findingType}"`,
    })
  }

  // ── Default credentials ──
  if (typeLower.includes('default_credential') || typeLower.includes('default_password') || descLower.includes('default credentials') || descLower.includes('default password')) {
    mappings.push({
      tacticId: 'TA0001', tacticName: 'Initial Access',
      techniqueId: 'T1078', techniqueName: 'Valid Accounts',
      subTechniqueId: 'T1078.001', subTechniqueName: 'Default Accounts',
      confidence: 95,
      evidence: `Default credentials found: "${findingType}"`,
    })
  }

  // ── Exposed remote services ──
  if (typeLower.includes('ssh') || typeLower.includes('rdp') || typeLower.includes('vpn') || typeLower.includes('remote_service') || descLower.includes('exposed ssh') || descLower.includes('exposed rdp')) {
    mappings.push({
      tacticId: 'TA0001', tacticName: 'Initial Access',
      techniqueId: 'T1133', techniqueName: 'External Remote Services',
      confidence: 80,
      evidence: `Exposed remote service found: "${findingType}"`,
    })
  }

  // ── Open ports / service discovery ──
  if (typeLower.includes('open_port') || typeLower.includes('service_discovery') || typeLower.includes('port_scan') || descLower.includes('open port')) {
    mappings.push({
      tacticId: 'TA0007', tacticName: 'Discovery',
      techniqueId: 'T1046', techniqueName: 'Network Service Discovery',
      confidence: 80,
      evidence: `Network service exposure found: "${findingType}"`,
    })
  }

  // ── Cloud misconfigurations ──
  if (typeLower.includes('cloud') || typeLower.includes('s3') || typeLower.includes('bucket') || typeLower.includes('blob') || descLower.includes('publicly accessible')) {
    mappings.push({
      tacticId: 'TA0009', tacticName: 'Collection',
      techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage',
      confidence: 85,
      evidence: `Cloud storage exposure: "${findingType}"`,
    })
    mappings.push({
      tacticId: 'TA0007', tacticName: 'Discovery',
      techniqueId: 'T1580', techniqueName: 'Cloud Infrastructure Discovery',
      confidence: 70,
      evidence: `Cloud misconfiguration enables infrastructure discovery`,
    })
  }

  // ── Supply chain / dependency ──
  if (typeLower.includes('supply_chain') || typeLower.includes('dependency') || typeLower.includes('package') || descLower.includes('vulnerable dependency')) {
    mappings.push({
      tacticId: 'TA0001', tacticName: 'Initial Access',
      techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise',
      subTechniqueId: 'T1195.001', subTechniqueName: 'Compromise Software Dependencies',
      confidence: 80,
      evidence: `Supply chain risk: "${findingType}"`,
    })
  }

  // ── Data exposure / exfiltration ──
  if (typeLower.includes('data_exposure') || typeLower.includes('exfiltration') || typeLower.includes('data_leak') || descLower.includes('sensitive data')) {
    mappings.push({
      tacticId: 'TA0010', tacticName: 'Exfiltration',
      techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service',
      confidence: 70,
      evidence: `Data exposure finding enables exfiltration: "${findingType}"`,
    })
  }

  // ── Denial of service ──
  if (typeLower.includes('dos') || typeLower.includes('denial_of_service') || descLower.includes('denial of service') || descLower.includes('resource exhaustion')) {
    mappings.push({
      tacticId: 'TA0040', tacticName: 'Impact',
      techniqueId: 'T1498', techniqueName: 'Network Denial of Service',
      confidence: 80,
      evidence: `DoS vulnerability: "${findingType}"`,
    })
  }

  // ── Account takeover ──
  if (typeLower.includes('account_takeover') || typeLower.includes('privilege_escalation') || descLower.includes('account takeover')) {
    mappings.push({
      tacticId: 'TA0040', tacticName: 'Impact',
      techniqueId: 'T1531', techniqueName: 'Account Access Removal',
      confidence: 75,
      evidence: `Account takeover risk enables access removal: "${findingType}"`,
    })
  }

  // ── Lateral movement indicators ──
  if (typeLower.includes('lateral') || typeLower.includes('pivot') || descLower.includes('lateral movement') || descLower.includes('pivot')) {
    mappings.push({
      tacticId: 'TA0008', tacticName: 'Lateral Movement',
      techniqueId: 'T1210', techniqueName: 'Exploitation of Remote Services',
      confidence: 75,
      evidence: `Finding enables lateral movement: "${findingType}"`,
    })
  }

  // ── Token / OAuth abuse ──
  if (typeLower.includes('token') || typeLower.includes('oauth') || typeLower.includes('jwt') || descLower.includes('token') || descLower.includes('oauth')) {
    mappings.push({
      tacticId: 'TA0008', tacticName: 'Lateral Movement',
      techniqueId: 'T1550', techniqueName: 'Use Alternate Authentication Material',
      subTechniqueId: 'T1550.001', subTechniqueName: 'Application Access Token',
      confidence: 80,
      evidence: `Token/OAuth weakness enables lateral movement: "${findingType}"`,
    })
  }

  return mappings
}
