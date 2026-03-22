// src/lib/bbrt/recon-engine.ts
// Phase 2: External Reconnaissance — Zero-Knowledge Discovery
import type {
  BbrtTargetConfig,
  BbrtReconResult,
  SubdomainRecord,
  DnsRecord,
  PortRecord,
  TechStackDetection,
  CertRecord,
  CertIssue,
  OsintRecord,
  CloudAssetRecord,
} from '@/lib/types/bbrt'
import type { SastSeverity } from '@/lib/types/sast'
import { randomUUID } from 'crypto'

// ─── Subdomain Wordlist (common prefixes for enumeration) ───────────────────
const SUBDOMAIN_PREFIXES = [
  'api', 'admin', 'staging', 'dev', 'test', 'cdn', 'mail', 'smtp', 'imap',
  'docs', 'status', 'monitor', 'grafana', 'jenkins', 'gitlab', 'ci', 'cd',
  'app', 'www', 'portal', 'dashboard', 'internal', 'vpn', 'auth', 'sso',
  'payments', 'billing', 'support', 'help', 'blog', 'shop', 'store',
  'api-v2', 'api-internal', 'beta', 'sandbox', 'demo', 'backoffice',
  'redis', 'db', 'pg', 'mongo', 'elastic', 'kibana', 'prometheus',
  'minio', 'vault', 'consul', 'traefik', 'nginx', 'proxy',
]

// ─── Common Ports for External Scanning ─────────────────────────────────────
const COMMON_PORTS: Array<{ port: number; service: string; risk: SastSeverity }> = [
  { port: 21, service: 'ftp', risk: 'HIGH' },
  { port: 22, service: 'ssh', risk: 'MEDIUM' },
  { port: 23, service: 'telnet', risk: 'CRITICAL' },
  { port: 25, service: 'smtp', risk: 'MEDIUM' },
  { port: 53, service: 'dns', risk: 'LOW' },
  { port: 80, service: 'http', risk: 'LOW' },
  { port: 110, service: 'pop3', risk: 'MEDIUM' },
  { port: 143, service: 'imap', risk: 'MEDIUM' },
  { port: 443, service: 'https', risk: 'LOW' },
  { port: 445, service: 'smb', risk: 'CRITICAL' },
  { port: 993, service: 'imaps', risk: 'LOW' },
  { port: 995, service: 'pop3s', risk: 'LOW' },
  { port: 1433, service: 'mssql', risk: 'CRITICAL' },
  { port: 1521, service: 'oracle', risk: 'CRITICAL' },
  { port: 2379, service: 'etcd', risk: 'CRITICAL' },
  { port: 3000, service: 'grafana', risk: 'HIGH' },
  { port: 3306, service: 'mysql', risk: 'CRITICAL' },
  { port: 3389, service: 'rdp', risk: 'HIGH' },
  { port: 5432, service: 'postgresql', risk: 'CRITICAL' },
  { port: 5672, service: 'amqp', risk: 'HIGH' },
  { port: 6379, service: 'redis', risk: 'CRITICAL' },
  { port: 8080, service: 'http-alt', risk: 'MEDIUM' },
  { port: 8443, service: 'https-alt', risk: 'MEDIUM' },
  { port: 8888, service: 'jupyter', risk: 'HIGH' },
  { port: 9090, service: 'prometheus', risk: 'HIGH' },
  { port: 9200, service: 'elasticsearch', risk: 'CRITICAL' },
  { port: 9300, service: 'elasticsearch-cluster', risk: 'CRITICAL' },
  { port: 11211, service: 'memcached', risk: 'HIGH' },
  { port: 15672, service: 'rabbitmq-mgmt', risk: 'HIGH' },
  { port: 27017, service: 'mongodb', risk: 'CRITICAL' },
  { port: 50000, service: 'jenkins', risk: 'HIGH' },
]

// ─── Technology Signatures ──────────────────────────────────────────────────
interface TechSignature {
  name: string
  category: TechStackDetection['category']
  detectVia: string
  patterns: string[]   // regex-compatible patterns for matching
  knownCVEs?: string[]
}

const TECH_SIGNATURES: TechSignature[] = [
  { name: 'React', category: 'framework', detectVia: 'HTML source', patterns: ['__NEXT_DATA__', 'react-root', '_reactRootContainer'], knownCVEs: [] },
  { name: 'Next.js', category: 'framework', detectVia: 'HTTP header', patterns: ['x-powered-by: Next.js', '__NEXT_DATA__'], knownCVEs: ['CVE-2024-34351'] },
  { name: 'Express', category: 'framework', detectVia: 'HTTP header', patterns: ['x-powered-by: Express'], knownCVEs: [] },
  { name: 'nginx', category: 'server', detectVia: 'Server header', patterns: ['server: nginx'], knownCVEs: ['CVE-2024-7347'] },
  { name: 'Apache', category: 'server', detectVia: 'Server header', patterns: ['server: Apache'], knownCVEs: ['CVE-2024-38476'] },
  { name: 'WordPress', category: 'cms', detectVia: 'HTML source', patterns: ['wp-content', 'wp-includes', 'wp-json'], knownCVEs: ['CVE-2024-6307'] },
  { name: 'Drupal', category: 'cms', detectVia: 'HTTP header', patterns: ['x-drupal-cache', 'x-generator: Drupal'], knownCVEs: [] },
  { name: 'PHP', category: 'language', detectVia: 'HTTP header', patterns: ['x-powered-by: PHP'], knownCVEs: ['CVE-2024-4577'] },
  { name: 'Node.js', category: 'language', detectVia: 'HTTP header', patterns: ['x-powered-by: Express', 'x-powered-by: Next.js'], knownCVEs: [] },
  { name: 'AWS CloudFront', category: 'cdn', detectVia: 'HTTP header', patterns: ['x-amz-cf-id', 'server: CloudFront'], knownCVEs: [] },
  { name: 'Cloudflare', category: 'cdn', detectVia: 'HTTP header', patterns: ['cf-ray', 'server: cloudflare'], knownCVEs: [] },
  { name: 'PostgreSQL', category: 'database', detectVia: 'Port banner', patterns: ['PostgreSQL'], knownCVEs: ['CVE-2024-10979'] },
  { name: 'MySQL', category: 'database', detectVia: 'Port banner', patterns: ['mysql_native_password', 'MariaDB'], knownCVEs: ['CVE-2024-21047'] },
  { name: 'Redis', category: 'database', detectVia: 'Port banner', patterns: ['redis_version'], knownCVEs: ['CVE-2024-31449'] },
  { name: 'MongoDB', category: 'database', detectVia: 'Port banner', patterns: ['mongodb', 'mongod'], knownCVEs: ['CVE-2024-6376'] },
  { name: 'Docker', category: 'container', detectVia: 'HTTP header', patterns: ['docker', 'x-docker-'], knownCVEs: ['CVE-2024-41110'] },
  { name: 'Kubernetes', category: 'container', detectVia: 'API endpoint', patterns: ['/api/v1/namespaces', 'kube-system'], knownCVEs: ['CVE-2024-3177'] },
  { name: 'Jenkins', category: 'server', detectVia: 'HTTP header', patterns: ['x-jenkins', 'x-hudson'], knownCVEs: ['CVE-2024-23897'] },
  { name: 'GitLab', category: 'server', detectVia: 'HTML source', patterns: ['gitlab-', 'gl-csrf-token'], knownCVEs: ['CVE-2024-45409'] },
  { name: 'Grafana', category: 'server', detectVia: 'HTML source', patterns: ['grafana-app', 'grafana.org'], knownCVEs: ['CVE-2024-1313'] },
  { name: 'Elasticsearch', category: 'database', detectVia: 'API response', patterns: ['"tagline" : "You Know, for Search"'], knownCVEs: [] },
  { name: 'Google Analytics', category: 'analytics', detectVia: 'HTML source', patterns: ['google-analytics.com', 'gtag/js'], knownCVEs: [] },
]

// ─── Deterministic hash for reproducibility ─────────────────────────────────
function simpleHash(input: string): number {
  let hash = 0
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32-bit integer
  }
  return Math.abs(hash)
}

function seededRandom(seed: string, index: number): number {
  return (simpleHash(`${seed}-${index}`) % 10000) / 10000
}

// ─── IP Generation (example/private ranges only) ────────────────────────────
function generateIP(domain: string, index: number): string {
  const h = simpleHash(`${domain}-ip-${index}`)
  return `203.0.113.${(h % 254) + 1}`
}

// ─── Main Reconnaissance Engine ─────────────────────────────────────────────

export function runReconnaissance(config: BbrtTargetConfig): BbrtReconResult {
  const domain = config.targetDomain
  const seed = domain

  const subdomains = enumerateSubdomains(domain, seed, config)
  const dnsRecords = discoverDnsRecords(domain, seed, subdomains)
  const openPorts = scanPorts(domain, seed, subdomains)
  const techStack = fingerprintTechStack(domain, seed, subdomains, openPorts)
  const tlsCertificates = analyzeCertificates(domain, seed, subdomains)
  const osintFindings = runOsint(domain, seed)
  const cloudAssets = discoverCloudAssets(domain, seed)
  const emailAddresses = harvestEmails(domain, seed)

  return {
    subdomains,
    dnsRecords,
    openPorts,
    techStack,
    tlsCertificates,
    osintFindings,
    cloudAssets,
    emailAddresses,
    whoisInfo: {
      registrar: 'Namecheap Inc.',
      createdDate: '2019-03-15',
      expiryDate: '2026-03-15',
      nameServers: [`ns1.${domain}`, `ns2.${domain}`, 'ns3.cloudflare.com'],
    },
    discoveredAt: new Date().toISOString(),
  }
}

// ─── Subdomain Enumeration ──────────────────────────────────────────────────
function enumerateSubdomains(
  domain: string,
  seed: string,
  config: BbrtTargetConfig,
): SubdomainRecord[] {
  const results: SubdomainRecord[] = []
  const scopeSet = new Set(config.targetScope.map(s => s.toLowerCase()))
  const shadowPrefixes = new Set(['internal', 'staging', 'jenkins', 'grafana', 'backoffice', 'dev', 'test'])

  // Always include the root domain
  results.push({
    subdomain: domain,
    ip: generateIP(domain, 0),
    status: 'active',
    httpStatus: 200,
    title: `${domain} — Home`,
    isShadowAsset: false,
    riskScore: 15,
  })

  // Enumerate subdomains based on wordlist
  for (let i = 0; i < SUBDOMAIN_PREFIXES.length; i++) {
    const prefix = SUBDOMAIN_PREFIXES[i]
    const fqdn = `${prefix}.${domain}`
    const probability = seededRandom(seed, i)

    // Simulate discovery probability — not all subdomains exist
    if (probability < 0.35) continue

    const ip = generateIP(domain, i + 1)
    const isActive = probability > 0.15
    const httpStatus = isActive ? [200, 301, 302, 403, 500][simpleHash(`${fqdn}-status`) % 5] : undefined
    const isShadow = shadowPrefixes.has(prefix) && !scopeSet.has(fqdn)

    let riskScore = 10
    if (prefix === 'admin' || prefix === 'backoffice') riskScore = 75
    else if (prefix === 'jenkins' || prefix === 'gitlab' || prefix === 'ci') riskScore = 85
    else if (prefix === 'grafana' || prefix === 'prometheus' || prefix === 'kibana') riskScore = 70
    else if (prefix === 'staging' || prefix === 'dev' || prefix === 'test') riskScore = 60
    else if (prefix === 'redis' || prefix === 'db' || prefix === 'pg' || prefix === 'mongo') riskScore = 90
    else if (prefix === 'api' || prefix === 'api-v2') riskScore = 45
    else if (prefix === 'vpn' || prefix === 'internal') riskScore = 80
    else if (prefix === 'mail' || prefix === 'smtp') riskScore = 35
    else if (isShadow) riskScore += 25

    results.push({
      subdomain: fqdn,
      ip,
      status: isActive ? 'active' : 'inactive',
      httpStatus,
      title: isActive ? `${prefix.charAt(0).toUpperCase() + prefix.slice(1)} — ${domain}` : undefined,
      isShadowAsset: isShadow,
      riskScore: Math.min(riskScore, 100),
    })
  }

  return results
}

// ─── DNS Record Discovery ───────────────────────────────────────────────────
function discoverDnsRecords(
  domain: string,
  seed: string,
  subdomains: SubdomainRecord[],
): DnsRecord[] {
  const records: DnsRecord[] = []

  // A records for discovered subdomains
  for (const sub of subdomains.filter(s => s.status === 'active').slice(0, 15)) {
    records.push({
      type: 'A',
      name: sub.subdomain,
      value: sub.ip,
      ttl: 300,
    })
  }

  // MX records
  records.push(
    { type: 'MX', name: domain, value: `mail.${domain}`, ttl: 3600, securityNotes: undefined },
    { type: 'MX', name: domain, value: 'aspmx.l.google.com', ttl: 3600, securityNotes: undefined },
  )

  // TXT records (SPF, DMARC, verification)
  const hasSPF = seededRandom(seed, 100) > 0.3
  const hasDMARC = seededRandom(seed, 101) > 0.5

  if (hasSPF) {
    records.push({
      type: 'TXT',
      name: domain,
      value: `v=spf1 include:_spf.google.com include:sendgrid.net ~all`,
      ttl: 3600,
      securityNotes: 'SPF uses soft fail (~all) instead of hard fail (-all)',
    })
  } else {
    records.push({
      type: 'TXT',
      name: domain,
      value: '',
      ttl: 3600,
      securityNotes: 'No SPF record found — email spoofing possible',
    })
  }

  if (hasDMARC) {
    records.push({
      type: 'TXT',
      name: `_dmarc.${domain}`,
      value: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`,
      ttl: 3600,
      securityNotes: 'DMARC policy is "none" — not enforcing',
    })
  } else {
    records.push({
      type: 'TXT',
      name: `_dmarc.${domain}`,
      value: '',
      ttl: 3600,
      securityNotes: 'No DMARC record found — email spoofing possible',
    })
  }

  // NS records
  records.push(
    { type: 'NS', name: domain, value: `ns1.${domain}`, ttl: 86400 },
    { type: 'NS', name: domain, value: `ns2.${domain}`, ttl: 86400 },
  )

  // CNAME records for CDN/cloud
  records.push(
    { type: 'CNAME', name: `cdn.${domain}`, value: 'd1234567.cloudfront.net', ttl: 300 },
    { type: 'CNAME', name: `status.${domain}`, value: 'statuspage.io', ttl: 300 },
  )

  // SOA record
  records.push({
    type: 'SOA',
    name: domain,
    value: `ns1.${domain} admin.${domain} 2024010101 3600 900 604800 86400`,
    ttl: 86400,
  })

  return records
}

// ─── Port Scanning ──────────────────────────────────────────────────────────
function scanPorts(
  domain: string,
  seed: string,
  subdomains: SubdomainRecord[],
): PortRecord[] {
  const results: PortRecord[] = []
  const activeHosts = subdomains.filter(s => s.status === 'active')

  for (const host of activeHosts) {
    const hostSeed = `${seed}-${host.subdomain}`

    for (let i = 0; i < COMMON_PORTS.length; i++) {
      const portDef = COMMON_PORTS[i]
      const openProbability = seededRandom(hostSeed, i)

      // Higher chance for common web ports, lower for DB ports
      let threshold = 0.75
      if ([80, 443].includes(portDef.port)) threshold = 0.3
      else if ([22].includes(portDef.port)) threshold = 0.5
      else if ([8080, 8443].includes(portDef.port)) threshold = 0.6
      else if ([3306, 5432, 6379, 27017, 9200].includes(portDef.port)) threshold = 0.85

      if (openProbability >= threshold) continue

      const versionIndex = simpleHash(`${hostSeed}-${portDef.port}-ver`) % 3
      const versions: Record<string, string[]> = {
        ssh: ['OpenSSH 8.9p1', 'OpenSSH 9.3p1', 'OpenSSH 7.4'],
        http: ['nginx/1.22.1', 'Apache/2.4.57', 'Node.js'],
        https: ['nginx/1.22.1', 'Apache/2.4.57', 'Node.js'],
        'http-alt': ['Jetty 9.4.51', 'Tomcat/9.0.78', 'Express'],
        mysql: ['MySQL 8.0.33', 'MariaDB 10.11', 'MySQL 5.7.42'],
        postgresql: ['PostgreSQL 15.3', 'PostgreSQL 14.9', 'PostgreSQL 16.1'],
        redis: ['Redis 7.0.12', 'Redis 6.2.13', 'Redis 7.2.1'],
        mongodb: ['MongoDB 6.0.8', 'MongoDB 5.0.19', 'MongoDB 7.0.2'],
        jenkins: ['Jenkins 2.414.2', 'Jenkins 2.401.3', 'Jenkins 2.426.1'],
        grafana: ['Grafana 10.0.3', 'Grafana 9.5.7', 'Grafana 10.1.5'],
        elasticsearch: ['Elasticsearch 8.9.1', 'Elasticsearch 7.17.12', 'Elasticsearch 8.10.2'],
      }

      const serviceVersions = versions[portDef.service]
      const version = serviceVersions ? serviceVersions[versionIndex] : undefined

      let notes: string | undefined
      if (['mysql', 'postgresql', 'redis', 'mongodb', 'elasticsearch'].includes(portDef.service)) {
        notes = `Database port ${portDef.port} exposed to internet — should be firewalled`
      } else if (portDef.service === 'jenkins') {
        notes = 'CI/CD server exposed to internet — high-value target'
      } else if (portDef.service === 'telnet') {
        notes = 'Telnet transmits credentials in cleartext'
      } else if (portDef.service === 'smb') {
        notes = 'SMB exposed to internet — ransomware attack vector'
      }

      results.push({
        host: host.subdomain,
        port: portDef.port,
        protocol: 'tcp',
        state: 'open',
        service: portDef.service,
        version,
        riskLevel: portDef.risk,
        notes,
      })
    }
  }

  return results
}

// ─── Technology Fingerprinting ──────────────────────────────────────────────
function fingerprintTechStack(
  domain: string,
  seed: string,
  subdomains: SubdomainRecord[],
  ports: PortRecord[],
): TechStackDetection[] {
  const detections: TechStackDetection[] = []
  const seen = new Set<string>()

  // Detect from port banners
  for (const port of ports) {
    if (!port.version) continue
    for (const sig of TECH_SIGNATURES) {
      if (seen.has(sig.name)) continue
      const versionLower = port.version.toLowerCase()
      if (versionLower.includes(sig.name.toLowerCase())) {
        seen.add(sig.name)
        detections.push({
          category: sig.category,
          name: sig.name,
          version: port.version.replace(sig.name, '').replace('/', '').trim() || undefined,
          confidence: 95,
          detectedVia: `Port ${port.port} banner on ${port.host}`,
          knownCVEs: sig.knownCVEs,
        })
      }
    }
  }

  // Simulate HTTP-based detection for main domain
  const httpSignatures: Array<{ name: string; category: TechStackDetection['category']; via: string; confidence: number; cves?: string[] }> = [
    { name: 'React', category: 'framework', via: 'HTML source analysis', confidence: 90 },
    { name: 'Next.js', category: 'framework', via: 'X-Powered-By header', confidence: 95, cves: ['CVE-2024-34351'] },
    { name: 'Node.js', category: 'language', via: 'Server response patterns', confidence: 85 },
    { name: 'AWS CloudFront', category: 'cdn', via: 'X-Amz-Cf-Id header', confidence: 98 },
    { name: 'Google Analytics', category: 'analytics', via: 'HTML script tag', confidence: 99 },
  ]

  for (let i = 0; i < httpSignatures.length; i++) {
    const sig = httpSignatures[i]
    if (seen.has(sig.name)) continue
    if (seededRandom(seed, 200 + i) < 0.7) {
      seen.add(sig.name)
      detections.push({
        category: sig.category,
        name: sig.name,
        confidence: sig.confidence,
        detectedVia: sig.via,
        knownCVEs: sig.cves,
      })
    }
  }

  return detections
}

// ─── TLS Certificate Analysis ───────────────────────────────────────────────
function analyzeCertificates(
  domain: string,
  seed: string,
  subdomains: SubdomainRecord[],
): CertRecord[] {
  const certs: CertRecord[] = []
  const now = new Date()

  // Main domain cert
  certs.push({
    host: domain,
    issuer: "Let's Encrypt Authority X3",
    subject: `CN=${domain}`,
    validFrom: new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000).toISOString(),
    validTo: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    serialNumber: simpleHash(`${seed}-cert-1`).toString(16).padStart(16, '0'),
    signatureAlgorithm: 'SHA-256 with RSA',
    sans: [domain, `*.${domain}`, `www.${domain}`],
    issues: [],
  })

  // Staging cert — self-signed
  const stagingSub = subdomains.find(s => s.subdomain.startsWith('staging'))
  if (stagingSub) {
    certs.push({
      host: stagingSub.subdomain,
      issuer: 'Self-Signed',
      subject: `CN=${stagingSub.subdomain}`,
      validFrom: new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString(),
      validTo: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      serialNumber: simpleHash(`${seed}-cert-2`).toString(16).padStart(16, '0'),
      signatureAlgorithm: 'SHA-1 with RSA',
      sans: [stagingSub.subdomain],
      issues: [
        { type: 'self_signed', description: 'Certificate is self-signed and not trusted by browsers', severity: 'MEDIUM' },
        { type: 'sha1', description: 'Uses deprecated SHA-1 signature algorithm', severity: 'MEDIUM' },
      ],
    })
  }

  // Expired cert on dev subdomain
  const devSub = subdomains.find(s => s.subdomain.startsWith('dev'))
  if (devSub) {
    certs.push({
      host: devSub.subdomain,
      issuer: "Let's Encrypt Authority X3",
      subject: `CN=${devSub.subdomain}`,
      validFrom: new Date(now.getTime() - 120 * 24 * 60 * 60 * 1000).toISOString(),
      validTo: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      serialNumber: simpleHash(`${seed}-cert-3`).toString(16).padStart(16, '0'),
      signatureAlgorithm: 'SHA-256 with RSA',
      sans: [devSub.subdomain],
      issues: [
        { type: 'expired', description: 'Certificate expired 30 days ago', severity: 'HIGH' },
      ],
    })
  }

  return certs
}

// ─── OSINT (Open Source Intelligence) ───────────────────────────────────────
function runOsint(domain: string, seed: string): OsintRecord[] {
  const findings: OsintRecord[] = []
  const now = new Date()

  // Common OSINT patterns for a realistic target
  const potentialFindings: Array<Omit<OsintRecord, 'discoveredAt'>> = [
    {
      source: 'github',
      type: 'api_key',
      title: 'Exposed API key in public repository',
      description: `AWS access key found in commit history of repository linked to ${domain}. Key prefix: AKIA****. The key was committed 6 months ago and may still be active.`,
      severity: 'CRITICAL',
      data: `AKIA****EXAMPLE**** found in config/aws.env (commit sha: a3f7b2c)`,
    },
    {
      source: 'github',
      type: 'config_file',
      title: 'Database connection string in public repo',
      description: `PostgreSQL connection string with credentials found in a Dockerfile associated with ${domain} infrastructure.`,
      severity: 'HIGH',
      data: `postgresql://app_user:****@pg.internal.${domain}:5432/production`,
    },
    {
      source: 'breach_db',
      type: 'credential_leak',
      title: 'Employee credentials in breach database',
      description: `Multiple email addresses from ${domain} found in known breach databases. Credentials may be reused on corporate systems.`,
      severity: 'HIGH',
      data: `Found 12 email addresses from ${domain} in 3 breach datasets (2022-2024)`,
    },
    {
      source: 'pastebin',
      type: 'internal_url',
      title: 'Internal URLs leaked on paste site',
      description: `Internal service URLs and staging endpoints for ${domain} found on a paste site, likely from a developer debug session.`,
      severity: 'MEDIUM',
      data: `internal-api.${domain}, staging-db.${domain}, admin.${domain}/debug`,
    },
    {
      source: 'cert_transparency',
      type: 'internal_url',
      title: 'Hidden subdomains via certificate transparency',
      description: `Certificate transparency logs reveal subdomains not listed in public DNS, suggesting internal services with public TLS certificates.`,
      severity: 'MEDIUM',
      data: `Found: vault.${domain}, consul.${domain}, k8s-dashboard.${domain}`,
    },
    {
      source: 'shodan',
      type: 'config_file',
      title: 'Exposed service banners on Shodan',
      description: `Multiple services for ${domain} IP range are indexed on Shodan with detailed version information and configuration details.`,
      severity: 'MEDIUM',
      data: `3 IPs indexed: SSH, HTTP, PostgreSQL banners exposed with version info`,
    },
    {
      source: 'social_media',
      type: 'employee_info',
      title: 'Employee role and technology details on LinkedIn',
      description: `LinkedIn profiles reveal internal technology stack and team structure details useful for targeted social engineering.`,
      severity: 'LOW',
      data: `CTO mentions "migrating from Heroku to K8s on AWS". 3 DevOps engineers list Terraform, ArgoCD, Vault.`,
    },
    {
      source: 'dns_history',
      type: 'internal_url',
      title: 'Historical DNS records reveal decommissioned services',
      description: `DNS history shows previously active subdomains that may still have residual attack surface.`,
      severity: 'LOW',
      data: `old-api.${domain} (last seen 6 months ago), legacy.${domain} (last seen 1 year ago)`,
    },
  ]

  for (let i = 0; i < potentialFindings.length; i++) {
    if (seededRandom(seed, 300 + i) < 0.7) {
      findings.push({
        ...potentialFindings[i],
        discoveredAt: new Date(now.getTime() - i * 3600000).toISOString(),
      })
    }
  }

  return findings
}

// ─── Cloud Asset Discovery ──────────────────────────────────────────────────
function discoverCloudAssets(domain: string, seed: string): CloudAssetRecord[] {
  const assets: CloudAssetRecord[] = []
  const orgName = domain.split('.')[0]

  const potentialAssets: CloudAssetRecord[] = [
    {
      provider: 'aws',
      type: 's3_bucket',
      identifier: `${orgName}-assets`,
      isPublic: true,
      region: 'us-east-1',
      issues: ['Public read access enabled', 'No server-side encryption'],
    },
    {
      provider: 'aws',
      type: 's3_bucket',
      identifier: `${orgName}-backups`,
      isPublic: false,
      region: 'us-east-1',
      issues: [],
    },
    {
      provider: 'aws',
      type: 's3_bucket',
      identifier: `${orgName}-logs`,
      isPublic: true,
      region: 'us-west-2',
      issues: ['Public list access enabled', 'Contains application log files'],
    },
    {
      provider: 'aws',
      type: 'cdn_distribution',
      identifier: 'd1234567890abc',
      isPublic: true,
      region: 'global',
      issues: [],
    },
    {
      provider: 'aws',
      type: 'lambda',
      identifier: `${orgName}-api-handler`,
      isPublic: true,
      region: 'us-east-1',
      issues: ['Function URL enabled without IAM auth'],
    },
  ]

  for (let i = 0; i < potentialAssets.length; i++) {
    if (seededRandom(seed, 400 + i) < 0.7) {
      assets.push(potentialAssets[i])
    }
  }

  return assets
}

// ─── Email Harvesting ───────────────────────────────────────────────────────
function harvestEmails(domain: string, seed: string): string[] {
  const prefixes = [
    'admin', 'info', 'support', 'hr', 'dev', 'security',
    'ops', 'cto', 'engineering', 'devops', 'noreply', 'hello',
  ]

  const emails: string[] = []
  for (let i = 0; i < prefixes.length; i++) {
    if (seededRandom(seed, 500 + i) < 0.6) {
      emails.push(`${prefixes[i]}@${domain}`)
    }
  }
  return emails
}
