// src/lib/mock-data/bbrt.ts
// HemisX BBRT — Comprehensive Mock Data for Demo Engagement

import type {
  BbrtEngagement,
  BbrtReconResult,
  BbrtAttackSurface,
  BbrtFinding,
  BbrtKillChain,
  BbrtReport,
  SubdomainRecord,
  DnsRecord,
  PortRecord,
  TechStackDetection,
  CertRecord,
  OsintRecord,
  CloudAssetRecord,
  AttackSurfaceAsset,
  BbrtKillChainStep,
  BbrtAttackSurfaceStats,
  BbrtFindingStats,
} from '@/lib/types/bbrt'
import type { ComplianceGap, RemediationItem, MitreAttackMapping } from '@/lib/types/wbrt'

// ─── Subdomains ───────────────────────────────────────────────────────────────

const MOCK_SUBDOMAINS: SubdomainRecord[] = [
  { subdomain: 'demo-app.hemisx.com', ip: '52.14.88.201', status: 'active', httpStatus: 200, title: 'HemisX Demo App', isShadowAsset: false, riskScore: 35 },
  { subdomain: 'api.demo-app.hemisx.com', ip: '52.14.88.202', status: 'active', httpStatus: 200, title: 'API Gateway', isShadowAsset: false, riskScore: 55 },
  { subdomain: 'staging.demo-app.hemisx.com', ip: '52.14.88.210', status: 'active', httpStatus: 200, title: 'Staging Environment', isShadowAsset: false, riskScore: 72 },
  { subdomain: 'admin.demo-app.hemisx.com', ip: '52.14.88.203', status: 'active', httpStatus: 401, title: 'Admin Panel', isShadowAsset: false, riskScore: 82 },
  { subdomain: 'mail.demo-app.hemisx.com', ip: '52.14.88.204', status: 'active', httpStatus: 200, title: 'Webmail Interface', isShadowAsset: false, riskScore: 40 },
  { subdomain: 'cdn.demo-app.hemisx.com', ip: '143.204.12.55', status: 'active', httpStatus: 200, title: 'CloudFront CDN', isShadowAsset: false, riskScore: 15 },
  { subdomain: 'docs.demo-app.hemisx.com', ip: '52.14.88.206', status: 'active', httpStatus: 200, title: 'API Documentation', isShadowAsset: false, riskScore: 28 },
  { subdomain: 'payments.demo-app.hemisx.com', ip: '52.14.88.207', status: 'active', httpStatus: 200, title: 'Payment Gateway', isShadowAsset: false, riskScore: 90 },
  { subdomain: 'jenkins.demo-app.hemisx.com', ip: '52.14.88.215', status: 'active', httpStatus: 200, title: 'Jenkins CI/CD', isShadowAsset: true, riskScore: 95 },
  { subdomain: 'grafana.demo-app.hemisx.com', ip: '52.14.88.216', status: 'active', httpStatus: 200, title: 'Grafana Dashboard', isShadowAsset: true, riskScore: 68 },
  { subdomain: 'dev.demo-app.hemisx.com', ip: '52.14.88.220', status: 'active', httpStatus: 200, title: 'Development Environment', isShadowAsset: false, riskScore: 78 },
  { subdomain: 'internal-api.demo-app.hemisx.com', ip: '52.14.88.230', status: 'active', httpStatus: 403, title: 'Internal API', isShadowAsset: true, riskScore: 88 },
  { subdomain: 'legacy.demo-app.hemisx.com', ip: '52.14.88.240', status: 'active', httpStatus: 200, title: 'Legacy Application', isShadowAsset: false, riskScore: 74 },
]

// ─── DNS Records ──────────────────────────────────────────────────────────────

const MOCK_DNS: DnsRecord[] = [
  { type: 'A', name: 'demo-app.hemisx.com', value: '52.14.88.201', ttl: 300 },
  { type: 'AAAA', name: 'demo-app.hemisx.com', value: '2600:1f18:66c:b800::1', ttl: 300 },
  { type: 'MX', name: 'demo-app.hemisx.com', value: 'mail.demo-app.hemisx.com (priority 10)', ttl: 3600, securityNotes: 'SPF record present but DMARC not enforced' },
  { type: 'TXT', name: 'demo-app.hemisx.com', value: 'v=spf1 include:_spf.google.com include:amazonses.com ~all', ttl: 3600 },
  { type: 'TXT', name: '_dmarc.demo-app.hemisx.com', value: 'v=DMARC1; p=none; rua=mailto:dmarc@hemisx.com', ttl: 3600, securityNotes: 'DMARC policy set to none — no enforcement' },
  { type: 'CNAME', name: 'cdn.demo-app.hemisx.com', value: 'd1234abcdef.cloudfront.net', ttl: 300 },
  { type: 'NS', name: 'demo-app.hemisx.com', value: 'ns-1234.awsdns-01.org', ttl: 172800 },
  { type: 'NS', name: 'demo-app.hemisx.com', value: 'ns-5678.awsdns-02.co.uk', ttl: 172800 },
  { type: 'CNAME', name: 'staging.demo-app.hemisx.com', value: 'staging-lb-123456.us-east-2.elb.amazonaws.com', ttl: 60 },
  { type: 'SRV', name: '_mongodb._tcp.demo-app.hemisx.com', value: '0 5 27017 db.demo-app.hemisx.com', ttl: 300, securityNotes: 'MongoDB SRV record publicly exposed' },
]

// ─── Open Ports ───────────────────────────────────────────────────────────────

const MOCK_PORTS: PortRecord[] = [
  // Main domain
  { host: 'demo-app.hemisx.com', port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'nginx/1.24.0', riskLevel: 'LOW', notes: 'Redirects to HTTPS' },
  { host: 'demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', version: 'nginx/1.24.0', riskLevel: 'LOW' },
  // API
  { host: 'api.demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', version: 'Node.js Express', riskLevel: 'MEDIUM' },
  { host: 'api.demo-app.hemisx.com', port: 8080, protocol: 'tcp', state: 'open', service: 'http-proxy', version: 'Express/4.18.2', riskLevel: 'HIGH', notes: 'Debug port exposed — returns stack traces' },
  // Admin
  { host: 'admin.demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', version: 'nginx/1.24.0', riskLevel: 'HIGH' },
  { host: 'admin.demo-app.hemisx.com', port: 22, protocol: 'tcp', state: 'open', service: 'ssh', version: 'OpenSSH 8.9p1', riskLevel: 'MEDIUM', notes: 'SSH accessible from internet' },
  // Staging
  { host: 'staging.demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', riskLevel: 'HIGH', notes: 'Uses production database credentials' },
  { host: 'staging.demo-app.hemisx.com', port: 3000, protocol: 'tcp', state: 'open', service: 'http', version: 'Next.js 14.1', riskLevel: 'HIGH', notes: 'Dev server exposed to internet' },
  // Payments
  { host: 'payments.demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', version: 'Node.js', riskLevel: 'CRITICAL' },
  // Jenkins (shadow)
  { host: 'jenkins.demo-app.hemisx.com', port: 8080, protocol: 'tcp', state: 'open', service: 'http', version: 'Jenkins 2.414.3', riskLevel: 'CRITICAL', notes: 'Jenkins console with default credentials' },
  { host: 'jenkins.demo-app.hemisx.com', port: 50000, protocol: 'tcp', state: 'open', service: 'jenkins-agent', riskLevel: 'CRITICAL', notes: 'Jenkins agent port open — allows remote code execution' },
  // Grafana (shadow)
  { host: 'grafana.demo-app.hemisx.com', port: 3000, protocol: 'tcp', state: 'open', service: 'http', version: 'Grafana 10.1.0', riskLevel: 'HIGH', notes: 'Default admin/admin credentials' },
  // Database (exposed)
  { host: '52.14.88.207', port: 5432, protocol: 'tcp', state: 'open', service: 'postgresql', version: 'PostgreSQL 15.2', riskLevel: 'CRITICAL', notes: 'Database port exposed to internet' },
  { host: '52.14.88.207', port: 6379, protocol: 'tcp', state: 'open', service: 'redis', version: 'Redis 7.0.12', riskLevel: 'CRITICAL', notes: 'Redis without authentication' },
  // Legacy
  { host: 'legacy.demo-app.hemisx.com', port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Apache/2.4.41', riskLevel: 'HIGH', notes: 'Outdated Apache with known CVEs' },
  { host: 'legacy.demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', version: 'Apache/2.4.41', riskLevel: 'HIGH' },
  { host: 'legacy.demo-app.hemisx.com', port: 3306, protocol: 'tcp', state: 'open', service: 'mysql', version: 'MySQL 5.7.42', riskLevel: 'CRITICAL', notes: 'MySQL exposed to internet with weak authentication' },
  // Internal API (shadow)
  { host: 'internal-api.demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', riskLevel: 'HIGH' },
  { host: 'internal-api.demo-app.hemisx.com', port: 9090, protocol: 'tcp', state: 'open', service: 'http', version: 'Prometheus', riskLevel: 'MEDIUM', notes: 'Prometheus metrics exposed without auth' },
  // Dev
  { host: 'dev.demo-app.hemisx.com', port: 443, protocol: 'tcp', state: 'open', service: 'https', riskLevel: 'MEDIUM' },
  { host: 'dev.demo-app.hemisx.com', port: 9229, protocol: 'tcp', state: 'open', service: 'node-debug', riskLevel: 'CRITICAL', notes: 'Node.js debugger port exposed — allows RCE' },
]

// ─── Tech Stack ───────────────────────────────────────────────────────────────

const MOCK_TECH_STACK: TechStackDetection[] = [
  { category: 'framework', name: 'React', version: '18.2.0', confidence: 95, detectedVia: 'JavaScript bundle analysis', knownCVEs: [] },
  { category: 'framework', name: 'Next.js', version: '14.1.0', confidence: 90, detectedVia: 'X-Powered-By header, _next/ paths', knownCVEs: ['CVE-2024-34351'] },
  { category: 'server', name: 'nginx', version: '1.24.0', confidence: 98, detectedVia: 'Server HTTP header', knownCVEs: [] },
  { category: 'language', name: 'Node.js', version: '18.19.0', confidence: 85, detectedVia: 'X-Powered-By: Express, error stack traces', knownCVEs: [] },
  { category: 'server', name: 'Express', version: '4.18.2', confidence: 88, detectedVia: 'X-Powered-By header on API routes', knownCVEs: [] },
  { category: 'database', name: 'PostgreSQL', version: '15.2', confidence: 92, detectedVia: 'Open port banner, error messages', knownCVEs: ['CVE-2023-5868', 'CVE-2023-5869'] },
  { category: 'database', name: 'Redis', version: '7.0.12', confidence: 90, detectedVia: 'Open port banner, INFO response', knownCVEs: [] },
  { category: 'database', name: 'MySQL', version: '5.7.42', confidence: 88, detectedVia: 'Port banner on legacy host', knownCVEs: ['CVE-2023-21977', 'CVE-2023-21980'] },
  { category: 'cloud', name: 'AWS', confidence: 95, detectedVia: 'CloudFront headers, S3 bucket naming, ELB DNS', knownCVEs: [] },
  { category: 'cdn', name: 'CloudFront', confidence: 98, detectedVia: 'X-Amz-Cf-Id header', knownCVEs: [] },
  { category: 'server', name: 'Apache', version: '2.4.41', confidence: 95, detectedVia: 'Server header on legacy subdomain', knownCVEs: ['CVE-2023-25690', 'CVE-2023-43622'] },
  { category: 'container', name: 'Docker', confidence: 70, detectedVia: 'Container-specific headers on staging', knownCVEs: [] },
  { category: 'server', name: 'Jenkins', version: '2.414.3', confidence: 99, detectedVia: 'Jenkins login page, X-Jenkins header', knownCVEs: ['CVE-2024-23897', 'CVE-2024-23898'] },
  { category: 'analytics', name: 'Grafana', version: '10.1.0', confidence: 95, detectedVia: 'Grafana login page', knownCVEs: ['CVE-2023-6152'] },
]

// ─── TLS Certificates ─────────────────────────────────────────────────────────

const MOCK_CERTS: CertRecord[] = [
  {
    host: 'demo-app.hemisx.com',
    issuer: "Let's Encrypt Authority X3",
    subject: 'demo-app.hemisx.com',
    validFrom: '2024-11-15T00:00:00Z',
    validTo: '2025-08-15T00:00:00Z',
    serialNumber: '03:A1:B2:C3:D4:E5:F6',
    signatureAlgorithm: 'SHA256withRSA',
    sans: ['demo-app.hemisx.com', '*.demo-app.hemisx.com'],
    issues: [
      { type: 'wildcard', description: 'Wildcard certificate — covers all subdomains including shadow assets', severity: 'LOW' },
    ],
  },
  {
    host: 'legacy.demo-app.hemisx.com',
    issuer: 'DigiCert SHA2 Secure Server CA',
    subject: 'legacy.demo-app.hemisx.com',
    validFrom: '2022-03-01T00:00:00Z',
    validTo: '2024-03-01T00:00:00Z',
    serialNumber: '0A:1B:2C:3D:4E:5F:6A',
    signatureAlgorithm: 'SHA1withRSA',
    sans: ['legacy.demo-app.hemisx.com'],
    issues: [
      { type: 'expired', description: 'Certificate expired on March 1, 2024 — over 1 year ago', severity: 'HIGH' },
      { type: 'sha1', description: 'Uses deprecated SHA-1 signature algorithm', severity: 'MEDIUM' },
    ],
  },
  {
    host: 'jenkins.demo-app.hemisx.com',
    issuer: 'jenkins.demo-app.hemisx.com (Self-Signed)',
    subject: 'jenkins.demo-app.hemisx.com',
    validFrom: '2024-01-01T00:00:00Z',
    validTo: '2026-01-01T00:00:00Z',
    serialNumber: 'FF:EE:DD:CC:BB:AA:99',
    signatureAlgorithm: 'SHA256withRSA',
    sans: ['jenkins.demo-app.hemisx.com'],
    issues: [
      { type: 'self_signed', description: 'Self-signed certificate — not trusted by browsers', severity: 'MEDIUM' },
    ],
  },
]

// ─── OSINT Findings ───────────────────────────────────────────────────────────

const MOCK_OSINT: OsintRecord[] = [
  {
    source: 'github',
    type: 'api_key',
    title: 'AWS Access Key Leaked in Public Repository',
    description: 'An AWS access key ID (AKIA...) and secret access key were found in a commit to the hemisx-demo-app repository. The key has IAM permissions for S3, EC2, and RDS.',
    url: 'https://github.com/hemisx-demo/app/commit/abc123',
    severity: 'CRITICAL',
    data: 'AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY (redacted)',
    discoveredAt: '2025-12-15T14:22:00Z',
  },
  {
    source: 'github',
    type: 'config_file',
    title: 'Database Connection String in .env File',
    description: 'A .env file containing PostgreSQL connection string with production credentials was committed to the repository history.',
    url: 'https://github.com/hemisx-demo/app/blob/main/.env.example',
    severity: 'HIGH',
    data: 'DATABASE_URL=postgresql://admin:Pr0d_P@ss!2024@52.14.88.207:5432/hemisx_prod (redacted)',
    discoveredAt: '2025-12-15T14:25:00Z',
  },
  {
    source: 'breach_db',
    type: 'credential_leak',
    title: 'Employee Credentials Found in Breach Database',
    description: '4 email/password combinations matching @hemisx.com domain found in the 2024 SaaS platform breach compilation.',
    severity: 'HIGH',
    data: 'admin@hemisx.com:******, dev@hemisx.com:******, ops@hemisx.com:******, cto@hemisx.com:****** (redacted)',
    discoveredAt: '2025-12-15T14:30:00Z',
  },
  {
    source: 'pastebin',
    type: 'internal_url',
    title: 'Internal API Endpoints Disclosed on Paste Site',
    description: 'A paste containing internal API documentation with endpoint paths, authentication bypass notes, and test credentials.',
    url: 'https://pastebin.com/EXAMPLE123',
    severity: 'MEDIUM',
    data: 'POST /internal/admin/users — no auth required in staging\nGET /debug/env — returns environment variables',
    discoveredAt: '2025-12-16T09:15:00Z',
  },
  {
    source: 'cert_transparency',
    type: 'internal_url',
    title: 'Hidden Subdomains via Certificate Transparency',
    description: 'Certificate transparency logs revealed additional subdomains not in public DNS: jenkins, grafana, internal-api.',
    severity: 'MEDIUM',
    data: 'jenkins.demo-app.hemisx.com, grafana.demo-app.hemisx.com, internal-api.demo-app.hemisx.com',
    discoveredAt: '2025-12-15T14:10:00Z',
  },
]

// ─── Cloud Assets ─────────────────────────────────────────────────────────────

const MOCK_CLOUD_ASSETS: CloudAssetRecord[] = [
  {
    provider: 'aws',
    type: 's3_bucket',
    identifier: 'hemisx-demo-app-uploads',
    isPublic: true,
    region: 'us-east-2',
    issues: ['Public read access enabled', 'No encryption at rest', 'Contains user PII documents'],
  },
  {
    provider: 'aws',
    type: 's3_bucket',
    identifier: 'hemisx-demo-backups',
    isPublic: true,
    region: 'us-east-2',
    issues: ['Public list access enabled', 'Contains database backups', 'No versioning enabled'],
  },
  {
    provider: 'aws',
    type: 'ec2_instance',
    identifier: 'i-0abc123def456',
    isPublic: true,
    region: 'us-east-2',
    issues: ['Security group allows 0.0.0.0/0 on all ports', 'IMDSv1 enabled'],
  },
]

// ─── Recon Result ─────────────────────────────────────────────────────────────

const MOCK_RECON: BbrtReconResult = {
  subdomains: MOCK_SUBDOMAINS,
  dnsRecords: MOCK_DNS,
  openPorts: MOCK_PORTS,
  techStack: MOCK_TECH_STACK,
  tlsCertificates: MOCK_CERTS,
  osintFindings: MOCK_OSINT,
  cloudAssets: MOCK_CLOUD_ASSETS,
  emailAddresses: [
    'admin@hemisx.com',
    'dev@hemisx.com',
    'ops@hemisx.com',
    'support@hemisx.com',
    'cto@hemisx.com',
    'security@hemisx.com',
  ],
  whoisInfo: {
    registrar: 'Amazon Registrar, Inc.',
    createdDate: '2021-06-15',
    expiryDate: '2026-06-15',
    nameServers: ['ns-1234.awsdns-01.org', 'ns-5678.awsdns-02.co.uk'],
  },
  discoveredAt: '2025-12-15T14:00:00Z',
}

// ─── Attack Surface ───────────────────────────────────────────────────────────

const MOCK_ASSETS: AttackSurfaceAsset[] = [
  {
    id: 'asset-main', type: 'domain', label: 'demo-app.hemisx.com', url: 'https://demo-app.hemisx.com', ip: '52.14.88.201', domain: 'demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['https/443', 'http/80'], techStack: ['React 18.2', 'Next.js 14.1', 'nginx/1.24'],
    knownVulnerabilities: [], riskScore: 35, isEntryPoint: true, isCrownJewel: false,
    metadata: { hosting: 'AWS EC2', region: 'us-east-2' },
  },
  {
    id: 'asset-api', type: 'api_endpoint', label: 'api.demo-app.hemisx.com', url: 'https://api.demo-app.hemisx.com', ip: '52.14.88.202', domain: 'api.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['https/443', 'http/8080'], techStack: ['Node.js 18', 'Express 4.18'],
    knownVulnerabilities: ['bbrt-finding-003'], riskScore: 70, isEntryPoint: true, isCrownJewel: false,
    metadata: { endpoints: '47 discovered', authType: 'JWT Bearer' },
  },
  {
    id: 'asset-admin', type: 'admin_panel', label: 'admin.demo-app.hemisx.com', url: 'https://admin.demo-app.hemisx.com', ip: '52.14.88.203', domain: 'admin.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['https/443', 'ssh/22'], techStack: ['React 18.2', 'nginx/1.24'],
    knownVulnerabilities: ['bbrt-finding-001'], riskScore: 82, isEntryPoint: true, isCrownJewel: true,
    metadata: { loginType: 'username/password', mfa: 'not enforced' },
  },
  {
    id: 'asset-payments', type: 'api_endpoint', label: 'payments.demo-app.hemisx.com', url: 'https://payments.demo-app.hemisx.com', ip: '52.14.88.207', domain: 'payments.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['https/443'], techStack: ['Node.js', 'Stripe SDK'],
    knownVulnerabilities: [], riskScore: 90, isEntryPoint: false, isCrownJewel: true,
    metadata: { pciScope: 'yes', dataType: 'payment card data' },
  },
  {
    id: 'asset-db', type: 'database', label: 'PostgreSQL (52.14.88.207)', ip: '52.14.88.207',
    exposureLevel: 'INTERNAL_EXPOSED', services: ['postgresql/5432', 'redis/6379'], techStack: ['PostgreSQL 15.2', 'Redis 7.0'],
    knownVulnerabilities: ['bbrt-finding-005'], riskScore: 95, isEntryPoint: false, isCrownJewel: true,
    metadata: { dataRecords: '2.1M users', encryption: 'at rest only' },
  },
  {
    id: 'asset-jenkins', type: 'admin_panel', label: 'jenkins.demo-app.hemisx.com', url: 'https://jenkins.demo-app.hemisx.com', ip: '52.14.88.215', domain: 'jenkins.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['http/8080', 'jenkins-agent/50000'], techStack: ['Jenkins 2.414.3'],
    knownVulnerabilities: ['bbrt-finding-001'], riskScore: 95, isEntryPoint: true, isCrownJewel: false,
    metadata: { authentication: 'default credentials', pipelines: '12 active' },
  },
  {
    id: 'asset-grafana', type: 'admin_panel', label: 'grafana.demo-app.hemisx.com', url: 'https://grafana.demo-app.hemisx.com', ip: '52.14.88.216', domain: 'grafana.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['http/3000'], techStack: ['Grafana 10.1.0'],
    knownVulnerabilities: ['bbrt-finding-007'], riskScore: 68, isEntryPoint: true, isCrownJewel: false,
    metadata: { dashboards: '8 active', dataSources: 'Prometheus, PostgreSQL' },
  },
  {
    id: 'asset-staging', type: 'subdomain', label: 'staging.demo-app.hemisx.com', url: 'https://staging.demo-app.hemisx.com', ip: '52.14.88.210', domain: 'staging.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['https/443', 'http/3000'], techStack: ['Next.js 14.1', 'Docker'],
    knownVulnerabilities: [], riskScore: 72, isEntryPoint: true, isCrownJewel: false,
    metadata: { environment: 'staging', usesProductionDB: 'yes' },
  },
  {
    id: 'asset-s3', type: 'cloud_asset', label: 'S3: hemisx-demo-app-uploads', url: 'https://hemisx-demo-app-uploads.s3.us-east-2.amazonaws.com',
    exposureLevel: 'PUBLIC', services: ['https/443'], techStack: ['AWS S3'],
    knownVulnerabilities: ['bbrt-finding-002'], riskScore: 88, isEntryPoint: false, isCrownJewel: true,
    metadata: { contents: 'User uploads, PII documents', publicAccess: 'read enabled' },
  },
  {
    id: 'asset-internal-api', type: 'api_endpoint', label: 'internal-api.demo-app.hemisx.com', url: 'https://internal-api.demo-app.hemisx.com', ip: '52.14.88.230', domain: 'internal-api.demo-app.hemisx.com',
    exposureLevel: 'INTERNAL_EXPOSED', services: ['https/443', 'http/9090'], techStack: ['Node.js', 'Prometheus'],
    knownVulnerabilities: [], riskScore: 80, isEntryPoint: false, isCrownJewel: false,
    metadata: { purpose: 'Internal microservice communication', authRequired: 'API key only' },
  },
  {
    id: 'asset-legacy', type: 'subdomain', label: 'legacy.demo-app.hemisx.com', url: 'https://legacy.demo-app.hemisx.com', ip: '52.14.88.240', domain: 'legacy.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['http/80', 'https/443', 'mysql/3306'], techStack: ['Apache 2.4.41', 'MySQL 5.7.42', 'PHP 7.4'],
    knownVulnerabilities: ['bbrt-finding-005'], riskScore: 85, isEntryPoint: true, isCrownJewel: false,
    metadata: { lastUpdate: '2023-01-15', framework: 'Laravel 8' },
  },
  {
    id: 'asset-dev', type: 'subdomain', label: 'dev.demo-app.hemisx.com', url: 'https://dev.demo-app.hemisx.com', ip: '52.14.88.220', domain: 'dev.demo-app.hemisx.com',
    exposureLevel: 'PUBLIC', services: ['https/443', 'node-debug/9229'], techStack: ['Next.js 14.1', 'Node.js 18'],
    knownVulnerabilities: [], riskScore: 78, isEntryPoint: true, isCrownJewel: false,
    metadata: { environment: 'development', debugPort: 'exposed' },
  },
]

const MOCK_ATTACK_SURFACE: BbrtAttackSurface = {
  assets: MOCK_ASSETS,
  entryPoints: ['asset-main', 'asset-api', 'asset-admin', 'asset-jenkins', 'asset-grafana', 'asset-staging', 'asset-legacy', 'asset-dev'],
  crownJewels: ['asset-admin', 'asset-payments', 'asset-db', 'asset-s3'],
  exposureScore: 78,
  shadowAssets: MOCK_ASSETS.filter(a => ['asset-jenkins', 'asset-grafana', 'asset-internal-api'].includes(a.id)),
  totalAssets: MOCK_ASSETS.length,
  publicAssets: MOCK_ASSETS.filter(a => a.exposureLevel === 'PUBLIC').length,
  internalExposedAssets: MOCK_ASSETS.filter(a => a.exposureLevel === 'INTERNAL_EXPOSED').length,
  changesSinceLastScan: [
    { assetId: 'asset-dev', changeType: 'added', description: 'New development subdomain detected', detectedAt: '2025-12-14T08:00:00Z' },
    { assetId: 'asset-jenkins', changeType: 'modified', description: 'Jenkins port 50000 newly opened', detectedAt: '2025-12-13T22:00:00Z' },
  ],
  mappedAt: '2025-12-15T14:35:00Z',
}

// ─── Findings ─────────────────────────────────────────────────────────────────

const MOCK_FINDINGS: BbrtFinding[] = [
  {
    id: 'bbrt-finding-001',
    engagementId: 'bbrt-demo-001',
    type: 'MISCONFIG',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    title: 'Jenkins CI/CD Server with Default Credentials',
    description: 'The Jenkins CI/CD server at jenkins.demo-app.hemisx.com is publicly accessible and uses default admin/admin credentials. This grants full control over build pipelines, secrets, and deployment infrastructure. An attacker can execute arbitrary code on the Jenkins server and access stored credentials for AWS, GitHub, and production databases.',
    affectedAsset: 'asset-jenkins',
    affectedAssetLabel: 'jenkins.demo-app.hemisx.com',
    affectedUrl: 'https://jenkins.demo-app.hemisx.com:8080/login',
    evidence: {
      httpRequest: 'POST /j_acegi_security_check HTTP/1.1\nHost: jenkins.demo-app.hemisx.com:8080\nContent-Type: application/x-www-form-urlencoded\n\nj_username=admin&j_password=admin&Submit=Sign+in',
      httpResponse: 'HTTP/1.1 302 Found\nLocation: https://jenkins.demo-app.hemisx.com:8080/\nSet-Cookie: JSESSIONID=abc123; Path=/; HttpOnly',
      pocPayload: 'curl -u admin:admin https://jenkins.demo-app.hemisx.com:8080/script -d \'script=println "whoami".execute().text\'',
      notes: 'Successfully authenticated with admin/admin. Full Groovy script console access confirmed. Jenkins stores AWS credentials, GitHub tokens, and database passwords in its credential store.',
    },
    mitreMapping: [
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.001', subTechniqueName: 'Default Accounts', confidence: 98, evidence: 'Default admin/admin credentials accepted' },
      { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.001', subTechniqueName: 'Credentials In Files', confidence: 95, evidence: 'Jenkins credential store accessible' },
    ],
    exploitability: 'TRIVIAL',
    businessImpact: {
      score: 95,
      financialEstimate: '$2.5M - $8.0M',
      dataRecordsAtRisk: 2100000,
      dataTypes: ['PII', 'PCI', 'CONFIDENTIAL'],
      complianceFrameworksAffected: ['PCI_DSS', 'SOC2', 'HIPAA'],
      reputationalScore: 92,
      operationalImpact: 'Full CI/CD pipeline compromise — all deployments controlled by attacker',
      legalExposure: 'Regulatory fines, mandatory breach notification for 2.1M users',
    },
    status: 'OPEN',
    remediationSteps: [
      'Immediately change Jenkins admin credentials to strong, unique password',
      'Enable SAML/LDAP authentication for Jenkins — disable local accounts',
      'Restrict Jenkins access to internal network only (remove from public DNS)',
      'Rotate all credentials stored in Jenkins credential store',
      'Enable Jenkins CSRF protection and disable Groovy script console',
      'Audit Jenkins build logs for unauthorized access',
    ],
    references: ['CWE-798', 'CVE-2024-23897', 'OWASP A07:2021'],
    discoveredInPhase: 'VULN_DISCOVERY',
    cweId: 'CWE-798',
  },
  {
    id: 'bbrt-finding-002',
    engagementId: 'bbrt-demo-001',
    type: 'CLOUD_EXPOSURE',
    severity: 'CRITICAL',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    title: 'Public S3 Bucket Containing User PII Data',
    description: 'The S3 bucket "hemisx-demo-app-uploads" has public read access enabled and contains user-uploaded documents including government IDs, financial statements, and personal information for approximately 850,000 users.',
    affectedAsset: 'asset-s3',
    affectedAssetLabel: 'S3: hemisx-demo-app-uploads',
    affectedUrl: 'https://hemisx-demo-app-uploads.s3.us-east-2.amazonaws.com/',
    evidence: {
      httpRequest: 'GET / HTTP/1.1\nHost: hemisx-demo-app-uploads.s3.us-east-2.amazonaws.com',
      httpResponse: 'HTTP/1.1 200 OK\nContent-Type: application/xml\n\n<ListBucketResult>\n  <Contents><Key>uploads/user-123/passport.pdf</Key>...</Contents>\n  <Contents><Key>uploads/user-456/bank-statement.pdf</Key>...</Contents>\n  <!-- 850,000+ objects -->\n</ListBucketResult>',
      pocPayload: 'aws s3 ls s3://hemisx-demo-app-uploads/ --no-sign-request',
      notes: 'Bucket listing returns all objects. Individual objects are also publicly readable. Contains government IDs, bank statements, and tax documents.',
    },
    mitreMapping: [
      { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage', confidence: 98, evidence: 'Public S3 bucket with PII data' },
    ],
    exploitability: 'TRIVIAL',
    businessImpact: {
      score: 93,
      financialEstimate: '$5.0M - $15.0M',
      dataRecordsAtRisk: 850000,
      dataTypes: ['PII', 'CONFIDENTIAL', 'RESTRICTED'],
      complianceFrameworksAffected: ['PCI_DSS', 'SOC2', 'HIPAA', 'GDPR'],
      reputationalScore: 95,
      operationalImpact: 'Massive PII exposure — 850K user documents accessible',
      legalExposure: 'GDPR fines up to 4% of annual revenue, class-action risk, mandatory breach notification in all jurisdictions',
    },
    status: 'OPEN',
    remediationSteps: [
      'Immediately disable public access on the S3 bucket',
      'Enable S3 Block Public Access at the account level',
      'Add server-side encryption (SSE-S3 or SSE-KMS)',
      'Implement CloudFront signed URLs for authorized access only',
      'Audit access logs to determine if data was already exfiltrated',
      'Conduct breach impact assessment and legal review',
    ],
    references: ['CWE-284', 'OWASP A01:2021'],
    discoveredInPhase: 'VULN_DISCOVERY',
    cweId: 'CWE-284',
  },
  {
    id: 'bbrt-finding-003',
    engagementId: 'bbrt-demo-001',
    type: 'VULN',
    severity: 'HIGH',
    cvssScore: 8.6,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    title: 'SQL Injection in API Search Endpoint',
    description: 'The /api/v2/search endpoint is vulnerable to blind SQL injection via the "q" parameter. An attacker can extract database contents including user credentials, payment tokens, and session data.',
    affectedAsset: 'asset-api',
    affectedAssetLabel: 'api.demo-app.hemisx.com',
    affectedUrl: 'https://api.demo-app.hemisx.com/api/v2/search?q=test',
    evidence: {
      httpRequest: 'GET /api/v2/search?q=test%27+OR+1%3D1--+- HTTP/1.1\nHost: api.demo-app.hemisx.com\nAuthorization: Bearer eyJhbG...',
      httpResponse: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"results": [...all records returned...], "total": 2100847}',
      pocPayload: "GET /api/v2/search?q=test' UNION SELECT username,password,email FROM users--",
      notes: 'Blind SQL injection confirmed. Time-based extraction of admin password hash successful in 4 minutes. Parameterized queries not used.',
    },
    mitreMapping: [
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', confidence: 95, evidence: 'SQL injection in public API endpoint' },
      { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1555', techniqueName: 'Credentials from Password Stores', confidence: 85, evidence: 'Database contains user credentials extractable via SQLi' },
    ],
    exploitability: 'EASY',
    businessImpact: {
      score: 85,
      financialEstimate: '$1.5M - $4.0M',
      dataRecordsAtRisk: 2100000,
      dataTypes: ['PII', 'CONFIDENTIAL'],
      complianceFrameworksAffected: ['PCI_DSS', 'SOC2'],
      reputationalScore: 80,
      operationalImpact: 'Full database read access via SQL injection',
      legalExposure: 'Breach notification required, potential regulatory fines',
    },
    status: 'OPEN',
    remediationSteps: [
      'Use parameterized queries / prepared statements for all database interactions',
      'Implement input validation and sanitization on the "q" parameter',
      'Deploy a Web Application Firewall (WAF) rule for SQLi patterns',
      'Review all API endpoints for similar injection vulnerabilities',
      'Implement least-privilege database access for the API service account',
    ],
    references: ['CWE-89', 'OWASP A03:2021'],
    discoveredInPhase: 'VULN_DISCOVERY',
    cweId: 'CWE-89',
  },
  {
    id: 'bbrt-finding-004',
    engagementId: 'bbrt-demo-001',
    type: 'CREDENTIAL_LEAK',
    severity: 'HIGH',
    cvssScore: 8.2,
    title: 'AWS Access Keys Leaked in Public GitHub Repository',
    description: 'Active AWS access keys with broad IAM permissions (S3, EC2, RDS full access) were found in a public GitHub commit. The keys remain active and can be used to access all AWS infrastructure.',
    affectedAsset: 'asset-main',
    affectedAssetLabel: 'demo-app.hemisx.com',
    affectedUrl: 'https://github.com/hemisx-demo/app/commit/abc123',
    evidence: {
      httpRequest: 'GET /hemisx-demo/app/commit/abc123 HTTP/1.1\nHost: github.com',
      pocPayload: 'aws sts get-caller-identity --access-key AKIAIOSFODNN7EXAMPLE --secret-key wJalr...',
      commandOutput: '{\n  "UserId": "AIDAEXAMPLE",\n  "Account": "123456789012",\n  "Arn": "arn:aws:iam::123456789012:user/deploy-bot"\n}',
      notes: 'Keys are still active. IAM user "deploy-bot" has AdministratorAccess policy attached.',
    },
    mitreMapping: [
      { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', subTechniqueId: 'T1552.004', subTechniqueName: 'Private Keys', confidence: 98, evidence: 'AWS keys in public GitHub repo' },
    ],
    exploitability: 'TRIVIAL',
    businessImpact: {
      score: 88,
      financialEstimate: '$3.0M - $10.0M',
      dataRecordsAtRisk: 2100000,
      dataTypes: ['PII', 'PCI', 'CONFIDENTIAL', 'RESTRICTED'],
      complianceFrameworksAffected: ['PCI_DSS', 'SOC2', 'HIPAA'],
      reputationalScore: 85,
      operationalImpact: 'Full AWS account compromise — attacker can modify/destroy all infrastructure',
      legalExposure: 'Multi-jurisdiction breach notification, regulatory fines, customer lawsuits',
    },
    status: 'OPEN',
    remediationSteps: [
      'Immediately deactivate the compromised AWS access keys',
      'Rotate all IAM credentials in the AWS account',
      'Enable AWS CloudTrail and review logs for unauthorized access',
      'Implement GitHub secret scanning and pre-commit hooks',
      'Use IAM roles instead of long-lived access keys',
      'Apply least-privilege IAM policies to all service accounts',
    ],
    references: ['CWE-798', 'CWE-200', 'OWASP A07:2021'],
    discoveredInPhase: 'RECONNAISSANCE',
    cweId: 'CWE-798',
  },
  {
    id: 'bbrt-finding-005',
    engagementId: 'bbrt-demo-001',
    type: 'VULN',
    severity: 'HIGH',
    cvssScore: 7.5,
    title: 'PostgreSQL Database Exposed to Internet with Known CVEs',
    description: 'PostgreSQL 15.2 is directly accessible from the internet on port 5432. This version has known vulnerabilities (CVE-2023-5868, CVE-2023-5869) that allow memory disclosure and arbitrary SQL execution.',
    affectedAsset: 'asset-db',
    affectedAssetLabel: 'PostgreSQL (52.14.88.207)',
    affectedUrl: 'postgresql://52.14.88.207:5432',
    evidence: {
      commandOutput: 'nmap -sV -p 5432 52.14.88.207\n5432/tcp open  postgresql PostgreSQL 15.2\n\npsql -h 52.14.88.207 -U postgres\nPassword: [attempted common passwords]\nConnection established with postgres/postgres',
      notes: 'PostgreSQL accepts connections from any IP. Default "postgres" user has weak password. Database contains 2.1M user records including PII.',
    },
    mitreMapping: [
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', confidence: 90, evidence: 'Database exposed with known CVEs' },
    ],
    exploitability: 'EASY',
    businessImpact: {
      score: 82,
      financialEstimate: '$2.0M - $6.0M',
      dataRecordsAtRisk: 2100000,
      dataTypes: ['PII', 'CONFIDENTIAL'],
      complianceFrameworksAffected: ['PCI_DSS', 'SOC2', 'HIPAA'],
      reputationalScore: 78,
      operationalImpact: 'Direct database access — all data readable and modifiable',
      legalExposure: 'Mandatory breach disclosure for 2.1M affected users',
    },
    status: 'OPEN',
    remediationSteps: [
      'Immediately restrict database access to application servers only via security groups',
      'Update PostgreSQL to latest patched version (15.5+)',
      'Change all database passwords to strong, unique values',
      'Enable SSL/TLS for all database connections',
      'Implement database activity monitoring and alerting',
    ],
    references: ['CVE-2023-5868', 'CVE-2023-5869', 'CWE-284'],
    discoveredInPhase: 'VULN_DISCOVERY',
    cweId: 'CWE-284',
    cveId: 'CVE-2023-5869',
  },
  {
    id: 'bbrt-finding-006',
    engagementId: 'bbrt-demo-001',
    type: 'MISCONFIG',
    severity: 'MEDIUM',
    cvssScore: 5.3,
    title: 'Missing Security Headers Across All Web Assets',
    description: 'Critical security headers are missing across demo-app.hemisx.com and subdomains: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, and Strict-Transport-Security (HSTS).',
    affectedAsset: 'asset-main',
    affectedAssetLabel: 'demo-app.hemisx.com',
    affectedUrl: 'https://demo-app.hemisx.com',
    evidence: {
      httpRequest: 'GET / HTTP/1.1\nHost: demo-app.hemisx.com',
      httpResponse: 'HTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: text/html; charset=utf-8\nX-Powered-By: Express\n\n[No CSP, X-Frame-Options, HSTS, or X-Content-Type-Options headers present]',
      notes: 'All 5 critical security headers missing. X-Powered-By header leaks technology information. This enables clickjacking, MIME-type sniffing, and makes XSS exploitation easier.',
    },
    mitreMapping: [
      { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', confidence: 70, evidence: 'X-Powered-By header leaks technology stack' },
    ],
    exploitability: 'MODERATE',
    businessImpact: {
      score: 45,
      financialEstimate: '$50K - $200K',
      dataRecordsAtRisk: 0,
      dataTypes: [],
      complianceFrameworksAffected: ['SOC2'],
      reputationalScore: 30,
      operationalImpact: 'Increases attack surface for XSS, clickjacking, and MIME-type attacks',
      legalExposure: 'SOC2 control gap — may affect audit results',
    },
    status: 'OPEN',
    remediationSteps: [
      'Add Content-Security-Policy header with strict policy',
      'Add X-Content-Type-Options: nosniff',
      'Add X-Frame-Options: DENY',
      'Add Strict-Transport-Security with min 1-year max-age and includeSubDomains',
      'Remove X-Powered-By header from all responses',
      'Add Permissions-Policy to restrict browser features',
    ],
    references: ['CWE-693', 'OWASP A05:2021'],
    discoveredInPhase: 'VULN_DISCOVERY',
    cweId: 'CWE-693',
  },
  {
    id: 'bbrt-finding-007',
    engagementId: 'bbrt-demo-001',
    type: 'MISCONFIG',
    severity: 'MEDIUM',
    cvssScore: 6.5,
    title: 'Grafana Dashboard Exposed with Default Credentials',
    description: 'The Grafana monitoring dashboard at grafana.demo-app.hemisx.com is publicly accessible with default admin/admin credentials. It displays internal system metrics, database connection strings, and infrastructure topology.',
    affectedAsset: 'asset-grafana',
    affectedAssetLabel: 'grafana.demo-app.hemisx.com',
    affectedUrl: 'https://grafana.demo-app.hemisx.com:3000/login',
    evidence: {
      httpRequest: 'POST /api/login HTTP/1.1\nHost: grafana.demo-app.hemisx.com:3000\nContent-Type: application/json\n\n{"user":"admin","password":"admin"}',
      httpResponse: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":1,"message":"Logged in","orgId":1}',
      notes: 'Default credentials accepted. 8 dashboards expose: PostgreSQL connection strings, Redis passwords, internal service map, AWS resource metrics.',
    },
    mitreMapping: [
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.001', subTechniqueName: 'Default Accounts', confidence: 95, evidence: 'Grafana default admin/admin credentials' },
      { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1046', techniqueName: 'Network Service Discovery', confidence: 80, evidence: 'Grafana dashboards reveal internal topology' },
    ],
    exploitability: 'TRIVIAL',
    businessImpact: {
      score: 55,
      financialEstimate: '$200K - $500K',
      dataRecordsAtRisk: 0,
      dataTypes: ['INTERNAL', 'CONFIDENTIAL'],
      complianceFrameworksAffected: ['SOC2'],
      reputationalScore: 40,
      operationalImpact: 'Internal infrastructure topology and credentials exposed',
      legalExposure: 'Credential exposure enables lateral movement attacks',
    },
    status: 'OPEN',
    remediationSteps: [
      'Change Grafana admin password immediately',
      'Restrict Grafana access to VPN/internal network only',
      'Remove database connection strings from dashboard variables',
      'Enable Grafana authentication via SSO/SAML',
      'Review and sanitize all dashboard data sources',
    ],
    references: ['CWE-798', 'OWASP A07:2021'],
    discoveredInPhase: 'VULN_DISCOVERY',
    cweId: 'CWE-798',
  },
  {
    id: 'bbrt-finding-008',
    engagementId: 'bbrt-demo-001',
    type: 'INFO_DISCLOSURE',
    severity: 'LOW',
    cvssScore: 3.7,
    title: 'Verbose Error Messages Expose Stack Traces and Internal Paths',
    description: 'The API returns detailed Node.js stack traces on 500 errors, revealing internal file paths, dependency versions, and database query structures.',
    affectedAsset: 'asset-api',
    affectedAssetLabel: 'api.demo-app.hemisx.com',
    affectedUrl: 'https://api.demo-app.hemisx.com/api/v2/users/undefined',
    evidence: {
      httpRequest: 'GET /api/v2/users/undefined HTTP/1.1\nHost: api.demo-app.hemisx.com',
      httpResponse: 'HTTP/1.1 500 Internal Server Error\n\n{"error":"TypeError: Cannot read properties of undefined","stack":"at UserController.getUser (/app/src/controllers/user.controller.ts:42:15)\\n  at /app/node_modules/express/lib/router/route.js:144:3\\n  at /app/node_modules/sequelize/lib/model.js:2188:12","query":"SELECT * FROM users WHERE id = $1"}',
      notes: 'Stack traces reveal: Node.js Express framework, TypeScript source paths, Sequelize ORM, raw SQL query patterns. This information aids in crafting targeted attacks.',
    },
    mitreMapping: [
      { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', subTechniqueId: 'T1592.004', subTechniqueName: 'Client Configurations', confidence: 85, evidence: 'Stack traces reveal internal architecture' },
    ],
    exploitability: 'HARD',
    businessImpact: {
      score: 25,
      financialEstimate: '$10K - $50K',
      dataRecordsAtRisk: 0,
      dataTypes: [],
      complianceFrameworksAffected: [],
      reputationalScore: 15,
      operationalImpact: 'Information disclosure aids reconnaissance for targeted attacks',
      legalExposure: 'Minimal direct legal risk, but enables chained attacks',
    },
    status: 'OPEN',
    remediationSteps: [
      'Disable detailed error messages in production (set NODE_ENV=production)',
      'Implement a global error handler that returns generic error messages',
      'Log detailed errors server-side only, not in API responses',
      'Remove X-Powered-By header',
    ],
    references: ['CWE-209', 'OWASP A04:2021'],
    discoveredInPhase: 'VULN_DISCOVERY',
    cweId: 'CWE-209',
  },
]

// ─── Kill Chains ──────────────────────────────────────────────────────────────

const MOCK_KILL_CHAINS: BbrtKillChain[] = [
  {
    id: 'kc-001',
    engagementId: 'bbrt-demo-001',
    name: 'GitHub Secret Leak → Admin Panel Access → Database Exfiltration',
    objective: 'Full database exfiltration via leaked AWS credentials and admin panel compromise',
    narrative: 'An attacker discovers AWS access keys leaked in a public GitHub repository. Using these keys, they enumerate AWS resources and discover the admin panel\'s infrastructure. The leaked credentials grant IAM access to the admin panel\'s authentication backend. The attacker logs into the admin panel, accesses the database management interface, and exfiltrates 2.1 million user records including PII, payment data, and authentication credentials. The entire attack takes approximately 2-3 hours and requires no specialized tools beyond the AWS CLI and a web browser.',
    likelihood: 'VERY_HIGH',
    impact: 'CRITICAL',
    steps: [
      { seq: 1, tactic: 'Reconnaissance', tacticId: 'TA0043', technique: 'Search Open Websites/Domains', techniqueId: 'T1593', subTechnique: 'Code Repositories', subTechniqueId: 'T1593.003', action: 'Attacker discovers AWS access keys in public GitHub repository commit history', target: 'GitHub repository hemisx-demo/app', result: 'SUCCESS', evidence: 'AKIAIOSFODNN7EXAMPLE found in commit abc123', findingIds: ['bbrt-finding-004'], assetIds: ['asset-main'] },
      { seq: 2, tactic: 'Resource Development', tacticId: 'TA0042', technique: 'Obtain Capabilities', techniqueId: 'T1588', action: 'Attacker uses leaked AWS keys to enumerate IAM permissions and discover infrastructure', target: 'AWS Account 123456789012', result: 'SUCCESS', evidence: 'aws iam list-attached-user-policies reveals AdministratorAccess', findingIds: ['bbrt-finding-004'], assetIds: ['asset-main'] },
      { seq: 3, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Valid Accounts', techniqueId: 'T1078', subTechnique: 'Cloud Accounts', subTechniqueId: 'T1078.004', action: 'Attacker uses AWS credentials to access admin panel infrastructure and extract stored secrets', target: 'admin.demo-app.hemisx.com', result: 'SUCCESS', evidence: 'SSM Parameter Store contains admin panel credentials', findingIds: ['bbrt-finding-004'], assetIds: ['asset-admin'] },
      { seq: 4, tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Unsecured Credentials', techniqueId: 'T1552', action: 'Attacker extracts database connection string from admin panel configuration', target: 'Admin panel settings', result: 'SUCCESS', evidence: 'DATABASE_URL contains production credentials', findingIds: ['bbrt-finding-004', 'bbrt-finding-005'], assetIds: ['asset-admin', 'asset-db'] },
      { seq: 5, tactic: 'Exfiltration', tacticId: 'TA0010', technique: 'Exfiltration Over Web Service', techniqueId: 'T1567', action: 'Attacker connects directly to exposed PostgreSQL and dumps all user data', target: 'PostgreSQL 52.14.88.207:5432', result: 'SUCCESS', evidence: 'pg_dump extracts 2.1M records to attacker-controlled S3 bucket', findingIds: ['bbrt-finding-005'], assetIds: ['asset-db'] },
    ],
    mitreMapping: [
      { tacticId: 'TA0043', tacticName: 'Reconnaissance', techniqueId: 'T1593', techniqueName: 'Search Open Websites/Domains', subTechniqueId: 'T1593.003', subTechniqueName: 'Code Repositories', confidence: 98, evidence: 'Keys found in public GitHub repo' },
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.004', subTechniqueName: 'Cloud Accounts', confidence: 95, evidence: 'AWS credentials grant admin access' },
      { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', confidence: 90, evidence: 'Direct database access enables bulk exfiltration' },
    ],
    affectedAssets: ['asset-main', 'asset-admin', 'asset-db'],
    dataAtRisk: ['2.1M user records', 'Payment card tokens', 'Authentication credentials', 'Government ID documents'],
    estimatedTimeToExploit: '2-3 hours',
    detectionDifficulty: 'DIFFICULT',
    riskScore: 96,
  },
  {
    id: 'kc-002',
    engagementId: 'bbrt-demo-001',
    name: 'Jenkins Default Creds → Internal Pivot → Payment Data Access',
    objective: 'Access payment processing system via Jenkins CI/CD compromise',
    narrative: 'An attacker discovers the externally exposed Jenkins server with default admin/admin credentials. After gaining access to Jenkins, they access the Groovy script console to execute arbitrary commands. Through Jenkins\' stored credentials, they obtain SSH keys for the payment processing server and database passwords. The attacker pivots to the payment system and extracts credit card tokens and transaction history for 500K customers. The attack exploits the shadow asset (Jenkins was not supposed to be publicly accessible) and the CI/CD pipeline\'s over-privileged access to production systems.',
    likelihood: 'VERY_HIGH',
    impact: 'CRITICAL',
    steps: [
      { seq: 1, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Valid Accounts', techniqueId: 'T1078', subTechnique: 'Default Accounts', subTechniqueId: 'T1078.001', action: 'Attacker logs into Jenkins with default admin/admin credentials', target: 'jenkins.demo-app.hemisx.com:8080', result: 'SUCCESS', evidence: 'Login successful with admin/admin', findingIds: ['bbrt-finding-001'], assetIds: ['asset-jenkins'] },
      { seq: 2, tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Unsecured Credentials', techniqueId: 'T1552', subTechnique: 'Credentials In Files', subTechniqueId: 'T1552.001', action: 'Attacker extracts stored credentials from Jenkins credential store including SSH keys and database passwords', target: 'Jenkins Credential Store', result: 'SUCCESS', evidence: '14 credentials extracted: SSH keys, DB passwords, API tokens', findingIds: ['bbrt-finding-001'], assetIds: ['asset-jenkins'] },
      { seq: 3, tactic: 'Lateral Movement', tacticId: 'TA0008', technique: 'Remote Services', techniqueId: 'T1210', action: 'Attacker uses extracted SSH key to access payment processing server', target: 'payments.demo-app.hemisx.com', result: 'SUCCESS', evidence: 'SSH access as deploy user with sudo privileges', findingIds: ['bbrt-finding-001'], assetIds: ['asset-jenkins', 'asset-payments'] },
      { seq: 4, tactic: 'Exfiltration', tacticId: 'TA0010', technique: 'Exfiltration Over Web Service', techniqueId: 'T1567', action: 'Attacker accesses payment database and exfiltrates transaction data and card tokens', target: 'Payment database', result: 'SUCCESS', evidence: '500K payment records with card tokens extracted', findingIds: ['bbrt-finding-001'], assetIds: ['asset-payments', 'asset-db'] },
    ],
    mitreMapping: [
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts', subTechniqueId: 'T1078.001', subTechniqueName: 'Default Accounts', confidence: 98, evidence: 'Jenkins default credentials' },
      { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1210', techniqueName: 'Exploitation of Remote Services', confidence: 90, evidence: 'Pivot from Jenkins to payment server' },
      { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service', confidence: 92, evidence: 'Payment data exfiltrated' },
    ],
    affectedAssets: ['asset-jenkins', 'asset-payments', 'asset-db'],
    dataAtRisk: ['500K payment card tokens', 'Transaction history', 'Customer billing addresses', 'Merchant credentials'],
    estimatedTimeToExploit: '1-2 hours',
    detectionDifficulty: 'VERY_DIFFICULT',
    riskScore: 94,
  },
  {
    id: 'kc-003',
    engagementId: 'bbrt-demo-001',
    name: 'SQL Injection → Credential Harvesting → Account Takeover',
    objective: 'Mass account takeover via SQL injection credential extraction',
    narrative: 'An attacker exploits the SQL injection vulnerability in the public API search endpoint to extract user credentials. Using the extracted bcrypt password hashes and a GPU-accelerated cracking rig, they crack 15% of passwords within 48 hours. The attacker then uses credential stuffing to log into user accounts, including 12 admin accounts. With admin access, they modify payment settings, create backdoor accounts, and establish persistent access to the application.',
    likelihood: 'HIGH',
    impact: 'HIGH',
    steps: [
      { seq: 1, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Exploit Public-Facing Application', techniqueId: 'T1190', action: 'Attacker exploits blind SQL injection in /api/v2/search to extract user table', target: 'api.demo-app.hemisx.com', result: 'SUCCESS', evidence: "UNION SELECT query returns all user records", findingIds: ['bbrt-finding-003'], assetIds: ['asset-api'] },
      { seq: 2, tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Brute Force', techniqueId: 'T1110', subTechnique: 'Password Cracking', subTechniqueId: 'T1110.002', action: 'Attacker cracks bcrypt hashes offline — 15% success rate including 12 admin accounts', target: 'Extracted password hashes', result: 'PARTIAL', evidence: '315,000 passwords cracked out of 2.1M hashes', findingIds: ['bbrt-finding-003'], assetIds: ['asset-api'] },
      { seq: 3, tactic: 'Initial Access', tacticId: 'TA0001', technique: 'Valid Accounts', techniqueId: 'T1078', action: 'Attacker logs into application using cracked admin credentials', target: 'demo-app.hemisx.com/login', result: 'SUCCESS', evidence: 'Admin session established — full application control', findingIds: ['bbrt-finding-003'], assetIds: ['asset-main', 'asset-admin'] },
      { seq: 4, tactic: 'Impact', tacticId: 'TA0040', technique: 'Account Access Removal', techniqueId: 'T1531', action: 'Attacker modifies payment settings, creates backdoor accounts, disables MFA for compromised accounts', target: 'Admin panel', result: 'SUCCESS', evidence: 'Backdoor admin account created: support-system@hemisx.com', findingIds: ['bbrt-finding-003'], assetIds: ['asset-admin'] },
    ],
    mitreMapping: [
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', confidence: 95, evidence: 'SQL injection enables credential extraction' },
      { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force', subTechniqueId: 'T1110.002', subTechniqueName: 'Password Cracking', confidence: 85, evidence: 'Bcrypt hashes crackable at 15% rate' },
    ],
    affectedAssets: ['asset-api', 'asset-main', 'asset-admin'],
    dataAtRisk: ['315K user credentials', 'Admin access', 'Application configuration', 'Payment settings'],
    estimatedTimeToExploit: '48-72 hours',
    detectionDifficulty: 'MODERATE',
    riskScore: 82,
  },
  {
    id: 'kc-004',
    engagementId: 'bbrt-demo-001',
    name: 'S3 Bucket Exposure → PII Data Theft → Regulatory Violation',
    objective: 'Mass PII exfiltration from publicly accessible cloud storage',
    narrative: 'An attacker discovers the publicly accessible S3 bucket through cloud asset enumeration. The bucket contains user-uploaded documents including government IDs, financial statements, and tax documents for 850,000 users. The attacker downloads the entire bucket contents using the AWS CLI without any authentication. This constitutes a reportable data breach under GDPR, CCPA, and multiple state privacy laws, triggering mandatory notification to all 850,000 affected users and regulatory bodies.',
    likelihood: 'VERY_HIGH',
    impact: 'CRITICAL',
    steps: [
      { seq: 1, tactic: 'Reconnaissance', tacticId: 'TA0043', technique: 'Active Scanning', techniqueId: 'T1595', action: 'Attacker enumerates S3 buckets matching naming patterns for demo-app.hemisx.com', target: 'AWS S3', result: 'SUCCESS', evidence: 'hemisx-demo-app-uploads bucket discovered with public listing', findingIds: ['bbrt-finding-002'], assetIds: ['asset-s3'] },
      { seq: 2, tactic: 'Collection', tacticId: 'TA0009', technique: 'Data from Cloud Storage', techniqueId: 'T1530', action: 'Attacker lists and downloads all objects from the public S3 bucket', target: 'hemisx-demo-app-uploads', result: 'SUCCESS', evidence: '850K documents downloaded — passport scans, bank statements, tax returns', findingIds: ['bbrt-finding-002'], assetIds: ['asset-s3'] },
      { seq: 3, tactic: 'Impact', tacticId: 'TA0040', technique: 'Data Destruction', techniqueId: 'T1485', action: 'Regulatory violation triggered — mandatory breach notification across multiple jurisdictions', target: 'Organization reputation and compliance', result: 'SUCCESS', evidence: 'GDPR Article 33/34, CCPA Section 1798.82 breach notification required', findingIds: ['bbrt-finding-002'], assetIds: ['asset-s3'] },
    ],
    mitreMapping: [
      { tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage', confidence: 98, evidence: 'Public S3 bucket with PII data' },
      { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1485', techniqueName: 'Data Destruction', confidence: 60, evidence: 'Regulatory and reputational impact' },
    ],
    affectedAssets: ['asset-s3'],
    dataAtRisk: ['850K government ID documents', '850K financial statements', 'Tax documents', 'Personal addresses'],
    estimatedTimeToExploit: '30 minutes',
    detectionDifficulty: 'VERY_DIFFICULT',
    riskScore: 91,
  },
]

// ─── Report ───────────────────────────────────────────────────────────────────

const MOCK_COMPLIANCE_GAPS: ComplianceGap[] = [
  { framework: 'PCI_DSS', controlId: '6.5.1', controlName: 'Injection Flaws', status: 'FAIL', affectedFindingIds: ['bbrt-finding-003'], remediationNote: 'SQL injection in API search endpoint violates PCI DSS requirement for injection flaw prevention' },
  { framework: 'PCI_DSS', controlId: '2.1', controlName: 'Default Credentials', status: 'FAIL', affectedFindingIds: ['bbrt-finding-001', 'bbrt-finding-007'], remediationNote: 'Jenkins and Grafana using default credentials violates vendor-supplied default removal' },
  { framework: 'PCI_DSS', controlId: '3.4', controlName: 'Render PAN Unreadable', status: 'FAIL', affectedFindingIds: ['bbrt-finding-002'], remediationNote: 'Public S3 bucket exposes cardholder data without encryption or access controls' },
  { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical Access Security', status: 'FAIL', affectedFindingIds: ['bbrt-finding-001', 'bbrt-finding-005', 'bbrt-finding-007'], remediationNote: 'Multiple systems accessible with default or no credentials' },
  { framework: 'SOC2', controlId: 'CC6.6', controlName: 'System Boundary Protection', status: 'FAIL', affectedFindingIds: ['bbrt-finding-005'], remediationNote: 'Database ports directly exposed to internet without boundary protection' },
  { framework: 'HIPAA', controlId: '164.312(a)(1)', controlName: 'Access Control', status: 'FAIL', affectedFindingIds: ['bbrt-finding-002', 'bbrt-finding-005'], remediationNote: 'PHI accessible without authentication via public S3 bucket and exposed database' },
  { framework: 'GDPR', controlId: 'Art. 32', controlName: 'Security of Processing', status: 'FAIL', affectedFindingIds: ['bbrt-finding-002', 'bbrt-finding-003', 'bbrt-finding-004'], remediationNote: 'Inadequate technical measures — PII exposed in cloud storage, injectable APIs, and leaked credentials' },
]

const MOCK_REMEDIATION_ROADMAP: RemediationItem[] = [
  { priority: 1, title: 'Rotate Leaked AWS Credentials and Lock Down IAM', description: 'Deactivate compromised AWS keys, rotate all IAM credentials, implement least-privilege policies, and enable CloudTrail monitoring.', effort: 'LOW', impact: 'CRITICAL', affectedFindingIds: ['bbrt-finding-004'], estimatedHours: 4 },
  { priority: 2, title: 'Restrict Jenkins and Grafana to Internal Network', description: 'Remove shadow assets from public DNS, restrict to VPN-only access, change all default credentials, and implement SSO authentication.', effort: 'MEDIUM', impact: 'CRITICAL', affectedFindingIds: ['bbrt-finding-001', 'bbrt-finding-007'], estimatedHours: 8 },
  { priority: 3, title: 'Secure S3 Buckets with Block Public Access', description: 'Enable S3 Block Public Access at account level, add encryption, implement CloudFront signed URLs, and audit access logs.', effort: 'LOW', impact: 'CRITICAL', affectedFindingIds: ['bbrt-finding-002'], estimatedHours: 4 },
  { priority: 4, title: 'Fix SQL Injection and Implement WAF', description: 'Convert all queries to parameterized statements, add input validation, deploy WAF rules for SQLi patterns, and conduct full API security review.', effort: 'MEDIUM', impact: 'HIGH', affectedFindingIds: ['bbrt-finding-003'], estimatedHours: 16 },
  { priority: 5, title: 'Restrict Database Network Access', description: 'Configure security groups to allow database access only from application servers, update PostgreSQL to patched version, change all database passwords, and enable SSL.', effort: 'LOW', impact: 'HIGH', affectedFindingIds: ['bbrt-finding-005'], estimatedHours: 6 },
  { priority: 6, title: 'Implement Security Headers Across All Web Assets', description: 'Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and Permissions-Policy headers to all web servers.', effort: 'LOW', impact: 'MEDIUM', affectedFindingIds: ['bbrt-finding-006'], estimatedHours: 4 },
  { priority: 7, title: 'Disable Verbose Error Messages in Production', description: 'Configure Express error handler to return generic messages, log details server-side only, remove X-Powered-By header.', effort: 'LOW', impact: 'LOW', affectedFindingIds: ['bbrt-finding-008'], estimatedHours: 2 },
]

const MOCK_ATTACK_SURFACE_STATS: BbrtAttackSurfaceStats = {
  totalAssets: 12,
  publicAssets: 10,
  shadowAssets: 3,
  entryPoints: 8,
  crownJewels: 4,
  exposureScore: 78,
  openPorts: MOCK_PORTS.length,
  subdomains: MOCK_SUBDOMAINS.length,
}

const MOCK_FINDING_STATS: BbrtFindingStats = {
  total: 8,
  critical: 2,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  byType: {
    MISCONFIG: 3,
    CLOUD_EXPOSURE: 1,
    VULN: 2,
    CREDENTIAL_LEAK: 1,
    INFO_DISCLOSURE: 1,
    RECON_EXPOSURE: 0,
    SUPPLY_CHAIN: 0,
    LLM_VULN: 0,
    CERT_ISSUE: 0,
    AUTH_WEAKNESS: 0,
  },
}

const MOCK_REPORT: BbrtReport = {
  id: 'report-001',
  engagementId: 'bbrt-demo-001',
  executiveSummary: `## Executive Summary

HemisX conducted a comprehensive black-box red team assessment of **demo-app.hemisx.com** and its associated infrastructure from December 15-16, 2025. The assessment simulated a real-world external attacker with zero prior knowledge of the target systems.

### Critical Findings

The assessment revealed **8 vulnerabilities** (2 Critical, 3 High, 2 Medium, 1 Low) across **12 discovered assets**. Four complete attack chains were identified that could lead to full infrastructure compromise, mass data exfiltration, and payment system access.

**The most critical finding is the combination of leaked AWS credentials in a public GitHub repository and a Jenkins CI/CD server accessible with default credentials.** Together, these provide an attacker with a direct path to complete infrastructure compromise within 1-2 hours.

### Key Risk Indicators

- **Exposure Score: 78/100** — Significantly above industry average (45) for fintech companies
- **3 Shadow Assets** discovered that were not intended to be publicly accessible (Jenkins, Grafana, Internal API)
- **2.1 million user records** at risk across multiple attack paths
- **850,000 PII documents** in publicly accessible S3 bucket
- **4 attack chains** identified, 2 rated as Critical impact with Very High likelihood

### Immediate Actions Required

1. **Rotate all leaked AWS credentials** (4 hours)
2. **Restrict Jenkins and Grafana to internal access only** (8 hours)
3. **Enable S3 Block Public Access** (4 hours)
4. **Fix SQL injection in API search endpoint** (16 hours)

The total estimated remediation effort is **44 hours** across all findings. We recommend completing Critical and High priority items within 72 hours.`,
  overallRiskScore: 82,
  riskLevel: 'CRITICAL',
  attackSurfaceStats: MOCK_ATTACK_SURFACE_STATS,
  findingStats: MOCK_FINDING_STATS,
  killChainCount: 4,
  topKillChains: MOCK_KILL_CHAINS.slice(0, 2),
  criticalFindings: MOCK_FINDINGS.filter(f => f.severity === 'CRITICAL'),
  complianceGaps: MOCK_COMPLIANCE_GAPS,
  remediationRoadmap: MOCK_REMEDIATION_ROADMAP,
  aiInsights: `### AI Threat Intelligence Analysis

**Threat Actor Profile:** Based on the discovered attack surface, this target is attractive to both **financially-motivated cybercriminal groups** (APT-FIN category) and **automated opportunistic scanners**. The exposed Jenkins server with default credentials would be discovered by automated scanning within 24-48 hours of exposure.

**Attack Likelihood Assessment:** Given the combination of leaked credentials, exposed administrative panels, and public cloud storage, we estimate a **>90% probability** that at least one of these attack paths has already been discovered and potentially exploited by threat actors. The GitHub credential leak has been public for at least 30 days based on commit timestamps.

**Industry Context:** For a fintech company processing payment data, this risk profile is in the **92nd percentile** — significantly worse than industry peers. The average fintech company in our dataset has 2.3 critical findings; this assessment found 2 critical findings with significantly higher business impact due to the combination of credential leaks and cloud misconfigurations.

**Recommended Security Posture Improvements:**
- Implement continuous attack surface monitoring to detect shadow assets within hours, not months
- Deploy GitHub secret scanning with pre-commit hooks to prevent future credential leaks
- Establish a CI/CD security baseline — Jenkins, GitHub Actions, and deployment pipelines should never be publicly accessible
- Implement Zero Trust architecture for internal services — assume the network perimeter is already compromised`,
  generatedAt: '2025-12-16T10:30:00Z',
}

// ─── Main Engagement Export ───────────────────────────────────────────────────

export const MOCK_BBRT_ENGAGEMENT: BbrtEngagement = {
  id: 'bbrt-demo-001',
  orgId: 'org-demo',
  name: 'HemisX Demo App — External Assessment',
  targetConfig: {
    targetDomain: 'demo-app.hemisx.com',
    targetIPs: ['52.14.88.201'],
    targetScope: ['*.demo-app.hemisx.com'],
    excludedPaths: [],
    engagementType: 'full',
    complianceRequirements: ['PCI_DSS', 'SOC2', 'HIPAA', 'GDPR'],
    businessContext: {
      industry: 'fintech',
      dataTypes: ['PII', 'PCI', 'CONFIDENTIAL', 'PHI'],
      userCount: '1K-10K',
      revenueRange: '$10M-100M',
      criticalSystems: ['Payment API', 'User Database', 'Admin Panel', 'CI/CD Pipeline'],
    },
  },
  status: 'COMPLETED',
  progress: 100,
  currentPhase: 'complete',
  reconResult: MOCK_RECON,
  attackSurface: MOCK_ATTACK_SURFACE,
  findings: MOCK_FINDINGS,
  killChains: MOCK_KILL_CHAINS,
  report: MOCK_REPORT,
  summary: {
    totalAssets: 12,
    totalFindings: 8,
    criticalFindings: 2,
    highFindings: 3,
    mediumFindings: 2,
    lowFindings: 1,
    totalKillChains: 4,
    overallRiskScore: 82,
    exposureScore: 78,
  },
  createdAt: '2025-12-15T13:00:00Z',
  startedAt: '2025-12-15T13:05:00Z',
  completedAt: '2025-12-16T10:30:00Z',
}

// Re-export individual mock data pieces for components that need them directly
export const MOCK_BBRT_RECON = MOCK_RECON
export const MOCK_BBRT_ATTACK_SURFACE = MOCK_ATTACK_SURFACE
export const MOCK_BBRT_FINDINGS = MOCK_FINDINGS
export const MOCK_BBRT_KILL_CHAINS = MOCK_KILL_CHAINS
export const MOCK_BBRT_REPORT = MOCK_REPORT
