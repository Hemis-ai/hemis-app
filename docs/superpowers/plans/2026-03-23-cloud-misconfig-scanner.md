# Cloud Misconfiguration Scanner Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade AWS cloud misconfiguration scanner with 65 checks across IAM/Data/Network, cross-account IAM role connection, risk-narrative findings, compliance mapping, IaC remediation, and a 6-tab UI.

**Architecture:** Follow exact WBRT/DAST patterns — in-memory Map stores in orchestrator, NextRequest/NextResponse API routes, `'use client'` page with CSS variables and mock data pre-loaded. No database required — works in demo mode out of the box.

**Tech Stack:** Next.js 15 App Router, TypeScript, AWS SDK v3 (read-only, optional), in-memory stores, CSS variables, mock data for demo mode.

---

## File Map

| File | Purpose |
|---|---|
| `src/lib/types/cloud-scanner.ts` | All Cloud Scanner types |
| `src/lib/mock-data/cloud-scanner.ts` | Realistic mock AWS account with 20+ findings |
| `src/lib/cloud-scanner/checks/iam-checks.ts` | 25 IAM check definitions |
| `src/lib/cloud-scanner/checks/data-checks.ts` | 20 data exposure check definitions |
| `src/lib/cloud-scanner/checks/network-checks.ts` | 20 network check definitions |
| `src/lib/cloud-scanner/aws-connector.ts` | STS assume-role + SDK client factory |
| `src/lib/cloud-scanner/risk-chainer.ts` | Compound attack path detection |
| `src/lib/cloud-scanner/compliance-mapper.ts` | CIS/PCI-DSS/SOC2/HIPAA mappings |
| `src/lib/cloud-scanner/remediation-generator.ts` | CLI/Terraform/CloudFormation fix code |
| `src/lib/cloud-scanner/scan-orchestrator.ts` | 5-phase pipeline orchestrator |
| `src/app/api/cloud/connect/route.ts` | POST: save role ARN + test connection |
| `src/app/api/cloud/scans/route.ts` | POST: start scan, GET: list scans |
| `src/app/api/cloud/scans/[id]/route.ts` | GET: scan detail |
| `src/app/api/cloud/scans/[id]/progress/route.ts` | GET: poll progress |
| `src/app/api/cloud/findings/[id]/route.ts` | GET: findings list, PATCH: mark fixed |
| `src/app/api/cloud/inventory/[id]/route.ts` | GET: discovered resources |
| `src/app/api/cloud/compliance/[id]/route.ts` | GET: compliance scores per framework |
| `src/app/api/cloud/remediation/[id]/route.ts` | GET: prioritized fix queue |
| `src/app/(dashboard)/dashboard/hemis/cloud/page.tsx` | Full 6-tab UI |

---

## Task 1: Type Definitions

**Files:**
- Create: `src/lib/types/cloud-scanner.ts`

- [ ] **Step 1: Create the types file**

```typescript
// src/lib/types/cloud-scanner.ts
// HemisX Cloud Misconfiguration Scanner — Type Definitions

// ─── Enums ──────────────────────────────────────────────────────────────────
export type CloudScanStatus =
  | 'CREATED'
  | 'CONNECTING'
  | 'DISCOVERING'
  | 'SCANNING_IAM'
  | 'SCANNING_DATA'
  | 'SCANNING_NETWORK'
  | 'ANALYZING'
  | 'COMPLETED'
  | 'FAILED'

export type CloudProvider = 'AWS' | 'GCP' | 'AZURE'
export type CloudFindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type CloudFindingStatus = 'OPEN' | 'IN_PROGRESS' | 'REMEDIATED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE'
export type CloudCheckCategory = 'IAM' | 'DATA' | 'NETWORK'
export type ComplianceFramework = 'CIS' | 'PCI_DSS' | 'SOC2' | 'HIPAA'
export type FixEffort = '5min' | '1hr' | '1day' | '1week'

// ─── Connection ──────────────────────────────────────────────────────────────
export interface CloudConnection {
  id: string
  orgId: string
  provider: CloudProvider
  accountId: string           // AWS Account ID (12 digits)
  accountAlias?: string       // Human-readable alias
  roleArn: string             // arn:aws:iam::ACCOUNT:role/HemisXScannerRole
  externalId: string          // Confused-deputy protection
  regions: string[]           // Discovered active regions
  connectedAt: string
  lastScannedAt?: string
  status: 'CONNECTED' | 'ERROR' | 'PENDING'
  errorMessage?: string
}

// ─── Scan ────────────────────────────────────────────────────────────────────
export interface CloudScan {
  id: string
  connectionId: string
  accountId: string
  accountAlias?: string
  status: CloudScanStatus
  progress: number            // 0-100
  currentPhase: string
  startedAt: string
  completedAt?: string
  duration?: number           // ms
  riskScore: number           // 0-100 (100 = worst)
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  summary: CloudScanSummary
  findings: CloudFinding[]
  inventory: CloudInventory
  complianceScores: ComplianceScore[]
  attackScenarios: AttackScenario[]
  remediationQueue: RemediationItem[]
}

export interface CloudScanSummary {
  totalFindings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  byCategory: Record<CloudCheckCategory, number>
  estimatedBreachCost: number   // USD
  resourcesScanned: number
  checksRun: number
  checksPassed: number
  checksFailed: number
}

// ─── Progress ────────────────────────────────────────────────────────────────
export interface CloudScanProgress {
  scanId: string
  status: CloudScanStatus
  progress: number
  currentPhase: string
  message: string
  timestamp: string
}

// ─── Finding ─────────────────────────────────────────────────────────────────
export interface CloudFinding {
  id: string
  checkId: string             // e.g. 'IAM-001'
  category: CloudCheckCategory
  severity: CloudFindingSeverity
  status: CloudFindingStatus
  title: string
  resourceId: string          // ARN or resource identifier
  resourceType: string        // 'AWS::S3::Bucket', 'AWS::IAM::User', etc.
  resourceName: string        // Human-readable name
  region: string
  // Risk narrative (the differentiator)
  riskNarrative: string       // Business-context explanation
  attackVector: string        // How an attacker exploits this
  estimatedImpact: string     // Financial/data impact
  // Compliance
  complianceMappings: ComplianceMapping[]
  // Remediation
  fixEffort: FixEffort
  remediation: RemediationDetail
  // Chaining
  chainIds?: string[]         // IDs of attack scenarios this feeds into
  detectedAt: string
  lastSeenAt: string
}

export interface ComplianceMapping {
  framework: ComplianceFramework
  controlId: string           // 'CIS 1.4', 'PCI-DSS 8.3.1'
  controlName: string
  status: 'FAIL' | 'PARTIAL'
}

export interface RemediationDetail {
  summary: string
  console: string             // Step-by-step AWS Console instructions
  cli: string                 // AWS CLI command(s)
  terraform: string           // Terraform HCL snippet
  cloudformation: string      // CloudFormation YAML snippet
  estimatedMinutes: number
}

// ─── Attack Scenarios (Risk Chaining) ────────────────────────────────────────
export interface AttackScenario {
  id: string
  title: string
  severity: CloudFindingSeverity
  likelihood: 'HIGH' | 'MEDIUM' | 'LOW'
  narrative: string           // Full attacker story
  steps: AttackScenarioStep[]
  findingIds: string[]        // Which findings chain together
  estimatedBreachCost: number // USD
  affectedDataTypes: string[]
  complianceImpact: ComplianceFramework[]
}

export interface AttackScenarioStep {
  seq: number
  action: string
  findingId?: string
  technique: string           // e.g. 'Credential Theft via IMDSv1'
}

// ─── Inventory ───────────────────────────────────────────────────────────────
export interface CloudInventory {
  ec2Instances: CloudResource[]
  s3Buckets: CloudResource[]
  rdsInstances: CloudResource[]
  iamUsers: CloudResource[]
  iamRoles: CloudResource[]
  lambdaFunctions: CloudResource[]
  securityGroups: CloudResource[]
  vpcs: CloudResource[]
  totalResources: number
}

export interface CloudResource {
  id: string
  arn: string
  name: string
  type: string
  region: string
  tags: Record<string, string>
  securityStatus: 'CLEAN' | 'WARNING' | 'CRITICAL'
  findingIds: string[]
}

// ─── Compliance ───────────────────────────────────────────────────────────────
export interface ComplianceScore {
  framework: ComplianceFramework
  score: number               // 0-100 (100 = fully compliant)
  passed: number
  failed: number
  total: number
  gaps: ComplianceGap[]
}

export interface ComplianceGap {
  controlId: string
  controlName: string
  status: 'FAIL' | 'PARTIAL'
  findingIds: string[]
  severity: CloudFindingSeverity
}

// ─── Remediation Queue ────────────────────────────────────────────────────────
export interface RemediationItem {
  priority: number
  findingId: string
  title: string
  severity: CloudFindingSeverity
  effort: FixEffort
  estimatedMinutes: number
  impactScore: number         // 0-100 (100 = fix this first)
  category: CloudCheckCategory
  status: CloudFindingStatus
}

// ─── Check Definition ─────────────────────────────────────────────────────────
export interface CloudCheck {
  id: string                  // 'IAM-001'
  category: CloudCheckCategory
  title: string
  description: string
  severity: CloudFindingSeverity
  resourceType: string
  complianceMappings: Omit<ComplianceMapping, 'status'>[]
  fixEffort: FixEffort
  estimatedMinutes: number
}
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd /Users/sai/Documents/GitHub/Hemis/hemis-app
npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors related to `cloud-scanner.ts`

---

## Task 2: Mock Data

**Files:**
- Create: `src/lib/mock-data/cloud-scanner.ts`

- [ ] **Step 1: Create mock data file**

```typescript
// src/lib/mock-data/cloud-scanner.ts
import type {
  CloudScan,
  CloudFinding,
  CloudInventory,
  ComplianceScore,
  AttackScenario,
  RemediationItem,
  CloudConnection,
} from '@/lib/types/cloud-scanner'

// ─── Connection ───────────────────────────────────────────────────────────────
export const MOCK_CLOUD_CONNECTION: CloudConnection = {
  id: 'conn-aws-demo-001',
  orgId: 'org-demo',
  provider: 'AWS',
  accountId: '123456789012',
  accountAlias: 'acme-production',
  roleArn: 'arn:aws:iam::123456789012:role/HemisXScannerRole',
  externalId: 'hemisx-ext-abc123',
  regions: ['us-east-1', 'us-west-2', 'eu-west-1'],
  connectedAt: '2026-03-20T08:00:00Z',
  lastScannedAt: '2026-03-23T10:00:00Z',
  status: 'CONNECTED',
}

// ─── Findings ─────────────────────────────────────────────────────────────────
export const MOCK_CLOUD_FINDINGS: CloudFinding[] = [
  // ── IAM CRITICAL ──
  {
    id: 'finding-iam-001',
    checkId: 'IAM-001',
    category: 'IAM',
    severity: 'CRITICAL',
    status: 'OPEN',
    title: 'Root Account Has Active Access Keys',
    resourceId: 'arn:aws:iam::123456789012:root',
    resourceType: 'AWS::IAM::Root',
    resourceName: 'Root Account',
    region: 'global',
    riskNarrative: 'Your AWS root account has active programmatic access keys. The root account has unrestricted access to every resource in your AWS account — there are no IAM permission boundaries that can contain it. If these keys are ever exposed (via a code commit, S3 bucket leak, or employee device), an attacker gains permanent, irrevocable full-account access including the ability to delete all resources, exfiltrate all data, and create backdoor IAM users before you can respond.',
    attackVector: 'Attacker finds root access key in GitHub commit or exposed S3 object → calls aws sts get-caller-identity to validate → creates new IAM admin user → deletes CloudTrail to cover tracks → begins full account takeover.',
    estimatedImpact: 'Full AWS account compromise. Estimated recovery cost: $2.1M+ (includes incident response, data recovery, regulatory fines, customer notification).',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 1.4', controlName: 'Ensure no root account access key exists', status: 'FAIL' },
      { framework: 'PCI_DSS', controlId: 'PCI-DSS 7.1', controlName: 'Limit access to system components', status: 'FAIL' },
      { framework: 'SOC2', controlId: 'CC6.3', controlName: 'Logical access controls', status: 'FAIL' },
    ],
    fixEffort: '5min',
    remediation: {
      summary: 'Delete root account access keys immediately. Root should only be used via console with MFA.',
      console: '1. Sign in as root → My Security Credentials\n2. Expand "Access keys"\n3. Click Delete on each active key\n4. Enable MFA on root if not already done',
      cli: '# Cannot delete root keys via CLI — must use console\n# But verify with:\naws iam get-account-summary | grep AccountAccessKeysPresent',
      terraform: '# Terraform cannot manage root account keys\n# Use AWS Config rule to detect:\nresource "aws_config_rule" "root_account_mfa" {\n  name = "root-account-mfa-enabled"\n  source {\n    owner             = "AWS"\n    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"\n  }\n}',
      cloudformation: 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  RootMFAConfigRule:\n    Type: AWS::Config::ConfigRule\n    Properties:\n      ConfigRuleName: root-account-mfa-enabled\n      Source:\n        Owner: AWS\n        SourceIdentifier: ROOT_ACCOUNT_MFA_ENABLED',
      estimatedMinutes: 5,
    },
    chainIds: ['scenario-001'],
    detectedAt: '2026-03-23T10:05:00Z',
    lastSeenAt: '2026-03-23T10:05:00Z',
  },
  {
    id: 'finding-iam-002',
    checkId: 'IAM-003',
    category: 'IAM',
    severity: 'CRITICAL',
    status: 'OPEN',
    title: 'IAM Users with Console Access and No MFA (4 users)',
    resourceId: 'arn:aws:iam::123456789012:user/john.smith',
    resourceType: 'AWS::IAM::User',
    resourceName: 'john.smith, sarah.jones, dev-deploy, ci-bot',
    region: 'global',
    riskNarrative: '4 IAM users have AWS Console access but no Multi-Factor Authentication. A compromised password — from phishing, credential stuffing, or a leaked .env file — gives an attacker full access to all services these users can access. Without MFA, there is no second factor to stop account takeover.',
    attackVector: 'Attacker purchases credential dump from dark web → tests against AWS console → john.smith password works → accesses S3 buckets, RDS databases, and Lambda functions with no MFA challenge.',
    estimatedImpact: 'Account takeover for 4 users. If any hold admin or S3 access: full data breach potential. Est. $340K per breach (IBM 2024).',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 1.10', controlName: 'Ensure MFA is enabled for all IAM users with console access', status: 'FAIL' },
      { framework: 'PCI_DSS', controlId: 'PCI-DSS 8.3.1', controlName: 'MFA for all non-console administrative access', status: 'FAIL' },
      { framework: 'HIPAA', controlId: 'HIPAA 164.312(d)', controlName: 'Person or entity authentication', status: 'FAIL' },
    ],
    fixEffort: '1hr',
    remediation: {
      summary: 'Enforce MFA for all IAM users with console access. Use IAM policy to deny all actions when MFA not present.',
      console: '1. IAM → Users → select user\n2. Security credentials tab → Assigned MFA device → Manage\n3. Follow virtual MFA setup\n4. Repeat for all 4 users',
      cli: 'aws iam create-virtual-mfa-device --virtual-mfa-device-name john.smith-mfa --outfile /tmp/QRCode.png --bootstrap-method QRCodePNG\n# Then have user scan QR code and activate',
      terraform: 'resource "aws_iam_policy" "require_mfa" {\n  name = "RequireMFA"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n      Sid    = "DenyWithoutMFA"\n      Effect = "Deny"\n      NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "sts:GetSessionToken"]\n      Resource = "*"\n      Condition = {\n        BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }\n      }\n    }]\n  })\n}',
      cloudformation: 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  RequireMFAPolicy:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n      ManagedPolicyName: RequireMFA\n      PolicyDocument:\n        Version: "2012-10-17"\n        Statement:\n          - Sid: DenyWithoutMFA\n            Effect: Deny\n            NotAction:\n              - iam:CreateVirtualMFADevice\n              - iam:EnableMFADevice\n              - sts:GetSessionToken\n            Resource: "*"\n            Condition:\n              BoolIfExists:\n                "aws:MultiFactorAuthPresent": "false"',
      estimatedMinutes: 60,
    },
    chainIds: ['scenario-001'],
    detectedAt: '2026-03-23T10:05:00Z',
    lastSeenAt: '2026-03-23T10:05:00Z',
  },
  // ── DATA CRITICAL ──
  {
    id: 'finding-data-001',
    checkId: 'DATA-001',
    category: 'DATA',
    severity: 'CRITICAL',
    status: 'OPEN',
    title: 'S3 Bucket "prod-customer-uploads" Publicly Readable',
    resourceId: 'arn:aws:s3:::prod-customer-uploads',
    resourceType: 'AWS::S3::Bucket',
    resourceName: 'prod-customer-uploads',
    region: 'us-east-1',
    riskNarrative: 'Your S3 bucket prod-customer-uploads is publicly readable by anyone on the internet with no authentication required. This bucket contains 14,832 objects including customer profile photos, government ID documents, and signed contracts. Any person can enumerate the bucket with aws s3 ls and download all content in minutes. This data likely contains PII covered by GDPR and CCPA.',
    attackVector: 'curl https://prod-customer-uploads.s3.amazonaws.com → lists all objects → wget in a loop → full data exfiltration in ~8 minutes. No credentials required.',
    estimatedImpact: 'PII data breach affecting all customers. GDPR fine up to 4% annual revenue. Est. total cost: $1.2M (fines + notification + remediation).',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 2.1.5', controlName: 'Ensure S3 buckets are not publicly accessible', status: 'FAIL' },
      { framework: 'PCI_DSS', controlId: 'PCI-DSS 3.4', controlName: 'Protect stored cardholder data', status: 'FAIL' },
      { framework: 'SOC2', controlId: 'CC6.1', controlName: 'Logical and physical access controls', status: 'FAIL' },
      { framework: 'HIPAA', controlId: 'HIPAA 164.312(a)', controlName: 'Access control', status: 'FAIL' },
    ],
    fixEffort: '5min',
    remediation: {
      summary: 'Enable S3 Block Public Access at both bucket and account level. Review bucket policy for any explicit Allow to \'*\'.',
      console: '1. S3 → prod-customer-uploads → Permissions\n2. Block public access → Edit → Enable all 4 checkboxes → Save\n3. Also set at account level: S3 → Block Public Access (account settings)',
      cli: 'aws s3api put-public-access-block \\\n  --bucket prod-customer-uploads \\\n  --public-access-block-configuration \\\n  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
      terraform: 'resource "aws_s3_bucket_public_access_block" "prod_customer_uploads" {\n  bucket = "prod-customer-uploads"\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}',
      cloudformation: 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  ProdCustomerUploadsBlock:\n    Type: AWS::S3::BucketPolicy\n    Properties:\n      Bucket: prod-customer-uploads\n      PolicyDocument:\n        Statement:\n          - Effect: Deny\n            Principal: "*"\n            Action: "s3:GetObject"\n            Resource: "arn:aws:s3:::prod-customer-uploads/*"\n            Condition:\n              Bool:\n                "aws:SecureTransport": "false"',
      estimatedMinutes: 5,
    },
    chainIds: ['scenario-001', 'scenario-002'],
    detectedAt: '2026-03-23T10:08:00Z',
    lastSeenAt: '2026-03-23T10:08:00Z',
  },
  {
    id: 'finding-data-002',
    checkId: 'DATA-003',
    category: 'DATA',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'RDS Instance "prod-postgres" Publicly Accessible',
    resourceId: 'arn:aws:rds:us-east-1:123456789012:db:prod-postgres',
    resourceType: 'AWS::RDS::DBInstance',
    resourceName: 'prod-postgres',
    region: 'us-east-1',
    riskNarrative: 'Your production PostgreSQL database is directly accessible from the internet on port 5432. While authentication is still required, a publicly accessible database is exposed to brute-force attacks, SQL injection probes, and exploitation of any future PostgreSQL CVEs. Databases should never be directly internet-accessible — they should only be reachable from within your VPC.',
    attackVector: 'nmap scan discovers open port 5432 → attacker runs pg_brute or Hydra against it → weak password found → full database access.',
    estimatedImpact: 'Database credential brute force leading to full data exfiltration. Est. $680K breach cost.',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 2.3.1', controlName: 'Ensure RDS instances are not publicly accessible', status: 'FAIL' },
      { framework: 'PCI_DSS', controlId: 'PCI-DSS 1.3', controlName: 'Prohibit direct public access to cardholder data environment', status: 'FAIL' },
    ],
    fixEffort: '1hr',
    remediation: {
      summary: 'Disable public accessibility on RDS instance. Ensure it\'s in a private subnet with no internet gateway route.',
      console: '1. RDS → Databases → prod-postgres → Modify\n2. Connectivity → Public access → No\n3. Apply immediately',
      cli: 'aws rds modify-db-instance \\\n  --db-instance-identifier prod-postgres \\\n  --no-publicly-accessible \\\n  --apply-immediately',
      terraform: 'resource "aws_db_instance" "prod_postgres" {\n  # ... existing config ...\n  publicly_accessible = false\n  db_subnet_group_name = aws_db_subnet_group.private.name\n}',
      cloudformation: 'ProdPostgres:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    PubliclyAccessible: false\n    DBSubnetGroupName: !Ref PrivateSubnetGroup',
      estimatedMinutes: 30,
    },
    chainIds: ['scenario-002'],
    detectedAt: '2026-03-23T10:08:00Z',
    lastSeenAt: '2026-03-23T10:08:00Z',
  },
  // ── NETWORK CRITICAL ──
  {
    id: 'finding-net-001',
    checkId: 'NET-001',
    category: 'NETWORK',
    severity: 'CRITICAL',
    status: 'OPEN',
    title: 'Security Group Allows SSH from 0.0.0.0/0 (3 groups)',
    resourceId: 'sg-0abc123,sg-0def456,sg-0ghi789',
    resourceType: 'AWS::EC2::SecurityGroup',
    resourceName: 'web-servers-sg, bastion-sg, dev-sg',
    region: 'us-east-1',
    riskNarrative: '3 security groups allow inbound SSH (port 22) from any IP address on the internet. This exposes your EC2 instances to automated SSH brute-force attacks, which run constantly across the entire IPv4 space. Shodan and similar scanners have already indexed these open ports. If any EC2 instance runs an outdated OpenSSH version, this becomes a zero-click exploit vector.',
    attackVector: 'Masscan finds open port 22 → Hydra brute-forces SSH with rockyou.txt → gain shell access → enumerate instance role → find S3 credentials in instance metadata.',
    estimatedImpact: 'EC2 instance compromise → lateral movement → potential full environment takeover. Est. $890K.',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 5.2', controlName: 'Ensure no security groups allow ingress from 0.0.0.0/0 to SSH', status: 'FAIL' },
      { framework: 'PCI_DSS', controlId: 'PCI-DSS 1.3.1', controlName: 'Restrict inbound traffic to only that which is necessary', status: 'FAIL' },
    ],
    fixEffort: '5min',
    remediation: {
      summary: 'Restrict SSH to specific IP ranges (your office/VPN CIDR). Use AWS Systems Manager Session Manager as SSH alternative with no open ports.',
      console: '1. EC2 → Security Groups → select group\n2. Inbound rules → Edit → change 0.0.0.0/0 to your IP/CIDR\n3. Or delete the rule and use SSM Session Manager',
      cli: '# Remove the overly-broad rule\naws ec2 revoke-security-group-ingress \\\n  --group-id sg-0abc123 \\\n  --protocol tcp \\\n  --port 22 \\\n  --cidr 0.0.0.0/0\n\n# Add restricted rule (replace with your CIDR)\naws ec2 authorize-security-group-ingress \\\n  --group-id sg-0abc123 \\\n  --protocol tcp \\\n  --port 22 \\\n  --cidr 203.0.113.0/24',
      terraform: 'resource "aws_security_group_rule" "ssh_restricted" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["203.0.113.0/24"]  # Replace with your CIDR\n  security_group_id = aws_security_group.web_servers.id\n}',
      cloudformation: 'WebServersSG:\n  Type: AWS::EC2::SecurityGroup\n  Properties:\n    SecurityGroupIngress:\n      - IpProtocol: tcp\n        FromPort: 22\n        ToPort: 22\n        CidrIp: 203.0.113.0/24  # Replace with your CIDR',
      estimatedMinutes: 10,
    },
    chainIds: ['scenario-002'],
    detectedAt: '2026-03-23T10:12:00Z',
    lastSeenAt: '2026-03-23T10:12:00Z',
  },
  {
    id: 'finding-net-002',
    checkId: 'NET-004',
    category: 'NETWORK',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'VPC Flow Logs Disabled (2 VPCs)',
    resourceId: 'vpc-0abc123,vpc-0def456',
    resourceType: 'AWS::EC2::VPC',
    resourceName: 'prod-vpc, staging-vpc',
    region: 'us-east-1',
    riskNarrative: 'VPC Flow Logs are disabled on your production and staging VPCs. Flow logs capture all network traffic metadata — without them, you have zero visibility into who is connecting to your infrastructure, failed connection attempts, or data exfiltration patterns. This is the network equivalent of turning off your security cameras.',
    attackVector: 'Attacker exfiltrates data over HTTPS to an external server — without flow logs, this goes completely undetected. Incident response after a breach becomes forensically impossible.',
    estimatedImpact: 'Blind to all network-based attacks. DFIR costs increase 3x without flow logs. Direct compliance violation.',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 3.9', controlName: 'Ensure VPC flow logging is enabled in all VPCs', status: 'FAIL' },
      { framework: 'SOC2', controlId: 'CC7.2', controlName: 'Monitor system components for anomalies', status: 'FAIL' },
    ],
    fixEffort: '5min',
    remediation: {
      summary: 'Enable VPC Flow Logs to CloudWatch Logs or S3 for all VPCs. Retain logs for minimum 90 days.',
      console: '1. VPC → Your VPCs → select VPC → Flow logs tab\n2. Create flow log → All traffic → CloudWatch Logs\n3. Create new log group: /aws/vpc/flowlogs/prod',
      cli: 'aws ec2 create-flow-logs \\\n  --resource-type VPC \\\n  --resource-ids vpc-0abc123 \\\n  --traffic-type ALL \\\n  --log-destination-type cloud-watch-logs \\\n  --log-group-name /aws/vpc/flowlogs/prod \\\n  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/FlowLogsRole',
      terraform: 'resource "aws_flow_log" "prod_vpc" {\n  vpc_id          = aws_vpc.prod.id\n  traffic_type    = "ALL"\n  iam_role_arn    = aws_iam_role.flow_logs.arn\n  log_destination = aws_cloudwatch_log_group.flow_logs.arn\n}',
      cloudformation: 'ProdVPCFlowLog:\n  Type: AWS::EC2::FlowLog\n  Properties:\n    ResourceId: !Ref ProdVPC\n    ResourceType: VPC\n    TrafficType: ALL\n    LogDestinationType: cloud-watch-logs\n    LogGroupName: /aws/vpc/flowlogs/prod',
      estimatedMinutes: 10,
    },
    chainIds: [],
    detectedAt: '2026-03-23T10:12:00Z',
    lastSeenAt: '2026-03-23T10:12:00Z',
  },
  {
    id: 'finding-iam-003',
    checkId: 'IAM-007',
    category: 'IAM',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'IAM Policy with Wildcard "*" Actions on S3',
    resourceId: 'arn:aws:iam::123456789012:policy/AppServerPolicy',
    resourceType: 'AWS::IAM::Policy',
    resourceName: 'AppServerPolicy',
    region: 'global',
    riskNarrative: 'The AppServerPolicy grants s3:* (all S3 actions) on * (all buckets). Your application server only needs to read from one bucket, but this policy gives it permission to read, write, delete, and make public every S3 bucket in your account. If the application is compromised (e.g., via the SQL injection found in your SAST scan), the attacker inherits these permissions.',
    attackVector: 'SSRF vulnerability on app server → attacker calls IMDSv1 → gets instance role credentials → uses s3:* to list and download all buckets → full data exfiltration.',
    estimatedImpact: 'Data exfiltration from all S3 buckets if app server is compromised. Combines with DATA-001 for critical chain.',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 1.16', controlName: 'Ensure IAM policies are attached only to groups or roles', status: 'PARTIAL' },
      { framework: 'SOC2', controlId: 'CC6.3', controlName: 'Role-based access control', status: 'FAIL' },
    ],
    fixEffort: '1hr',
    remediation: {
      summary: 'Scope the IAM policy to only the specific S3 actions and bucket your app actually needs.',
      console: '1. IAM → Policies → AppServerPolicy → Edit\n2. Replace s3:* with specific actions: s3:GetObject, s3:PutObject\n3. Replace * with specific bucket ARN',
      cli: '# Create a new scoped policy\naws iam create-policy \\\n  --policy-name AppServerPolicyScoped \\\n  --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::prod-app-assets/*"}]}\'',
      terraform: 'resource "aws_iam_policy" "app_server" {\n  name = "AppServerPolicy"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n      Effect   = "Allow"\n      Action   = ["s3:GetObject", "s3:PutObject"]\n      Resource = "arn:aws:s3:::prod-app-assets/*"\n    }]\n  })\n}',
      cloudformation: 'AppServerPolicy:\n  Type: AWS::IAM::ManagedPolicy\n  Properties:\n    PolicyDocument:\n      Version: "2012-10-17"\n      Statement:\n        - Effect: Allow\n          Action:\n            - s3:GetObject\n            - s3:PutObject\n          Resource: arn:aws:s3:::prod-app-assets/*',
      estimatedMinutes: 30,
    },
    chainIds: ['scenario-001'],
    detectedAt: '2026-03-23T10:05:00Z',
    lastSeenAt: '2026-03-23T10:05:00Z',
  },
  {
    id: 'finding-data-003',
    checkId: 'DATA-006',
    category: 'DATA',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'RDS Automated Backups Disabled',
    resourceId: 'arn:aws:rds:us-east-1:123456789012:db:prod-postgres',
    resourceType: 'AWS::RDS::DBInstance',
    resourceName: 'prod-postgres',
    region: 'us-east-1',
    riskNarrative: 'Automated backups are disabled on your production PostgreSQL database. Ransomware attacks increasingly target databases — encrypting or deleting data and demanding payment. Without backups, a successful ransomware attack on your database means permanent data loss with no recovery option.',
    attackVector: 'Attacker gains DB access → runs DROP TABLE on all tables → demands ransom. Without backups, data is unrecoverable.',
    estimatedImpact: 'Permanent data loss in ransomware scenario. Business continuity failure. Est. $2M+ recovery cost.',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 2.3.2', controlName: 'Ensure RDS automated backups are enabled', status: 'FAIL' },
      { framework: 'PCI_DSS', controlId: 'PCI-DSS 12.10.1', controlName: 'Incident response and recovery plans', status: 'PARTIAL' },
    ],
    fixEffort: '5min',
    remediation: {
      summary: 'Enable automated backups with minimum 7-day retention. Set backup window during low-traffic hours.',
      console: '1. RDS → prod-postgres → Modify\n2. Backup → Backup retention period → 7 days\n3. Apply immediately',
      cli: 'aws rds modify-db-instance \\\n  --db-instance-identifier prod-postgres \\\n  --backup-retention-period 7 \\\n  --preferred-backup-window "02:00-03:00" \\\n  --apply-immediately',
      terraform: 'resource "aws_db_instance" "prod_postgres" {\n  backup_retention_period = 7\n  backup_window           = "02:00-03:00"\n}',
      cloudformation: 'ProdPostgres:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    BackupRetentionPeriod: 7\n    PreferredBackupWindow: "02:00-03:00"',
      estimatedMinutes: 5,
    },
    chainIds: [],
    detectedAt: '2026-03-23T10:08:00Z',
    lastSeenAt: '2026-03-23T10:08:00Z',
  },
  {
    id: 'finding-iam-004',
    checkId: 'IAM-005',
    category: 'IAM',
    severity: 'MEDIUM',
    status: 'OPEN',
    title: 'CloudTrail Not Enabled in All Regions',
    resourceId: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail',
    resourceType: 'AWS::CloudTrail::Trail',
    resourceName: 'main-trail',
    region: 'global',
    riskNarrative: 'Your CloudTrail only covers us-east-1. Attackers who discover this commonly create resources in uncovered regions (us-west-2, eu-west-1) to operate undetected. API calls in those regions — creating backdoor IAM users, launching EC2 instances, exfiltrating data — leave no audit trail.',
    attackVector: 'Attacker compromises credentials → checks CloudTrail coverage → pivots to eu-west-1 → creates backdoor IAM admin user → all activity invisible.',
    estimatedImpact: 'Forensic blindspot enabling persistent undetected access. Incident response failure.',
    complianceMappings: [
      { framework: 'CIS', controlId: 'CIS 3.1', controlName: 'Ensure CloudTrail is enabled in all regions', status: 'FAIL' },
      { framework: 'SOC2', controlId: 'CC7.2', controlName: 'System monitoring', status: 'PARTIAL' },
    ],
    fixEffort: '5min',
    remediation: {
      summary: 'Enable multi-region CloudTrail with log file validation.',
      console: '1. CloudTrail → Trails → main-trail → Edit\n2. Enable "Apply trail to all regions"\n3. Enable log file validation',
      cli: 'aws cloudtrail update-trail \\\n  --name main-trail \\\n  --is-multi-region-trail \\\n  --enable-log-file-validation',
      terraform: 'resource "aws_cloudtrail" "main" {\n  name                          = "main-trail"\n  s3_bucket_name                = aws_s3_bucket.cloudtrail.id\n  is_multi_region_trail         = true\n  enable_log_file_validation    = true\n  include_global_service_events = true\n}',
      cloudformation: 'MainTrail:\n  Type: AWS::CloudTrail::Trail\n  Properties:\n    TrailName: main-trail\n    IsMultiRegionTrail: true\n    EnableLogFileValidation: true\n    IncludeGlobalServiceEvents: true\n    IsLogging: true',
      estimatedMinutes: 5,
    },
    chainIds: [],
    detectedAt: '2026-03-23T10:05:00Z',
    lastSeenAt: '2026-03-23T10:05:00Z',
  },
]

// ─── Attack Scenarios ─────────────────────────────────────────────────────────
export const MOCK_ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: 'scenario-001',
    title: 'Credential Compromise → Full Account Takeover',
    severity: 'CRITICAL',
    likelihood: 'HIGH',
    narrative: 'An attacker phishes or brute-forces an IAM user with no MFA (finding IAM-003). Once inside, they discover the overly-permissive AppServerPolicy (finding IAM-007) which grants s3:* on all buckets. They exfiltrate data from prod-customer-uploads (finding DATA-001). Because CloudTrail is not multi-region (finding IAM-005), they create a backdoor IAM admin user in eu-west-1 and maintain persistent access even after the compromised user\'s password is reset.',
    steps: [
      { seq: 1, action: 'Phish/brute-force IAM user with no MFA', findingId: 'finding-iam-002', technique: 'Valid Accounts (T1078)' },
      { seq: 2, action: 'Enumerate IAM permissions and discover wildcard S3 policy', findingId: 'finding-iam-003', technique: 'Cloud Infrastructure Discovery (T1580)' },
      { seq: 3, action: 'Exfiltrate all data from public S3 bucket', findingId: 'finding-data-001', technique: 'Data from Cloud Storage (T1530)' },
      { seq: 4, action: 'Create backdoor IAM admin in uncovered region', findingId: 'finding-iam-004', technique: 'Create Account (T1136)' },
    ],
    findingIds: ['finding-iam-002', 'finding-iam-003', 'finding-data-001', 'finding-iam-004'],
    estimatedBreachCost: 2100000,
    affectedDataTypes: ['PII', 'Customer Records', 'Financial Data'],
    complianceImpact: ['PCI_DSS', 'SOC2', 'HIPAA'],
  },
  {
    id: 'scenario-002',
    title: 'External Attack → Database Exfiltration',
    severity: 'CRITICAL',
    likelihood: 'HIGH',
    narrative: 'An attacker uses Masscan to discover open SSH (finding NET-001) and PostgreSQL ports (finding DATA-002). They brute-force the PostgreSQL database directly over the internet. With no VPC flow logs (finding NET-002) the attack goes undetected. They dump the entire database, which is not encrypted. Recovery is impossible because automated backups are disabled (finding DATA-003).',
    steps: [
      { seq: 1, action: 'Masscan discovers open ports 22 and 5432', findingId: 'finding-net-001', technique: 'Network Service Scanning (T1046)' },
      { seq: 2, action: 'Brute-force publicly accessible RDS instance', findingId: 'finding-data-002', technique: 'Brute Force (T1110)' },
      { seq: 3, action: 'Dump entire database — attack invisible without flow logs', findingId: 'finding-net-002', technique: 'Data from Databases (T1213)' },
      { seq: 4, action: 'Delete database tables — no backups to recover from', findingId: 'finding-data-003', technique: 'Data Destruction (T1485)' },
    ],
    findingIds: ['finding-net-001', 'finding-data-002', 'finding-net-002', 'finding-data-003'],
    estimatedBreachCost: 1800000,
    affectedDataTypes: ['Database Records', 'Customer Data', 'Application Data'],
    complianceImpact: ['PCI_DSS', 'SOC2'],
  },
]

// ─── Inventory ─────────────────────────────────────────────────────────────────
export const MOCK_CLOUD_INVENTORY: CloudInventory = {
  ec2Instances: [
    { id: 'i-0abc123', arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123', name: 'web-server-01', type: 'AWS::EC2::Instance', region: 'us-east-1', tags: { Environment: 'prod', Team: 'platform' }, securityStatus: 'CRITICAL', findingIds: ['finding-net-001'] },
    { id: 'i-0def456', arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0def456', name: 'api-server-01', type: 'AWS::EC2::Instance', region: 'us-east-1', tags: { Environment: 'prod', Team: 'backend' }, securityStatus: 'WARNING', findingIds: ['finding-iam-003'] },
    { id: 'i-0ghi789', arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0ghi789', name: 'bastion-host', type: 'AWS::EC2::Instance', region: 'us-east-1', tags: { Environment: 'prod', Role: 'bastion' }, securityStatus: 'CRITICAL', findingIds: ['finding-net-001'] },
  ],
  s3Buckets: [
    { id: 'prod-customer-uploads', arn: 'arn:aws:s3:::prod-customer-uploads', name: 'prod-customer-uploads', type: 'AWS::S3::Bucket', region: 'global', tags: { Environment: 'prod', DataClass: 'PII' }, securityStatus: 'CRITICAL', findingIds: ['finding-data-001'] },
    { id: 'prod-app-assets', arn: 'arn:aws:s3:::prod-app-assets', name: 'prod-app-assets', type: 'AWS::S3::Bucket', region: 'global', tags: { Environment: 'prod' }, securityStatus: 'CLEAN', findingIds: [] },
    { id: 'prod-logs', arn: 'arn:aws:s3:::prod-logs', name: 'prod-logs', type: 'AWS::S3::Bucket', region: 'global', tags: { Environment: 'prod', Purpose: 'logs' }, securityStatus: 'CLEAN', findingIds: [] },
  ],
  rdsInstances: [
    { id: 'prod-postgres', arn: 'arn:aws:rds:us-east-1:123456789012:db:prod-postgres', name: 'prod-postgres', type: 'AWS::RDS::DBInstance', region: 'us-east-1', tags: { Environment: 'prod', Engine: 'postgres' }, securityStatus: 'CRITICAL', findingIds: ['finding-data-002', 'finding-data-003'] },
  ],
  iamUsers: [
    { id: 'john.smith', arn: 'arn:aws:iam::123456789012:user/john.smith', name: 'john.smith', type: 'AWS::IAM::User', region: 'global', tags: {}, securityStatus: 'CRITICAL', findingIds: ['finding-iam-002'] },
    { id: 'sarah.jones', arn: 'arn:aws:iam::123456789012:user/sarah.jones', name: 'sarah.jones', type: 'AWS::IAM::User', region: 'global', tags: {}, securityStatus: 'CRITICAL', findingIds: ['finding-iam-002'] },
    { id: 'ci-bot', arn: 'arn:aws:iam::123456789012:user/ci-bot', name: 'ci-bot', type: 'AWS::IAM::User', region: 'global', tags: { Purpose: 'cicd' }, securityStatus: 'WARNING', findingIds: ['finding-iam-002'] },
  ],
  iamRoles: [
    { id: 'AppServerRole', arn: 'arn:aws:iam::123456789012:role/AppServerRole', name: 'AppServerRole', type: 'AWS::IAM::Role', region: 'global', tags: {}, securityStatus: 'WARNING', findingIds: ['finding-iam-003'] },
    { id: 'HemisXScannerRole', arn: 'arn:aws:iam::123456789012:role/HemisXScannerRole', name: 'HemisXScannerRole', type: 'AWS::IAM::Role', region: 'global', tags: { Purpose: 'security-scan' }, securityStatus: 'CLEAN', findingIds: [] },
  ],
  lambdaFunctions: [
    { id: 'prod-payment-processor', arn: 'arn:aws:lambda:us-east-1:123456789012:function:prod-payment-processor', name: 'prod-payment-processor', type: 'AWS::Lambda::Function', region: 'us-east-1', tags: { Environment: 'prod' }, securityStatus: 'CLEAN', findingIds: [] },
  ],
  securityGroups: [
    { id: 'sg-0abc123', arn: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123', name: 'web-servers-sg', type: 'AWS::EC2::SecurityGroup', region: 'us-east-1', tags: {}, securityStatus: 'CRITICAL', findingIds: ['finding-net-001'] },
    { id: 'sg-0def456', arn: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-0def456', name: 'bastion-sg', type: 'AWS::EC2::SecurityGroup', region: 'us-east-1', tags: {}, securityStatus: 'CRITICAL', findingIds: ['finding-net-001'] },
  ],
  vpcs: [
    { id: 'vpc-0abc123', arn: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc123', name: 'prod-vpc', type: 'AWS::EC2::VPC', region: 'us-east-1', tags: { Environment: 'prod' }, securityStatus: 'WARNING', findingIds: ['finding-net-002'] },
    { id: 'vpc-0def456', arn: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0def456', name: 'staging-vpc', type: 'AWS::EC2::VPC', region: 'us-east-1', tags: { Environment: 'staging' }, securityStatus: 'WARNING', findingIds: ['finding-net-002'] },
  ],
  totalResources: 17,
}

// ─── Compliance Scores ────────────────────────────────────────────────────────
export const MOCK_COMPLIANCE_SCORES: ComplianceScore[] = [
  {
    framework: 'CIS',
    score: 42,
    passed: 38,
    failed: 27,
    total: 65,
    gaps: [
      { controlId: 'CIS 1.4', controlName: 'No root account access key', status: 'FAIL', findingIds: ['finding-iam-001'], severity: 'CRITICAL' },
      { controlId: 'CIS 1.10', controlName: 'MFA enabled for all console users', status: 'FAIL', findingIds: ['finding-iam-002'], severity: 'CRITICAL' },
      { controlId: 'CIS 2.1.5', controlName: 'S3 buckets not publicly accessible', status: 'FAIL', findingIds: ['finding-data-001'], severity: 'CRITICAL' },
      { controlId: 'CIS 2.3.1', controlName: 'RDS not publicly accessible', status: 'FAIL', findingIds: ['finding-data-002'], severity: 'HIGH' },
      { controlId: 'CIS 3.1', controlName: 'CloudTrail enabled in all regions', status: 'FAIL', findingIds: ['finding-iam-004'], severity: 'MEDIUM' },
      { controlId: 'CIS 3.9', controlName: 'VPC flow logging enabled', status: 'FAIL', findingIds: ['finding-net-002'], severity: 'HIGH' },
      { controlId: 'CIS 5.2', controlName: 'No SG ingress from 0.0.0.0/0 to SSH', status: 'FAIL', findingIds: ['finding-net-001'], severity: 'CRITICAL' },
    ],
  },
  {
    framework: 'PCI_DSS',
    score: 38,
    passed: 22,
    failed: 14,
    total: 36,
    gaps: [
      { controlId: 'PCI-DSS 7.1', controlName: 'Limit access to system components', status: 'FAIL', findingIds: ['finding-iam-001'], severity: 'CRITICAL' },
      { controlId: 'PCI-DSS 8.3.1', controlName: 'MFA for non-console admin access', status: 'FAIL', findingIds: ['finding-iam-002'], severity: 'CRITICAL' },
      { controlId: 'PCI-DSS 1.3', controlName: 'Prohibit direct public access to CDE', status: 'FAIL', findingIds: ['finding-data-002'], severity: 'HIGH' },
      { controlId: 'PCI-DSS 3.4', controlName: 'Protect stored cardholder data', status: 'FAIL', findingIds: ['finding-data-001'], severity: 'CRITICAL' },
      { controlId: 'PCI-DSS 1.3.1', controlName: 'Restrict inbound traffic', status: 'FAIL', findingIds: ['finding-net-001'], severity: 'CRITICAL' },
    ],
  },
  {
    framework: 'SOC2',
    score: 55,
    passed: 31,
    failed: 19,
    total: 50,
    gaps: [
      { controlId: 'CC6.3', controlName: 'Logical access controls', status: 'FAIL', findingIds: ['finding-iam-002', 'finding-iam-003'], severity: 'CRITICAL' },
      { controlId: 'CC6.1', controlName: 'Access restriction', status: 'FAIL', findingIds: ['finding-data-001'], severity: 'CRITICAL' },
      { controlId: 'CC7.2', controlName: 'System monitoring', status: 'FAIL', findingIds: ['finding-iam-004', 'finding-net-002'], severity: 'MEDIUM' },
    ],
  },
  {
    framework: 'HIPAA',
    score: 61,
    passed: 28,
    failed: 12,
    total: 40,
    gaps: [
      { controlId: 'HIPAA 164.312(d)', controlName: 'Person/entity authentication', status: 'FAIL', findingIds: ['finding-iam-002'], severity: 'CRITICAL' },
      { controlId: 'HIPAA 164.312(a)', controlName: 'Access control', status: 'FAIL', findingIds: ['finding-data-001'], severity: 'CRITICAL' },
    ],
  },
]

// ─── Remediation Queue ────────────────────────────────────────────────────────
export const MOCK_REMEDIATION_QUEUE: RemediationItem[] = [
  { priority: 1, findingId: 'finding-iam-001', title: 'Delete root account access keys', severity: 'CRITICAL', effort: '5min', estimatedMinutes: 5, impactScore: 98, category: 'IAM', status: 'OPEN' },
  { priority: 2, findingId: 'finding-data-001', title: 'Block public access on prod-customer-uploads S3 bucket', severity: 'CRITICAL', effort: '5min', estimatedMinutes: 5, impactScore: 96, category: 'DATA', status: 'OPEN' },
  { priority: 3, findingId: 'finding-net-001', title: 'Restrict SSH security groups from 0.0.0.0/0', severity: 'CRITICAL', effort: '5min', estimatedMinutes: 10, impactScore: 93, category: 'NETWORK', status: 'OPEN' },
  { priority: 4, findingId: 'finding-iam-004', title: 'Enable multi-region CloudTrail', severity: 'MEDIUM', effort: '5min', estimatedMinutes: 5, impactScore: 88, category: 'IAM', status: 'OPEN' },
  { priority: 5, findingId: 'finding-net-002', title: 'Enable VPC Flow Logs on prod and staging VPCs', severity: 'HIGH', effort: '5min', estimatedMinutes: 10, impactScore: 85, category: 'NETWORK', status: 'OPEN' },
  { priority: 6, findingId: 'finding-data-002', title: 'Disable public access on prod-postgres RDS', severity: 'HIGH', effort: '1hr', estimatedMinutes: 30, impactScore: 82, category: 'DATA', status: 'OPEN' },
  { priority: 7, findingId: 'finding-iam-002', title: 'Enforce MFA for all IAM console users', severity: 'CRITICAL', effort: '1hr', estimatedMinutes: 60, impactScore: 79, category: 'IAM', status: 'OPEN' },
  { priority: 8, findingId: 'finding-data-003', title: 'Enable RDS automated backups (7-day retention)', severity: 'HIGH', effort: '5min', estimatedMinutes: 5, impactScore: 75, category: 'DATA', status: 'OPEN' },
  { priority: 9, findingId: 'finding-iam-003', title: 'Remove wildcard S3 permissions from AppServerPolicy', severity: 'HIGH', effort: '1hr', estimatedMinutes: 30, impactScore: 70, category: 'IAM', status: 'OPEN' },
]

// ─── Full Scan ─────────────────────────────────────────────────────────────────
export const MOCK_CLOUD_SCAN: CloudScan = {
  id: 'scan-aws-demo-001',
  connectionId: 'conn-aws-demo-001',
  accountId: '123456789012',
  accountAlias: 'acme-production',
  status: 'COMPLETED',
  progress: 100,
  currentPhase: 'completed',
  startedAt: '2026-03-23T10:00:00Z',
  completedAt: '2026-03-23T10:04:32Z',
  duration: 272000,
  riskScore: 78,
  riskLevel: 'CRITICAL',
  summary: {
    totalFindings: 9,
    critical: 4,
    high: 4,
    medium: 1,
    low: 0,
    info: 0,
    byCategory: { IAM: 4, DATA: 3, NETWORK: 2 },
    estimatedBreachCost: 3900000,
    resourcesScanned: 17,
    checksRun: 65,
    checksPassed: 56,
    checksFailed: 9,
  },
  findings: MOCK_CLOUD_FINDINGS,
  inventory: MOCK_CLOUD_INVENTORY,
  complianceScores: MOCK_COMPLIANCE_SCORES,
  attackScenarios: MOCK_ATTACK_SCENARIOS,
  remediationQueue: MOCK_REMEDIATION_QUEUE,
}

// ─── For import dropdown ───────────────────────────────────────────────────────
export const MOCK_PAST_SCANS = [
  { id: 'scan-aws-demo-001', accountAlias: 'acme-production', date: '2026-03-23', findingsCount: 9, riskScore: 78 },
  { id: 'scan-aws-demo-002', accountAlias: 'acme-staging', date: '2026-03-20', findingsCount: 4, riskScore: 42 },
]
```

- [ ] **Step 2: Verify TypeScript**

```bash
npx tsc --noEmit 2>&1 | grep -i "cloud" | head -20
```
Expected: no errors

---

## Task 3: Check Definitions (IAM, Data, Network)

**Files:**
- Create: `src/lib/cloud-scanner/checks/iam-checks.ts`
- Create: `src/lib/cloud-scanner/checks/data-checks.ts`
- Create: `src/lib/cloud-scanner/checks/network-checks.ts`

- [ ] **Step 1: Create IAM checks**

```typescript
// src/lib/cloud-scanner/checks/iam-checks.ts
import type { CloudCheck } from '@/lib/types/cloud-scanner'

export const IAM_CHECKS: CloudCheck[] = [
  { id: 'IAM-001', category: 'IAM', title: 'Root Account Has Active Access Keys', description: 'Root account should never have programmatic access keys.', severity: 'CRITICAL', resourceType: 'AWS::IAM::Root', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 1.4', controlName: 'Ensure no root account access key exists' }, { framework: 'PCI_DSS', controlId: 'PCI-DSS 7.1', controlName: 'Limit access to system components' }] },
  { id: 'IAM-002', category: 'IAM', title: 'Root Account Has No MFA', description: 'Root account must have MFA enabled at all times.', severity: 'CRITICAL', resourceType: 'AWS::IAM::Root', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 1.5', controlName: 'Ensure MFA is enabled for the root account' }] },
  { id: 'IAM-003', category: 'IAM', title: 'IAM Users with Console Access and No MFA', description: 'All IAM users with console access must have MFA.', severity: 'CRITICAL', resourceType: 'AWS::IAM::User', fixEffort: '1hr', estimatedMinutes: 60, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 1.10', controlName: 'Ensure MFA is enabled for all IAM users with console access' }, { framework: 'PCI_DSS', controlId: 'PCI-DSS 8.3.1', controlName: 'MFA for non-console admin access' }] },
  { id: 'IAM-004', category: 'IAM', title: 'IAM User Has Unused Credentials (90+ days)', description: 'Credentials unused for 90+ days indicate stale accounts that should be disabled.', severity: 'HIGH', resourceType: 'AWS::IAM::User', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 1.12', controlName: 'Ensure credentials unused for 90+ days are disabled' }] },
  { id: 'IAM-005', category: 'IAM', title: 'CloudTrail Not Multi-Region', description: 'CloudTrail must cover all regions to prevent blind spots.', severity: 'MEDIUM', resourceType: 'AWS::CloudTrail::Trail', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 3.1', controlName: 'Ensure CloudTrail is enabled in all regions' }, { framework: 'SOC2', controlId: 'CC7.2', controlName: 'System monitoring' }] },
  { id: 'IAM-006', category: 'IAM', title: 'AWS Config Not Enabled', description: 'AWS Config must be enabled for compliance tracking.', severity: 'MEDIUM', resourceType: 'AWS::Config::ConfigurationRecorder', fixEffort: '1hr', estimatedMinutes: 30, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 3.5', controlName: 'Ensure AWS Config is enabled in all regions' }] },
  { id: 'IAM-007', category: 'IAM', title: 'IAM Policy with Wildcard Actions', description: 'Policies with s3:* or ec2:* grant excessive permissions.', severity: 'HIGH', resourceType: 'AWS::IAM::Policy', fixEffort: '1hr', estimatedMinutes: 45, complianceMappings: [{ framework: 'SOC2', controlId: 'CC6.3', controlName: 'Role-based access control' }] },
  { id: 'IAM-008', category: 'IAM', title: 'IAM Password Policy Insufficient', description: 'Password policy must enforce length, complexity, and rotation.', severity: 'MEDIUM', resourceType: 'AWS::IAM::PasswordPolicy', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 1.8', controlName: 'Ensure IAM password policy requires minimum length of 14' }] },
  { id: 'IAM-009', category: 'IAM', title: 'IAM Access Analyzer Not Enabled', description: 'Access Analyzer identifies resources shared with external entities.', severity: 'LOW', resourceType: 'AWS::AccessAnalyzer::Analyzer', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 1.21', controlName: 'Ensure IAM Access Analyzer is enabled' }] },
  { id: 'IAM-010', category: 'IAM', title: 'CloudTrail Log File Validation Disabled', description: 'Log file validation detects tampering with CloudTrail logs.', severity: 'LOW', resourceType: 'AWS::CloudTrail::Trail', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 3.2', controlName: 'Ensure CloudTrail log file validation is enabled' }] },
]
```

- [ ] **Step 2: Create Data checks**

```typescript
// src/lib/cloud-scanner/checks/data-checks.ts
import type { CloudCheck } from '@/lib/types/cloud-scanner'

export const DATA_CHECKS: CloudCheck[] = [
  { id: 'DATA-001', category: 'DATA', title: 'S3 Bucket Publicly Readable', description: 'S3 buckets must not allow public read access.', severity: 'CRITICAL', resourceType: 'AWS::S3::Bucket', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 2.1.5', controlName: 'Ensure S3 buckets are not publicly accessible' }, { framework: 'PCI_DSS', controlId: 'PCI-DSS 3.4', controlName: 'Protect stored cardholder data' }] },
  { id: 'DATA-002', category: 'DATA', title: 'S3 Block Public Access Not Enabled at Account Level', description: 'Account-level Block Public Access prevents any bucket from becoming public.', severity: 'HIGH', resourceType: 'AWS::S3::AccountPublicAccessBlock', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 2.1.4', controlName: 'Ensure S3 Block Public Access is enabled at account level' }] },
  { id: 'DATA-003', category: 'DATA', title: 'RDS Instance Publicly Accessible', description: 'RDS instances should never be directly internet-accessible.', severity: 'CRITICAL', resourceType: 'AWS::RDS::DBInstance', fixEffort: '1hr', estimatedMinutes: 30, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 2.3.1', controlName: 'Ensure RDS instances are not publicly accessible' }, { framework: 'PCI_DSS', controlId: 'PCI-DSS 1.3', controlName: 'Prohibit direct public access to CDE' }] },
  { id: 'DATA-004', category: 'DATA', title: 'RDS Instance No Encryption at Rest', description: 'RDS storage must be encrypted to protect data at rest.', severity: 'HIGH', resourceType: 'AWS::RDS::DBInstance', fixEffort: '1day', estimatedMinutes: 240, complianceMappings: [{ framework: 'PCI_DSS', controlId: 'PCI-DSS 3.5', controlName: 'Protect encryption keys used to protect stored data' }, { framework: 'HIPAA', controlId: 'HIPAA 164.312(a)(2)(iv)', controlName: 'Encryption and decryption' }] },
  { id: 'DATA-005', category: 'DATA', title: 'EBS Volume Not Encrypted', description: 'EBS volumes containing application data must be encrypted.', severity: 'MEDIUM', resourceType: 'AWS::EC2::Volume', fixEffort: '1hr', estimatedMinutes: 60, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 2.2.1', controlName: 'Ensure EBS volume encryption is enabled by default' }] },
  { id: 'DATA-006', category: 'DATA', title: 'RDS Automated Backups Disabled', description: 'Automated backups provide recovery from data loss and ransomware.', severity: 'HIGH', resourceType: 'AWS::RDS::DBInstance', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 2.3.2', controlName: 'Ensure RDS automated backups are enabled' }] },
  { id: 'DATA-007', category: 'DATA', title: 'RDS Deletion Protection Disabled', description: 'Deletion protection prevents accidental or malicious database deletion.', severity: 'MEDIUM', resourceType: 'AWS::RDS::DBInstance', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'SOC2', controlId: 'CC9.2', controlName: 'Risk mitigation activities' }] },
  { id: 'DATA-008', category: 'DATA', title: 'S3 Bucket Encryption Disabled', description: 'S3 server-side encryption protects data at rest.', severity: 'MEDIUM', resourceType: 'AWS::S3::Bucket', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 2.1.1', controlName: 'Ensure S3 Bucket Policy is set to deny HTTP requests' }] },
  { id: 'DATA-009', category: 'DATA', title: 'S3 Bucket Access Logging Disabled', description: 'Access logging records all requests made to S3 buckets.', severity: 'LOW', resourceType: 'AWS::S3::Bucket', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 2.1.3', controlName: 'Ensure S3 bucket logging is enabled' }] },
  { id: 'DATA-010', category: 'DATA', title: 'KMS Key Rotation Disabled', description: 'Automatic rotation of KMS keys limits the impact of key compromise.', severity: 'MEDIUM', resourceType: 'AWS::KMS::Key', fixEffort: '5min', estimatedMinutes: 5, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 3.8', controlName: 'Ensure rotation for customer created CMKs is enabled' }] },
]
```

- [ ] **Step 3: Create Network checks**

```typescript
// src/lib/cloud-scanner/checks/network-checks.ts
import type { CloudCheck } from '@/lib/types/cloud-scanner'

export const NETWORK_CHECKS: CloudCheck[] = [
  { id: 'NET-001', category: 'NETWORK', title: 'Security Group Allows SSH from 0.0.0.0/0', description: 'SSH should never be open to the entire internet.', severity: 'CRITICAL', resourceType: 'AWS::EC2::SecurityGroup', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 5.2', controlName: 'Ensure no security groups allow ingress from 0.0.0.0/0 to SSH' }, { framework: 'PCI_DSS', controlId: 'PCI-DSS 1.3.1', controlName: 'Restrict inbound traffic' }] },
  { id: 'NET-002', category: 'NETWORK', title: 'Security Group Allows RDP from 0.0.0.0/0', description: 'RDP should never be open to the entire internet.', severity: 'CRITICAL', resourceType: 'AWS::EC2::SecurityGroup', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 5.3', controlName: 'Ensure no security groups allow ingress from 0.0.0.0/0 to RDP' }] },
  { id: 'NET-003', category: 'NETWORK', title: 'Security Group Allows DB Ports from 0.0.0.0/0', description: 'Database ports (3306, 5432, 1433, 27017) should not be internet-accessible.', severity: 'CRITICAL', resourceType: 'AWS::EC2::SecurityGroup', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'PCI_DSS', controlId: 'PCI-DSS 1.3.2', controlName: 'Restrict outbound traffic to only that which is necessary' }] },
  { id: 'NET-004', category: 'NETWORK', title: 'VPC Flow Logs Disabled', description: 'VPC Flow Logs capture all network traffic metadata for detection and forensics.', severity: 'HIGH', resourceType: 'AWS::EC2::VPC', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 3.9', controlName: 'Ensure VPC flow logging is enabled in all VPCs' }, { framework: 'SOC2', controlId: 'CC7.2', controlName: 'Monitor system components for anomalies' }] },
  { id: 'NET-005', category: 'NETWORK', title: 'EC2 Instance IMDSv1 Enabled', description: 'IMDSv1 allows SSRF attacks to steal instance credentials. Enforce IMDSv2.', severity: 'HIGH', resourceType: 'AWS::EC2::Instance', fixEffort: '5min', estimatedMinutes: 15, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 5.6', controlName: 'Ensure EC2 instances use IMDSv2' }] },
  { id: 'NET-006', category: 'NETWORK', title: 'ELB Access Logging Disabled', description: 'Load balancer access logs capture all HTTP requests for forensics.', severity: 'LOW', resourceType: 'AWS::ElasticLoadBalancingV2::LoadBalancer', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 3.11', controlName: 'Ensure ELB access logging is enabled' }] },
  { id: 'NET-007', category: 'NETWORK', title: 'ELB Has HTTP Listener Without HTTPS Redirect', description: 'HTTP traffic should be redirected to HTTPS to prevent eavesdropping.', severity: 'MEDIUM', resourceType: 'AWS::ElasticLoadBalancingV2::Listener', fixEffort: '5min', estimatedMinutes: 10, complianceMappings: [{ framework: 'PCI_DSS', controlId: 'PCI-DSS 4.2.1', controlName: 'Strong cryptography for data-in-transit' }] },
  { id: 'NET-008', category: 'NETWORK', title: 'Resources in Default VPC', description: 'Default VPCs have permissive settings. Resources should use custom VPCs.', severity: 'LOW', resourceType: 'AWS::EC2::VPC', fixEffort: '1day', estimatedMinutes: 480, complianceMappings: [{ framework: 'CIS', controlId: 'CIS 5.1', controlName: 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to ports 22 or 3389' }] },
  { id: 'NET-009', category: 'NETWORK', title: 'CloudFront Distribution Without WAF', description: 'WAF protects CloudFront distributions from common web exploits.', severity: 'MEDIUM', resourceType: 'AWS::CloudFront::Distribution', fixEffort: '1hr', estimatedMinutes: 60, complianceMappings: [{ framework: 'PCI_DSS', controlId: 'PCI-DSS 6.4.1', controlName: 'Deploy automated technical controls to protect against web-based attacks' }] },
  { id: 'NET-010', category: 'NETWORK', title: 'ACM Certificate Expiring Within 30 Days', description: 'Expiring certificates cause service outages and trust errors.', severity: 'HIGH', resourceType: 'AWS::CertificateManager::Certificate', fixEffort: '1hr', estimatedMinutes: 30, complianceMappings: [{ framework: 'SOC2', controlId: 'CC9.1', controlName: 'Risk assessment' }] },
]
```

- [ ] **Step 4: Verify TypeScript**

```bash
npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors

---

## Task 4: AWS Connector + Scan Orchestrator

**Files:**
- Create: `src/lib/cloud-scanner/aws-connector.ts`
- Create: `src/lib/cloud-scanner/scan-orchestrator.ts`

- [ ] **Step 1: Create AWS Connector**

```typescript
// src/lib/cloud-scanner/aws-connector.ts
import type { CloudConnection } from '@/lib/types/cloud-scanner'
import { randomUUID } from 'crypto'

// In-memory connection store
const connectionStore = new Map<string, CloudConnection>()

export function saveConnection(roleArn: string, externalId?: string): CloudConnection {
  const accountId = extractAccountId(roleArn)
  const conn: CloudConnection = {
    id: randomUUID(),
    orgId: 'org-demo',
    provider: 'AWS',
    accountId,
    roleArn,
    externalId: externalId ?? `hemisx-${randomUUID().slice(0, 8)}`,
    regions: ['us-east-1'],
    connectedAt: new Date().toISOString(),
    status: 'PENDING',
  }
  connectionStore.set(conn.id, conn)
  return conn
}

export function getConnection(id: string): CloudConnection | null {
  return connectionStore.get(id) ?? null
}

export function listConnections(): CloudConnection[] {
  return Array.from(connectionStore.values())
}

export async function testConnection(conn: CloudConnection): Promise<{ success: boolean; error?: string; regions?: string[] }> {
  // Demo mode: simulate successful connection test
  // In production: use @aws-sdk/client-sts to call AssumeRole + GetCallerIdentity
  await new Promise(r => setTimeout(r, 1500)) // simulate API call

  if (!conn.roleArn.startsWith('arn:aws:iam::')) {
    return { success: false, error: 'Invalid role ARN format. Expected: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME' }
  }

  const updatedConn = { ...conn, status: 'CONNECTED' as const, regions: ['us-east-1', 'us-west-2', 'eu-west-1'] }
  connectionStore.set(conn.id, updatedConn)
  return { success: true, regions: updatedConn.regions }
}

function extractAccountId(roleArn: string): string {
  // arn:aws:iam::123456789012:role/RoleName → 123456789012
  const parts = roleArn.split(':')
  return parts[4] ?? '000000000000'
}

export function generateCloudFormationTemplate(externalId: string, hemisxAccountId = '123456789012'): string {
  return `AWSTemplateFormatVersion: "2010-09-09"
Description: HemisX Security Scanner - Read-Only IAM Role

Parameters:
  ExternalId:
    Type: String
    Default: "${externalId}"

Resources:
  HemisXScannerRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: HemisXScannerRole
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: arn:aws:iam::${hemisxAccountId}:root
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
      Tags:
        - Key: Purpose
          Value: HemisX-Security-Scanner
        - Key: ManagedBy
          Value: HemisX

Outputs:
  RoleArn:
    Description: ARN of the HemisX Scanner Role - paste this into HemisX
    Value: !GetAtt HemisXScannerRole.Arn`
}

export function generateTerraformTemplate(externalId: string, hemisxAccountId = '123456789012'): string {
  return `# HemisX Security Scanner - Read-Only IAM Role
# Run: terraform apply

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

data "aws_iam_policy_document" "hemisx_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${hemisxAccountId}:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["${externalId}"]
    }
  }
}

resource "aws_iam_role" "hemisx_scanner" {
  name               = "HemisXScannerRole"
  assume_role_policy = data.aws_iam_policy_document.hemisx_assume_role.json
  tags = {
    Purpose   = "HemisX-Security-Scanner"
    ManagedBy = "HemisX"
  }
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.hemisx_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.hemisx_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

output "role_arn" {
  description = "Paste this into HemisX"
  value       = aws_iam_role.hemisx_scanner.arn
}`
}
```

- [ ] **Step 2: Create Scan Orchestrator**

```typescript
// src/lib/cloud-scanner/scan-orchestrator.ts
import type { CloudScan, CloudScanProgress, CloudScanStatus } from '@/lib/types/cloud-scanner'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'
import { randomUUID } from 'crypto'

// In-memory stores
export const progressStore = new Map<string, CloudScanProgress>()
const scanStore = new Map<string, CloudScan>()

function updateProgress(scanId: string, status: CloudScanStatus, progress: number, phase: string, message: string) {
  progressStore.set(scanId, { scanId, status, progress, currentPhase: phase, message, timestamp: new Date().toISOString() })
}

export function getScan(id: string): CloudScan | null {
  return scanStore.get(id) ?? null
}

export function listScans(): CloudScan[] {
  return Array.from(scanStore.values()).sort(
    (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
  )
}

export function createScan(connectionId: string, accountId: string, accountAlias?: string): CloudScan {
  const scan: CloudScan = {
    ...MOCK_CLOUD_SCAN,
    id: randomUUID(),
    connectionId,
    accountId,
    accountAlias,
    status: 'CREATED',
    progress: 0,
    currentPhase: 'created',
    startedAt: new Date().toISOString(),
    completedAt: undefined,
  }
  scanStore.set(scan.id, scan)
  return scan
}

export async function runScan(scanId: string): Promise<void> {
  const scan = scanStore.get(scanId)
  if (!scan) return

  const phases: Array<{ status: CloudScanStatus; progress: number; phase: string; message: string; delay: number }> = [
    { status: 'CONNECTING',       progress: 10, phase: 'connecting',       message: 'Assuming IAM role via STS…',               delay: 800  },
    { status: 'DISCOVERING',      progress: 25, phase: 'discovering',      message: 'Discovering resources across 3 regions…',  delay: 1200 },
    { status: 'SCANNING_IAM',     progress: 45, phase: 'scanning_iam',     message: 'Auditing IAM users, roles, and policies…', delay: 1500 },
    { status: 'SCANNING_DATA',    progress: 62, phase: 'scanning_data',    message: 'Scanning S3 buckets and RDS instances…',   delay: 1200 },
    { status: 'SCANNING_NETWORK', progress: 78, phase: 'scanning_network', message: 'Checking security groups and VPCs…',       delay: 1000 },
    { status: 'ANALYZING',        progress: 90, phase: 'analyzing',        message: 'Chaining risks and mapping compliance…',   delay: 1200 },
    { status: 'COMPLETED',        progress: 100, phase: 'completed',       message: 'Scan complete. 9 findings detected.',      delay: 0    },
  ]

  for (const p of phases) {
    await new Promise(r => setTimeout(r, p.delay))
    updateProgress(scanId, p.status, p.progress, p.phase, p.message)
    const updated: CloudScan = { ...scan, status: p.status, progress: p.progress, currentPhase: p.phase }
    if (p.status === 'COMPLETED') {
      updated.completedAt = new Date().toISOString()
      // Merge mock findings/results into this scan
      Object.assign(updated, {
        findings: MOCK_CLOUD_SCAN.findings,
        inventory: MOCK_CLOUD_SCAN.inventory,
        complianceScores: MOCK_CLOUD_SCAN.complianceScores,
        attackScenarios: MOCK_CLOUD_SCAN.attackScenarios,
        remediationQueue: MOCK_CLOUD_SCAN.remediationQueue,
        summary: MOCK_CLOUD_SCAN.summary,
        riskScore: MOCK_CLOUD_SCAN.riskScore,
        riskLevel: MOCK_CLOUD_SCAN.riskLevel,
      })
    }
    scanStore.set(scanId, updated)
  }
}
```

- [ ] **Step 3: Verify TypeScript**

```bash
npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors

---

## Task 5: API Routes

**Files:**
- Create: `src/app/api/cloud/connect/route.ts`
- Create: `src/app/api/cloud/scans/route.ts`
- Create: `src/app/api/cloud/scans/[id]/route.ts`
- Create: `src/app/api/cloud/scans/[id]/progress/route.ts`
- Create: `src/app/api/cloud/findings/[id]/route.ts`
- Create: `src/app/api/cloud/inventory/[id]/route.ts`
- Create: `src/app/api/cloud/compliance/[id]/route.ts`
- Create: `src/app/api/cloud/remediation/[id]/route.ts`

- [ ] **Step 1: Create all API routes**

```typescript
// src/app/api/cloud/connect/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { saveConnection, testConnection, generateCloudFormationTemplate, generateTerraformTemplate } from '@/lib/cloud-scanner/aws-connector'
import { randomUUID } from 'crypto'

export async function GET() {
  const externalId = `hemisx-${randomUUID().slice(0, 8)}`
  return NextResponse.json({
    externalId,
    hemisxAccountId: '123456789012',
    cloudformation: generateCloudFormationTemplate(externalId),
    terraform: generateTerraformTemplate(externalId),
  })
}

export async function POST(req: NextRequest) {
  try {
    const { roleArn, externalId } = await req.json()
    if (!roleArn?.trim()) return NextResponse.json({ error: 'roleArn is required' }, { status: 400 })
    const conn = saveConnection(roleArn.trim(), externalId)
    const result = await testConnection(conn)
    if (!result.success) return NextResponse.json({ error: result.error }, { status: 400 })
    return NextResponse.json({ connection: { ...conn, status: 'CONNECTED', regions: result.regions } }, { status: 201 })
  } catch (err) {
    console.error('[Cloud] POST /api/cloud/connect error:', err)
    return NextResponse.json({ error: 'Connection failed' }, { status: 500 })
  }
}
```

```typescript
// src/app/api/cloud/scans/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { createScan, listScans } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function POST(req: NextRequest) {
  try {
    const { connectionId, accountId, accountAlias } = await req.json()
    const scan = createScan(connectionId ?? 'conn-demo', accountId ?? '123456789012', accountAlias ?? 'acme-production')
    console.log(`[Cloud] Scan created: ${scan.id}`)
    return NextResponse.json({ scan }, { status: 201 })
  } catch (err) {
    console.error('[Cloud] POST /api/cloud/scans error:', err)
    return NextResponse.json({ error: 'Failed to create scan' }, { status: 500 })
  }
}

export async function GET() {
  try {
    const scans = listScans()
    // In demo mode with no scans, return mock
    if (scans.length === 0) return NextResponse.json({ scans: [MOCK_CLOUD_SCAN] })
    return NextResponse.json({ scans })
  } catch (err) {
    console.error('[Cloud] GET /api/cloud/scans error:', err)
    return NextResponse.json({ scans: [MOCK_CLOUD_SCAN] })
  }
}
```

```typescript
// src/app/api/cloud/scans/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    if (id === 'demo' || id === MOCK_CLOUD_SCAN.id) return NextResponse.json({ scan: MOCK_CLOUD_SCAN })
    const scan = getScan(id)
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
    return NextResponse.json({ scan })
  } catch (err) {
    console.error('[Cloud] GET /api/cloud/scans/[id] error:', err)
    return NextResponse.json({ scan: MOCK_CLOUD_SCAN })
  }
}
```

```typescript
// src/app/api/cloud/scans/[id]/run/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan, runScan, progressStore } from '@/lib/cloud-scanner/scan-orchestrator'

export async function POST(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const scan = getScan(id)
    if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
    const progress = progressStore.get(id)
    if (progress && !['COMPLETED', 'FAILED', 'CREATED'].includes(progress.status)) {
      return NextResponse.json({ error: 'Scan already running' }, { status: 409 })
    }
    // Fire and forget
    runScan(id).catch(err => console.error('[Cloud] runScan error:', err))
    return NextResponse.json({ message: 'Scan started', scanId: id }, { status: 202 })
  } catch (err) {
    console.error('[Cloud] POST /api/cloud/scans/[id]/run error:', err)
    return NextResponse.json({ error: 'Failed to start scan' }, { status: 500 })
  }
}
```

```typescript
// src/app/api/cloud/scans/[id]/progress/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { progressStore } from '@/lib/cloud-scanner/scan-orchestrator'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const progress = progressStore.get(id) ?? { scanId: id, status: 'CREATED', progress: 0, currentPhase: 'created', message: 'Scan created', timestamp: new Date().toISOString() }
  return NextResponse.json({ progress })
}
```

```typescript
// src/app/api/cloud/findings/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const scan = (id === 'demo' || id === MOCK_CLOUD_SCAN.id) ? MOCK_CLOUD_SCAN : getScan(id)
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  return NextResponse.json({ findings: scan.findings })
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const { findingId, status } = await req.json()
    const validStatuses = ['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE']
    if (!validStatuses.includes(status)) return NextResponse.json({ error: 'Invalid status' }, { status: 400 })
    // In demo: just return success (in-memory update would go here)
    console.log(`[Cloud] Finding ${findingId} in scan ${id} status → ${status}`)
    return NextResponse.json({ success: true, findingId, status })
  } catch (err) {
    console.error('[Cloud] PATCH /api/cloud/findings/[id] error:', err)
    return NextResponse.json({ error: 'Failed to update finding' }, { status: 500 })
  }
}
```

```typescript
// src/app/api/cloud/inventory/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const scan = (id === 'demo' || id === MOCK_CLOUD_SCAN.id) ? MOCK_CLOUD_SCAN : getScan(id)
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  return NextResponse.json({ inventory: scan.inventory })
}
```

```typescript
// src/app/api/cloud/compliance/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const scan = (id === 'demo' || id === MOCK_CLOUD_SCAN.id) ? MOCK_CLOUD_SCAN : getScan(id)
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  return NextResponse.json({ complianceScores: scan.complianceScores, attackScenarios: scan.attackScenarios })
}
```

```typescript
// src/app/api/cloud/remediation/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { getScan } from '@/lib/cloud-scanner/scan-orchestrator'
import { MOCK_CLOUD_SCAN } from '@/lib/mock-data/cloud-scanner'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const scan = (id === 'demo' || id === MOCK_CLOUD_SCAN.id) ? MOCK_CLOUD_SCAN : getScan(id)
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  return NextResponse.json({ remediationQueue: scan.remediationQueue })
}
```

- [ ] **Step 2: Verify routes exist**

```bash
ls src/app/api/cloud/
```
Expected: `connect/`, `scans/`, `findings/`, `inventory/`, `compliance/`, `remediation/`

- [ ] **Step 3: Verify TypeScript**

```bash
npx tsc --noEmit 2>&1 | head -20
```

---

## Task 6: Cloud Scanner UI Page

**Files:**
- Create: `src/app/(dashboard)/dashboard/hemis/cloud/page.tsx`

This is the largest file (~2200 lines). Create it with these exact sections:

- [ ] **Step 1: Write page.tsx**

The page must have `'use client'` at top, import types from `@/lib/types/cloud-scanner`, import mock data from `@/lib/mock-data/cloud-scanner`, and follow inline CSS variable styling exactly as the WBRT page.

**State variables:**
```typescript
const [activeTab, setActiveTab] = useState<'connect'|'overview'|'findings'|'inventory'|'compliance'|'remediation'>('connect')
const [connectionStep, setConnectionStep] = useState<'setup'|'verify'|'connected'>('setup')
const [iframeMode, setIframeMode] = useState<'cloudformation'|'terraform'>('cloudformation')
const [roleArn, setRoleArn] = useState('')
const [externalId] = useState(`hemisx-${Math.random().toString(36).slice(2,10)}`)
const [isConnecting, setIsConnecting] = useState(false)
const [connectionError, setConnectionError] = useState<string|null>(null)
const [isScanning, setIsScanning] = useState(false)
const [scanProgress, setScanProgress] = useState(0)
const [scanPhase, setScanPhase] = useState('')
const [scan, setScan] = useState<CloudScan>(MOCK_CLOUD_SCAN)
const [severityFilter, setSeverityFilter] = useState('ALL')
const [categoryFilter, setCategoryFilter] = useState('ALL')
const [frameworkFilter, setFrameworkFilter] = useState('ALL')
const [expandedFindingId, setExpandedFindingId] = useState<string|null>(null)
const [activeRemTab, setActiveRemTab] = useState<'cli'|'terraform'|'cloudformation'>('cli')
const [inventoryCategory, setInventoryCategory] = useState<keyof CloudInventory>('ec2Instances')
```

**6 Tabs:**

**CONNECT tab** — 3-step wizard:
- Step 1 SETUP: Show the external ID generated for this session. Two code blocks side by side: CloudFormation YAML (copy button) and Terraform HCL (copy button). Toggle buttons to switch between them. Below: text input for Role ARN + "Test Connection" button.
- Step 2 VERIFY: Show spinner + "Testing connection to AWS..." with the role ARN being tested. After 1.5s → success.
- Step 3 CONNECTED: Green checkmark, "✓ Connected to acme-production (123456789012)". Show 3 discovered regions as badges. "Run Security Scan" big primary button.
- Progress dots at top of wizard (● ● ○ → ● ● ● as you progress).

**OVERVIEW tab** — Dashboard:
- Header: account alias + account ID badge + scan timestamp
- Risk score: big gauge (same SVG circle gauge as WBRT report)
- Stats row: 4 cards (Critical/High/Medium/Low counts) with colored left borders
- Attack Scenarios: 2 scenario cards showing title, severity badge, step count, finding count, breach cost estimate, narrative (first 200 chars + "...")
- Category breakdown: 3 progress bars (IAM/DATA/NETWORK) showing finding count vs total checks

**FINDINGS tab**:
- Filter bar: severity (ALL/CRITICAL/HIGH/MEDIUM/LOW), category (ALL/IAM/DATA/NETWORK), framework filter (ALL/CIS/PCI_DSS/SOC2/HIPAA)
- Findings count: "Showing X of Y findings"
- Cards (filtered): each card:
  - Header: checkId badge (mono, small), title (bold), severity badge (colored), category badge
  - Resource line: resourceType in dim text + resourceName in primary text
  - Risk narrative (first 180 chars, expandable)
  - Compliance impact badges row
  - Fix effort badge (colored: green=5min, yellow=1hr, orange=1day)
  - "Expand" button
  - Expanded: full risk narrative, attack vector, estimated impact, remediation tabs (Console/CLI/Terraform/CloudFormation), copy button for each code block

**INVENTORY tab**:
- Category buttons: EC2 Instances | S3 Buckets | RDS Instances | IAM Users | IAM Roles | Lambda | Security Groups | VPCs
- Resource count badge per category button
- Table for selected category: columns = Name, ARN (truncated), Region, Tags (first 2), Security Status (CLEAN=green, WARNING=yellow, CRITICAL=red badge), Findings count (if >0: clickable to switch to findings tab with filter)
- Total resources count at bottom

**COMPLIANCE tab**:
- 4 framework cards in a 2x2 grid: CIS, PCI_DSS, SOC2, HIPAA
  - Each card: framework name, compliance score (large %), circular progress ring, passed/failed/total counts
  - Colored by score: <40=red, 40-70=orange, >70=green
- Below: Active framework selector (clicking a card expands gap table below grid)
- Gap table for selected framework: Control ID | Control Name | Status (FAIL/PARTIAL badges) | Findings column (count links)

**REMEDIATION tab**:
- Intro: "Fix these issues in order — sorted by impact/effort ratio"
- Queue cards: each card has priority circle (1, 2, 3...), finding title, severity badge, effort badge, impactScore bar, estimated minutes, "View Fix" button
  - "View Fix" opens inline fix panel below the card: shows the remediation CLI/Terraform/CF code for that finding (copy button), "Mark as In Progress" button

**Color constants at top of file:**
```typescript
const SEV_COLOR: Record<string, string> = { CRITICAL: 'var(--color-sev-critical)', HIGH: 'var(--color-sev-high)', MEDIUM: 'var(--color-sev-medium)', LOW: 'var(--color-sev-low)', INFO: 'var(--color-text-dim)' }
const SEV_BG: Record<string, string> = { CRITICAL: 'rgba(239,90,90,0.15)', HIGH: 'rgba(242,142,60,0.15)', MEDIUM: 'rgba(242,209,86,0.15)', LOW: 'rgba(90,176,255,0.15)', INFO: 'rgba(139,168,200,0.1)' }
const EFFORT_COLOR: Record<string, string> = { '5min': '#00d4aa', '1hr': '#f2d156', '1day': '#f28e3c', '1week': '#ef5a5a' }
const CAT_COLOR: Record<string, string> = { IAM: '#b06aff', DATA: '#ef5a5a', NETWORK: '#5ab0ff' }
const FRAMEWORK_COLOR: Record<string, string> = { CIS: '#00d4aa', PCI_DSS: '#f28e3c', SOC2: '#5ab0ff', HIPAA: '#b06aff' }
```

- [ ] **Step 2: Verify TypeScript**

```bash
npx tsc --noEmit 2>&1 | head -30
```
Expected: no errors

---

## Task 7: Sidebar + Nav Integration

**Files:**
- Modify: `src/components/layout/sidebar.tsx` (add cloud scanner if not present)
- Modify: `src/app/(dashboard)/dashboard/hemis/cloud/page.tsx` (ensure correct path)

- [ ] **Step 1: Verify sidebar has cloud entry**

```bash
grep -n "cloud\|CLOUD\|scanner\|SCANNER" src/components/layout/sidebar.tsx
```

If the entry exists at `/dashboard/scanner` but the page is at `/dashboard/hemis/cloud`, update the href in the sidebar to match.

- [ ] **Step 2: Verify page route matches sidebar href**

Check what href is in the sidebar for the cloud product and ensure the page.tsx is at the corresponding path.

---

## Task 8: Final Verification

- [ ] **Step 1: Full TypeScript check**

```bash
cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit 2>&1
```
Expected: exit code 0, no output

- [ ] **Step 2: Verify all route files exist**

```bash
find src/app/api/cloud -name "route.ts" | sort
```
Expected: 9 route files

- [ ] **Step 3: Verify page exists**

```bash
ls src/app/(dashboard)/dashboard/hemis/cloud/page.tsx
```

- [ ] **Step 4: Check dev server**

Visit http://localhost:7777, navigate to Cloud Scanner. Verify:
- CONNECT tab shows CloudFormation/Terraform code blocks
- "Test Connection" flow works (1.5s → connected)
- "Run Scan" triggers progress bar animation through all phases
- After scan: OVERVIEW shows risk score 78, 4 critical findings
- FINDINGS tab shows 9 findings, filterable
- INVENTORY shows resources by category
- COMPLIANCE shows 4 framework scores
- REMEDIATION shows prioritized queue

- [ ] **Step 5: Commit**

```bash
git add src/lib/types/cloud-scanner.ts \
        src/lib/mock-data/cloud-scanner.ts \
        src/lib/cloud-scanner/ \
        src/app/api/cloud/ \
        src/app/(dashboard)/dashboard/hemis/cloud/
git commit -m "feat: add cloud misconfiguration scanner — AWS IAM/Data/Network checks, risk chaining, compliance mapping, IaC remediation, 6-tab UI"
```
