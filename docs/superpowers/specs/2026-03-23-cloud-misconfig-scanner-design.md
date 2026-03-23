# HemisX Cloud Misconfiguration Scanner — Design Spec

**Date:** 2026-03-23
**Status:** Approved
**Feature:** Full cloud misconfiguration scanner with 65-check library, risk chaining, compliance mapping, and IaC remediation

---

## 1. Executive Summary — What Makes It Supreme

Most cloud security scanners produce a flat list of findings with no context. HemisX Cloud Misconfig Scanner does three things that set it apart:

1. **Narrative findings** — every check produces a plain-English risk narrative explaining *why* the misconfiguration is dangerous, not just that it failed a policy line.
2. **Risk chaining engine** — the scanner identifies compound attack paths where two or more individually medium-severity findings combine into a critical kill chain (e.g., public S3 + no CloudTrail = silent data exfiltration with zero forensic evidence).
3. **Implementation-ready remediation** — every finding ships with estimated fix time, a copy-paste Terraform or CloudFormation snippet, and a compliance cross-reference so an engineer can go from finding to merged PR in under 30 minutes.

The scanner connects via a cross-account IAM role (read-only) deployed by a guided wizard. Zero credentials are stored. The STS assume-role + external ID pattern means HemisX never touches the customer's data plane — only the control plane metadata.

---

## 2. Connection Architecture

### 2.1 Model: Cross-Account IAM Role

HemisX never stores AWS access keys. The connection model is:

```
Customer AWS Account
  └── IAM Role: HemisXScannerRole
        ├── Trust Policy: allows sts:AssumeRole by HemisX AWS Account (123456789012)
        ├── External ID: hemis-{org_id}-{random_16}   ← prevents confused deputy
        └── Permissions: SecurityAudit (AWS managed) + custom inline policy
```

The HemisX backend calls `sts:AssumeRole` with the external ID at scan time, receives a short-lived credential set (15-minute session), performs all API calls, then discards the credentials. Nothing is persisted beyond the scan results.

### 2.2 Deployment Wizard

The UI presents a two-option wizard on the CONNECT tab:

**Option A — CloudFormation (recommended, 2 minutes)**

1. User clicks "Deploy via CloudFormation".
2. HemisX generates a pre-signed S3 URL pointing to a CloudFormation template.
3. Browser opens AWS Console → CloudFormation → Create Stack with the template pre-loaded.
4. Stack creates `HemisXScannerRole` with the correct trust policy and external ID embedded.
5. User pastes the generated Role ARN back into the HemisX UI.
6. HemisX calls `sts:AssumeRole` as a connectivity test; success = green checkmark.

**Option B — Terraform (infrastructure-as-code teams)**

1. HemisX renders a downloadable `hemis_scanner_role.tf` file with the org-specific external ID baked in.
2. Engineer runs `terraform apply` locally.
3. Terraform outputs the Role ARN; engineer pastes it into HemisX.

### 2.3 CloudFormation Template Structure

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: HemisX Cloud Scanner — read-only cross-account IAM role

Parameters:
  ExternalId:
    Type: String
    Description: HemisX-provided external ID for confused deputy protection

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
              AWS: arn:aws:iam::HEMIS_ACCOUNT_ID:root
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
      Policies:
        - PolicyName: HemisXExtendedReadOnly
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - access-analyzer:List*
                  - account:GetContactInformation
                  - s3:GetBucketPublicAccessBlock
                  - s3:GetBucketAcl
                  - s3:GetBucketPolicy
                  - s3:GetBucketPolicyStatus
                  - ec2:DescribeSecurityGroups
                  - ec2:DescribeNetworkAcls
                  - ec2:DescribeVpcs
                  - ec2:DescribeFlowLogs
                  - rds:DescribeDBInstances
                  - rds:DescribeDBSnapshots
                  - lambda:GetPolicy
                  - secretsmanager:ListSecrets
                  - secretsmanager:GetResourcePolicy
                  - kms:DescribeKey
                  - kms:GetKeyPolicy
                  - kms:GetKeyRotationStatus
                  - cloudtrail:DescribeTrails
                  - cloudtrail:GetTrailStatus
                  - guardduty:ListDetectors
                  - guardduty:GetDetector
                  - config:DescribeConfigurationRecorders
                  - config:DescribeDeliveryChannels
                  - iam:GenerateCredentialReport
                  - iam:GetCredentialReport
                  - iam:ListUsers
                  - iam:ListRoles
                  - iam:ListPolicies
                  - iam:GetAccountPasswordPolicy
                  - iam:ListMFADevices
                  - iam:ListAccessKeys
                  - iam:GetAccessKeyLastUsed
                Resource: "*"

Outputs:
  RoleArn:
    Value: !GetAtt HemisXScannerRole.Arn
    Description: Paste this ARN into HemisX to complete connection
```

### 2.4 Terraform Module Structure

```hcl
# hemis_scanner_role.tf
variable "hemis_external_id" {
  description = "External ID provided by HemisX during account connection"
  type        = string
}

variable "hemis_aws_account_id" {
  description = "HemisX AWS account ID (provided by HemisX)"
  type        = string
  default     = "HEMIS_ACCOUNT_ID"
}

resource "aws_iam_role" "hemis_scanner" {
  name = "HemisXScannerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.hemis_aws_account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.hemis_external_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.hemis_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

output "role_arn" {
  value       = aws_iam_role.hemis_scanner.arn
  description = "Paste this ARN into HemisX to complete connection"
}
```

### 2.5 STS Assume-Role Flow (Backend)

```
HemisX Backend (Node.js)
  1. Load account record from DB: { roleArn, externalId, region }
  2. Call AWS STS:
       sts.assumeRole({
         RoleArn: roleArn,
         RoleSessionName: "hemis-scan-{scanId}",
         ExternalId: externalId,
         DurationSeconds: 900   // 15 minutes
       })
  3. Receive: { AccessKeyId, SecretAccessKey, SessionToken, Expiration }
  4. Construct AWS SDK clients using temporary credentials
  5. Execute all check functions in parallel batches (max 10 concurrent)
  6. Persist findings to DB
  7. Credentials expire / are discarded — never written to disk or logs
```

---

## 3. The Check Library — 65 Checks

Checks are organized into three domains. Each check has an ID, name, severity, compliance tags, and produces a structured finding.

### 3.1 IAM Checks (25 checks)

| ID | Check Name | Severity | Compliance Tags |
|----|-----------|----------|----------------|
| IAM-001 | Root account has active access keys | CRITICAL | CIS 1.4, PCI-DSS 7.1, SOC2 CC6.1 |
| IAM-002 | Root account used in last 90 days | CRITICAL | CIS 1.1, SOC2 CC6.1 |
| IAM-003 | MFA not enabled for root account | CRITICAL | CIS 1.5, PCI-DSS 8.4, HIPAA 164.312 |
| IAM-004 | MFA not enabled for console IAM users | HIGH | CIS 1.10, PCI-DSS 8.4 |
| IAM-005 | Password policy does not require minimum length (< 14 chars) | HIGH | CIS 1.8, PCI-DSS 8.3 |
| IAM-006 | Password policy does not prevent password reuse (< 24 remembered) | MEDIUM | CIS 1.9, PCI-DSS 8.3 |
| IAM-007 | Password policy does not expire passwords (> 90 days) | MEDIUM | CIS 1.11, PCI-DSS 8.3 |
| IAM-008 | Access keys not rotated in 90+ days | HIGH | CIS 1.14, PCI-DSS 8.6 |
| IAM-009 | Access keys not rotated in 180+ days | CRITICAL | CIS 1.14, PCI-DSS 8.6 |
| IAM-010 | Unused access keys active for 45+ days (no last-used date) | HIGH | CIS 1.12 |
| IAM-011 | Inline policies attached directly to users (not roles/groups) | MEDIUM | CIS 1.16 |
| IAM-012 | Wildcard `*` action in customer-managed IAM policy | HIGH | CIS 1.16, SOC2 CC6.3 |
| IAM-013 | Wildcard `*` resource in customer-managed IAM policy | HIGH | CIS 1.16, SOC2 CC6.3 |
| IAM-014 | IAM user with both console access and active access keys | MEDIUM | CIS 1.15 |
| IAM-015 | Service role allows `sts:AssumeRole` with no condition (open trust) | HIGH | SOC2 CC6.3 |
| IAM-016 | IAM role cross-account trust to unknown external account | HIGH | SOC2 CC6.3, CIS 1.20 |
| IAM-017 | IAM Access Analyzer not enabled in all regions | MEDIUM | CIS 1.20, SOC2 CC7.1 |
| IAM-018 | No IAM policy for emergency break-glass procedure | LOW | SOC2 CC6.1 |
| IAM-019 | More than 1 IAM user with AdministratorAccess policy | HIGH | CIS 1.16, PCI-DSS 7.1 |
| IAM-020 | IAM user credentials unused for 45 days not disabled | HIGH | CIS 1.12 |
| IAM-021 | Lambda execution role has overly broad permissions (admin/wildcard) | HIGH | SOC2 CC6.3 |
| IAM-022 | EC2 instance profile with AdministratorAccess | CRITICAL | CIS 1.16, SOC2 CC6.3 |
| IAM-023 | No MFA delete on S3 versioning-enabled bucket | MEDIUM | CIS 2.1.3 |
| IAM-024 | Support role not configured (no aws-support policy attached to any role) | LOW | CIS 1.17 |
| IAM-025 | IAM credential report older than 24 hours (stale visibility) | LOW | CIS 1.1 |

### 3.2 Data Exposure Checks (20 checks)

| ID | Check Name | Severity | Compliance Tags |
|----|-----------|----------|----------------|
| DE-001 | S3 bucket has public ACL (AllUsers or AuthenticatedUsers READ/WRITE) | CRITICAL | CIS 2.1.5, PCI-DSS 1.3, HIPAA 164.312 |
| DE-002 | S3 bucket policy allows `*` principal (public bucket policy) | CRITICAL | CIS 2.1.5, PCI-DSS 1.3 |
| DE-003 | S3 bucket does not block public access at account level | HIGH | CIS 2.1.4 |
| DE-004 | S3 bucket does not block public access at bucket level | HIGH | CIS 2.1.4 |
| DE-005 | S3 bucket has no server-side encryption (no SSE-S3 or SSE-KMS) | HIGH | CIS 2.1.1, PCI-DSS 3.4, HIPAA 164.312 |
| DE-006 | S3 bucket uses SSE-S3 instead of SSE-KMS (weaker key management) | LOW | PCI-DSS 3.4 |
| DE-007 | S3 bucket versioning disabled | MEDIUM | CIS 2.1.3, SOC2 A1.2 |
| DE-008 | S3 bucket has no lifecycle policy (unbounded data retention) | LOW | SOC2 A1.2 |
| DE-009 | RDS instance publicly accessible | CRITICAL | CIS 2.3.1, PCI-DSS 1.3, HIPAA 164.312 |
| DE-010 | RDS instance not encrypted at rest | HIGH | CIS 2.3.1, PCI-DSS 3.4, HIPAA 164.312 |
| DE-011 | RDS automated backups disabled | HIGH | CIS 2.3.2, SOC2 A1.2 |
| DE-012 | RDS snapshot is publicly restorable | CRITICAL | CIS 2.3.3, PCI-DSS 1.3 |
| DE-013 | RDS deletion protection disabled on production-tagged instance | MEDIUM | SOC2 A1.2 |
| DE-014 | Secrets Manager secret not rotated in 90+ days | HIGH | CIS 2.1, PCI-DSS 8.6, SOC2 CC6.1 |
| DE-015 | Secrets Manager secret has no rotation configured | MEDIUM | PCI-DSS 8.6 |
| DE-016 | KMS key has no key rotation enabled | HIGH | CIS 3.8, PCI-DSS 3.6 |
| DE-017 | KMS key policy allows `*` principal (cross-account decrypt) | CRITICAL | CIS 3.8, PCI-DSS 3.4 |
| DE-018 | DynamoDB table not encrypted with customer-managed KMS key | LOW | PCI-DSS 3.4, HIPAA 164.312 |
| DE-019 | EBS volume not encrypted | HIGH | CIS 2.2.1, PCI-DSS 3.4, HIPAA 164.312 |
| DE-020 | EBS snapshot is public | CRITICAL | CIS 2.2.1, PCI-DSS 1.3 |

### 3.3 Network & Perimeter Checks (20 checks)

| ID | Check Name | Severity | Compliance Tags |
|----|-----------|----------|----------------|
| NP-001 | Security group allows SSH (port 22) from 0.0.0.0/0 | CRITICAL | CIS 5.2, PCI-DSS 1.2 |
| NP-002 | Security group allows RDP (port 3389) from 0.0.0.0/0 | CRITICAL | CIS 5.3, PCI-DSS 1.2 |
| NP-003 | Security group allows all traffic inbound (0.0.0.0/0 all ports) | CRITICAL | CIS 5.4, PCI-DSS 1.2 |
| NP-004 | Security group allows inbound from 0.0.0.0/0 on non-standard port | HIGH | CIS 5.4 |
| NP-005 | Default VPC security group has inbound rules (not empty) | HIGH | CIS 5.4 |
| NP-006 | Default VPC in use (workloads not in custom VPC) | MEDIUM | CIS 5.1, SOC2 CC6.6 |
| NP-007 | VPC has no Flow Logs enabled | HIGH | CIS 3.9, PCI-DSS 10.2, SOC2 CC7.2 |
| NP-008 | VPC peering connection with no DNS resolution restriction | LOW | SOC2 CC6.6 |
| NP-009 | Subnet auto-assigns public IP on launch | MEDIUM | CIS 5.1 |
| NP-010 | Internet Gateway attached to VPC with no route table restriction | HIGH | SOC2 CC6.6 |
| NP-011 | Network ACL allows all inbound traffic (0.0.0.0/0, all ports) | HIGH | CIS 5.4, PCI-DSS 1.2 |
| NP-012 | Network ACL allows all outbound traffic (unrestricted egress) | MEDIUM | PCI-DSS 1.2 |
| NP-013 | CloudTrail not enabled in all regions | CRITICAL | CIS 3.1, PCI-DSS 10.1, SOC2 CC7.2 |
| NP-014 | CloudTrail not logging management events | HIGH | CIS 3.4, PCI-DSS 10.2 |
| NP-015 | CloudTrail log file validation disabled | HIGH | CIS 3.2, PCI-DSS 10.5 |
| NP-016 | CloudTrail S3 bucket has public access | CRITICAL | CIS 3.3, PCI-DSS 10.5 |
| NP-017 | AWS Config not enabled in all regions | HIGH | CIS 3.5, SOC2 CC7.1 |
| NP-018 | GuardDuty not enabled in all regions | HIGH | CIS 4.1, SOC2 CC7.2 |
| NP-019 | EC2 instance has a public IP in a non-DMZ subnet | MEDIUM | CIS 5.1 |
| NP-020 | WAF not associated with internet-facing ALB or API Gateway | HIGH | PCI-DSS 6.6, SOC2 CC6.6 |

---

## 4. Finding Structure

Every check produces a finding object with the following schema. The goal is that a non-security engineer can read a finding and immediately understand what to do.

### 4.1 Finding Data Model

```typescript
interface CloudFinding {
  // Identity
  id: string;                        // e.g., "finding_abc123"
  checkId: string;                   // e.g., "IAM-003"
  accountId: string;                 // AWS account ID
  region: string;                    // e.g., "us-east-1" or "global"
  resourceId: string;                // ARN or resource identifier
  resourceType: string;              // e.g., "AWS::IAM::User", "AWS::S3::Bucket"
  resourceName: string;              // human-readable name if available

  // Severity & Risk
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvssScore?: number;                // 0.0–10.0 where applicable

  // The Three Core Narrative Fields
  riskNarrative: string;             // 2–4 sentences: what can an attacker do with this?
  complianceImpact: ComplianceImpact[];
  remediation: Remediation;

  // Risk Chaining
  chainIds?: string[];               // IDs of other findings this combines with
  compoundSeverity?: "CRITICAL" | "HIGH"; // severity of the compound path

  // Metadata
  detectedAt: string;                // ISO 8601
  scanId: string;
  status: "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "SUPPRESSED";
  suppressedUntil?: string;          // ISO 8601, for time-boxed suppression
  resolvedAt?: string;
}

interface ComplianceImpact {
  standard: "CIS" | "PCI-DSS" | "SOC2" | "HIPAA" | "NIST";
  control: string;                   // e.g., "CIS 1.5", "PCI-DSS 8.4.2"
  description: string;               // one sentence on the specific control requirement
}

interface Remediation {
  summary: string;                   // one-line fix description
  fixTimeEstimate: string;           // e.g., "5 minutes", "30 minutes", "2 hours"
  steps: string[];                   // ordered list of manual steps
  iacCode: IaCCode;
  references: string[];              // AWS docs URLs
}

interface IaCCode {
  terraform?: string;                // HCL block, copy-paste ready
  cloudformation?: string;           // YAML snippet, copy-paste ready
  awsCli?: string;                   // fallback CLI command
}
```

### 4.2 Example Finding — IAM-003 (MFA not enabled for root)

```json
{
  "id": "finding_7a3c9f1e",
  "checkId": "IAM-003",
  "accountId": "123456789012",
  "region": "global",
  "resourceId": "arn:aws:iam::123456789012:root",
  "resourceType": "AWS::IAM::User",
  "resourceName": "root",
  "severity": "CRITICAL",
  "cvssScore": 9.8,
  "riskNarrative": "The root account has no Multi-Factor Authentication (MFA) device enrolled. An attacker who obtains the root password — through credential stuffing, phishing, or a data breach — gains unrestricted access to every resource in the AWS account with no additional barrier. Root can delete all IAM users, disable CloudTrail to erase evidence, exfiltrate all S3 data, and terminate every running workload. This is the single highest-impact finding in any AWS account.",
  "complianceImpact": [
    {
      "standard": "CIS",
      "control": "CIS 1.5",
      "description": "CIS AWS Foundations Benchmark requires hardware or virtual MFA on the root account."
    },
    {
      "standard": "PCI-DSS",
      "control": "PCI-DSS 8.4.2",
      "description": "PCI-DSS requires MFA for all access into the cardholder data environment."
    },
    {
      "standard": "SOC2",
      "control": "SOC2 CC6.1",
      "description": "SOC2 CC6.1 requires logical access controls that restrict access to only authorized users."
    }
  ],
  "remediation": {
    "summary": "Enable a virtual or hardware MFA device on the AWS root account via the IAM console.",
    "fixTimeEstimate": "5 minutes",
    "steps": [
      "Sign in to the AWS Management Console as root.",
      "Navigate to IAM → Security credentials (click your account name top-right → Security credentials).",
      "Under 'Multi-factor authentication (MFA)', click 'Assign MFA device'.",
      "Select 'Authenticator app' for virtual MFA or 'Hardware TOTP token' for physical device.",
      "Follow the wizard to scan the QR code and enter two consecutive TOTP codes.",
      "Click 'Add MFA' to complete enrollment.",
      "Verify: sign out and sign back in as root — you should be prompted for MFA."
    ],
    "iacCode": {
      "awsCli": "# MFA enrollment cannot be automated via CLI for root — must be performed in console.\n# After enabling, enforce MFA usage with a preventive SCP:\naws organizations create-policy --type SERVICE_CONTROL_POLICY --name RequireRootMFA --content file://require-root-mfa-scp.json",
      "terraform": "# Root MFA enrollment is a console-only operation. Use this SCP to enforce MFA at the org level:\nresource \"aws_organizations_policy\" \"require_mfa\" {\n  name    = \"RequireMFAForSensitiveOps\"\n  type    = \"SERVICE_CONTROL_POLICY\"\n  content = jsonencode({\n    Version = \"2012-10-17\"\n    Statement = [{\n      Sid      = \"DenyWithoutMFA\"\n      Effect   = \"Deny\"\n      Action   = [\"iam:*\", \"organizations:*\", \"account:*\"]\n      Resource = \"*\"\n      Condition = {\n        BoolIfExists = {\n          \"aws:MultiFactorAuthPresent\" = \"false\"\n        }\n      }\n    }]\n  })\n}"
    },
    "references": [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html"
    ]
  },
  "detectedAt": "2026-03-23T10:15:00Z",
  "scanId": "scan_9b1d2e3f",
  "status": "OPEN"
}
```

### 4.3 Example Finding — DE-001 (S3 public ACL)

```json
{
  "id": "finding_2c8d4f0a",
  "checkId": "DE-001",
  "accountId": "123456789012",
  "region": "us-east-1",
  "resourceId": "arn:aws:s3:::acme-customer-uploads",
  "resourceType": "AWS::S3::Bucket",
  "resourceName": "acme-customer-uploads",
  "severity": "CRITICAL",
  "cvssScore": 9.1,
  "riskNarrative": "The S3 bucket 'acme-customer-uploads' has a public ACL granting READ access to AllUsers (unauthenticated internet). Any person with internet access can enumerate and download every object in this bucket without credentials. If this bucket stores customer PII, documents, or application data, this constitutes an active data exposure incident. Public write access would additionally allow an attacker to upload malicious files that could be served to end users.",
  "complianceImpact": [
    {
      "standard": "PCI-DSS",
      "control": "PCI-DSS 1.3.2",
      "description": "PCI-DSS prohibits unrestricted inbound or outbound traffic to/from the cardholder data environment."
    },
    {
      "standard": "HIPAA",
      "control": "HIPAA 164.312(a)(1)",
      "description": "HIPAA requires access controls limiting access to ePHI to only authorized persons."
    },
    {
      "standard": "CIS",
      "control": "CIS 2.1.5",
      "description": "CIS AWS Foundations requires S3 buckets not to allow public read or write ACLs."
    }
  ],
  "remediation": {
    "summary": "Remove the public ACL and enable S3 Block Public Access at the bucket level.",
    "fixTimeEstimate": "10 minutes",
    "steps": [
      "Navigate to S3 console → bucket 'acme-customer-uploads' → Permissions tab.",
      "Under 'Block public access (bucket settings)', click Edit and enable all four Block Public Access settings.",
      "Save changes.",
      "Under 'Access Control List (ACL)', click Edit and remove any 'Everyone' or 'Authenticated users' entries.",
      "Review bucket policy for any Statement with Principal: '*' and remove or restrict it.",
      "Verify no objects have individual public ACLs: run the AWS CLI command in the IaC section."
    ],
    "iacCode": {
      "awsCli": "# Block public access\naws s3api put-public-access-block \\\n  --bucket acme-customer-uploads \\\n  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n\n# Remove bucket ACL (set to private)\naws s3api put-bucket-acl --bucket acme-customer-uploads --acl private",
      "terraform": "resource \"aws_s3_bucket_public_access_block\" \"acme_customer_uploads\" {\n  bucket = \"acme-customer-uploads\"\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n\nresource \"aws_s3_bucket_acl\" \"acme_customer_uploads\" {\n  bucket = \"acme-customer-uploads\"\n  acl    = \"private\"\n}",
      "cloudformation": "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  AcmeCustomerUploadsPublicAccessBlock:\n    Type: AWS::S3::BucketPublicAccessBlock\n    Properties:\n      Bucket: acme-customer-uploads\n      BlockPublicAcls: true\n      BlockPublicPolicy: true\n      IgnorePublicAcls: true\n      RestrictPublicBuckets: true"
    },
    "references": [
      "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
      "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"
    ]
  },
  "detectedAt": "2026-03-23T10:15:00Z",
  "scanId": "scan_9b1d2e3f",
  "status": "OPEN"
}
```

---

## 5. Risk Chaining Engine

### 5.1 Concept

A single MEDIUM finding is manageable. Two MEDIUM findings that form an attack path together become a CRITICAL business risk. The risk chaining engine identifies these compound paths and surfaces them as "Attack Chains" — distinct from individual findings.

### 5.2 Chain Detection Algorithm

After all 65 checks complete, the engine runs a post-processing pass:

```
1. Build a findings map: { checkId → Finding[] }
2. For each ChainRule in the chain rule library:
   a. Check if all required checkIds have findings for the same account
   b. If yes, instantiate a CompoundRisk record
   c. Set compoundSeverity (always >= max severity of individual findings)
   d. Write chainIds back to each participating Finding
3. Persist CompoundRisk records alongside individual findings
```

### 5.3 Chain Rule Library (12 predefined chains)

| Chain ID | Name | Required Findings | Compound Severity | Description |
|----------|------|-------------------|-------------------|-------------|
| CHAIN-001 | Silent Data Exfiltration | DE-001 or DE-002 + NP-013 | CRITICAL | Public S3 bucket with no CloudTrail: attacker downloads all data with zero log evidence |
| CHAIN-002 | Privilege Escalation via Weak IAM | IAM-012 or IAM-013 + IAM-004 | CRITICAL | Wildcard IAM policy + no user MFA: attacker compromises any user and becomes admin |
| CHAIN-003 | Lateral Movement via Open Network | NP-001 + NP-007 | CRITICAL | SSH open to internet + no VPC Flow Logs: attacker pivots to internal resources undetected |
| CHAIN-004 | Database Takeover | DE-009 + IAM-003 | CRITICAL | Public RDS + no root MFA: attacker gains DB access and can escalate to full account compromise |
| CHAIN-005 | Stealthy Persistence | IAM-003 + NP-013 | CRITICAL | No root MFA + CloudTrail disabled: attacker creates backdoor IAM users with no forensic trail |
| CHAIN-006 | Snapshot Data Breach | DE-012 or DE-020 + DE-005 | CRITICAL | Public RDS/EBS snapshot + unencrypted data: attacker restores snapshot and reads all data |
| CHAIN-007 | Credential Harvest | IAM-008 or IAM-009 + IAM-017 | HIGH | Stale access keys + no IAM Access Analyzer: active keys leaked with no detection |
| CHAIN-008 | Ransomware Precondition | DE-007 + NP-001 | HIGH | S3 versioning off + SSH open: attacker enters via SSH, deletes S3 objects, no recovery |
| CHAIN-009 | Compliance Audit Failure | NP-013 + NP-017 | HIGH | No CloudTrail + no AWS Config: zero audit evidence, automatic compliance failure |
| CHAIN-010 | Unrestricted Blast Radius | IAM-022 + NP-003 | CRITICAL | EC2 instance with admin role + SG allowing all traffic: any SSRF gives full account access |
| CHAIN-011 | Secret Exposure Path | DE-014 + DE-001 | CRITICAL | Unrotated secrets + public S3: if secrets were ever logged/written to S3, they are publicly readable |
| CHAIN-012 | Account Takeover via Password Spray | IAM-005 + IAM-004 + NP-018 | CRITICAL | Weak passwords + no MFA + no GuardDuty: password spray undetected, accounts compromised |

### 5.4 CompoundRisk Data Model

```typescript
interface CompoundRisk {
  id: string;                        // e.g., "chain_a1b2c3"
  chainId: string;                   // e.g., "CHAIN-001"
  name: string;
  accountId: string;
  severity: "CRITICAL" | "HIGH";
  participatingFindingIds: string[]; // finding IDs that form this chain
  attackNarrative: string;           // 3–5 sentence story of the full attack path
  businessImpact: string;            // dollar/reputation impact framing
  remediationPriority: number;       // 1 = fix this first
  detectedAt: string;
  scanId: string;
}
```

---

## 6. UI — Six Tabs

The cloud scanner UI is a full-page view within the HemisX app. It has six tabs rendered in a top tab bar:

```
[ CONNECT ]  [ OVERVIEW ]  [ FINDINGS ]  [ INVENTORY ]  [ COMPLIANCE ]  [ REMEDIATION ]
```

### 6.1 CONNECT Tab

**Purpose:** Add and manage cloud accounts.

**Layout:**
- Page header: "Cloud Accounts" with "+ Add Account" button (top right)
- Account cards grid (2 columns): each card shows AWS account ID, alias, connection status, last scan time, region count, finding summary (CRITICAL / HIGH / MEDIUM badges)
- Empty state: large centered illustration + "Connect your first AWS account to begin scanning"

**Add Account Modal (stepped wizard):**
- Step 1 — Account details: input fields for Account ID, Display Name, Primary Region
- Step 2 — Deploy role: two option cards (CloudFormation / Terraform), each with a "Download" or "Open in Console" button; shows the org-specific external ID in a monospace copy box
- Step 3 — Verify: input field for Role ARN; "Test Connection" button; success shows green checkmark + account alias fetched from AWS

**Connection status badges:**
- CONNECTED (green) — last scan < 24h ago
- CONNECTED (yellow) — last scan > 24h ago
- ERROR (red) — assume-role failed; shows error message
- PENDING (grey) — role not yet verified

### 6.2 OVERVIEW Tab

**Purpose:** Executive-level snapshot of the entire cloud security posture across all connected accounts.

**Layout (top to bottom):**

**Row 1 — KPI Cards (5 cards):**
- Total Findings (number + delta vs. last scan)
- Critical Findings (red badge)
- Attack Chains Detected (amber badge with chain icon)
- Compliance Score (percentage, color-coded green/yellow/red)
- Resources Scanned (total resource count)

**Row 2 — Severity Trend Chart:**
- Line chart: x-axis = last 30 days, y-axis = finding count, four lines by severity (CRITICAL red, HIGH orange, MEDIUM yellow, LOW blue)
- Hover tooltip shows exact counts per day

**Row 3 — Two columns:**
- Left: "Top Attack Chains" — ordered list of up to 5 compound risks with severity badge, name, and "View Details" link
- Right: "Findings by Category" — horizontal bar chart (IAM / Data Exposure / Network & Perimeter) with count and percentage

**Row 4 — Compliance Coverage:**
- Row of compliance standard cards: CIS, PCI-DSS, SOC2, HIPAA, NIST
- Each card shows: standard name, pass/fail count, percentage score, colored progress arc

**Row 5 — Recent Activity:**
- Table: timestamp, event type (finding opened/resolved, scan completed, new chain detected), account, details

### 6.3 FINDINGS Tab

**Purpose:** Full findings list with filtering, sorting, bulk actions.

**Layout:**

**Filter bar (horizontal):**
- Search input (filters by resource name, check ID, or narrative text)
- Severity multi-select: CRITICAL / HIGH / MEDIUM / LOW
- Category multi-select: IAM / Data Exposure / Network
- Status filter: OPEN / ACKNOWLEDGED / SUPPRESSED / RESOLVED
- Account filter (if multi-account)
- Region filter
- Compliance standard filter

**Findings table:**
| Column | Content |
|--------|---------|
| Severity | Colored badge (CRITICAL / HIGH / MEDIUM / LOW) |
| Check ID | e.g., IAM-003, monospace chip |
| Resource | resourceName + resourceType icon |
| Account | account alias + account ID |
| Region | AWS region |
| Risk Summary | First sentence of riskNarrative |
| Compliance | Compliance standard chips (up to 3) |
| Detected | relative time (e.g., "2 hours ago") |
| Status | status badge |
| Actions | "Details" button |

**Row click → Finding Detail Drawer (slides in from right):**
- Header: severity badge + check ID + resource name
- Tab set within drawer: OVERVIEW / COMPLIANCE / REMEDIATION / HISTORY
  - OVERVIEW: full riskNarrative, resource details, CVSS score, chain membership if applicable
  - COMPLIANCE: table of all complianceImpact entries with standard, control, description
  - REMEDIATION: fixTimeEstimate chip, ordered steps list, IaC code block (tabs: Terraform / CloudFormation / AWS CLI), copy button
  - HISTORY: timeline of status changes, who acknowledged, notes

**Bulk actions (appear when rows selected):**
- Acknowledge selected
- Suppress for 30 days / 90 days
- Export as CSV / JSON

### 6.4 INVENTORY Tab

**Purpose:** Visualize all cloud resources discovered, grouped by type and region.

**Layout:**

**Top row — Resource summary chips:**
- EC2 Instances (count), S3 Buckets (count), RDS Instances (count), Lambda Functions (count), IAM Users (count), IAM Roles (count), VPCs (count), Security Groups (count)

**Main area — Resource table with toggle (Table / Card view):**

Table columns:
| Column | Content |
|--------|---------|
| Resource Type | AWS icon + resource type label |
| Name / ID | resourceName or ARN |
| Region | region flag + name |
| Account | account alias |
| Open Findings | colored count pills per severity |
| Tags | up to 3 tag key:value chips |
| Last Seen | relative time |

Card view: 3-column grid of resource cards; each card shows type icon, name, region, and a mini severity bar.

**Filters:** resource type, region, account, tag key/value, "has findings only" toggle.

**Row/card click → Resource Detail Drawer:**
- Full resource metadata (ARN, creation date, tags)
- List of findings for this specific resource
- Compliance impact summary

### 6.5 COMPLIANCE Tab

**Purpose:** Map all findings to compliance frameworks and track pass/fail rates per control.

**Layout:**

**Standard selector (top):** Tab pills — CIS AWS Foundations / PCI-DSS / SOC2 / HIPAA / NIST 800-53

**Per-standard view:**
- Header: standard name, version, overall score (% controls passing), last assessed date
- Progress bar: green (passing) / red (failing) / grey (not applicable)

**Controls table:**
| Column | Content |
|--------|---------|
| Control ID | e.g., CIS 1.5 |
| Control Name | short description |
| Status | PASSING / FAILING / NOT APPLICABLE badge |
| Checks Mapped | number of HemisX checks covering this control |
| Open Findings | count of open findings |
| Details | expand row |

Expanding a control row shows:
- Full control description
- List of mapped HemisX checks with pass/fail per check
- Links to each failing finding

**Export button (top right):** "Export Compliance Report" → generates a PDF summary with executive narrative, control-by-control table, and remediation recommendations.

### 6.6 REMEDIATION Tab

**Purpose:** Prioritized remediation queue — a single place to work through all open findings ordered by business impact.

**Layout:**

**Remediation Queue header:**
- Total open findings count
- Estimated total fix time (sum of fixTimeEstimate across all OPEN findings)
- "Quick Wins" count (findings with fix time ≤ 10 minutes)

**Priority queue (ordered list):**
Each item in the queue is a remediation card:

```
┌─────────────────────────────────────────────────────────┐
│  [CRITICAL]  IAM-003 · Root MFA Not Enabled · global    │
│                                                         │
│  Fix time: 5 minutes                                    │
│  Risk: An attacker with the root password gains...      │
│                                                         │
│  [ Terraform ]  [ CloudFormation ]  [ AWS CLI ]         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ # MFA enrollment is console-only...             │   │
│  │ aws organizations create-policy ...             │   │
│  └─────────────────────────────────────────────────┘   │
│                          [Copy]  [Mark Resolved]        │
└─────────────────────────────────────────────────────────┘
```

**Ordering logic:**
1. Attack chain members first (sorted by chain remediationPriority)
2. Then individual findings by severity (CRITICAL → LOW)
3. Within same severity, by fixTimeEstimate ascending (quick wins first)

**Filters (sidebar):**
- "Quick Wins only" (≤ 10 min fix)
- By account
- By category
- By compliance standard

**Batch Export:**
- "Export Remediation Plan" → Markdown or PDF document with all steps, IaC snippets, and estimated total effort

---

## 7. Full File Architecture

```
hemis-app/
├── src/
│   ├── app/
│   │   └── cloud/
│   │       ├── page.tsx                          # Cloud scanner root page — renders 6-tab layout
│   │       └── [accountId]/
│   │           └── page.tsx                      # Per-account deep-link view
│   │
│   ├── components/
│   │   └── cloud/
│   │       ├── CloudScannerTabs.tsx              # Top-level 6-tab container component
│   │       │
│   │       ├── connect/
│   │       │   ├── ConnectTab.tsx                # CONNECT tab root
│   │       │   ├── AccountCard.tsx               # Connected account summary card
│   │       │   ├── AddAccountModal.tsx           # Stepped wizard modal
│   │       │   ├── DeployRoleStep.tsx            # Step 2: CloudFormation / Terraform option cards
│   │       │   ├── VerifyRoleStep.tsx            # Step 3: Role ARN input + test connection
│   │       │   └── ConnectionStatusBadge.tsx     # CONNECTED / ERROR / PENDING badge
│   │       │
│   │       ├── overview/
│   │       │   ├── OverviewTab.tsx               # OVERVIEW tab root
│   │       │   ├── KpiCards.tsx                  # 5-card KPI row
│   │       │   ├── SeverityTrendChart.tsx        # 30-day line chart (recharts)
│   │       │   ├── TopAttackChains.tsx           # Top 5 compound risks list
│   │       │   ├── FindingsByCategory.tsx        # Horizontal bar chart
│   │       │   ├── ComplianceCoverageRow.tsx     # Standard arc cards row
│   │       │   └── RecentActivityFeed.tsx        # Activity timeline table
│   │       │
│   │       ├── findings/
│   │       │   ├── FindingsTab.tsx               # FINDINGS tab root
│   │       │   ├── FindingsFilterBar.tsx         # Filter bar (search, severity, category, etc.)
│   │       │   ├── FindingsTable.tsx             # Main findings data table
│   │       │   ├── FindingRow.tsx                # Single table row component
│   │       │   ├── FindingDetailDrawer.tsx       # Right-side detail drawer
│   │       │   ├── FindingOverviewPanel.tsx      # Drawer OVERVIEW sub-tab
│   │       │   ├── FindingCompliancePanel.tsx    # Drawer COMPLIANCE sub-tab
│   │       │   ├── FindingRemediationPanel.tsx   # Drawer REMEDIATION sub-tab (IaC code blocks)
│   │       │   ├── FindingHistoryPanel.tsx       # Drawer HISTORY sub-tab
│   │       │   ├── IacCodeBlock.tsx              # Tabbed Terraform/CF/CLI code display with copy button
│   │       │   ├── SeverityBadge.tsx             # Reusable severity chip
│   │       │   └── BulkActionsBar.tsx            # Bulk acknowledge/suppress/export bar
│   │       │
│   │       ├── inventory/
│   │       │   ├── InventoryTab.tsx              # INVENTORY tab root
│   │       │   ├── ResourceSummaryChips.tsx      # Count chips by resource type
│   │       │   ├── ResourceTable.tsx             # Table view of all resources
│   │       │   ├── ResourceCardGrid.tsx          # Card grid view
│   │       │   ├── ResourceCard.tsx              # Single resource card
│   │       │   ├── ResourceDetailDrawer.tsx      # Resource detail side panel
│   │       │   └── InventoryViewToggle.tsx       # Table / Card toggle button
│   │       │
│   │       ├── compliance/
│   │       │   ├── ComplianceTab.tsx             # COMPLIANCE tab root
│   │       │   ├── StandardSelector.tsx          # Tab pills: CIS / PCI-DSS / SOC2 / HIPAA / NIST
│   │       │   ├── StandardScoreHeader.tsx       # Score, progress bar, last assessed date
│   │       │   ├── ControlsTable.tsx             # Controls with pass/fail per row
│   │       │   ├── ControlRow.tsx                # Expandable control row
│   │       │   ├── ControlDetailExpanded.tsx     # Expanded control detail with linked findings
│   │       │   └── ComplianceReportExport.tsx    # PDF export trigger + modal
│   │       │
│   │       └── remediation/
│   │           ├── RemediationTab.tsx            # REMEDIATION tab root
│   │           ├── RemediationQueueHeader.tsx    # Total count, estimated time, quick wins
│   │           ├── RemediationCard.tsx           # Single remediation queue card with IaC
│   │           ├── RemediationSidebar.tsx        # Filter sidebar (quick wins, account, category)
│   │           └── BatchExportButton.tsx         # Export remediation plan as MD/PDF
│   │
│   ├── lib/
│   │   └── cloud/
│   │       ├── scanner/
│   │       │   ├── index.ts                      # Scanner orchestrator — initiates scan, batches checks
│   │       │   ├── stsClient.ts                  # STS assume-role logic, credential management
│   │       │   ├── awsClients.ts                 # Factory: build SDK clients from temp credentials
│   │       │   │
│   │       │   ├── checks/
│   │       │   │   ├── iam/
│   │       │   │   │   ├── index.ts              # Exports all 25 IAM checks
│   │       │   │   │   ├── IAM001_rootAccessKeys.ts
│   │       │   │   │   ├── IAM002_rootUsageRecent.ts
│   │       │   │   │   ├── IAM003_rootMfa.ts
│   │       │   │   │   ├── IAM004_userMfa.ts
│   │       │   │   │   ├── IAM005_passwordMinLength.ts
│   │       │   │   │   ├── IAM006_passwordReuse.ts
│   │       │   │   │   ├── IAM007_passwordExpiry.ts
│   │       │   │   │   ├── IAM008_accessKeyAge90.ts
│   │       │   │   │   ├── IAM009_accessKeyAge180.ts
│   │       │   │   │   ├── IAM010_unusedAccessKeys.ts
│   │       │   │   │   ├── IAM011_inlinePolicies.ts
│   │       │   │   │   ├── IAM012_wildcardAction.ts
│   │       │   │   │   ├── IAM013_wildcardResource.ts
│   │       │   │   │   ├── IAM014_dualAccessUser.ts
│   │       │   │   │   ├── IAM015_openRoleTrust.ts
│   │       │   │   │   ├── IAM016_crossAccountTrust.ts
│   │       │   │   │   ├── IAM017_accessAnalyzer.ts
│   │       │   │   │   ├── IAM018_breakGlassPolicy.ts
│   │       │   │   │   ├── IAM019_multipleAdmins.ts
│   │       │   │   │   ├── IAM020_staleCredentials.ts
│   │       │   │   │   ├── IAM021_lambdaRolePermissions.ts
│   │       │   │   │   ├── IAM022_ec2AdminProfile.ts
│   │       │   │   │   ├── IAM023_mfaDeleteS3.ts
│   │       │   │   │   ├── IAM024_supportRole.ts
│   │       │   │   │   └── IAM025_credentialReportAge.ts
│   │       │   │   │
│   │       │   │   ├── dataExposure/
│   │       │   │   │   ├── index.ts              # Exports all 20 data exposure checks
│   │       │   │   │   ├── DE001_s3PublicAcl.ts
│   │       │   │   │   ├── DE002_s3PublicBucketPolicy.ts
│   │       │   │   │   ├── DE003_s3AccountPublicAccess.ts
│   │       │   │   │   ├── DE004_s3BucketPublicAccess.ts
│   │       │   │   │   ├── DE005_s3NoEncryption.ts
│   │       │   │   │   ├── DE006_s3SseS3VsKms.ts
│   │       │   │   │   ├── DE007_s3VersioningDisabled.ts
│   │       │   │   │   ├── DE008_s3NoLifecycle.ts
│   │       │   │   │   ├── DE009_rdsPubliclyAccessible.ts
│   │       │   │   │   ├── DE010_rdsNoEncryption.ts
│   │       │   │   │   ├── DE011_rdsNoBackups.ts
│   │       │   │   │   ├── DE012_rdsPublicSnapshot.ts
│   │       │   │   │   ├── DE013_rdsDeletionProtection.ts
│   │       │   │   │   ├── DE014_secretsManagerRotation.ts
│   │       │   │   │   ├── DE015_secretsManagerNoRotation.ts
│   │       │   │   │   ├── DE016_kmsNoRotation.ts
│   │       │   │   │   ├── DE017_kmsWildcardPolicy.ts
│   │       │   │   │   ├── DE018_dynamoNoKms.ts
│   │       │   │   │   ├── DE019_ebsNoEncryption.ts
│   │       │   │   │   └── DE020_ebsPublicSnapshot.ts
│   │       │   │   │
│   │       │   │   └── network/
│   │       │   │       ├── index.ts              # Exports all 20 network checks
│   │       │   │       ├── NP001_sgOpenSsh.ts
│   │       │   │       ├── NP002_sgOpenRdp.ts
│   │       │   │       ├── NP003_sgAllTraffic.ts
│   │       │   │       ├── NP004_sgOpenNonStandard.ts
│   │       │   │       ├── NP005_defaultSgHasRules.ts
│   │       │   │       ├── NP006_defaultVpcInUse.ts
│   │       │   │       ├── NP007_vpcNoFlowLogs.ts
│   │       │   │       ├── NP008_vpcPeeringDns.ts
│   │       │   │       ├── NP009_subnetAutoPublicIp.ts
│   │       │   │       ├── NP010_igwNoRouteRestriction.ts
│   │       │   │       ├── NP011_naclAllInbound.ts
│   │       │   │       ├── NP012_naclAllOutbound.ts
│   │       │   │       ├── NP013_cloudtrailAllRegions.ts
│   │       │   │       ├── NP014_cloudtrailMgmtEvents.ts
│   │       │   │       ├── NP015_cloudtrailValidation.ts
│   │       │   │       ├── NP016_cloudtrailS3Public.ts
│   │       │   │       ├── NP017_configAllRegions.ts
│   │       │   │       ├── NP018_guarddutyAllRegions.ts
│   │       │   │       ├── NP019_ec2PublicIpNonDmz.ts
│   │       │   │       └── NP020_wafMissingAlb.ts
│   │       │   │
│   │       │   └── checkRunner.ts                # Executes check functions, normalizes output, handles errors
│   │       │
│   │       ├── chainEngine/
│   │       │   ├── index.ts                      # Chain engine entry point
│   │       │   ├── chainRules.ts                 # All 12 chain rule definitions
│   │       │   └── chainEvaluator.ts             # Post-scan chain detection logic
│   │       │
│   │       ├── compliance/
│   │       │   ├── index.ts                      # Compliance engine entry point
│   │       │   ├── mappings/
│   │       │   │   ├── cis.ts                    # CIS AWS Foundations control → check mappings
│   │       │   │   ├── pciDss.ts                 # PCI-DSS control → check mappings
│   │       │   │   ├── soc2.ts                   # SOC2 control → check mappings
│   │       │   │   ├── hipaa.ts                  # HIPAA control → check mappings
│   │       │   │   └── nist.ts                   # NIST 800-53 control → check mappings
│   │       │   └── scoreCalculator.ts            # Compute pass% per standard from findings
│   │       │
│   │       ├── inventory/
│   │       │   ├── index.ts                      # Inventory discovery orchestrator
│   │       │   ├── collectors/
│   │       │   │   ├── ec2Collector.ts           # Discover EC2 instances
│   │       │   │   ├── s3Collector.ts            # Discover S3 buckets
│   │       │   │   ├── rdsCollector.ts           # Discover RDS instances
│   │       │   │   ├── lambdaCollector.ts        # Discover Lambda functions
│   │       │   │   ├── iamCollector.ts           # Discover IAM users and roles
│   │       │   │   └── vpcCollector.ts           # Discover VPCs and security groups
│   │       │   └── resourceNormalizer.ts         # Normalize disparate AWS responses to CloudResource type
│   │       │
│   │       ├── remediation/
│   │       │   ├── index.ts                      # Remediation queue builder
│   │       │   ├── prioritizer.ts                # Sort findings by chain membership + severity + fix time
│   │       │   └── planExporter.ts               # Generate Markdown / PDF remediation plan
│   │       │
│   │       └── types.ts                          # All TypeScript interfaces: CloudFinding, CompoundRisk, CloudResource, etc.
│   │
│   ├── api/
│   │   └── cloud/
│   │       ├── accounts/
│   │       │   ├── route.ts                      # GET (list accounts) / POST (create account)
│   │       │   └── [accountId]/
│   │       │       ├── route.ts                  # GET / PATCH / DELETE account
│   │       │       └── test/
│   │       │           └── route.ts              # POST — test STS assume-role connectivity
│   │       │
│   │       ├── scans/
│   │       │   ├── route.ts                      # POST — start a new scan
│   │       │   └── [scanId]/
│   │       │       └── route.ts                  # GET — scan status and results
│   │       │
│   │       ├── findings/
│   │       │   ├── route.ts                      # GET (list with filters) / PATCH (bulk status update)
│   │       │   └── [findingId]/
│   │       │       └── route.ts                  # GET / PATCH single finding
│   │       │
│   │       ├── inventory/
│   │       │   └── route.ts                      # GET — list cloud resources
│   │       │
│   │       ├── compliance/
│   │       │   └── route.ts                      # GET — compliance scores per standard
│   │       │
│   │       ├── chains/
│   │       │   └── route.ts                      # GET — list compound risks
│   │       │
│   │       └── cfn-template/
│   │           └── route.ts                      # GET — generate signed CloudFormation template URL
│   │
│   └── hooks/
│       └── cloud/
│           ├── useCloudAccounts.ts               # SWR hook: fetch and manage cloud accounts
│           ├── useCloudFindings.ts               # SWR hook: findings with filter state
│           ├── useCloudInventory.ts              # SWR hook: resource inventory
│           ├── useComplianceScores.ts            # SWR hook: compliance data per standard
│           ├── useAttackChains.ts                # SWR hook: compound risk chains
│           └── useScanProgress.ts               # WebSocket or polling hook: live scan progress
│
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-03-23-cloud-misconfig-scanner-design.md   # This document
│
└── prisma/
    └── schema.prisma                             # Extend with: CloudAccount, CloudScan, CloudFinding,
                                                  #   CloudResource, CompoundRisk, ComplianceScore models
```

---

## 8. Database Schema Extensions

The following Prisma models are required additions to the existing schema:

```prisma
model CloudAccount {
  id           String   @id @default(cuid())
  orgId        String
  awsAccountId String
  displayName  String
  roleArn      String
  externalId   String
  primaryRegion String
  status       String   @default("PENDING") // CONNECTED | ERROR | PENDING
  lastScanAt   DateTime?
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt

  scans        CloudScan[]
  findings     CloudFinding[]
  resources    CloudResource[]
  chains       CompoundRisk[]
}

model CloudScan {
  id          String   @id @default(cuid())
  accountId   String
  account     CloudAccount @relation(fields: [accountId], references: [id])
  status      String   @default("RUNNING") // RUNNING | COMPLETE | FAILED
  startedAt   DateTime @default(now())
  completedAt DateTime?
  checksRun   Int      @default(0)
  findingCount Json?   // { critical: N, high: N, medium: N, low: N }

  findings    CloudFinding[]
  chains      CompoundRisk[]
}

model CloudFinding {
  id                String   @id @default(cuid())
  checkId           String
  accountId         String
  account           CloudAccount @relation(fields: [accountId], references: [id])
  scanId            String
  scan              CloudScan @relation(fields: [scanId], references: [id])
  region            String
  resourceId        String
  resourceType      String
  resourceName      String
  severity          String
  cvssScore         Float?
  riskNarrative     String   @db.Text
  complianceImpact  Json
  remediation       Json
  chainIds          String[]
  compoundSeverity  String?
  status            String   @default("OPEN")
  suppressedUntil   DateTime?
  resolvedAt        DateTime?
  detectedAt        DateTime @default(now())
}

model CloudResource {
  id           String   @id @default(cuid())
  accountId    String
  account      CloudAccount @relation(fields: [accountId], references: [id])
  resourceId   String
  resourceType String
  resourceName String
  region       String
  tags         Json?
  metadata     Json?
  lastSeenAt   DateTime @default(now())
}

model CompoundRisk {
  id                     String   @id @default(cuid())
  chainId                String
  name                   String
  accountId              String
  account                CloudAccount @relation(fields: [accountId], references: [id])
  scanId                 String
  scan                   CloudScan @relation(fields: [scanId], references: [id])
  severity               String
  participatingFindingIds String[]
  attackNarrative        String   @db.Text
  businessImpact         String   @db.Text
  remediationPriority    Int
  detectedAt             DateTime @default(now())
}

model ComplianceScore {
  id         String   @id @default(cuid())
  accountId  String
  scanId     String
  standard   String   // CIS | PCI-DSS | SOC2 | HIPAA | NIST
  score      Float
  passing    Int
  failing    Int
  notApplicable Int
  breakdown  Json     // control-level detail
  calculatedAt DateTime @default(now())
}
```

---

## 9. Scan Execution Flow

```
POST /api/cloud/scans
  │
  ├── 1. Create CloudScan record (status: RUNNING)
  ├── 2. stsClient.assumeRole(account.roleArn, account.externalId)
  ├── 3. awsClients.buildClients(tempCredentials, primaryRegion)
  ├── 4. inventory/index.ts — run all collectors in parallel → persist CloudResource records
  │
  ├── 5. checkRunner.ts — run all 65 checks in batches of 10:
  │       ├── IAM checks (25) — mostly global, single region
  │       ├── Data Exposure checks (20) — multi-region where applicable
  │       └── Network checks (20) — iterate across all active regions
  │
  ├── 6. Persist CloudFinding records as checks complete (streaming inserts)
  ├── 7. chainEngine/index.ts — run chain evaluator on completed findings
  ├── 8. compliance/scoreCalculator.ts — compute ComplianceScore per standard
  ├── 9. Update CloudScan: status = COMPLETE, completedAt, findingCount
  └── 10. Emit WebSocket event: scan:complete → { scanId, accountId, summary }
```

Scans are expected to complete in under 5 minutes for a typical AWS account (< 500 resources, 10 regions). Multi-region accounts with large resource counts may take up to 10 minutes.

---

## 10. Key Design Decisions & Rationale

| Decision | Rationale |
|----------|-----------|
| Cross-account IAM role (not stored keys) | Zero credential storage risk; short-lived STS sessions; industry standard pattern for third-party cloud access |
| External ID on assume-role | Prevents confused deputy attacks where a malicious customer could trick HemisX into scanning another customer's account |
| 65 checks across 3 domains | Covers the highest-impact, most common misconfigurations found in SMB AWS accounts without overwhelming users |
| Risk narrative on every finding | Engineers and non-security managers both need to understand *why* a finding matters, not just that a policy failed |
| Fix time estimate on every finding | Enables engineering managers to prioritize remediation sprints and communicate to leadership |
| IaC code (Terraform + CF + CLI) | Meets engineers where they work; copy-paste ready means finding-to-fix in < 30 minutes |
| Risk chaining engine | Elevates compound risks that are invisible in flat finding lists; demonstrates superior analysis vs. raw compliance tools |
| Six-tab UI | Separation of concerns: connecting accounts, executive overview, detailed findings, resource inventory, compliance mapping, and actionable remediation are distinct workflows for distinct personas |
| SWR hooks for all data fetching | Enables stale-while-revalidate pattern — UI remains responsive during scans; findings stream in as they complete |
