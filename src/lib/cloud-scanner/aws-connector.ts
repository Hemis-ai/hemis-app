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
