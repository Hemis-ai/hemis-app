'use client'

import { useState, useCallback, useRef } from 'react'
import type {
  CloudScan,
  CloudFinding,
  CloudFindingSeverity,
  CloudCheckCategory,
  ComplianceFramework,
  CloudInventory,
} from '@/lib/types/cloud-scanner'
import { MOCK_CLOUD_SCAN, MOCK_CLOUD_CONNECTION } from '@/lib/mock-data/cloud-scanner'

// ─── Color constants ──────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
  INFO:     'var(--color-text-dim)',
}

const SEV_BG: Record<string, string> = {
  CRITICAL: 'rgba(239,90,90,0.15)',
  HIGH:     'rgba(242,142,60,0.15)',
  MEDIUM:   'rgba(242,209,86,0.15)',
  LOW:      'rgba(90,176,255,0.15)',
  INFO:     'rgba(139,168,200,0.1)',
}

const EFFORT_COLOR: Record<string, string> = {
  '5min':  '#00d4aa',
  '1hr':   '#f2d156',
  '1day':  '#f28e3c',
  '1week': '#ef5a5a',
}

const CAT_COLOR: Record<string, string> = {
  IAM:     '#b06aff',
  DATA:    '#ef5a5a',
  NETWORK: '#5ab0ff',
}

const FRAMEWORK_COLOR: Record<string, string> = {
  CIS:     '#00d4aa',
  PCI_DSS: '#f28e3c',
  SOC2:    '#5ab0ff',
  HIPAA:   '#b06aff',
}

const FRAMEWORK_LABEL: Record<string, string> = {
  CIS:     'CIS Benchmark',
  PCI_DSS: 'PCI-DSS 4.0',
  SOC2:    'SOC 2 Type II',
  HIPAA:   'HIPAA',
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskScoreColor(score: number): string {
  if (score >= 75) return 'var(--color-sev-critical)'
  if (score >= 50) return 'var(--color-sev-high)'
  if (score >= 25) return 'var(--color-sev-medium)'
  return '#00d4aa'
}

function priorityColor(p: number): string {
  if (p === 1) return '#ef5a5a'
  if (p === 2) return '#f28e3c'
  if (p <= 4) return '#f2d156'
  return '#00d4aa'
}

function secStatusBadge(status: string) {
  const cfg: Record<string, { bg: string; color: string }> = {
    CLEAN:    { bg: 'rgba(0,212,170,0.15)', color: '#00d4aa' },
    WARNING:  { bg: 'rgba(242,209,86,0.15)', color: '#f2d156' },
    CRITICAL: { bg: 'rgba(239,90,90,0.15)', color: '#ef5a5a' },
  }
  const c = cfg[status] ?? cfg['CLEAN']
  return (
    <span style={{
      background: c.bg, color: c.color,
      fontSize: 11, fontWeight: 700, padding: '2px 8px',
      borderRadius: 4, fontFamily: 'var(--font-mono)',
    }}>
      {status}
    </span>
  )
}

// ─── CloudFormation template generator ───────────────────────────────────────

function cfTemplate(externalId: string): string {
  return `AWSTemplateFormatVersion: "2010-09-09"
Description: HemisX Read-Only Security Scanner Role

Parameters:
  HemisXAccountId:
    Type: String
    Default: "891377270755"
    Description: HemisX AWS Account ID

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
              AWS: !Sub "arn:aws:iam::\${HemisXAccountId}:root"
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: "${externalId}"
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/ReadOnlyAccess
      MaxSessionDuration: 3600

Outputs:
  RoleArn:
    Description: ARN of the HemisX Scanner Role
    Value: !GetAtt HemisXScannerRole.Arn`
}

function tfTemplate(externalId: string): string {
  return `terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "hemisx_account_id" {
  default = "891377270755"
  description = "HemisX AWS Account ID"
}

resource "aws_iam_role" "hemisx_scanner" {
  name = "HemisXScannerRole"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::\${var.hemisx_account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "sts:ExternalId" = "${externalId}" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.hemisx_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.hemisx_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "role_arn" {
  value = aws_iam_role.hemisx_scanner.arn
}`
}

// ─── RiskGauge SVG component ──────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const r = 52
  const cx = 70
  const cy = 70
  const circumference = 2 * Math.PI * r
  const dashOffset = circumference * (1 - score / 100)
  const color = riskScoreColor(score)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={140} height={140} style={{ transform: 'rotate(-90deg)' }}>
        <circle
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={10}
        />
        <circle
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
        <text
          x={cx} y={cy + 6}
          textAnchor="middle"
          fill={color}
          fontSize={26}
          fontWeight={800}
          fontFamily="var(--font-mono)"
          style={{ transform: 'rotate(90deg)', transformOrigin: `${cx}px ${cy}px` }}
        >
          {score}
        </text>
      </svg>
      <span style={{ fontSize: 12, color: 'var(--color-text-dim)', fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase' }}>
        Risk Score
      </span>
    </div>
  )
}

// ─── Small circular compliance ring ──────────────────────────────────────────

function ComplianceRing({ score, color }: { score: number; color: string }) {
  const r = 28
  const circumference = 2 * Math.PI * r
  const dashOffset = circumference * (1 - score / 100)
  return (
    <svg width={72} height={72} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={36} cy={36} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={6} />
      <circle
        cx={36} cy={36} r={r}
        fill="none"
        stroke={color}
        strokeWidth={6}
        strokeDasharray={circumference}
        strokeDashoffset={dashOffset}
        strokeLinecap="round"
      />
      <text
        x={36} y={40}
        textAnchor="middle"
        fill={color}
        fontSize={14}
        fontWeight={800}
        fontFamily="var(--font-mono)"
        style={{ transform: 'rotate(90deg)', transformOrigin: '36px 36px' }}
      >
        {score}
      </text>
    </svg>
  )
}

// ─── Copy button ──────────────────────────────────────────────────────────────

function CopyButton({ text, style }: { text: string; style?: React.CSSProperties }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <button
      onClick={handleCopy}
      style={{
        background: copied ? 'rgba(0,212,170,0.2)' : 'rgba(255,255,255,0.08)',
        border: '1px solid var(--color-border)',
        borderRadius: 6,
        color: copied ? '#00d4aa' : 'var(--color-text-secondary)',
        cursor: 'pointer',
        fontSize: 11,
        fontWeight: 600,
        padding: '4px 10px',
        transition: 'all 0.2s',
        ...style,
      }}
    >
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  )
}

// ─── Inventory category meta ──────────────────────────────────────────────────

const INVENTORY_TABS: { key: keyof CloudInventory; label: string }[] = [
  { key: 'ec2Instances',    label: 'EC2 Instances' },
  { key: 's3Buckets',       label: 'S3 Buckets' },
  { key: 'rdsInstances',    label: 'RDS' },
  { key: 'iamUsers',        label: 'IAM Users' },
  { key: 'iamRoles',        label: 'IAM Roles' },
  { key: 'lambdaFunctions', label: 'Lambda' },
  { key: 'securityGroups',  label: 'Security Groups' },
  { key: 'vpcs',            label: 'VPCs' },
]

// ─── Main page component ──────────────────────────────────────────────────────

export default function CloudScannerPage() {
  const [activeTab, setActiveTab]           = useState<'connect' | 'overview' | 'findings' | 'inventory' | 'compliance' | 'remediation'>('connect')
  const [connectionStep, setConnectionStep] = useState<'setup' | 'connecting' | 'connected'>('setup')
  const [templateMode, setTemplateMode]     = useState<'cloudformation' | 'terraform'>('cloudformation')
  const [roleArn, setRoleArn]               = useState('')
  const [isConnecting, setIsConnecting]     = useState(false)
  const [connectionError, setConnectionError] = useState<string | null>(null)
  const [isScanning, setIsScanning]         = useState(false)
  const [scanProgress, setScanProgress]     = useState(0)
  const [scanPhase, setScanPhase]           = useState('')
  const [scan, setScan]                     = useState<CloudScan>(MOCK_CLOUD_SCAN)
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [categoryFilter, setCategoryFilter] = useState('ALL')
  const [frameworkFilter, setFrameworkFilter] = useState('ALL')
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null)
  const [activeFixTab, setActiveFixTab]     = useState<'console' | 'cli' | 'terraform' | 'cloudformation'>('cli')
  const [inventoryType, setInventoryType]   = useState<keyof CloudInventory>('ec2Instances')
  const [selectedFramework, setSelectedFramework] = useState<string>('CIS')
  const [expandedRemId, setExpandedRemId]   = useState<string | null>(null)
  const [findingStatuses, setFindingStatuses] = useState<Record<string, string>>({})

  const externalId = useRef(`hemisx-${Math.random().toString(36).slice(2, 10)}`).current

  // ── Connect handler ──────────────────────────────────────────────────────────

  const handleConnect = useCallback(async () => {
    if (!roleArn.trim()) {
      setConnectionError('Please enter a Role ARN')
      return
    }
    if (!roleArn.startsWith('arn:aws:iam::')) {
      setConnectionError('Invalid ARN format. Expected: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME')
      return
    }
    setConnectionError(null)
    setIsConnecting(true)
    setConnectionStep('connecting')
    await new Promise(r => setTimeout(r, 1500))
    setIsConnecting(false)
    setConnectionStep('connected')
  }, [roleArn])

  // ── Scan handler ─────────────────────────────────────────────────────────────

  const handleRunScan = useCallback(() => {
    setIsScanning(true)
    setScanProgress(0)
    const phases = [
      { progress: 10,  label: 'Connecting to AWS via STS...' },
      { progress: 25,  label: 'Discovering resources across 3 regions...' },
      { progress: 45,  label: 'Auditing IAM users, roles, and policies...' },
      { progress: 62,  label: 'Scanning S3 buckets and RDS instances...' },
      { progress: 78,  label: 'Checking security groups and VPCs...' },
      { progress: 90,  label: 'Chaining risks and mapping compliance...' },
      { progress: 100, label: 'Scan complete. 9 findings detected.' },
    ]
    let i = 0
    const interval = setInterval(() => {
      if (i < phases.length) {
        setScanProgress(phases[i].progress)
        setScanPhase(phases[i].label)
        i++
      } else {
        clearInterval(interval)
        setIsScanning(false)
        setScan(MOCK_CLOUD_SCAN)
        setActiveTab('overview')
      }
    }, 1200)
  }, [])

  // ── Filtered findings ────────────────────────────────────────────────────────

  const filteredFindings = scan.findings
    .filter(f => severityFilter === 'ALL' || f.severity === severityFilter)
    .filter(f => categoryFilter === 'ALL' || f.category === categoryFilter)
    .filter(f => frameworkFilter === 'ALL' || f.complianceMappings.some(m => m.framework === frameworkFilter))
    .sort((a, b) => {
      const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
      return order.indexOf(a.severity) - order.indexOf(b.severity)
    })

  // ── Shared styles ────────────────────────────────────────────────────────────

  const cardStyle: React.CSSProperties = {
    background: 'var(--color-bg-surface)',
    border: '1px solid var(--color-border)',
    borderRadius: 10,
    padding: '18px 20px',
  }

  const codeBlockStyle: React.CSSProperties = {
    background: '#0a0d14',
    border: '1px solid var(--color-border)',
    borderRadius: 8,
    color: '#e0e0e0',
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    height: 280,
    lineHeight: 1.6,
    overflow: 'auto',
    padding: '16px',
    whiteSpace: 'pre',
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TAB: CONNECT
  // ─────────────────────────────────────────────────────────────────────────────

  function renderConnect() {
    const templateText = templateMode === 'cloudformation' ? cfTemplate(externalId) : tfTemplate(externalId)

    return (
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '32px 0' }}>
        {/* Title */}
        <div style={{ marginBottom: 28, textAlign: 'center' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 10,
            background: 'rgba(0,212,170,0.1)', border: '1px solid rgba(0,212,170,0.25)',
            borderRadius: 8, padding: '6px 14px', marginBottom: 16,
          }}>
            <span style={{ fontSize: 14 }}>☁</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: '#00d4aa', letterSpacing: 1 }}>AWS CLOUD SCANNER</span>
          </div>
          <h1 style={{ fontSize: 24, fontWeight: 800, color: 'var(--color-text-primary)', margin: '0 0 8px' }}>
            Connect AWS Account
          </h1>
          <p style={{ fontSize: 14, color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.6 }}>
            Create a read-only IAM role using our CloudFormation or Terraform template. We never store credentials — only your Role ARN.
          </p>
        </div>

        {/* Progress dots */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: 12, marginBottom: 32 }}>
          {[
            { step: 'setup',      label: '1. Deploy Role' },
            { step: 'connecting', label: '2. Test Connection' },
            { step: 'connected',  label: '3. Run Scan' },
          ].map(({ step, label }, idx) => {
            const stepOrder = ['setup', 'connecting', 'connected']
            const current = stepOrder.indexOf(connectionStep)
            const thisIdx = stepOrder.indexOf(step)
            const isActive = thisIdx === current
            const isDone   = thisIdx < current

            return (
              <div key={step} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{
                  width: 28, height: 28, borderRadius: '50%', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700,
                  background: isDone ? '#00d4aa' : isActive ? 'rgba(0,212,170,0.2)' : 'rgba(255,255,255,0.06)',
                  border: `2px solid ${isDone ? '#00d4aa' : isActive ? '#00d4aa' : 'var(--color-border)'}`,
                  color: isDone ? '#000' : isActive ? '#00d4aa' : 'var(--color-text-dim)',
                  transition: 'all 0.3s',
                }}>
                  {isDone ? '✓' : idx + 1}
                </div>
                <span style={{ fontSize: 12, fontWeight: 600, color: isActive ? 'var(--color-text-primary)' : 'var(--color-text-dim)' }}>
                  {label}
                </span>
                {idx < 2 && (
                  <div style={{ width: 32, height: 1, background: isDone ? '#00d4aa' : 'var(--color-border)', transition: 'all 0.3s', marginLeft: 4 }} />
                )}
              </div>
            )
          })}
        </div>

        {/* Step: setup */}
        {connectionStep === 'setup' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* External ID */}
            <div style={cardStyle}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--color-text-dim)', marginBottom: 8, letterSpacing: 0.5, textTransform: 'uppercase' }}>
                Your External ID (confused-deputy protection)
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <code style={{
                  flex: 1, background: '#0a0d14', border: '1px solid var(--color-border)',
                  borderRadius: 6, padding: '8px 12px', fontFamily: 'var(--font-mono)',
                  fontSize: 13, color: '#00d4aa', letterSpacing: 1,
                }}>
                  {externalId}
                </code>
                <CopyButton text={externalId} />
              </div>
              <p style={{ fontSize: 11, color: 'var(--color-text-dim)', margin: '8px 0 0', lineHeight: 1.5 }}>
                This ID is unique to your HemisX account. It prevents attackers from tricking AWS into allowing them to assume your role (confused deputy attack).
              </p>
            </div>

            {/* Template toggle + code block */}
            <div style={cardStyle}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text-primary)' }}>
                  IAM Role Template
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {(['cloudformation', 'terraform'] as const).map(m => (
                    <button
                      key={m}
                      onClick={() => setTemplateMode(m)}
                      style={{
                        background: templateMode === m ? 'rgba(0,212,170,0.15)' : 'rgba(255,255,255,0.05)',
                        border: `1px solid ${templateMode === m ? '#00d4aa' : 'var(--color-border)'}`,
                        borderRadius: 6, color: templateMode === m ? '#00d4aa' : 'var(--color-text-secondary)',
                        cursor: 'pointer', fontSize: 12, fontWeight: 600, padding: '5px 12px',
                        transition: 'all 0.2s',
                      }}
                    >
                      {m === 'cloudformation' ? 'CloudFormation' : 'Terraform'}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ position: 'relative' }}>
                <div style={{ position: 'absolute', top: 10, right: 10, zIndex: 2 }}>
                  <CopyButton text={templateText} />
                </div>
                <div style={codeBlockStyle}>{templateText}</div>
              </div>

              <p style={{ fontSize: 12, color: 'var(--color-text-dim)', margin: '12px 0 0', lineHeight: 1.5 }}>
                Deploy this template in your AWS account. It creates a read-only IAM role (SecurityAudit + ReadOnlyAccess) that HemisX can assume for scanning. <strong style={{ color: 'var(--color-text-secondary)' }}>No write permissions are granted.</strong>
              </p>
            </div>

            {/* ARN input */}
            <div style={cardStyle}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 14 }}>
                Step 2 — Enter Role ARN
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-dim)', letterSpacing: 0.5, textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                    Role ARN
                  </label>
                  <input
                    value={roleArn}
                    onChange={e => setRoleArn(e.target.value)}
                    placeholder="arn:aws:iam::123456789012:role/HemisXScannerRole"
                    style={{
                      width: '100%', background: '#0a0d14',
                      border: `1px solid ${connectionError ? '#ef5a5a' : 'var(--color-border)'}`,
                      borderRadius: 7, color: 'var(--color-text-primary)',
                      fontFamily: 'var(--font-mono)', fontSize: 12, outline: 'none',
                      padding: '10px 14px', boxSizing: 'border-box',
                    }}
                  />
                </div>
                <button
                  onClick={handleConnect}
                  disabled={isConnecting}
                  style={{
                    alignSelf: 'flex-end',
                    background: isConnecting ? 'rgba(0,212,170,0.3)' : '#00d4aa',
                    border: 'none', borderRadius: 7,
                    color: '#000', cursor: isConnecting ? 'wait' : 'pointer',
                    fontSize: 13, fontWeight: 700, padding: '10px 20px',
                    transition: 'all 0.2s', whiteSpace: 'nowrap',
                  }}
                >
                  {isConnecting ? 'Testing...' : 'Test Connection →'}
                </button>
              </div>
              {connectionError && (
                <div style={{
                  marginTop: 10, padding: '8px 12px', background: 'rgba(239,90,90,0.1)',
                  border: '1px solid rgba(239,90,90,0.3)', borderRadius: 6,
                  fontSize: 12, color: '#ef5a5a',
                }}>
                  ⚠ {connectionError}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Step: connecting */}
        {connectionStep === 'connecting' && (
          <div style={{ ...cardStyle, textAlign: 'center', padding: '48px 32px' }}>
            <div style={{
              width: 52, height: 52, borderRadius: '50%',
              border: '3px solid rgba(255,255,255,0.1)',
              borderTopColor: '#00d4aa',
              animation: 'spin 0.9s linear infinite',
              margin: '0 auto 24px',
            }} />
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 8 }}>
              Testing connection...
            </div>
            <div style={{ fontSize: 12, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
              {roleArn}
            </div>
            <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginTop: 16, lineHeight: 1.6 }}>
              Calling <code style={{ fontFamily: 'var(--font-mono)', color: '#00d4aa' }}>sts:AssumeRole</code> with your External ID to verify access...
            </p>
          </div>
        )}

        {/* Step: connected */}
        {connectionStep === 'connected' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ ...cardStyle, textAlign: 'center', padding: '36px 32px' }}>
              <div style={{
                width: 64, height: 64, borderRadius: '50%',
                background: 'rgba(0,212,170,0.15)', border: '2px solid #00d4aa',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                margin: '0 auto 20px', fontSize: 28, color: '#00d4aa',
              }}>
                ✓
              </div>
              <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--color-text-primary)', marginBottom: 6 }}>
                Connected!
              </div>
              <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginBottom: 20 }}>
                Successfully assumed role · Read-only access granted
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', gap: 24, marginBottom: 24, flexWrap: 'wrap' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>Account</div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>
                    acme-production (123456789012)
                  </div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>Regions</div>
                  <div style={{ display: 'flex', gap: 6, justifyContent: 'center' }}>
                    {['us-east-1', 'us-west-2', 'eu-west-1'].map(r => (
                      <span key={r} style={{
                        background: 'rgba(0,212,170,0.12)', border: '1px solid rgba(0,212,170,0.3)',
                        borderRadius: 4, color: '#00d4aa', fontSize: 11, fontWeight: 600,
                        padding: '2px 8px', fontFamily: 'var(--font-mono)',
                      }}>
                        {r}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {!isScanning ? (
                <button
                  onClick={handleRunScan}
                  style={{
                    background: '#00d4aa', border: 'none', borderRadius: 8,
                    color: '#000', cursor: 'pointer', fontSize: 15, fontWeight: 700,
                    padding: '14px 32px', transition: 'all 0.2s',
                  }}
                >
                  Run Security Scan →
                </button>
              ) : (
                <div style={{ textAlign: 'left', background: '#0a0d14', border: '1px solid var(--color-border)', borderRadius: 8, padding: '20px 24px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>Scanning in progress</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: '#00d4aa', fontFamily: 'var(--font-mono)' }}>{scanProgress}%</span>
                  </div>
                  <div style={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.07)', borderRadius: 3, overflow: 'hidden', marginBottom: 10 }}>
                    <div style={{
                      height: '100%', borderRadius: 3,
                      width: `${scanProgress}%`, background: '#00d4aa',
                      transition: 'width 0.5s ease',
                    }} />
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {scanPhase}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TAB: OVERVIEW
  // ─────────────────────────────────────────────────────────────────────────────

  function renderOverview() {
    const s = scan
    const catTotals: Record<string, number> = { IAM: 9, DATA: 8, NETWORK: 6 }

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: '24px 0' }}>

        {/* Header row */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{
              background: 'rgba(0,212,170,0.12)', border: '1px solid rgba(0,212,170,0.3)',
              borderRadius: 6, color: '#00d4aa', fontSize: 12, fontWeight: 700,
              padding: '4px 12px',
            }}>
              acme-production
            </span>
            <span style={{ fontSize: 12, color: 'var(--color-text-dim)' }}>
              Last scanned: March 23, 2026 at 10:04 AM
            </span>
          </div>
          <button
            onClick={() => setActiveTab('connect')}
            style={{
              background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)',
              borderRadius: 7, color: 'var(--color-text-secondary)', cursor: 'pointer',
              fontSize: 12, fontWeight: 600, padding: '7px 14px',
            }}
          >
            ↺ Re-scan
          </button>
        </div>

        {/* Risk Score + Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: 20 }}>
          {/* Risk gauge card */}
          <div style={{ ...cardStyle, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8 }}>
            <RiskGauge score={s.riskScore} />
            <div style={{
              background: SEV_BG[s.riskLevel],
              border: `1px solid ${SEV_COLOR[s.riskLevel]}33`,
              borderRadius: 6, padding: '4px 14px',
              fontSize: 12, fontWeight: 700, color: SEV_COLOR[s.riskLevel],
              textAlign: 'center',
            }}>
              {s.riskLevel} RISK
            </div>
          </div>

          {/* Stats grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gridTemplateRows: 'repeat(2, 1fr)', gap: 12 }}>
            {([
              { label: 'Critical', count: s.summary.critical,  sev: 'CRITICAL' },
              { label: 'High',     count: s.summary.high,      sev: 'HIGH' },
              { label: 'Medium',   count: s.summary.medium,    sev: 'MEDIUM' },
              { label: 'Low',      count: s.summary.low,       sev: 'LOW' },
            ] as const).map(({ label, count, sev }) => (
              <div key={sev} style={{
                ...cardStyle, padding: '14px 16px',
                display: 'flex', flexDirection: 'column', gap: 4,
                borderLeft: `3px solid ${SEV_COLOR[sev]}`,
                cursor: 'pointer',
              }}
              onClick={() => { setSeverityFilter(sev); setActiveTab('findings') }}>
                <div style={{ fontSize: 28, fontWeight: 800, color: SEV_COLOR[sev], fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
                  {count}
                </div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                  {label}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Breach cost + scan stats */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          <div style={{ ...cardStyle, textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
              Estimated Breach Cost
            </div>
            <div style={{ fontSize: 32, fontWeight: 800, color: '#ef5a5a', fontFamily: 'var(--font-mono)' }}>
              ${(s.summary.estimatedBreachCost / 1000000).toFixed(1)}M
            </div>
            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 4 }}>
              worst-case scenario
            </div>
          </div>
          <div style={{ ...cardStyle, textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
              Resources Scanned
            </div>
            <div style={{ fontSize: 32, fontWeight: 800, color: '#5ab0ff', fontFamily: 'var(--font-mono)' }}>
              {s.summary.resourcesScanned}
            </div>
            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 4 }}>
              across 3 regions
            </div>
          </div>
          <div style={{ ...cardStyle, textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
              Checks Run
            </div>
            <div style={{ fontSize: 32, fontWeight: 800, color: '#00d4aa', fontFamily: 'var(--font-mono)' }}>
              {s.summary.checksRun}
            </div>
            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 4 }}>
              {s.summary.checksPassed} passed · {s.summary.checksFailed} failed
            </div>
          </div>
        </div>

        {/* Attack Scenarios */}
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: '#f2d156' }}>⚠</span> Attack Scenarios
            <span style={{ fontSize: 11, color: 'var(--color-text-dim)', fontWeight: 400 }}>
              — how these findings chain together
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            {s.attackScenarios.map(scenario => {
              const isExp = expandedFindingId === scenario.id
              return (
                <div key={scenario.id} style={{
                  ...cardStyle, padding: 0, overflow: 'hidden',
                  borderLeft: `3px solid ${SEV_COLOR[scenario.severity]}`,
                }}>
                  <div
                    style={{ padding: '16px 18px', cursor: 'pointer' }}
                    onClick={() => setExpandedFindingId(isExp ? null : scenario.id)}
                  >
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10, marginBottom: 10 }}>
                      <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--color-text-primary)', lineHeight: 1.4 }}>
                        {scenario.title}
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-end', flexShrink: 0 }}>
                        <span style={{
                          background: SEV_BG[scenario.severity], color: SEV_COLOR[scenario.severity],
                          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                        }}>
                          {scenario.severity}
                        </span>
                        <span style={{
                          background: 'rgba(242,209,86,0.12)', color: '#f2d156',
                          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                        }}>
                          {scenario.likelihood} LIKELIHOOD
                        </span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--color-text-dim)', marginBottom: 10 }}>
                      <span>{scenario.steps.length} steps</span>
                      <span style={{ color: '#ef5a5a', fontWeight: 600 }}>
                        ${(scenario.estimatedBreachCost / 1000000).toFixed(1)}M breach
                      </span>
                    </div>

                    <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
                      {isExp ? scenario.narrative : `${scenario.narrative.slice(0, 220)}...`}
                    </div>

                    <div style={{ marginTop: 8, fontSize: 11, color: '#00d4aa', fontWeight: 600 }}>
                      {isExp ? '▲ Collapse' : '▼ Read full scenario'}
                    </div>
                  </div>

                  {isExp && (
                    <div style={{ borderTop: '1px solid var(--color-border)', padding: '14px 18px' }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 10 }}>
                        Attack Steps
                      </div>
                      {scenario.steps.map(step => (
                        <div key={step.seq} style={{ display: 'flex', gap: 12, marginBottom: 10, alignItems: 'flex-start' }}>
                          <div style={{
                            width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
                            background: SEV_BG[scenario.severity], border: `1px solid ${SEV_COLOR[scenario.severity]}33`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: 10, fontWeight: 800, color: SEV_COLOR[scenario.severity],
                          }}>
                            {step.seq}
                          </div>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 2 }}>
                              {step.action}
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
                              {step.technique}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Category breakdown */}
        <div style={cardStyle}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 16 }}>
            Findings by Category
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {(['IAM', 'DATA', 'NETWORK'] as CloudCheckCategory[]).map(cat => {
              const count = s.summary.byCategory[cat] ?? 0
              const total = catTotals[cat] ?? 10
              const pct = Math.round((count / total) * 100)
              return (
                <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <span style={{
                    background: `${CAT_COLOR[cat]}22`, color: CAT_COLOR[cat],
                    border: `1px solid ${CAT_COLOR[cat]}44`,
                    fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 4,
                    minWidth: 70, textAlign: 'center', fontFamily: 'var(--font-mono)',
                  }}>
                    {cat}
                  </span>
                  <div style={{ flex: 1, height: 8, background: 'rgba(255,255,255,0.06)', borderRadius: 4, overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', borderRadius: 4,
                      width: `${pct}%`, background: CAT_COLOR[cat],
                      transition: 'width 0.8s ease',
                    }} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', minWidth: 60, textAlign: 'right' }}>
                    {count}/{total} checks
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TAB: FINDINGS
  // ─────────────────────────────────────────────────────────────────────────────

  function renderFindings() {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '24px 0' }}>

        {/* Filter bar */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Severity */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--color-text-dim)', fontWeight: 600, minWidth: 60 }}>SEVERITY</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                style={{
                  background: severityFilter === s
                    ? (s === 'ALL' ? 'rgba(0,212,170,0.15)' : SEV_BG[s])
                    : 'rgba(255,255,255,0.04)',
                  border: `1px solid ${severityFilter === s ? (s === 'ALL' ? '#00d4aa' : SEV_COLOR[s]) : 'var(--color-border)'}`,
                  borderRadius: 5, cursor: 'pointer', fontSize: 11, fontWeight: 700,
                  color: severityFilter === s ? (s === 'ALL' ? '#00d4aa' : SEV_COLOR[s]) : 'var(--color-text-dim)',
                  padding: '4px 10px', transition: 'all 0.15s',
                }}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Category */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--color-text-dim)', fontWeight: 600, minWidth: 60 }}>CATEGORY</span>
            {['ALL', 'IAM', 'DATA', 'NETWORK'].map(c => (
              <button
                key={c}
                onClick={() => setCategoryFilter(c)}
                style={{
                  background: categoryFilter === c ? `${c === 'ALL' ? 'rgba(0,212,170,0.15)' : CAT_COLOR[c] + '22'}` : 'rgba(255,255,255,0.04)',
                  border: `1px solid ${categoryFilter === c ? (c === 'ALL' ? '#00d4aa' : CAT_COLOR[c]) : 'var(--color-border)'}`,
                  borderRadius: 5, cursor: 'pointer', fontSize: 11, fontWeight: 700,
                  color: categoryFilter === c ? (c === 'ALL' ? '#00d4aa' : CAT_COLOR[c]) : 'var(--color-text-dim)',
                  padding: '4px 10px', transition: 'all 0.15s',
                }}
              >
                {c}
              </button>
            ))}
          </div>

          {/* Framework select */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--color-text-dim)', fontWeight: 600, minWidth: 60 }}>FRAMEWORK</span>
            <select
              value={frameworkFilter}
              onChange={e => setFrameworkFilter(e.target.value)}
              style={{
                background: '#0a0d14', border: '1px solid var(--color-border)',
                borderRadius: 5, color: 'var(--color-text-secondary)',
                fontSize: 12, padding: '5px 10px', outline: 'none', cursor: 'pointer',
              }}
            >
              {['ALL', 'CIS', 'PCI_DSS', 'SOC2', 'HIPAA'].map(f => (
                <option key={f} value={f}>{f === 'ALL' ? 'All Frameworks' : FRAMEWORK_LABEL[f]}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Count */}
        <div style={{ fontSize: 12, color: 'var(--color-text-dim)', fontWeight: 600 }}>
          Showing <span style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{filteredFindings.length}</span> of {scan.findings.length} findings
        </div>

        {/* Finding cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filteredFindings.map(finding => {
            const isExp = expandedFindingId === finding.id
            const currentStatus = findingStatuses[finding.id] ?? finding.status

            return (
              <div key={finding.id} style={{
                ...cardStyle, padding: 0, overflow: 'hidden',
                borderLeft: `3px solid ${SEV_COLOR[finding.severity]}`,
              }}>
                {/* Card header */}
                <div style={{ padding: '14px 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
                    {/* checkId */}
                    <span style={{
                      background: '#0a0d14', border: '1px solid var(--color-border)',
                      borderRadius: 4, color: 'var(--color-text-dim)',
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                      padding: '2px 7px', flexShrink: 0,
                    }}>
                      {finding.checkId}
                    </span>

                    {/* category */}
                    <span style={{
                      background: `${CAT_COLOR[finding.category]}22`, color: CAT_COLOR[finding.category],
                      border: `1px solid ${CAT_COLOR[finding.category]}44`,
                      fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4, flexShrink: 0,
                    }}>
                      {finding.category}
                    </span>

                    {/* title */}
                    <div style={{ flex: 1, fontWeight: 700, fontSize: 13, color: 'var(--color-text-primary)', lineHeight: 1.4 }}>
                      {finding.title}
                    </div>

                    {/* severity */}
                    <span style={{
                      background: SEV_BG[finding.severity], color: SEV_COLOR[finding.severity],
                      fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4, flexShrink: 0,
                    }}>
                      {finding.severity}
                    </span>

                    {/* effort */}
                    <span style={{
                      background: `${EFFORT_COLOR[finding.fixEffort]}22`,
                      color: EFFORT_COLOR[finding.fixEffort],
                      border: `1px solid ${EFFORT_COLOR[finding.fixEffort]}44`,
                      fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4, flexShrink: 0,
                    }}>
                      ⏱ {finding.fixEffort}
                    </span>
                  </div>

                  {/* Resource */}
                  <div style={{ fontSize: 12, marginBottom: 8 }}>
                    <span style={{ color: 'var(--color-text-dim)' }}>{finding.resourceType}</span>
                    <span style={{ color: 'var(--color-text-dim)' }}> → </span>
                    <span style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{finding.resourceName}</span>
                  </div>

                  {/* Risk narrative preview */}
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 10 }}>
                    {finding.riskNarrative.slice(0, 160)}...
                  </div>

                  {/* Compliance badges */}
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                    {finding.complianceMappings.map(m => (
                      <span key={m.controlId} style={{
                        background: `${FRAMEWORK_COLOR[m.framework]}18`,
                        color: FRAMEWORK_COLOR[m.framework],
                        border: `1px solid ${FRAMEWORK_COLOR[m.framework]}33`,
                        fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 4,
                      }}>
                        {FRAMEWORK_LABEL[m.framework]} · {m.controlId}
                      </span>
                    ))}
                  </div>

                  {/* Toggle */}
                  <button
                    onClick={() => setExpandedFindingId(isExp ? null : finding.id)}
                    style={{
                      background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)',
                      borderRadius: 5, color: 'var(--color-text-dim)', cursor: 'pointer',
                      fontSize: 11, fontWeight: 600, padding: '5px 12px',
                    }}
                  >
                    {isExp ? '▲ Collapse' : '▼ View Details'}
                  </button>
                </div>

                {/* Expanded details */}
                {isExp && (
                  <div style={{ borderTop: '1px solid var(--color-border)', padding: '16px 16px' }}>
                    {/* Full risk narrative */}
                    <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 14 }}>
                      {finding.riskNarrative}
                    </div>

                    {/* Attack vector */}
                    <div style={{
                      background: 'rgba(239,90,90,0.06)', border: '1px solid rgba(239,90,90,0.2)',
                      borderRadius: 7, padding: '12px 14px', marginBottom: 12,
                    }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: '#ef5a5a', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                        Attack Vector
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, fontFamily: 'var(--font-mono)' }}>
                        {finding.attackVector}
                      </div>
                    </div>

                    {/* Estimated impact */}
                    <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 16, padding: '10px 14px', background: 'rgba(242,209,86,0.06)', border: '1px solid rgba(242,209,86,0.2)', borderRadius: 7 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: '#f2d156', marginRight: 8 }}>💰 ESTIMATED IMPACT</span>
                      {finding.estimatedImpact}
                    </div>

                    {/* Fix tabs */}
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 10 }}>
                        Remediation
                      </div>
                      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
                        {(['console', 'cli', 'terraform', 'cloudformation'] as const).map(tab => (
                          <button
                            key={tab}
                            onClick={() => setActiveFixTab(tab)}
                            style={{
                              background: activeFixTab === tab ? 'rgba(0,212,170,0.15)' : 'rgba(255,255,255,0.04)',
                              border: `1px solid ${activeFixTab === tab ? '#00d4aa' : 'var(--color-border)'}`,
                              borderRadius: 5, color: activeFixTab === tab ? '#00d4aa' : 'var(--color-text-dim)',
                              cursor: 'pointer', fontSize: 11, fontWeight: 600,
                              padding: '5px 11px', textTransform: 'capitalize',
                            }}
                          >
                            {tab === 'cloudformation' ? 'CloudFormation' : tab.toUpperCase()}
                          </button>
                        ))}
                      </div>

                      <div style={{ position: 'relative' }}>
                        <div style={{ position: 'absolute', top: 8, right: 8, zIndex: 2 }}>
                          <CopyButton text={finding.remediation[activeFixTab]} />
                        </div>
                        <div style={{ ...codeBlockStyle, height: 180 }}>
                          {finding.remediation[activeFixTab]}
                        </div>
                      </div>
                    </div>

                    {/* Status select */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Status</span>
                      <select
                        value={currentStatus}
                        onChange={e => setFindingStatuses(prev => ({ ...prev, [finding.id]: e.target.value }))}
                        style={{
                          background: '#0a0d14', border: '1px solid var(--color-border)',
                          borderRadius: 5, color: 'var(--color-text-secondary)',
                          fontSize: 12, padding: '6px 10px', outline: 'none', cursor: 'pointer',
                        }}
                      >
                        {['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'].map(s => (
                          <option key={s} value={s}>{s.replace('_', ' ')}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TAB: INVENTORY
  // ─────────────────────────────────────────────────────────────────────────────

  function renderInventory() {
    const inventory = scan.inventory
    const resources = inventory[inventoryType] as { id: string; arn: string; name: string; region: string; securityStatus: string; findingIds: string[] }[]

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '24px 0' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-secondary)' }}>
            <span style={{ fontWeight: 800, color: 'var(--color-text-primary)' }}>{inventory.totalResources}</span> resources discovered across{' '}
            <span style={{ color: '#00d4aa', fontWeight: 700 }}>3 regions</span>
          </div>
        </div>

        {/* Category nav */}
        <div style={{ display: 'flex', gap: 6, overflowX: 'auto', paddingBottom: 4 }}>
          {INVENTORY_TABS.map(({ key, label }) => {
            const items = inventory[key] as unknown[]
            const count = Array.isArray(items) ? items.length : 0
            const isActive = inventoryType === key
            return (
              <button
                key={key}
                onClick={() => setInventoryType(key)}
                style={{
                  background: isActive ? 'rgba(0,212,170,0.12)' : 'rgba(255,255,255,0.04)',
                  border: `1px solid ${isActive ? '#00d4aa' : 'var(--color-border)'}`,
                  borderRadius: 6, cursor: 'pointer', fontSize: 12, fontWeight: 600, whiteSpace: 'nowrap',
                  color: isActive ? '#00d4aa' : 'var(--color-text-secondary)',
                  padding: '7px 14px', flexShrink: 0, transition: 'all 0.15s',
                }}
              >
                {label} <span style={{ opacity: 0.7, fontFamily: 'var(--font-mono)' }}>({count})</span>
              </button>
            )
          })}
        </div>

        {/* Table */}
        <div style={{ ...cardStyle, padding: 0, overflow: 'hidden' }}>
          {/* Table header */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '180px 1fr 110px 110px 80px',
            gap: 0, background: 'var(--color-bg-surface)',
            borderBottom: '1px solid var(--color-border)',
            padding: '10px 16px',
          }}>
            {['Name', 'ARN', 'Region', 'Security Status', 'Findings'].map(col => (
              <div key={col} style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
                {col}
              </div>
            ))}
          </div>

          {/* Rows */}
          {resources.map((res, idx) => (
            <div
              key={res.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '180px 1fr 110px 110px 80px',
                gap: 0, padding: '12px 16px',
                background: idx % 2 === 1 ? 'rgba(255,255,255,0.018)' : 'transparent',
                borderBottom: idx < resources.length - 1 ? '1px solid var(--color-border)' : 'none',
                alignItems: 'center',
              }}
            >
              <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--color-text-primary)' }}>
                {res.name}
              </div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-text-dim)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                {res.arn.length > 45 ? res.arn.slice(0, 45) + '…' : res.arn}
              </div>
              <div>
                <span style={{
                  background: 'rgba(90,176,255,0.1)', color: '#5ab0ff',
                  fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                  fontFamily: 'var(--font-mono)',
                }}>
                  {res.region}
                </span>
              </div>
              <div>{secStatusBadge(res.securityStatus)}</div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700,
                color: res.findingIds.length > 0 ? '#ef5a5a' : 'var(--color-text-dim)',
              }}>
                {res.findingIds.length > 0 ? res.findingIds.length : '—'}
              </div>
            </div>
          ))}

          {resources.length === 0 && (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
              No resources in this category
            </div>
          )}
        </div>
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TAB: COMPLIANCE
  // ─────────────────────────────────────────────────────────────────────────────

  function renderCompliance() {
    const soc2Score = scan.complianceScores.find(s => s.framework === 'SOC2')?.score ?? 100
    const selectedScore = scan.complianceScores.find(s => s.framework === selectedFramework)

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: '24px 0' }}>
        {/* SOC2 warning */}
        {soc2Score < 70 && (
          <div style={{
            background: 'rgba(239,90,90,0.08)', border: '1px solid rgba(239,90,90,0.3)',
            borderRadius: 8, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12,
          }}>
            <span style={{ fontSize: 18 }}>⚠</span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#ef5a5a', marginBottom: 2 }}>
                Would fail a SOC 2 audit today
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                SOC 2 score is {soc2Score}% — below the 70% minimum threshold for audit readiness. Fix critical findings first.
              </div>
            </div>
          </div>
        )}

        {/* Framework cards 2x2 */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
          {scan.complianceScores.map(cs => {
            const isSelected = selectedFramework === cs.framework
            const color = FRAMEWORK_COLOR[cs.framework]
            return (
              <div
                key={cs.framework}
                onClick={() => setSelectedFramework(cs.framework)}
                style={{
                  ...cardStyle, padding: '20px',
                  borderTop: `3px solid ${color}`,
                  cursor: 'pointer',
                  boxShadow: isSelected ? `0 0 0 2px ${color}55` : 'none',
                  transition: 'all 0.2s',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: 'var(--color-text-primary)', marginBottom: 3 }}>
                      {FRAMEWORK_LABEL[cs.framework]}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-dim)' }}>
                      {cs.passed} passed · {cs.failed} failed · {cs.total} total
                    </div>
                  </div>
                  <ComplianceRing score={cs.score} color={color} />
                </div>

                {/* Mini progress */}
                <div style={{ width: '100%', height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', borderRadius: 3,
                    width: `${cs.score}%`, background: color,
                    transition: 'width 0.8s ease',
                  }} />
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
                  <span style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>{cs.gaps.length} control gaps</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: color }}>{cs.score}% compliant</span>
                </div>
              </div>
            )
          })}
        </div>

        {/* Gap table */}
        {selectedScore && (
          <div style={cardStyle}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 16 }}>
              <span style={{ color: FRAMEWORK_COLOR[selectedFramework] }}>{FRAMEWORK_LABEL[selectedFramework]}</span> — Control Gaps
            </div>

            {/* Table header */}
            <div style={{
              display: 'grid', gridTemplateColumns: '100px 1fr 80px 90px 90px',
              background: 'rgba(255,255,255,0.03)', borderRadius: '6px 6px 0 0',
              padding: '9px 12px', borderBottom: '1px solid var(--color-border)',
            }}>
              {['Control ID', 'Control Name', 'Status', 'Severity', 'Findings'].map(h => (
                <div key={h} style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
                  {h}
                </div>
              ))}
            </div>

            {selectedScore.gaps.map((gap, idx) => (
              <div key={gap.controlId} style={{
                display: 'grid', gridTemplateColumns: '100px 1fr 80px 90px 90px',
                padding: '11px 12px', alignItems: 'center',
                background: idx % 2 === 1 ? 'rgba(255,255,255,0.018)' : 'transparent',
                borderBottom: idx < selectedScore.gaps.length - 1 ? '1px solid var(--color-border)' : 'none',
              }}>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                  background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)',
                  borderRadius: 4, padding: '2px 7px', color: 'var(--color-text-dim)',
                }}>
                  {gap.controlId}
                </span>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.4, paddingRight: 12 }}>
                  {gap.controlName}
                </span>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                  background: gap.status === 'FAIL' ? 'rgba(239,90,90,0.15)' : 'rgba(242,209,86,0.15)',
                  color: gap.status === 'FAIL' ? '#ef5a5a' : '#f2d156',
                }}>
                  {gap.status}
                </span>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                  background: SEV_BG[gap.severity], color: SEV_COLOR[gap.severity],
                }}>
                  {gap.severity}
                </span>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#ef5a5a', fontFamily: 'var(--font-mono)' }}>
                  {gap.findingIds.length}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TAB: REMEDIATION
  // ─────────────────────────────────────────────────────────────────────────────

  function renderRemediation() {
    const totalMins = scan.remediationQueue.reduce((sum, r) => sum + r.estimatedMinutes, 0)
    const totalHours = (totalMins / 60).toFixed(1)

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '24px 0' }}>
        {/* Intro */}
        <div>
          <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--color-text-primary)', marginBottom: 4 }}>
            Remediation Queue
          </div>
          <div style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>
            Fix these in order — ranked by business impact vs. effort.
          </div>
        </div>

        {/* Stats bar */}
        <div style={{
          display: 'flex', gap: 24, background: 'rgba(0,212,170,0.06)',
          border: '1px solid rgba(0,212,170,0.2)', borderRadius: 8, padding: '12px 18px',
          flexWrap: 'wrap',
        }}>
          <div>
            <span style={{ fontSize: 20, fontWeight: 800, color: '#00d4aa', fontFamily: 'var(--font-mono)' }}>
              {scan.remediationQueue.length}
            </span>
            <span style={{ fontSize: 12, color: 'var(--color-text-dim)', marginLeft: 6 }}>issues to fix</span>
          </div>
          <div>
            <span style={{ fontSize: 20, fontWeight: 800, color: '#5ab0ff', fontFamily: 'var(--font-mono)' }}>
              {totalHours}h
            </span>
            <span style={{ fontSize: 12, color: 'var(--color-text-dim)', marginLeft: 6 }}>est. total fix time</span>
          </div>
          <div>
            <span style={{ fontSize: 20, fontWeight: 800, color: '#f2d156', fontFamily: 'var(--font-mono)' }}>
              {scan.remediationQueue.filter(r => r.effort === '5min').length}
            </span>
            <span style={{ fontSize: 12, color: 'var(--color-text-dim)', marginLeft: 6 }}>5-minute quick wins</span>
          </div>
        </div>

        {/* Queue cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {scan.remediationQueue.map(item => {
            const isExp = expandedRemId === item.findingId
            const finding = scan.findings.find(f => f.id === item.findingId)
            const currentStatus = findingStatuses[item.findingId] ?? item.status
            const pColor = priorityColor(item.priority)

            return (
              <div key={item.findingId} style={{
                ...cardStyle, padding: 0, overflow: 'hidden',
              }}>
                <div style={{ padding: '14px 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                    {/* Priority circle */}
                    <div style={{
                      width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
                      background: `${pColor}22`, border: `2px solid ${pColor}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 14, fontWeight: 800, color: pColor, fontFamily: 'var(--font-mono)',
                    }}>
                      {item.priority}
                    </div>

                    <div style={{ flex: 1, minWidth: 0 }}>
                      {/* Title row */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
                        <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--color-text-primary)' }}>
                          {item.title}
                        </span>
                        <span style={{
                          background: SEV_BG[item.severity], color: SEV_COLOR[item.severity],
                          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                        }}>
                          {item.severity}
                        </span>
                        <span style={{
                          background: `${EFFORT_COLOR[item.effort]}22`, color: EFFORT_COLOR[item.effort],
                          border: `1px solid ${EFFORT_COLOR[item.effort]}44`,
                          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                        }}>
                          ⏱ {item.effort}
                        </span>
                        <span style={{
                          background: `${CAT_COLOR[item.category]}22`, color: CAT_COLOR[item.category],
                          border: `1px solid ${CAT_COLOR[item.category]}44`,
                          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                        }}>
                          {item.category}
                        </span>
                      </div>

                      {/* Impact score bar */}
                      <div style={{ marginBottom: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                          <span style={{ fontSize: 10, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
                            Business Impact
                          </span>
                          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                            {item.impactScore}/100
                          </span>
                        </div>
                        <div style={{ width: '100%', height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{
                            height: '100%', borderRadius: 3,
                            width: `${item.impactScore}%`,
                            background: item.impactScore >= 90 ? '#ef5a5a' : item.impactScore >= 75 ? '#f28e3c' : item.impactScore >= 60 ? '#f2d156' : '#00d4aa',
                            transition: 'width 0.8s ease',
                          }} />
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                          Est. {item.estimatedMinutes} min fix time
                        </span>
                        <button
                          onClick={() => setExpandedRemId(isExp ? null : item.findingId)}
                          style={{
                            background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)',
                            borderRadius: 5, color: 'var(--color-text-dim)', cursor: 'pointer',
                            fontSize: 11, fontWeight: 600, padding: '4px 10px',
                          }}
                        >
                          {isExp ? '▲ Collapse' : '▼ View Fix'}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Expanded fix */}
                {isExp && finding && (
                  <div style={{ borderTop: '1px solid var(--color-border)', padding: '14px 16px' }}>
                    <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
                      {finding.remediation.summary}
                    </div>

                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 8 }}>
                        CLI Fix
                      </div>
                      <div style={{ position: 'relative' }}>
                        <div style={{ position: 'absolute', top: 8, right: 8, zIndex: 2 }}>
                          <CopyButton text={finding.remediation.cli} />
                        </div>
                        <div style={{ ...codeBlockStyle, height: 140 }}>
                          {finding.remediation.cli}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                      <button
                        onClick={() => setFindingStatuses(prev => ({ ...prev, [item.findingId]: 'IN_PROGRESS' }))}
                        style={{
                          background: currentStatus === 'IN_PROGRESS' ? 'rgba(0,212,170,0.15)' : 'rgba(255,255,255,0.06)',
                          border: `1px solid ${currentStatus === 'IN_PROGRESS' ? '#00d4aa' : 'var(--color-border)'}`,
                          borderRadius: 6, color: currentStatus === 'IN_PROGRESS' ? '#00d4aa' : 'var(--color-text-secondary)',
                          cursor: 'pointer', fontSize: 12, fontWeight: 600, padding: '7px 14px',
                          transition: 'all 0.2s',
                        }}
                      >
                        {currentStatus === 'IN_PROGRESS' ? '✓ In Progress' : 'Mark as In Progress'}
                      </button>
                      <button
                        onClick={() => setFindingStatuses(prev => ({ ...prev, [item.findingId]: 'REMEDIATED' }))}
                        style={{
                          background: currentStatus === 'REMEDIATED' ? 'rgba(0,212,170,0.25)' : 'rgba(0,212,170,0.08)',
                          border: `1px solid ${currentStatus === 'REMEDIATED' ? '#00d4aa' : 'rgba(0,212,170,0.3)'}`,
                          borderRadius: 6, color: '#00d4aa', cursor: 'pointer',
                          fontSize: 12, fontWeight: 600, padding: '7px 14px', transition: 'all 0.2s',
                        }}
                      >
                        {currentStatus === 'REMEDIATED' ? '✓ Remediated' : 'Mark as Remediated'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────────────────────────────────────

  const TABS = [
    { id: 'connect',     label: 'Connect' },
    { id: 'overview',    label: 'Overview' },
    { id: 'findings',    label: `Findings (${scan.summary.totalFindings})` },
    { id: 'inventory',   label: 'Inventory' },
    { id: 'compliance',  label: 'Compliance' },
    { id: 'remediation', label: 'Remediation' },
  ] as const

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--color-bg-base)',
      color: 'var(--color-text-primary)',
      padding: '0 0 48px',
    }}>
      {/* Page header */}
      <div style={{
        borderBottom: '1px solid var(--color-border)',
        background: 'var(--color-bg-surface)',
        padding: '18px 28px 0',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 8,
            background: 'rgba(0,212,170,0.15)', border: '1px solid rgba(0,212,170,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16,
          }}>
            ☁
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 800, color: 'var(--color-text-primary)', lineHeight: 1.2 }}>
              Cloud Misconfiguration Scanner
            </div>
            <div style={{ fontSize: 12, color: 'var(--color-text-dim)' }}>
              AWS · Azure · GCP — read-only, zero-credential security audit
            </div>
          </div>
          {connectionStep === 'connected' && (
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00d4aa' }} />
              <span style={{ fontSize: 12, fontWeight: 600, color: '#00d4aa' }}>acme-production connected</span>
            </div>
          )}
        </div>

        {/* Tab bar */}
        <div style={{ display: 'flex', gap: 0, overflowX: 'auto' }}>
          {TABS.map(tab => {
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  borderBottom: `2px solid ${isActive ? '#00d4aa' : 'transparent'}`,
                  color: isActive ? '#00d4aa' : 'var(--color-text-dim)',
                  cursor: 'pointer',
                  fontSize: 13,
                  fontWeight: isActive ? 700 : 500,
                  padding: '10px 18px 12px',
                  transition: 'all 0.15s',
                  whiteSpace: 'nowrap',
                }}
              >
                {tab.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Tab content */}
      <div style={{ padding: '0 28px' }}>
        {activeTab === 'connect'     && renderConnect()}
        {activeTab === 'overview'    && renderOverview()}
        {activeTab === 'findings'    && renderFindings()}
        {activeTab === 'inventory'   && renderInventory()}
        {activeTab === 'compliance'  && renderCompliance()}
        {activeTab === 'remediation' && renderRemediation()}
      </div>
    </div>
  )
}
