import type { ThreatAlert, KillChainEvent, HealthScore } from '@/lib/types'

export const INITIAL_ALERTS: ThreatAlert[] = [
  {
    id: 'alert-001', severity: 'CRITICAL',
    title: 'IAM Credentials Used from Anomalous Geolocation',
    summary: 'AWS credentials for "deploy-bot" were used from an IP address in Eastern Europe (185.220.101.47) — a location never seen before for this account. This follows a pattern consistent with credential theft and unauthorized access.',
    source: 'CloudTrail', resource: 'IAM:deploy-bot', ip: '185.220.101.47',
    region: 'eu-central-1', timestamp: '2026-03-13T10:07:44Z',
    status: 'INVESTIGATING', tactics: ['Initial Access', 'Persistence'],
    autoResponded: true,
    responseActions: ['IAM credentials suspended', 'Security team notified', 'Session terminated'],
  },
  {
    id: 'alert-002', severity: 'CRITICAL',
    title: 'Mass S3 Object Enumeration Detected',
    summary: '4,200+ S3 ListObjects API calls were made in under 60 seconds from the same session. This is consistent with automated data harvesting — a precursor to data exfiltration.',
    source: 'CloudTrail', resource: 'S3:prod-customer-backups', ip: '185.220.101.47',
    region: 'us-east-1', timestamp: '2026-03-13T10:06:58Z',
    status: 'CONTAINED', tactics: ['Collection', 'Exfiltration'],
    autoResponded: true,
    responseActions: ['Bucket policy updated to deny external access', 'S3 access logging enabled', 'Incident ticket created (INC-2847)'],
  },
  {
    id: 'alert-003', severity: 'HIGH',
    title: 'GuardDuty: EC2 Instance Communicating with Known Tor Exit Node',
    summary: 'Production instance "api-server-prod-2" has established outbound connections to 3 known Tor exit nodes. This may indicate command-and-control activity or data exfiltration over an anonymization network.',
    source: 'GuardDuty', resource: 'EC2:i-0a1b2c3d4e5f6a7b9', ip: '176.10.99.200',
    region: 'us-east-1', timestamp: '2026-03-13T09:51:22Z',
    status: 'INVESTIGATING', tactics: ['Command and Control', 'Exfiltration'],
    autoResponded: false,
    responseActions: [],
  },
  {
    id: 'alert-004', severity: 'HIGH',
    title: 'New IAM Admin Role Created Outside IaC Pipeline',
    summary: 'An IAM role with AdministratorAccess was created directly via the AWS Console by "dev-user-chen" — bypassing the normal Terraform pipeline. This is a potential persistence mechanism.',
    source: 'CloudTrail', resource: 'IAM:HemisX-emergency-role', ip: '203.0.113.45',
    region: 'us-east-1', timestamp: '2026-03-13T09:33:10Z',
    status: 'NEW', tactics: ['Persistence', 'Privilege Escalation'],
    autoResponded: false,
    responseActions: [],
  },
  {
    id: 'alert-005', severity: 'MEDIUM',
    title: 'VPC Flow Logs: Port Scan Detected',
    summary: 'Sequential connection attempts across 2,048 ports were detected originating from IP 91.213.50.12 targeting your production VPC. No successful connections were established.',
    source: 'VPC Flow Logs', resource: 'VPC:vpc-0c8d2f1a4b5e6c7d', ip: '91.213.50.12',
    region: 'us-east-1', timestamp: '2026-03-13T09:12:04Z',
    status: 'RESOLVED', tactics: ['Reconnaissance'],
    autoResponded: true,
    responseActions: ['IP blocked via WAF', 'Alert correlated with HEMIS scan data'],
  },
  {
    id: 'alert-006', severity: 'MEDIUM',
    title: 'Unusual Lambda Invocation Pattern',
    summary: '"process-payments" Lambda was invoked 1,240 times in 5 minutes — 47× above baseline. The invocations carry unusual payload structures not matching normal transaction patterns.',
    source: 'CloudTrail', resource: 'Lambda:process-payments',
    region: 'us-east-1', timestamp: '2026-03-13T08:55:33Z',
    status: 'RESOLVED', tactics: ['Execution', 'Impact'],
    autoResponded: true,
    responseActions: ['Lambda concurrency throttled', 'Payload anomaly flagged for review'],
  },
]

export const KILL_CHAIN_EVENTS: KillChainEvent[] = [
  { timestamp:'10:04:12', stage:'Reconnaissance',     action:'Port & service scan',           actor:'185.220.101.47', target:'api.acme-corp.com',     severity:'LOW'      },
  { timestamp:'10:05:08', stage:'Initial Access',     action:'SQL injection exploit',         actor:'185.220.101.47', target:'/v1/login endpoint',    severity:'CRITICAL' },
  { timestamp:'10:05:44', stage:'Credential Access',  action:'AWS key exfiltration from S3',  actor:'185.220.101.47', target:'prod-env-config bucket', severity:'CRITICAL' },
  { timestamp:'10:06:02', stage:'Privilege Escalation',action:'IAM escalation via stolen key', actor:'deploy-bot',    target:'AWS IAM',                severity:'CRITICAL' },
  { timestamp:'10:06:18', stage:'Discovery',          action:'IAM enumeration',               actor:'deploy-bot',    target:'AWS IAM',                severity:'HIGH'     },
  { timestamp:'10:06:58', stage:'Collection',         action:'Mass S3 enumeration',           actor:'deploy-bot',    target:'prod-customer-backups',  severity:'HIGH'     },
  { timestamp:'10:07:33', stage:'Exfiltration',       action:'Data transfer to external S3',  actor:'deploy-bot',    target:'attacker-staging-bucket', severity:'CRITICAL'},
  { timestamp:'10:07:44', stage:'Containment',        action:'AI Blue Team auto-response',    actor:'HemisX AI',     target:'IAM:deploy-bot',         severity:'INFO'     },
]

export const HEALTH_SCORE: HealthScore = {
  overall:   72,
  detection: 84,
  response:  79,
  coverage:  58,
  mttr:      '4m 12s',
}

// New alerts that stream in during demo
export const LIVE_ALERT_FEED: Omit<ThreatAlert, 'id'>[] = [
  {
    severity: 'HIGH',
    title: 'Privilege Escalation Attempt via IMDSv1',
    summary: 'An EC2 instance queried the metadata service using IMDSv1 to retrieve instance profile credentials, then attempted to attach an admin policy to a new IAM role.',
    source: 'CloudTrail', resource: 'EC2:i-0x7f3a9b2c',
    region: 'us-east-1', timestamp: new Date().toISOString(),
    status: 'NEW', tactics: ['Privilege Escalation'],
    autoResponded: false, responseActions: [],
  },
  {
    severity: 'MEDIUM',
    title: 'Suspicious CloudFormation Stack Deployment',
    summary: 'A CloudFormation stack was deployed by "ci-runner" that provisions an S3 bucket with public read access and disables Block Public Access. This deviates from approved IaC templates.',
    source: 'CloudTrail', resource: 'CloudFormation:stack/mystery-stack',
    region: 'us-east-2', timestamp: new Date().toISOString(),
    status: 'NEW', tactics: ['Persistence', 'Defense Evasion'],
    autoResponded: true, responseActions: ['Stack deployment blocked', 'IaC policy violation flagged'],
  },
]
