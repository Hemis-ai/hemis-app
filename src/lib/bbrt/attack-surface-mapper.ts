// src/lib/bbrt/attack-surface-mapper.ts
// Phase 3: Attack Surface Mapping — Build asset graph from recon data
import type {
  BbrtReconResult,
  BbrtAttackSurface,
  AttackSurfaceAsset,
  BbrtTargetConfig,
  AssetType,
  ExposureLevel,
} from '@/lib/types/bbrt'
import { randomUUID } from 'crypto'

// ─── Asset Classification Rules ─────────────────────────────────────────────

const ADMIN_INDICATORS = ['admin', 'backoffice', 'dashboard', 'panel', 'console', 'manage']
const DB_SERVICES = ['mysql', 'postgresql', 'redis', 'mongodb', 'elasticsearch', 'mssql', 'oracle', 'memcached', 'etcd']
const CROWN_JEWEL_INDICATORS = ['payment', 'billing', 'auth', 'sso', 'vault', 'db', 'pg', 'redis', 'mongo']
const CDN_INDICATORS = ['cdn', 'static', 'assets', 'media', 'cloudfront']
const EMAIL_INDICATORS = ['mail', 'smtp', 'imap', 'mx']

function classifyAssetType(subdomain: string, services: string[]): AssetType {
  const prefix = subdomain.split('.')[0].toLowerCase()

  if (ADMIN_INDICATORS.some(a => prefix.includes(a))) return 'admin_panel'
  if (services.some(s => DB_SERVICES.includes(s))) return 'database'
  if (CDN_INDICATORS.some(c => prefix.includes(c))) return 'cdn'
  if (EMAIL_INDICATORS.some(e => prefix.includes(e))) return 'email_server'
  if (prefix === 'api' || prefix.startsWith('api-')) return 'api_endpoint'
  if (prefix === 'lb' || prefix === 'proxy' || prefix === 'traefik') return 'load_balancer'

  // Check if it's the root domain or a subdomain
  if (!subdomain.includes('.') || subdomain.split('.').length === 2) return 'domain'
  return 'subdomain'
}

function classifyExposure(
  services: string[],
  ports: number[],
  hasAuth: boolean,
): ExposureLevel {
  // Databases or internal services exposed = INTERNAL_EXPOSED
  if (services.some(s => DB_SERVICES.includes(s))) return 'INTERNAL_EXPOSED'
  if (ports.some(p => [2379, 9300, 11211, 15672].includes(p))) return 'INTERNAL_EXPOSED'

  // Admin/management without auth = PUBLIC
  if (!hasAuth) return 'PUBLIC'

  // Standard web services with some protection
  if (ports.every(p => [80, 443, 8080, 8443].includes(p))) return 'PUBLIC'

  return 'SEMI_PUBLIC'
}

function calculateAssetRisk(
  asset: Partial<AttackSurfaceAsset>,
  services: string[],
  ports: number[],
  techCVEs: string[],
): number {
  let score = 0

  // Base score by type
  const typeScores: Record<AssetType, number> = {
    database: 40, admin_panel: 35, api_endpoint: 25, domain: 10,
    subdomain: 15, ip: 20, cloud_asset: 30, cdn: 5,
    email_server: 15, load_balancer: 10,
  }
  score += typeScores[asset.type || 'subdomain'] || 10

  // Exposure penalty
  if (asset.exposureLevel === 'INTERNAL_EXPOSED') score += 25
  else if (asset.exposureLevel === 'PUBLIC') score += 10

  // Service risk
  if (services.some(s => DB_SERVICES.includes(s))) score += 20
  if (services.includes('telnet')) score += 15
  if (services.includes('ftp')) score += 10
  if (services.includes('smb')) score += 15

  // Port count risk (more ports = larger attack surface)
  score += Math.min(ports.length * 3, 15)

  // Known CVEs
  score += Math.min(techCVEs.length * 5, 20)

  // Is it a crown jewel?
  if (asset.isCrownJewel) score += 10

  return Math.min(score, 100)
}

// ─── Main Attack Surface Mapper ─────────────────────────────────────────────

export function mapAttackSurface(
  recon: BbrtReconResult,
  config: BbrtTargetConfig,
): BbrtAttackSurface {
  const assets: AttackSurfaceAsset[] = []
  const entryPoints: string[] = []
  const crownJewels: string[] = []
  const shadowAssets: AttackSurfaceAsset[] = []

  // ── Build assets from subdomains + ports ──
  for (const sub of recon.subdomains.filter(s => s.status === 'active')) {
    const hostPorts = recon.openPorts.filter(p => p.host === sub.subdomain)
    const services = hostPorts.map(p => p.service)
    const portNumbers = hostPorts.map(p => p.port)
    const hostTech = recon.techStack.filter(t =>
      t.detectedVia.toLowerCase().includes(sub.subdomain.toLowerCase()) ||
      t.detectedVia.toLowerCase().includes('port')
    )
    const techCVEs = hostTech.flatMap(t => t.knownCVEs || [])
    const techNames = hostTech.map(t => t.version ? `${t.name}/${t.version}` : t.name)

    const type = classifyAssetType(sub.subdomain, services)
    const hasAuth = !['jenkins', 'grafana', 'kibana', 'prometheus', 'admin'].some(
      a => sub.subdomain.toLowerCase().includes(a)
    )
    const exposure = classifyExposure(services, portNumbers, hasAuth)

    const isCJ = CROWN_JEWEL_INDICATORS.some(c => sub.subdomain.toLowerCase().includes(c))
    const isEP = type === 'api_endpoint' || type === 'admin_panel' ||
      portNumbers.includes(80) || portNumbers.includes(443) || portNumbers.includes(8080)

    const asset: AttackSurfaceAsset = {
      id: `asset-${randomUUID().slice(0, 8)}`,
      type,
      label: sub.subdomain,
      url: portNumbers.includes(443) ? `https://${sub.subdomain}` :
        portNumbers.includes(80) ? `http://${sub.subdomain}` : undefined,
      ip: sub.ip,
      domain: config.targetDomain,
      exposureLevel: exposure,
      services,
      techStack: techNames,
      knownVulnerabilities: techCVEs,
      riskScore: 0, // calculated below
      isEntryPoint: isEP,
      isCrownJewel: isCJ,
      metadata: {
        httpStatus: sub.httpStatus?.toString() || 'N/A',
        portCount: portNumbers.length.toString(),
        isShadow: sub.isShadowAsset.toString(),
      },
    }

    asset.riskScore = calculateAssetRisk(asset, services, portNumbers, techCVEs)

    assets.push(asset)
    if (isEP) entryPoints.push(asset.id)
    if (isCJ) crownJewels.push(asset.id)
    if (sub.isShadowAsset) shadowAssets.push(asset)
  }

  // ── Build assets from cloud resources ──
  for (const cloud of recon.cloudAssets) {
    const asset: AttackSurfaceAsset = {
      id: `asset-cloud-${randomUUID().slice(0, 8)}`,
      type: 'cloud_asset',
      label: `${cloud.provider}:${cloud.identifier}`,
      domain: config.targetDomain,
      exposureLevel: cloud.isPublic ? 'PUBLIC' : 'SEMI_PUBLIC',
      services: [cloud.type],
      techStack: [cloud.provider.toUpperCase()],
      knownVulnerabilities: cloud.issues,
      riskScore: cloud.isPublic ? 65 : 20,
      isEntryPoint: cloud.isPublic,
      isCrownJewel: cloud.type === 's3_bucket' && cloud.issues.length > 0,
      metadata: {
        provider: cloud.provider,
        region: cloud.region || 'unknown',
        isPublic: cloud.isPublic.toString(),
      },
    }

    assets.push(asset)
    if (cloud.isPublic) entryPoints.push(asset.id)
    if (asset.isCrownJewel) crownJewels.push(asset.id)
  }

  // ── Calculate overall exposure score ──
  const totalRisk = assets.reduce((sum, a) => sum + a.riskScore, 0)
  const exposureScore = assets.length > 0 ? Math.round(totalRisk / assets.length) : 0

  const publicAssets = assets.filter(a => a.exposureLevel === 'PUBLIC').length
  const internalExposed = assets.filter(a => a.exposureLevel === 'INTERNAL_EXPOSED').length

  return {
    assets,
    entryPoints,
    crownJewels,
    exposureScore: Math.min(exposureScore, 100),
    shadowAssets,
    totalAssets: assets.length,
    publicAssets,
    internalExposedAssets: internalExposed,
    mappedAt: new Date().toISOString(),
  }
}
