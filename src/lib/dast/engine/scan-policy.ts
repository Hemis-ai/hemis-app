// DAST Scan Policy Configuration
// Maps scan profiles to ZAP scan policy settings for differentiated scan intensity.

import { ZapClient } from './zap/zap-client'
import type { ScanProfile, ScanPolicyConfig, AttackStrength, AlertThreshold } from '../types'

// ─── OWASP Top 10 Critical Scanner IDs ──────────────────────────────────────
// These cover the most impactful vulnerability categories for quick scans.

const OWASP_TOP10_CRITICAL_SCANNERS = [
  // A03: Injection — SQLi variants
  '40018', '40019', '40020', '40021', '40022', '40024', '40027', '90018',
  // A03: Injection — XSS
  '40012', '40014', '40026',
  // A03: Injection — Command injection
  '90020',
  // A03: Injection — XXE
  '90023',
  // A03: Injection — SSTI
  '90035',
  // A03: Injection — Expression Language injection
  '90025',
  // A10: SSRF
  '40046',
  // A01: Broken Access Control — Path traversal
  '10202',
  // A06: Vulnerable Components — Log4Shell
  '40043',
]

// Scanner IDs focused on injection testing (for api_only profile)
const INJECTION_FOCUSED_SCANNERS = [
  // All SQLi
  '40018', '40019', '40020', '40021', '40022', '40024', '40027', '90018',
  // XSS (reflected only — DOM not relevant for APIs)
  '40012',
  // Command injection, XXE, SSRF, SSTI, EL injection
  '90020', '90023', '40046', '90035', '90025',
  // CRLF injection, parameter tampering
  '40003', '40008',
  // XPath injection, XSLT injection
  '90021', '90017',
  // Server-side code injection, SSI
  '90019', '40009',
  // Log4Shell
  '40043',
  // Path traversal
  '10202',
  // Bypassing 403
  '40038',
  // Cloud metadata
  '90034',
]

// DOM-based scanners to skip for API-only scans
const DOM_SCANNERS = [
  '40026',  // DOM XSS
  '40014',  // Stored XSS (requires rendering)
  '10043',  // User controllable JS event
]

// ─── Profile → Policy Mapping ────────────────────────────────────────────────

const PROFILE_CONFIGS: Record<ScanProfile, ScanPolicyConfig> = {
  full: {
    name: 'hemisx-full',
    defaultStrength: 'MEDIUM',
    defaultThreshold: 'LOW',
    maxRuleDurationMins: 10,
    threadPerHost: 3,
  },
  quick: {
    name: 'hemisx-quick',
    defaultStrength: 'HIGH',
    defaultThreshold: 'HIGH',
    maxRuleDurationMins: 5,
    threadPerHost: 5,
    enabledScannerIds: OWASP_TOP10_CRITICAL_SCANNERS,
  },
  api_only: {
    name: 'hemisx-api',
    defaultStrength: 'HIGH',
    defaultThreshold: 'MEDIUM',
    maxRuleDurationMins: 8,
    threadPerHost: 4,
    enabledScannerIds: INJECTION_FOCUSED_SCANNERS,
    disabledScannerIds: DOM_SCANNERS,
  },
  deep: {
    name: 'hemisx-deep',
    defaultStrength: 'INSANE',
    defaultThreshold: 'LOW',
    maxRuleDurationMins: 20,
    threadPerHost: 2,
  },
}

/**
 * Create and configure a ZAP scan policy for the given profile.
 * Returns the policy name to pass to `startActiveScan`.
 */
export async function configureScanPolicy(client: ZapClient, scanProfile: ScanProfile): Promise<string> {
  const config = PROFILE_CONFIGS[scanProfile]
  const policyName = config.name

  // Remove any existing policy with this name (best-effort)
  try { await client.removeScanPolicy(policyName) } catch { /* may not exist */ }

  // Create the policy
  await client.addScanPolicy(policyName)

  // Set global scan options
  await client.setOptionThreadPerHost(config.threadPerHost)
  await client.setOptionMaxRuleDurationInMins(config.maxRuleDurationMins)

  // For profiles with a specific scanner whitelist, disable all first then enable only the selected set
  if (config.enabledScannerIds) {
    await client.disableAllScanners(policyName)
    await client.enableScanners(config.enabledScannerIds, policyName)
  } else {
    // Enable everything, then disable specific ones if needed
    await client.enableAllScanners(policyName)
    if (config.disabledScannerIds) {
      await client.disableScanners(config.disabledScannerIds, policyName)
    }
  }

  // Set attack strength and alert threshold for all enabled scanners.
  // ZAP allows setting these per-scanner, but we apply the profile defaults globally.
  // The special IDs '0' applies to all scanners in the policy.
  await setGlobalScannerConfig(client, policyName, config.defaultStrength, config.defaultThreshold)

  // For the deep profile, boost injection scanner strength to INSANE individually
  if (scanProfile === 'deep') {
    await boostInjectionScanners(client, policyName)
  }

  return policyName
}

/**
 * Set strength and threshold for all scanners in a policy.
 * We iterate over the key scanner groups rather than using a global ID,
 * since ZAP requires per-scanner configuration.
 */
async function setGlobalScannerConfig(
  client: ZapClient,
  policyName: string,
  strength: AttackStrength,
  threshold: AlertThreshold,
): Promise<void> {
  // Scanner category IDs that cover all ZAP active scan rules
  const allScannerCategories = [
    // Injection
    '40018', '40019', '40020', '40021', '40022', '40024', '40027', '90018',
    // XSS
    '40012', '40014', '40026',
    // Command injection, XXE, SSRF
    '90020', '90023', '40046',
    // Path traversal, CRLF, parameter tampering
    '10202', '40003', '40008',
    // Server-side code injection, SSI, XPath, XSLT
    '90019', '40009', '90021', '90017',
    // Misc active scanners
    '10048', '40028', '40032', '40034', '10058', '10105', '10026',
    // New expanded scanners
    '40013', '40016', '40017', '40029', '40035', '40038', '40042', '40043',
    '90025', '90028', '90034', '90035',
  ]

  // Apply in batches to avoid overwhelming ZAP with requests
  const batchSize = 10
  for (let i = 0; i < allScannerCategories.length; i += batchSize) {
    const batch = allScannerCategories.slice(i, i + batchSize)
    await Promise.all(batch.map(async (id) => {
      try {
        await client.setScannerAttackStrength(id, strength, policyName)
        await client.setScannerAlertThreshold(id, threshold, policyName)
      } catch { /* scanner may not exist in this ZAP version — skip */ }
    }))
  }
}

/**
 * For deep scans, set INSANE strength on injection-class scanners
 * for maximum payload coverage and detection.
 */
async function boostInjectionScanners(client: ZapClient, policyName: string): Promise<void> {
  const injectionScanners = [
    // SQLi variants
    '40018', '40019', '40020', '40021', '40022', '40024', '40027', '90018',
    // XSS
    '40012', '40014', '40026',
    // Command injection, XXE, SSRF, SSTI, EL injection
    '90020', '90023', '40046', '90035', '90025',
    // CRLF, XPath, XSLT, code injection
    '40003', '90021', '90017', '90019',
    // Log4Shell
    '40043',
  ]

  await Promise.all(injectionScanners.map(async (id) => {
    try {
      await client.setScannerAttackStrength(id, 'INSANE', policyName)
      await client.setScannerAlertThreshold(id, 'LOW', policyName)
    } catch { /* skip if scanner not available */ }
  }))
}

/**
 * Clean up a scan policy after use.
 */
export async function cleanupScanPolicy(client: ZapClient, scanProfile: ScanProfile): Promise<void> {
  const config = PROFILE_CONFIGS[scanProfile]
  try { await client.removeScanPolicy(config.name) } catch { /* best-effort cleanup */ }
}

/**
 * Get the policy config for a scan profile (for display/logging).
 */
export function getScanPolicyConfig(scanProfile: ScanProfile): ScanPolicyConfig {
  return { ...PROFILE_CONFIGS[scanProfile] }
}
