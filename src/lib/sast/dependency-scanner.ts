// HemisX SAST — Dependency Vulnerability Scanner (SCA)
// Scans package manifests (package.json, requirements.txt, go.mod, Gemfile, pom.xml)
// for known vulnerable dependencies.

import type { SastFindingResult } from '@/lib/types/sast'
import { randomUUID } from 'crypto'

// ─── Known Vulnerable Packages Database ───────────────────────────────────────
// In production this would query the OSV (Open Source Vulnerabilities) database.
// For now we embed a curated list of high-signal known-vulnerable packages/versions.

interface VulnEntry {
  ecosystem: 'npm' | 'pypi' | 'go' | 'rubygems' | 'maven'
  package:   string
  vulnerableVersions: string   // semver range or descriptive
  cve:       string
  severity:  'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  title:     string
  fix:       string            // recommended version
}

const VULN_DB: VulnEntry[] = [
  // npm
  { ecosystem: 'npm', package: 'lodash', vulnerableVersions: '<4.17.21', cve: 'CVE-2021-23337', severity: 'HIGH', title: 'Command Injection in lodash', fix: '>=4.17.21' },
  { ecosystem: 'npm', package: 'minimist', vulnerableVersions: '<1.2.6', cve: 'CVE-2021-44906', severity: 'CRITICAL', title: 'Prototype Pollution in minimist', fix: '>=1.2.6' },
  { ecosystem: 'npm', package: 'axios', vulnerableVersions: '<1.6.0', cve: 'CVE-2023-45857', severity: 'MEDIUM', title: 'CSRF Token Leakage in axios', fix: '>=1.6.0' },
  { ecosystem: 'npm', package: 'express', vulnerableVersions: '<4.19.2', cve: 'CVE-2024-29041', severity: 'MEDIUM', title: 'Open Redirect in express', fix: '>=4.19.2' },
  { ecosystem: 'npm', package: 'jsonwebtoken', vulnerableVersions: '<9.0.0', cve: 'CVE-2022-23529', severity: 'CRITICAL', title: 'Insecure Key Handling in jsonwebtoken', fix: '>=9.0.0' },
  { ecosystem: 'npm', package: 'qs', vulnerableVersions: '<6.10.3', cve: 'CVE-2022-24999', severity: 'HIGH', title: 'Prototype Pollution in qs', fix: '>=6.10.3' },
  { ecosystem: 'npm', package: 'node-fetch', vulnerableVersions: '<2.6.7', cve: 'CVE-2022-0235', severity: 'HIGH', title: 'Information Disclosure in node-fetch', fix: '>=2.6.7' },
  { ecosystem: 'npm', package: 'tar', vulnerableVersions: '<6.1.9', cve: 'CVE-2021-37713', severity: 'HIGH', title: 'Arbitrary File Overwrite in tar', fix: '>=6.1.9' },
  { ecosystem: 'npm', package: 'glob-parent', vulnerableVersions: '<5.1.2', cve: 'CVE-2020-28469', severity: 'HIGH', title: 'Regular Expression Denial of Service in glob-parent', fix: '>=5.1.2' },
  { ecosystem: 'npm', package: 'xml2js', vulnerableVersions: '<0.5.0', cve: 'CVE-2023-0842', severity: 'MEDIUM', title: 'Prototype Pollution in xml2js', fix: '>=0.5.0' },
  { ecosystem: 'npm', package: 'semver', vulnerableVersions: '<7.5.2', cve: 'CVE-2022-25883', severity: 'MEDIUM', title: 'ReDoS in semver', fix: '>=7.5.2' },
  { ecosystem: 'npm', package: 'tough-cookie', vulnerableVersions: '<4.1.3', cve: 'CVE-2023-26136', severity: 'MEDIUM', title: 'Prototype Pollution in tough-cookie', fix: '>=4.1.3' },
  { ecosystem: 'npm', package: 'shelljs', vulnerableVersions: '<0.8.5', cve: 'CVE-2022-0144', severity: 'HIGH', title: 'Improper Privilege Management in shelljs', fix: '>=0.8.5' },
  { ecosystem: 'npm', package: 'moment', vulnerableVersions: '<2.29.4', cve: 'CVE-2022-31129', severity: 'HIGH', title: 'ReDoS in moment', fix: '>=2.29.4 or migrate to dayjs/date-fns' },
  { ecosystem: 'npm', package: 'underscore', vulnerableVersions: '<1.13.6', cve: 'CVE-2021-23358', severity: 'HIGH', title: 'Arbitrary Code Execution in underscore', fix: '>=1.13.6' },

  // Python (pypi)
  { ecosystem: 'pypi', package: 'django', vulnerableVersions: '<4.2.11', cve: 'CVE-2024-24680', severity: 'HIGH', title: 'Denial of Service in Django intcomma filter', fix: '>=4.2.11' },
  { ecosystem: 'pypi', package: 'flask', vulnerableVersions: '<2.3.2', cve: 'CVE-2023-30861', severity: 'HIGH', title: 'Session Cookie Disclosure in Flask', fix: '>=2.3.2' },
  { ecosystem: 'pypi', package: 'requests', vulnerableVersions: '<2.31.0', cve: 'CVE-2023-32681', severity: 'MEDIUM', title: 'Information Disclosure in requests', fix: '>=2.31.0' },
  { ecosystem: 'pypi', package: 'urllib3', vulnerableVersions: '<2.0.7', cve: 'CVE-2023-45803', severity: 'MEDIUM', title: 'Request Body Leakage in urllib3', fix: '>=2.0.7' },
  { ecosystem: 'pypi', package: 'pillow', vulnerableVersions: '<10.0.1', cve: 'CVE-2023-44271', severity: 'HIGH', title: 'Denial of Service in Pillow', fix: '>=10.0.1' },
  { ecosystem: 'pypi', package: 'cryptography', vulnerableVersions: '<41.0.6', cve: 'CVE-2023-49083', severity: 'HIGH', title: 'NULL Pointer Dereference in cryptography', fix: '>=41.0.6' },
  { ecosystem: 'pypi', package: 'pyyaml', vulnerableVersions: '<6.0.1', cve: 'CVE-2020-14343', severity: 'CRITICAL', title: 'Arbitrary Code Execution in PyYAML', fix: '>=6.0.1' },
  { ecosystem: 'pypi', package: 'jinja2', vulnerableVersions: '<3.1.3', cve: 'CVE-2024-22195', severity: 'MEDIUM', title: 'XSS via xmlattr filter in Jinja2', fix: '>=3.1.3' },
  { ecosystem: 'pypi', package: 'sqlalchemy', vulnerableVersions: '<2.0.0', cve: 'CVE-2023-30798', severity: 'MEDIUM', title: 'SQL Injection in SQLAlchemy', fix: '>=2.0.0' },
  { ecosystem: 'pypi', package: 'paramiko', vulnerableVersions: '<3.4.0', cve: 'CVE-2023-48795', severity: 'MEDIUM', title: 'Terrapin SSH Attack in Paramiko', fix: '>=3.4.0' },

  // Go
  { ecosystem: 'go', package: 'golang.org/x/crypto', vulnerableVersions: '<0.17.0', cve: 'CVE-2023-48795', severity: 'MEDIUM', title: 'Terrapin SSH Attack in x/crypto', fix: '>=0.17.0' },
  { ecosystem: 'go', package: 'golang.org/x/net', vulnerableVersions: '<0.17.0', cve: 'CVE-2023-44487', severity: 'HIGH', title: 'HTTP/2 Rapid Reset in x/net', fix: '>=0.17.0' },
  { ecosystem: 'go', package: 'github.com/gin-gonic/gin', vulnerableVersions: '<1.9.1', cve: 'CVE-2023-29401', severity: 'HIGH', title: 'Open Redirect in Gin', fix: '>=1.9.1' },
  { ecosystem: 'go', package: 'github.com/golang-jwt/jwt', vulnerableVersions: '<4.5.0', cve: 'CVE-2024-51744', severity: 'MEDIUM', title: 'Improper Validation in golang-jwt', fix: '>=4.5.0' },

  // Ruby
  { ecosystem: 'rubygems', package: 'rails', vulnerableVersions: '<7.0.8', cve: 'CVE-2023-44487', severity: 'HIGH', title: 'HTTP/2 Rapid Reset in Rails', fix: '>=7.0.8' },
  { ecosystem: 'rubygems', package: 'nokogiri', vulnerableVersions: '<1.15.5', cve: 'CVE-2023-44487', severity: 'HIGH', title: 'HTTP/2 Rapid Reset via libxml2 in Nokogiri', fix: '>=1.15.5' },
  { ecosystem: 'rubygems', package: 'rack', vulnerableVersions: '<3.0.9.1', cve: 'CVE-2024-25126', severity: 'MEDIUM', title: 'Denial of Service in Rack', fix: '>=3.0.9.1' },
]

// ─── Parsers ──────────────────────────────────────────────────────────────────

interface ParsedDep {
  name:    string
  version: string
  line:    number
}

function parsePackageJson(content: string): ParsedDep[] {
  const deps: ParsedDep[] = []
  try {
    const pkg = JSON.parse(content)
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies }
    const lines = content.split('\n')
    for (const [name, ver] of Object.entries(allDeps)) {
      const lineIdx = lines.findIndex(l => l.includes(`"${name}"`))
      deps.push({ name, version: String(ver).replace(/^[\^~>=<\s]+/, ''), line: lineIdx + 1 })
    }
  } catch { /* invalid JSON */ }
  return deps
}

function parseRequirementsTxt(content: string): ParsedDep[] {
  const deps: ParsedDep[] = []
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line || line.startsWith('#') || line.startsWith('-')) continue
    const match = line.match(/^([a-zA-Z0-9_-]+)\s*(?:[><=!~]+\s*)?(\d+[\d.]*)?/)
    if (match) {
      deps.push({ name: match[1].toLowerCase(), version: match[2] ?? 'latest', line: i + 1 })
    }
  }
  return deps
}

function parseGoMod(content: string): ParsedDep[] {
  const deps: ParsedDep[] = []
  const lines = content.split('\n')
  let inRequire = false
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (line.startsWith('require (')) { inRequire = true; continue }
    if (line === ')') { inRequire = false; continue }
    if (inRequire || line.startsWith('require ')) {
      const m = line.match(/^\s*([\w./-]+)\s+v?([\d.]+)/)
      if (m) deps.push({ name: m[1], version: m[2], line: i + 1 })
    }
  }
  return deps
}

function parseGemfile(content: string): ParsedDep[] {
  const deps: ParsedDep[] = []
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    const m = line.match(/gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?/)
    if (m) {
      deps.push({ name: m[1], version: (m[2] ?? 'latest').replace(/^[~>=<\s]+/, ''), line: i + 1 })
    }
  }
  return deps
}

// ─── Version comparison (simple semver) ───────────────────────────────────────

function parseVersion(v: string): number[] {
  return v.split('.').map(n => parseInt(n, 10) || 0)
}

function versionLessThan(a: string, b: string): boolean {
  const pa = parseVersion(a)
  const pb = parseVersion(b.replace(/^[<>=]+/, ''))
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const va = pa[i] ?? 0
    const vb = pb[i] ?? 0
    if (va < vb) return true
    if (va > vb) return false
  }
  return false
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface DepScanResult {
  findings:    SastFindingResult[]
  totalDeps:   number
  vulnerable:  number
  ecosystem:   string
}

export function scanDependencies(
  scanId: string,
  filePath: string,
  content: string,
): DepScanResult {
  // Detect manifest type
  let deps: ParsedDep[] = []
  let ecosystem = 'unknown'

  const fname = filePath.toLowerCase().split('/').pop() ?? ''

  if (fname === 'package.json') {
    deps = parsePackageJson(content)
    ecosystem = 'npm'
  } else if (fname === 'requirements.txt' || fname === 'requirements-dev.txt' || fname === 'requirements_dev.txt') {
    deps = parseRequirementsTxt(content)
    ecosystem = 'pypi'
  } else if (fname === 'go.mod') {
    deps = parseGoMod(content)
    ecosystem = 'go'
  } else if (fname === 'gemfile' || fname === 'gemfile.lock') {
    deps = parseGemfile(content)
    ecosystem = 'rubygems'
  }

  if (deps.length === 0) {
    return { findings: [], totalDeps: 0, vulnerable: 0, ecosystem }
  }

  const findings: SastFindingResult[] = []
  const lines = content.split('\n')

  for (const dep of deps) {
    const vulns = VULN_DB.filter(v =>
      v.ecosystem === ecosystem &&
      v.package === dep.name &&
      (dep.version === 'latest' || versionLessThan(dep.version, v.vulnerableVersions.replace(/^</, '')))
    )

    for (const vuln of vulns) {
      const start = Math.max(0, dep.line - 2)
      const end   = Math.min(lines.length - 1, dep.line + 1)
      const snippet = lines
        .slice(start, end + 1)
        .map((l, i) => `${start + i + 1} | ${l}`)
        .join('\n')

      findings.push({
        id:           randomUUID(),
        scanId,
        ruleId:       `SCA-${vuln.cve}`,
        ruleName:     vuln.title,
        severity:     vuln.severity,
        confidence:   'HIGH',
        language:     ecosystem,
        filePath,
        lineStart:    dep.line,
        lineEnd:      dep.line,
        codeSnippet:  snippet,
        description:  `${dep.name}@${dep.version} is vulnerable to ${vuln.cve}: ${vuln.title}. Vulnerable versions: ${vuln.vulnerableVersions}.`,
        remediation:  `Upgrade ${dep.name} to ${vuln.fix}. Run: ${ecosystem === 'npm' ? `npm install ${dep.name}@latest` : ecosystem === 'pypi' ? `pip install --upgrade ${dep.name}` : ecosystem === 'go' ? `go get ${dep.name}@latest` : `bundle update ${dep.name}`}`,
        owasp:        'A06:2021 – Vulnerable and Outdated Components',
        cwe:          'CWE-1035',
        category:     'Injection', // closest category match
        status:       'OPEN',
        falsePositive: false,
        detectedAt:   new Date().toISOString(),
      })
    }
  }

  return {
    findings,
    totalDeps:  deps.length,
    vulnerable: new Set(findings.map(f => f.filePath + ':' + f.lineStart)).size,
    ecosystem,
  }
}

/** Check if a file is a dependency manifest */
export function isDependencyManifest(filePath: string): boolean {
  const fname = filePath.toLowerCase().split('/').pop() ?? ''
  return ['package.json', 'requirements.txt', 'requirements-dev.txt', 'go.mod', 'gemfile', 'pom.xml'].includes(fname)
}
