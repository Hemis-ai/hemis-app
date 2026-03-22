/**
 * Built-in DAST Scanner — performs real HTTP-based security analysis.
 * Works without ZAP or the Python engine. Makes actual requests to the target.
 */

export interface BuiltinFinding {
  type: string
  owaspCategory: string
  cweId?: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  cvssScore?: number
  riskScore: number
  title: string
  description: string
  businessImpact?: string
  affectedUrl: string
  affectedParameter?: string
  payload?: string
  requestEvidence?: string
  responseEvidence?: string
  remediation: string
  confidenceScore: number
}

export interface ScanResult {
  findings: BuiltinFinding[]
  endpointsDiscovered: number
  endpointsTested: number
  techStack: string[]
}

interface CrawledPage {
  url: string
  status: number
  headers: Record<string, string>
  body: string
  links: string[]
}

/**
 * Run a real DAST scan against the target URL.
 * This makes actual HTTP requests — no mocking.
 */
export async function runBuiltinScan(
  targetUrl: string,
  onProgress?: (percent: number, phase: string, message: string) => void,
): Promise<ScanResult> {
  const findings: BuiltinFinding[] = []
  const techStack: string[] = []

  // Phase 1: Validate target is reachable (0-5%)
  onProgress?.(1, 'initializing', 'Validating target URL...')
  const baseResponse = await fetchWithTimeout(targetUrl, 15000)
  if (!baseResponse) {
    throw new Error(`Target ${targetUrl} is not reachable. Verify the URL and try again.`)
  }
  onProgress?.(5, 'initializing', `Target reachable (HTTP ${baseResponse.status})`)

  // Phase 2: Crawl and discover pages (5-30%)
  onProgress?.(6, 'crawling', 'Crawling target site...')
  const crawled = await crawlSite(targetUrl, baseResponse, (percent, msg) => {
    onProgress?.(5 + Math.round(percent * 0.25), 'crawling', msg)
  })
  onProgress?.(30, 'crawling', `Discovered ${crawled.length} pages`)

  // Phase 3: Detect tech stack (30-35%)
  onProgress?.(31, 'scanning', 'Detecting technology stack...')
  detectTechStack(baseResponse, techStack)

  // Phase 4: Run security checks on all discovered pages (35-90%)
  const totalPages = crawled.length
  for (let i = 0; i < totalPages; i++) {
    const page = crawled[i]
    const percent = 35 + Math.round((i / totalPages) * 55)
    onProgress?.(percent, 'scanning', `Analyzing ${new URL(page.url).pathname} (${i + 1}/${totalPages})`)

    // Run all checks on this page
    checkSecurityHeaders(page, findings)
    checkCORS(page, findings)
    checkCookieSecurity(page, findings)
    checkInformationDisclosure(page, findings)
    checkClickjacking(page, findings)
    checkCacheHeaders(page, findings)
  }

  // Phase 5: TLS check (90-92%)
  onProgress?.(90, 'scanning', 'Checking TLS/SSL configuration...')
  await checkTLS(targetUrl, findings)

  // Phase 6: Backup file discovery (92-96%)
  onProgress?.(92, 'scanning', 'Probing for backup files...')
  await checkBackupFiles(targetUrl, findings, (msg) => onProgress?.(94, 'scanning', msg))

  // Phase 7: HSTS check (96-98%)
  onProgress?.(96, 'scanning', 'Checking HSTS enforcement...')
  checkHSTS(crawled[0], findings)

  // Deduplicate findings
  const seen = new Set<string>()
  const unique = findings.filter(f => {
    const key = `${f.type}|${f.affectedUrl}|${f.title}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })

  onProgress?.(100, 'complete', `Scan complete. Found ${unique.length} issues.`)

  return {
    findings: unique,
    endpointsDiscovered: crawled.length,
    endpointsTested: crawled.length,
    techStack,
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

async function fetchWithTimeout(url: string, timeout = 10000): Promise<CrawledPage | null> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    })
    clearTimeout(timer)
    const body = await res.text()
    const headers: Record<string, string> = {}
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v })
    const links = extractLinks(body, url)
    return { url: res.url, status: res.status, headers, body, links }
  } catch {
    return null
  }
}

function extractLinks(html: string, baseUrl: string): string[] {
  const links: string[] = []
  const seen = new Set<string>()
  // Match href and src attributes
  const regex = /(?:href|src)\s*=\s*["']([^"'#]+)/gi
  let match
  while ((match = regex.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], baseUrl).href
      // Only follow same-origin links
      if (new URL(resolved).origin === new URL(baseUrl).origin && !seen.has(resolved)) {
        seen.add(resolved)
        links.push(resolved)
      }
    } catch { /* invalid URL */ }
  }
  return links
}

async function crawlSite(
  targetUrl: string,
  basePage: CrawledPage,
  onProgress?: (percent: number, msg: string) => void,
): Promise<CrawledPage[]> {
  const crawled: CrawledPage[] = [basePage]
  const visited = new Set<string>([basePage.url])
  const queue = [...basePage.links]
  const origin = new URL(targetUrl).origin
  const maxPages = 50 // Reasonable limit

  let processed = 0
  while (queue.length > 0 && crawled.length < maxPages) {
    const url = queue.shift()!
    if (visited.has(url)) continue
    // Only crawl same-origin
    try {
      if (new URL(url).origin !== origin) continue
    } catch { continue }
    visited.add(url)

    const page = await fetchWithTimeout(url, 8000)
    if (!page || page.status >= 400) continue

    crawled.push(page)
    processed++
    onProgress?.(Math.min(100, Math.round((processed / maxPages) * 100)), `Crawled ${crawled.length} pages...`)

    // Add newly discovered links to queue
    for (const link of page.links) {
      if (!visited.has(link)) queue.push(link)
    }
  }

  return crawled
}

function detectTechStack(page: CrawledPage, stack: string[]) {
  const h = page.headers
  const b = page.body.toLowerCase()

  if (h['server']) stack.push(h['server'])
  if (h['x-powered-by']) stack.push(h['x-powered-by'])
  if (b.includes('__next') || b.includes('_next/static')) stack.push('Next.js')
  if (b.includes('react')) stack.push('React')
  if (b.includes('vue.js') || b.includes('vue.min.js')) stack.push('Vue.js')
  if (b.includes('angular')) stack.push('Angular')
  if (b.includes('wordpress') || b.includes('wp-content')) stack.push('WordPress')
  if (h['x-aspnet-version'] || h['x-aspnetmvc-version']) stack.push('ASP.NET')
  if (h['x-drupal-cache']) stack.push('Drupal')
  if (b.includes('laravel') || h['set-cookie']?.includes('laravel')) stack.push('Laravel')
}

// ─── Security Checks ─────────────────────────────────────────────────────

function checkSecurityHeaders(page: CrawledPage, findings: BuiltinFinding[]) {
  const h = page.headers
  const ct = h['content-type'] || ''
  if (!ct.includes('text/html')) return // Only check HTML pages

  if (!h['content-security-policy']) {
    findings.push({
      type: 'MISSING_SECURITY_HEADERS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'MEDIUM', cvssScore: 5.3, riskScore: 45,
      title: 'Missing Content-Security-Policy Header',
      description: `The page at ${page.url} does not set a Content-Security-Policy header, leaving it more susceptible to XSS and data injection attacks.`,
      affectedUrl: page.url,
      responseEvidence: 'No Content-Security-Policy header in response',
      remediation: "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'",
      confidenceScore: 100,
    })
  }

  if (!h['x-content-type-options']) {
    findings.push({
      type: 'MISSING_SECURITY_HEADERS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'LOW', riskScore: 20,
      title: 'Missing X-Content-Type-Options Header',
      description: `${page.url} does not set X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses, potentially executing malicious content.`,
      affectedUrl: page.url,
      remediation: 'Add header: X-Content-Type-Options: nosniff',
      confidenceScore: 100,
    })
  }

  if (!h['x-frame-options'] && !h['content-security-policy']?.includes('frame-ancestors')) {
    findings.push({
      type: 'MISSING_SECURITY_HEADERS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-1021', severity: 'MEDIUM', cvssScore: 4.3, riskScore: 40,
      title: 'Missing X-Frame-Options Header (Clickjacking)',
      description: `${page.url} does not set X-Frame-Options or CSP frame-ancestors, making it vulnerable to clickjacking.`,
      affectedUrl: page.url,
      remediation: 'Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.',
      confidenceScore: 100,
    })
  }

  if (!h['referrer-policy']) {
    findings.push({
      type: 'MISSING_SECURITY_HEADERS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-200', severity: 'INFO', riskScore: 10,
      title: 'Missing Referrer-Policy Header',
      description: `${page.url} does not set a Referrer-Policy header. The browser may leak the full URL in the Referer header when navigating away.`,
      affectedUrl: page.url,
      remediation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
      confidenceScore: 100,
    })
  }

  if (!h['permissions-policy'] && !h['feature-policy']) {
    findings.push({
      type: 'MISSING_SECURITY_HEADERS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'INFO', riskScore: 10,
      title: 'Missing Permissions-Policy Header',
      description: `${page.url} does not set a Permissions-Policy header. Browser features like camera, microphone, geolocation are not restricted.`,
      affectedUrl: page.url,
      remediation: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
      confidenceScore: 100,
    })
  }
}

function checkCORS(page: CrawledPage, findings: BuiltinFinding[]) {
  const acao = page.headers['access-control-allow-origin']
  const acac = page.headers['access-control-allow-credentials']

  if (!acao) return

  if (acao === '*' && acac === 'true') {
    findings.push({
      type: 'CORS_MISCONFIGURATION', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-942', severity: 'HIGH', cvssScore: 7.5, riskScore: 75,
      title: 'CORS Wildcard with Credentials',
      description: `${page.url} sets Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Any website can make authenticated cross-origin requests.`,
      affectedUrl: page.url,
      responseEvidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
      remediation: 'Never combine wildcard CORS with credentials. Use specific trusted origins.',
      confidenceScore: 95,
    })
  } else if (acao === '*') {
    findings.push({
      type: 'CORS_MISCONFIGURATION', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-942', severity: 'INFO', riskScore: 15,
      title: 'Overly Permissive CORS Policy (Wildcard Origin)',
      description: `${page.url} sets Access-Control-Allow-Origin: *. Any website can read cross-origin responses from this endpoint.`,
      affectedUrl: page.url,
      responseEvidence: `Access-Control-Allow-Origin: *`,
      remediation: 'Restrict CORS to specific trusted origins instead of wildcard *.',
      confidenceScore: 85,
    })
  }
}

function checkCookieSecurity(page: CrawledPage, findings: BuiltinFinding[]) {
  const setCookie = page.headers['set-cookie']
  if (!setCookie) return

  const cookies = setCookie.split(/,(?=\s*\w+=)/) // Split multiple Set-Cookie values

  for (const cookie of cookies) {
    const name = cookie.split('=')[0]?.trim()
    if (!name) continue

    const lower = cookie.toLowerCase()

    if (!lower.includes('secure') && page.url.startsWith('https')) {
      findings.push({
        type: 'INSECURE_COOKIE', owaspCategory: 'A07:2021 Identification and Authentication Failures',
        cweId: 'CWE-614', severity: 'MEDIUM', cvssScore: 4.7, riskScore: 42,
        title: `Cookie "${name}" Missing Secure Flag`,
        description: `The cookie "${name}" on ${page.url} is not set with the Secure flag, allowing it to be sent over unencrypted HTTP.`,
        affectedUrl: page.url, affectedParameter: `Set-Cookie: ${name}`,
        responseEvidence: cookie.trim(),
        remediation: 'Set the Secure flag on all cookies transmitted over HTTPS.',
        confidenceScore: 90,
      })
    }

    if (!lower.includes('httponly') && (name.toLowerCase().includes('session') || name.toLowerCase().includes('token') || name.toLowerCase().includes('auth'))) {
      findings.push({
        type: 'INSECURE_COOKIE', owaspCategory: 'A07:2021 Identification and Authentication Failures',
        cweId: 'CWE-1004', severity: 'MEDIUM', cvssScore: 4.3, riskScore: 38,
        title: `Sensitive Cookie "${name}" Missing HttpOnly Flag`,
        description: `The cookie "${name}" on ${page.url} is not HttpOnly. JavaScript can access it, making it vulnerable to XSS-based theft.`,
        affectedUrl: page.url, affectedParameter: `Set-Cookie: ${name}`,
        responseEvidence: cookie.trim(),
        remediation: 'Set the HttpOnly flag on all session/authentication cookies.',
        confidenceScore: 85,
      })
    }

    if (!lower.includes('samesite')) {
      findings.push({
        type: 'INSECURE_COOKIE', owaspCategory: 'A07:2021 Identification and Authentication Failures',
        cweId: 'CWE-1275', severity: 'LOW', riskScore: 20,
        title: `Cookie "${name}" Missing SameSite Attribute`,
        description: `The cookie "${name}" on ${page.url} does not set a SameSite attribute, making it vulnerable to CSRF attacks in older browsers.`,
        affectedUrl: page.url, affectedParameter: `Set-Cookie: ${name}`,
        remediation: 'Set SameSite=Lax or SameSite=Strict on all cookies.',
        confidenceScore: 80,
      })
    }
  }
}

function checkInformationDisclosure(page: CrawledPage, findings: BuiltinFinding[]) {
  const h = page.headers

  // Server version disclosure
  const server = h['server']
  if (server && /\d/.test(server)) {
    findings.push({
      type: 'INFORMATION_DISCLOSURE', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-200', severity: 'LOW', riskScore: 20,
      title: 'Server Version Information Disclosure',
      description: `${page.url} reveals server version in response headers: "${server}". This aids attackers in identifying known vulnerabilities.`,
      affectedUrl: page.url, affectedParameter: 'Server header',
      responseEvidence: `Server: ${server}`,
      remediation: 'Remove or obfuscate the Server header to hide version information.',
      confidenceScore: 100,
    })
  }

  // X-Powered-By disclosure
  const poweredBy = h['x-powered-by']
  if (poweredBy) {
    findings.push({
      type: 'INFORMATION_DISCLOSURE', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-200', severity: 'LOW', riskScore: 15,
      title: 'X-Powered-By Header Exposes Technology Stack',
      description: `${page.url} reveals technology via X-Powered-By: "${poweredBy}".`,
      affectedUrl: page.url, affectedParameter: 'X-Powered-By header',
      responseEvidence: `X-Powered-By: ${poweredBy}`,
      remediation: "Remove the X-Powered-By header. In Express: app.disable('x-powered-by')",
      confidenceScore: 100,
    })
  }
}

function checkClickjacking(page: CrawledPage, findings: BuiltinFinding[]) {
  const ct = page.headers['content-type'] || ''
  if (!ct.includes('text/html')) return

  const xfo = page.headers['x-frame-options']
  const csp = page.headers['content-security-policy']
  const hasFrameAncestors = csp?.includes('frame-ancestors')

  if (!xfo && !hasFrameAncestors) {
    findings.push({
      type: 'CLICKJACKING', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-1021', severity: 'MEDIUM', cvssScore: 4.3, riskScore: 35,
      title: 'Frameable Response (Potential Clickjacking)',
      description: `${page.url} can be embedded in an iframe by any site. An attacker could overlay invisible frames to trick users into clicking unintended elements.`,
      affectedUrl: page.url,
      responseEvidence: 'No X-Frame-Options or CSP frame-ancestors directive set',
      remediation: 'Set X-Frame-Options: DENY or use Content-Security-Policy: frame-ancestors \'none\'',
      confidenceScore: 90,
    })
  }
}

function checkCacheHeaders(page: CrawledPage, findings: BuiltinFinding[]) {
  const ct = page.headers['content-type'] || ''
  if (!ct.includes('text/html')) return

  const cacheControl = page.headers['cache-control'] || ''
  const pragma = page.headers['pragma'] || ''
  const url = page.url

  // Only flag if the page is served over HTTPS and has no cache prevention
  if (url.startsWith('https://') && !cacheControl.includes('no-store') && !cacheControl.includes('no-cache') && !pragma.includes('no-cache')) {
    findings.push({
      type: 'CACHEABLE_RESPONSE', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-525', severity: 'INFO', riskScore: 10,
      title: 'Cacheable HTTPS Response',
      description: `${url} is served over HTTPS but does not prevent caching. Sensitive data may be stored in browser or proxy caches.`,
      affectedUrl: url,
      responseEvidence: cacheControl ? `Cache-Control: ${cacheControl}` : 'No Cache-Control header set',
      remediation: 'For sensitive pages, add: Cache-Control: no-store, no-cache, must-revalidate',
      confidenceScore: 75,
    })
  }
}

async function checkTLS(targetUrl: string, findings: BuiltinFinding[]) {
  if (!targetUrl.startsWith('https://')) {
    findings.push({
      type: 'TLS_CONFIGURATION', owaspCategory: 'A02:2021 Cryptographic Failures',
      cweId: 'CWE-319', severity: 'HIGH', cvssScore: 7.4, riskScore: 70,
      title: 'Site Not Using HTTPS',
      description: `${targetUrl} is served over unencrypted HTTP. All data transmitted is visible to anyone on the network.`,
      affectedUrl: targetUrl,
      remediation: 'Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.',
      confidenceScore: 100,
    })
  }
}

function checkHSTS(page: CrawledPage | undefined, findings: BuiltinFinding[]) {
  if (!page || !page.url.startsWith('https://')) return

  const hsts = page.headers['strict-transport-security']
  if (!hsts) {
    findings.push({
      type: 'MISSING_SECURITY_HEADERS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-319', severity: 'MEDIUM', cvssScore: 5.3, riskScore: 45,
      title: 'Strict Transport Security (HSTS) Not Enforced',
      description: `${page.url} does not set the Strict-Transport-Security header. Users can be downgraded to HTTP via man-in-the-middle attacks.`,
      affectedUrl: page.url,
      responseEvidence: 'No Strict-Transport-Security header in response',
      remediation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      confidenceScore: 100,
    })
  } else {
    // Check max-age is reasonable (at least 6 months)
    const maxAgeMatch = hsts.match(/max-age=(\d+)/)
    if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 15768000) {
      findings.push({
        type: 'MISSING_SECURITY_HEADERS', owaspCategory: 'A05:2021 Security Misconfiguration',
        cweId: 'CWE-319', severity: 'LOW', riskScore: 20,
        title: 'HSTS Max-Age Too Short',
        description: `${page.url} sets HSTS with max-age=${maxAgeMatch[1]} (less than 6 months). This provides limited protection against SSL stripping.`,
        affectedUrl: page.url,
        responseEvidence: `Strict-Transport-Security: ${hsts}`,
        remediation: 'Increase HSTS max-age to at least 31536000 (1 year).',
        confidenceScore: 90,
      })
    }
  }
}

async function checkBackupFiles(targetUrl: string, findings: BuiltinFinding[], onProgress?: (msg: string) => void) {
  const backupPaths = [
    '/robots.txt', '/robots.txt.bak', '/robots.txt.old', '/robots.copy',
    '/.env', '/.env.bak', '/.env.local', '/.env.production',
    '/wp-config.php.bak', '/config.php.bak', '/web.config.bak',
    '/.git/config', '/.git/HEAD',
    '/backup.sql', '/dump.sql', '/database.sql',
    '/.htaccess.bak', '/server-status', '/phpinfo.php',
    '/sitemap.xml', '/.well-known/security.txt',
  ]

  for (const path of backupPaths) {
    onProgress?.(`Checking ${path}...`)
    try {
      const url = new URL(path, targetUrl).href
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 5000)
      const res = await fetch(url, {
        signal: controller.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)' },
      })
      clearTimeout(timer)

      if (res.ok && res.status === 200) {
        const ct = res.headers.get('content-type') || ''
        const bodyPreview = (await res.text()).slice(0, 500)

        // Skip if it returns the same HTML page (custom 404)
        if (ct.includes('text/html') && !path.endsWith('.html') && !path.includes('sitemap') && !path.includes('security.txt')) continue

        // Sensitive files
        if (path.includes('.env') || path.includes('.git') || path.includes('.sql') || path.includes('config')) {
          findings.push({
            type: 'SENSITIVE_FILE_EXPOSURE', owaspCategory: 'A01:2021 Broken Access Control',
            cweId: 'CWE-538', severity: 'HIGH', cvssScore: 7.5, riskScore: 70,
            title: `Sensitive File Accessible: ${path}`,
            description: `The file ${url} is publicly accessible. This may expose sensitive configuration, credentials, or database information.`,
            affectedUrl: url,
            responseEvidence: bodyPreview.slice(0, 200),
            remediation: `Block access to ${path} via web server configuration. Never expose configuration or backup files publicly.`,
            confidenceScore: 85,
          })
        }

        // Backup files
        if (path.includes('.bak') || path.includes('.old') || path.includes('.copy') || path.includes('backup') || path.includes('dump')) {
          findings.push({
            type: 'BACKUP_FILE_FOUND', owaspCategory: 'A05:2021 Security Misconfiguration',
            cweId: 'CWE-530', severity: 'MEDIUM', riskScore: 40,
            title: `Backup File Discovered: ${path}`,
            description: `A backup or old copy of a file was found at ${url}. Backup files may contain sensitive data or reveal application internals.`,
            affectedUrl: url,
            responseEvidence: bodyPreview.slice(0, 200),
            remediation: `Remove backup files from production servers. Block access to common backup extensions in web server configuration.`,
            confidenceScore: 80,
          })
        }

        // robots.txt (informational, always useful)
        if (path === '/robots.txt') {
          findings.push({
            type: 'INFORMATION_DISCLOSURE', owaspCategory: 'A05:2021 Security Misconfiguration',
            cweId: 'CWE-200', severity: 'INFO', riskScore: 5,
            title: 'robots.txt File Found',
            description: `${url} reveals paths that are disallowed for crawlers, which may indicate sensitive areas of the site.`,
            affectedUrl: url,
            responseEvidence: bodyPreview.slice(0, 300),
            remediation: 'Review robots.txt to ensure it does not reveal sensitive paths. robots.txt is not a security control.',
            confidenceScore: 100,
          })
        }
      }
    } catch { /* timeout or network error, skip */ }
  }
}
