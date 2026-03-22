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

  // Phase 4: Run security checks on all discovered pages (35-70%)
  const totalPages = crawled.length
  for (let i = 0; i < totalPages; i++) {
    const page = crawled[i]
    const percent = 35 + Math.round((i / totalPages) * 35)
    onProgress?.(percent, 'scanning', `Analyzing ${new URL(page.url).pathname} (${i + 1}/${totalPages})`)

    // Run all checks on this page
    checkSecurityHeaders(page, findings)
    checkCORS(page, findings)
    checkCookieSecurity(page, findings)
    checkInformationDisclosure(page, findings)
    checkClickjacking(page, findings)
    checkCacheHeaders(page, findings)
    checkCSPDetails(page, findings)
    checkSRI(page, findings)
    checkMixedContent(page, findings)
    checkDOMXSSHeuristic(page, findings)
    checkInfoDisclosureBody(page, findings)
  }

  // Phase 5: Active CORS test (70-73%)
  onProgress?.(70, 'scanning', 'Testing CORS with crafted Origin header...')
  await checkCORSActive(targetUrl, findings)

  // Phase 6: TLS check + cert details (73-77%)
  onProgress?.(73, 'scanning', 'Checking TLS/SSL configuration...')
  await checkTLS(targetUrl, findings)
  await checkTLSCertDetails(targetUrl, findings)

  // Phase 7: Backup file + VCS discovery (77-85%)
  onProgress?.(77, 'scanning', 'Probing for backup and sensitive files...')
  await checkBackupFiles(targetUrl, findings, (msg) => onProgress?.(80, 'scanning', msg))

  // Phase 8: HSTS check (85-86%)
  onProgress?.(85, 'scanning', 'Checking HSTS enforcement...')
  checkHSTS(crawled[0], findings)

  // Phase 9: Admin/debug endpoint probing (86-90%)
  onProgress?.(86, 'scanning', 'Probing for admin and debug endpoints...')
  await checkAdminDebugEndpoints(targetUrl, findings, (msg) => onProgress?.(88, 'scanning', msg))

  // Phase 10: HTTP methods enumeration (90-92%)
  onProgress?.(90, 'scanning', 'Enumerating HTTP methods...')
  await checkHTTPMethods(crawled.slice(0, 5), findings)

  // Phase 11: Open redirect test (92-94%)
  onProgress?.(92, 'scanning', 'Testing for open redirects...')
  await checkOpenRedirect(crawled, findings)

  // Phase 12: Verbose error detection (94-96%)
  onProgress?.(94, 'scanning', 'Testing for verbose errors...')
  await checkVerboseErrors(targetUrl, crawled, findings)

  // Phase 13: Prototype pollution (96-98%)
  onProgress?.(96, 'scanning', 'Testing for prototype pollution...')
  await checkPrototypePollution(targetUrl, findings)

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
    // Standard discovery
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
    // Environment and config files
    '/.env', '/.env.bak', '/.env.local', '/.env.production', '/.env.staging', '/.env.development',
    '/wp-config.php.bak', '/config.php.bak', '/web.config.bak', '/config.yml', '/config.json',
    '/application.yml', '/application.properties', '/appsettings.json',
    // Version control
    '/.git/config', '/.git/HEAD', '/.git/COMMIT_EDITMSG', '/.git/packed-refs', '/.git/refs/heads/main',
    '/.svn/wc.db', '/.svn/entries',
    '/.hg/hgrc', '/.hg/store/00manifest.i',
    // CI/CD
    '/.gitlab-ci.yml', '/.github/workflows/ci.yml', '/.circleci/config.yml',
    '/Jenkinsfile', '/Dockerfile', '/docker-compose.yml',
    // Database dumps
    '/backup.sql', '/dump.sql', '/database.sql', '/db.sql', '/data.sql',
    '/backup.tar.gz', '/backup.zip', '/site.tar.gz',
    // Server config
    '/.htaccess', '/.htaccess.bak', '/.htpasswd',
    '/server-status', '/server-info', '/phpinfo.php',
    '/nginx.conf', '/httpd.conf',
    // Backup and temp files
    '/robots.txt.bak', '/robots.txt.old', '/robots.copy',
    '/index.php.bak', '/index.html.bak', '/web.config.old',
    // Credentials and keys
    '/id_rsa', '/id_dsa', '/.ssh/authorized_keys',
    '/credentials.json', '/service-account.json',
    // Package files that leak dependencies
    '/package.json', '/composer.json', '/Gemfile', '/requirements.txt',
    '/package-lock.json', '/yarn.lock',
    // Error logs
    '/error.log', '/debug.log', '/access.log',
    '/wp-content/debug.log', '/storage/logs/laravel.log',
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

// ─── Phase 1A: Active CORS Origin Reflection ─────────────────────────────

async function checkCORSActive(targetUrl: string, findings: BuiltinFinding[]) {
  const evilOrigin = 'https://evil-attacker.com'
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 8000)
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)',
        'Origin': evilOrigin,
      },
    })
    clearTimeout(timer)

    const acao = res.headers.get('access-control-allow-origin')
    const acac = res.headers.get('access-control-allow-credentials')

    if (acao === evilOrigin) {
      findings.push({
        type: 'CORS_MISCONFIGURATION', owaspCategory: 'A05:2021 Security Misconfiguration',
        cweId: 'CWE-942', severity: acac === 'true' ? 'CRITICAL' : 'HIGH',
        cvssScore: acac === 'true' ? 9.1 : 7.5, riskScore: acac === 'true' ? 90 : 75,
        title: `CORS: Arbitrary Origin Actively Confirmed${acac === 'true' ? ' (with Credentials)' : ''}`,
        description: `${targetUrl} reflects the attacker-controlled origin "${evilOrigin}" in Access-Control-Allow-Origin. ${acac === 'true' ? 'Combined with Access-Control-Allow-Credentials: true, any malicious site can make fully authenticated cross-origin requests and steal user data.' : 'Any site can read cross-origin responses.'}`,
        affectedUrl: targetUrl,
        payload: `Origin: ${evilOrigin}`,
        requestEvidence: `GET ${targetUrl}\nOrigin: ${evilOrigin}`,
        responseEvidence: `Access-Control-Allow-Origin: ${acao}${acac ? `\nAccess-Control-Allow-Credentials: ${acac}` : ''}`,
        remediation: 'Validate the Origin header against a strict whitelist. Never reflect arbitrary origins. Remove Access-Control-Allow-Credentials when using permissive CORS.',
        confidenceScore: 98,
      })
    }

    // Also test null origin (can be triggered via sandboxed iframes)
    const controller2 = new AbortController()
    const timer2 = setTimeout(() => controller2.abort(), 8000)
    const res2 = await fetch(targetUrl, {
      signal: controller2.signal,
      headers: {
        'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)',
        'Origin': 'null',
      },
    })
    clearTimeout(timer2)

    const acao2 = res2.headers.get('access-control-allow-origin')
    if (acao2 === 'null') {
      findings.push({
        type: 'CORS_MISCONFIGURATION', owaspCategory: 'A05:2021 Security Misconfiguration',
        cweId: 'CWE-942', severity: 'HIGH', cvssScore: 7.5, riskScore: 70,
        title: 'CORS: Null Origin Allowed',
        description: `${targetUrl} allows the "null" origin. Attackers can exploit this via sandboxed iframes (sandbox="allow-scripts") to bypass CORS restrictions.`,
        affectedUrl: targetUrl,
        payload: 'Origin: null',
        requestEvidence: `GET ${targetUrl}\nOrigin: null`,
        responseEvidence: `Access-Control-Allow-Origin: null`,
        remediation: 'Do not whitelist the "null" origin. It can be easily spoofed via sandboxed iframes.',
        confidenceScore: 95,
      })
    }
  } catch { /* timeout */ }
}

// ─── Phase 1B: Subresource Integrity (SRI) Check ─────────────────────────

function checkSRI(page: CrawledPage, findings: BuiltinFinding[]) {
  const ct = page.headers['content-type'] || ''
  if (!ct.includes('text/html')) return

  const pageOrigin = new URL(page.url).origin

  // Find external scripts without integrity attribute
  const scriptRegex = /<script[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi
  let match
  while ((match = scriptRegex.exec(page.body)) !== null) {
    const src = match[1]
    const fullTag = match[0]
    try {
      const scriptUrl = new URL(src, page.url)
      if (scriptUrl.origin !== pageOrigin && !fullTag.toLowerCase().includes('integrity')) {
        findings.push({
          type: 'MISSING_SRI', owaspCategory: 'A08:2021 Software and Data Integrity Failures',
          cweId: 'CWE-353', severity: 'MEDIUM', cvssScore: 5.3, riskScore: 45,
          title: `Missing Subresource Integrity on External Script`,
          description: `${page.url} loads an external script from ${scriptUrl.origin} without an integrity attribute. If the CDN is compromised, attackers can inject malicious code.`,
          affectedUrl: page.url,
          affectedParameter: src,
          responseEvidence: fullTag.slice(0, 200),
          remediation: `Add integrity="sha384-..." and crossorigin="anonymous" attributes to the <script> tag loading ${src}.`,
          confidenceScore: 95,
        })
      }
    } catch { /* invalid URL */ }
  }

  // Find external stylesheets without integrity
  const linkRegex = /<link[^>]*\brel\s*=\s*["']stylesheet["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi
  while ((match = linkRegex.exec(page.body)) !== null) {
    const href = match[1]
    const fullTag = match[0]
    try {
      const linkUrl = new URL(href, page.url)
      if (linkUrl.origin !== pageOrigin && !fullTag.toLowerCase().includes('integrity')) {
        findings.push({
          type: 'MISSING_SRI', owaspCategory: 'A08:2021 Software and Data Integrity Failures',
          cweId: 'CWE-353', severity: 'LOW', cvssScore: 3.7, riskScore: 25,
          title: `Missing Subresource Integrity on External Stylesheet`,
          description: `${page.url} loads an external stylesheet from ${linkUrl.origin} without an integrity attribute. A compromised CDN could inject CSS-based attacks.`,
          affectedUrl: page.url,
          affectedParameter: href,
          responseEvidence: fullTag.slice(0, 200),
          remediation: `Add integrity="sha384-..." and crossorigin="anonymous" to the <link> tag loading ${href}.`,
          confidenceScore: 90,
        })
      }
    } catch { /* invalid URL */ }
  }
}

// ─── Phase 1C: Content Security Policy Analysis ──────────────────────────

function checkCSPDetails(page: CrawledPage, findings: BuiltinFinding[]) {
  const csp = page.headers['content-security-policy']
  if (!csp) return

  const ct = page.headers['content-type'] || ''
  if (!ct.includes('text/html')) return

  const directives = parseCSP(csp)

  const scriptSrc = directives['script-src'] || directives['default-src'] || ''

  if (scriptSrc.includes("'unsafe-inline'")) {
    findings.push({
      type: 'CSP_WEAKNESS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'HIGH', cvssScore: 6.1, riskScore: 60,
      title: "CSP Allows 'unsafe-inline' in script-src",
      description: `${page.url} CSP allows inline scripts via 'unsafe-inline'. This significantly weakens XSS protection as attackers can inject inline <script> tags.`,
      affectedUrl: page.url,
      responseEvidence: `Content-Security-Policy: ...script-src ${scriptSrc}...`,
      remediation: "Remove 'unsafe-inline' from script-src. Use nonces or hashes for inline scripts instead.",
      confidenceScore: 100,
    })
  }

  if (scriptSrc.includes("'unsafe-eval'")) {
    findings.push({
      type: 'CSP_WEAKNESS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'HIGH', cvssScore: 6.1, riskScore: 60,
      title: "CSP Allows 'unsafe-eval' in script-src",
      description: `${page.url} CSP allows eval() and related functions via 'unsafe-eval'. Attackers can execute arbitrary code through eval injection.`,
      affectedUrl: page.url,
      responseEvidence: `Content-Security-Policy: ...script-src ${scriptSrc}...`,
      remediation: "Remove 'unsafe-eval' from script-src. Refactor code to avoid eval(), new Function(), and setTimeout/setInterval with strings.",
      confidenceScore: 100,
    })
  }

  if (/(?:^|\s)\*(?:\s|$)/.test(scriptSrc) || scriptSrc.includes('https:') || scriptSrc.includes('http:')) {
    findings.push({
      type: 'CSP_WEAKNESS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'HIGH', cvssScore: 6.1, riskScore: 55,
      title: 'CSP script-src Has Overly Broad Source',
      description: `${page.url} CSP script-src allows scripts from overly broad sources (wildcard, https:, or http:). Attackers can host payloads on any domain and bypass CSP.`,
      affectedUrl: page.url,
      responseEvidence: `Content-Security-Policy: ...script-src ${scriptSrc}...`,
      remediation: "Restrict script-src to specific trusted domains. Avoid wildcards and protocol-only sources.",
      confidenceScore: 95,
    })
  }

  // Check for missing default-src
  if (!directives['default-src']) {
    findings.push({
      type: 'CSP_WEAKNESS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'MEDIUM', cvssScore: 5.3, riskScore: 40,
      title: 'CSP Missing default-src Directive',
      description: `${page.url} CSP does not define a default-src fallback. Resource types not explicitly covered by other directives are unrestricted.`,
      affectedUrl: page.url,
      responseEvidence: `Content-Security-Policy: ${csp.slice(0, 200)}`,
      remediation: "Add default-src 'self' as the first directive in your CSP.",
      confidenceScore: 90,
    })
  }

  // Check for data: in script-src (allows XSS via data: URIs)
  if (scriptSrc.includes('data:')) {
    findings.push({
      type: 'CSP_WEAKNESS', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-693', severity: 'HIGH', cvssScore: 6.1, riskScore: 60,
      title: "CSP Allows data: URI in script-src",
      description: `${page.url} CSP allows data: URIs in script-src. Attackers can use data:text/javascript,... to inject scripts bypassing CSP.`,
      affectedUrl: page.url,
      responseEvidence: `Content-Security-Policy: ...script-src ${scriptSrc}...`,
      remediation: "Remove 'data:' from script-src. Use nonces or hashes for inline content.",
      confidenceScore: 100,
    })
  }
}

function parseCSP(csp: string): Record<string, string> {
  const directives: Record<string, string> = {}
  for (const part of csp.split(';')) {
    const trimmed = part.trim()
    const spaceIdx = trimmed.indexOf(' ')
    if (spaceIdx > 0) {
      directives[trimmed.slice(0, spaceIdx)] = trimmed.slice(spaceIdx + 1)
    }
  }
  return directives
}

// ─── Phase 1D: Information Disclosure in Response Body ───────────────────

function checkInfoDisclosureBody(page: CrawledPage, findings: BuiltinFinding[]) {
  const body = page.body

  // AWS Access Key IDs
  const awsKeyMatch = body.match(/AKIA[A-Z0-9]{16}/)
  if (awsKeyMatch) {
    findings.push({
      type: 'SECRET_EXPOSURE', owaspCategory: 'A01:2021 Broken Access Control',
      cweId: 'CWE-798', severity: 'CRITICAL', cvssScore: 9.8, riskScore: 95,
      title: 'AWS Access Key Exposed in Response',
      description: `${page.url} contains what appears to be an AWS Access Key ID (${awsKeyMatch[0].slice(0, 8)}...). This could allow unauthorized access to AWS resources.`,
      affectedUrl: page.url,
      responseEvidence: `Found: ${awsKeyMatch[0].slice(0, 8)}...`,
      remediation: 'Immediately rotate the exposed AWS credentials. Remove hardcoded keys from source code and use IAM roles or environment variables.',
      confidenceScore: 90,
    })
  }

  // Generic API keys (sk-... pattern used by OpenAI, Stripe, etc.)
  const apiKeyMatch = body.match(/(?:sk|pk)[-_](?:live|test|prod)?[-_]?[a-zA-Z0-9]{20,}/)
  if (apiKeyMatch) {
    findings.push({
      type: 'SECRET_EXPOSURE', owaspCategory: 'A01:2021 Broken Access Control',
      cweId: 'CWE-798', severity: 'HIGH', cvssScore: 8.6, riskScore: 80,
      title: 'API Key/Secret Exposed in Response',
      description: `${page.url} contains what appears to be an API key or secret token (${apiKeyMatch[0].slice(0, 10)}...). This could allow unauthorized API access.`,
      affectedUrl: page.url,
      responseEvidence: `Found: ${apiKeyMatch[0].slice(0, 10)}...`,
      remediation: 'Rotate the exposed API key immediately. Never embed secrets in client-facing responses.',
      confidenceScore: 75,
    })
  }

  // Private IP addresses
  const privateIPs = body.match(/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g)
  if (privateIPs && privateIPs.length > 0) {
    const uniqueIPs = [...new Set(privateIPs)]
    findings.push({
      type: 'INFORMATION_DISCLOSURE', owaspCategory: 'A05:2021 Security Misconfiguration',
      cweId: 'CWE-200', severity: 'LOW', riskScore: 20,
      title: 'Private IP Address Disclosed in Response',
      description: `${page.url} reveals internal/private IP address(es): ${uniqueIPs.join(', ')}. This may help attackers map internal network infrastructure.`,
      affectedUrl: page.url,
      responseEvidence: `Private IPs found: ${uniqueIPs.join(', ')}`,
      remediation: 'Remove internal IP addresses from responses. Use reverse proxies to strip internal headers.',
      confidenceScore: 70,
    })
  }

  // Stack traces
  const stackTracePatterns = [
    /at\s+\w+\s*\((?:\/|\\|\w:)[^)]+:\d+:\d+\)/,  // Node.js: at Function (/path:line:col)
    /Traceback\s*\(most recent call last\)/,          // Python
    /Exception in thread/,                            // Java
    /Fatal error:.*on line \d+/,                      // PHP
    /System\.(?:NullReference|ArgumentNull|InvalidOperation)Exception/,  // .NET
  ]
  for (const pattern of stackTracePatterns) {
    if (pattern.test(body)) {
      findings.push({
        type: 'INFORMATION_DISCLOSURE', owaspCategory: 'A05:2021 Security Misconfiguration',
        cweId: 'CWE-209', severity: 'MEDIUM', cvssScore: 5.3, riskScore: 45,
        title: 'Stack Trace Exposed in Response',
        description: `${page.url} contains a stack trace or error dump. This reveals internal file paths, line numbers, and potentially sensitive implementation details.`,
        affectedUrl: page.url,
        remediation: 'Configure error handling to show generic error messages in production. Log detailed errors server-side only.',
        confidenceScore: 85,
      })
      break // One finding per page is enough
    }
  }

  // Email addresses (only if many — a contact email is fine)
  const emails = body.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g)
  if (emails && emails.length >= 5) {
    const uniqueEmails = [...new Set(emails)]
    findings.push({
      type: 'INFORMATION_DISCLOSURE', owaspCategory: 'A01:2021 Broken Access Control',
      cweId: 'CWE-200', severity: 'LOW', riskScore: 20,
      title: 'Multiple Email Addresses Exposed in Response',
      description: `${page.url} contains ${uniqueEmails.length} email addresses. Mass email exposure can lead to phishing and social engineering attacks.`,
      affectedUrl: page.url,
      responseEvidence: `Found ${uniqueEmails.length} emails: ${uniqueEmails.slice(0, 3).join(', ')}...`,
      remediation: 'Review whether all exposed emails are necessary. Obfuscate or remove internal email addresses from public responses.',
      confidenceScore: 65,
    })
  }
}

// ─── Phase 1E: Verbose Error Detection ───────────────────────────────────

async function checkVerboseErrors(targetUrl: string, crawled: CrawledPage[], findings: BuiltinFinding[]) {
  // Test 1: Append SQL-like character to trigger errors
  const errorProbes = [
    { suffix: "'", desc: 'single quote (SQL error trigger)' },
    { suffix: '/<script>', desc: 'XSS probe in path' },
    { suffix: '/../../etc/passwd', desc: 'path traversal probe' },
  ]

  for (const probe of errorProbes) {
    try {
      const testUrl = targetUrl.replace(/\/?$/, probe.suffix)
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 5000)
      const res = await fetch(testUrl, {
        signal: controller.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)' },
      })
      clearTimeout(timer)

      const body = await res.text()
      const errorIndicators = [
        { pattern: /SQL syntax.*MySQL/i, tech: 'MySQL', sev: 'HIGH' as const },
        { pattern: /Microsoft OLE DB Provider/i, tech: 'MSSQL', sev: 'HIGH' as const },
        { pattern: /PostgreSQL.*ERROR/i, tech: 'PostgreSQL', sev: 'HIGH' as const },
        { pattern: /ORA-\d{5}/, tech: 'Oracle DB', sev: 'HIGH' as const },
        { pattern: /Warning:.*\bPHP\b/i, tech: 'PHP', sev: 'MEDIUM' as const },
        { pattern: /at\s+\w+\.java:\d+/, tech: 'Java', sev: 'MEDIUM' as const },
        { pattern: /Microsoft \.NET Framework/i, tech: '.NET', sev: 'MEDIUM' as const },
        { pattern: /Django.*Traceback/i, tech: 'Django', sev: 'MEDIUM' as const },
        { pattern: /Rails.*Error/i, tech: 'Rails', sev: 'MEDIUM' as const },
      ]

      for (const indicator of errorIndicators) {
        if (indicator.pattern.test(body)) {
          findings.push({
            type: 'VERBOSE_ERROR', owaspCategory: 'A05:2021 Security Misconfiguration',
            cweId: 'CWE-209', severity: indicator.sev, cvssScore: indicator.sev === 'HIGH' ? 7.5 : 5.3,
            riskScore: indicator.sev === 'HIGH' ? 70 : 45,
            title: `Verbose ${indicator.tech} Error Message Triggered`,
            description: `Sending ${probe.desc} to ${testUrl} triggered a detailed ${indicator.tech} error response. This reveals internal technology, file paths, and potentially database structure to attackers.`,
            affectedUrl: testUrl,
            payload: probe.suffix,
            requestEvidence: `GET ${testUrl}`,
            remediation: 'Configure custom error pages for production. Disable detailed error output. Log errors server-side only.',
            confidenceScore: 90,
          })
          break
        }
      }
    } catch { /* timeout or error, skip */ }
  }
}

// ─── Phase 1F: Mixed Content Detection ───────────────────────────────────

function checkMixedContent(page: CrawledPage, findings: BuiltinFinding[]) {
  if (!page.url.startsWith('https://')) return

  const ct = page.headers['content-type'] || ''
  if (!ct.includes('text/html')) return

  // Look for http:// references in src and href attributes
  const httpRefs = page.body.match(/(?:src|action)\s*=\s*["']http:\/\/[^"']+["']/gi)
  if (httpRefs && httpRefs.length > 0) {
    const uniqueRefs = [...new Set(httpRefs.map(r => {
      const m = r.match(/["'](http:\/\/[^"']+)["']/)
      return m ? m[1] : r
    }))]
    findings.push({
      type: 'MIXED_CONTENT', owaspCategory: 'A02:2021 Cryptographic Failures',
      cweId: 'CWE-311', severity: 'MEDIUM', cvssScore: 4.8, riskScore: 40,
      title: 'Mixed Content: HTTPS Page Loads HTTP Resources',
      description: `${page.url} (HTTPS) loads resources over insecure HTTP. This allows man-in-the-middle attackers to inject malicious content via the unencrypted resources.`,
      affectedUrl: page.url,
      responseEvidence: `HTTP resources found: ${uniqueRefs.slice(0, 3).join(', ')}${uniqueRefs.length > 3 ? ` (+${uniqueRefs.length - 3} more)` : ''}`,
      remediation: 'Update all resource URLs to use HTTPS. Use protocol-relative URLs or Content-Security-Policy: upgrade-insecure-requests.',
      confidenceScore: 90,
    })
  }
}

// ─── Phase 1G: Open Redirect Test ────────────────────────────────────────

async function checkOpenRedirect(crawled: CrawledPage[], findings: BuiltinFinding[]) {
  const redirectParams = ['redirect', 'url', 'next', 'return', 'returnUrl', 'return_url', 'goto', 'target', 'redir', 'destination', 'continue']
  const evilUrl = 'https://evil-attacker.com/phish'

  // Find URLs with redirect-like parameters in crawled pages
  const testedParams = new Set<string>()
  for (const page of crawled) {
    for (const link of page.links) {
      try {
        const parsed = new URL(link)
        for (const param of redirectParams) {
          if (parsed.searchParams.has(param) && !testedParams.has(`${parsed.pathname}:${param}`)) {
            testedParams.add(`${parsed.pathname}:${param}`)

            // Replace the param value with our evil URL
            parsed.searchParams.set(param, evilUrl)
            const testUrl = parsed.href

            const controller = new AbortController()
            const timer = setTimeout(() => controller.abort(), 5000)
            const res = await fetch(testUrl, {
              signal: controller.signal,
              redirect: 'manual', // Don't follow — check the Location header
              headers: { 'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)' },
            })
            clearTimeout(timer)

            if (res.status >= 300 && res.status < 400) {
              const location = res.headers.get('location') || ''
              if (location.includes('evil-attacker.com')) {
                findings.push({
                  type: 'OPEN_REDIRECT', owaspCategory: 'A01:2021 Broken Access Control',
                  cweId: 'CWE-601', severity: 'HIGH', cvssScore: 6.1, riskScore: 60,
                  title: `Open Redirect via "${param}" Parameter`,
                  description: `${parsed.pathname} redirects to an attacker-controlled URL when the "${param}" parameter is set to an external domain. This can be abused for phishing attacks.`,
                  affectedUrl: link,
                  affectedParameter: param,
                  payload: evilUrl,
                  requestEvidence: `GET ${testUrl}`,
                  responseEvidence: `HTTP ${res.status}\nLocation: ${location}`,
                  remediation: `Validate redirect URLs against a whitelist of allowed domains. Use relative paths for redirects. Never redirect to user-supplied external URLs.`,
                  confidenceScore: 95,
                })
              }
            }
          }
        }
      } catch { /* invalid URL */ }
    }
  }
}

// ─── Phase 1H: Prototype Pollution ───────────────────────────────────────

async function checkPrototypePollution(targetUrl: string, findings: BuiltinFinding[]) {
  const payloads = [
    '__proto__[polluted]=hemis_test',
    'constructor[prototype][polluted]=hemis_test',
    '__proto__.polluted=hemis_test',
  ]

  for (const payload of payloads) {
    try {
      const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${payload}`
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 5000)
      const res = await fetch(testUrl, {
        signal: controller.signal,
        headers: { 'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)' },
      })
      clearTimeout(timer)

      const body = await res.text()
      // Check if our pollution value appears in the response (indicating server-side pollution)
      if (body.includes('hemis_test') && !body.includes('__proto__')) {
        findings.push({
          type: 'PROTOTYPE_POLLUTION', owaspCategory: 'A03:2021 Injection',
          cweId: 'CWE-1321', severity: 'HIGH', cvssScore: 7.3, riskScore: 70,
          title: 'Server-Side Prototype Pollution Detected',
          description: `${targetUrl} appears vulnerable to prototype pollution. Injecting "${payload}" caused the pollution value to appear in the response, indicating the server merged user input into object prototypes.`,
          affectedUrl: targetUrl,
          payload: payload,
          requestEvidence: `GET ${testUrl}`,
          responseEvidence: 'Pollution value "hemis_test" reflected in response',
          remediation: 'Sanitize user input before merging into objects. Use Object.create(null) for lookups. Avoid recursive object merging with user-controlled data.',
          confidenceScore: 80,
        })
        break // One finding is enough
      }
    } catch { /* timeout */ }
  }
}

// ─── Phase 1I: Admin/Debug Endpoint Probing ──────────────────────────────

async function checkAdminDebugEndpoints(targetUrl: string, findings: BuiltinFinding[], onProgress?: (msg: string) => void) {
  const endpoints = [
    // Admin panels
    { path: '/admin', severity: 'HIGH' as const, category: 'admin' },
    { path: '/admin/', severity: 'HIGH' as const, category: 'admin' },
    { path: '/administrator', severity: 'HIGH' as const, category: 'admin' },
    { path: '/wp-admin/', severity: 'HIGH' as const, category: 'admin' },
    { path: '/cpanel', severity: 'HIGH' as const, category: 'admin' },
    { path: '/phpmyadmin', severity: 'HIGH' as const, category: 'admin' },
    { path: '/phpMyAdmin', severity: 'HIGH' as const, category: 'admin' },
    { path: '/adminer.php', severity: 'HIGH' as const, category: 'admin' },
    // Debug/diagnostic
    { path: '/debug', severity: 'HIGH' as const, category: 'debug' },
    { path: '/console', severity: 'HIGH' as const, category: 'debug' },
    { path: '/_debug', severity: 'HIGH' as const, category: 'debug' },
    { path: '/_profiler', severity: 'HIGH' as const, category: 'debug' },
    { path: '/trace', severity: 'HIGH' as const, category: 'debug' },
    { path: '/elmah.axd', severity: 'HIGH' as const, category: 'debug' },
    // Spring Boot Actuator
    { path: '/actuator', severity: 'HIGH' as const, category: 'actuator' },
    { path: '/actuator/health', severity: 'MEDIUM' as const, category: 'actuator' },
    { path: '/actuator/env', severity: 'CRITICAL' as const, category: 'actuator' },
    { path: '/actuator/configprops', severity: 'CRITICAL' as const, category: 'actuator' },
    { path: '/actuator/heapdump', severity: 'CRITICAL' as const, category: 'actuator' },
    // GraphQL
    { path: '/graphql', severity: 'INFO' as const, category: 'api' },
    { path: '/graphiql', severity: 'MEDIUM' as const, category: 'api' },
    { path: '/playground', severity: 'MEDIUM' as const, category: 'api' },
    // API docs
    { path: '/swagger-ui.html', severity: 'MEDIUM' as const, category: 'api' },
    { path: '/swagger.json', severity: 'MEDIUM' as const, category: 'api' },
    { path: '/openapi.json', severity: 'MEDIUM' as const, category: 'api' },
    { path: '/api-docs', severity: 'MEDIUM' as const, category: 'api' },
    // Well-known
    { path: '/.well-known/jwks.json', severity: 'INFO' as const, category: 'wellknown' },
    { path: '/.well-known/openid-configuration', severity: 'INFO' as const, category: 'wellknown' },
  ]

  for (const ep of endpoints) {
    onProgress?.(`Probing ${ep.path}...`)
    try {
      const url = new URL(ep.path, targetUrl).href
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 5000)
      const res = await fetch(url, {
        signal: controller.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)' },
      })
      clearTimeout(timer)

      if (res.status === 200) {
        const body = await res.text()
        // Skip if it's clearly a custom 404 or generic page (check for common 404 indicators)
        if (body.length < 50) continue
        const lower = body.toLowerCase()
        if (lower.includes('not found') || lower.includes('404') || lower.includes('page not found')) continue

        const titles: Record<string, string> = {
          admin: `Admin Panel Accessible: ${ep.path}`,
          debug: `Debug Endpoint Exposed: ${ep.path}`,
          actuator: `Spring Boot Actuator Exposed: ${ep.path}`,
          api: `API Documentation/Playground Accessible: ${ep.path}`,
          wellknown: `Well-Known Endpoint Accessible: ${ep.path}`,
        }

        const descriptions: Record<string, string> = {
          admin: `An administrative panel at ${url} is publicly accessible. This may allow unauthorized access to site administration functions.`,
          debug: `A debug/diagnostic endpoint at ${url} is publicly accessible. Debug endpoints often expose sensitive application state, environment variables, or allow code execution.`,
          actuator: `A Spring Boot Actuator endpoint at ${url} is publicly accessible. ${ep.severity === 'CRITICAL' ? 'This endpoint may expose environment variables, credentials, or heap dumps containing sensitive data.' : 'This reveals application health and configuration information.'}`,
          api: `API documentation or interactive playground at ${url} is publicly accessible. This reveals API structure, endpoints, and may allow unauthorized API testing.`,
          wellknown: `The endpoint ${url} is accessible and provides OAuth/OIDC configuration information. This is informational and may reveal token endpoints and supported flows.`,
        }

        findings.push({
          type: 'EXPOSED_ENDPOINT', owaspCategory: 'A01:2021 Broken Access Control',
          cweId: ep.category === 'actuator' ? 'CWE-215' : 'CWE-284',
          severity: ep.severity, cvssScore: ep.severity === 'CRITICAL' ? 9.1 : ep.severity === 'HIGH' ? 7.5 : 5.3,
          riskScore: ep.severity === 'CRITICAL' ? 90 : ep.severity === 'HIGH' ? 70 : ep.severity === 'MEDIUM' ? 45 : 15,
          title: titles[ep.category] || `Endpoint Found: ${ep.path}`,
          description: descriptions[ep.category] || `${url} is publicly accessible.`,
          affectedUrl: url,
          responseEvidence: `HTTP 200 OK (${body.length} bytes)`,
          remediation: ep.category === 'wellknown'
            ? 'Ensure only necessary claims and scopes are exposed in OIDC configuration.'
            : `Restrict access to ${ep.path} via authentication, IP whitelisting, or firewall rules. Remove debug/admin endpoints from production.`,
          confidenceScore: ep.category === 'wellknown' ? 100 : 75,
        })
      }
    } catch { /* timeout */ }
  }
}

// ─── Phase 1J: TLS Certificate Details ───────────────────────────────────

async function checkTLSCertDetails(targetUrl: string, findings: BuiltinFinding[]) {
  if (!targetUrl.startsWith('https://')) return

  try {
    // Use Node.js https module to inspect the certificate
    const https = await import('https')
    const url = new URL(targetUrl)

    const certInfo = await new Promise<{
      subject: string
      issuer: string
      validFrom: string
      validTo: string
      protocol: string
    } | null>((resolve) => {
      const req = https.request({
        hostname: url.hostname,
        port: url.port || 443,
        path: '/',
        method: 'HEAD',
        rejectUnauthorized: false, // Accept all certs to inspect them
        timeout: 8000,
      }, (res) => {
        const socket = res.socket as import('tls').TLSSocket
        if (socket.getPeerCertificate) {
          const cert = socket.getPeerCertificate()
          const protocol = socket.getProtocol?.() || 'unknown'
          const cn = cert.subject?.CN
          const issuerO = cert.issuer?.O
          const issuerCN = cert.issuer?.CN
          resolve({
            subject: (Array.isArray(cn) ? cn[0] : cn) || 'unknown',
            issuer: (Array.isArray(issuerO) ? issuerO[0] : issuerO) || (Array.isArray(issuerCN) ? issuerCN[0] : issuerCN) || 'unknown',
            validFrom: cert.valid_from || 'unknown',
            validTo: cert.valid_to || 'unknown',
            protocol,
          })
        } else {
          resolve(null)
        }
        res.resume()
      })
      req.on('error', () => resolve(null))
      req.on('timeout', () => { req.destroy(); resolve(null) })
      req.end()
    })

    if (!certInfo) return

    // Informational: Report cert details
    findings.push({
      type: 'TLS_CERTIFICATE_INFO', owaspCategory: 'A02:2021 Cryptographic Failures',
      cweId: 'CWE-295', severity: 'INFO', riskScore: 5,
      title: 'TLS Certificate Details',
      description: `Certificate for ${url.hostname}: Subject=${certInfo.subject}, Issuer=${certInfo.issuer}, Valid=${certInfo.validFrom} to ${certInfo.validTo}, Protocol=${certInfo.protocol}`,
      affectedUrl: targetUrl,
      responseEvidence: `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nValid From: ${certInfo.validFrom}\nValid To: ${certInfo.validTo}\nProtocol: ${certInfo.protocol}`,
      remediation: 'Ensure TLS certificates are renewed before expiration and use strong ciphers.',
      confidenceScore: 100,
    })

    // Check expiry
    const expiryDate = new Date(certInfo.validTo)
    const now = new Date()
    const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))

    if (daysUntilExpiry < 0) {
      findings.push({
        type: 'TLS_CONFIGURATION', owaspCategory: 'A02:2021 Cryptographic Failures',
        cweId: 'CWE-295', severity: 'CRITICAL', cvssScore: 9.1, riskScore: 90,
        title: 'TLS Certificate Has Expired',
        description: `The TLS certificate for ${url.hostname} expired on ${certInfo.validTo} (${Math.abs(daysUntilExpiry)} days ago). Browsers will show security warnings and users may be vulnerable to MITM attacks.`,
        affectedUrl: targetUrl,
        responseEvidence: `Certificate expired: ${certInfo.validTo}`,
        remediation: 'Immediately renew the TLS certificate. Set up automated renewal (e.g., Let\'s Encrypt with certbot).',
        confidenceScore: 100,
      })
    } else if (daysUntilExpiry <= 30) {
      findings.push({
        type: 'TLS_CONFIGURATION', owaspCategory: 'A02:2021 Cryptographic Failures',
        cweId: 'CWE-295', severity: 'HIGH', cvssScore: 7.4, riskScore: 65,
        title: `TLS Certificate Expires in ${daysUntilExpiry} Days`,
        description: `The TLS certificate for ${url.hostname} expires on ${certInfo.validTo} (${daysUntilExpiry} days from now). Urgent renewal needed to avoid service disruption.`,
        affectedUrl: targetUrl,
        responseEvidence: `Certificate valid until: ${certInfo.validTo}`,
        remediation: 'Renew the TLS certificate immediately. Set up automated renewal to prevent future expirations.',
        confidenceScore: 100,
      })
    } else if (daysUntilExpiry <= 90) {
      findings.push({
        type: 'TLS_CONFIGURATION', owaspCategory: 'A02:2021 Cryptographic Failures',
        cweId: 'CWE-295', severity: 'MEDIUM', cvssScore: 5.3, riskScore: 40,
        title: `TLS Certificate Expires in ${daysUntilExpiry} Days`,
        description: `The TLS certificate for ${url.hostname} expires on ${certInfo.validTo} (${daysUntilExpiry} days from now). Plan renewal soon.`,
        affectedUrl: targetUrl,
        responseEvidence: `Certificate valid until: ${certInfo.validTo}`,
        remediation: 'Schedule TLS certificate renewal. Consider automated renewal with Let\'s Encrypt.',
        confidenceScore: 100,
      })
    }

    // Check for weak protocol
    if (certInfo.protocol === 'TLSv1' || certInfo.protocol === 'TLSv1.1') {
      findings.push({
        type: 'TLS_CONFIGURATION', owaspCategory: 'A02:2021 Cryptographic Failures',
        cweId: 'CWE-326', severity: 'HIGH', cvssScore: 7.4, riskScore: 65,
        title: `Outdated TLS Protocol: ${certInfo.protocol}`,
        description: `${url.hostname} uses ${certInfo.protocol}, which is deprecated and has known vulnerabilities (POODLE, BEAST). Modern browsers are dropping support.`,
        affectedUrl: targetUrl,
        responseEvidence: `Negotiated protocol: ${certInfo.protocol}`,
        remediation: 'Disable TLS 1.0 and 1.1. Enable only TLS 1.2 and TLS 1.3.',
        confidenceScore: 100,
      })
    }
  } catch { /* HTTPS module not available in all runtimes */ }
}

// ─── Phase 1K: HTTP Methods Enumeration ──────────────────────────────────

async function checkHTTPMethods(pages: CrawledPage[], findings: BuiltinFinding[]) {
  const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
  const tested = new Set<string>()

  for (const page of pages) {
    const url = page.url
    if (tested.has(url)) continue
    tested.add(url)

    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 5000)
      const res = await fetch(url, {
        method: 'OPTIONS',
        signal: controller.signal,
        headers: { 'User-Agent': 'HemisX-DAST-Scanner/1.0 (Security Audit)' },
      })
      clearTimeout(timer)

      const allow = res.headers.get('allow')
      if (!allow) continue

      const methods = allow.split(',').map(m => m.trim().toUpperCase())
      const dangerous = methods.filter(m => dangerousMethods.includes(m))

      if (dangerous.length > 0) {
        const isTrace = dangerous.includes('TRACE')
        findings.push({
          type: 'HTTP_METHODS', owaspCategory: 'A05:2021 Security Misconfiguration',
          cweId: isTrace ? 'CWE-693' : 'CWE-749',
          severity: isTrace ? 'MEDIUM' : 'LOW',
          cvssScore: isTrace ? 5.3 : 3.7,
          riskScore: isTrace ? 45 : 20,
          title: `Dangerous HTTP Methods Enabled: ${dangerous.join(', ')}`,
          description: `${url} allows HTTP methods: ${dangerous.join(', ')}. ${isTrace ? 'TRACE method enables Cross-Site Tracing (XST) attacks that can steal credentials.' : 'Unnecessary methods increase the attack surface.'}`,
          affectedUrl: url,
          responseEvidence: `Allow: ${allow}`,
          remediation: `Disable unnecessary HTTP methods. ${isTrace ? 'Disable TRACE method to prevent XST attacks.' : 'Only allow GET, POST, HEAD, and OPTIONS as needed.'}`,
          confidenceScore: 85,
        })
      }
    } catch { /* timeout */ }
  }
}

// ─── Phase 1N: DOM-Based XSS Heuristic ──────────────────────────────────

function checkDOMXSSHeuristic(page: CrawledPage, findings: BuiltinFinding[]) {
  const ct = page.headers['content-type'] || ''
  if (!ct.includes('text/html') && !ct.includes('javascript')) return

  const sources = [
    'location.hash', 'location.search', 'location.href', 'location.pathname',
    'document.referrer', 'document.URL', 'document.documentURI',
    'window.name', 'URLSearchParams',
    'document.cookie', // can be a source if attacker-controlled
  ]

  const sinks = [
    'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
    'insertAdjacentHTML', '.html(', // jQuery
    'eval(', 'setTimeout(', 'setInterval(', 'new Function(',
    'window.location', 'location.assign', 'location.replace',
    'element.src', 'element.href', 'element.action',
  ]

  const body = page.body
  const foundSources: string[] = []
  const foundSinks: string[] = []

  for (const src of sources) {
    if (body.includes(src)) foundSources.push(src)
  }
  for (const sink of sinks) {
    if (body.includes(sink)) foundSinks.push(sink)
  }

  // Only report if both sources AND sinks are present (indicating potential dataflow)
  if (foundSources.length > 0 && foundSinks.length > 0) {
    findings.push({
      type: 'DOM_XSS', owaspCategory: 'A03:2021 Injection',
      cweId: 'CWE-79', severity: 'MEDIUM', cvssScore: 6.1, riskScore: 50,
      title: 'Potential DOM-Based XSS (Source + Sink Detected)',
      description: `${page.url} contains JavaScript with both user-controllable sources (${foundSources.slice(0, 3).join(', ')}) and dangerous sinks (${foundSinks.slice(0, 3).join(', ')}). If data flows from source to sink without sanitization, DOM XSS is possible.`,
      affectedUrl: page.url,
      responseEvidence: `Sources: ${foundSources.join(', ')}\nSinks: ${foundSinks.join(', ')}`,
      remediation: 'Sanitize all user-controllable inputs before passing to DOM manipulation functions. Use textContent instead of innerHTML. Avoid eval() and document.write().',
      confidenceScore: 55, // Heuristic — needs manual confirmation
      businessImpact: 'DOM XSS allows attackers to execute JavaScript in the victim\'s browser, potentially stealing session tokens, credentials, or performing actions on behalf of the user.',
    })
  }
}
