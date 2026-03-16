/**
 * Target URL validation and technology detection
 * Validates target URL reachability and fingerprints the tech stack,
 * probes for OpenAPI/Swagger specs and GraphQL endpoints.
 */

export interface TargetValidationResult {
  reachable: boolean
  url: string
  statusCode?: number
  responseTimeMs?: number
  serverHeader?: string
  error?: string
  // ── Tech detection (Phase 2) ──
  detectedTech: string[]
  apiSpecUrl: string | null
  apiSpecFormat: 'openapi3' | 'openapi2' | 'swagger' | null
  hasGraphql: boolean
  graphqlEndpoint: string | null
  tlsInfo?: { protocol?: string; cipher?: string }
}

/**
 * Validate a target URL: reachability, tech fingerprinting, and API detection.
 */
export async function validateTarget(url: string): Promise<TargetValidationResult> {
  const startTime = Date.now()
  const base: TargetValidationResult = {
    reachable: false,
    url,
    detectedTech: [],
    apiSpecUrl: null,
    apiSpecFormat: null,
    hasGraphql: false,
    graphqlEndpoint: null,
  }

  try {
    // Validate URL format
    const parsed = new URL(url)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { ...base, error: `Unsupported protocol: ${parsed.protocol}. Only http and https are supported.` }
    }

    // ── Step 1: Reachability check with full GET (need body for fingerprinting) ──
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 15000)

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'HemisX-DAST-Validator/2.0' },
    })
    clearTimeout(timeout)

    const responseTimeMs = Date.now() - startTime
    const body = await response.text().catch(() => '')
    const headers = response.headers

    // ── Step 2: Fingerprint technology from headers ──
    const detectedTech = detectTechFromHeaders(headers, body)

    // ── Step 3: Probe for API specs and GraphQL (parallel) ──
    const origin = parsed.origin
    const [apiSpec, graphql] = await Promise.all([
      probeApiSpec(origin),
      probeGraphql(origin),
    ])

    return {
      reachable: true,
      url,
      statusCode: response.status,
      responseTimeMs,
      serverHeader: headers.get('server') ?? undefined,
      detectedTech,
      apiSpecUrl: apiSpec?.url ?? null,
      apiSpecFormat: apiSpec?.format ?? null,
      hasGraphql: graphql.found,
      graphqlEndpoint: graphql.endpoint,
    }
  } catch (error) {
    const responseTimeMs = Date.now() - startTime
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    return { ...base, responseTimeMs, error: errorMessage }
  }
}

// ─── Technology Detection from Headers and Body ─────────────────────────────

/** Common header → technology mappings */
const HEADER_TECH_MAP: [string, string | RegExp, string][] = [
  ['x-powered-by', 'Express', 'Express.js'],
  ['x-powered-by', 'Next.js', 'Next.js'],
  ['x-powered-by', 'Nuxt', 'Nuxt.js'],
  ['x-powered-by', 'PHP', 'PHP'],
  ['x-powered-by', 'ASP.NET', 'ASP.NET'],
  ['x-powered-by', 'Servlet', 'Java Servlet'],
  ['x-powered-by', 'JSF', 'JavaServer Faces'],
  ['server', /nginx/i, 'nginx'],
  ['server', /apache/i, 'Apache'],
  ['server', /cloudflare/i, 'Cloudflare'],
  ['server', /Microsoft-IIS/i, 'IIS'],
  ['server', /gunicorn/i, 'Gunicorn (Python)'],
  ['server', /uvicorn/i, 'Uvicorn (Python)'],
  ['server', /Kestrel/i, 'Kestrel (.NET)'],
  ['server', /openresty/i, 'OpenResty'],
  ['server', /AmazonS3/i, 'Amazon S3'],
  ['x-aspnet-version', /.+/, 'ASP.NET'],
  ['x-aspnetmvc-version', /.+/, 'ASP.NET MVC'],
  ['x-drupal-cache', /.+/, 'Drupal'],
  ['x-generator', /WordPress/i, 'WordPress'],
  ['x-generator', /Drupal/i, 'Drupal'],
  ['x-generator', /Joomla/i, 'Joomla'],
  ['x-django-version', /.+/, 'Django'],
  ['x-rails-version', /.+/, 'Ruby on Rails'],
  ['x-runtime', /ruby/i, 'Ruby'],
  ['x-request-id', /.+/, ''], // Not a tech indicator, but common
  ['set-cookie', /laravel_session/i, 'Laravel'],
  ['set-cookie', /JSESSIONID/i, 'Java'],
  ['set-cookie', /ASP.NET_SessionId/i, 'ASP.NET'],
  ['set-cookie', /PHPSESSID/i, 'PHP'],
  ['set-cookie', /connect.sid/i, 'Express.js'],
  ['set-cookie', /_rails_session/i, 'Ruby on Rails'],
]

/** Body patterns for framework fingerprinting */
const BODY_PATTERNS: [RegExp, string][] = [
  [/\/_next\//i, 'Next.js'],
  [/__nuxt/i, 'Nuxt.js'],
  [/wp-content\//i, 'WordPress'],
  [/\/sites\/default\/files/i, 'Drupal'],
  [/<meta name="generator" content="WordPress/i, 'WordPress'],
  [/<meta name="generator" content="Joomla/i, 'Joomla'],
  [/react/i, 'React'],
  [/ng-app|ng-controller|angular/i, 'Angular'],
  [/vue\.js|v-bind|v-if/i, 'Vue.js'],
  [/ember/i, 'Ember.js'],
  [/swagger-ui/i, 'Swagger UI'],
  [/__vite_ping|@vite/i, 'Vite'],
  [/data-turbo|turbolinks/i, 'Hotwire/Turbolinks'],
  [/blazor/i, 'Blazor'],
  [/gatsby/i, 'Gatsby'],
  [/remix/i, 'Remix'],
  [/svelte/i, 'Svelte'],
]

function detectTechFromHeaders(headers: Headers, body: string): string[] {
  const detected = new Set<string>()

  // Check headers
  for (const [headerName, pattern, tech] of HEADER_TECH_MAP) {
    if (!tech) continue
    const value = headers.get(headerName)
    if (!value) continue
    if (typeof pattern === 'string') {
      if (value.includes(pattern)) detected.add(tech)
    } else {
      if (pattern.test(value)) detected.add(tech)
    }
  }

  // Check body (limit scan to first 50KB for performance)
  const bodySlice = body.slice(0, 50000)
  for (const [pattern, tech] of BODY_PATTERNS) {
    if (pattern.test(bodySlice)) detected.add(tech)
  }

  return Array.from(detected).sort()
}

// ─── API Spec Detection ─────────────────────────────────────────────────────

interface ApiSpecResult {
  url: string
  format: 'openapi3' | 'openapi2' | 'swagger'
}

/** Common paths where OpenAPI/Swagger specs are served */
const API_SPEC_PATHS = [
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
  '/swagger.yaml',
  '/api-docs',
  '/api-docs.json',
  '/v2/api-docs',
  '/v3/api-docs',
  '/api/swagger.json',
  '/api/openapi.json',
  '/docs/openapi.json',
  '/.well-known/openapi.json',
  '/api/v1/openapi.json',
  '/api/v2/openapi.json',
  '/api/v3/openapi.json',
]

async function probeApiSpec(origin: string): Promise<ApiSpecResult | null> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 8000)

  try {
    // Probe all common paths concurrently, return first valid hit
    const results = await Promise.allSettled(
      API_SPEC_PATHS.map(async (path): Promise<ApiSpecResult | null> => {
        try {
          const res = await fetch(`${origin}${path}`, {
            method: 'GET',
            signal: controller.signal,
            headers: { 'User-Agent': 'HemisX-DAST-Validator/2.0', 'Accept': 'application/json, application/yaml' },
          })

          if (!res.ok) return null

          const contentType = res.headers.get('content-type') || ''
          const body = await res.text()

          // Check if it looks like a valid OpenAPI/Swagger spec
          if (body.includes('"openapi"') || body.includes("openapi:")) {
            const isV3 = body.includes('"openapi": "3') || body.includes('openapi: "3') || body.includes("openapi: '3")
            return {
              url: `${origin}${path}`,
              format: isV3 ? 'openapi3' : 'openapi2',
            }
          }

          if (body.includes('"swagger"') || body.includes('swagger:')) {
            return { url: `${origin}${path}`, format: 'swagger' }
          }

          // JSON with "paths" key could be a spec
          if (contentType.includes('json') && body.includes('"paths"')) {
            return { url: `${origin}${path}`, format: 'openapi3' }
          }

          return null
        } catch {
          return null
        }
      })
    )

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        return result.value
      }
    }

    return null
  } finally {
    clearTimeout(timeout)
  }
}

// ─── GraphQL Detection ──────────────────────────────────────────────────────

interface GraphqlResult {
  found: boolean
  endpoint: string | null
}

const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/graphql/v1', '/gql', '/query']

async function probeGraphql(origin: string): Promise<GraphqlResult> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 6000)

  try {
    const results = await Promise.allSettled(
      GRAPHQL_PATHS.map(async (path): Promise<string | null> => {
        try {
          // Send a simple introspection query
          const res = await fetch(`${origin}${path}`, {
            method: 'POST',
            signal: controller.signal,
            headers: {
              'Content-Type': 'application/json',
              'User-Agent': 'HemisX-DAST-Validator/2.0',
            },
            body: JSON.stringify({ query: '{ __typename }' }),
          })

          if (!res.ok) return null

          const body = await res.text()
          // GraphQL responses have a "data" key
          if (body.includes('"data"') && (body.includes('__typename') || body.includes('"Query"'))) {
            return `${origin}${path}`
          }

          return null
        } catch {
          return null
        }
      })
    )

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        return { found: true, endpoint: result.value }
      }
    }

    return { found: false, endpoint: null }
  } finally {
    clearTimeout(timeout)
  }
}
