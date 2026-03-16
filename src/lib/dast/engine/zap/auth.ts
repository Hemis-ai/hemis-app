import { ZapClient } from './zap-client'
import type { AuthConfig } from '../../types'

export async function configureAuth(client: ZapClient, contextId: string, authConfig: AuthConfig): Promise<void> {
  switch (authConfig.type) {
    case 'none': return
    case 'form': return configureFormAuth(client, contextId, authConfig)
    case 'bearer': return configureBearerAuth(client, authConfig.token)
    case 'apikey': return configureApiKeyAuth(client, authConfig.headerName, authConfig.value)
    case 'oauth2': return configureOAuth2Auth(client, authConfig)
    case 'cookie': return configureCookieAuth(client, authConfig)
    case 'header': return configureCustomHeaderAuth(client, authConfig.headers)
  }
}

export async function cleanupAuth(client: ZapClient, authConfig: AuthConfig): Promise<void> {
  try {
    switch (authConfig.type) {
      case 'bearer':
        await client.removeReplacerRule('hemisx-bearer-auth')
        break
      case 'apikey':
        await client.removeReplacerRule('hemisx-apikey-auth')
        break
      case 'oauth2':
        await client.removeReplacerRule('hemisx-oauth2-auth')
        break
      case 'cookie':
        await client.removeReplacerRule('hemisx-cookie-auth')
        break
      case 'header':
        for (const headerName of Object.keys(authConfig.headers)) {
          await client.removeReplacerRule(`hemisx-header-${headerName.toLowerCase()}`).catch(() => {})
        }
        break
    }
  } catch { /* cleanup is best-effort */ }
}

// ─── Session Management Configuration ────────────────────────────────────────

/**
 * Configure ZAP session management based on the auth type.
 * Called after auth is configured to ensure proper session handling.
 */
export async function configureSessionManagement(
  client: ZapClient,
  contextId: string,
  authConfig: AuthConfig,
  targetUrl: string,
): Promise<void> {
  try {
    const site = new URL(targetUrl).host

    switch (authConfig.type) {
      case 'form': {
        // Cookie-based session management (default for form auth)
        await client.setSessionManagementMethod(contextId, 'cookieBasedSessionManagement')
        // Add common session token names for tracking
        for (const tokenName of ['JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId', 'connect.sid', 'session', 'sid', '_session_id']) {
          await client.addSessionToken(site, tokenName).catch(() => {})
        }
        break
      }
      case 'cookie': {
        // Track the specific cookie as a session token
        await client.setSessionManagementMethod(contextId, 'cookieBasedSessionManagement')
        await client.addSessionToken(site, authConfig.cookieName).catch(() => {})
        break
      }
      case 'bearer':
      case 'oauth2':
      case 'apikey':
      case 'header': {
        // Header-based auth typically uses HTTP header session management
        await client.setSessionManagementMethod(contextId, 'httpAuthSessionManagement')
        break
      }
      default:
        break
    }
  } catch (error) {
    // Session management config is best-effort
    console.warn('Failed to configure session management:', error)
  }
}

// ─── Auth Handlers ───────────────────────────────────────────────────────────

async function configureFormAuth(client: ZapClient, contextId: string, auth: Extract<AuthConfig, { type: 'form' }>): Promise<void> {
  const loginRequestData = `${encodeURIComponent(auth.usernameField)}={%username%}&${encodeURIComponent(auth.passwordField)}={%password%}`
  const configParams = `loginUrl=${encodeURIComponent(auth.loginUrl)}&loginRequestData=${encodeURIComponent(loginRequestData)}`
  await client.setAuthenticationMethod(contextId, 'formBasedAuthentication', configParams)
  await client.setLoggedInIndicator(contextId, auth.loggedInPattern)
  const userId = await client.createUser(contextId, 'hemisx-scan-user')
  const credParams = `username=${encodeURIComponent(auth.username)}&password=${encodeURIComponent(auth.password)}`
  await client.setAuthCredentials(contextId, userId, credParams)
  await client.setUserEnabled(contextId, userId, true)
  await client.setForcedUser(contextId, userId)
  await client.setForcedUserModeEnabled(true)
}

async function configureBearerAuth(client: ZapClient, token: string): Promise<void> {
  await client.addReplacerRule('hemisx-bearer-auth', true, 'REQ_HEADER', false, 'Authorization', `Bearer ${token}`)
}

async function configureApiKeyAuth(client: ZapClient, headerName: string, value: string): Promise<void> {
  await client.addReplacerRule('hemisx-apikey-auth', true, 'REQ_HEADER', false, headerName, value)
}

/**
 * OAuth2 Client Credentials or Password Grant flow.
 * Fetches a token from the tokenUrl and injects it as a Bearer header.
 */
async function configureOAuth2Auth(client: ZapClient, auth: Extract<AuthConfig, { type: 'oauth2' }>): Promise<void> {
  const token = await fetchOAuth2Token(auth)
  await client.addReplacerRule('hemisx-oauth2-auth', true, 'REQ_HEADER', false, 'Authorization', `Bearer ${token}`)
}

/**
 * Fetch OAuth2 access token using client_credentials or password grant.
 */
async function fetchOAuth2Token(auth: Extract<AuthConfig, { type: 'oauth2' }>): Promise<string> {
  const grantType = auth.grantType || 'client_credentials'
  const body = new URLSearchParams({
    grant_type: grantType,
    client_id: auth.clientId,
    client_secret: auth.clientSecret,
  })

  if (auth.scope) body.set('scope', auth.scope)

  if (grantType === 'password') {
    if (!auth.username || !auth.password) {
      throw new Error('OAuth2 password grant requires username and password')
    }
    body.set('username', auth.username)
    body.set('password', auth.password)
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 15000)

  try {
    const response = await fetch(auth.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: controller.signal,
    })

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '')
      throw new Error(`OAuth2 token request failed (${response.status}): ${errorBody}`)
    }

    const data = await response.json() as { access_token?: string; token_type?: string }
    if (!data.access_token) {
      throw new Error('OAuth2 response missing access_token')
    }

    return data.access_token
  } finally {
    clearTimeout(timeout)
  }
}

/**
 * Cookie-based auth: injects a specific cookie into all requests via ZAP replacer.
 */
async function configureCookieAuth(client: ZapClient, auth: Extract<AuthConfig, { type: 'cookie' }>): Promise<void> {
  const cookieValue = `${auth.cookieName}=${auth.cookieValue}`
  await client.addReplacerRule('hemisx-cookie-auth', true, 'REQ_HEADER', false, 'Cookie', cookieValue)
}

/**
 * Custom header auth: injects arbitrary headers into all requests.
 */
async function configureCustomHeaderAuth(client: ZapClient, headers: Record<string, string>): Promise<void> {
  for (const [headerName, headerValue] of Object.entries(headers)) {
    const ruleName = `hemisx-header-${headerName.toLowerCase()}`
    await client.addReplacerRule(ruleName, true, 'REQ_HEADER', false, headerName, headerValue)
  }
}
