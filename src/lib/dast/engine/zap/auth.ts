import { ZapClient } from './zap-client'
import type { AuthConfig } from '../../types'

export async function configureAuth(client: ZapClient, contextId: string, authConfig: AuthConfig): Promise<void> {
  switch (authConfig.type) {
    case 'none': return
    case 'form': return configureFormAuth(client, contextId, authConfig)
    case 'bearer': return configureBearerAuth(client, authConfig.token)
    case 'apikey': return configureApiKeyAuth(client, authConfig.headerName, authConfig.value)
  }
}

export async function cleanupAuth(client: ZapClient, authConfig: AuthConfig): Promise<void> {
  try {
    if (authConfig.type === 'bearer') await client.removeReplacerRule('hemisx-bearer-auth')
    if (authConfig.type === 'apikey') await client.removeReplacerRule('hemisx-apikey-auth')
  } catch { /* cleanup is best-effort */ }
}

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
