import type {
  ZapResultResponse, ZapSpiderStartResponse, ZapSpiderStatusResponse,
  ZapSpiderResultsResponse, ZapAjaxSpiderStatusResponse,
  ZapActiveScanStartResponse, ZapActiveScanStatusResponse,
  ZapAlertsResponse, ZapContextCreateResponse, ZapNewUserResponse,
  ZapVersionResponse, AttackStrength, AlertThreshold,
} from '../../types'

export class ZapApiError extends Error {
  public readonly operation: string
  public override readonly cause?: unknown
  constructor(operation: string, message: string, cause?: unknown) {
    super(`ZAP API error in ${operation}: ${message}`)
    this.name = 'ZapApiError'
    this.operation = operation
    this.cause = cause
  }
}

/**
 * ZAP REST API client — uses native fetch (no axios dependency).
 * ZAP uses query-string params on GET requests for everything.
 */
export class ZapClient {
  private readonly baseUrl: string
  private readonly apiKey: string | null
  private readonly timeout: number

  constructor(baseUrl?: string, apiKey?: string, timeout?: number) {
    this.baseUrl = (baseUrl || process.env.ZAP_URL || 'http://localhost:8090').replace(/\/$/, '')
    this.apiKey = apiKey || process.env.ZAP_API_KEY || null
    this.timeout = timeout || 30000
  }

  /** Build URL with query params, injecting apikey when configured */
  private buildUrl(path: string, params?: Record<string, string>): string {
    const url = new URL(path, this.baseUrl)
    if (this.apiKey) url.searchParams.set('apikey', this.apiKey)
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, v)
      }
    }
    return url.toString()
  }

  /** Make a GET request to ZAP and return the parsed JSON */
  private async request<T>(operation: string, path: string, params?: Record<string, string>): Promise<T> {
    const url = this.buildUrl(path, params)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeout)

    try {
      const res = await fetch(url, { signal: controller.signal })
      if (!res.ok) {
        const body = await res.text().catch(() => '')
        throw new ZapApiError(operation, `HTTP ${res.status}: ${body || res.statusText}`)
      }
      return (await res.json()) as T
    } catch (error) {
      if (error instanceof ZapApiError) throw error
      const msg = error instanceof Error ? error.message : 'Unknown error'
      throw new ZapApiError(operation, msg, error)
    } finally {
      clearTimeout(timer)
    }
  }

  // ─── Core ───────────────────────────────────────────────────────────────

  async getVersion(): Promise<string> {
    const data = await this.request<ZapVersionResponse>('getVersion', '/JSON/core/view/version/')
    return data.version
  }

  async newSession(name?: string, overwrite = true): Promise<void> {
    await this.request<ZapResultResponse>('newSession', '/JSON/core/action/newSession/', {
      name: name ?? '', overwrite: overwrite.toString(),
    })
  }

  // ─── Context ────────────────────────────────────────────────────────────

  async createContext(name: string): Promise<string> {
    const data = await this.request<ZapContextCreateResponse>('createContext', '/JSON/context/action/newContext/', { contextName: name })
    return data.contextId
  }

  async includeInContext(contextName: string, regex: string): Promise<void> {
    await this.request<ZapResultResponse>('includeInContext', '/JSON/context/action/includeInContext/', { contextName, regex })
  }

  async excludeFromContext(contextName: string, regex: string): Promise<void> {
    await this.request<ZapResultResponse>('excludeFromContext', '/JSON/context/action/excludeFromContext/', { contextName, regex })
  }

  // ─── Spider ─────────────────────────────────────────────────────────────

  async startSpider(url: string, contextName?: string, maxChildren?: number): Promise<string> {
    const params: Record<string, string> = { url }
    if (contextName) params.contextName = contextName
    if (maxChildren !== undefined) params.maxChildren = maxChildren.toString()

    const data = await this.request<ZapSpiderStartResponse>('startSpider', '/JSON/spider/action/scan/', params)
    return data.scan
  }

  async getSpiderStatus(scanId: string): Promise<number> {
    const data = await this.request<ZapSpiderStatusResponse>('getSpiderStatus', '/JSON/spider/view/status/', { scanId })
    return parseInt(data.status, 10)
  }

  async getSpiderResults(scanId: string): Promise<string[]> {
    const data = await this.request<ZapSpiderResultsResponse>('getSpiderResults', '/JSON/spider/view/results/', { scanId })
    return data.results
  }

  async stopSpider(scanId: string): Promise<void> {
    await this.request<ZapResultResponse>('stopSpider', '/JSON/spider/action/stop/', { scanId })
  }

  // ─── AJAX Spider ────────────────────────────────────────────────────────

  async startAjaxSpider(url: string, contextName?: string): Promise<void> {
    const params: Record<string, string> = { url }
    if (contextName) params.contextName = contextName
    await this.request<ZapResultResponse>('startAjaxSpider', '/JSON/ajaxSpider/action/scan/', params)
  }

  async getAjaxSpiderStatus(): Promise<string> {
    const data = await this.request<ZapAjaxSpiderStatusResponse>('getAjaxSpiderStatus', '/JSON/ajaxSpider/view/status/')
    return data.status
  }

  async stopAjaxSpider(): Promise<void> {
    await this.request<ZapResultResponse>('stopAjaxSpider', '/JSON/ajaxSpider/action/stop/')
  }

  // ─── Scan Policy Management ────────────────────────────────────────────

  async addScanPolicy(scanPolicyName: string): Promise<void> {
    await this.request<ZapResultResponse>('addScanPolicy', '/JSON/ascan/action/addScanPolicy/', { scanPolicyName })
  }

  async removeScanPolicy(scanPolicyName: string): Promise<void> {
    await this.request<ZapResultResponse>('removeScanPolicy', '/JSON/ascan/action/removeScanPolicy/', { scanPolicyName })
  }

  async setScannerAttackStrength(scanId: string, attackStrength: AttackStrength, scanPolicyName?: string): Promise<void> {
    const params: Record<string, string> = { id: scanId, attackStrength }
    if (scanPolicyName) params.scanPolicyName = scanPolicyName
    await this.request<ZapResultResponse>('setScannerAttackStrength', '/JSON/ascan/action/setScannerAttackStrength/', params)
  }

  async setScannerAlertThreshold(scanId: string, alertThreshold: AlertThreshold, scanPolicyName?: string): Promise<void> {
    const params: Record<string, string> = { id: scanId, alertThreshold }
    if (scanPolicyName) params.scanPolicyName = scanPolicyName
    await this.request<ZapResultResponse>('setScannerAlertThreshold', '/JSON/ascan/action/setScannerAlertThreshold/', params)
  }

  async enableScanners(ids: string[], scanPolicyName?: string): Promise<void> {
    const params: Record<string, string> = { ids: ids.join(',') }
    if (scanPolicyName) params.scanPolicyName = scanPolicyName
    await this.request<ZapResultResponse>('enableScanners', '/JSON/ascan/action/enableScanners/', params)
  }

  async disableScanners(ids: string[], scanPolicyName?: string): Promise<void> {
    const params: Record<string, string> = { ids: ids.join(',') }
    if (scanPolicyName) params.scanPolicyName = scanPolicyName
    await this.request<ZapResultResponse>('disableScanners', '/JSON/ascan/action/disableScanners/', params)
  }

  async disableAllScanners(scanPolicyName?: string): Promise<void> {
    const params: Record<string, string> = {}
    if (scanPolicyName) params.scanPolicyName = scanPolicyName
    await this.request<ZapResultResponse>('disableAllScanners', '/JSON/ascan/action/disableAllScanners/', params)
  }

  async enableAllScanners(scanPolicyName?: string): Promise<void> {
    const params: Record<string, string> = {}
    if (scanPolicyName) params.scanPolicyName = scanPolicyName
    await this.request<ZapResultResponse>('enableAllScanners', '/JSON/ascan/action/enableAllScanners/', params)
  }

  async setOptionMaxRuleDurationInMins(minutes: number): Promise<void> {
    await this.request<ZapResultResponse>('setOptionMaxRuleDurationInMins', '/JSON/ascan/action/setOptionMaxRuleDurationInMins/', {
      Integer: minutes.toString(),
    })
  }

  async setOptionThreadPerHost(threads: number): Promise<void> {
    await this.request<ZapResultResponse>('setOptionThreadPerHost', '/JSON/ascan/action/setOptionThreadPerHost/', {
      Integer: threads.toString(),
    })
  }

  async setOptionMaxScanDurationInMins(minutes: number): Promise<void> {
    await this.request<ZapResultResponse>('setOptionMaxScanDurationInMins', '/JSON/ascan/action/setOptionMaxScanDurationInMins/', {
      Integer: minutes.toString(),
    })
  }

  // ─── Active Scan ────────────────────────────────────────────────────────

  async startActiveScan(url: string, contextId?: string, recurse = true, scanPolicyName?: string): Promise<string> {
    const params: Record<string, string> = { url, recurse: recurse.toString() }
    if (contextId) params.contextId = contextId
    if (scanPolicyName) params.scanPolicyName = scanPolicyName

    const data = await this.request<ZapActiveScanStartResponse>('startActiveScan', '/JSON/ascan/action/scan/', params)
    return data.scan
  }

  async getActiveScanStatus(scanId: string): Promise<number> {
    const data = await this.request<ZapActiveScanStatusResponse>('getActiveScanStatus', '/JSON/ascan/view/status/', { scanId })
    return parseInt(data.status, 10)
  }

  async pauseActiveScan(scanId: string): Promise<void> {
    await this.request<ZapResultResponse>('pauseActiveScan', '/JSON/ascan/action/pause/', { scanId })
  }

  async resumeActiveScan(scanId: string): Promise<void> {
    await this.request<ZapResultResponse>('resumeActiveScan', '/JSON/ascan/action/resume/', { scanId })
  }

  async stopActiveScan(scanId: string): Promise<void> {
    await this.request<ZapResultResponse>('stopActiveScan', '/JSON/ascan/action/stop/', { scanId })
  }

  // ─── Alerts ─────────────────────────────────────────────────────────────

  async getAlerts(baseUrl?: string, start?: number, count?: number): Promise<ZapAlertsResponse> {
    const params: Record<string, string> = {}
    if (baseUrl) params.baseurl = baseUrl
    if (start !== undefined) params.start = start.toString()
    if (count !== undefined) params.count = count.toString()

    return this.request<ZapAlertsResponse>('getAlerts', '/JSON/alert/view/alerts/', params)
  }

  // ─── Authentication ─────────────────────────────────────────────────────

  async setAuthenticationMethod(contextId: string, authMethodName: string, authMethodConfigParams: string): Promise<void> {
    await this.request<ZapResultResponse>('setAuthenticationMethod', '/JSON/authentication/action/setAuthenticationMethod/', {
      contextId, authMethodName, authMethodConfigParams,
    })
  }

  async setLoggedInIndicator(contextId: string, loggedInIndicatorRegex: string): Promise<void> {
    await this.request<ZapResultResponse>('setLoggedInIndicator', '/JSON/authentication/action/setLoggedInIndicator/', {
      contextId, loggedInIndicatorRegex,
    })
  }

  // ─── Users ──────────────────────────────────────────────────────────────

  async createUser(contextId: string, name: string): Promise<string> {
    const data = await this.request<ZapNewUserResponse>('createUser', '/JSON/users/action/newUser/', { contextId, name })
    return data.userId
  }

  async setAuthCredentials(contextId: string, userId: string, authCredentialsConfigParams: string): Promise<void> {
    await this.request<ZapResultResponse>('setAuthCredentials', '/JSON/users/action/setAuthenticationCredentials/', {
      contextId, userId, authCredentialsConfigParams,
    })
  }

  async setUserEnabled(contextId: string, userId: string, enabled: boolean): Promise<void> {
    await this.request<ZapResultResponse>('setUserEnabled', '/JSON/users/action/setUserEnabled/', {
      contextId, userId, enabled: enabled.toString(),
    })
  }

  async setForcedUser(contextId: string, userId: string): Promise<void> {
    await this.request<ZapResultResponse>('setForcedUser', '/JSON/forcedUser/action/setForcedUser/', {
      contextId, userId,
    })
  }

  async setForcedUserModeEnabled(enabled: boolean): Promise<void> {
    await this.request<ZapResultResponse>('setForcedUserModeEnabled', '/JSON/forcedUser/action/setForcedUserModeEnabled/', {
      boolean: enabled.toString(),
    })
  }

  // ─── Replacer ───────────────────────────────────────────────────────────

  async addReplacerRule(description: string, enabled: boolean, matchType: string, matchRegex: boolean, matchString: string, replacement: string, initiators?: string): Promise<void> {
    await this.request<ZapResultResponse>('addReplacerRule', '/JSON/replacer/action/addRule/', {
      description, enabled: enabled.toString(), matchType, matchRegex: matchRegex.toString(),
      matchString, replacement, initiators: initiators ?? '',
    })
  }

  async removeReplacerRule(description: string): Promise<void> {
    await this.request<ZapResultResponse>('removeReplacerRule', '/JSON/replacer/action/removeRule/', { description })
  }
}
