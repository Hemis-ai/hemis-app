import axios, { AxiosInstance, AxiosError } from 'axios'
import type {
  ZapResultResponse, ZapSpiderStartResponse, ZapSpiderStatusResponse,
  ZapSpiderResultsResponse, ZapAjaxSpiderStatusResponse,
  ZapActiveScanStartResponse, ZapActiveScanStatusResponse,
  ZapAlertsResponse, ZapContextCreateResponse, ZapNewUserResponse,
  ZapVersionResponse,
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

export class ZapClient {
  private readonly http: AxiosInstance

  constructor(baseUrl?: string, apiKey?: string, timeout?: number) {
    this.http = axios.create({
      baseURL: baseUrl || process.env.ZAP_URL || 'http://localhost:8090',
      timeout: timeout || 30000,
      params: apiKey ? { apikey: apiKey } : (process.env.ZAP_API_KEY ? { apikey: process.env.ZAP_API_KEY } : {}),
    })
  }

  private extractError(error: unknown): string {
    if (error instanceof AxiosError) return error.message
    if (error instanceof Error) return error.message
    return 'Unknown error'
  }

  async getVersion(): Promise<string> {
    try {
      const { data } = await this.http.get<ZapVersionResponse>('/JSON/core/view/version/')
      return data.version
    } catch (error) { throw new ZapApiError('getVersion', this.extractError(error), error) }
  }

  async newSession(name?: string, overwrite = true): Promise<void> {
    try {
      await this.http.get<ZapResultResponse>('/JSON/core/action/newSession/', {
        params: { name: name ?? '', overwrite: overwrite.toString() },
      })
    } catch (error) { throw new ZapApiError('newSession', this.extractError(error), error) }
  }

  async createContext(name: string): Promise<string> {
    try {
      const { data } = await this.http.get<ZapContextCreateResponse>('/JSON/context/action/newContext/', { params: { contextName: name } })
      return data.contextId
    } catch (error) { throw new ZapApiError('createContext', this.extractError(error), error) }
  }

  async includeInContext(contextName: string, regex: string): Promise<void> {
    try {
      await this.http.get<ZapResultResponse>('/JSON/context/action/includeInContext/', { params: { contextName, regex } })
    } catch (error) { throw new ZapApiError('includeInContext', this.extractError(error), error) }
  }

  async excludeFromContext(contextName: string, regex: string): Promise<void> {
    try {
      await this.http.get<ZapResultResponse>('/JSON/context/action/excludeFromContext/', { params: { contextName, regex } })
    } catch (error) { throw new ZapApiError('excludeFromContext', this.extractError(error), error) }
  }

  async startSpider(url: string, contextName?: string, maxChildren?: number): Promise<string> {
    try {
      const { data } = await this.http.get<ZapSpiderStartResponse>('/JSON/spider/action/scan/', {
        params: { url, ...(contextName && { contextName }), ...(maxChildren !== undefined && { maxChildren: maxChildren.toString() }) },
      })
      return data.scan
    } catch (error) { throw new ZapApiError('startSpider', this.extractError(error), error) }
  }

  async getSpiderStatus(scanId: string): Promise<number> {
    try {
      const { data } = await this.http.get<ZapSpiderStatusResponse>('/JSON/spider/view/status/', { params: { scanId } })
      return parseInt(data.status, 10)
    } catch (error) { throw new ZapApiError('getSpiderStatus', this.extractError(error), error) }
  }

  async getSpiderResults(scanId: string): Promise<string[]> {
    try {
      const { data } = await this.http.get<ZapSpiderResultsResponse>('/JSON/spider/view/results/', { params: { scanId } })
      return data.results
    } catch (error) { throw new ZapApiError('getSpiderResults', this.extractError(error), error) }
  }

  async stopSpider(scanId: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/spider/action/stop/', { params: { scanId } }) }
    catch (error) { throw new ZapApiError('stopSpider', this.extractError(error), error) }
  }

  async startAjaxSpider(url: string, contextName?: string): Promise<void> {
    try {
      await this.http.get<ZapResultResponse>('/JSON/ajaxSpider/action/scan/', {
        params: { url, ...(contextName && { contextName }) },
      })
    } catch (error) { throw new ZapApiError('startAjaxSpider', this.extractError(error), error) }
  }

  async getAjaxSpiderStatus(): Promise<string> {
    try {
      const { data } = await this.http.get<ZapAjaxSpiderStatusResponse>('/JSON/ajaxSpider/view/status/')
      return data.status
    } catch (error) { throw new ZapApiError('getAjaxSpiderStatus', this.extractError(error), error) }
  }

  async stopAjaxSpider(): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/ajaxSpider/action/stop/') }
    catch (error) { throw new ZapApiError('stopAjaxSpider', this.extractError(error), error) }
  }

  async startActiveScan(url: string, contextId?: string, recurse = true, scanPolicyName?: string): Promise<string> {
    try {
      const { data } = await this.http.get<ZapActiveScanStartResponse>('/JSON/ascan/action/scan/', {
        params: { url, recurse: recurse.toString(), ...(contextId && { contextId }), ...(scanPolicyName && { scanPolicyName }) },
      })
      return data.scan
    } catch (error) { throw new ZapApiError('startActiveScan', this.extractError(error), error) }
  }

  async getActiveScanStatus(scanId: string): Promise<number> {
    try {
      const { data } = await this.http.get<ZapActiveScanStatusResponse>('/JSON/ascan/view/status/', { params: { scanId } })
      return parseInt(data.status, 10)
    } catch (error) { throw new ZapApiError('getActiveScanStatus', this.extractError(error), error) }
  }

  async pauseActiveScan(scanId: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/ascan/action/pause/', { params: { scanId } }) }
    catch (error) { throw new ZapApiError('pauseActiveScan', this.extractError(error), error) }
  }

  async resumeActiveScan(scanId: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/ascan/action/resume/', { params: { scanId } }) }
    catch (error) { throw new ZapApiError('resumeActiveScan', this.extractError(error), error) }
  }

  async stopActiveScan(scanId: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/ascan/action/stop/', { params: { scanId } }) }
    catch (error) { throw new ZapApiError('stopActiveScan', this.extractError(error), error) }
  }

  async getAlerts(baseUrl?: string, start?: number, count?: number): Promise<ZapAlertsResponse> {
    try {
      const { data } = await this.http.get<ZapAlertsResponse>('/JSON/alert/view/alerts/', {
        params: { ...(baseUrl && { baseurl: baseUrl }), ...(start !== undefined && { start: start.toString() }), ...(count !== undefined && { count: count.toString() }) },
      })
      return data
    } catch (error) { throw new ZapApiError('getAlerts', this.extractError(error), error) }
  }

  async setAuthenticationMethod(contextId: string, authMethodName: string, authMethodConfigParams: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/authentication/action/setAuthenticationMethod/', { params: { contextId, authMethodName, authMethodConfigParams } }) }
    catch (error) { throw new ZapApiError('setAuthenticationMethod', this.extractError(error), error) }
  }

  async setLoggedInIndicator(contextId: string, loggedInIndicatorRegex: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/authentication/action/setLoggedInIndicator/', { params: { contextId, loggedInIndicatorRegex } }) }
    catch (error) { throw new ZapApiError('setLoggedInIndicator', this.extractError(error), error) }
  }

  async createUser(contextId: string, name: string): Promise<string> {
    try {
      const { data } = await this.http.get<ZapNewUserResponse>('/JSON/users/action/newUser/', { params: { contextId, name } })
      return data.userId
    } catch (error) { throw new ZapApiError('createUser', this.extractError(error), error) }
  }

  async setAuthCredentials(contextId: string, userId: string, authCredentialsConfigParams: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/users/action/setAuthenticationCredentials/', { params: { contextId, userId, authCredentialsConfigParams } }) }
    catch (error) { throw new ZapApiError('setAuthCredentials', this.extractError(error), error) }
  }

  async setUserEnabled(contextId: string, userId: string, enabled: boolean): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/users/action/setUserEnabled/', { params: { contextId, userId, enabled: enabled.toString() } }) }
    catch (error) { throw new ZapApiError('setUserEnabled', this.extractError(error), error) }
  }

  async setForcedUser(contextId: string, userId: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/forcedUser/action/setForcedUser/', { params: { contextId, userId } }) }
    catch (error) { throw new ZapApiError('setForcedUser', this.extractError(error), error) }
  }

  async setForcedUserModeEnabled(enabled: boolean): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/forcedUser/action/setForcedUserModeEnabled/', { params: { boolean: enabled.toString() } }) }
    catch (error) { throw new ZapApiError('setForcedUserModeEnabled', this.extractError(error), error) }
  }

  async addReplacerRule(description: string, enabled: boolean, matchType: string, matchRegex: boolean, matchString: string, replacement: string, initiators?: string): Promise<void> {
    try {
      await this.http.get<ZapResultResponse>('/JSON/replacer/action/addRule/', {
        params: { description, enabled: enabled.toString(), matchType, matchRegex: matchRegex.toString(), matchString, replacement, initiators: initiators ?? '' },
      })
    } catch (error) { throw new ZapApiError('addReplacerRule', this.extractError(error), error) }
  }

  async removeReplacerRule(description: string): Promise<void> {
    try { await this.http.get<ZapResultResponse>('/JSON/replacer/action/removeRule/', { params: { description } }) }
    catch (error) { throw new ZapApiError('removeReplacerRule', this.extractError(error), error) }
  }
}
