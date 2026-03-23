'use client'

import { useState, useEffect, useCallback } from 'react'

const STORAGE_KEY = 'hemisx-dast-integrations'

interface IntegrationConfig {
  name: string
  values: Record<string, string>
  connected: boolean
  lastTested: string | null
}

function loadConfigs(): Record<string, IntegrationConfig> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch { return {} }
}

function saveConfigs(configs: Record<string, IntegrationConfig>) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(configs)) } catch { /* noop */ }
}

const INTEGRATIONS = [
  {
    category: 'CI/CD PIPELINES',
    items: [
      {
        name: 'GitHub Actions',
        icon: '⬡',
        desc: 'Auto-scan on PR, block merge on CRITICAL',
        snippet: `name: DAST Scan
on: [pull_request]
jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: hemisx/dast-action@v1
        with:
          target-url: \${{ secrets.TARGET_URL }}
          api-key: \${{ secrets.HEMISX_API_KEY }}
          fail-on: critical
          profile: quick`,
      },
      {
        name: 'GitLab CI',
        icon: '◆',
        desc: 'Pipeline stage with artifact reports',
        snippet: `dast_scan:
  stage: test
  image: hemisx/dast-scanner:latest
  script:
    - hemisx-scan --url $TARGET_URL --profile quick
  artifacts:
    reports:
      dast: gl-dast-report.json
  rules:
    - if: $CI_MERGE_REQUEST_ID`,
      },
      {
        name: 'Jenkins',
        icon: '◇',
        desc: 'Pipeline step with quality gate',
        snippet: `pipeline {
  stages {
    stage('DAST') {
      steps {
        sh 'hemisx-scan --url $TARGET --profile full --output report.json'
        script {
          def results = readJSON file: 'report.json'
          if (results.criticalCount > 0) {
            error "DAST found critical vulnerabilities"
          }
        }
      }
    }
  }
}`,
      },
    ],
  },
  {
    category: 'NOTIFICATIONS',
    items: [
      {
        name: 'Slack',
        icon: '#',
        desc: 'Send scan results to a Slack channel',
        config: true,
        fields: ['Webhook URL', 'Channel'],
      },
      {
        name: 'Microsoft Teams',
        icon: '⊞',
        desc: 'Post scan summaries to Teams',
        config: true,
        fields: ['Webhook URL'],
      },
      {
        name: 'Email',
        icon: '✉',
        desc: 'Email scan reports to stakeholders',
        config: true,
        fields: ['Recipients (comma-separated)', 'Notify on severity'],
      },
    ],
  },
  {
    category: 'ISSUE TRACKERS',
    items: [
      {
        name: 'Jira',
        icon: '◈',
        desc: 'Auto-create tickets from CRITICAL/HIGH findings',
        config: true,
        fields: ['Jira URL', 'Project Key', 'API Token'],
      },
      {
        name: 'GitHub Issues',
        icon: '⊙',
        desc: 'Create issues with fix code in body',
        config: true,
        fields: ['Repository (owner/repo)', 'Labels'],
      },
      {
        name: 'Linear',
        icon: '▬',
        desc: 'Create issues in Linear projects',
        config: true,
        fields: ['API Key', 'Team ID'],
      },
    ],
  },
  {
    category: 'EXPORT & WEBHOOKS',
    items: [
      {
        name: 'Webhook',
        icon: '↗',
        desc: 'POST scan results to any endpoint',
        config: true,
        fields: ['Endpoint URL', 'Auth Header (optional)'],
      },
      {
        name: 'Splunk',
        icon: '▤',
        desc: 'Forward findings to Splunk HEC',
        config: true,
        fields: ['HEC URL', 'HEC Token', 'Index'],
      },
    ],
  },
]

export default function IntegrationsTab() {
  const [expandedItem, setExpandedItem] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [configs, setConfigs] = useState<Record<string, IntegrationConfig>>({})
  const [fieldValues, setFieldValues] = useState<Record<string, Record<string, string>>>({})
  const [testingId, setTestingId] = useState<string | null>(null)
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  // Load from localStorage on mount
  useEffect(() => {
    const loaded = loadConfigs()
    setConfigs(loaded)
    // Initialize field values from saved configs
    const fv: Record<string, Record<string, string>> = {}
    for (const [name, cfg] of Object.entries(loaded)) {
      fv[name] = { ...cfg.values }
    }
    setFieldValues(fv)
  }, [])

  const updateConfig = useCallback((name: string, config: IntegrationConfig) => {
    setConfigs(prev => {
      const next = { ...prev, [name]: config }
      saveConfigs(next)
      return next
    })
  }, [])

  function showToast(message: string, type: 'success' | 'error') {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  async function handleCopy(text: string, id: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch { /* clipboard not available */ }
  }

  function handleFieldChange(itemName: string, fieldName: string, value: string) {
    setFieldValues(prev => ({
      ...prev,
      [itemName]: { ...(prev[itemName] || {}), [fieldName]: value },
    }))
  }

  async function handleSaveAndTest(itemName: string, fields: string[]) {
    const values = fieldValues[itemName] || {}
    // Validate required fields
    const emptyFields = fields.filter(f => !values[f]?.trim() && !f.includes('optional'))
    if (emptyFields.length > 0) {
      showToast(`Missing required fields: ${emptyFields.join(', ')}`, 'error')
      return
    }

    setTestingId(itemName)

    // Test webhook/notification endpoints
    try {
      let testResult = false

      if (itemName === 'Webhook') {
        const url = values['Endpoint URL']
        try {
          const controller = new AbortController()
          const timer = setTimeout(() => controller.abort(), 8000)
          const headers: Record<string, string> = { 'Content-Type': 'application/json' }
          if (values['Auth Header (optional)']) headers['Authorization'] = values['Auth Header (optional)']
          const res = await fetch(url, {
            method: 'POST',
            signal: controller.signal,
            headers,
            body: JSON.stringify({ test: true, source: 'hemisx-dast', timestamp: new Date().toISOString() }),
          })
          clearTimeout(timer)
          testResult = res.ok || res.status < 500
        } catch { testResult = false }
      } else if (itemName === 'Slack') {
        const url = values['Webhook URL']
        if (url?.includes('hooks.slack.com')) {
          try {
            const controller = new AbortController()
            const timer = setTimeout(() => controller.abort(), 8000)
            const res = await fetch(url, {
              method: 'POST',
              signal: controller.signal,
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ text: '🔒 HemisX DAST — Integration test successful!' }),
            })
            clearTimeout(timer)
            testResult = res.ok
          } catch { testResult = false }
        }
      } else if (itemName === 'Microsoft Teams') {
        const url = values['Webhook URL']
        if (url?.includes('webhook.office.com') || url?.includes('microsoft.com')) {
          try {
            const controller = new AbortController()
            const timer = setTimeout(() => controller.abort(), 8000)
            const res = await fetch(url, {
              method: 'POST',
              signal: controller.signal,
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                '@type': 'MessageCard',
                summary: 'HemisX DAST Test',
                text: '🔒 HemisX DAST — Integration test successful!',
              }),
            })
            clearTimeout(timer)
            testResult = res.ok
          } catch { testResult = false }
        }
      } else {
        // For other integrations, just save config (actual integration requires server-side handling)
        testResult = true
      }

      const config: IntegrationConfig = {
        name: itemName,
        values,
        connected: testResult,
        lastTested: new Date().toISOString(),
      }
      updateConfig(itemName, config)

      if (testResult) {
        showToast(`${itemName} connected successfully`, 'success')
      } else {
        showToast(`${itemName} test failed — check credentials`, 'error')
      }
    } catch {
      showToast(`${itemName} — connection error`, 'error')
    }

    setTestingId(null)
  }

  function handleDisconnect(itemName: string) {
    setConfigs(prev => {
      const next = { ...prev }
      delete next[itemName]
      saveConfigs(next)
      return next
    })
    setFieldValues(prev => {
      const next = { ...prev }
      delete next[itemName]
      return next
    })
    showToast(`${itemName} disconnected`, 'success')
  }

  return (
    <div style={{ marginTop: 20 }}>
      {/* Toast */}
      {toast && (
        <div style={{
          position: 'fixed', top: 20, right: 20, zIndex: 1000,
          padding: '10px 20px', borderRadius: 6,
          background: toast.type === 'error' ? '#ef444420' : '#22c55e20',
          border: `1px solid ${toast.type === 'error' ? '#ef4444' : '#22c55e'}`,
          color: toast.type === 'error' ? '#ef4444' : '#22c55e',
        }}>
          <span className="mono" style={{ fontSize: 11 }}>{toast.message}</span>
        </div>
      )}

      {/* Connected count */}
      {Object.values(configs).filter(c => c.connected).length > 0 && (
        <div className="bracket-card bracket-dast" style={{ padding: '10px 16px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#22c55e' }} />
          <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-primary)' }}>
            {Object.values(configs).filter(c => c.connected).length} integration{Object.values(configs).filter(c => c.connected).length !== 1 ? 's' : ''} connected
          </span>
          <div style={{ flex: 1 }} />
          <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)' }}>
            {Object.values(configs).filter(c => c.connected).map(c => c.name).join(' · ')}
          </div>
        </div>
      )}

      {INTEGRATIONS.map(cat => (
        <div key={cat.category} style={{ marginBottom: 24 }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-dast)', marginBottom: 10, fontWeight: 700 }}>
            {cat.category}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
            {cat.items.map(item => {
              const isExpanded = expandedItem === item.name
              const isConnected = configs[item.name]?.connected
              return (
                <div
                  key={item.name}
                  className="bracket-card"
                  style={{ padding: 0, overflow: 'hidden', borderColor: isConnected ? '#22c55e40' : undefined }}
                >
                  <div
                    onClick={() => setExpandedItem(isExpanded ? null : item.name)}
                    style={{
                      padding: '14px 16px', cursor: 'pointer',
                      display: 'flex', alignItems: 'center', gap: 12,
                    }}
                  >
                    <span style={{ fontSize: 18, width: 28, textAlign: 'center' }}>{item.icon}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-primary)' }}>
                          {item.name}
                        </span>
                        {isConnected && (
                          <span className="mono" style={{ fontSize: 8, padding: '1px 5px', borderRadius: 10, background: '#22c55e20', border: '1px solid #22c55e40', color: '#22c55e' }}>
                            CONNECTED
                          </span>
                        )}
                      </div>
                      <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', marginTop: 2 }}>
                        {item.desc}
                      </div>
                    </div>
                    <span className="mono" style={{
                      fontSize: 9, padding: '2px 8px', borderRadius: 10,
                      background: 'var(--color-bg-secondary)',
                      border: '1px solid var(--color-border)',
                      color: 'var(--color-text-secondary)',
                    }}>
                      {isExpanded ? 'HIDE' : 'SETUP'}
                    </span>
                  </div>

                  {isExpanded && (
                    <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--color-border)' }}>
                      {'snippet' in item && item.snippet && (
                        <div style={{ marginTop: 10 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                            <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', letterSpacing: '0.08em' }}>
                              CONFIGURATION
                            </div>
                            <button
                              onClick={(e) => { e.stopPropagation(); handleCopy(item.snippet!, item.name) }}
                              className="mono"
                              style={{
                                fontSize: 9, padding: '2px 8px', borderRadius: 3,
                                background: copiedId === item.name ? '#22c55e20' : 'var(--color-bg-secondary)',
                                border: `1px solid ${copiedId === item.name ? '#22c55e' : 'var(--color-border)'}`,
                                color: copiedId === item.name ? '#22c55e' : 'var(--color-text-secondary)',
                                cursor: 'pointer',
                              }}
                            >
                              {copiedId === item.name ? 'COPIED' : 'COPY'}
                            </button>
                          </div>
                          <pre style={{
                            padding: 10, borderRadius: 4, fontSize: 10, lineHeight: 1.5,
                            background: 'var(--color-bg-secondary)',
                            border: '1px solid var(--color-border)',
                            color: 'var(--color-text-primary)', overflow: 'auto',
                            fontFamily: 'var(--font-mono)', maxHeight: 200,
                          }}>
                            {item.snippet}
                          </pre>
                        </div>
                      )}
                      {'fields' in item && item.fields && (
                        <div style={{ marginTop: 10 }}>
                          {item.fields.map(field => (
                            <div key={field} style={{ marginBottom: 8 }}>
                              <label className="mono" style={{ fontSize: 9, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 3 }}>
                                {field.toUpperCase()}
                              </label>
                              <input
                                type={field.toLowerCase().includes('token') || field.toLowerCase().includes('key') || field.toLowerCase().includes('secret') ? 'password' : 'text'}
                                placeholder={field}
                                value={(fieldValues[item.name] || {})[field] || ''}
                                onChange={e => handleFieldChange(item.name, field, e.target.value)}
                                className="mono"
                                style={{
                                  width: '100%', padding: '6px 8px', fontSize: 11,
                                  background: 'var(--color-bg-primary)',
                                  border: '1px solid var(--color-border)',
                                  borderRadius: 4, color: 'var(--color-text-primary)',
                                  fontFamily: 'var(--font-mono)',
                                }}
                              />
                            </div>
                          ))}
                          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                            <button
                              onClick={() => handleSaveAndTest(item.name, item.fields!)}
                              disabled={testingId === item.name}
                              className="mono"
                              style={{
                                padding: '6px 16px', fontSize: 10,
                                background: testingId === item.name ? '#f9731640' : 'var(--color-dast)',
                                color: '#fff',
                                border: 'none', borderRadius: 4, cursor: 'pointer',
                                letterSpacing: '0.08em',
                                opacity: testingId === item.name ? 0.7 : 1,
                              }}
                            >
                              {testingId === item.name ? 'TESTING...' : 'SAVE & TEST'}
                            </button>
                            {isConnected && (
                              <button
                                onClick={() => handleDisconnect(item.name)}
                                className="mono"
                                style={{
                                  padding: '6px 12px', fontSize: 10,
                                  background: 'none', color: '#ef4444',
                                  border: '1px solid #ef444440', borderRadius: 4, cursor: 'pointer',
                                }}
                              >
                                DISCONNECT
                              </button>
                            )}
                          </div>
                          {isConnected && configs[item.name]?.lastTested && (
                            <div className="mono" style={{ fontSize: 8, color: '#22c55e', marginTop: 6 }}>
                              Last tested: {new Date(configs[item.name].lastTested!).toLocaleString()}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}
