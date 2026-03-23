'use client'

import { useState } from 'react'

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

  async function handleCopy(text: string, id: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch { /* clipboard not available */ }
  }

  return (
    <div style={{ marginTop: 20 }}>
      {INTEGRATIONS.map(cat => (
        <div key={cat.category} style={{ marginBottom: 24 }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-dast)', marginBottom: 10, fontWeight: 700 }}>
            {cat.category}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
            {cat.items.map(item => {
              const isExpanded = expandedItem === item.name
              return (
                <div
                  key={item.name}
                  className="bracket-card"
                  style={{ padding: 0, overflow: 'hidden' }}
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
                      <div className="mono" style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        {item.name}
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
                                type={field.toLowerCase().includes('token') || field.toLowerCase().includes('key') ? 'password' : 'text'}
                                placeholder={field}
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
                          <button className="mono" style={{
                            marginTop: 4, padding: '6px 16px', fontSize: 10,
                            background: 'var(--color-dast)', color: '#fff',
                            border: 'none', borderRadius: 4, cursor: 'pointer',
                            letterSpacing: '0.08em',
                          }}>
                            SAVE & TEST
                          </button>
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
