'use client'

import { useState, useRef, useCallback, useEffect } from 'react'
import type { SastScanResult, SastFindingResult, SastSeverity, OwaspCategory } from '@/lib/types/sast'

// ─── Severity helpers ────────────────────────────────────────────────────────

const SEV_COLOR: Record<SastSeverity, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
  INFO:     'var(--color-text-dim)',
}

const SEV_BG: Record<SastSeverity, string> = {
  CRITICAL: 'rgba(239,90,90,0.12)',
  HIGH:     'rgba(255,160,50,0.12)',
  MEDIUM:   'rgba(242,209,86,0.10)',
  LOW:      'rgba(90,176,255,0.10)',
  INFO:     'rgba(140,160,180,0.08)',
}

const SEV_ORDER: SastSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

// ─── Sample vulnerable code for demo ────────────────────────────────────────

const DEMO_SNIPPETS: Record<string, { path: string; content: string }[]> = {
  nodejs: [
    {
      path: 'src/api/user.js',
      content: `const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const crypto = require('crypto');
const router = express.Router();

const DB_PASSWORD = "admin123";
const API_KEY = "sk-live_a1b2c3d4e5f6g7h8i9j0k1l2";

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // Vulnerable: SQL injection
  const query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
  db.query(query, (err, results) => {
    if (results.length > 0) {
      // Vulnerable: weak token generation
      const token = crypto.createHash('md5').update(username + Date.now()).digest('hex');
      res.json({ token, user: results[0] });
    }
  });
});

router.get('/ping', (req, res) => {
  const host = req.query.host;
  // Vulnerable: command injection
  exec('ping -c 1 ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

router.get('/file', (req, res) => {
  const filename = req.query.name;
  // Vulnerable: path traversal
  const fs = require('fs');
  fs.readFile('/app/files/' + filename, (err, data) => {
    if (err) res.status(500).send(err.stack);
    else res.send(data);
  });
});

router.post('/render', (req, res) => {
  // Vulnerable: XSS
  document.getElementById('output').innerHTML = req.body.userInput;
});

module.exports = router;`,
    },
    {
      path: 'package.json',
      content: `{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.15",
    "jsonwebtoken": "8.5.1",
    "axios": "0.21.1",
    "minimist": "1.2.0",
    "moment": "2.29.1",
    "node-fetch": "2.6.0",
    "qs": "6.9.0",
    "xml2js": "0.4.23"
  }
}`,
    },
  ],
  python: [
    {
      path: 'app/views.py',
      content: `import os
import pickle
import hashlib
import subprocess
import yaml
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config['DEBUG'] = True
SECRET_KEY = "mysupersecretkey123"

@app.route('/search')
def search():
    query = request.args.get('q')
    # Vulnerable: SQL injection
    sql = f"SELECT * FROM products WHERE name = '{query}'"
    cursor.execute(sql)
    return str(cursor.fetchall())

@app.route('/run')
def run_command():
    cmd = request.args.get('cmd')
    # Vulnerable: command injection
    result = os.system(cmd)
    return str(result)

@app.route('/load')
def load_data():
    data = request.get_data()
    # Vulnerable: insecure deserialization
    obj = pickle.loads(data)
    return str(obj)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # Vulnerable: SSRF
    resp = requests.get(url)
    return resp.text

@app.route('/config')
def load_config():
    # Vulnerable: unsafe yaml.load
    config = yaml.load(open('config.yaml').read())
    return str(config)

def hash_password(password):
    # Vulnerable: MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/proc')
def run_proc():
    cmd = request.args.get('c', 'ls')
    # Vulnerable: shell=True
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()`,
    },
    {
      path: 'requirements.txt',
      content: `flask==2.2.0
requests==2.28.0
pyyaml==5.4.1
pillow==9.5.0
cryptography==40.0.0
jinja2==3.1.0
urllib3==1.26.0
paramiko==3.1.0
django==4.2.0`,
    },
  ],
  php: [
    {
      path: 'api/user.php',
      content: `<?php
$password = "admin";
$api_key = "AKIAIOSFODNN7EXAMPLE";

function getUserById($id) {
    global $conn;
    // Vulnerable: SQL injection
    $query = "SELECT * FROM users WHERE id = " . $id;
    return mysqli_query($conn, $query);
}

function login($username, $password_input) {
    global $conn;
    // Vulnerable: SQL injection
    $sql = "SELECT * FROM users WHERE username='" . $username . "' AND password='" . $password_input . "'";
    $result = mysqli_query($conn, $sql);

    if ($result && mysqli_num_rows($result) > 0) {
        $_SESSION['user'] = $username;
        return true;
    }
    return false;
}

function loadData() {
    // Vulnerable: PHP unserialize
    $data = $_POST['data'];
    return unserialize($data);
}

function getFile() {
    // Vulnerable: path traversal
    $file = $_GET['file'];
    return file_get_contents('/var/www/' . $file);
}

function runCmd() {
    // Vulnerable: command injection
    $host = $_GET['host'];
    exec('ping -c 1 ' . $host, $output);
    return implode('\\n', $output);
}
?>`,
    },
  ],
}

// ─── Finding card ────────────────────────────────────────────────────────────

interface AiEnrichmentData {
  falsePositiveProbability: number
  fpReasoning: string
  businessImpact: string
  impactLevel: string
  detailedRemediation: string
  fixCode: string
  fixLanguage: string
  executiveExplanation: string
  relatedCVEs: string[]
  attackTechniques: string[]
  aiConfidence: number
  model: string
}

function FindingCard({ f, index, onToggleFP }: {
  f: SastFindingResult
  index: number
  onToggleFP?: (id: string, fp: boolean) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [aiData, setAiData] = useState<AiEnrichmentData | null>(null)
  const [aiLoading, setAiLoading] = useState(false)
  const sev = f.severity as SastSeverity
  const isFP = f.falsePositive

  async function analyzeWithAI() {
    setAiLoading(true)
    try {
      const res = await fetch('/api/sast/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'finding', finding: f }),
      })
      const data = await res.json()
      if (data.enrichment) setAiData(data.enrichment)
    } catch { /* ignore */ }
    setAiLoading(false)
  }

  return (
    <div
      key={f.id}
      style={{
        border: `1px solid ${isFP ? 'var(--color-border)' : SEV_COLOR[sev] + '44'}`,
        background: isFP ? 'var(--color-bg-surface)' : SEV_BG[sev],
        marginBottom: 8,
        borderRadius: 2,
        overflow: 'hidden',
        opacity: isFP ? 0.5 : 1,
        transition: 'opacity 0.2s',
      }}
    >
      {/* Header row */}
      <div
        onClick={() => setExpanded(x => !x)}
        style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 14px', cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
          letterSpacing: '0.1em', padding: '2px 7px',
          background: isFP ? 'var(--color-bg-elevated)' : SEV_COLOR[sev] + '22',
          color: isFP ? 'var(--color-text-dim)' : SEV_COLOR[sev],
          border: `1px solid ${isFP ? 'var(--color-border)' : SEV_COLOR[sev] + '55'}`,
          borderRadius: 2, whiteSpace: 'nowrap', minWidth: 70, textAlign: 'center',
          textDecoration: isFP ? 'line-through' : 'none',
        }}>
          {sev}
        </span>

        <span className="mono" style={{ fontSize: 11, color: isFP ? 'var(--color-text-dim)' : 'var(--color-sast)', minWidth: 100 }}>
          {f.ruleId}
        </span>

        <span style={{
          flex: 1, fontSize: 13, fontWeight: 500,
          color: isFP ? 'var(--color-text-dim)' : 'var(--color-text-primary)',
          textDecoration: isFP ? 'line-through' : 'none',
        }}>
          {f.ruleName}
        </span>

        {isFP && (
          <span className="mono" style={{
            fontSize: 9, padding: '2px 6px',
            background: 'var(--color-text-dim)22',
            color: 'var(--color-text-dim)',
            border: '1px solid var(--color-border)',
            letterSpacing: '0.1em',
          }}>
            FALSE POSITIVE
          </span>
        )}

        <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', marginRight: 8 }}>
          {f.filePath}:{f.lineStart}
        </span>

        <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
          {f.cwe}
        </span>

        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10,
          color: 'var(--color-text-dim)', marginLeft: 8,
        }}>
          {expanded ? '▲' : '▼'}
        </span>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: '0 14px 14px', borderTop: '1px solid var(--color-border)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 12 }}>
            {/* Left: description + remediation */}
            <div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>
                Description
              </div>
              <p style={{ fontSize: 13, color: 'var(--color-text-primary)', lineHeight: 1.6, margin: 0, marginBottom: 14 }}>
                {f.description}
              </p>

              <div className="mono" style={{ fontSize: 10, color: 'var(--color-scanner)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>
                Remediation
              </div>
              <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.6, margin: 0 }}>
                {f.remediation}
              </p>

              <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                {[f.owasp.split('–')[0]?.trim(), f.cwe, f.category].filter(Boolean).map(tag => (
                  <span key={tag} className="mono" style={{
                    fontSize: 10, padding: '2px 8px',
                    background: 'var(--color-bg-elevated)',
                    border: '1px solid var(--color-border)',
                    color: 'var(--color-text-secondary)',
                  }}>
                    {tag}
                  </span>
                ))}
                <span className="mono" style={{
                  fontSize: 10, padding: '2px 8px',
                  background: 'var(--color-bg-elevated)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-text-dim)',
                }}>
                  Confidence: {f.confidence}
                </span>

                {/* False positive toggle */}
                {onToggleFP && (
                  <button
                    onClick={e => { e.stopPropagation(); onToggleFP(f.id, !f.falsePositive) }}
                    className="mono"
                    style={{
                      marginLeft: 'auto',
                      padding: '4px 12px', fontSize: 10, cursor: 'pointer',
                      letterSpacing: '0.08em',
                      background: isFP ? 'var(--color-scanner)15' : 'var(--color-bg-elevated)',
                      border: `1px solid ${isFP ? 'var(--color-scanner)' : 'var(--color-border)'}`,
                      color: isFP ? 'var(--color-scanner)' : 'var(--color-text-dim)',
                    }}
                  >
                    {isFP ? '↩ REOPEN' : '✕ MARK FALSE POSITIVE'}
                  </button>
                )}
              </div>
            </div>

            {/* Right: code snippet */}
            <div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>
                Code Snippet · {f.filePath}
              </div>
              <pre style={{
                fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.6,
                background: 'var(--color-bg-base)', border: '1px solid var(--color-border)',
                padding: '10px 12px', margin: 0, overflowX: 'auto',
                color: 'var(--color-text-secondary)',
                maxHeight: 180,
              }}>
                {f.codeSnippet}
              </pre>

              {/* AI Analysis button */}
              <button
                onClick={e => { e.stopPropagation(); analyzeWithAI() }}
                disabled={aiLoading || !!aiData}
                className="mono"
                style={{
                  marginTop: 10, padding: '6px 14px', fontSize: 10, cursor: aiLoading ? 'not-allowed' : 'pointer',
                  letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: 6,
                  background: aiData ? 'var(--color-sast)15' : 'var(--color-bg-elevated)',
                  border: `1px solid ${aiData ? 'var(--color-sast)' : 'var(--color-border)'}`,
                  color: aiData ? 'var(--color-sast)' : 'var(--color-text-dim)',
                }}
              >
                {aiLoading ? (
                  <><span className="dot-live" style={{ background: 'var(--color-sast)', width: 6, height: 6 }} /> ANALYZING...</>
                ) : aiData ? '✓ AI ANALYSIS COMPLETE' : '⚡ ANALYZE WITH AI'}
              </button>
            </div>
          </div>

          {/* AI Enrichment Results */}
          {aiData && (
            <div style={{ marginTop: 14, padding: 14, background: 'var(--color-bg-base)', border: '1px solid var(--color-sast)33' }}>
              <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 10 }}>
                [ AI ANALYSIS — {aiData.model.split('/').pop()} ]
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <div>
                  <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', marginBottom: 4, textTransform: 'uppercase' }}>Executive Summary</div>
                  <p style={{ fontSize: 12, color: 'var(--color-text-primary)', lineHeight: 1.5, margin: 0, marginBottom: 10 }}>
                    {aiData.executiveExplanation}
                  </p>

                  <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', marginBottom: 4, textTransform: 'uppercase' }}>Business Impact</div>
                  <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.5, margin: 0, marginBottom: 10 }}>
                    {aiData.businessImpact}
                  </p>

                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <span className="mono" style={{ fontSize: 9, padding: '2px 8px', border: '1px solid var(--color-border)', color: 'var(--color-text-dim)' }}>
                      FP Probability: {aiData.falsePositiveProbability}%
                    </span>
                    <span className="mono" style={{ fontSize: 9, padding: '2px 8px', border: '1px solid var(--color-border)', color: 'var(--color-text-dim)' }}>
                      AI Confidence: {aiData.aiConfidence}%
                    </span>
                    {aiData.relatedCVEs.length > 0 && aiData.relatedCVEs.map(cve => (
                      <span key={cve} className="mono" style={{ fontSize: 9, padding: '2px 8px', background: 'var(--color-sev-high)12', border: '1px solid var(--color-sev-high)44', color: 'var(--color-sev-high)' }}>
                        {cve}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="mono" style={{ fontSize: 9, color: 'var(--color-scanner)', marginBottom: 4, textTransform: 'uppercase' }}>AI Remediation</div>
                  <pre style={{ fontSize: 11, color: 'var(--color-text-secondary)', lineHeight: 1.5, margin: 0, marginBottom: 10, whiteSpace: 'pre-wrap', fontFamily: 'inherit' }}>
                    {aiData.detailedRemediation}
                  </pre>

                  {aiData.fixCode && (
                    <>
                      <div className="mono" style={{ fontSize: 9, color: 'var(--color-scanner)', marginBottom: 4, textTransform: 'uppercase' }}>Suggested Fix</div>
                      <pre style={{
                        fontFamily: 'var(--font-mono)', fontSize: 10, lineHeight: 1.5,
                        background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)',
                        padding: '8px 10px', margin: 0, overflowX: 'auto',
                        color: 'var(--color-text-secondary)', maxHeight: 150,
                      }}>
                        {aiData.fixCode}
                      </pre>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── OWASP heatmap ────────────────────────────────────────────────────────────

function OwaspHeatmap({ coverage }: { coverage: OwaspCategory[] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
      {coverage.map(cat => {
        const color = cat.highest ? SEV_COLOR[cat.highest as SastSeverity] : 'var(--color-border)'
        const bg    = cat.highest ? SEV_BG[cat.highest as SastSeverity]    : 'var(--color-bg-surface)'
        return (
          <div
            key={cat.id}
            style={{
              background: bg, border: `1px solid ${color}55`,
              padding: '10px 12px', borderRadius: 2, textAlign: 'center',
            }}
          >
            <div className="mono" style={{ fontSize: 13, fontWeight: 700, color, marginBottom: 4 }}>
              {cat.id}
            </div>
            <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginBottom: 6, lineHeight: 1.3 }}>
              {cat.name}
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: cat.count > 0 ? color : 'var(--color-text-dim)' }}>
              {cat.count}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── CI/CD Panel ──────────────────────────────────────────────────────────────

function CiCdPanel() {
  const [failOn, setFailOn] = useState<string>('CRITICAL')
  const [copied, setCopied] = useState('')
  const [template, setTemplate] = useState<'github' | 'gitlab' | 'precommit'>('github')

  const templates: Record<string, string> = {
    github: `# HemisX SAST — GitHub Actions
name: HemisX SAST Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Collect source files
        id: collect
        run: |
          FILES=$(find . -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.php" \\) \\
            -not -path "*/node_modules/*" -not -path "*/.git/*" | head -50 | \\
            while read f; do
              c=$(cat "$f" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
              echo "{\\"path\\":\\"$f\\",\\"content\\":$c}"
            done | jq -s '.')
          echo "files=$FILES" >> $GITHUB_OUTPUT

      - name: Run HemisX SAST
        run: |
          RESULT=$(curl -s -X POST "\${{ secrets.HEMISX_URL }}/api/sast/scan" \\
            -H "Content-Type: application/json" \\
            -d "{\\"name\\":\\"CI Scan\\",\\"files\\":\${{ steps.collect.outputs.files }}}")
          echo "$RESULT" | jq '.summary'
          CRITICAL=$(echo "$RESULT" | jq '.summary.critical')
          ${failOn !== 'NONE' ? `if [ "$CRITICAL" -gt 0 ]; then exit 1; fi` : ''}`,
    gitlab: `# HemisX SAST — GitLab CI
hemisx-sast:
  stage: test
  script:
    - |
      FILES=$(find . -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.py" \\) \\
        -not -path "*/node_modules/*" | head -50 | \\
        while read f; do
          c=$(cat "$f" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
          echo "{\\"path\\":\\"$f\\",\\"content\\":$c}"
        done | jq -s '.')
      curl -s -X POST "\${HEMISX_URL}/api/sast/scan" \\
        -H "Content-Type: application/json" \\
        -d "{\\"name\\":\\"GitLab CI Scan\\",\\"files\\":$FILES}" | jq '.summary'
  only:
    - merge_requests
    - main`,
    precommit: `#!/bin/sh
# HemisX SAST — Pre-commit Hook
# Install: cp .hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

echo "[HemisX SAST] Scanning staged files..."
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(js|ts|py|php)$' | head -20)
[ -z "$STAGED" ] && exit 0

FILES_JSON="["
FIRST=true
for f in $STAGED; do
  C=$(git show ":$f" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
  [ "$FIRST" = true ] && FIRST=false || FILES_JSON="$FILES_JSON,"
  FILES_JSON="$FILES_JSON{\\"path\\":\\"$f\\",\\"content\\":$C}"
done
FILES_JSON="$FILES_JSON]"

RESULT=$(curl -s -X POST "http://localhost:7777/api/sast/scan" \\
  -H "Content-Type: application/json" \\
  -d "{\\"name\\":\\"Pre-commit\\",\\"files\\":$FILES_JSON}")

CRITICAL=$(echo "$RESULT" | jq -r '.summary.critical // 0')
echo "[HemisX SAST] CRITICAL=$CRITICAL"
[ "$CRITICAL" -gt 0 ] && { echo "Blocked: CRITICAL findings"; exit 1; }
exit 0`,
  }

  function copyToClipboard(text: string, label: string) {
    navigator.clipboard.writeText(text)
    setCopied(label)
    setTimeout(() => setCopied(''), 2000)
  }

  return (
    <div className="bracket-card" style={{ padding: 20, marginBottom: 24 }}>
      <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
        [ CI/CD INTEGRATION ]
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {(['github', 'gitlab', 'precommit'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTemplate(t)}
            className="mono"
            style={{
              padding: '6px 14px', fontSize: 10, cursor: 'pointer',
              letterSpacing: '0.08em',
              background: template === t ? 'var(--color-sast)18' : 'var(--color-bg-elevated)',
              border: `1px solid ${template === t ? 'var(--color-sast)' : 'var(--color-border)'}`,
              color: template === t ? 'var(--color-sast)' : 'var(--color-text-dim)',
            }}
          >
            {t === 'github' ? 'GitHub Actions' : t === 'gitlab' ? 'GitLab CI' : 'Pre-commit Hook'}
          </button>
        ))}

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>Fail on:</span>
          <select
            value={failOn}
            onChange={e => setFailOn(e.target.value)}
            style={{
              background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)',
              color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)',
              fontSize: 10, padding: '4px 8px', outline: 'none',
            }}
          >
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div style={{ position: 'relative' }}>
        <pre style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.5,
          background: 'var(--color-bg-base)', border: '1px solid var(--color-border)',
          padding: '14px 16px', margin: 0, overflowX: 'auto',
          color: 'var(--color-text-secondary)', maxHeight: 260,
        }}>
          {templates[template]}
        </pre>
        <button
          onClick={() => copyToClipboard(templates[template], template)}
          className="mono"
          style={{
            position: 'absolute', top: 8, right: 8,
            padding: '4px 12px', fontSize: 10, cursor: 'pointer',
            background: copied === template ? 'var(--color-scanner)22' : 'var(--color-bg-elevated)',
            border: `1px solid ${copied === template ? 'var(--color-scanner)' : 'var(--color-border)'}`,
            color: copied === template ? 'var(--color-scanner)' : 'var(--color-text-dim)',
            letterSpacing: '0.08em',
          }}
        >
          {copied === template ? '✓ COPIED' : 'COPY'}
        </button>
      </div>
    </div>
  )
}

// ─── Scan History ─────────────────────────────────────────────────────────────

interface ScanHistoryItem {
  id: string; name: string; language: string; status: string
  filesScanned: number; linesOfCode: number; duration: number | null
  startedAt: string; criticalCount: number; highCount: number
  mediumCount: number; lowCount: number; infoCount: number
}

function ScanHistory({ onLoadScan }: { onLoadScan: (id: string) => void }) {
  const [scans, setScans] = useState<ScanHistoryItem[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/sast/scans?limit=10')
      .then(r => r.json())
      .then(d => { setScans(d.scans ?? []); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', padding: '20px 0' }}>
      Loading scan history...
    </div>
  )

  if (scans.length === 0) return (
    <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', padding: '20px 0', textAlign: 'center' }}>
      No previous scans found. Run a scan to see history here.
    </div>
  )

  return (
    <div>
      {scans.map(s => {
        const total = s.criticalCount + s.highCount + s.mediumCount + s.lowCount + s.infoCount
        return (
          <div
            key={s.id}
            onClick={() => onLoadScan(s.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 16,
              padding: '10px 14px', cursor: 'pointer',
              borderBottom: '1px solid var(--color-border)',
              transition: 'background 0.1s',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'var(--color-bg-elevated)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--color-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {s.name}
              </div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 2 }}>
                {new Date(s.startedAt).toLocaleDateString()} · {s.language} · {s.filesScanned} files · {s.linesOfCode} LOC
              </div>
            </div>

            <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
              {s.criticalCount > 0 && (
                <span className="mono" style={{ fontSize: 10, color: SEV_COLOR.CRITICAL, background: SEV_BG.CRITICAL, padding: '2px 6px', border: `1px solid ${SEV_COLOR.CRITICAL}44` }}>
                  {s.criticalCount} C
                </span>
              )}
              {s.highCount > 0 && (
                <span className="mono" style={{ fontSize: 10, color: SEV_COLOR.HIGH, background: SEV_BG.HIGH, padding: '2px 6px', border: `1px solid ${SEV_COLOR.HIGH}44` }}>
                  {s.highCount} H
                </span>
              )}
              {(s.mediumCount + s.lowCount + s.infoCount) > 0 && (
                <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', background: 'var(--color-bg-elevated)', padding: '2px 6px', border: '1px solid var(--color-border)' }}>
                  +{s.mediumCount + s.lowCount + s.infoCount}
                </span>
              )}
              {total === 0 && (
                <span className="mono" style={{ fontSize: 10, color: 'var(--color-scanner)', background: 'var(--color-scanner)15', padding: '2px 6px', border: '1px solid var(--color-scanner)44' }}>
                  CLEAN
                </span>
              )}
            </div>

            <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
              {s.duration ? `${s.duration}ms` : '—'}
            </span>
          </div>
        )
      })}
    </div>
  )
}

// ─── Multi-file input ─────────────────────────────────────────────────────────

interface FileEntry { path: string; content: string }

function MultiFileInput({
  files, setFiles,
}: {
  files: FileEntry[]
  setFiles: React.Dispatch<React.SetStateAction<FileEntry[]>>
}) {
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files
    if (!uploadedFiles) return

    const newFiles: FileEntry[] = []
    let loaded = 0
    Array.from(uploadedFiles).forEach(file => {
      const reader = new FileReader()
      reader.onload = ev => {
        newFiles.push({
          path: file.webkitRelativePath || file.name,
          content: ev.target?.result as string ?? '',
        })
        loaded++
        if (loaded === uploadedFiles.length) {
          setFiles(prev => [...prev, ...newFiles])
        }
      }
      reader.readAsText(file)
    })
  }, [setFiles])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const items = e.dataTransfer.files
    if (!items.length) return

    const newFiles: FileEntry[] = []
    let loaded = 0
    Array.from(items).forEach(file => {
      const reader = new FileReader()
      reader.onload = ev => {
        newFiles.push({
          path: file.name,
          content: ev.target?.result as string ?? '',
        })
        loaded++
        if (loaded === items.length) {
          setFiles(prev => [...prev, ...newFiles])
        }
      }
      reader.readAsText(file)
    })
  }, [setFiles])

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center' }}>
        <button
          onClick={() => fileInputRef.current?.click()}
          className="mono"
          style={{
            padding: '6px 14px', fontSize: 10, cursor: 'pointer',
            background: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text-secondary)',
            letterSpacing: '0.08em',
          }}
        >
          + ADD FILES
        </button>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".js,.ts,.jsx,.tsx,.py,.php,.java,.go,.rb,.cs,.json,.txt,.mod,.yaml,.yml,.toml"
          onChange={handleFileUpload}
          style={{ display: 'none' }}
        />

        {files.length > 0 && (
          <>
            <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
              {files.length} file{files.length !== 1 ? 's' : ''} · {(files.reduce((a, f) => a + f.content.length, 0) / 1024).toFixed(1)} KB
            </span>
            <button
              onClick={() => setFiles([])}
              className="mono"
              style={{
                marginLeft: 'auto', padding: '4px 10px', fontSize: 10, cursor: 'pointer',
                background: 'none', border: '1px solid var(--color-border)',
                color: 'var(--color-text-dim)', letterSpacing: '0.08em',
              }}
            >
              CLEAR ALL
            </button>
          </>
        )}
      </div>

      {files.length === 0 ? (
        <div
          onDragOver={e => e.preventDefault()}
          onDrop={handleDrop}
          style={{
            border: '1px dashed var(--color-border)',
            padding: '40px 20px', textAlign: 'center',
            background: 'var(--color-bg-base)',
          }}
        >
          <div style={{ fontSize: 24, color: 'var(--color-text-dim)', marginBottom: 8 }}>↓</div>
          <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', letterSpacing: '0.06em' }}>
            Drop files here or click ADD FILES
          </div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 6, opacity: 0.6 }}>
            Supports JS, TS, PY, PHP, Java, Go, Ruby, C# + package.json, requirements.txt, go.mod
          </div>
        </div>
      ) : (
        <div style={{
          border: '1px solid var(--color-border)',
          background: 'var(--color-bg-base)',
          maxHeight: 200, overflowY: 'auto',
        }}
          onDragOver={e => e.preventDefault()}
          onDrop={handleDrop}
        >
          {files.map((f, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '6px 12px',
              borderBottom: i < files.length - 1 ? '1px solid var(--color-border)' : 'none',
            }}>
              <span className="mono" style={{ fontSize: 11, color: 'var(--color-sast)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {f.path}
              </span>
              <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', flexShrink: 0 }}>
                {(f.content.length / 1024).toFixed(1)} KB
              </span>
              <button
                onClick={() => setFiles(prev => prev.filter((_, j) => j !== i))}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--color-text-dim)', fontSize: 12, padding: '0 4px',
                }}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Compliance Panel ─────────────────────────────────────────────────────────

interface ComplianceResultData {
  framework:     string
  fullName:      string
  totalControls: number
  passedControls: number
  failedControls: number
  score:         number
  controls:      {
    control: { id: string; name: string; description: string; criticality: string }
    status:  'PASS' | 'FAIL' | 'PARTIAL' | 'N/A'
    findings: SastFindingResult[]
    highest: SastSeverity | null
  }[]
}

function CompliancePanel({ findings }: { findings: SastFindingResult[] }) {
  const [results, setResults]         = useState<ComplianceResultData[]>([])
  const [loading, setLoading]         = useState(false)
  const [expandedFw, setExpandedFw]   = useState<string | null>(null)
  const [selectedFw, setSelectedFw]   = useState<string>('ALL')

  const runCompliance = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/sast/compliance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings,
          framework: selectedFw !== 'ALL' ? selectedFw : undefined,
        }),
      })
      const data = await res.json()
      if (data.results) setResults(data.results)
    } catch { /* ignore */ }
    setLoading(false)
  }, [findings, selectedFw])

  useEffect(() => {
    if (findings.length > 0) runCompliance()
  }, [findings.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const statusColor = (s: string) =>
    s === 'PASS' ? 'var(--color-scanner)' : s === 'FAIL' ? 'var(--color-sev-critical)' : 'var(--color-sev-medium)'

  const scoreColor = (score: number) =>
    score >= 80 ? 'var(--color-scanner)' : score >= 50 ? 'var(--color-sev-medium)' : 'var(--color-sev-critical)'

  if (findings.length === 0) {
    return (
      <div className="bracket-card" style={{ padding: 40, textAlign: 'center', marginTop: 20 }}>
        <div style={{ fontSize: 36, color: 'var(--color-text-dim)', marginBottom: 12 }}>◇</div>
        <div className="mono" style={{ fontSize: 12, color: 'var(--color-text-dim)', letterSpacing: '0.08em' }}>
          Run a SAST scan first to generate compliance reports.
        </div>
        <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 8, opacity: 0.6 }}>
          Supports PCI-DSS 4.0, SOC2, OWASP ASVS, ISO 27001, HIPAA, GDPR
        </div>
      </div>
    )
  }

  return (
    <div style={{ marginTop: 20 }}>
      {/* Framework selector */}
      <div className="bracket-card" style={{ padding: 16, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <span className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-dim)', textTransform: 'uppercase' }}>
            Framework:
          </span>
          {['ALL', 'PCI-DSS', 'SOC2', 'OWASP-ASVS', 'ISO-27001', 'HIPAA', 'GDPR'].map(fw => (
            <button
              key={fw}
              onClick={() => { setSelectedFw(fw); setTimeout(runCompliance, 0) }}
              className="mono"
              style={{
                padding: '4px 12px', fontSize: 10, cursor: 'pointer',
                background: selectedFw === fw ? 'var(--color-sast)18' : 'var(--color-bg-elevated)',
                border: `1px solid ${selectedFw === fw ? 'var(--color-sast)' : 'var(--color-border)'}`,
                color: selectedFw === fw ? 'var(--color-sast)' : 'var(--color-text-dim)',
                letterSpacing: '0.06em',
              }}
            >
              {fw}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', padding: '20px 0', textAlign: 'center' }}>
          Mapping findings to compliance frameworks...
        </div>
      ) : (
        <>
          {/* Framework score cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12, marginBottom: 20 }}>
            {results.map(r => (
              <div
                key={r.framework}
                onClick={() => setExpandedFw(expandedFw === r.framework ? null : r.framework)}
                style={{
                  background: expandedFw === r.framework ? 'var(--color-bg-elevated)' : 'var(--color-bg-surface)',
                  border: `1px solid ${expandedFw === r.framework ? 'var(--color-sast)' : 'var(--color-border)'}`,
                  padding: 16, cursor: 'pointer', transition: 'all 0.15s',
                }}
              >
                <div className="mono" style={{ fontSize: 10, letterSpacing: '0.1em', color: 'var(--color-text-dim)', marginBottom: 8, textTransform: 'uppercase' }}>
                  {r.framework}
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 8 }}>
                  <span style={{ fontSize: 32, fontWeight: 700, color: scoreColor(r.score) }}>
                    {r.score}
                  </span>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>/100</span>
                </div>

                {/* Mini bar */}
                <div style={{ height: 4, background: 'var(--color-bg-base)', marginBottom: 8 }}>
                  <div style={{ height: '100%', width: `${r.score}%`, background: scoreColor(r.score), transition: 'width 0.3s' }} />
                </div>

                <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>
                  {r.passedControls} passed · {r.failedControls} failed · {r.totalControls} total
                </div>
              </div>
            ))}
          </div>

          {/* Expanded framework detail */}
          {expandedFw && (() => {
            const fw = results.find(r => r.framework === expandedFw)
            if (!fw) return null
            return (
              <div className="bracket-card" style={{ padding: 20 }}>
                <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 6 }}>
                  [ {fw.fullName} — CONTROL ASSESSMENT ]
                </div>
                <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 16 }}>
                  Score: {fw.score}/100 · {fw.passedControls} passed · {fw.failedControls} failed
                </div>

                {fw.controls.map(ca => (
                  <div
                    key={ca.control.id}
                    style={{
                      display: 'grid', gridTemplateColumns: '90px 1fr auto',
                      gap: 12, alignItems: 'start',
                      padding: '10px 0',
                      borderBottom: '1px solid var(--color-border)',
                    }}
                  >
                    <div>
                      <span className="mono" style={{
                        fontSize: 10, padding: '2px 8px',
                        background: ca.status === 'PASS' ? 'rgba(90,200,120,0.12)' : ca.status === 'FAIL' ? 'rgba(239,90,90,0.12)' : 'rgba(242,209,86,0.10)',
                        color: statusColor(ca.status),
                        border: `1px solid ${statusColor(ca.status)}44`,
                      }}>
                        {ca.status}
                      </span>
                    </div>
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: 2 }}>
                        {ca.control.id}: {ca.control.name}
                      </div>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', lineHeight: 1.5 }}>
                        {ca.control.description}
                      </div>
                      {ca.findings.length > 0 && (
                        <div className="mono" style={{ fontSize: 10, color: 'var(--color-sev-high)', marginTop: 4 }}>
                          {ca.findings.length} finding{ca.findings.length > 1 ? 's' : ''}: {ca.findings.map(f => f.ruleName).slice(0, 3).join(', ')}
                          {ca.findings.length > 3 && ` +${ca.findings.length - 3} more`}
                        </div>
                      )}
                    </div>
                    <div>
                      <span className="mono" style={{
                        fontSize: 9, color: 'var(--color-text-dim)',
                        padding: '2px 6px', border: '1px solid var(--color-border)',
                      }}>
                        {ca.control.criticality}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )
          })()}

          {/* Gap analysis summary */}
          {results.length > 0 && (
            <div className="bracket-card" style={{ padding: 20, marginTop: 16 }}>
              <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
                [ GAP ANALYSIS SUMMARY ]
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--color-scanner)' }}>
                    {results.reduce((s, r) => s + r.passedControls, 0)}
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>Controls Passing</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--color-sev-critical)' }}>
                    {results.reduce((s, r) => s + r.failedControls, 0)}
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>Controls Failing</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--color-sast)' }}>
                    {Math.round(results.reduce((s, r) => s + r.score, 0) / Math.max(results.length, 1))}%
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>Avg. Score</div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ─── Custom Rules Panel ──────────────────────────────────────────────────────

function CustomRulesPanel() {
  const [rules, setRules]           = useState<{ id: string; name: string; pattern: string; category: string; severity: SastSeverity; enabled: boolean; description: string; owasp: string; cwe: string; remediation: string; testCases: { code: string; shouldMatch: boolean; label: string }[] }[]>([])
  const [loading, setLoading]       = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [testCode, setTestCode]     = useState('')
  const [testPattern, setTestPattern] = useState('')
  const [testResult, setTestResult] = useState<{ matches: boolean; matchCount: number } | null>(null)
  const [newRule, setNewRule]        = useState({
    name: '', pattern: '', description: '', category: 'Injection', severity: 'MEDIUM' as SastSeverity,
    owasp: 'A03:2021 – Injection', cwe: 'CWE-79', remediation: '',
  })

  useEffect(() => {
    fetch('/api/sast/rules')
      .then(r => r.json())
      .then(d => { if (d.rules) setRules(d.rules); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  async function toggleRule(id: string, enabled: boolean) {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r))
    await fetch('/api/sast/rules', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, enabled }),
    }).catch(() => {})
  }

  async function testPatternClick() {
    if (!testPattern || !testCode) return
    try {
      const res = await fetch('/api/sast/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'test', pattern: testPattern, code: testCode }),
      })
      const data = await res.json()
      setTestResult(data)
    } catch { setTestResult(null) }
  }

  async function createRule() {
    if (!newRule.name || !newRule.pattern) return
    try {
      const res = await fetch('/api/sast/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule),
      })
      const data = await res.json()
      if (data.rule) {
        setRules(prev => [...prev, data.rule])
        setShowCreate(false)
        setNewRule({ name: '', pattern: '', description: '', category: 'Injection', severity: 'MEDIUM', owasp: 'A03:2021 – Injection', cwe: 'CWE-79', remediation: '' })
      }
    } catch { /* ignore */ }
  }

  async function deleteRule(id: string) {
    setRules(prev => prev.filter(r => r.id !== id))
    await fetch('/api/sast/rules', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    }).catch(() => {})
  }

  if (loading) return (
    <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', padding: '20px 0', textAlign: 'center', marginTop: 20 }}>
      Loading rules...
    </div>
  )

  return (
    <div style={{ marginTop: 20 }}>
      {/* Header */}
      <div className="bracket-card" style={{ padding: 16, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase' }}>
              [ CUSTOM RULES — {rules.length} ]
            </div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>
              55 built-in rules + {rules.filter(r => r.enabled).length} custom rules active
            </div>
          </div>
          <button
            onClick={() => setShowCreate(!showCreate)}
            className="mono"
            style={{
              padding: '8px 16px', fontSize: 10, cursor: 'pointer', letterSpacing: '0.1em',
              background: showCreate ? 'var(--color-sast)' : 'var(--color-bg-elevated)',
              border: `1px solid ${showCreate ? 'var(--color-sast)' : 'var(--color-border)'}`,
              color: showCreate ? '#0a0d0f' : 'var(--color-sast)',
              fontWeight: 600,
            }}
          >
            {showCreate ? 'CANCEL' : '+ NEW RULE'}
          </button>
        </div>
      </div>

      {/* Create rule form */}
      {showCreate && (
        <div className="bracket-card" style={{ padding: 20, marginBottom: 16 }}>
          <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 16 }}>
            [ CREATE CUSTOM RULE ]
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>Rule Name</label>
              <input value={newRule.name} onChange={e => setNewRule(p => ({ ...p, name: e.target.value }))} className="tac-input" style={{ display: 'block' }} placeholder="e.g. Detect eval() usage" />
            </div>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>CWE ID</label>
              <input value={newRule.cwe} onChange={e => setNewRule(p => ({ ...p, cwe: e.target.value }))} className="tac-input" style={{ display: 'block' }} placeholder="CWE-79" />
            </div>
          </div>

          <div style={{ marginBottom: 12 }}>
            <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>Regex Pattern</label>
            <input value={newRule.pattern} onChange={e => setNewRule(p => ({ ...p, pattern: e.target.value }))} className="tac-input" style={{ display: 'block', fontFamily: 'var(--font-mono)' }} placeholder="e.g. eval\\s*\\(" />
          </div>

          <div style={{ marginBottom: 12 }}>
            <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>Description</label>
            <textarea value={newRule.description} onChange={e => setNewRule(p => ({ ...p, description: e.target.value }))} style={{ width: '100%', height: 60, background: 'var(--color-bg-base)', border: '1px solid var(--color-border)', color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '8px 12px', resize: 'vertical', outline: 'none', boxSizing: 'border-box' }} placeholder="Describe what this rule detects..." />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>Severity</label>
              <select value={newRule.severity} onChange={e => setNewRule(p => ({ ...p, severity: e.target.value as SastSeverity }))} style={{ width: '100%', background: 'var(--color-bg-base)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '6px 10px', outline: 'none' }}>
                {SEV_ORDER.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>Category</label>
              <select value={newRule.category} onChange={e => setNewRule(p => ({ ...p, category: e.target.value }))} style={{ width: '100%', background: 'var(--color-bg-base)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '6px 10px', outline: 'none' }}>
                {['Injection', 'XSS', 'Secrets', 'Cryptography', 'Authentication', 'Authorization', 'Misconfiguration', 'Logging', 'Dependencies', 'Deserialization', 'Path Traversal', 'SSRF', 'XXE', 'Race Condition'].map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>OWASP</label>
              <select value={newRule.owasp} onChange={e => setNewRule(p => ({ ...p, owasp: e.target.value }))} style={{ width: '100%', background: 'var(--color-bg-base)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '6px 10px', outline: 'none' }}>
                {['A01:2021 – Broken Access Control', 'A02:2021 – Cryptographic Failures', 'A03:2021 – Injection', 'A04:2021 – Insecure Design', 'A05:2021 – Security Misconfiguration', 'A06:2021 – Vulnerable Components', 'A07:2021 – Auth Failures', 'A08:2021 – Software Integrity', 'A09:2021 – Logging Failures', 'A10:2021 – SSRF'].map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            </div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 4, letterSpacing: '0.1em', textTransform: 'uppercase' }}>Remediation</label>
            <input value={newRule.remediation} onChange={e => setNewRule(p => ({ ...p, remediation: e.target.value }))} className="tac-input" style={{ display: 'block' }} placeholder="How to fix this issue..." />
          </div>

          <button
            onClick={createRule}
            disabled={!newRule.name || !newRule.pattern}
            className="mono"
            style={{
              padding: '10px 24px', fontSize: 11, cursor: newRule.name && newRule.pattern ? 'pointer' : 'not-allowed',
              background: newRule.name && newRule.pattern ? 'var(--color-sast)' : 'var(--color-bg-elevated)',
              color: newRule.name && newRule.pattern ? '#0a0d0f' : 'var(--color-text-dim)',
              border: 'none', fontWeight: 700, letterSpacing: '0.1em',
            }}
          >
            CREATE RULE
          </button>
        </div>
      )}

      {/* Pattern tester */}
      <div className="bracket-card" style={{ padding: 16, marginBottom: 16 }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: 10 }}>
          Pattern Tester
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 10, alignItems: 'end' }}>
          <div>
            <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', marginBottom: 4 }}>REGEX PATTERN</div>
            <input value={testPattern} onChange={e => setTestPattern(e.target.value)} className="tac-input" style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: 11 }} placeholder="e.g. eval\\s*\\(" />
          </div>
          <div>
            <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', marginBottom: 4 }}>TEST CODE</div>
            <input value={testCode} onChange={e => setTestCode(e.target.value)} className="tac-input" style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: 11 }} placeholder="e.g. eval(userInput)" />
          </div>
          <button onClick={testPatternClick} className="mono" style={{ padding: '8px 16px', fontSize: 10, cursor: 'pointer', background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', color: 'var(--color-sast)', letterSpacing: '0.1em', fontWeight: 600, whiteSpace: 'nowrap' }}>
            TEST
          </button>
        </div>
        {testResult && (
          <div className="mono" style={{ fontSize: 10, marginTop: 8, padding: '6px 10px', background: testResult.matches ? 'rgba(90,200,120,0.08)' : 'rgba(239,90,90,0.08)', border: `1px solid ${testResult.matches ? 'var(--color-scanner)44' : 'var(--color-sev-critical)44'}`, color: testResult.matches ? 'var(--color-scanner)' : 'var(--color-sev-critical)' }}>
            {testResult.matches ? `MATCH — ${testResult.matchCount} occurrence${testResult.matchCount > 1 ? 's' : ''} found` : 'NO MATCH'}
          </div>
        )}
      </div>

      {/* Rules list */}
      <div className="bracket-card" style={{ padding: 20 }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
          [ ACTIVE CUSTOM RULES ]
        </div>
        {rules.length === 0 ? (
          <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', textAlign: 'center', padding: '20px 0' }}>
            No custom rules defined. Click &quot;+ NEW RULE&quot; to create one.
          </div>
        ) : (
          <div>
            {rules.map(rule => (
              <div key={rule.id} style={{
                display: 'grid', gridTemplateColumns: '40px 1fr auto',
                gap: 12, alignItems: 'center', padding: '12px 0',
                borderBottom: '1px solid var(--color-border)',
                opacity: rule.enabled ? 1 : 0.5,
              }}>
                <button
                  onClick={() => toggleRule(rule.id, !rule.enabled)}
                  style={{
                    width: 32, height: 18, cursor: 'pointer',
                    background: rule.enabled ? 'var(--color-sast)' : 'var(--color-bg-elevated)',
                    border: `1px solid ${rule.enabled ? 'var(--color-sast)' : 'var(--color-border)'}`,
                    borderRadius: 9, position: 'relative', padding: 0,
                  }}
                >
                  <div style={{
                    width: 12, height: 12, borderRadius: '50%',
                    background: rule.enabled ? '#0a0d0f' : 'var(--color-text-dim)',
                    position: 'absolute', top: 2,
                    left: rule.enabled ? 16 : 2,
                    transition: 'left 0.15s',
                  }} />
                </button>

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                    <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-primary)' }}>{rule.name}</span>
                    <span className="mono" style={{ fontSize: 9, padding: '1px 6px', background: SEV_BG[rule.severity], color: SEV_COLOR[rule.severity], border: `1px solid ${SEV_COLOR[rule.severity]}44` }}>
                      {rule.severity}
                    </span>
                    <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', padding: '1px 6px', border: '1px solid var(--color-border)' }}>
                      {rule.category}
                    </span>
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
                    {rule.id} · {rule.cwe} · Pattern: <span style={{ color: 'var(--color-sast)' }}>{rule.pattern.slice(0, 60)}{rule.pattern.length > 60 ? '...' : ''}</span>
                  </div>
                </div>

                <button onClick={() => deleteRule(rule.id)} className="mono" style={{ padding: '4px 10px', fontSize: 10, cursor: 'pointer', background: 'none', border: '1px solid var(--color-border)', color: 'var(--color-text-dim)', letterSpacing: '0.06em' }}>
                  DELETE
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Trends Dashboard ────────────────────────────────────────────────────────

interface TrendData {
  findingsOverTime: { date: string; critical: number; high: number; medium: number; low: number; info: number; total: number }[]
  topVulnTypes: { name: string; count: number; severity: string; cwe: string }[]
  severityDistribution: { critical: number; high: number; medium: number; low: number; info: number }
  categoryBreakdown: { category: string; count: number }[]
  summary: {
    totalScans: number; totalFindings: number; avgFindingsPerScan: number
    remediatedCount: number; falsePositiveCount: number; avgScanDuration: number
    criticalOpen: number; highOpen: number
  }
}

function TrendsDashboard() {
  const [data, setData]       = useState<TrendData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/sast/trends')
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', padding: '40px 0', textAlign: 'center', marginTop: 20 }}>
      Loading analytics...
    </div>
  )

  if (!data) return null

  const maxDaily = Math.max(...data.findingsOverTime.map(d => d.total), 1)
  const maxVuln = Math.max(...data.topVulnTypes.map(v => v.count), 1)
  const maxCat = Math.max(...data.categoryBreakdown.map(c => c.count), 1)
  const totalSev = data.severityDistribution.critical + data.severityDistribution.high + data.severityDistribution.medium + data.severityDistribution.low + data.severityDistribution.info || 1

  return (
    <div style={{ marginTop: 20 }}>
      {/* KPI cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'TOTAL SCANS', value: data.summary.totalScans, color: 'var(--color-sast)' },
          { label: 'TOTAL FINDINGS', value: data.summary.totalFindings, color: 'var(--color-text-primary)' },
          { label: 'CRITICAL OPEN', value: data.summary.criticalOpen, color: 'var(--color-sev-critical)' },
          { label: 'REMEDIATED', value: data.summary.remediatedCount, color: 'var(--color-scanner)' },
        ].map(kpi => (
          <div key={kpi.label} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: 16, textAlign: 'center' }}>
            <div className="mono" style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--color-text-dim)', marginBottom: 6, textTransform: 'uppercase' }}>
              {kpi.label}
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color: kpi.color }}>
              {kpi.value}
            </div>
          </div>
        ))}
      </div>

      {/* Secondary KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'AVG FINDINGS/SCAN', value: data.summary.avgFindingsPerScan },
          { label: 'FALSE POSITIVES', value: data.summary.falsePositiveCount },
          { label: 'AVG SCAN TIME', value: `${data.summary.avgScanDuration}ms` },
        ].map(kpi => (
          <div key={kpi.label} style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', padding: 12, textAlign: 'center' }}>
            <div className="mono" style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--color-text-dim)', marginBottom: 4, textTransform: 'uppercase' }}>
              {kpi.label}
            </div>
            <div style={{ fontSize: 20, fontWeight: 600, color: 'var(--color-text-secondary)' }}>
              {kpi.value}
            </div>
          </div>
        ))}
      </div>

      {/* Findings over time (bar chart) */}
      <div className="bracket-card" style={{ padding: 20, marginBottom: 16 }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 16 }}>
          [ FINDINGS OVER TIME — LAST 30 DAYS ]
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 120 }}>
          {data.findingsOverTime.map((d, i) => {
            const cH = (d.critical / maxDaily) * 100
            const hH = (d.high / maxDaily) * 100
            const mH = (d.medium / maxDaily) * 100
            const lH = ((d.low + d.info) / maxDaily) * 100
            return (
              <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: '100%' }} title={`${d.date}: C=${d.critical} H=${d.high} M=${d.medium} L=${d.low}`}>
                {d.critical > 0 && <div style={{ height: `${cH}%`, background: 'var(--color-sev-critical)', minHeight: d.critical > 0 ? 2 : 0 }} />}
                {d.high > 0 && <div style={{ height: `${hH}%`, background: 'var(--color-sev-high)', minHeight: d.high > 0 ? 2 : 0 }} />}
                {d.medium > 0 && <div style={{ height: `${mH}%`, background: 'var(--color-sev-medium)', minHeight: d.medium > 0 ? 2 : 0 }} />}
                {(d.low + d.info) > 0 && <div style={{ height: `${lH}%`, background: 'var(--color-sev-low)', minHeight: (d.low + d.info) > 0 ? 2 : 0 }} />}
                {d.total === 0 && <div style={{ height: 1, background: 'var(--color-border)' }} />}
              </div>
            )
          })}
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
          <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>
            {data.findingsOverTime[0]?.date}
          </span>
          <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>
            {data.findingsOverTime[data.findingsOverTime.length - 1]?.date}
          </span>
        </div>
        {/* Legend */}
        <div style={{ display: 'flex', gap: 16, marginTop: 10, justifyContent: 'center' }}>
          {[
            { label: 'Critical', color: 'var(--color-sev-critical)' },
            { label: 'High', color: 'var(--color-sev-high)' },
            { label: 'Medium', color: 'var(--color-sev-medium)' },
            { label: 'Low/Info', color: 'var(--color-sev-low)' },
          ].map(l => (
            <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <div style={{ width: 8, height: 8, background: l.color }} />
              <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>{l.label}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* Severity distribution */}
        <div className="bracket-card" style={{ padding: 20 }}>
          <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
            [ SEVERITY DISTRIBUTION ]
          </div>
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
            const count = data.severityDistribution[sev]
            const pct = Math.round((count / totalSev) * 100)
            return (
              <div key={sev} style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span className="mono" style={{ fontSize: 10, color: SEV_COLOR[sev.toUpperCase() as SastSeverity], textTransform: 'uppercase' }}>{sev}</span>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{count} ({pct}%)</span>
                </div>
                <div style={{ height: 6, background: 'var(--color-bg-base)' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: SEV_COLOR[sev.toUpperCase() as SastSeverity], transition: 'width 0.3s' }} />
                </div>
              </div>
            )
          })}
        </div>

        {/* Category breakdown */}
        <div className="bracket-card" style={{ padding: 20 }}>
          <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
            [ CATEGORY BREAKDOWN ]
          </div>
          {data.categoryBreakdown.slice(0, 8).map(cat => (
            <div key={cat.category} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-secondary)' }}>{cat.category}</span>
                <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>{cat.count}</span>
              </div>
              <div style={{ height: 6, background: 'var(--color-bg-base)' }}>
                <div style={{ height: '100%', width: `${(cat.count / maxCat) * 100}%`, background: 'var(--color-sast)', opacity: 0.6, transition: 'width 0.3s' }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Top vulnerability types */}
      <div className="bracket-card" style={{ padding: 20 }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
          [ TOP VULNERABILITY TYPES ]
        </div>
        {data.topVulnTypes.map((v, i) => (
          <div key={i} style={{ display: 'grid', gridTemplateColumns: '24px 1fr 60px 80px', gap: 10, alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--color-border)' }}>
            <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', textAlign: 'right' }}>#{i + 1}</span>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.name}</div>
              <div style={{ height: 3, background: 'var(--color-bg-base)', marginTop: 4 }}>
                <div style={{ height: '100%', width: `${(v.count / maxVuln) * 100}%`, background: SEV_COLOR[v.severity as SastSeverity] || 'var(--color-sast)' }} />
              </div>
            </div>
            <span className="mono" style={{ fontSize: 10, color: SEV_COLOR[v.severity as SastSeverity] || 'var(--color-text-dim)', textAlign: 'right' }}>{v.severity}</span>
            <span className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', textAlign: 'right' }}>{v.count} hits · {v.cwe}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Report Panel ────────────────────────────────────────────────────────────

interface ReportData {
  title: string
  generatedAt: string
  scanInfo: { scanId: string; scanName: string; language: string; filesScanned: number; linesOfCode: number; duration: number }
  riskScore: { overall: number; grade: string; breakdown: Record<string, number> }
  executiveSummary: string
  topRisks: { rank: number; finding: string; severity: string; category: string; cwe: string; impact: string; remediation: string; effort: string }[]
  remediationPlan: { priority: number; category: string; action: string; findingCount: number; effort: string; impact: string }[]
  compliance?: { framework: string; score: number; status: string; failedControls: number }[]
}

function ReportPanel({ scanResult }: { scanResult: SastScanResult | null }) {
  const [report, setReport]     = useState<ReportData | null>(null)
  const [loading, setLoading]   = useState(false)
  const [inclCompliance, setInclCompliance] = useState(true)

  async function generateReport() {
    if (!scanResult) return
    setLoading(true)
    try {
      const res = await fetch('/api/sast/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan: scanResult, includeCompliance: inclCompliance }),
      })
      const data = await res.json()
      if (data.report) setReport(data.report)
    } catch { /* ignore */ }
    setLoading(false)
  }

  const gradeColor = (g: string) =>
    g === 'A' ? 'var(--color-scanner)' : g === 'B' ? 'var(--color-sev-low)' : g === 'C' ? 'var(--color-sev-medium)' : g === 'D' ? 'var(--color-sev-high)' : 'var(--color-sev-critical)'

  const effortColor = (e: string) =>
    e === 'LOW' ? 'var(--color-scanner)' : e === 'MEDIUM' ? 'var(--color-sev-medium)' : 'var(--color-sev-high)'

  if (!scanResult) {
    return (
      <div className="bracket-card" style={{ padding: 40, textAlign: 'center', marginTop: 20 }}>
        <div style={{ fontSize: 36, color: 'var(--color-text-dim)', marginBottom: 12 }}>◈</div>
        <div className="mono" style={{ fontSize: 12, color: 'var(--color-text-dim)', letterSpacing: '0.08em' }}>
          Run a SAST scan first to generate an executive security report.
        </div>
      </div>
    )
  }

  return (
    <div style={{ marginTop: 20 }}>
      {/* Generate button */}
      {!report && (
        <div className="bracket-card" style={{ padding: 24, textAlign: 'center' }}>
          <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 16 }}>
            [ EXECUTIVE SECURITY REPORT ]
          </div>
          <div className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 16 }}>
            Generate a comprehensive security assessment report with risk scoring, remediation priorities, and compliance mapping.
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 12, alignItems: 'center', marginBottom: 16 }}>
            <button
              onClick={() => setInclCompliance(!inclCompliance)}
              className="mono"
              style={{
                padding: '6px 14px', fontSize: 10, cursor: 'pointer',
                background: inclCompliance ? 'var(--color-sast)18' : 'var(--color-bg-elevated)',
                border: `1px solid ${inclCompliance ? 'var(--color-sast)' : 'var(--color-border)'}`,
                color: inclCompliance ? 'var(--color-sast)' : 'var(--color-text-dim)',
              }}
            >
              {inclCompliance ? '◉ Include Compliance' : '○ Include Compliance'}
            </button>
          </div>
          <button
            onClick={generateReport}
            disabled={loading}
            className="mono"
            style={{
              padding: '12px 32px', fontSize: 12, cursor: loading ? 'not-allowed' : 'pointer',
              background: loading ? 'var(--color-bg-elevated)' : 'var(--color-sast)',
              color: loading ? 'var(--color-text-dim)' : '#0a0d0f',
              border: 'none', fontWeight: 700, letterSpacing: '0.12em',
            }}
          >
            {loading ? 'GENERATING...' : 'GENERATE REPORT'}
          </button>
        </div>
      )}

      {/* Report content */}
      {report && (
        <div>
          {/* Report header */}
          <div className="bracket-card" style={{ padding: 24, marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
              <div>
                <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 8 }}>
                  [ EXECUTIVE SECURITY REPORT ]
                </div>
                <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0, marginBottom: 8 }}>
                  {report.title}
                </h2>
                <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)' }}>
                  Generated: {new Date(report.generatedAt).toLocaleString()} · {report.scanInfo.language} · {report.scanInfo.filesScanned} files · {report.scanInfo.linesOfCode.toLocaleString()} LOC
                </div>
              </div>

              {/* Risk grade */}
              <div style={{ textAlign: 'center', padding: '8px 20px', border: `2px solid ${gradeColor(report.riskScore.grade)}`, minWidth: 80 }}>
                <div style={{ fontSize: 42, fontWeight: 800, color: gradeColor(report.riskScore.grade), lineHeight: 1 }}>
                  {report.riskScore.grade}
                </div>
                <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', marginTop: 4 }}>
                  RISK: {report.riskScore.overall}/100
                </div>
              </div>
            </div>
          </div>

          {/* Executive summary */}
          <div className="bracket-card" style={{ padding: 20, marginBottom: 16 }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 10 }}>
              [ EXECUTIVE SUMMARY ]
            </div>
            <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: 0 }}>
              {report.executiveSummary}
            </p>
          </div>

          {/* Risk breakdown */}
          <div className="bracket-card" style={{ padding: 20, marginBottom: 16 }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
              [ RISK BREAKDOWN BY CATEGORY ]
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              {Object.entries(report.riskScore.breakdown).map(([cat, score]) => (
                <div key={cat} style={{ padding: 12, background: 'var(--color-bg-base)', border: '1px solid var(--color-border)' }}>
                  <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>{cat}</div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                    <span style={{ fontSize: 22, fontWeight: 700, color: score > 60 ? 'var(--color-sev-critical)' : score > 30 ? 'var(--color-sev-medium)' : 'var(--color-scanner)' }}>{score}</span>
                    <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>/100</span>
                  </div>
                  <div style={{ height: 4, background: 'var(--color-bg-elevated)', marginTop: 6 }}>
                    <div style={{ height: '100%', width: `${score}%`, background: score > 60 ? 'var(--color-sev-critical)' : score > 30 ? 'var(--color-sev-medium)' : 'var(--color-scanner)' }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top risks */}
          <div className="bracket-card" style={{ padding: 20, marginBottom: 16 }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
              [ TOP 5 SECURITY RISKS ]
            </div>
            {report.topRisks.map(risk => (
              <div key={risk.rank} style={{ padding: '14px 0', borderBottom: '1px solid var(--color-border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                  <span className="mono" style={{ fontSize: 18, fontWeight: 700, color: 'var(--color-text-dim)', width: 24 }}>
                    {risk.rank}
                  </span>
                  <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--color-text-primary)', flex: 1 }}>
                    {risk.finding}
                  </span>
                  <span className="mono" style={{ fontSize: 9, padding: '2px 8px', background: SEV_BG[risk.severity as SastSeverity], color: SEV_COLOR[risk.severity as SastSeverity], border: `1px solid ${SEV_COLOR[risk.severity as SastSeverity]}44` }}>
                    {risk.severity}
                  </span>
                  <span className="mono" style={{ fontSize: 9, color: effortColor(risk.effort), padding: '2px 8px', border: `1px solid ${effortColor(risk.effort)}44` }}>
                    {risk.effort} EFFORT
                  </span>
                </div>
                <div style={{ marginLeft: 34 }}>
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 4, lineHeight: 1.5 }}>
                    <strong style={{ color: 'var(--color-text-secondary)' }}>Impact:</strong> {risk.impact}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', lineHeight: 1.5 }}>
                    <strong style={{ color: 'var(--color-text-secondary)' }}>Fix:</strong> {risk.remediation}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Remediation plan */}
          <div className="bracket-card" style={{ padding: 20, marginBottom: 16 }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
              [ REMEDIATION ROADMAP ]
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '40px 1fr 80px 80px 80px', gap: 8, alignItems: 'center', padding: '8px 0', borderBottom: '2px solid var(--color-border)' }}>
              <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>PRI</span>
              <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>ACTION</span>
              <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', textAlign: 'center' }}>FINDINGS</span>
              <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', textAlign: 'center' }}>EFFORT</span>
              <span className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', textAlign: 'center' }}>IMPACT</span>
            </div>
            {report.remediationPlan.map((item, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '40px 1fr 80px 80px 80px', gap: 8, alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--color-border)' }}>
                <span className="mono" style={{ fontSize: 14, fontWeight: 700, color: item.priority === 1 ? 'var(--color-sev-critical)' : item.priority === 2 ? 'var(--color-sev-high)' : 'var(--color-sev-medium)', textAlign: 'center' }}>
                  P{item.priority}
                </span>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 500, color: 'var(--color-text-primary)', marginBottom: 2 }}>{item.category}</div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', lineHeight: 1.4 }}>{item.action}</div>
                </div>
                <span className="mono" style={{ fontSize: 11, color: 'var(--color-text-secondary)', textAlign: 'center' }}>{item.findingCount}</span>
                <span className="mono" style={{ fontSize: 10, color: effortColor(item.effort), textAlign: 'center' }}>{item.effort}</span>
                <span className="mono" style={{ fontSize: 10, color: item.impact === 'CRITICAL' ? 'var(--color-sev-critical)' : item.impact === 'HIGH' ? 'var(--color-sev-high)' : 'var(--color-sev-medium)', textAlign: 'center' }}>{item.impact}</span>
              </div>
            ))}
          </div>

          {/* Compliance summary (if included) */}
          {report.compliance && report.compliance.length > 0 && (
            <div className="bracket-card" style={{ padding: 20, marginBottom: 16 }}>
              <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
                [ COMPLIANCE POSTURE ]
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
                {report.compliance.map(c => (
                  <div key={c.framework} style={{ padding: 14, background: 'var(--color-bg-base)', border: '1px solid var(--color-border)' }}>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 6, letterSpacing: '0.06em' }}>{c.framework}</div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                      <span style={{ fontSize: 24, fontWeight: 700, color: c.score >= 80 ? 'var(--color-scanner)' : c.score >= 50 ? 'var(--color-sev-medium)' : 'var(--color-sev-critical)' }}>
                        {c.score}%
                      </span>
                      <span className="mono" style={{ fontSize: 9, padding: '1px 6px', color: c.status === 'PASS' ? 'var(--color-scanner)' : c.status === 'FAIL' ? 'var(--color-sev-critical)' : 'var(--color-sev-medium)', border: `1px solid ${c.status === 'PASS' ? 'var(--color-scanner)44' : c.status === 'FAIL' ? 'var(--color-sev-critical)44' : 'var(--color-sev-medium)44'}` }}>
                        {c.status}
                      </span>
                    </div>
                    {c.failedControls > 0 && (
                      <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', marginTop: 4 }}>
                        {c.failedControls} controls need attention
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Regenerate button */}
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 8 }}>
            <button onClick={generateReport} className="mono" style={{ padding: '8px 20px', fontSize: 10, cursor: 'pointer', background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', color: 'var(--color-sast)', letterSpacing: '0.1em' }}>
              REGENERATE
            </button>
            <button onClick={() => setReport(null)} className="mono" style={{ padding: '8px 20px', fontSize: 10, cursor: 'pointer', background: 'none', border: '1px solid var(--color-border)', color: 'var(--color-text-dim)', letterSpacing: '0.1em' }}>
              CLOSE
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function SastPage() {
  const [tab, setTab]           = useState<'paste' | 'demo' | 'multifile'>('demo')
  const [panel, setPanel]       = useState<'scan' | 'history' | 'cicd' | 'compliance' | 'rules' | 'trends' | 'report'>('scan')
  const [scanName, setScanName] = useState('My Code Review')
  const [code, setCode]         = useState('')
  const [filePath, setFilePath] = useState('src/index.js')
  const [demoLang, setDemoLang] = useState<keyof typeof DEMO_SNIPPETS>('nodejs')
  const [scanning, setScanning] = useState(false)
  const [result, setResult]     = useState<SastScanResult | null>(null)
  const [error, setError]       = useState('')
  const [filterSev, setFilterSev] = useState<SastSeverity | 'ALL'>('ALL')
  const [filterCat, setFilterCat] = useState('ALL')
  const [hideFP, setHideFP]     = useState(false)
  const [multiFiles, setMultiFiles] = useState<FileEntry[]>([])
  const dragRef = useRef<HTMLTextAreaElement>(null)

  const categories = result
    ? ['ALL', ...Array.from(new Set(result.findings.map(f => f.category)))]
    : ['ALL']

  const filteredFindings = result?.findings.filter(f => {
    if (filterSev !== 'ALL' && f.severity !== filterSev) return false
    if (filterCat !== 'ALL' && f.category !== filterCat) return false
    if (hideFP && f.falsePositive) return false
    return true
  }) ?? []

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (!file) return
    setFilePath(file.name)
    const reader = new FileReader()
    reader.onload = ev => setCode(ev.target?.result as string ?? '')
    reader.readAsText(file)
  }, [])

  function toggleFalsePositive(findingId: string, fp: boolean) {
    if (!result) return
    // Optimistic UI update
    setResult(prev => {
      if (!prev) return prev
      return {
        ...prev,
        findings: prev.findings.map(f =>
          f.id === findingId ? { ...f, falsePositive: fp, status: fp ? 'ACKNOWLEDGED' : 'OPEN' } : f
        ),
      }
    })
    // Fire-and-forget API call (works when DB is available)
    fetch(`/api/sast/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ falsePositive: fp, status: fp ? 'ACKNOWLEDGED' : 'OPEN' }),
    }).catch(() => {})
  }

  async function runScan() {
    setError('')
    setResult(null)
    setScanning(true)

    let files: { path: string; content: string }[]

    if (tab === 'demo') {
      files = DEMO_SNIPPETS[demoLang]
    } else if (tab === 'multifile') {
      files = multiFiles
    } else {
      files = [{ path: filePath, content: code }]
    }

    const name = tab === 'demo'
      ? `Demo Scan — ${demoLang === 'nodejs' ? 'Node.js' : demoLang === 'python' ? 'Python' : 'PHP'}`
      : scanName

    if (files.length === 0 || (tab === 'paste' && !code.trim())) {
      setError('No files to scan')
      setScanning(false)
      return
    }

    try {
      const res  = await fetch('/api/sast/scan', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name, files }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error ?? 'Scan failed'); return }
      setResult(data)
      setPanel('scan')
    } catch {
      setError('Network error — check dev server')
    } finally {
      setScanning(false)
    }
  }

  async function loadScanFromHistory(scanId: string) {
    try {
      const res  = await fetch(`/api/sast/scan/${scanId}`)
      const data = await res.json()
      if (!res.ok) { setError(data.error ?? 'Failed to load scan'); return }
      // Transform DB scan into SastScanResult shape
      const findings: SastFindingResult[] = (data.findings ?? []).map((f: Record<string, unknown>) => ({
        ...f,
        detectedAt: typeof f.detectedAt === 'string' ? f.detectedAt : new Date(f.detectedAt as string).toISOString(),
      }))
      setResult({
        id:           data.id,
        name:         data.name,
        language:     data.language,
        linesOfCode:  data.linesOfCode,
        filesScanned: data.filesScanned,
        status:       data.status,
        duration:     data.duration,
        startedAt:    data.startedAt,
        completedAt:  data.completedAt,
        summary: {
          critical: data.criticalCount,
          high:     data.highCount,
          medium:   data.mediumCount,
          low:      data.lowCount,
          info:     data.infoCount,
          total:    findings.length,
        },
        findings,
        owaspCoverage: [], // will be rebuilt below
      })
      setPanel('scan')
    } catch {
      setError('Failed to load scan from history')
    }
  }

  // Compute active (non-FP) summary
  const activeSummary = result ? {
    critical: result.findings.filter(f => !f.falsePositive && f.severity === 'CRITICAL').length,
    high:     result.findings.filter(f => !f.falsePositive && f.severity === 'HIGH').length,
    medium:   result.findings.filter(f => !f.falsePositive && f.severity === 'MEDIUM').length,
    low:      result.findings.filter(f => !f.falsePositive && f.severity === 'LOW').length,
    info:     result.findings.filter(f => !f.falsePositive && f.severity === 'INFO').length,
    fpCount:  result.findings.filter(f => f.falsePositive).length,
  } : null

  return (
    <div style={{ padding: 32, maxWidth: 1400 }}>

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: '0.16em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 8 }}>
          [ STATIC ANALYSIS ]
        </div>
        <h1 className="display" style={{ fontSize: 26, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0, marginBottom: 6 }}>
          SAST Scanner
        </h1>
        <p style={{ fontSize: 14, color: 'var(--color-text-secondary)', margin: 0 }}>
          67 rules (55 regex + 12 AST) · OWASP Top 10 · 8 languages · CWE mapped · Secret detection · SCA · AI enrichment
        </p>
      </div>

      {/* Top panel tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 0, borderBottom: '1px solid var(--color-border)' }}>
        {([
          { id: 'scan', label: 'SCANNER' },
          { id: 'history', label: 'HISTORY' },
          { id: 'compliance', label: 'COMPLIANCE' },
          { id: 'trends', label: 'TRENDS' },
          { id: 'rules', label: 'RULES' },
          { id: 'cicd', label: 'CI/CD' },
          { id: 'report', label: 'REPORT' },
        ] as const).map(p => (
          <button
            key={p.id}
            onClick={() => setPanel(p.id)}
            className="mono"
            style={{
              padding: '10px 20px', fontSize: 11, letterSpacing: '0.12em',
              textTransform: 'uppercase', cursor: 'pointer',
              background: 'none', border: 'none',
              borderBottom: panel === p.id ? '2px solid var(--color-sast)' : '2px solid transparent',
              color: panel === p.id ? 'var(--color-sast)' : 'var(--color-text-secondary)',
              marginBottom: -1,
            }}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Panel: Scan History */}
      {panel === 'history' && (
        <div className="bracket-card" style={{ padding: 20, marginTop: 20 }}>
          <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
            [ RECENT SCANS ]
          </div>
          <ScanHistory onLoadScan={loadScanFromHistory} />
        </div>
      )}

      {/* Panel: CI/CD */}
      {panel === 'cicd' && (
        <div style={{ marginTop: 20 }}>
          <CiCdPanel />
        </div>
      )}

      {/* Panel: Compliance */}
      {panel === 'compliance' && (
        <CompliancePanel findings={result?.findings ?? []} />
      )}

      {/* Panel: Custom Rules */}
      {panel === 'rules' && (
        <CustomRulesPanel />
      )}

      {/* Panel: Trends */}
      {panel === 'trends' && (
        <TrendsDashboard />
      )}

      {/* Panel: Report */}
      {panel === 'report' && (
        <ReportPanel scanResult={result} />
      )}

      {/* Panel: Scanner */}
      {panel === 'scan' && (
        <>
          {/* Input panel */}
          <div className="bracket-card" style={{ padding: 24, marginTop: 20, marginBottom: 24 }}>

            {/* Tabs */}
            <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--color-border)' }}>
              {([
                { id: 'demo', label: 'Demo Code' },
                { id: 'paste', label: 'Paste Code' },
                { id: 'multifile', label: 'Multi-File Upload' },
              ] as const).map(t => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className="mono"
                  style={{
                    padding: '8px 20px', fontSize: 11, letterSpacing: '0.12em',
                    textTransform: 'uppercase', cursor: 'pointer',
                    background: 'none', border: 'none',
                    borderBottom: tab === t.id ? '2px solid var(--color-sast)' : '2px solid transparent',
                    color: tab === t.id ? 'var(--color-sast)' : 'var(--color-text-secondary)',
                    marginBottom: -1,
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 20, alignItems: 'start' }}>
              <div>
                {tab === 'demo' ? (
                  <div>
                    <div className="mono" style={{ fontSize: 11, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: 8 }}>
                      Select vulnerable sample
                    </div>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                      {(Object.keys(DEMO_SNIPPETS) as Array<keyof typeof DEMO_SNIPPETS>).map(lang => (
                        <button
                          key={lang}
                          onClick={() => setDemoLang(lang)}
                          style={{
                            padding: '8px 18px', cursor: 'pointer',
                            background: demoLang === lang ? 'var(--color-sast)22' : 'var(--color-bg-elevated)',
                            border: `1px solid ${demoLang === lang ? 'var(--color-sast)' : 'var(--color-border)'}`,
                            color: demoLang === lang ? 'var(--color-sast)' : 'var(--color-text-secondary)',
                            fontFamily: 'var(--font-mono)', fontSize: 12,
                          }}
                        >
                          {lang === 'nodejs' ? 'Node.js' : lang === 'python' ? 'Python' : 'PHP'}
                        </button>
                      ))}
                    </div>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 8 }}>
                      {DEMO_SNIPPETS[demoLang].length} file{DEMO_SNIPPETS[demoLang].length > 1 ? 's' : ''}: {DEMO_SNIPPETS[demoLang].map(f => f.path).join(', ')}
                    </div>
                    <pre style={{
                      background: 'var(--color-bg-base)', border: '1px solid var(--color-border)',
                      padding: '14px 16px', fontSize: 11, fontFamily: 'var(--font-mono)',
                      color: 'var(--color-text-secondary)', height: 180, overflowY: 'auto',
                      lineHeight: 1.6,
                    }}>
                      {DEMO_SNIPPETS[demoLang][0].content.slice(0, 600)}...
                    </pre>
                  </div>
                ) : tab === 'multifile' ? (
                  <div>
                    <div style={{ display: 'flex', gap: 12, marginBottom: 10 }}>
                      <div style={{ flex: 1 }}>
                        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: 5 }}>
                          Scan Name
                        </div>
                        <input
                          value={scanName}
                          onChange={e => setScanName(e.target.value)}
                          className="tac-input"
                          style={{ display: 'block' }}
                          placeholder="e.g. project-audit-v2"
                        />
                      </div>
                    </div>
                    <MultiFileInput files={multiFiles} setFiles={setMultiFiles} />
                  </div>
                ) : (
                  <div>
                    <div style={{ display: 'flex', gap: 12, marginBottom: 10 }}>
                      <div style={{ flex: 1 }}>
                        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: 5 }}>
                          Scan Name
                        </div>
                        <input
                          value={scanName}
                          onChange={e => setScanName(e.target.value)}
                          className="tac-input"
                          style={{ display: 'block' }}
                          placeholder="e.g. auth-service review"
                        />
                      </div>
                      <div style={{ flex: 1 }}>
                        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: 5 }}>
                          File Path
                        </div>
                        <input
                          value={filePath}
                          onChange={e => setFilePath(e.target.value)}
                          className="tac-input"
                          style={{ display: 'block' }}
                          placeholder="src/api/user.js"
                        />
                      </div>
                    </div>
                    <textarea
                      ref={dragRef}
                      value={code}
                      onChange={e => setCode(e.target.value)}
                      onDragOver={e => e.preventDefault()}
                      onDrop={handleFileDrop}
                      placeholder="Paste source code here, or drag & drop a file..."
                      style={{
                        width: '100%', height: 220, background: 'var(--color-bg-base)',
                        border: '1px solid var(--color-border)', color: 'var(--color-text-primary)',
                        fontFamily: 'var(--font-mono)', fontSize: 12, padding: '12px 14px',
                        resize: 'vertical', outline: 'none', lineHeight: 1.6,
                        boxSizing: 'border-box',
                      }}
                    />
                  </div>
                )}
              </div>

              {/* Run button */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 160 }}>
                <button
                  onClick={runScan}
                  disabled={scanning || (tab === 'paste' && !code.trim()) || (tab === 'multifile' && multiFiles.length === 0)}
                  style={{
                    background: scanning ? 'var(--color-bg-elevated)' : 'var(--color-sast)',
                    color: scanning ? 'var(--color-text-dim)' : '#0a0d0f',
                    border: 'none', padding: '13px 20px', cursor: scanning ? 'not-allowed' : 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
                    letterSpacing: '0.12em', textTransform: 'uppercase', whiteSpace: 'nowrap',
                  }}
                >
                  {scanning ? (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="dot-live" style={{ background: 'var(--color-sast)' }} />
                      SCANNING...
                    </span>
                  ) : '⚡ RUN SAST SCAN'}
                </button>

                {result && (
                  <div style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', textAlign: 'center' }}>
                    {result.linesOfCode.toLocaleString()} LOC<br />
                    {result.duration}ms
                  </div>
                )}
              </div>
            </div>

            {error && (
              <div className="mono" style={{ marginTop: 12, fontSize: 12, color: 'var(--color-hemis)' }}>
                ✕ {error}
              </div>
            )}
          </div>

          {/* Results */}
          {result && (
            <div>
              {/* Summary cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 24 }}>
                {SEV_ORDER.map(sev => {
                  const count = result.summary[sev.toLowerCase() as keyof typeof result.summary] as number
                  const activeCount = activeSummary ? activeSummary[sev.toLowerCase() as keyof typeof activeSummary] as number : count
                  const hasFP = count !== activeCount
                  return (
                    <div
                      key={sev}
                      onClick={() => setFilterSev(filterSev === sev ? 'ALL' : sev)}
                      style={{
                        background: filterSev === sev ? SEV_BG[sev] : 'var(--color-bg-surface)',
                        border: `1px solid ${filterSev === sev ? SEV_COLOR[sev] : 'var(--color-border)'}`,
                        padding: '14px 16px', cursor: 'pointer', textAlign: 'center',
                        transition: 'all 0.15s',
                      }}
                    >
                      <div className="mono" style={{ fontSize: 10, letterSpacing: '0.1em', color: SEV_COLOR[sev], marginBottom: 6 }}>
                        {sev}
                      </div>
                      <div style={{ fontSize: 28, fontWeight: 700, color: activeCount > 0 ? SEV_COLOR[sev] : 'var(--color-text-dim)' }}>
                        {activeCount}
                      </div>
                      {hasFP && (
                        <div className="mono" style={{ fontSize: 9, color: 'var(--color-text-dim)', marginTop: 4 }}>
                          +{count - activeCount} FP
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>

              {/* OWASP heatmap */}
              {result.owaspCoverage && result.owaspCoverage.length > 0 && (
                <div className="bracket-card" style={{ padding: 20, marginBottom: 24 }}>
                  <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase', marginBottom: 14 }}>
                    [ OWASP TOP 10 COVERAGE ]
                  </div>
                  <OwaspHeatmap coverage={result.owaspCoverage} />
                </div>
              )}

              {/* Findings table */}
              <div className="bracket-card" style={{ padding: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
                  <div className="mono" style={{ fontSize: 11, letterSpacing: '0.14em', color: 'var(--color-sast)', textTransform: 'uppercase' }}>
                    [ FINDINGS — {filteredFindings.length} / {result.findings.length} ]
                    {activeSummary && activeSummary.fpCount > 0 && (
                      <span style={{ color: 'var(--color-text-dim)', fontSize: 10, marginLeft: 8 }}>
                        ({activeSummary.fpCount} marked as false positive)
                      </span>
                    )}
                  </div>

                  {/* Filters */}
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    {/* Hide FP toggle */}
                    <button
                      onClick={() => setHideFP(!hideFP)}
                      className="mono"
                      style={{
                        padding: '4px 10px', fontSize: 10, cursor: 'pointer',
                        background: hideFP ? 'var(--color-sast)18' : 'var(--color-bg-elevated)',
                        border: `1px solid ${hideFP ? 'var(--color-sast)' : 'var(--color-border)'}`,
                        color: hideFP ? 'var(--color-sast)' : 'var(--color-text-dim)',
                        letterSpacing: '0.08em',
                      }}
                    >
                      {hideFP ? '◉ HIDE FP' : '○ SHOW FP'}
                    </button>

                    {/* Severity filter */}
                    <div style={{ display: 'flex', gap: 4 }}>
                      {(['ALL', ...SEV_ORDER] as const).map(s => (
                        <button key={s} onClick={() => setFilterSev(s)}
                          className="mono"
                          style={{
                            padding: '4px 10px', fontSize: 10, cursor: 'pointer',
                            background: filterSev === s ? (s === 'ALL' ? 'var(--color-sast)22' : SEV_BG[s]) : 'var(--color-bg-elevated)',
                            border: `1px solid ${filterSev === s ? (s === 'ALL' ? 'var(--color-sast)' : SEV_COLOR[s]) : 'var(--color-border)'}`,
                            color: filterSev === s ? (s === 'ALL' ? 'var(--color-sast)' : SEV_COLOR[s]) : 'var(--color-text-dim)',
                            letterSpacing: '0.08em',
                          }}
                        >{s}</button>
                      ))}
                    </div>

                    {/* Category filter */}
                    <select
                      value={filterCat}
                      onChange={e => setFilterCat(e.target.value)}
                      style={{
                        background: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)',
                        color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)',
                        fontSize: 11, padding: '4px 10px', outline: 'none',
                      }}
                    >
                      {categories.map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                </div>

                {filteredFindings.length === 0 ? (
                  <div className="mono" style={{ textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 12, padding: '32px 0' }}>
                    No findings match the current filters.
                  </div>
                ) : (
                  <div>
                    {filteredFindings
                      .sort((a, b) => {
                        // FP goes to bottom
                        if (a.falsePositive !== b.falsePositive) return a.falsePositive ? 1 : -1
                        return SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
                      })
                      .map((f, i) => <FindingCard key={f.id} f={f} index={i} onToggleFP={toggleFalsePositive} />)
                    }
                  </div>
                )}
              </div>

              {/* Scan metadata footer */}
              <div style={{ marginTop: 16, display: 'flex', gap: 24, flexWrap: 'wrap' }}>
                {[
                  ['Scan ID',    result.id.slice(0, 8) + '...'],
                  ['Language',   result.language],
                  ['Files',      String(result.filesScanned)],
                  ['Lines',      result.linesOfCode.toLocaleString()],
                  ['Duration',   `${result.duration}ms`],
                  ['Rules Run',  '55 regex + 12 AST + 18 secrets + SCA'],
                ].map(([k, v]) => (
                  <div key={k} className="mono" style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>
                    {k}: <span style={{ color: 'var(--color-text-secondary)' }}>{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
