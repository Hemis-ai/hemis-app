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

function FindingCard({ f, index, onToggleFP }: {
  f: SastFindingResult
  index: number
  onToggleFP?: (id: string, fp: boolean) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const sev = f.severity as SastSeverity
  const isFP = f.falsePositive

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
            </div>
          </div>
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

// ─── Main page ────────────────────────────────────────────────────────────────

export default function SastPage() {
  const [tab, setTab]           = useState<'paste' | 'demo' | 'multifile'>('demo')
  const [panel, setPanel]       = useState<'scan' | 'history' | 'cicd'>('scan')
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
          55 rules · OWASP Top 10 · 8 languages · CWE mapped · Secret detection · SCA dependency scanning
        </p>
      </div>

      {/* Top panel tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 0, borderBottom: '1px solid var(--color-border)' }}>
        {([
          { id: 'scan', label: 'SCANNER' },
          { id: 'history', label: 'SCAN HISTORY' },
          { id: 'cicd', label: 'CI/CD' },
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
                  ['Rules Run',  '55 + 18 secrets + SCA'],
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
