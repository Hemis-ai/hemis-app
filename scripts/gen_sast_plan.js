'use strict';
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumber, PageBreak, LevelFormat,
  ExternalHyperlink, TabStopType, TabStopPosition,
} = require('docx');
const fs = require('fs');
const path = require('path');

// ── Color helpers ──────────────────────────────────────────────────────────────
const PURPLE = '7c3aed';
const DARK   = '1e1e2e';
const MID    = '2d2d3f';
const LIGHT  = 'f5f5fa';
const WHITE  = 'ffffff';
const GRAY   = '6b7280';
const RED    = 'ef4444';
const ORANGE = 'f97316';
const YELLOW = 'eab308';
const BLUE   = '3b82f6';
const GREEN  = '10b981';

function border(color = '5b21b6', size = 6) {
  return { style: BorderStyle.SINGLE, size, color };
}
function noBorder() {
  return { style: BorderStyle.NONE, size: 0, color: 'ffffff' };
}
const cellBorders = { top: border('d8b4fe', 4), bottom: border('d8b4fe', 4), left: border('d8b4fe', 4), right: border('d8b4fe', 4) };
const headerBorders = { top: border(PURPLE, 6), bottom: border(PURPLE, 6), left: border(PURPLE, 6), right: border(PURPLE, 6) };

function h(text, level) {
  return new Paragraph({ heading: level, children: [new TextRun(text)] });
}

function p(text, opts = {}) {
  return new Paragraph({
    alignment: opts.center ? AlignmentType.CENTER : AlignmentType.LEFT,
    spacing: { before: opts.before ?? 80, after: opts.after ?? 80 },
    children: [new TextRun({ text, color: opts.color ?? DARK, bold: opts.bold, size: opts.size ?? 22, font: 'Arial' })],
  });
}

function bullet(text, level = 0) {
  return new Paragraph({
    numbering: { reference: 'bullets', level },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, size: 22, font: 'Arial', color: DARK })],
  });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

function sectionTitle(text) {
  return new Paragraph({
    spacing: { before: 320, after: 160 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: PURPLE, space: 6 } },
    children: [
      new TextRun({ text, font: 'Arial', size: 36, bold: true, color: PURPLE }),
    ],
  });
}

function subTitle(text) {
  return new Paragraph({
    spacing: { before: 200, after: 80 },
    children: [new TextRun({ text, font: 'Arial', size: 26, bold: true, color: '4c1d95' })],
  });
}

function labelRow(label, value, labelColor = PURPLE) {
  return new Paragraph({
    spacing: { before: 40, after: 40 },
    children: [
      new TextRun({ text: `${label}: `, font: 'Arial', size: 22, bold: true, color: labelColor }),
      new TextRun({ text: value, font: 'Courier New', size: 20, color: DARK }),
    ],
  });
}

function makeTable({ headers, rows, widths, headerBg = PURPLE, headerColor = WHITE, fontSize = 18 }) {
  const totalW = widths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: totalW, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      new TableRow({
        tableHeader: true,
        children: headers.map((h, i) =>
          new TableCell({
            borders: headerBorders,
            width: { size: widths[i], type: WidthType.DXA },
            shading: { fill: headerBg, type: ShadingType.CLEAR },
            margins: { top: 80, bottom: 80, left: 100, right: 100 },
            children: [new Paragraph({
              alignment: AlignmentType.CENTER,
              children: [new TextRun({ text: h, font: 'Arial', size: fontSize, bold: true, color: headerColor })]
            })],
          })
        ),
      }),
      ...rows.map((row, ri) =>
        new TableRow({
          children: row.map((cell, ci) =>
            new TableCell({
              borders: cellBorders,
              width: { size: widths[ci], type: WidthType.DXA },
              shading: { fill: ri % 2 === 0 ? 'f5f0ff' : WHITE, type: ShadingType.CLEAR },
              margins: { top: 60, bottom: 60, left: 100, right: 100 },
              children: [new Paragraph({
                children: [new TextRun({ text: cell ?? '', font: 'Arial', size: fontSize - 2, color: DARK })]
              })],
            })
          ),
        })
      ),
    ],
  });
}

// ── Document ───────────────────────────────────────────────────────────────────
const doc = new Document({
  numbering: {
    config: [
      {
        reference: 'bullets',
        levels: [
          { level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } } },
          { level: 1, format: LevelFormat.BULLET, text: '◦', alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 1080, hanging: 360 } } } },
        ],
      },
    ],
  },
  styles: {
    default: {
      document: { run: { font: 'Arial', size: 22, color: DARK } },
    },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 40, bold: true, font: 'Arial', color: PURPLE },
        paragraph: { spacing: { before: 400, after: 200 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 28, bold: true, font: 'Arial', color: '4c1d95' },
        paragraph: { spacing: { before: 280, after: 120 }, outlineLevel: 1 } },
      { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 24, bold: true, font: 'Arial', color: '6d28d9' },
        paragraph: { spacing: { before: 200, after: 80 }, outlineLevel: 2 } },
    ],
  },
  sections: [
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 },
        },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'd8b4fe', space: 4 } },
            children: [
              new TextRun({ text: 'HemisX SAST — Product Plan v1.0', font: 'Arial', size: 18, color: PURPLE, bold: true }),
              new TextRun({ text: '\tCONFIDENTIAL', font: 'Arial', size: 18, color: GRAY }),
            ],
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            border: { top: { style: BorderStyle.SINGLE, size: 4, color: 'd8b4fe', space: 4 } },
            children: [
              new TextRun({ text: 'sai@secguard.io  |  HemisX Engineering', font: 'Arial', size: 16, color: GRAY }),
              new TextRun({ text: '\tPage ', font: 'Arial', size: 16, color: GRAY }),
              new TextRun({ children: [PageNumber.CURRENT], font: 'Arial', size: 16, color: GRAY }),
            ],
          })],
        }),
      },

      children: [
        // ── COVER ─────────────────────────────────────────────────────────────
        new Paragraph({ spacing: { before: 1200, after: 160 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: '◧', font: 'Arial', size: 96, color: PURPLE })] }),

        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 120 },
          children: [new TextRun({ text: 'HemisX SAST', font: 'Arial', size: 72, bold: true, color: PURPLE })] }),

        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 },
          children: [new TextRun({ text: 'Complete Product Plan & Implementation Blueprint', font: 'Arial', size: 32, color: '4c1d95' })] }),

        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 240 },
          children: [new TextRun({ text: 'Static Application Security Testing Module  |  Version 1.0  |  March 2026', font: 'Arial', size: 22, color: GRAY })] }),

        // Status badge
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80, after: 80 },
          children: [
            new TextRun({ text: '  ✓ PART 1 COMPLETE  ', font: 'Arial', size: 24, bold: true, color: GREEN, highlight: 'green' }),
          ] }),

        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80, after: 1200 },
          children: [new TextRun({ text: 'Prepared by HemisX Engineering Team  ·  sai@secguard.io  ·  March 14, 2026', font: 'Arial', size: 20, color: GRAY })] }),

        pageBreak(),

        // ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────
        h('Executive Summary', HeadingLevel.HEADING_1),
        p('HemisX SAST is an AI-powered static application security testing engine embedded directly into the HemisX security console. It enables developers and security teams to scan source code for vulnerabilities before code ships — catching SQL injection, XSS, command injection, hardcoded secrets, insecure cryptography, SSRF, and 50+ other vulnerability classes across 8 programming languages without any external tooling.'),
        p(''),
        p('Current Status: Part 1 COMPLETE — 55-rule engine, secret detector, full UI, API layer, DB persistence.', { bold: true, color: GREEN }),

        pageBreak(),

        // ── SECTION 1: PRODUCT VISION ──────────────────────────────────────────
        h('Section 1: Product Vision', HeadingLevel.HEADING_1),

        h('1.1  Problem Statement', HeadingLevel.HEADING_2),
        bullet('68% of vulnerabilities are introduced at the code level, not the infrastructure level'),
        bullet('Traditional SAST tools (Veracode, Checkmarx, SonarQube) cost $20K–$100K/year — out of reach for SMBs'),
        bullet('Existing free tools (Semgrep OSS, Bandit) require CLI expertise and lack business-facing reporting'),
        bullet('Security findings are not mapped to business risk or compliance standards that executives understand'),
        bullet('No existing tool combines SAST + red team simulation + cloud security in one platform'),

        h('1.2  HemisX SAST Solution', HeadingLevel.HEADING_2),
        bullet('Browser-based code scanner: paste code, drop a file, or connect a Git repository'),
        bullet('55 security rules covering OWASP Top 10 (2021), mapped to CWE identifiers'),
        bullet('18 high-precision secret detection patterns (AWS, GitHub, Stripe, OpenAI, JWT, private keys, etc.)'),
        bullet('Supports JavaScript, TypeScript, Python, PHP, Java, Go, Ruby, C#'),
        bullet('One-click executive PDF reports with business risk context'),
        bullet('Claude AI-powered remediation explanations tailored to the developer\'s stack'),
        bullet('Integrated into the HemisX platform alongside Red Team and Blue Team modules'),

        h('1.3  Target Users', HeadingLevel.HEADING_2),
        p(''),
        makeTable({
          headers: ['User Type', 'Primary Need'],
          widths: [2800, 6760],
          rows: [
            ['Security Engineers', 'Deep technical findings with line numbers, CWE, MITRE mapping'],
            ['Developers', 'Fast feedback during PR reviews with clear remediation guidance'],
            ['Security Managers', 'Compliance reports (OWASP, PCI-DSS, SOC2) and trend dashboards'],
            ['CTOs / CISOs', 'Executive risk summaries and board-ready metrics'],
          ],
        }),

        pageBreak(),

        // ── SECTION 2: WHAT IS BUILT ───────────────────────────────────────────
        h('Section 2: What Is Built — SAST Part 1 (COMPLETE)', HeadingLevel.HEADING_1),

        h('2.1  Core Engine', HeadingLevel.HEADING_2),
        labelRow('File', 'src/lib/sast/scanner.ts'),
        bullet('Regex-based pattern matching engine applying 55 rules to source code'),
        bullet('Line-level finding detection with configurable context window (±3 lines)'),
        bullet('Code snippet extraction centered on the vulnerable line'),
        bullet('Per-file language detection with fallback content heuristics'),
        bullet('OWASP Top 10 coverage map computed from findings'),
        bullet('Primary language detection across multi-file scans'),
        bullet('Scan duration tracking (milliseconds)'),

        h('2.2  Rule Library — 55 Rules', HeadingLevel.HEADING_2),
        labelRow('File', 'src/lib/sast/rules.ts'),
        p(''),
        makeTable({
          headers: ['Category', 'Rules', 'Count'],
          widths: [3000, 5200, 1360],
          rows: [
            ['Injection', 'SQL, Command, LDAP, XPath, Template', '12'],
            ['XSS', 'innerHTML, document.write, dangerouslySetInnerHTML, eval, Function', '5'],
            ['Cryptographic Failures', 'MD5, SHA1, Math.random, static IV, SSL verify disabled', '6'],
            ['Hardcoded Secrets', 'password, API key, AWS key, private key, token', '5'],
            ['Broken Access Control', 'Path traversal, TOCTOU, missing auth', '3'],
            ['Authentication Failures', 'Plaintext comparison, JWT none alg, token in URL, weak secret', '4'],
            ['Insecure Deserialization', 'pickle, yaml.load, PHP unserialize, Java ObjectInputStream', '4'],
            ['SSRF', 'fetch with user URL, requests.get, cloud metadata endpoint', '3'],
            ['Security Misconfiguration', 'DEBUG=True, wildcard CORS, hardcoded localhost, HTTP URLs, cookies', '5'],
            ['Logging Failures', 'Password in logs, stack trace to client', '2'],
            ['Vulnerable Components', 'Deprecated crypto.createCipher, weak hashlib', '2'],
            ['Insecure Design', 'ReDoS, mass assignment', '2'],
            ['XXE', 'XML parsing without disabling external entities', '1'],
            ['Go-specific', 'ListenAndServe without TLS, fmt.Sprintf SQL', '2'],
            ['Race Conditions', 'TOCTOU file operations', '1'],
            ['TOTAL', '', '55'],
          ],
        }),

        h('2.3  Secret Detector — 18 Patterns', HeadingLevel.HEADING_2),
        labelRow('File', 'src/lib/sast/secret-detector.ts'),
        p('AWS Access Key ID, AWS Secret Access Key, GCP Service Account Key, Azure Storage Account Key, GitHub PAT, GitHub OAuth Secret, Stripe API Key, Slack Bot Token, JWT, PEM Private Key, SendGrid API Key, Twilio Auth Token, Mailgun API Key, npm Auth Token, Heroku API Key, Discord Bot Token, OpenAI API Key, Anthropic API Key'),

        h('2.4  Language Detector', HeadingLevel.HEADING_2),
        labelRow('File', 'src/lib/sast/language-detector.ts'),
        bullet('JavaScript (js, mjs, cjs, jsx)'),
        bullet('TypeScript (ts, tsx)'),
        bullet('Python (py)'),
        bullet('PHP (php, phtml)'),
        bullet('Java (java)'),
        bullet('Go (go)'),
        bullet('Ruby (rb)'),
        bullet('C# (cs)'),
        p('Detection method: File extension primary, content heuristics (shebangs, import patterns, class signatures) as fallback.'),

        h('2.5  API Layer', HeadingLevel.HEADING_2),
        bullet('POST /api/sast/scan — Submit code (up to 50 files, 2MB total), run scan synchronously, return full results + persist to DB'),
        bullet('GET /api/sast/scan/:id — Retrieve stored scan results from DB'),
        bullet('GET /api/sast/scans — List all org scans paginated (used for history dashboard)'),

        h('2.6  Database Models (Prisma / PostgreSQL)', HeadingLevel.HEADING_2),
        p('SastScan model fields: id, orgId, initiatedBy, name, language, linesOfCode, status, filesScanned, duration, startedAt, completedAt, criticalCount, highCount, mediumCount, lowCount, infoCount', { size: 20 }),
        p('SastFinding model fields: id, scanId, ruleId, ruleName, severity, confidence, language, filePath, lineStart, lineEnd, codeSnippet, description, remediation, owasp, cwe, category, status, falsePositive, detectedAt', { size: 20 }),

        h('2.7  UI', HeadingLevel.HEADING_2),
        labelRow('File', 'src/app/(dashboard)/dashboard/sast/page.tsx'),
        bullet('Demo Code tab: Pre-loaded vulnerable Node.js, Python, PHP code samples'),
        bullet('Paste / Drop Code tab: Textarea with drag-and-drop file support, file path input, scan name'),
        bullet('Severity summary cards (CRITICAL / HIGH / MEDIUM / LOW / INFO) — clickable filters'),
        bullet('OWASP Top 10 heatmap: 10-cell grid showing finding counts per category, color-coded by severity'),
        bullet('Findings list: Expandable cards with rule ID, severity badge, file path, line, CWE, description, remediation, code snippet'),
        bullet('Filters: Severity buttons + category dropdown'),
        bullet('Scan metadata footer: scan ID, language, files, lines of code, duration'),

        pageBreak(),

        // ── SECTION 3: PART 2 ─────────────────────────────────────────────────
        h('Section 3: SAST Part 2 — Next (Planned)', HeadingLevel.HEADING_1),

        h('3.1  AST-Based Analysis', HeadingLevel.HEADING_2),
        p('Current limitation: regex-based patterns have moderate false-positive rates on complex code.'),
        bullet('Integrate tree-sitter WASM for JavaScript and Python AST parsing'),
        bullet('Context-aware taint tracking: trace user-controlled data from source (req.params) to sink (db.query, exec, innerHTML)'),
        bullet('Eliminate false positives from variable assignments that never reach a dangerous sink'),
        bullet('Data flow analysis for inter-function vulnerability detection'),
        bullet('Estimated improvement: false positive rate drops from ~25% to ~8%'),

        h('3.2  Multi-File Project Upload', HeadingLevel.HEADING_2),
        p('Current limitation: one file or pasted code per scan.'),
        bullet('ZIP archive upload (up to 10MB)'),
        bullet('Git repository URL scanning (public repos, GitHub/GitLab token for private)'),
        bullet('Automatic file discovery and filtering (.gitignore respect, skip node_modules/vendor)'),
        bullet('Cross-file taint analysis (variable passed from one module to another)'),
        bullet('Project-level dependency detection (package.json, requirements.txt, pom.xml)'),

        h('3.3  Dependency Vulnerability Scanning (SCA)', HeadingLevel.HEADING_2),
        bullet('Parse package.json, requirements.txt, pom.xml, go.mod, Gemfile'),
        bullet('Query OSV (Open Source Vulnerabilities) database for known CVEs'),
        bullet('Map CVE severity to findings with CVSS scores'),
        bullet('Identify transitive dependency vulnerabilities'),
        bullet('Generate upgrade recommendations with breaking change warnings'),

        h('3.4  False Positive Management', HeadingLevel.HEADING_2),
        bullet('Per-finding false positive toggle (already modeled in DB as falsePositive boolean)'),
        bullet('Suppression rules: suppress rule X in file pattern Y'),
        bullet('Team-wide suppression sharing across org'),
        bullet('Audit trail of who marked what as false positive and when'),
        bullet('Weekly false positive rate metrics'),

        h('3.5  CI/CD Integration', HeadingLevel.HEADING_2),
        bullet('GitHub Actions workflow generator (one-click copy)'),
        bullet('GitLab CI template'),
        bullet('API key-based authentication for headless scanning'),
        bullet('PR comment mode: post findings as GitHub PR review comments'),
        bullet('Fail/pass threshold configuration (e.g., fail CI if any CRITICAL found)'),
        bullet('Baseline scan: only report new findings since last clean scan (diff mode)'),

        h('3.6  Claude AI Remediation Engine', HeadingLevel.HEADING_2),
        bullet('Each finding gets a Claude-generated explanation tailored to the developer\'s framework'),
        bullet('Context-aware fix suggestions with actual code patches'),
        bullet('"Fix this for me" button: Claude generates a corrected code snippet'),
        bullet('Remediation difficulty rating (Easy / Medium / Hard)'),
        bullet('Estimated fix time and links to relevant documentation / CVE references'),

        pageBreak(),

        // ── SECTION 4: PART 3 ─────────────────────────────────────────────────
        h('Section 4: SAST Part 3 — Advanced (Roadmap)', HeadingLevel.HEADING_1),

        h('4.1  Compliance Report Generation', HeadingLevel.HEADING_2),
        bullet('Supported standards: PCI-DSS 4.0, SOC2 Type II, OWASP ASVS, ISO 27001, HIPAA, GDPR'),
        bullet('PDF reports with executive summary, technical findings, compliance gap analysis, remediation roadmap'),
        bullet('Audience: Auditors, CISOs, compliance officers'),

        h('4.2  IDE Plugin (VS Code Extension)', HeadingLevel.HEADING_2),
        bullet('Real-time scan on file save'),
        bullet('Inline red squiggles on vulnerable lines'),
        bullet('Hover tooltip with finding description + remediation'),
        bullet('Uses same rule engine as the platform (consistent results)'),
        bullet('Syncs findings back to HemisX console for team visibility'),

        h('4.3  Advanced Secret Scanning', HeadingLevel.HEADING_2),
        bullet('Shannon entropy analysis to catch high-entropy strings not matching known patterns'),
        bullet('Git history scanning (find secrets ever committed, even if deleted)'),
        bullet('.env file scanning with format validation'),
        bullet('Kubernetes Secret YAML scanning'),
        bullet('Terraform variable file scanning for plaintext secrets'),

        h('4.4  Custom Rule Builder', HeadingLevel.HEADING_2),
        bullet('UI to write custom regex or semgrep-compatible rules'),
        bullet('Rule testing interface (paste code, see matches highlighted)'),
        bullet('Rule sharing across organization'),
        bullet('Import community rule packs (Semgrep registry, GitHub Advisory)'),
        bullet('Rule performance metrics (match rate, false positive rate)'),

        h('4.5  Trend Analytics Dashboard', HeadingLevel.HEADING_2),
        bullet('Finding count over time (per week/month)'),
        bullet('MTTR (mean time to remediate) by severity'),
        bullet('Top 5 most common vulnerability classes'),
        bullet('Developer leaderboard (least findings introduced)'),
        bullet('Compliance score trend over time'),
        bullet('Comparison: this sprint vs last sprint'),

        h('4.6  Remediation Workflow Integration', HeadingLevel.HEADING_2),
        bullet('Jira ticket auto-creation from findings'),
        bullet('GitHub Issue and Linear integration'),
        bullet('Slack notification for new CRITICAL findings'),
        bullet('Email digest: daily/weekly finding summary'),
        bullet('Two-way sync: mark finding resolved in Jira — auto-closes in HemisX'),

        pageBreak(),

        // ── SECTION 5: ARCHITECTURE ────────────────────────────────────────────
        h('Section 5: Technical Architecture', HeadingLevel.HEADING_1),

        h('5.1  Current Architecture (Part 1)', HeadingLevel.HEADING_2),
        p(''),
        makeTable({
          headers: ['Layer', 'Technology'],
          widths: [2500, 7060],
          rows: [
            ['Frontend', 'Next.js 16 / React 19 / TypeScript (App Router)'],
            ['Backend', 'Next.js API Routes (Node.js runtime)'],
            ['Database', 'PostgreSQL via Prisma v5 ORM'],
            ['Auth', 'JWT (jose) + bcrypt, httpOnly cookies, route middleware'],
            ['Scanner', 'Synchronous regex engine, runs in API handler'],
            ['Storage', 'DB findings + in-memory for demo mode fallback'],
          ],
        }),

        h('5.2  Target Architecture (Part 2+)', HeadingLevel.HEADING_2),
        p(''),
        makeTable({
          headers: ['Component', 'Technology'],
          widths: [2500, 7060],
          rows: [
            ['Scanner Worker', 'Offload heavy scans to background worker (BullMQ + Redis)'],
            ['Async Scanning', 'POST /scan returns immediately with scan ID; client polls for progress'],
            ['Tree-sitter', 'WASM-compiled parsers for JS/TS/Python AST analysis'],
            ['File Storage', 'S3/R2 for uploaded ZIP archives'],
            ['CDN', 'Cloudflare for frontend assets'],
            ['Observability', 'OpenTelemetry traces for scan performance'],
          ],
        }),

        h('5.3  Future Scanning Pipeline', HeadingLevel.HEADING_2),
        p(''),
        makeTable({
          headers: ['Step', 'Action'],
          widths: [800, 8760],
          rows: [
            ['1', 'File ingestion → language detection → file tree building'],
            ['2', 'Secret detection pass (fast, regex, high priority)'],
            ['3', 'Syntax tree parsing (tree-sitter)'],
            ['4', 'Taint analysis (data flow source-to-sink)'],
            ['5', 'Rule matching (pattern rules applied to AST nodes)'],
            ['6', 'Dependency scanning (SCA against OSV database)'],
            ['7', 'Deduplication and ranking'],
            ['8', 'Claude AI enrichment (remediation generation)'],
            ['9', 'Report generation and DB persistence'],
          ],
        }),

        h('5.4  API Specification', HeadingLevel.HEADING_2),
        p(''),
        makeTable({
          headers: ['Endpoint', 'Method', 'Description', 'Part'],
          widths: [2800, 800, 4800, 1160],
          rows: [
            ['/api/sast/scan', 'POST', 'Submit code, run scan, return full results + persist', 'Part 1'],
            ['/api/sast/scan/:id', 'GET', 'Retrieve stored scan results (org-scoped)', 'Part 1'],
            ['/api/sast/scans', 'GET', 'Paginated list of scan summaries', 'Part 1'],
            ['/api/sast/findings/:id', 'PATCH', 'Update finding status / false positive', 'Part 2'],
            ['/api/sast/scan/repo', 'POST', 'Clone repo, scan all files, async job', 'Part 2'],
            ['/api/sast/report/:id', 'GET', 'PDF report stream with executive summary', 'Part 3'],
          ],
        }),

        pageBreak(),

        // ── SECTION 6: RULE COVERAGE MATRIX ───────────────────────────────────
        h('Section 6: Rule Coverage Matrix (55 Rules)', HeadingLevel.HEADING_1),

        p(''),
        makeTable({
          headers: ['Rule ID', 'Name', 'Language', 'OWASP', 'CWE', 'Severity'],
          widths: [1400, 2800, 1200, 700, 900, 1200],
          fontSize: 16,
          rows: [
            ['SAST-SQL-001','SQL Injection via concatenation','All','A03','CWE-89','CRITICAL'],
            ['SAST-SQL-002','Python f-string SQL injection','Python','A03','CWE-89','CRITICAL'],
            ['SAST-SQL-003','PHP mysqli_query concatenation','PHP','A03','CWE-89','CRITICAL'],
            ['SAST-CMD-001','OS command injection exec/system','All','A03','CWE-78','CRITICAL'],
            ['SAST-CMD-002','Node.js child_process.exec','JS/TS','A03','CWE-78','CRITICAL'],
            ['SAST-CMD-003','Python subprocess shell=True','Python','A03','CWE-78','HIGH'],
            ['SAST-CMD-004','Python os.system/os.popen','Python','A03','CWE-78','CRITICAL'],
            ['SAST-XSS-001','Unsafe innerHTML assignment','JS/TS','A03','CWE-79','HIGH'],
            ['SAST-XSS-002','document.write with variable','JS/TS','A03','CWE-79','HIGH'],
            ['SAST-XSS-003','React dangerouslySetInnerHTML','JS/TS','A03','CWE-79','HIGH'],
            ['SAST-XSS-004','eval() with dynamic content','JS/TS/PHP/Ruby','A03','CWE-95','CRITICAL'],
            ['SAST-XSS-005','new Function() constructor','JS/TS','A03','CWE-95','HIGH'],
            ['SAST-CRYPTO-001','MD5 for hashing','All','A02','CWE-327','HIGH'],
            ['SAST-CRYPTO-002','SHA-1 for hashing','All','A02','CWE-327','MEDIUM'],
            ['SAST-CRYPTO-003','Math.random() for security','JS/TS','A02','CWE-338','MEDIUM'],
            ['SAST-CRYPTO-004','Python random module','Python','A02','CWE-338','MEDIUM'],
            ['SAST-CRYPTO-005','Hardcoded static IV','All','A02','CWE-329','HIGH'],
            ['SAST-CRYPTO-006','SSL/TLS verify disabled','All','A02','CWE-295','HIGH'],
            ['SAST-SEC-001','Hardcoded password','All','A07','CWE-798','CRITICAL'],
            ['SAST-SEC-002','Hardcoded API key/token','All','A07','CWE-798','CRITICAL'],
            ['SAST-SEC-003','AWS access key pattern','All','A02','CWE-798','CRITICAL'],
            ['SAST-SEC-004','Private key PEM header','All','A02','CWE-321','CRITICAL'],
            ['SAST-SEC-005','Generic secret variable','All','A07','CWE-798','HIGH'],
            ['SAST-AUTHZ-001','Path traversal user file path','All','A01','CWE-22','HIGH'],
            ['SAST-AUTHZ-002','Directory traversal sequence','All','A01','CWE-22','HIGH'],
            ['SAST-AUTHZ-003','Missing auth on route','JS/TS','A01','CWE-862','MEDIUM'],
            ['SAST-AUTH-001','Plaintext password comparison','All','A07','CWE-256','CRITICAL'],
            ['SAST-AUTH-002','JWT none algorithm','JS/TS','A07','CWE-347','CRITICAL'],
            ['SAST-AUTH-003','Token in URL query string','All','A07','CWE-598','HIGH'],
            ['SAST-AUTH-004','Weak/short HMAC secret','All','A07','CWE-521','HIGH'],
            ['SAST-DESER-001','Python pickle.loads','Python','A08','CWE-502','CRITICAL'],
            ['SAST-DESER-002','Python yaml.load unsafe','Python','A08','CWE-502','HIGH'],
            ['SAST-DESER-003','PHP unserialize user input','PHP','A08','CWE-502','CRITICAL'],
            ['SAST-DESER-004','Java ObjectInputStream','Java','A08','CWE-502','HIGH'],
            ['SAST-SSRF-001','fetch/axios with user URL','JS/TS','A10','CWE-918','HIGH'],
            ['SAST-SSRF-002','Python requests with user URL','Python','A10','CWE-918','HIGH'],
            ['SAST-SSRF-003','Cloud metadata endpoint','All','A10','CWE-918','HIGH'],
            ['SAST-CFG-001','Django/Flask DEBUG=True','Python','A05','CWE-489','HIGH'],
            ['SAST-CFG-002','Wildcard CORS origin','All','A05','CWE-942','MEDIUM'],
            ['SAST-CFG-003','Hardcoded localhost URL','All','A05','CWE-547','LOW'],
            ['SAST-CFG-004','HTTP (non-TLS) endpoint','All','A05','CWE-319','MEDIUM'],
            ['SAST-CFG-005','Cookie without Secure/HttpOnly','All','A05','CWE-614','MEDIUM'],
            ['SAST-LOG-001','Password/secret in log','All','A09','CWE-532','HIGH'],
            ['SAST-LOG-002','Stack trace sent to client','JS/TS','A09','CWE-209','MEDIUM'],
            ['SAST-DEP-001','crypto.createCipher deprecated','JS/TS','A06','CWE-327','HIGH'],
            ['SAST-DEP-002','hashlib.new weak algorithm','Python','A06','CWE-327','MEDIUM'],
            ['SAST-DESIGN-001','RegExp from user input (ReDoS)','JS/TS','A04','CWE-1333','MEDIUM'],
            ['SAST-DESIGN-002','Mass assignment from req.body','JS/TS','A04','CWE-915','HIGH'],
            ['SAST-XXE-001','XML parsing no entity disable','All','A03','CWE-611','HIGH'],
            ['SAST-TMPL-001','Server-side template injection','All','A03','CWE-94','CRITICAL'],
            ['SAST-LDAP-001','LDAP query user input','All','A03','CWE-90','HIGH'],
            ['SAST-RACE-001','TOCTOU file operations','Py/JS/Java','A04','CWE-367','MEDIUM'],
            ['SAST-GO-001','Go HTTP without TLS','Go','A05','CWE-319','MEDIUM'],
            ['SAST-GO-002','Go fmt.Sprintf SQL','Go','A03','CWE-89','CRITICAL'],
          ],
        }),

        pageBreak(),

        // ── SECTION 7: SECRET PATTERNS ─────────────────────────────────────────
        h('Section 7: Secret Detection Patterns (18 Patterns)', HeadingLevel.HEADING_1),

        p(''),
        makeTable({
          headers: ['Pattern ID', 'Name', 'Format', 'Action on Detection'],
          widths: [1600, 2000, 2400, 3560],
          fontSize: 16,
          rows: [
            ['SECRET-AWS-001','AWS Access Key ID','AKIA[16 chars]','Revoke in IAM immediately'],
            ['SECRET-AWS-002','AWS Secret Access Key','40-char base64 string','Rotate and audit CloudTrail'],
            ['SECRET-GCP-001','GCP Service Account Key','JSON with "private_key_id"','Delete key in GCP Console'],
            ['SECRET-AZURE-001','Azure Storage Account Key','AccountKey=[88 chars]==','Regenerate in Azure Portal'],
            ['SECRET-GITHUB-001','GitHub PAT (new format)','ghp_/gho_/ghs_...','Revoke at github.com/settings/tokens'],
            ['SECRET-GITHUB-002','GitHub Fine-grained PAT','github_pat_...','Revoke and audit usage'],
            ['SECRET-STRIPE-001','Stripe API Key','sk_live_/pk_live_...','Roll key in Stripe Dashboard'],
            ['SECRET-SLACK-001','Slack Bot Token','xoxb-/xoxp-/xoxa-...','Revoke in Slack App settings'],
            ['SECRET-JWT-001','JSON Web Token','eyJ...eyJ...signature','Expire token, rotate signing key'],
            ['SECRET-PRIVATE-KEY-001','PEM Private Key','-----BEGIN PRIVATE KEY-----','Remove, revoke, reissue certificate'],
            ['SECRET-SENDGRID-001','SendGrid API Key','SG.[22].[43]','Revoke in SendGrid settings'],
            ['SECRET-TWILIO-001','Twilio Auth Token','SK[32 hex chars]','Rotate in Twilio Console'],
            ['SECRET-MAILGUN-001','Mailgun API Key','key-[32 hex chars]','Regenerate in Mailgun'],
            ['SECRET-NPM-001','npm Auth Token','//registry.npmjs.org/:_authToken','Revoke npm token'],
            ['SECRET-HEROKU-001','Heroku API Key','UUID format','Regenerate in Heroku settings'],
            ['SECRET-DISCORD-001','Discord Bot Token','[26].[6].[27] base64','Regenerate in Developer Portal'],
            ['SECRET-OPENAI-001','OpenAI API Key','sk-[48 chars]','Revoke at platform.openai.com'],
            ['SECRET-ANTHROPIC-001','Anthropic API Key','sk-ant-api[version]-[93 chars]','Revoke at console.anthropic.com'],
          ],
        }),

        pageBreak(),

        // ── SECTION 8: TIMELINE ────────────────────────────────────────────────
        h('Section 8: Implementation Timeline', HeadingLevel.HEADING_1),

        p(''),
        makeTable({
          headers: ['Phase', 'Timeline', 'Key Deliverables', 'Status'],
          widths: [1200, 1400, 5200, 1760],
          rows: [
            ['Part 1','March 2026','55-rule regex engine, 18 secret patterns, 8-language support, OWASP heatmap UI, DB persistence, REST API, demo code samples, paste/drop UI','✓ COMPLETE'],
            ['Part 2 — Week 1','April W1','tree-sitter AST integration for JS/TS/Python','Planned'],
            ['Part 2 — Week 2','April W2','ZIP upload + multi-file scanning + dependency parsing','Planned'],
            ['Part 2 — Week 3','April W3','Claude AI remediation engine + false positive management','Planned'],
            ['Part 2 — Week 4','April W4','CI/CD GitHub Actions integration + PR comment mode','Planned'],
            ['Part 3 — Weeks 1-2','May W1-W2','Compliance PDF report generation (PCI-DSS, SOC2, OWASP ASVS)','Roadmap'],
            ['Part 3 — Weeks 3-4','May W3-W4','Trend analytics dashboard + MTTR tracking','Roadmap'],
            ['Part 3 — Week 5','May W5','VS Code extension (real-time scanning)','Roadmap'],
            ['Part 3 — Week 6','May W6','Advanced secret scanning (entropy analysis + git history)','Roadmap'],
            ['Part 4','Q3 2026','Custom rule builder, Jira/Linear integration, Enterprise SSO, Multi-region','Roadmap'],
          ],
        }),

        pageBreak(),

        // ── SECTION 9: METRICS ─────────────────────────────────────────────────
        h('Section 9: Success Metrics', HeadingLevel.HEADING_1),

        h('9.1  Accuracy Metrics', HeadingLevel.HEADING_2),
        p(''),
        makeTable({
          headers: ['Metric', 'Current (Part 1)', 'Target (Part 2)'],
          widths: [3000, 2500, 4060],
          rows: [
            ['False positive rate','~20%','<8% (with AST analysis)'],
            ['False negative rate (OWASP critical)','~10%','<5%'],
            ['Secret detection precision','~92%','>95%'],
            ['Scan latency (500KB)','~200ms average','<3s'],
          ],
        }),

        h('9.2  Business Metrics', HeadingLevel.HEADING_2),
        p(''),
        makeTable({
          headers: ['Metric', 'Target'],
          widths: [4000, 5560],
          rows: [
            ['SAST scans/month (90 days post-launch)','500+'],
            ['Rule library growth','+ 20 rules per quarter'],
            ['Language coverage','8 now — 12 by Q3 2026 (add Rust, Swift, Kotlin, Scala)'],
            ['CI/CD integration adoption','30% of users within first month'],
          ],
        }),

        h('9.3  Quality Targets', HeadingLevel.HEADING_2),
        bullet('100% OWASP Top 10 (2021) coverage by end of Part 2'),
        bullet('CWE Top 25 Most Dangerous Weaknesses: 80% coverage by Part 2'),
        bullet('All findings include: severity, CWE, OWASP mapping, code snippet, remediation'),

        pageBreak(),

        // ── SECTION 10: COMPETITIVE ────────────────────────────────────────────
        h('Section 10: Competitive Positioning', HeadingLevel.HEADING_1),

        p(''),
        makeTable({
          headers: ['Feature', 'HemisX SAST', 'Semgrep OSS', 'SonarQube CE', 'Veracode', 'Checkmarx'],
          widths: [2200, 1400, 1300, 1400, 1300, 1960],
          rows: [
            ['Browser-based UI','Yes','No (CLI)','Yes','Yes','Yes'],
            ['Price','Included','Free','Free/Paid','$20K+/yr','$30K+/yr'],
            ['Secret detection','18 patterns','Community','Limited','Yes','Yes'],
            ['OWASP heatmap','Yes','No','Yes','Yes','Yes'],
            ['Claude AI remediation','Yes','No','No','No','No'],
            ['Red Team + SAST + Cloud','Yes','No','No','No','No'],
            ['SMB-friendly','Yes','Moderate','Moderate','No','No'],
            ['Setup time','<60 seconds','Hours','Hours','Days','Weeks'],
            ['Languages (Part 1)','8','30+','30+','25+','25+'],
          ],
        }),

        p(''),
        new Paragraph({
          spacing: { before: 160, after: 160 },
          shading: { fill: 'f5f0ff', type: ShadingType.CLEAR },
          border: { left: { style: BorderStyle.SINGLE, size: 16, color: PURPLE, space: 8 } },
          children: [
            new TextRun({ text: 'HemisX SAST differentiation: ', font: 'Arial', size: 22, bold: true, color: PURPLE }),
            new TextRun({ text: 'The only SAST tool that combines static analysis, red team simulation, and cloud security auditing in a single unified platform — with AI-powered remediation guidance and built-in compliance mapping.', font: 'Arial', size: 22, color: DARK }),
          ],
        }),

        pageBreak(),

        // ── APPENDIX A ─────────────────────────────────────────────────────────
        h('Appendix A: File Structure', HeadingLevel.HEADING_1),

        p(''),
        makeTable({
          headers: ['File Path', 'Purpose'],
          widths: [3800, 5760],
          rows: [
            ['src/lib/sast/rules.ts','55 security rules with patterns, OWASP/CWE mapping'],
            ['src/lib/sast/scanner.ts','Core scanning engine, snippet extraction, OWASP coverage'],
            ['src/lib/sast/language-detector.ts','Extension + content-based language detection'],
            ['src/lib/sast/secret-detector.ts','18 high-precision secret patterns'],
            ['src/lib/types/sast.ts','TypeScript interfaces for all SAST types'],
            ['src/app/api/sast/scan/route.ts','POST /api/sast/scan — submit, run, persist'],
            ['src/app/api/sast/scan/[id]/route.ts','GET /api/sast/scan/:id — retrieve from DB'],
            ['src/app/api/sast/scans/route.ts','GET /api/sast/scans — list paginated'],
            ['src/app/(dashboard)/dashboard/sast/page.tsx','Full SAST UI — demo, paste, results, heatmap, findings'],
            ['prisma/schema.prisma','SastScan + SastFinding models'],
            ['src/app/globals.css','--color-sast (#a78bfa) + --color-sev-* tokens'],
            ['src/components/layout/sidebar.tsx','SAST added as 4th product in navigation'],
          ],
        }),

        pageBreak(),

        // ── APPENDIX B ─────────────────────────────────────────────────────────
        h('Appendix B: API Quick Reference', HeadingLevel.HEADING_1),

        h('Scan code', HeadingLevel.HEADING_3),
        new Paragraph({
          spacing: { before: 80, after: 80 },
          shading: { fill: 'f0f0f8', type: ShadingType.CLEAR },
          children: [
            new TextRun({ text: 'POST /api/sast/scan\nContent-Type: application/json\nBody: { "name": "My PR Review", "files": [{ "path": "src/api.js", "content": "... source code ..." }] }', font: 'Courier New', size: 18, color: DARK }),
          ],
        }),

        h('Get scan result', HeadingLevel.HEADING_3),
        new Paragraph({
          spacing: { before: 80, after: 80 },
          shading: { fill: 'f0f0f8', type: ShadingType.CLEAR },
          children: [
            new TextRun({ text: 'GET /api/sast/scan/{scanId}\nHeaders: Cookie: hemisx_access=<jwt>', font: 'Courier New', size: 18, color: DARK }),
          ],
        }),

        h('List all scans', HeadingLevel.HEADING_3),
        new Paragraph({
          spacing: { before: 80, after: 80 },
          shading: { fill: 'f0f0f8', type: ShadingType.CLEAR },
          children: [
            new TextRun({ text: 'GET /api/sast/scans?page=1&limit=20\nHeaders: Cookie: hemisx_access=<jwt>', font: 'Courier New', size: 18, color: DARK }),
          ],
        }),

        p(''),
        p(''),
        p('Document prepared by: HemisX Engineering Team', { color: GRAY }),
        p('Contact: sai@secguard.io', { color: GRAY }),
        p('Last updated: March 14, 2026', { color: GRAY }),
      ],
    },
  ],
});

Packer.toBuffer(doc).then(buffer => {
  const outPath = path.resolve(__dirname, '../SAST_PRODUCT_PLAN.docx');
  fs.writeFileSync(outPath, buffer);
  console.log('Written:', outPath, `(${(buffer.length / 1024).toFixed(1)} KB)`);
}).catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
